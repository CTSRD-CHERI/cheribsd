#!/usr/bin/env python
#===----------------------------------------------------------------------===##
#
# Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
# See https://llvm.org/LICENSE.txt for license information.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
#===----------------------------------------------------------------------===##

"""
Runs an executable on a remote host.

This is meant to be used as an executor when running the C++ Standard Library
conformance test suite.
"""
from __future__ import print_function

import argparse
import os
import posixpath
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile

try:
   from shlex import quote as cmd_quote
except ImportError:
   # for Python 2 compatibility
   from pipes import quote as cmd_quote

def ssh(args, command):
    cmd = ['ssh', '-oBatchMode=yes']
    if args.extra_ssh_args is not None:
        cmd.extend(shlex.split(args.extra_ssh_args))
    return cmd + [args.host, command]


def scp(args, src, dst):
    cmd = ['scp', '-q', '-oBatchMode=yes']
    if args.extra_scp_args is not None:
        cmd.extend(shlex.split(args.extra_scp_args))
    return cmd + [src, '{}:{}'.format(args.host, dst)]


def debug(cmdlineArgs, *args, **kwargs):
    if cmdlineArgs.debug:
        print(*args, file=sys.stderr, **kwargs)


def createTempdir(args):
    if args.shared_mount_local_path:
        localTmp = tempfile.mkdtemp(prefix="libcxx.", dir=args.shared_mount_local_path)
        remoteTmp = os.path.join(args.shared_mount_remote_path, os.path.basename(localTmp))
        debug(args, "Created local tmp dir:", localTmp)
        debug(args, "Assuming remote path is:", remoteTmp)
        return localTmp, remoteTmp
    remoteTmp = subprocess.check_output(ssh(args, 'mktemp -d {}/libcxx.XXXXXXXXXX'.format(args.tempdir)),
                                        universal_newlines=True).strip()
    debug(args, "Create remote tmp dir:", remoteTmp)
    return None, remoteTmp


def cleanupTempdir(args, localTmp, remoteTmp):
    if localTmp is not None:
        # If we have a shared mount we can simply delete the local directory.
        assert args.shared_mount_local_path is not None
        debug(args, "Deleting local tmp dir:", localTmp)
        shutil.rmtree(localTmp)
    else:
        debug(args, "Deleting remote tmp dir:", remoteTmp)
        subprocess.check_call(ssh(args, 'rm -r {}'.format(remoteTmp)))


def uploadTarball(args, src, dst):
    if args.shared_mount_local_path:
        # TODO: when using a shared mount we should probably just copy all files
        # and skip creating the tarball.
        remoteRelPath = os.path.relpath(dst, args.shared_mount_remote_path)
        # The remote path should be inside the shared directory:
        assert not remoteRelPath.startswith('..'), remoteRelPath
        localPath = os.path.join(args.shared_mount_local_path, remoteRelPath)
        debug(args, "Copying", src, "->", localPath)
        shutil.copy2(src, localPath)
    else:
        debug(args, "Uploading", src, "->", dst, "using scp")
        subprocess.check_call(scp(args, src, dst))
    return dst


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', type=str, required=True)
    parser.add_argument('--execdir', type=str, required=True)
    parser.add_argument('--debug', action="store_true", required=False)
    parser.add_argument('--tempdir', type=str, required=False, default='/tmp')
    parser.add_argument('--extra-ssh-args', type=str, required=False)
    parser.add_argument('--extra-scp-args', type=str, required=False)
    parser.add_argument('--shared-mount-local-path', type=str, required=False,
                        help="Local path that is shared with the remote system (e.g. via NFS)")
    parser.add_argument('--shared-mount-remote-path', type=str, required=False,
                        help="Path for the shared directory on the remote system")
    parser.add_argument('--codesign_identity', type=str, required=False, default=None)
    parser.add_argument('--env', type=str, nargs='*', required=False, default=dict())
    parser.add_argument("command", nargs=argparse.ONE_OR_MORE)
    args = parser.parse_args()
    commandLine = args.command

    # Allow using a directory that is shared between the local system and the
    # remote on. This can significantly speed up testing by avoiding three
    # additional ssh connections for every test.
    if args.shared_mount_local_path:
        if not os.path.isdir(args.shared_mount_local_path):
            sys.exit("ERROR: --shared-mount-local-path is not a directory.")
        if not args.shared_mount_remote_path:
            sys.exit("ERROR: missing --shared-mount-remote-path argument.")

    # Create a temporary directory where the test will be run.
    # That is effectively the value of %T on the remote host.
    localTmp, remoteTmp = createTempdir(args)

    # HACK:
    # If an argument is a file that ends in `.tmp.exe`, assume it is the name
    # of an executable generated by a test file. We call these test-executables
    # below. This allows us to do custom processing like codesigning test-executables
    # and changing their path when running on the remote host. It's also possible
    # for there to be no such executable, for example in the case of a .sh.cpp
    # test.
    isTestExe = lambda exe: exe.endswith('.tmp.exe') and os.path.exists(exe)
    pathOnRemote = lambda file: posixpath.join(remoteTmp, os.path.basename(file))

    try:
        # Do any necessary codesigning of test-executables found in the command line.
        if args.codesign_identity:
            for exe in filter(isTestExe, commandLine):
                subprocess.check_call(['xcrun', 'codesign', '-f', '-s', args.codesign_identity, exe], env={})

        # tar up the execution directory (which contains everything that's needed
        # to run the test), and copy the tarball over to the remote host.
        try:
            tmpTar = tempfile.NamedTemporaryFile(suffix='.tar', delete=False)
            with tarfile.open(fileobj=tmpTar, mode='w') as tarball:
                tarball.add(args.execdir, arcname=os.path.basename(args.execdir))

            # Make sure we close the file before we scp it, because accessing
            # the temporary file while still open doesn't work on Windows.
            tmpTar.close()
            remoteTarball = uploadTarball(args, tmpTar.name, pathOnRemote(tmpTar.name))
        finally:
            # Make sure we close the file in case an exception happens before
            # we've closed it above -- otherwise close() is idempotent.
            tmpTar.close()
            os.remove(tmpTar.name)

        # Untar the dependencies in the temporary directory and remove the tarball.
        remoteCommands = [
            'tar -xf {} -C {} --strip-components 1'.format(remoteTarball, remoteTmp),
            'rm {}'.format(remoteTarball)
        ]

        # Make sure all test-executables in the remote command line have 'execute'
        # permissions on the remote host. The host that compiled the test-executable
        # might not have a notion of 'executable' permissions.
        for exe in map(pathOnRemote, filter(isTestExe, commandLine)):
            remoteCommands.append('chmod +x {}'.format(exe))

        # Execute the command through SSH in the temporary directory, with the
        # correct environment. We tweak the command line to run it on the remote
        # host by transforming the path of test-executables to their path in the
        # temporary directory on the remote host.
        commandLine = (pathOnRemote(x) if isTestExe(x) else x for x in commandLine)
        remoteCommands.append('cd {}'.format(remoteTmp))
        if args.env:
            remoteCommands.append('export {}'.format(cmd_quote(' '.join(args.env))))
        remoteCommands.append(subprocess.list2cmdline(commandLine))

        # Finally, SSH to the remote host and execute all the commands.
        executeRemoteCommand = ssh(args, ' && '.join(remoteCommands))
        debug(args, "Executing test using", executeRemoteCommand)
        rc = subprocess.call(executeRemoteCommand)
        return rc

    finally:
        # Make sure the temporary directory is removed when we're done.
        cleanupTempdir(args, localTmp, remoteTmp)


if __name__ == '__main__':
    exit(main())
