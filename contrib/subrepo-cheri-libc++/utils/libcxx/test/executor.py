#===----------------------------------------------------------------------===##
#
# Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
# See https://llvm.org/LICENSE.txt for license information.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
#===----------------------------------------------------------------------===##

from __future__ import print_function
import platform
import os
import errno
import tempfile
import datetime
import shutil
import pipes
import sys

from libcxx.test import tracing
from libcxx.util import executeCommand, ExecuteCommandTimeoutException


class Executor(object):
    is_remote = False

    def run(self, exe_path, cmd, local_cwd, file_deps=None, env=None):
        """Execute a command.
            Be very careful not to change shared state in this function.
            Executor objects are shared between python processes in `lit -jN`.
        Args:
            exe_path: str:    Local path to the executable to be run
            cmd: [str]:       subprocess.call style command
            local_cwd: str:   Local path to the working directory
            file_deps: [str]: Files required by the test
            env: {str: str}:  Environment variables to execute under
        Returns:
            cmd, out, err, exitCode
        """
        raise NotImplementedError


class LocalExecutor(Executor):
    def __init__(self):
        super(LocalExecutor, self).__init__()
        self.is_windows = platform.system() == 'Windows'

    def run(self, exe_path, cmd=None, work_dir='.', file_deps=None, env=None):
        cmd = cmd or [exe_path]
        if work_dir == '.':
            work_dir = os.getcwd()
        out, err, rc = executeCommand(cmd, cwd=work_dir, env=env)
        return (cmd, out, err, rc)


class CompileOnlyExecutor(Executor):
    def run(self, exe_path, cmd, local_cwd, file_deps=None, env=None):
        cmd = cmd or [exe_path]
        # just always return 0 to pretend that it ran successfully
        return cmd, "", "", 0


class CollectBinariesExecutor(Executor):
    """Prefix an executor with some other command wrapper.

    Most useful for setting ulimits on commands, or running an emulator like
    qemu and valgrind.
    """
    def __init__(self, target_dir, config):
        super(CollectBinariesExecutor, self).__init__()
        self.config = config
        self.target_dir = target_dir

    def run(self, exe_path, cmd=None, work_dir='.', file_deps=None, env=None):
        # import pprint
        # pprint.pprint(vars(self))
        # pprint.pprint(vars(self.config))
        # pprint.pprint(vars(self.config.lit_config))
        # pprint.pprint(vars(self.config.config))
        # print "exe_path=", exe_path, "cmd=", cmd, "cwd=", work_dir, "file_deps=", file_deps, "env=", env
        # if env is not None:
        #     self.config.lit_config.warning('Cannot handle env yet: ' + str(env))
        if file_deps:
            return cmd, str(file_deps), 'Cannot handle file_deps yet', 7
        if cmd is not None and cmd != [exe_path]:
            return cmd, cmd, 'Cannot handle extra cmd args yet', 7
        exe_path = os.path.realpath(exe_path)
        test_exec_root = os.path.realpath(self.config.config.test_exec_root)
        assert exe_path.startswith(test_exec_root), exe_path + " doesn't start with " + str(test_exec_root)
        suffix = os.path.relpath(exe_path, test_exec_root)
        target = os.path.join(self.target_dir, suffix)
        if not os.path.isdir(os.path.dirname(target)):
            try:
                os.makedirs(os.path.dirname(target))
            except OSError as e:
                if e.errno == errno.EEXIST:
                    pass  # concurrent TOCTOU
                else:
                    raise
        cp_cmd = ["cp", "-f", exe_path, target]
        out, err, rc = executeCommand(cp_cmd)
        return cp_cmd, out, err, rc


class PrefixExecutor(Executor):
    """Prefix an executor with some other command wrapper.

    Most useful for setting ulimits on commands, or running an emulator like
    qemu and valgrind.
    """
    def __init__(self, commandPrefix, chain):
        super(PrefixExecutor, self).__init__()

        self.commandPrefix = commandPrefix
        self.chain = chain

    def run(self, exe_path, cmd=None, work_dir='.', file_deps=None, env=None):
        cmd = cmd or [exe_path]
        return self.chain.run(exe_path, self.commandPrefix + cmd, work_dir,
                              file_deps, env=env)


class PostfixExecutor(Executor):
    """Postfix an executor with some args."""
    def __init__(self, commandPostfix, chain):
        super(PostfixExecutor, self).__init__()

        self.commandPostfix = commandPostfix
        self.chain = chain

    def run(self, exe_path, cmd=None, work_dir='.', file_deps=None, env=None):
        cmd = cmd or [exe_path]
        return self.chain.run(cmd + self.commandPostfix, work_dir, file_deps,
                              env=env)



class TimeoutExecutor(PrefixExecutor):
    """Execute another action under a timeout.

    Deprecated. http://reviews.llvm.org/D6584 adds timeouts to LIT.
    """
    def __init__(self, duration, chain):
        super(TimeoutExecutor, self).__init__(
            ['timeout', duration], chain)


class RemoteExecutor(Executor):
    is_remote = True

    def __init__(self):
        self.local_run = executeCommand
        self.keep_test = False

    def remote_temp_dir(self):
        return self._remote_temp(True)

    def remote_temp_file(self):
        return self._remote_temp(False)

    def _remote_temp(self, is_dir):
        raise NotImplementedError()

    def copy_in(self, local_srcs, remote_dsts):
        # This could be wrapped up in a tar->scp->untar for performance
        # if there are lots of files to be copied/moved
        for src, dst in zip(local_srcs, remote_dsts):
            self._copy_in_file(src, dst)

    def _copy_in_file(self, src, dst):
        raise NotImplementedError()

    def delete_remote(self, remote):
        try:
            self._execute_command_remote(['rm', '-rf', remote])
        except OSError:
            # TODO: Log failure to delete?
            pass

    def run(self, exe_path, cmd=None, work_dir='.', file_deps=None, env=None):
        target_exe_path = None
        target_cwd = None
        try:
            target_cwd = self.remote_temp_dir()
            target_exe_path = os.path.join(target_cwd, os.path.basename(exe_path))
            if cmd:
                # Replace exe_path with target_exe_path.
                cmd = [c if c != exe_path else target_exe_path for c in cmd]
            else:
                cmd = [target_exe_path]

            if self.config and self.config.lit_config.run_with_debugger:
                # Use "thread apply all bt" instead of "bt" to ensure a successful exit doesn't
                # result in GDB returning a non-zero exit code due to missing stack
                cmd = ["gdb", "--quiet", "--batch", "--return-child-result", "-ex=r",
                       "-ex=thread apply all bt", "--args"] + cmd

            srcs = [exe_path]
            dsts = [target_exe_path]
            if file_deps is not None:
                dev_paths = [os.path.join(target_cwd, os.path.basename(f))
                             for f in file_deps]
                srcs.extend(file_deps)
                dsts.extend(dev_paths)
            self.copy_in(srcs, dsts)
            # TODO(jroelofs): capture the copy_in and delete_remote commands,
            # and conjugate them with '&&'s around the first tuple element
            # returned here:
            (remote_cmd, out, err, rc) = self._execute_command_remote(cmd, target_cwd, env)
            self.keep_test = rc != 0
            return remote_cmd, out, err, rc
        finally:
            if target_cwd and not self.keep_test:
                self.delete_remote(target_cwd)

    def _execute_command_remote(self, cmd, remote_work_dir='.', env=None):
        raise NotImplementedError()


class SSHExecutor(RemoteExecutor):
    def __init__(self, host, username=None, port=None, config=None, extra_ssh_flags=None, extra_scp_flags=None):
        super(SSHExecutor, self).__init__()

        self.user_prefix = username + '@' if username else ''
        self.host = host
        self.port = port
        self.config = config
        self.scp_command = ['scp'] if port is None else ['scp', '-P', str(port)]
        if extra_scp_flags:
            self.scp_command.extend(extra_scp_flags)
        self.ssh_command = ['ssh'] if port is None else ['ssh', '-p', str(port)]
        if extra_ssh_flags:
            self.ssh_command.extend(extra_ssh_flags)
        self.remote_host_failed_connections = 0

        # TODO(jroelofs): switch this on some -super-verbose-debug config flag
        # TODO: this breaks multiprocessing
        if self.config and self.config.lit_config.debug and False:
            self.local_run = tracing.trace_function(
                self.local_run, log_calls=True, log_results=True,
                label='ssh_local')

    def _remote_temp(self, is_dir, is_retry=False):
        # TODO: detect what the target system is, and use the correct
        # mktemp command for it. (linux and darwin differ here, and I'm
        # sure windows has another way to do it)

        # Not sure how to do suffix on osx yet
        dir_arg = '-d' if is_dir else ''
        cmd = 'mktemp -q {} /tmp/libcxx.XXXXXXXXXX'.format(dir_arg)
        _, temp_path, err, exitCode = self._execute_command_remote([cmd])
        temp_path = temp_path.strip()
        if exitCode != 0:
            if not is_retry and "write: Broken pipe" in err:
                # try again
                return self._remote_temp(is_dir, is_retry=True)
            raise RuntimeError("mktemp failed: " + err)
        return temp_path

    def _copy_in_file(self, src, dst):
        remote = self.host
        remote = self.user_prefix + remote
        cmd = self.scp_command + ['-p', src, remote + ':' + dst]
        if self.config and self.config.lit_config.debug:
            print('{}: Copying {} to {}'.format(datetime.datetime.now(), src, dst), file=sys.stderr)
        self.local_run(cmd)

    def _execute_command_remote(self, cmd, remote_work_dir='.', env=None):
        remote = self.user_prefix + self.host
        # Add -tt to force a TTY allocation so that the remote process is killed
        # when SSH exits.
        ssh_cmd = self.ssh_command + ['-tt', '-oBatchMode=yes', remote]
        # FIXME: doesn't handle spaces... and Py2.7 doesn't have shlex.quote()
        if env:
            env_cmd = ['env'] + ['%s=%s' % (k, v) for k, v in env.items()]
        else:
            env_cmd = []
        remote_cmd = ' '.join(map(pipes.quote, env_cmd + cmd))
        if remote_work_dir != '.':
            remote_cmd = 'cd ' + pipes.quote(remote_work_dir) + ' && ' + remote_cmd
        if self.config and self.config.lit_config.debug:
            print('{}: About to run {}'.format(datetime.datetime.now(), remote_cmd), file=sys.stderr)
        out, err, rc = self.local_run(ssh_cmd + [remote_cmd], timeout=self.config.lit_config.maxIndividualTestTime)
        if self.config and self.config.lit_config.debug:
            print('{}: Remote command completed'.format(datetime.datetime.now()), file=sys.stderr)
        if rc != 0:
            is_connection_failed_error = False
            if "Connection closed by remote host" in err:
                is_connection_failed_error = True
            elif "ssh_exchange_identification: read: Connection reset by peer" in err:
                is_connection_failed_error = True
            elif "ssh: connect to host" in err and ": Connection refused" in err:
                is_connection_failed_error = True
            if is_connection_failed_error:
                # accept up to N failed connections before giving up
                self.config.lit_config.warning("Remote host seems to have died?: " + " ".join(ssh_cmd))
                self.remote_host_failed_connections += 1
                raise ExecuteCommandTimeoutException("REMOTE HOST SEEMS DEAD", out, err, rc, command=ssh_cmd + [remote_cmd])
        return ssh_cmd + [remote_cmd], out, err, rc

    def run(self, *args, **kwargs):
        # If more than N connections to the remote host failed we assume the
        # QEMU instance has wedged and just give up instead of timing out
        MAX_FAILED_CONNECTIONS = 10
        if self.remote_host_failed_connections > MAX_FAILED_CONNECTIONS:
            cmd = [] if "cmd" not in kwargs or kwargs["cmd"] is None else kwargs["cmd"]
            raise ExecuteCommandTimeoutException("REMOTE HOST SEEMS DEAD", "", "", 1, command=cmd)
        return super(SSHExecutor, self).run(*args, **kwargs)


class SSHExecutorWithNFSMount(SSHExecutor):
    def __init__(self, host, nfs_dir, path_in_target, config=None, username=None, port=None, extra_ssh_flags=None, extra_scp_flags=None):
        super(SSHExecutorWithNFSMount, self).__init__(
            host, config=config, username=username, port=port,
            extra_ssh_flags=extra_ssh_flags, extra_scp_flags=extra_scp_flags)
        self.nfs_dir = nfs_dir
        if not self.nfs_dir.endswith('/'):
            self.nfs_dir = self.nfs_dir + '/'
        self.path_in_target = path_in_target
        if not self.path_in_target.endswith('/'):
            self.path_in_target = self.path_in_target + '/'
        # TODO: this breaks multiprocessing
        if self.config and self.config.lit_config.debug and False:
            self._remote_temp = tracing.trace_function(
                self._remote_temp, log_calls=False, log_results=True,
                label='ssh-exec')
            self._copy_in_file = tracing.trace_function(
                self._copy_in_file, log_calls=True, log_results=False,
                label='ssh-exec')
            self.delete_remote = tracing.trace_function(
                self.delete_remote, log_calls=True, log_results=False,
                label='ssh-exec')
            self.run = tracing.trace_function(
                self.run, log_calls=True, log_results=True, label='ssh-exec')

    def _copy_in_file(self, src, dst):
        if not dst.startswith(self.nfs_dir):
            raise NotImplementedError('Cannot copy file %s to directory that is not below %s: %s'
                                      % (src, self.nfs_dir, dst))
        if self.config and self.config.lit_config.debug:
            print('{}: About to run cp \'{}\' \'{}\''.format(datetime.datetime.now(), src, dst), file=sys.stderr)
        shutil.copy(src, dst)

    def delete_remote(self, remote):
        # TODO: add an option to keep failing tests
        if not remote.startswith(self.nfs_dir):
            raise NotImplementedError('Cannot delete file that is not below %s: %s'
                                      % (self.nfs_dir, remote))
        else:
            if self.config and self.config.lit_config.debug:
                print('{}: About to run rm -rf {}'.format(datetime.datetime.now(), remote), file=sys.stderr)
            shutil.rmtree(remote)

    def _remote_temp(self, is_dir, is_retry=False):
        if is_dir:
            return tempfile.mkdtemp(prefix="libcxx-", dir=self.nfs_dir)
        else:
            return tempfile.mkstemp(prefix="libcxx-", dir=self.nfs_dir)

    def _execute_command_remote(self, cmd, remote_work_dir='.', env=None):
        if remote_work_dir != ".":
            if not remote_work_dir.startswith(self.nfs_dir):
                return cmd, None, "Custom remote_work_dir not implemented: %r" % remote_work_dir, 42
            remote_work_dir = remote_work_dir.replace(self.nfs_dir, self.path_in_target)
        if env:
            env.update((k, v.replace(self.nfs_dir, self.path_in_target)) for k, v in env.items())
            # return cmd, None, "Custom env not implemented: %r" % env, 42
        if all(self.nfs_dir not in s for s in cmd):
            raise NotImplementedError("Cannot run non-test binaries: Command was: %s" % cmd)
        cmd = [s.replace(self.nfs_dir, self.path_in_target) for s in cmd]
        return super(SSHExecutorWithNFSMount, self)._execute_command_remote(cmd, remote_work_dir=remote_work_dir, env=env)
