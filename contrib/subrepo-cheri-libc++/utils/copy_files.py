#!/usr/bin/env python3
#===----------------------------------------------------------------------===##
#
# Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
# See https://llvm.org/LICENSE.txt for license information.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
#===----------------------------------------------------------------------===##

"""copy_files.py is a utility for collecting test binaries (possibly with code signing) in a given directory."""

import argparse
import os
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--execdir', type=str, required=True)
    parser.add_argument('--output-dir', type=str, required=True)
    parser.add_argument('--codesign_identity', type=str, required=False, default=None)
    parser.add_argument('--env', type=str, nargs='*', required=False, default=dict())
    (args, remaining) = parser.parse_known_args(sys.argv[1:])

    if len(remaining) < 2:
        sys.stderr.write('Missing actual commands to run')
        exit(1)
    commandLine = remaining[1:] # Skip the '--'

    # Do any necessary codesigning.
    if args.codesign_identity:
        exe = commandLine[0]
        rc = subprocess.call(['xcrun', 'codesign', '-f', '-s', args.codesign_identity, exe], env={})
        if rc != 0:
            sys.stderr.write('Failed to codesign: ' + exe)
            return rc

    # Copy the executable to the output directory
    target_dir = args.output_dir
    print("Copying", args.execdir, "to", target_dir, flush=True)
    if not os.path.isdir(target_dir):
        os.makedirs(target_dir)
    subprocess.check_call(["cp", "-av", args.execdir, target_dir])

if __name__ == '__main__':
    exit(main())
