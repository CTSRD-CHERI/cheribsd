#!/usr/bin/env python3
from pathlib import Path
import argparse
import shlex
import subprocess
import os
import sys


parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
docker_images_dir = Path(__file__).parent / "docker"
local_docker_images = list(os.listdir(str(docker_images_dir)))
parser.add_argument("--local-docker-image", choices=local_docker_images, default="ubuntu",
                    help="Which directory in tools/build/crossbuild/docker to use as a source for the Dockerfile")
parser.add_argument("--external-docker-image",
                    help="Build with an existing docker image instead of using the Dockerfiles from the source tree")
try:
    import argcomplete  # bash completion:
    argcomplete.autocomplete(parser)
except ImportError:
    pass
parsed_args, bmake_args = parser.parse_known_args()

if parsed_args.external_docker_image:
    docker_image = parsed_args.external_docker_image
else:
    docker_image = "freebsd-crossbuild-" + parsed_args.local_docker_image
    dockerfile_dir = docker_images_dir / parsed_args.local_docker_image
    dockerfile = dockerfile_dir / "Dockerfile"
    if not dockerfile.exists():
        sys.exit("Invalid choice for --local-docker-image: " + str(dockerfile) +
                 " is missing.")
    build_cmd = ["docker", "build", "-q", "-t", docker_image, str(dockerfile_dir)]
    print("Running", build_cmd)
    subprocess.check_call(build_cmd)

makeobjdirprefix = os.getenv("MAKEOBJDIRPREFIX")
if not makeobjdirprefix:
    sys.exit("Must set MAKEOBJDIRPREFIX")
if not Path(makeobjdirprefix).is_dir():
    sys.exit("MAKEOBJDIRPREFIX must be a directory")
makeobjdirprefix = str(Path(makeobjdirprefix).absolute())
srcroot = Path(__file__).parent.parent.parent.parent
if not (srcroot / "Makefile.inc1").exists():
    sys.exit("script moved but srcroot not updated")
srcroot = str(srcroot.resolve())

env_flags = ["--env", "MAKEOBJDIRPREFIX=/build"]
make_args = []

if docker_image == "freebsd-crossbuild-opensuse":
    make_args += [
        # "--host-bindir=/usr/bin",
        "--cross-bindir=/usr/bin",
    ]
elif docker_image == "freebsd-crossbuild-ubuntu":
    # Build everything with clang 7.0 (using /usr/bin/cc causes strange errors)
    env_flags += [
        "--env", "LD=/usr/bin/ld",
    ]
    make_args += [
        "--host-bindir=/usr/lib/llvm-9/bin",
        "--cross-bindir=/usr/lib/llvm-9/bin",
        "--host-compiler-type=clang",
    ]
elif docker_image == "freebsd-crossbuild-alpine":
    env_flags += [
    ]
    make_args += [
        "--host-bindir=/usr/bin",
        "--cross-bindir=/usr/bin",
        "--host-compiler-type=clang",
    ]
elif docker_image == "freebsd-crossbuild-arch":
    env_flags += [
    ]
    make_args += [
        "--host-bindir=/usr/bin",
        "--cross-bindir=/usr/bin",
        "--host-compiler-type=clang",
    ]
elif docker_image == "freebsd-crossbuild-centos":
    env_flags += [
        "--env", "XLD=/usr/bin/ld",
    ]
    make_args += [
        "--host-bindir=/usr/bin",
        "--cross-bindir=/opt/llvm-5.0.1/bin",
        # somehow usr.bin/dtc fails with the libstdc++ version shipped with centos
        "-DWITH_GPL_DTC",
    ]

docker_args = ["docker", "run", "-it", "--rm",
               # mount the FreeBSD sources read-only
               "-v", str(srcroot) + ":" + srcroot + ":ro",
               "-v", makeobjdirprefix + ":/build",
               # "-v", makeobjdirprefix + ":/output",
               ] + env_flags + [docker_image]
make_cmd = [srcroot + "/tools/build/make.py"] + make_args + bmake_args
print("Running", " ".join(shlex.quote(s) for s in docker_args + make_cmd))
os.execvp("docker", docker_args + make_cmd)
