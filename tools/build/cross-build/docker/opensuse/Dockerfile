FROM opensuse/leap:15.1
LABEL maintainer="arichardson@FreeBSD.org"

# Install clang 9.0
RUN zypper addrepo http://download.opensuse.org/repositories/devel:/tools:/compiler/openSUSE_Leap_15.1/devel:tools:compiler.repo && \
	zypper --gpg-auto-import-keys refresh && zypper -n install -y clang9 lld9

RUN zypper -n refresh && zypper -n install -y \
  python3-base gcc-c++ hostname patch which git-core \
  lsb-release which libtool automake autoconf make gzip \
  bzip2 gperf zlib-devel libbz2-devel libarchive-devel

VOLUME ["/source", "/build", "/output"]
CMD /bin/bash
