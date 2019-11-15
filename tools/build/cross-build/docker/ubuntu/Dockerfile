FROM ubuntu:18.04
LABEL maintainer="arichardson@FreeBSD.org"

RUN apt-get update && apt-get install -y --no-install-recommends \
  make ninja-build git ca-certificates python3-minimal \
  lsb-release wget gnupg \
  bzip2 gperf libz-dev libbz2-dev libarchive-dev

# Clang 9.0 is in a separate repository
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
RUN echo "deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-9 main" > /etc/apt/sources.list.d/llvm.list
RUN apt-get update && apt-get install -y --no-install-recommends clang-9 lld-9

RUN apt-get install -y patch

VOLUME ["/source", "/build", "/output"]
CMD /bin/bash
