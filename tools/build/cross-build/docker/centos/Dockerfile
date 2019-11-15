FROM centos:7
LABEL maintainer="arichardson@FreeBSD.org"

RUN yum -y update && yum -y install yum-plugin-copr git
RUN yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
RUN yum -y copr enable alonid/llvm-5.0.1
# clang 5.0 is too old (but let's try anyway)
RUN yum -y install clang-5.0.1

# The step before takes forever, don't add anything before
RUN yum -y install python36

RUN yum -y install autoconf automake libtool

RUN yum -y install cross-binutils-common
RUN ln -s /usr/bin/python3.6 /usr/bin/python3

RUN yum -y install make which

RUN yum -y install lsb-release which bzip2 gperf zlib-devel libbz2-devel libarchive-devel

RUN yum -y install patch bzip2-devel

VOLUME ["/source", "/build", "/output"]
CMD /bin/bash
