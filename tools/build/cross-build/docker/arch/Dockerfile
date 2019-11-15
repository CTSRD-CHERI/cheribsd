FROM archlinux/base:latest
LABEL maintainer="arichardson@FreeBSD.org"
RUN pacman -Sy && pacman -S --noconfirm clang lld autoconf binutils make automake python patch git which inetutils gperf readline awk aarch64-linux-gnu-binutils
RUN pacman -Syu --noconfirm

VOLUME ["/source", "/build", "/output"]
CMD /bin/bash
