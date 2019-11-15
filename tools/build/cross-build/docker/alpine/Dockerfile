FROM alpine:latest
LABEL maintainer="arichardson@FreeBSD.org"

# Note: even though we build with clang, gcc and musl-dev
# are needed to build any host binary
RUN apk add gcc musl-dev linux-headers git python3 binutils autoconf automake lld libtool make clang


VOLUME ["/source", "/build", "/output"]
CMD /bin/bash
