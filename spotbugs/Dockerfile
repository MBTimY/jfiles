FROM golang:1.15 AS build
ENV CGO_ENABLED=0 GOOS=linux
WORKDIR /go/src/app
COPY . .
RUN go env -w  GOPROXY=https://goproxy.cn,direct && go build -o analyzer

FROM alpine:3.12

ARG ANT_VERSION
ARG FINDSECBUGS_VERSION
ARG GRAILS_VERSION
ARG GRADLE_VERSION
ARG MAVEN_VERSION
ARG SBT_VERSION
ARG SCALA_VERSION
ARG JAVA_8_VERSION
ARG JAVA_11_VERSION
ARG SPOTBUGS_VERSION
ARG GLIBC_VERSION=2.31-r0
ARG ZLIB_VERSION=1:1.2.11-4-x86_64
ARG ZLIB_SHA1SUM=be23c6422981570d2656623d4d5b0ab57703a1ed
ARG GCC_LIBS_VERSION=10.1.0-1-x86_64
ARG GCC_LIBS_SHA1SUM=8933549c3f3b333183b1b0c415d188f320c5ce9f

ENV ANT_VERSION ${ANT_VERSION:-1.10.1}
ENV FINDSECBUGS_VERSION ${FINDSECBUGS_VERSION:-1.10.1}
ENV GRAILS_VERSION ${GRAILS_VERSION:-4.0.3}
ENV GRADLE_VERSION ${GRADLE_VERSION:-6.4.1}
ENV MAVEN_VERSION ${MAVEN_VERSION:-3.6.3}
ENV SBT_VERSION ${SBT_VERSION:-1.3.10}
ENV SCALA_VERSION ${SCALA_VERSION:-2.13.1}
ENV JAVA_8_VERSION ${JAVA_8_VERSION:-8.0.265.hs-adpt}
ENV JAVA_11_VERSION ${JAVA_11_VERSION:-11.0.8.hs-adpt}
ENV SPOTBUGS_VERSION ${SPOTBUGS_VERSION:-4.0.2}
ENV SDKMAN_DIR="/usr/local/sdkman"
ENV SDK_CAND="$SDKMAN_DIR/candidates"
ENV JAVA_HOME="$SDK_CAND/java/current"

RUN apk add --no-cache bash curl zip zstd
USER 0

# glibc
RUN curl -LSs https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub -o /etc/apk/keys/sgerrand.rsa.pub \
    && curl -LSs https://github.com/sgerrand/alpine-pkg-glibc/releases/download/$GLIBC_VERSION/glibc-$GLIBC_VERSION.apk > /tmp/glibc.apk \
    && apk add /tmp/glibc.apk \
    && rm /tmp/glibc.apk

# zlib
RUN curl -LSs https://archive.archlinux.org/packages/z/zlib/zlib-$ZLIB_VERSION.pkg.tar.xz -o /tmp/zlib.tar.xz \
    && echo "$ZLIB_SHA1SUM  /tmp/zlib.tar.xz" | sha1sum -c \
    && mkdir -p /tmp/zlib && tar xvf /tmp/zlib.tar.xz -C /tmp/zlib \
    && cp /tmp/zlib/usr/lib/libz.* /usr/glibc-compat/lib/ \
    && rm -rf /tmp/zlib /tmp/zlib.tar.xz

# gcc libs
RUN apk add --no-cache binutils \
    && curl -LSs https://archive.archlinux.org/packages/g/gcc-libs/gcc-libs-$GCC_LIBS_VERSION.pkg.tar.zst -o /tmp/gcc-libs.tar.zst \
    && echo "$GCC_LIBS_SHA1SUM  /tmp/gcc-libs.tar.zst" | sha1sum -c \
    && mkdir -p /tmp/gcc-libs \
    && zstd -d /tmp/gcc-libs.tar.zst && tar xvf /tmp/gcc-libs.tar -C /tmp/gcc-libs \
    && mv /tmp/gcc-libs/usr/lib/libgcc* /tmp/gcc-libs/usr/lib/libstdc++* /usr/glibc-compat/lib \
    && strip /usr/glibc-compat/lib/libgcc_s.so.* \
    && strip /usr/glibc-compat/lib/libstdc++.so.* \
    && rm -rf /tmp/gcc-libs /tmp/gcc-libs.tar.xz \
    && apk del binutils

# Install SDK man for SDK installations
# The folder sdkman/ contains a vendored version of the
# script, so we can diff it with newer versions if needed.
# See https://gitlab.com/gitlab-org/security-products/analyzers/spotbugs/-/merge_requests/39
COPY sdkman/sdkman.sha1sum sdkman/sdkman.sha1sum
RUN curl -s https://get.sdkman.io -o sdkman.sh \
    && cat sdkman/sdkman.sha1sum | sha1sum -c \
    && /bin/bash sdkman.sh \
    && rm sdkman.sh

# Install SDKs
RUN /bin/bash -c "\
  source ${SDKMAN_DIR}/bin/sdkman-init.sh && \
  sdk install ant $ANT_VERSION && \
  sdk install gradle $GRADLE_VERSION && \
  sdk install grails $GRAILS_VERSION && \
  sdk install maven $MAVEN_VERSION && \
  sdk install scala $SCALA_VERSION && \
  sdk install sbt $SBT_VERSION && \
  sdk install java $JAVA_8_VERSION && \
  sdk install java $JAVA_11_VERSION && \
  sdk default java $JAVA_8_VERSION"

# Install SpotBugs CLI
COPY spotbugs /spotbugs
RUN cd /spotbugs && \
  mkdir -p dist && \
  wget https://repo.maven.apache.org/maven2/com/github/spotbugs/spotbugs/${SPOTBUGS_VERSION}/spotbugs-${SPOTBUGS_VERSION}.tgz && \
  tar xzf spotbugs-${SPOTBUGS_VERSION}.tgz -C dist --strip-components 1 && \
  rm -f spotbugs-${SPOTBUGS_VERSION}.tgz

# Install FindSecBugs for use as a SpotBugs plugin
RUN mkdir -p /fsb && \
  cd /fsb && \
  wget https://github.com/find-sec-bugs/find-sec-bugs/releases/download/version-${FINDSECBUGS_VERSION}/findsecbugs-cli-${FINDSECBUGS_VERSION}.zip && \
  unzip -n findsecbugs-cli-${FINDSECBUGS_VERSION}.zip && \
  rm -f findsecbugs-cli-${FINDSECBUGS_VERSION}.zip && \
  mv lib/findsecbugs-plugin-${FINDSECBUGS_VERSION}.jar lib/findsecbugs-plugin.jar

# Install analyzer
COPY --from=build --chown=root:root /go/src/app/analyzer /

ENV PATH="${JAVA_HOME}/bin:${SDK_CAND}/ant/current/bin:${SDK_CAND}/gradle/current/bin:${SDK_CAND}/grails/current/bin:${SDK_CAND}/maven/current/bin:${SDK_CAND}/scala/current/bin:${SDK_CAND}/sbt/current/bin:${PATH}"

ENTRYPOINT []
ADD start.sh /
RUN chmod +x /start.sh
CMD ["/start.sh"]
