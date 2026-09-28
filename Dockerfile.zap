# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM gradle:8.13-jdk17-alpine@sha256:849f12df262884668387cf463f02e104394fde950689cc9f644764cde22a2c13 AS network-builder

ARG CERBERUS_ZAP_NETWORK_COMMIT=d7e0725adb263b5cd4d34bc6dd395004ec865360

USER root
RUN apk add --no-cache git \
    && git init /src \
    && git -C /src remote add origin https://github.com/zaproxy/zap-extensions.git \
    && git -C /src fetch --depth 1 origin "${CERBERUS_ZAP_NETWORK_COMMIT}" \
    && git -C /src checkout --detach FETCH_HEAD \
    && sed -i 's@mavenCentral()@maven(url = "https://maven-central.storage-download.googleapis.com/maven2")@g' \
       /src/settings.gradle.kts /src/build.gradle.kts \
       /src/buildSrc/settings.gradle.kts /src/buildSrc/build.gradle.kts \
    && cd /src \
    && ./gradlew :addOns:network:jarZapAddOn --no-daemon \
    && test -s /src/addOns/network/build/zapAddOn/bin/network-beta-0.30.0.zap

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

ARG CERBERUS_ZAP_VERSION=2.17.0
ARG CERBERUS_ZAP_SHA256=94c8f767b1c2e94f0db66b3ae56514d5e3f5a728ee1b6c798e0c8fe2d61fbff0
ARG CERBERUS_VERSION=0.2.0
ARG CERBERUS_REVISION=unknown
ARG CERBERUS_CREATED=unknown

LABEL org.opencontainers.image.title="Cerberus ZAP worker" \
      org.opencontainers.image.description="Minimal multi-architecture OWASP ZAP runtime for Cerberus" \
      org.opencontainers.image.source="https://github.com/vaxman14/cerberus-selfhost" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${CERBERUS_VERSION}" \
      org.opencontainers.image.revision="${CERBERUS_REVISION}" \
      org.opencontainers.image.created="${CERBERUS_CREATED}"

COPY --from=network-builder /src/addOns/network/build/zapAddOn/bin/network-beta-0.30.0.zap /network-fixed.zap

RUN apk upgrade --no-cache \
    && apk add --no-cache bash ca-certificates curl openjdk17-jre-headless unzip zip \
    && curl --fail --location --proto '=https' --tlsv1.2 \
      "https://github.com/zaproxy/zaproxy/releases/download/v${CERBERUS_ZAP_VERSION}/ZAP_${CERBERUS_ZAP_VERSION}_Crossplatform.zip" \
      --output /tmp/zap.zip \
    && echo "${CERBERUS_ZAP_SHA256}  /tmp/zap.zip" | sha256sum -c - \
    && unzip -q /tmp/zap.zip -d /opt \
    && mv "/opt/ZAP_${CERBERUS_ZAP_VERSION}" /zap \
    && rm -f /tmp/zap.zip \
    && rm -f /zap/plugin/*.zap \
    && fetch() { \
         url="$1"; output="$2"; digest="$3"; \
         curl --fail --location --proto '=https' --tlsv1.2 "$url" --output "$output"; \
         echo "$digest  $output" | sha256sum -c -; \
       } \
    && fetch https://github.com/zaproxy/zap-extensions/releases/download/commonlib-v1.44.0/commonlib-release-1.44.0.zap /zap/plugin/commonlib-release-1.44.0.zap 6450205e07248c20e9c8de185268cf1cd571f3cec7f7c0e5d10178b2126834f9 \
    && fetch https://github.com/zaproxy/zap-extensions/releases/download/callhome-v0.23.0/callhome-release-0.23.0.zap /zap/plugin/callhome-release-0.23.0.zap eadebd4ae60c1865f6811a276a643ebe954328e2e903447bf460d8b3ef691d7f \
    && mv /network-fixed.zap /zap/plugin/network-beta-0.30.0.zap \
    && fetch https://github.com/zaproxy/zap-extensions/releases/download/spider-v0.20.0/spider-release-0.20.0.zap /zap/plugin/spider-release-0.20.0.zap 82acf7e307fdd4f46ac4d387656370ecad9c2ab940e1c81d9776768bacdedcd5 \
    && fetch https://github.com/zaproxy/zap-extensions/releases/download/ascanrules-v83/ascanrules-release-83.zap /zap/plugin/ascanrules-release-83.zap 9c1b64c2fceda629f7c0ab0c21b5901035494f78da51d584972eaf85e94e91cc \
    && fetch https://github.com/zaproxy/zap-extensions/releases/download/pscanrules-v76/pscanrules-release-76.zap /zap/plugin/pscanrules-release-76.zap 6201955247e538ddf8d11fd4332450e5821dbf419dbd29ed616b2909e9aabcaa \
    && fetch https://github.com/zaproxy/zap-extensions/releases/download/database-v0.9.0/database-alpha-0.9.0.zap /zap/plugin/database-alpha-0.9.0.zap 4c58ca142288d9ddc6ae3fd8fe6815e3894462bae67eb0776e540a2d9ddaf87d \
    && fetch https://github.com/zaproxy/zap-extensions/releases/download/oast-v0.26.0/oast-beta-0.26.0.zap /zap/plugin/oast-beta-0.26.0.zap d1471b0bbcd75315d7d142bbd4675d950aefbd31ad39e999b6df8f09a97bda0e \
    && fetch https://github.com/zaproxy/zap-extensions/releases/download/pscan-v0.6.0/pscan-alpha-0.6.0.zap /zap/plugin/pscan-alpha-0.6.0.zap 269ff66f0d8a8012f156e90e13238606a8d503b99521170649b62c9aa7295927 \
    && mkdir /tmp/database \
    && cd /tmp/database \
    && unzip -q /zap/plugin/database-alpha-0.9.0.zap \
    && fetch https://maven-central.storage-download.googleapis.com/maven2/com/fasterxml/jackson/core/jackson-annotations/2.21/jackson-annotations-2.21.jar /tmp/jackson-annotations-2.21.jar 53ca085f4a150f703f49e1aabd935bd03b43e1ea3d55d135438292af22cef56b \
    && fetch https://maven-central.storage-download.googleapis.com/maven2/com/fasterxml/jackson/core/jackson-core/2.21.4/jackson-core-2.21.4.jar /tmp/jackson-core-2.21.4.jar 4b40a06396f239f8de2da57419adde6e94e5edc18a2171d471ea05eeed4e5c2d \
    && fetch https://maven-central.storage-download.googleapis.com/maven2/com/fasterxml/jackson/core/jackson-databind/2.21.4/jackson-databind-2.21.4.jar /tmp/jackson-databind-2.21.4.jar 3888e9e69ab66fbacaacc9aea0e9ffbf15368288e4aca468b024dba11c09fbf9 \
    && rm -f libs/jackson-annotations-2.19.1.jar libs/jackson-core-2.19.1.jar libs/jackson-databind-2.19.1.jar \
    && mv /tmp/jackson-annotations-2.21.jar /tmp/jackson-core-2.21.4.jar /tmp/jackson-databind-2.21.4.jar libs/ \
    && sed -i 's/jackson-annotations-2\.19\.1\.jar/jackson-annotations-2.21.jar/g; s/jackson-core-2\.19\.1\.jar/jackson-core-2.21.4.jar/g; s/jackson-databind-2\.19\.1\.jar/jackson-databind-2.21.4.jar/g' ZapAddOn.xml \
    && rm -f /zap/plugin/database-alpha-0.9.0.zap \
    && zip -qr /zap/plugin/database-alpha-0.9.0.zap . \
    && cd / \
    && rm -rf /tmp/database \
    && addgroup -g 1000 zap \
    && adduser -D -u 1000 -G zap -h /home/zap -s /bin/bash zap \
    && mkdir -p /home/zap/.ZAP /zap/wrk \
    && find /zap/plugin -name '*.zap' -exec unzip -tq {} \; \
    && test -s /zap/zap-2.17.0.jar \
    && chown -R zap:zap /home/zap /zap

ENV PATH="/zap:${PATH}" \
    ZAP_PATH=/zap/zap.sh \
    HOME=/home/zap \
    ZAP_PORT=8080 \
    IS_CONTAINERIZED=true \
    JAVA_TOOL_OPTIONS=-Djava.awt.headless=true

WORKDIR /zap
USER zap
EXPOSE 8080
HEALTHCHECK --interval=20s --timeout=8s --start-period=30s --retries=6 \
  CMD wget -q -O- http://127.0.0.1:8080/ >/dev/null

CMD ["zap.sh", "-daemon", "-silent", "-host", "0.0.0.0", "-port", "8080"]
