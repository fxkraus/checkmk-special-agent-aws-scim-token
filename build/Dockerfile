# Latest Checkmk 2.5 patch release. The tag floats on purpose, so it is not
# managed by Dependabot. CI resolves it to a digest once per run and passes
# CHECKMK_IMAGE, so tests, MKP build and release all use the same image.
ARG CHECKMK_IMAGE=docker.io/checkmk/check-mk-ultimatemt:2.5.0-latest
FROM ${CHECKMK_IMAGE}

# Initialize the CheckMK site at build time so it is cached in the image layer.
# This avoids the ~25 s penalty of running /docker-entrypoint.sh on every container start.
RUN /docker-entrypoint.sh /bin/true

COPY build/build-entrypoint.sh /build-entrypoint.sh
COPY build/build-modify-extension.py /build-modify-extension.py

RUN chmod +x /build-entrypoint.sh /build-modify-extension.py

ENTRYPOINT ["/build-entrypoint.sh"]
