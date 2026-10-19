# Both arguments must be reviewed immutable digests before building.
ARG RAMA_IMAGE
ARG TOOLS_BASE_IMAGE
FROM ${RAMA_IMAGE} AS rama
FROM ${TOOLS_BASE_IMAGE}

USER root
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install --no-install-recommends -y \
    ca-certificates python3 python3-venv postgresql tshark && \
    rm -rf /var/lib/apt/lists/* && \
    (getent passwd 1000 || useradd --uid 1000 --create-home evidence)
COPY --from=rama /app/rama /app/rama
ARG RAMA_BINARY_SHA256
RUN test -n "$RAMA_BINARY_SHA256" && \
    printf '%s  /app/rama\n' "$RAMA_BINARY_SHA256" | sha256sum --check

WORKDIR /opt/evidence/repo
COPY examples/tests/browser_profile examples/tests/browser_profile
COPY rama-fp/browser_automation rama-fp/browser_automation
COPY rama-fp/browserstack/matrix.py rama-fp/browserstack/matrix.py
RUN python3 -m venv /opt/evidence && \
    /opt/evidence/bin/pip install --no-cache-dir --only-binary=:all: \
        -r examples/tests/browser_profile/requirements.txt && \
    /opt/evidence/bin/python -c 'import sys; assert sys.version_info >= (3, 12)' && \
    /opt/evidence/bin/python -c 'import sys; sys.path.insert(0,"examples/tests/browser_profile"); from fixture_process import require_h3_tshark; require_h3_tshark()' && \
    test "$(ls -d /usr/lib/postgresql/*/bin | wc -l)" -eq 1

# The VM runs a finite lease; the SSH helper owns only its own child processes.
ENTRYPOINT ["/opt/evidence/bin/python", "/opt/evidence/repo/examples/tests/browser_profile/remote/helper.py", "lease"]
