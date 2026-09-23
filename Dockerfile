FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY cloudmesh_sentinel/cli.py cloudmesh_sentinel/__init__.py ./cloudmesh_sentinel/
COPY examples/demo-plan.json examples/safe-plan.json examples/gcp-network-risk-plan.json ./examples/

# The scanner needs no packages, writable application files, or root privileges.
USER 10001:10001
ENTRYPOINT ["python", "-m", "cloudmesh_sentinel.cli"]
CMD ["--help"]
