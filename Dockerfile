# The project runs from a clone with no Python environment at all:
#   docker compose up
# Then open http://localhost:8000
#
# The image installs only runtime dependencies. Tests are not in it on purpose:
# pytest, pytest-cov and friends are dev dependencies, and a demo image that
# ships a test runner is a demo image carrying dead weight.
FROM python:3.12-slim

# Without this, Python writes .pyc files and buffers stdout, and a container log
# that arrives minutes late is a container that looks hung.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Dependencies are installed from the project metadata in their own layer, so a
# source change does not invalidate the installed packages. app/ and scripts/ are
# both copied first: pyproject declares the `entra-analyze` console script, and
# copying scripts/ after the install would leave that entry point pointing at a
# module that was not in the distribution.
COPY pyproject.toml README.md ./
COPY app ./app
COPY scripts ./scripts
RUN pip install --no-cache-dir .

# The dashboard and CLI both need the sample data and somewhere writable to put
# the database. The database lives in the volume below, so the image only needs
# the sample data.
COPY data ./data
RUN useradd --create-home --uid 1000 appuser && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

# The health endpoint is the same one the dashboard's data comes from, so a
# container that starts but cannot open the database is reported as unhealthy
# rather than as a running service.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/api/health', timeout=4).status == 200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
