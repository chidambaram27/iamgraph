FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy PATH="/app/.venv/bin:$PATH"

COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-install-project

COPY src ./src
COPY tests ./tests
COPY scripts ./scripts
RUN uv sync --frozen

ENTRYPOINT ["sh", "-c", "iamgraph load >/dev/null && exec \"$@\"", "--"]
CMD ["iamgraph", "scan"]
