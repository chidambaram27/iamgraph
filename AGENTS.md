# Agent instructions

1. Read `README.md` first: graph model, the Cypher each tool runs, and the architecture.
2. Before finishing: `uv run iamgraph load && uv run pytest -q` must pass.
3. Keep FalkorDB load-bearing: permissions must be edges, never queried JSON blobs.
4. New edge type ⇒ add a branch in `tools._candidates`, a kind in `KIND_PRIORITY`, and a branch in `_render`.
5. Match existing style: small functions, Cypher in `tools.py`, no new comments unless non-obvious.
6. After changing a generator, run `iamgraph generate` (`load` only generates when data is missing).
