"""Minimal web UI: FastAPI JSON endpoints over the same graph tools, plus a single vis-network page."""

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel

from iamgraph import tools as T
from iamgraph.cli import fix_diff
from iamgraph.db import get_graph

STATIC = Path(__file__).parent / "static"
app = FastAPI(title="iamgraph")


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/graph")
def graph():
    return T.graph_overview(get_graph())


@app.get("/api/path")
def path(source: str, target: str):
    return T.find_attack_path(get_graph(), source, target)


@app.get("/api/fix")
def fix(source: str, target: str):
    r = T.propose_fix(get_graph(), source, target)
    for f in r.get("fixes", []):
        if "before" in f:
            f["diff"] = fix_diff(f)
    return r


@app.get("/api/who")
def who(resource: str):
    return T.who_can_reach(get_graph(), resource)


@app.get("/api/blast")
def blast(principal: str):
    return T.blast_radius(get_graph(), principal)


@app.get("/api/scan")
def scan():
    g = get_graph()
    return {**T.scan_exposures(g), **T.rank_chokepoints(g)}


@app.get("/api/golden")
def golden():
    from iamgraph.agent import GOLDEN

    return GOLDEN


class Question(BaseModel):
    question: str


@app.post("/api/ask")
def ask(q: Question):
    from iamgraph.agent import Agent

    calls = []
    try:
        answer = Agent(get_graph(), on_tool=lambda n, a, r: calls.append({"tool": n, "args": a, "result": r})).ask(q.question)
    except Exception as e:  # missing API key / LLM down: show it in the UI instead of a 500
        return {"error": f"{type(e).__name__}: {e}", "tool_calls": calls}
    for c in calls:
        for f in c["result"].get("fixes", []):
            if "before" in f:
                f["diff"] = fix_diff(f)
    return {"answer": answer, "tool_calls": calls}
