import difflib
import json
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.tree import Tree

from iamgraph import gen_iam, gen_k8s, ingest
from iamgraph import tools as T
from iamgraph.db import get_graph

app = typer.Typer(help="IAM attack-path + auto-remediation agent on FalkorDB", no_args_is_help=True)
console = Console()

DATA_DIR = Path("data/generated")
STYLE = {"User": "bold cyan", "Group": "blue", "Role": "bold magenta", "Policy": "yellow", "Resource": "bold green",
         "Pod": "bold bright_blue", "ServiceAccount": "cyan", "K8sRole": "magenta"}


# --- rendering -----------------------------------------------------------------

def render_path(path: dict, title: str = "") -> Tree:
    tree = Tree(title or f"[bold]{len(path['edges'])}-hop path[/bold]")
    node = tree
    first = path["nodes"][0]
    node = node.add(f"[{STYLE.get(first['label'], 'default')}]{first['label']}: {first['name']}[/]")
    for e, n in zip(path["edges"], path["nodes"][1:]):
        rel = e["type"] + (f" ({e['kind']})" if e.get("kind") else "")
        detail = f" Sid={e['sid']}" if e.get("sid") else ""
        if e.get("actions") and e.get("kind") != "access":
            detail += " " + ", ".join(e["actions"])
        name = f"{n['name']}" + (" [red]SENSITIVE[/red]" if n.get("sensitive") else "")
        node = node.add(f"[dim]--{rel}{detail}-->[/dim] [{STYLE.get(n['label'], 'default')}]{n['label']}: {name}[/]")
    return tree


def fix_diff(fix: dict) -> str:
    dump = (lambda d: yaml.safe_dump(d, sort_keys=False)) if fix.get("format") == "yaml" else \
        (lambda d: json.dumps(d, indent=2))
    return "\n".join(difflib.unified_diff(
        dump(fix["before"]).splitlines(), dump(fix["after"]).splitlines(),
        fromfile=f"{fix['file']} (current)", tofile=f"{fix['file']} (fixed)", lineterm=""))


def render_fix(fix: dict, n: int) -> None:
    body = [f"[bold]{fix['summary']}[/bold]", f"Cuts: [red]{fix['cuts_edge']}[/red]",
            f"Exposures removed: {fix['exposures_removed']}   Legit access lost: {len(fix['collateral']) or 'none'}"]
    if fix["collateral"]:
        body.append("  " + ", ".join(fix["collateral"]))
    console.print(Panel("\n".join(body), title=f"Fix #{n}", border_style="green"))
    if "before" in fix:
        console.print(Syntax(fix_diff(fix), "diff", theme="ansi_dark"))
    if "command" in fix:
        console.print(Syntax(fix["command"], "bash", theme="ansi_dark"))


def render_tool(name: str, args: dict, result: dict) -> None:
    argstr = ", ".join(f"{k}={v!r}" for k, v in args.items())
    console.print(f"[dim]→ tool[/dim] [bold]{name}[/bold]([dim]{argstr}[/dim])")
    if "error" in result:
        console.print(f"  [red]{result['error']}[/red]")
    elif name == "find_attack_path":
        if not result["reachable"]:
            console.print("  [green]no path[/green]")
        for i, p in enumerate(result["paths"][:2]):
            console.print(render_path(p, f"[bold]Path {i + 1}[/bold] ({p['hops']} hops) — traced in FalkorDB"))
    elif name == "propose_fix":
        for i, f in enumerate(result["fixes"], 1):
            render_fix(f, i)
        ok = result["verified_no_path_after_fix"]
        console.print(f"  [{'green' if ok else 'red'}]verified on simulated graph: "
                      f"{'path is gone' if ok else 'path still exists'}[/]")
    elif name == "scan_exposures":
        console.print(f"  {len(result['exposures'])} exposures found")
    elif name == "who_can_reach":
        t = Table("actor", "type", "hops", "access", title=f"Who can reach {result['resource']}")
        for p in result["principals"]:
            why = "admin" if p["admin"] else "declared expected_access"
            access = f"[green]expected ({why})[/green]" if p["expected"] else "[red]UNEXPECTED[/red]"
            t.add_row(f"[{STYLE.get(p['type'], 'default')}]{p['name']}[/]", p["type"], str(p["hops"]), access)
        console.print(t)
        console.print(f"  {result['unexpected_count']} unexpected of {len(result['principals'])} "
                      f"(trace one with: iamgraph path <actor> {result['resource']})")


# --- commands ------------------------------------------------------------------

@app.command()
def ping():
    """Check FalkorDB connectivity with a round-trip write/read."""
    g = get_graph("iamgraph_ping")
    g.query("MERGE (:Ping {ok: true})")
    result = g.query("MATCH (p:Ping) RETURN p.ok")
    g.delete()
    console.print(f"[green]FalkorDB OK[/green] -> {result.result_set}")


@app.command()
def generate(out: Path = DATA_DIR, seed: int = 42):
    """Generate a synthetic AWS account + EKS cluster (IAM auth details, resource inventory, k8s objects)."""
    gen_iam.write(out, seed)
    gen_k8s.write(out, seed)
    console.print(f"[green]wrote[/green] {out}/aws_iam.json, resources.json, k8s.json, planted.json")


@app.command()
def load(data: Path = DATA_DIR):
    """Ingest generated JSON into FalkorDB (replaces the graph)."""
    if not (data / "aws_iam.json").exists() or not (data / "k8s.json").exists():
        generate(data)
    counts = ingest.ingest_files(get_graph(), data)
    console.print(f"[green]loaded[/green] {counts['nodes']} nodes, {counts['edges']} edges")
    stats()


@app.command()
def stats():
    """Show node/edge counts per label/type in the IAM graph."""
    g = get_graph()
    t = Table("label / type", "count")
    for label, c in g.ro_query("MATCH (n) RETURN labels(n)[0] AS l, count(*) ORDER BY l").result_set:
        t.add_row(f"({label})", str(c))
    for typ, kind, c in g.ro_query("MATCH ()-[r]->() RETURN type(r) AS t, r.kind AS k, count(*) ORDER BY t, k").result_set:
        t.add_row(f"-[:{typ}{' ' + kind if kind else ''}]->", str(c))
    console.print(t)


@app.command()
def path(source: str, target: str):
    """Find attack paths from SOURCE principal to TARGET resource (no LLM)."""
    r = T.find_attack_path(get_graph(), source, target)
    render_tool("find_attack_path", {"source": source, "target": target}, r)


@app.command()
def who(resource: str):
    """List every actor that can reach RESOURCE, flagging which access is expected (no LLM)."""
    r = T.who_can_reach(get_graph(), resource)
    render_tool("who_can_reach", {"resource": resource}, r)


@app.command()
def fix(source: str, target: str):
    """Propose a verified least-privilege fix for SOURCE -> TARGET (no LLM)."""
    r = T.propose_fix(get_graph(), source, target)
    if r.get("already_safe"):
        console.print("[green]no path, nothing to fix[/green]")
    render_tool("propose_fix", {"source": source, "target": target}, r)


@app.command()
def scan():
    """List every non-admin user / unexpected pod that can reach a sensitive resource (no LLM)."""
    g = get_graph()
    t = Table("principal", "sensitive resource", "hops", "chain", show_lines=True)
    for e in T.scan_exposures(g)["exposures"]:
        t.add_row(f"{e['source']} [dim]({e['source_type']})[/dim]", e["target"], str(e["hops"]), e["chain"])
    console.print(t)
    ck = T.rank_chokepoints(g)
    t2 = Table("chokepoint", "type", "betweenness", title="Chokepoints (betweenness centrality)")
    for c in ck["chokepoints"]:
        t2.add_row(c["name"], c["type"], str(c["betweenness"]))
    console.print(t2)


@app.command()
def web(host: str = "127.0.0.1", port: int = 8000):
    """Serve the web UI (graph view, attack paths, fixes, scan, agent chat)."""
    import uvicorn

    console.print(f"[green]web UI[/green] → http://{'localhost' if host in ('0.0.0.0', '127.0.0.1') else host}:{port}")
    uvicorn.run("iamgraph.web:app", host=host, port=port, log_level="warning")


@app.command()
def ask(question: str = typer.Argument(None, help="Question; omit for interactive mode")):
    """Ask the agent in natural language."""
    from iamgraph.agent import GOLDEN, Agent

    agent = Agent(get_graph(), on_tool=render_tool)

    def once(q: str):
        answer = agent.ask(q)
        console.print(Panel(Markdown(answer), title="Agent", border_style="cyan"))

    if question:
        once(question)
        return
    console.print("[dim]Ask about your IAM + Kubernetes graph. Ctrl-D to quit. Try:[/dim]")
    for g in GOLDEN:
        console.print(f"[dim]  • {g}[/dim]")
    while True:
        try:
            q = console.input("[bold cyan]? [/bold cyan]").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if q:
            once(q)


if __name__ == "__main__":
    app()
