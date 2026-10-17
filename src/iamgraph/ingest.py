"""Load AWS IAM authorization details + a resource inventory into FalkorDB.

Every effective permission becomes an edge so attack paths are plain graph
traversals:

  (User)-[:MEMBER_OF]->(Group)
  (User|Group|Role)-[:HAS_POLICY]->(Policy)
  (Policy)-[:GRANTS {kind:'access'}]->(Resource)      data access
  (Policy)-[:GRANTS {kind:'assume'}]->(Role)          sts:AssumeRole (role chaining)
  (Policy)-[:GRANTS {kind:'passrole'}]->(Role)        iam:PassRole + compute create
  (User|Role)-[:CAN_ASSUME {kind:'trust'}]->(Role)    explicit principal in trust policy

Policy documents are kept on Policy/Role nodes only so remediation can emit a
patched document; no traversal ever reads them.
"""

import json
from dataclasses import dataclass, field

from falkordb import Graph

from iamgraph import policy as P

LABELS = ["User", "Group", "Role", "Policy", "Resource", "Pod", "ServiceAccount", "K8sRole"]


@dataclass
class Batch:
    nodes: dict[str, tuple[str, dict]] = field(default_factory=dict)
    edges: list[tuple[str, str, str, dict]] = field(default_factory=list)

    def node(self, label: str, uid: str, **props):
        self.nodes[uid] = (label, {"uid": uid, **props})

    def edge(self, type_: str, src: str, dst: str, **props):
        self.edges.append((type_, src, dst, props))


def _is_metadata_only(action: str) -> bool:
    verb = action.split(":", 1)[-1].lower()
    return verb.startswith(("list", "describe"))


def _policy_edges(b: Batch, uid: str, doc: dict, roles: list[dict], resources: list[dict]):
    stmts = P.allow_statements(doc)
    all_actions = [a for _, s in stmts for a in P.as_list(s.get("Action"))]

    for i, s in stmts:
        actions = P.as_list(s.get("Action"))
        patterns = P.as_list(s.get("Resource"))
        sid = s.get("Sid", f"stmt{i}")

        for r in resources:
            acts = [a for a in P.actions_for_service(actions, P.arn_service(r["Arn"])) if not _is_metadata_only(a)]
            if acts and any(P.arn_matches(p, r["Arn"]) for p in patterns):
                b.edge("GRANTS", uid, r["Arn"], kind="access", actions=acts, sid=sid, stmt=i)

        if any(P.action_matches(a, P.ASSUME_ACTION) for a in actions):
            for role in roles:
                if role["_trust"]["root"] and any(P.arn_matches(p, role["Arn"]) for p in patterns):
                    b.edge("GRANTS", uid, role["Arn"], kind="assume", actions=["sts:AssumeRole"], sid=sid, stmt=i)

        if any(P.action_matches(a, P.PASSROLE_ACTION) for a in actions):
            for role in roles:
                for service, create in P.PASSROLE_COMPUTE.items():
                    if (
                        service in role["_trust"]["services"]
                        and any(P.action_matches(a, create) for a in all_actions)
                        and any(P.arn_matches(p, role["Arn"]) for p in patterns)
                    ):
                        b.edge("GRANTS", uid, role["Arn"], kind="passrole",
                               actions=["iam:PassRole", create], via=service, sid=sid, stmt=i)


def build_batch(auth: dict, inventory: dict) -> Batch:
    b = Batch()
    account = inventory["Account"]
    resources = inventory["Resources"]
    roles = auth["RoleDetailList"]
    for role in roles:
        role["_trust"] = P.parse_trust(role["AssumeRolePolicyDocument"], account)

    for r in resources:
        b.node("Resource", r["Arn"], name=r["Name"], arn=r["Arn"], type=r["Type"],
               sensitive=r.get("Tags", {}).get("sensitivity") == "high")

    managed = {}
    for p in auth["Policies"]:
        doc = next(v["Document"] for v in p["PolicyVersionList"] if v["IsDefaultVersion"])
        managed[p["Arn"]] = doc
        b.node("Policy", p["Arn"], name=p["PolicyName"], arn=p["Arn"], managed=True,
               aws_managed=p["Arn"].startswith("arn:aws:iam::aws:"),
               full_admin=_is_full_admin(doc), document=json.dumps(doc))
        _policy_edges(b, p["Arn"], doc, roles, resources)

    def attach(owner_type: str, owner: dict, name_key: str, inline_key: str):
        for m in owner["AttachedManagedPolicies"]:
            b.edge("HAS_POLICY", owner["Arn"], m["PolicyArn"])
        for ip in owner.get(inline_key, []):
            uid = f"{owner['Arn']}#inline/{ip['PolicyName']}"
            doc = ip["PolicyDocument"]
            b.node("Policy", uid, name=ip["PolicyName"], managed=False, aws_managed=False,
                   owner_type=owner_type, owner_name=owner[name_key], owner_arn=owner["Arn"],
                   full_admin=_is_full_admin(doc), document=json.dumps(doc))
            b.edge("HAS_POLICY", owner["Arn"], uid)
            _policy_edges(b, uid, doc, roles, resources)

    groups_by_name = {g["GroupName"]: g["Arn"] for g in auth["GroupDetailList"]}
    for g in auth["GroupDetailList"]:
        b.node("Group", g["Arn"], name=g["GroupName"], arn=g["Arn"])
        attach("group", g, "GroupName", "GroupPolicyList")

    for u in auth["UserDetailList"]:
        team = next((t["Value"] for t in u.get("Tags", []) if t["Key"] == "team"), "")
        b.node("User", u["Arn"], name=u["UserName"], arn=u["Arn"], team=team)
        for gname in u["GroupList"]:
            b.edge("MEMBER_OF", u["Arn"], groups_by_name[gname])
        attach("user", u, "UserName", "UserPolicyList")

    for role in roles:
        trust = role["_trust"]
        b.node("Role", role["Arn"], name=role["RoleName"], arn=role["Arn"], domain="aws",
               trusted_services=sorted(trust["services"]), trusts_account=trust["root"],
               oidc_providers=sorted({f["provider"] for f in trust["federated"]}),
               irsa_subjects=sorted({s for f in trust["federated"] for s in f["sub"]}),
               trust_document=json.dumps(role["AssumeRolePolicyDocument"]))
        attach("role", role, "RoleName", "RolePolicyList")

    for role in roles:
        for principal, stmt in role["_trust"]["principals"].items():
            if principal in b.nodes:
                b.edge("CAN_ASSUME", principal, role["Arn"], kind="trust", principal=principal, stmt=stmt)

    return b


def _is_full_admin(doc: dict) -> bool:
    return any(
        "*" in P.as_list(s.get("Action")) and "*" in P.as_list(s.get("Resource"))
        for _, s in P.allow_statements(doc)
    )


def load(graph: Graph, b: Batch, reset: bool = True) -> dict:
    if reset:
        try:
            graph.delete()
        except Exception:
            pass  # graph did not exist yet

    for label in LABELS:
        for prop in ("uid", "name"):
            try:
                graph.query(f"CREATE INDEX FOR (n:{label}) ON (n.{prop})")
            except Exception:
                pass  # index already exists

    by_label: dict[str, list[dict]] = {}
    for label, props in b.nodes.values():
        by_label.setdefault(label, []).append(props)
    for label, rows in by_label.items():
        graph.query(f"UNWIND $rows AS row MERGE (n:{label} {{uid: row.uid}}) SET n += row", {"rows": rows})

    by_type: dict[tuple[str, str, str], list[dict]] = {}
    for type_, src, dst, props in b.edges:
        key = (type_, b.nodes[src][0], b.nodes[dst][0])
        by_type.setdefault(key, []).append({"src": src, "dst": dst, "props": props})
    for (type_, src_label, dst_label), rows in by_type.items():
        graph.query(
            f"UNWIND $rows AS row MATCH (a:{src_label} {{uid: row.src}}), (b:{dst_label} {{uid: row.dst}}) "
            f"CREATE (a)-[e:{type_}]->(b) SET e += row.props",
            {"rows": rows},
        )

    return {"nodes": len(b.nodes), "edges": len(b.edges)}


def ingest_files(graph: Graph, data_dir) -> dict:
    from pathlib import Path

    from iamgraph.ingest_k8s import build_k8s

    d = Path(data_dir)
    auth = json.loads((d / "aws_iam.json").read_text())
    inventory = json.loads((d / "resources.json").read_text())
    b = build_batch(auth, inventory)
    if (d / "k8s.json").exists():
        build_k8s(b, json.loads((d / "k8s.json").read_text()))
    return load(graph, b)
