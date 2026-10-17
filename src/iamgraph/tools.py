"""Graph tools the agent can call. Every tool is a Cypher query (or a few) on FalkorDB."""

import copy
import json
import time
import uuid

from falkordb import Graph
from redis.exceptions import ResponseError

from iamgraph import policy as P

# Edge types an attacker can traverse. K8s types (Phase 2) are included up front:
# FalkorDB path functions ignore types that do not exist yet.
TRAVERSAL = ["MEMBER_OF", "HAS_POLICY", "GRANTS", "CAN_ASSUME", "ASSUMES_AWS", "USES", "BOUND_TO"]
REL = "|".join(TRAVERSAL)
MAX_HOPS = 12
PRINCIPAL = "(s:User OR s:Role OR s:Group OR s:ServiceAccount OR s:Pod)"

ADMIN_USERS_Q = """
MATCH (u:User)-[:MEMBER_OF*0..1]->()-[:HAS_POLICY]->(p:Policy {full_admin: true})
RETURN collect(DISTINCT u.uid)
"""


def _rows(graph: Graph, q: str, params: dict | None = None) -> list:
    return graph.ro_query(q, params or {}).result_set


def _find(graph: Graph, name: str, where: str = PRINCIPAL) -> dict | None:
    """Resolve a name (or `namespace/name` for K8s objects). Returns {'ambiguous': [...]} on collisions."""
    ns, _, short = name.rpartition("/") if "/" in name and not name.startswith("arn:") else ("", "", name)
    rows = _rows(graph, f"MATCH (s) WHERE s.name = $name AND {where} AND ($ns = '' OR s.namespace = $ns) "
                        "RETURN labels(s)[0], s.uid, s.namespace", {"name": short, "ns": ns})
    if len(rows) > 1:
        return {"ambiguous": sorted(f"{n}/{short}" if n else f"{label}:{short}" for label, _, n in rows)}
    return {"label": rows[0][0], "uid": rows[0][1], "name": short, "namespace": rows[0][2]} if rows else None


def _lookup_error(*pairs: tuple[str, str, dict | None]) -> str | None:
    for what, name, node in pairs:
        if node is None:
            return f"unknown {what}: {name}"
        if "ambiguous" in node:
            return f"ambiguous {what} '{name}': use one of {', '.join(node['ambiguous'])}"
    return None


def _admin_users(graph: Graph) -> set[str]:
    return set(_rows(graph, ADMIN_USERS_Q)[0][0])


def _copy(graph: Graph, suffix: str, attempts: int = 50) -> Graph:
    """GRAPH.COPY forks, which fails while Redis runs a background save; wait it out."""
    for i in range(attempts):
        try:
            return graph.copy(f"{graph.name}__{suffix}_{uuid.uuid4().hex[:8]}")
        except ResponseError as e:
            if "could not fork" not in str(e) or i == attempts - 1:
                raise
            time.sleep(0.1)


# --- paths -------------------------------------------------------------------

PATH_PROJECTION = """
[n IN nodes({p}) | {{label: labels(n)[0], name: n.name, uid: n.uid, sensitive: n.sensitive, namespace: n.namespace}}] AS nodes,
[e IN relationships({p}) | {{id: id(e), type: type(e), kind: e.kind, sid: e.sid, actions: e.actions,
    from: startNode(e).name, to: endNode(e).name}}] AS edges
"""

SPPATHS_Q = f"""
MATCH (s {{uid: $src}}), (t:Resource {{uid: $dst}})
CALL algo.SPpaths({{sourceNode: s, targetNode: t, relTypes: {json.dumps(TRAVERSAL)},
                   relDirection: 'outgoing', pathCount: $k, maxLen: {MAX_HOPS}}})
YIELD path, pathWeight
RETURN {PATH_PROJECTION.format(p='path')}
ORDER BY pathWeight
"""

SHORTEST_Q = f"""
MATCH (s {{uid: $src}}), (t:Resource {{uid: $dst}})
WITH shortestPath((s)-[:{REL}*1..{MAX_HOPS}]->(t)) AS p
WHERE p IS NOT NULL
RETURN {PATH_PROJECTION.format(p='p')}
"""


def _paths(graph: Graph, src_uid: str, dst_uid: str, k: int = 3) -> list[dict]:
    rows = _rows(graph, SPPATHS_Q, {"src": src_uid, "dst": dst_uid, "k": k})
    return [{"nodes": [dict(n) for n in ns], "edges": [dict(e) for e in es]} for ns, es in rows]


def _shortest(graph: Graph, src_uid: str, dst_uid: str) -> dict | None:
    rows = _rows(graph, SHORTEST_Q, {"src": src_uid, "dst": dst_uid})
    return {"nodes": [dict(n) for n in rows[0][0]], "edges": [dict(e) for e in rows[0][1]]} if rows else None


def format_path(path: dict) -> str:
    parts = [f"{path['nodes'][0]['label']}:{path['nodes'][0]['name']}"]
    for e, n in zip(path["edges"], path["nodes"][1:]):
        rel = e["type"] + (f"/{e['kind']}" if e.get("kind") else "")
        if e.get("sid"):
            rel += f" [{e['sid']}]"
        parts.append(f"-[{rel}]-> {n['label']}:{n['name']}")
    return " ".join(parts)


def find_attack_path(graph: Graph, source: str, target: str, k: int = 3) -> dict:
    s, t = _find(graph, source), _find(graph, target, "s:Resource")
    if err := _lookup_error(("source", source, s), ("target", target, t)):
        return {"error": err}
    paths = _paths(graph, s["uid"], t["uid"], k)
    return {
        "source": source, "target": target, "reachable": bool(paths),
        "paths": [{"hops": len(p["edges"]), "chain": format_path(p), **p} for p in paths],
    }


def who_can_reach(graph: Graph, resource: str) -> dict:
    """Users, pods, and SAs no pod runs as, that can reach a resource. `expected` = admin user, or pod that
    declares the resource in expected_access; everything else is a finding."""
    t = _find(graph, resource, "s:Resource")
    if err := _lookup_error(("resource", resource, t)):
        return {"error": err}
    admins = _admin_users(graph)
    rows = _rows(graph, f"""
        MATCH (t:Resource {{uid: $dst}}), (s)
        WHERE s:User OR s:Pod OR (s:ServiceAccount AND NOT (:Pod)-[:USES]->(s))
        WITH s, t, shortestPath((s)-[:{REL}*1..{MAX_HOPS}]->(t)) AS p
        WHERE p IS NOT NULL
        RETURN labels(s)[0], s.name, s.uid, s.namespace, t.name IN coalesce(s.expected_access, []), length(p) AS hops
        ORDER BY hops, s.name
    """, {"dst": t["uid"]})
    principals = []
    for label, name, uid, ns, declared, hops in rows:
        admin = uid in admins
        principals.append({"type": label, "name": f"{ns}/{name}" if ns else name, "hops": hops, "admin": admin,
                           "expected": admin or (label == "Pod" and declared)})
    return {"resource": resource, "principals": principals,
            "unexpected_count": sum(1 for p in principals if not p["expected"])}


def scan_exposures(graph: Graph) -> dict:
    """Every non-admin user, and every pod reaching beyond its declared expected_access, that can reach a
    sensitive resource, with the shortest chain. ServiceAccounts are covered by their pods."""
    admins = list(_admin_users(graph))
    rows = _rows(graph, f"""
        MATCH (s), (t:Resource {{sensitive: true}})
        WHERE (s:User AND NOT s.uid IN $admins) OR (s:Pod AND NOT t.name IN coalesce(s.expected_access, []))
        WITH s, t, shortestPath((s)-[:{REL}*1..{MAX_HOPS}]->(t)) AS p
        WHERE p IS NOT NULL
        RETURN labels(s)[0], s.name, t.name, length(p) AS hops, {PATH_PROJECTION.format(p='p')}
        ORDER BY s.name, hops
    """, {"admins": admins})
    return {"exposures": [
        {"source": s, "source_type": l, "target": t, "hops": h, "chain": format_path({"nodes": ns, "edges": es})}
        for l, s, t, h, ns, es in rows
    ]}


def blast_radius(graph: Graph, principal: str) -> dict:
    s = _find(graph, principal)
    if err := _lookup_error(("principal", principal, s)):
        return {"error": err}
    rows = _rows(graph, f"""
        MATCH (s {{uid: $uid}})-[:{REL}*1..{MAX_HOPS}]->(x)
        WHERE x:Resource OR x:Role
        RETURN DISTINCT labels(x)[0] AS type, x.name, x.sensitive ORDER BY type, x.name
    """, {"uid": s["uid"]})
    return {
        "principal": principal,
        "roles_assumable": [n for t, n, _ in rows if t == "Role"],
        "resources": [{"name": n, "sensitive": bool(sv)} for t, n, sv in rows if t == "Resource"],
        "sensitive_count": sum(1 for t, _, sv in rows if t == "Resource" and sv),
    }


def rank_chokepoints(graph: Graph, limit: int = 5) -> dict:
    """Betweenness centrality over the permission graph: the roles/policies most paths flow through."""
    types = set(_rows(graph, "CALL db.relationshipTypes() YIELD relationshipType RETURN collect(relationshipType)")[0][0])
    nodes = _rows(graph, "MATCH (n) RETURN count(n)")[0][0]
    # algo.betweenness samples random sources (default 32, time-seeded); a fixed seed keeps rankings reproducible.
    rows = _rows(graph, f"""
        CALL algo.betweenness({{relationshipTypes: {json.dumps([t for t in TRAVERSAL if t in types])},
                               samplingSize: $nodes, samplingSeed: 42}})
        YIELD node, score
        WHERE (node:Role OR node:Policy OR node:Group) AND score > 0
        RETURN labels(node)[0], node.name, score ORDER BY score DESC LIMIT $limit
    """, {"limit": limit, "nodes": nodes})
    exposed = _rows(graph, f"""
        MATCH (t:Resource {{sensitive: true}})<-[:{REL}*1..{MAX_HOPS}]-(s:User)
        WHERE NOT s.uid IN $admins
        RETURN t.name, count(DISTINCT s) AS users ORDER BY users DESC LIMIT $limit
    """, {"limit": limit, "admins": list(_admin_users(graph))})
    return {
        "chokepoints": [{"type": t, "name": n, "betweenness": round(sc, 2)} for t, n, sc in rows],
        "most_exposed_resources": [{"resource": n, "non_admin_users_with_access": c} for n, c in exposed],
    }


# --- remediation ---------------------------------------------------------------

KIND_PRIORITY = {"narrow_statement": 0, "narrow_rbac_rule": 0, "edit_trust_policy": 1, "remove_irsa_binding": 1,
                 "remove_from_group": 2, "delete_rolebinding": 2, "detach_policy": 3}
K8S_SKIP = {"USES"}  # never recommend deleting/recreating a pod; cut its SA's permissions instead


def _reach(graph: Graph) -> dict[str, set[tuple[str, str, str]]]:
    """All (principal, resource) reachability, plus the subset reachable without a full-admin policy.

    Access a non-admin only gets via an admin policy is the bug itself, so losing it is not collateral.
    ServiceAccounts are left out: their pods already carry the same reachability.
    """
    q = f"""
        MATCH (p) WHERE p:User OR p:Role OR p:Pod
        MATCH path = (p)-[:{REL}*1..{MAX_HOPS}]->(r:Resource)
        {{where}}
        RETURN DISTINCT labels(p)[0], p.uid, r.uid
    """
    return {
        "all": {tuple(row) for row in _rows(graph, q.format(where=""))},
        "legit": {tuple(row) for row in _rows(graph, q.format(
            where="WHERE none(n IN nodes(path) WHERE n:Policy AND n.full_admin)"))},
    }


def _candidates(graph: Graph, path: dict) -> list[dict]:
    out = []
    for pos, e in enumerate(path["edges"]):
        src, dst = path["nodes"][pos], path["nodes"][pos + 1]
        base = {"edge": e, "position": pos, "delete_edges": [e["id"]]}
        if e["type"] in K8S_SKIP:
            continue
        if e["type"] == "MEMBER_OF":
            out.append({**base, "kind": "remove_from_group", "user": src["name"], "group": dst["name"]})
        elif e["type"] == "HAS_POLICY":
            out.append({**base, "kind": "detach_policy", "owner": src, "policy": dst})
        elif e["type"] == "CAN_ASSUME" and e.get("kind") == "trust":
            out.append({**base, "kind": "edit_trust_policy", "role": dst, "principal": src})
        elif e["type"] == "ASSUMES_AWS":
            out.append({**base, **_irsa_candidate(graph, e, src, dst)})
        elif e["type"] == "BOUND_TO":
            out.append({**base, **_binding_candidate(graph, e, src, dst)})
        elif e["type"] == "GRANTS" and src["label"] == "K8sRole":
            out.append({**base, **_narrow_rbac_candidate(graph, e, src, dst)})
        elif e["type"] == "GRANTS":
            c = _narrow_candidate(graph, e, src, dst)
            if c:
                out.append({**base, **c})
    return out


def _edge_props(graph: Graph, edge_id: int) -> dict:
    return dict(_rows(graph, "MATCH ()-[e]->() WHERE id(e) = $id RETURN properties(e)", {"id": edge_id})[0][0])


def _irsa_candidate(graph: Graph, e: dict, sa: dict, role: dict) -> dict:
    trust_doc, = _rows(graph, "MATCH (r:Role {uid: $uid}) RETURN r.trust_document", {"uid": role["uid"]})[0]
    keep = _rows(graph, """
        MATCH (o:ServiceAccount)-[:ASSUMES_AWS]->(:Role {uid: $role}) WHERE o.uid <> $sa
        RETURN o.namespace, o.name ORDER BY o.namespace, o.name
    """, {"role": role["uid"], "sa": sa["uid"]})
    return {"kind": "remove_irsa_binding", "sa": sa, "role": role, "trust_doc": json.loads(trust_doc),
            "keep_subjects": [f"system:serviceaccount:{ns}:{n}" for ns, n in keep],
            "sub": _edge_props(graph, e["id"]).get("sub")}


def _binding_candidate(graph: Graph, e: dict, sa: dict, k8s_role: dict) -> dict:
    props = _edge_props(graph, e["id"])
    role_kind = _rows(graph, "MATCH (k:K8sRole {uid: $uid}) RETURN k.kind", {"uid": k8s_role["uid"]})[0][0]
    return {"kind": "delete_rolebinding", "sa": sa, "k8s_role": k8s_role, "role_kind": role_kind,
            "binding_kind": props["kind"], "binding": props["binding"], "binding_namespace": props["binding_namespace"],
            "subject": props.get("subject", 0), "subjects": props.get("subjects", 1)}


def _narrow_rbac_candidate(graph: Graph, e: dict, k8s_role: dict, target: dict) -> dict:
    role_ns, kind, rules_json, rule_ix = _rows(graph, """
        MATCH (k:K8sRole {uid: $uid})-[g:GRANTS]->() WHERE id(g) = $id
        RETURN k.namespace, k.kind, k.rules, g.rule
    """, {"uid": k8s_role["uid"], "id": e["id"]})[0]
    rules = json.loads(rules_json)
    # A ClusterRole's rules are shared by every node made from it (cluster-wide and per-RoleBinding copies).
    scope = "k.kind = 'ClusterRole' AND k.name = $name" if kind == "ClusterRole" else "k.uid = $uid"
    siblings = _rows(graph, f"""
        MATCH (k:K8sRole)-[g:GRANTS {{rule: $rule}}]->(x) WHERE {scope}
        RETURN id(g), x.uid, x.name, coalesce(x.sensitive, false)
    """, {"uid": k8s_role["uid"], "name": k8s_role["name"], "rule": rule_ix})
    has_names = "resourceNames" in rules[rule_ix]
    removed = {target["uid"]} | ({u for _, u, _, sens in siblings if sens} if not has_names else set())
    return {
        "kind": "narrow_rbac_rule", "k8s_role": k8s_role, "role_kind": kind, "namespace": role_ns,
        "rules": rules, "rule": rule_ix,
        "removed": sorted({n for _, u, n, _ in siblings if u in removed}),
        "kept": sorted({n for _, u, n, _ in siblings if u not in removed}),
        "delete_edges": [i for i, u, _, _ in siblings if u in removed],
    }


def _narrow_candidate(graph: Graph, e: dict, policy_node: dict, target: dict) -> dict | None:
    rows = _rows(graph, """
        MATCH (p:Policy {uid: $uid})-[g:GRANTS]->(x) WHERE id(g) = $id
        RETURN p.aws_managed, p.document, g.stmt
    """, {"uid": policy_node["uid"], "id": e["id"]})
    if not rows or rows[0][0]:
        return None  # AWS-managed policies cannot be edited, only detached
    _, document, stmt = rows[0]
    doc = json.loads(document)
    statement = P.as_list(doc["Statement"])[stmt]
    has_wildcard = any("*" in p for p in P.as_list(statement.get("Resource")))

    siblings = _rows(graph, """
        MATCH (p:Policy {uid: $uid})-[g:GRANTS {stmt: $stmt}]->(x)
        RETURN id(g), x.uid, coalesce(x.sensitive, false)
    """, {"uid": policy_node["uid"], "stmt": stmt})
    # Wildcard statements lose every sensitive match, not just this target; explicit ones lose only the target.
    removed = {target["uid"]} | ({u for _, u, sens in siblings if sens} if has_wildcard else set())
    return {
        "kind": "narrow_statement", "policy": policy_node, "stmt": stmt, "sid": statement.get("Sid"),
        "removed_arns": sorted(removed),
        "kept_arns": sorted({u for _, u, _ in siblings} - removed),
        "delete_edges": [i for i, u, _ in siblings if u in removed],
        "document": doc,
    }


def _is_exposure(label: str, p: str, r: str, admins: set[str], sensitive: set[str], expected: dict) -> bool:
    if r not in sensitive:
        return False
    if label == "User":
        return p not in admins
    return label == "Pod" and r not in expected.get(p, set())


def _score(graph: Graph, cand: dict, before: dict, admins: set[str]) -> dict:
    sim = _copy(graph, "sim")
    try:
        sim.query("MATCH ()-[e]->() WHERE id(e) IN $ids DELETE e", {"ids": cand["delete_edges"]})
        after = _reach(sim)
    finally:
        sim.delete()
    sensitive = set(_rows(graph, "MATCH (r:Resource {sensitive: true}) RETURN collect(r.uid)")[0][0])
    expected = {p: set(rs) for p, rs in _rows(graph, """
        MATCH (p:Pod), (r:Resource) WHERE r.name IN p.expected_access RETURN p.uid, collect(r.uid)""")}
    names = dict(_rows(graph, "MATCH (n) WHERE n:User OR n:Role OR n:Resource OR n:ServiceAccount OR n:Pod "
                              "RETURN n.uid, n.name"))
    def exposed(label: str, p: str, r: str) -> bool:
        return _is_exposure(label, p, r, admins, sensitive, expected)

    exposures = [(p, r) for label, p, r in before["all"] - after["all"] if exposed(label, p, r)]
    collateral = [(label, p, r) for label, p, r in before["legit"] - after["all"] if not exposed(label, p, r)]
    weight = sum(3 if label == "Role" else 1 for label, _, _ in collateral)
    return {**cand, "exposures_removed": len(exposures), "collateral_weight": weight,
            "score": weight - 2 * len(exposures),
            "collateral": sorted({f"{names[p]} -> {names[r]}" for _, p, r in collateral})}


def _render_k8s(c: dict) -> dict:
    kind = c["kind"]
    if kind == "remove_irsa_binding":
        sa, role = c["sa"], c["role"]
        subject = f"system:serviceaccount:{sa['namespace']}:{sa['name']}"
        after = P.narrow_irsa_trust(c["trust_doc"], subject, c["keep_subjects"])
        return {"summary": f"Stop {sa['namespace']}/{sa['name']} from assuming AWS role {role['name']} "
                           f"(remove the IRSA annotation and narrow trust sub `{c['sub']}`)",
                "file": f"trust-policy:{role['name']}", "before": c["trust_doc"], "after": after,
                "command": f"kubectl annotate serviceaccount {sa['name']} -n {sa['namespace']} "
                           f"eks.amazonaws.com/role-arn-\n"
                           f"aws iam update-assume-role-policy --role-name {role['name']} "
                           f"--policy-document file://trust.json"}
    if kind == "delete_rolebinding":
        sa, kr = c["sa"], c["k8s_role"]
        obj = c["binding_kind"]
        ns = "" if obj == "clusterrolebinding" else f" -n {c['binding_namespace']}"
        if c["subjects"] > 1:
            cmd = (f"kubectl patch {obj} {c['binding']}{ns} --type=json "
                   f"-p '[{{\"op\":\"remove\",\"path\":\"/subjects/{c['subject']}\"}}]'")
            what = f"Remove {sa['namespace']}/{sa['name']} from {obj} {c['binding']}"
        else:
            cmd = f"kubectl delete {obj} {c['binding']}{ns}"
            what = f"Delete {obj} {c['binding']} ({sa['namespace']}/{sa['name']} → {c['role_kind']} {kr['name']})"
        return {"summary": what, "command": cmd}
    # narrow_rbac_rule
    after = copy.deepcopy(c["rules"])
    if c["kept"]:
        after[c["rule"]]["resourceNames"] = c["kept"]
        what = f"Restrict rule {c['rule']} of {c['role_kind']} {c['k8s_role']['name']} to resourceNames {c['kept']}"
    else:
        after.pop(c["rule"])
        what = f"Remove secrets rule {c['rule']} from {c['role_kind']} {c['k8s_role']['name']}"
    meta = {"name": c["k8s_role"]["name"], **({"namespace": c["namespace"]} if c["role_kind"] == "Role" else {})}
    head = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": c["role_kind"], "metadata": meta}
    return {"summary": what, "file": f"{c['role_kind'].lower()}:{c['k8s_role']['name']}", "format": "yaml",
            "before": {**head, "rules": c["rules"]}, "after": {**head, "rules": after},
            "removes_access_to": c["removed"], "command": "kubectl apply -f role.yaml"}


def _render(c: dict) -> dict:
    kind = c["kind"]
    if kind in ("remove_irsa_binding", "delete_rolebinding", "narrow_rbac_rule"):
        return _render_k8s(c)
    if kind == "remove_from_group":
        return {"summary": f"Remove user {c['user']} from group {c['group']}",
                "command": f"aws iam remove-user-from-group --user-name {c['user']} --group-name {c['group']}"}
    if kind == "detach_policy":
        owner, pol = c["owner"], c["policy"]
        otype = owner["label"].lower()
        if pol["uid"].startswith("arn:aws:iam::") and "#inline/" not in pol["uid"]:
            cmd = f"aws iam detach-{otype}-policy --{otype}-name {owner['name']} --policy-arn {pol['uid']}"
        else:
            cmd = f"aws iam delete-{otype}-policy --{otype}-name {owner['name']} --policy-name {pol['name']}"
        return {"summary": f"Detach policy {pol['name']} from {otype} {owner['name']}", "command": cmd}
    if kind == "edit_trust_policy":
        rows = c["_trust_doc"]
        before = json.loads(rows)
        after = copy.deepcopy(before)
        stmts = P.as_list(after["Statement"])
        st = stmts[c["edge_stmt"]]
        principals = [p for p in P.as_list(st["Principal"].get("AWS")) if p != c["principal"]["uid"]]
        if principals:
            st["Principal"]["AWS"] = principals
        else:
            stmts.pop(c["edge_stmt"])
        after["Statement"] = stmts
        role = c["role"]["name"]
        fix = {"summary": f"Remove {c['principal']['name']} from the trust policy of role {role}",
               "file": f"trust-policy:{role}", "before": before, "after": after,
               "command": f"aws iam update-assume-role-policy --role-name {role} --policy-document file://trust.json"}
        if not stmts:
            fix["summary"] += " (no trusted principals remain, so delete the role)"
            fix["command"] = f"aws iam delete-role --role-name {role}  # detach/delete its policies first"
        return fix
    # narrow_statement
    before = c["document"]
    after = copy.deepcopy(before)
    stmts = P.as_list(after["Statement"])
    st = stmts[c["stmt"]]
    removed = c["removed_arns"]
    resources = [p for p in P.as_list(st["Resource"])
                 if "*" not in p and not any(P.arn_matches(p, r) for r in removed)]
    for arn in c["kept_arns"]:
        if not any(P.arn_matches(p, arn) for p in resources):
            resources += [arn, f"{arn}/*"] if arn.startswith("arn:aws:s3:::") else [arn]
    if resources:
        st["Resource"] = resources if len(resources) > 1 else resources[0]
        what = f"Narrow statement {c['sid'] or c['stmt']} of {c['policy']['name']} to {len(resources)} explicit resource(s)"
    else:
        stmts.pop(c["stmt"])
        what = f"Remove statement {c['sid'] or c['stmt']} from {c['policy']['name']}"
    after["Statement"] = stmts
    return {"summary": what, "file": f"policy:{c['policy']['name']}", "before": before, "after": after,
            "removes_access_to": [r.rsplit(":", 1)[-1] for r in removed]}


def propose_fix(graph: Graph, source: str, target: str, max_rounds: int = 4) -> dict:
    """Find the least-collateral edge cuts that disconnect source from target, verified by simulation."""
    s, t = _find(graph, source), _find(graph, target, "s:Resource")
    if err := _lookup_error(("source", source, s), ("target", target, t)):
        return {"error": err}

    scratch = _copy(graph, "fix")
    try:
        admins = _admin_users(scratch)
        fixes = []
        for _ in range(max_rounds):
            path = _shortest(scratch, s["uid"], t["uid"])
            if not path:
                break
            before = _reach(scratch)
            cands = _candidates(scratch, path)
            for c in cands:
                if c["kind"] == "edit_trust_policy":
                    row = _rows(scratch, "MATCH ()-[e]->(r:Role) WHERE id(e) = $id RETURN r.trust_document, e.stmt",
                                {"id": c["edge"]["id"]})[0]
                    c["_trust_doc"], c["edge_stmt"] = row
            scored = [_score(scratch, c, before, admins) for c in cands]
            if not scored:
                break
            scored.sort(key=lambda c: (c["score"], c["collateral_weight"],
                                       KIND_PRIORITY[c["kind"]], -c["position"]))
            best = scored[0]
            scratch.query("MATCH ()-[e]->() WHERE id(e) IN $ids DELETE e", {"ids": best["delete_edges"]})
            fixes.append({
                "cuts_edge": f"{best['edge']['from']} -[{best['edge']['type']}]-> {best['edge']['to']}",
                "cut_edge_ids": best["delete_edges"],
                "path_cut": format_path(path),
                "exposures_removed": best["exposures_removed"],
                "collateral": best["collateral"],
                "alternatives_considered": [
                    {"kind": c["kind"], "edge": f"{c['edge']['from']} -> {c['edge']['to']}",
                     "exposures_removed": c["exposures_removed"],
                     "collateral_weight": c["collateral_weight"]} for c in scored[1:]
                ],
                **_render(best),
            })
        verified = _shortest(scratch, s["uid"], t["uid"]) is None
    finally:
        scratch.delete()
    return {"source": source, "target": target, "fixes": fixes,
            "verified_no_path_after_fix": verified, "already_safe": not fixes and verified}


def graph_overview(graph: Graph) -> dict:
    """Whole graph for the web UI (not an agent tool)."""
    nodes = _rows(graph, "MATCH (n) RETURN n.uid, labels(n)[0], n.name, n.namespace, coalesce(n.sensitive, false), "
                         "coalesce(n.full_admin, false)")
    edges = _rows(graph, "MATCH (a)-[e]->(b) RETURN id(e), a.uid, b.uid, type(e), e.kind, e.sid")
    return {
        "nodes": [{"uid": u, "label": l, "name": n, "namespace": ns, "sensitive": s, "full_admin": a}
                  for u, l, n, ns, s, a in nodes],
        "edges": [{"id": i, "from": a, "to": b, "type": t, "kind": k, "sid": sid} for i, a, b, t, k, sid in edges],
    }


TOOLS = {
    "find_attack_path": find_attack_path,
    "who_can_reach": who_can_reach,
    "scan_exposures": scan_exposures,
    "blast_radius": blast_radius,
    "rank_chokepoints": rank_chokepoints,
    "propose_fix": propose_fix,
}
