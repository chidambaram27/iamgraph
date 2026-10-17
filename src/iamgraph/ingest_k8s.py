"""Load a Kubernetes cluster dump (`kubectl get … -o json` List) into the same Batch as AWS IAM.

  (Pod)-[:USES]->(ServiceAccount)
  (ServiceAccount)-[:BOUND_TO {kind:'rolebinding'|'clusterrolebinding'}]->(K8sRole)
  (K8sRole)-[:GRANTS {kind:'access', verbs, rule}]->(Resource {type:'k8s-secret'})
  (ServiceAccount)-[:ASSUMES_AWS {kind:'irsa'}]->(Role)   IRSA bridge into AWS

A ClusterRole bound by a RoleBinding only applies inside that binding's namespace,
so it gets its own namespaced K8sRole node; bound by a ClusterRoleBinding it covers
every namespace. Only `secrets` read rules become edges (other resources are not
sensitive targets in this model).
"""

import json
from fnmatch import fnmatchcase

from iamgraph.ingest import Batch

IRSA_ANNOTATION = "eks.amazonaws.com/role-arn"
EXPECTED_ACCESS = "security.iamgraph.dev/expected-access"
READ_VERBS = {"get", "list", "watch", "*"}
CLUSTER = ""  # namespace slot in uids of cluster-scoped objects


def uid(ns: str, kind: str, name: str) -> str:
    return f"k8s:{ns}:{kind.lower()}:{name}"


def _rule_secrets(rule: dict) -> tuple[list[str], list[str] | None] | None:
    """(read verbs, resourceNames or None for all) if the rule can read secrets."""
    if not {"", "*"} & set(rule.get("apiGroups", [])):
        return None
    if not {"secrets", "*"} & set(rule.get("resources", [])):
        return None
    verbs = sorted(READ_VERBS & set(rule.get("verbs", [])))
    return (verbs, rule.get("resourceNames")) if verbs else None


def _grant_secrets(b: Batch, role_uid: str, rules: list[dict], secrets: list[dict], scope: str | None):
    for i, rule in enumerate(rules):
        parsed = _rule_secrets(rule)
        if not parsed:
            continue
        verbs, names = parsed
        for s in secrets:
            m = s["metadata"]
            if scope is not None and m["namespace"] != scope:
                continue
            if names is not None and m["name"] not in names:
                continue
            b.edge("GRANTS", role_uid, uid(m["namespace"], "secret", m["name"]),
                   kind="access", verbs=verbs, actions=[f"secrets:{v}" for v in verbs], sid=f"rule{i}", rule=i)


def _irsa_matches(role_props: dict, ns: str, sa: str) -> str | None:
    subject = f"system:serviceaccount:{ns}:{sa}"
    return next((p for p in role_props.get("irsa_subjects", []) if fnmatchcase(subject, p)), None)


def build_k8s(b: Batch, cluster: dict) -> Batch:
    by_kind: dict[str, list[dict]] = {}
    for item in cluster["items"]:
        by_kind.setdefault(item["kind"], []).append(item)
    secrets = by_kind.get("Secret", [])

    for s in secrets:
        m = s["metadata"]
        b.node("Resource", uid(m["namespace"], "secret", m["name"]), name=m["name"], namespace=m["namespace"],
               type="k8s-secret", sensitive=m.get("labels", {}).get("sensitivity") == "high")

    for sa in by_kind.get("ServiceAccount", []):
        m = sa["metadata"]
        role_arn = m.get("annotations", {}).get(IRSA_ANNOTATION)
        b.node("ServiceAccount", uid(m["namespace"], "serviceaccount", m["name"]), name=m["name"],
               namespace=m["namespace"], irsa_role_arn=role_arn or "")
        role = b.nodes.get(role_arn) if role_arn else None
        if role and role[0] == "Role":
            sub = _irsa_matches(role[1], m["namespace"], m["name"])
            if sub:
                b.edge("ASSUMES_AWS", uid(m["namespace"], "serviceaccount", m["name"]), role_arn,
                       kind="irsa", annotation=role_arn, sub=sub)

    for pod in by_kind.get("Pod", []):
        m = pod["metadata"]
        sa = pod["spec"].get("serviceAccountName", "default")
        expected = m.get("annotations", {}).get(EXPECTED_ACCESS, "")
        b.node("Pod", uid(m["namespace"], "pod", m["name"]), name=m["name"], namespace=m["namespace"],
               service_account=sa, image=pod["spec"]["containers"][0]["image"],
               expected_access=[x.strip() for x in expected.split(",") if x.strip()])
        sa_uid = uid(m["namespace"], "serviceaccount", sa)
        if sa_uid in b.nodes:
            b.edge("USES", uid(m["namespace"], "pod", m["name"]), sa_uid)

    roles = {(r["metadata"].get("namespace", CLUSTER), r["kind"], r["metadata"]["name"]): r
             for r in by_kind.get("Role", []) + by_kind.get("ClusterRole", [])}
    for (ns, kind, name), r in roles.items():
        b.node("K8sRole", uid(ns, kind, name), name=name, namespace=ns, kind=kind, rules=json.dumps(r["rules"]))
        _grant_secrets(b, uid(ns, kind, name), r["rules"], secrets, ns if kind == "Role" else None)

    for binding in by_kind.get("RoleBinding", []) + by_kind.get("ClusterRoleBinding", []):
        m, ref = binding["metadata"], binding["roleRef"]
        bns = m.get("namespace", CLUSTER)
        role = roles.get((bns if ref["kind"] == "Role" else CLUSTER, ref["kind"], ref["name"]))
        if not role:
            continue
        if binding["kind"] == "ClusterRoleBinding":
            role_uid = uid(CLUSTER, ref["kind"], ref["name"])
        else:
            role_uid = uid(bns, ref["kind"], ref["name"])
            if role_uid not in b.nodes:  # ClusterRole via RoleBinding: scoped to the binding's namespace
                b.node("K8sRole", role_uid, name=ref["name"], namespace=bns, kind=ref["kind"],
                       rules=json.dumps(role["rules"]))
                _grant_secrets(b, role_uid, role["rules"], secrets, bns)
        subjects = binding.get("subjects", [])
        for i, subj in enumerate(subjects):
            if subj["kind"] != "ServiceAccount":
                continue
            sa_uid = uid(subj.get("namespace", bns), "serviceaccount", subj["name"])
            if sa_uid in b.nodes:
                b.edge("BOUND_TO", sa_uid, role_uid, kind=binding["kind"].lower(),
                       binding=m["name"], binding_namespace=bns, subject=i, subjects=len(subjects))
    return b
