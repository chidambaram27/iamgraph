"""Synthetic EKS cluster generator.

Emits `k8s.json` shaped like `kubectl get pods,serviceaccounts,roles,clusterroles,
rolebindings,clusterrolebindings,secrets -A -o json` (a `List` of `items`) plus
planted ground truth in the same format as `gen_iam.build()`.

Planted:
  irsa-wildcard        web-frontend pod -> SA annotated with eks-orders-irsa (copy-paste
                       from orders-api); the role trusts `system:serviceaccount:shop:*`
                       -> AWS prod-db-credentials (the cross-boundary path)
  k8s-secrets-cluster  ci-runner pod -> SA bound by ClusterRoleBinding to a ClusterRole
                       with secrets get/list cluster-wide -> payments/stripe-webhook-key

IRSA decoys (must NOT produce an ASSUMES_AWS edge):
  cart-sa       in `shop`, matches the trust `sub` but has no role annotation
  reporting-sa  annotated with eks-orders-irsa, but `analytics` is not in the trust `sub`

Legit sensitive access (not findings): orders-api -> prod-db-credentials via IRSA,
payments-worker -> stripe-webhook-key via a resourceNames-scoped Role. Workload owners
declare it with the `security.iamgraph.dev/expected-access` pod annotation (comma-separated
resource names); anything else a pod can reach that is sensitive is an exposure.
"""

import base64
import json
import random
import uuid
from pathlib import Path

from iamgraph.gen_iam import IAM

IRSA_ANNOTATION = "eks.amazonaws.com/role-arn"
EXPECTED_ACCESS = "security.iamgraph.dev/expected-access"
ORDERS_IRSA = f"{IAM}:role/eks-orders-irsa"
REDACTED = base64.b64encode(b"redacted").decode()


class Cluster:
    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self.items: list[dict] = []

    def _meta(self, name: str, namespace: str | None, labels=None, annotations=None) -> dict:
        m = {"name": name, "uid": str(uuid.UUID(int=self.rng.getrandbits(128)))}
        if namespace:
            m["namespace"] = namespace
        if labels:
            m["labels"] = labels
        if annotations:
            m["annotations"] = annotations
        return m

    def _add(self, api: str, kind: str, meta: dict, **body) -> dict:
        item = {"apiVersion": api, "kind": kind, "metadata": meta, **body}
        self.items.append(item)
        return item

    def service_account(self, ns: str, name: str, role_arn: str | None = None):
        ann = {IRSA_ANNOTATION: role_arn} if role_arn else None
        self._add("v1", "ServiceAccount", self._meta(name, ns, annotations=ann))

    def pod(self, ns: str, name: str, sa: str, image: str, expected=()):
        ann = {EXPECTED_ACCESS: ",".join(expected)} if expected else None
        self._add("v1", "Pod", self._meta(name, ns, labels={"app": name}, annotations=ann), spec={
            "serviceAccountName": sa,
            "containers": [{"name": name, "image": image}],
        })

    def secret(self, ns: str, name: str, keys=("value",), sensitive: bool = False):
        labels = {"sensitivity": "high" if sensitive else "internal"}
        self._add("v1", "Secret", self._meta(name, ns, labels=labels), type="Opaque",
                  data={k: REDACTED for k in keys})

    def role(self, ns: str | None, name: str, rules: list[dict]):
        kind = "Role" if ns else "ClusterRole"
        self._add("rbac.authorization.k8s.io/v1", kind, self._meta(name, ns), rules=rules)

    def binding(self, ns: str | None, name: str, role_kind: str, role: str, subjects: list[tuple[str, str]]):
        kind = "RoleBinding" if ns else "ClusterRoleBinding"
        self._add("rbac.authorization.k8s.io/v1", kind, self._meta(name, ns),
                  roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": role_kind, "name": role},
                  subjects=[{"kind": "ServiceAccount", "name": sa, "namespace": sns} for sns, sa in subjects])

    def export(self) -> dict:
        return {"apiVersion": "v1", "kind": "List", "items": self.items}


def rule(resources, verbs, names=None, groups=("",)) -> dict:
    r = {"apiGroups": list(groups), "resources": list(resources), "verbs": list(verbs)}
    if names:
        r["resourceNames"] = list(names)
    return r


def _app(c: Cluster, ns: str, app: str, image: str, role_arn: str | None = None, expected=()):
    c.service_account(ns, f"{app}-sa", role_arn)
    c.pod(ns, app, f"{app}-sa", image, expected)


def build(seed: int = 42) -> tuple[dict, list[dict]]:
    c = Cluster(seed)
    rng = c.rng

    # Cluster-wide roles: a safe `view` (no secrets, like the built-in) and the monitoring reader
    c.role(None, "view", [rule(["pods", "services", "configmaps", "endpoints"], ["get", "list", "watch"]),
                          rule(["deployments", "replicasets"], ["get", "list", "watch"], groups=["apps"])])
    c.role(None, "prometheus-scraper", [rule(["nodes", "nodes/metrics", "pods", "services", "endpoints"],
                                             ["get", "list", "watch"])])

    # --- shop: IRSA workloads -------------------------------------------------
    _app(c, "shop", "orders-api", "shop/orders-api:2.14.1", ORDERS_IRSA,
         expected=["prod-db-credentials", "prod-data-key"])
    _app(c, "shop", "cart", "shop/cart:1.9.0")  # decoy: matches trust sub, no annotation
    # PLANTED a: frontend chart was copied from orders-api, annotation left in place
    _app(c, "shop", "web-frontend", "shop/web-frontend:5.2.0", ORDERS_IRSA)
    c.secret("shop", "frontend-session-key", sensitive=False)
    c.role("shop", "shop-config-reader", [rule(["configmaps"], ["get", "list"])])
    c.binding("shop", "shop-config-reader", "Role", "shop-config-reader",
              [("shop", "orders-api-sa"), ("shop", "cart-sa"), ("shop", "web-frontend-sa")])

    # --- payments: legit narrowly-scoped secret access ------------------------
    _app(c, "payments", "payments-worker", "payments/worker:3.0.4", expected=["stripe-webhook-key"])
    c.secret("payments", "stripe-webhook-key", keys=("signing-secret",), sensitive=True)
    c.secret("payments", "payments-db-password", keys=("password",), sensitive=True)
    c.role("payments", "worker-secrets", [rule(["secrets"], ["get"], names=["stripe-webhook-key"])])
    c.binding("payments", "worker-secrets", "Role", "worker-secrets", [("payments", "payments-worker-sa")])

    # --- ci: PLANTED b, cluster-wide secret read ------------------------------
    _app(c, "ci", "ci-runner", "ci/runner:16.4")
    c.role(None, "secret-reader", [rule(["secrets"], ["get", "list"])])
    c.binding(None, "ci-secret-reader", "ClusterRole", "secret-reader", [("ci", "ci-runner-sa")])

    # --- analytics: IRSA decoy (annotated, but namespace not in trust sub) ----
    _app(c, "analytics", "reporting", "analytics/reporting:0.8.2", ORDERS_IRSA)

    # --- monitoring -----------------------------------------------------------
    _app(c, "monitoring", "prometheus", "prom/prometheus:v2.53.0")
    c.binding(None, "prometheus-scraper", "ClusterRole", "prometheus-scraper", [("monitoring", "prometheus-sa")])

    # --- noise namespaces -----------------------------------------------------
    for ns, apps in {"blog": ["blog-web", "blog-worker"], "internal-tools": ["wiki", "status-page"],
                     "search": ["search-api", "indexer"]}.items():
        for app in apps:
            _app(c, ns, app, f"{ns}/{app}:{rng.randint(1, 4)}.{rng.randint(0, 20)}.{rng.randint(0, 9)}")
        c.secret(ns, f"{ns}-config", keys=("settings.yaml",))
        c.role(ns, f"{ns}-app", [rule(["configmaps"], ["get", "list"]),
                                 rule(["secrets"], ["get"], names=[f"{ns}-config"])])
        c.binding(ns, f"{ns}-app", "Role", f"{ns}-app", [(ns, f"{a}-sa") for a in apps])
        c.binding(ns, f"{ns}-view", "ClusterRole", "view", [(ns, f"{apps[0]}-sa")])

    planted = [
        {"id": "irsa-wildcard", "source": "web-frontend", "target": "prod-db-credentials",
         "via": ["web-frontend-sa", "eks-orders-irsa", "orders-irsa-secrets"]},
        {"id": "k8s-secrets-cluster", "source": "ci-runner", "target": "stripe-webhook-key",
         "via": ["ci-runner-sa", "secret-reader"]},
    ]
    return c.export(), planted


def write(out_dir: Path, seed: int = 42) -> Path:
    """Write k8s.json and append the K8s cases to planted.json (written first by gen_iam.write)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    cluster, planted = build(seed)
    (out_dir / "k8s.json").write_text(json.dumps(cluster, indent=2))
    pf = out_dir / "planted.json"
    existing = json.loads(pf.read_text()) if pf.exists() else []
    ids = {p["id"] for p in planted}
    pf.write_text(json.dumps([p for p in existing if p["id"] not in ids] + planted, indent=2))
    return out_dir
