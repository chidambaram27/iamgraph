"""Sanity tests against the planted attack paths. Requires FalkorDB running (docker compose up -d)."""

import pytest

from iamgraph import gen_iam, gen_k8s
from iamgraph import tools as T

PLANTED = gen_iam.build()[2] + gen_k8s.build()[1]


@pytest.mark.parametrize("case", PLANTED, ids=lambda c: c["id"])
def test_planted_path_found(g, case):
    r = T.find_attack_path(g, case["source"], case["target"])
    assert r["reachable"]
    names = {n["name"] for p in r["paths"] for n in p["nodes"]}
    assert set(case["via"]) <= names


@pytest.mark.parametrize("case", PLANTED, ids=lambda c: c["id"])
def test_fix_cuts_path_with_minimal_collateral(g, case):
    r = T.propose_fix(g, case["source"], case["target"])
    assert r["verified_no_path_after_fix"]
    assert r["fixes"]
    assert all(f["exposures_removed"] > 0 for f in r["fixes"])
    # passrole: the analyst's billing-reports access only existed through the exploited role
    assert sum(len(f["collateral"]) for f in r["fixes"]) <= 1


def test_scan_only_flags_planted_principals(g):
    found = {(e["source_type"], e["source"]) for e in T.scan_exposures(g)["exposures"]}
    users = {"dev-intern", "maria-dev", "tom-dev", "data-analyst", "contractor-bob", "support-jane"}
    assert found == {("User", u) for u in users} | {("Pod", "web-frontend"), ("Pod", "ci-runner")}


def test_background_user_safe(g):
    user = g.ro_query("MATCH (u:User {team: 'web'}) RETURN u.name LIMIT 1").result_set[0][0]
    assert not T.find_attack_path(g, user, "prod-db-credentials")["reachable"]
    assert T.propose_fix(g, user, "prod-db-credentials")["already_safe"]


def test_fix_does_not_mutate_graph(g):
    before = g.ro_query("MATCH ()-[e]->() RETURN count(e)").result_set[0][0]
    T.propose_fix(g, "dev-intern", "prod-db-credentials")
    assert g.ro_query("MATCH ()-[e]->() RETURN count(e)").result_set[0][0] == before


def test_irsa_requires_annotation_and_trust_match(g):
    bridged = {n for (n,) in g.ro_query("MATCH (s:ServiceAccount)-[:ASSUMES_AWS]->() RETURN s.name").result_set}
    assert bridged == {"orders-api-sa", "web-frontend-sa"}
    assert not T.find_attack_path(g, "cart", "prod-db-credentials")["reachable"]  # no annotation
    assert not T.find_attack_path(g, "reporting", "prod-db-credentials")["reachable"]  # ns not in trust sub


def test_irsa_fix_keeps_legit_workload(g):
    fix = T.propose_fix(g, "web-frontend", "prod-db-credentials")["fixes"][0]
    assert fix["cuts_edge"] == "web-frontend-sa -[ASSUMES_AWS]-> eks-orders-irsa"
    assert "kubectl annotate serviceaccount web-frontend-sa -n shop" in fix["command"]
    assert not fix["collateral"]
    assert T.find_attack_path(g, "orders-api", "prod-db-credentials")["reachable"]


def test_k8s_rolebinding_scope(g):
    # resourceNames-scoped Role: the worker reads only its own secret
    assert T.find_attack_path(g, "payments-worker", "stripe-webhook-key")["reachable"]
    assert not T.find_attack_path(g, "payments-worker", "payments-db-password")["reachable"]
    # ClusterRole bound by a RoleBinding stays in that namespace (view has no secrets anyway)
    assert not T.find_attack_path(g, "blog-web", "stripe-webhook-key")["reachable"]


def test_who_can_reach_flags_expected(g):
    r = T.who_can_reach(g, "prod-db-credentials")
    access = {p["name"]: p["expected"] for p in r["principals"]}
    assert access == {"alice-admin": True, "raj-sre": True, "shop/orders-api": True, "support-jane": False,
                      "shop/web-frontend": False, "dev-intern": False, "maria-dev": False, "tom-dev": False}
    assert r["unexpected_count"] == 5


def test_ns_qualified_names(g):
    # ClusterRole `view` exists cluster-wide and as a per-namespace copy for each RoleBinding
    assert "ambiguous" in T._find(g, "view", "s:K8sRole")
    assert T._find(g, "blog/view", "s:K8sRole")["namespace"] == "blog"
    assert "error" not in T.find_attack_path(g, "shop/web-frontend", "prod-db-credentials")
    assert "unknown" in T.find_attack_path(g, "ci/web-frontend", "prod-db-credentials")["error"]
