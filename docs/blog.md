# How a dev-intern reached production secrets in 7 hops, and how a graph found the fix

*Building an IAM attack-path agent on FalkorDB for Graph Hacks (WeMakeDevs x FalkorDB), Track 01: Agents That Act on Connected Data.*

---

## Why I built this

I started iamgraph for a hackathon. I wanted a weekend project that would push a graph database harder than a toy social network. Somewhere between the second planted attack path and the first verified fix, it stopped feeling like a hackathon project. It started to feel like something my team had needed for a long time.

I work on a platform team. People join all the time: new employees, freelancers on a three-month contract, engineers moving between teams. Each of them gets added to a group, given a role, or bound to a namespace. And honestly, after a while we don't know **who can reach what** anymore. We know what we granted. We don't know what all of it adds up to.

That gap is growing quickly. We're in the agentic era now. Developers, often with an AI assistant next to them, ship new services, roles and Kubernetes manifests faster than any platform team can review them by hand. A wildcard trust policy that was meant to be "temporary" gets merged on a Friday. A contractor's access is never cleaned up. A new pod picks up an IRSA annotation copied from another service. None of these is a big mistake on its own, and that's why they're scary. By the time someone notices, a production secret has been reachable for weeks.

I didn't want another dashboard listing permissions. I wanted something that could answer, with evidence, the question that keeps platform engineers up at night: *is anything in production reachable by someone who shouldn't have it, and what's the smallest change that fixes it?*

## The problem: nobody grants admin on purpose

Most cloud breaches don't start with someone being handed `AdministratorAccess`. They start with a set of permissions that each look fine when you review them alone:

- The `Developers` group can assume any role matching `ci-*`. That makes sense, since devs debug CI.
- The `ci-deploy` role can assume `prod-admin`. Also reasonable, because CI deploys to prod.
- `prod-admin` has `AdministratorAccess`. Of course it does.

Put those together and an intern can read `prod-db-credentials`. Every policy passes review on its own, and the problem only shows up when you follow the chain.

Kubernetes makes this worse. A pod uses a ServiceAccount, the ServiceAccount carries an IRSA annotation, and the AWS role it points to trusts `system:serviceaccount:shop:*`. Now a public-facing `web-frontend` pod can read the same production database secret, and the path crosses two completely separate permission systems.

Policy simulators answer "can X do Y?" one hop at a time. Security teams need a different set of answers:

1. **Can** this principal reach this secret, and **how**?
2. **Who** can reach this secret, and is that access expected?
3. **Where** is the one change that cuts the path without breaking anything legitimate?

Those are graph questions, so I built **iamgraph** on a graph database.

## What iamgraph does

iamgraph loads AWS IAM (`get-account-authorization-details`), a resource inventory with sensitivity tags, and Kubernetes RBAC (`kubectl get … -o json`) into one FalkorDB graph. On top of that it runs an LLM agent with six tools:

| Tool | Question it answers |
|---|---|
| `find_attack_path` | How does X reach Y? (k shortest paths) |
| `who_can_reach` | Every user or pod that can reach Y, marked expected or **UNEXPECTED** |
| `scan_exposures` | Every non-admin principal that can reach any sensitive resource |
| `blast_radius` | Everything one principal can reach |
| `rank_chokepoints` | Which roles, policies or groups the most paths flow through |
| `propose_fix` | The least-privilege change that cuts the path, **verified** |

You ask in plain English:

```bash
iamgraph ask "Can dev-intern reach prod-db-credentials? If so, fix it."
```

and the agent returns the traced path as evidence:

```text
User: dev-intern
└── MEMBER_OF ──> Group: Developers
    └── HAS_POLICY ──> Policy: dev-assume-ci
        └── GRANTS (assume) sts:AssumeRole ──> Role: ci-deploy
            └── HAS_POLICY ──> Policy: ci-deploy-policy
                └── GRANTS (assume) sts:AssumeRole ──> Role: prod-admin
                    └── HAS_POLICY ──> Policy: AdministratorAccess
                        └── GRANTS (access) ──> Resource: prod-db-credentials  SENSITIVE
```

It also returns a concrete fix: the exact `aws iam …` or `kubectl …` command, a before/after diff of the policy, trust policy or RBAC YAML, and a note that the fix was checked on a simulated graph and the path is gone.

The LLM never invents evidence. Every path, count and fix comes from a Cypher query, and the CLI and web UI show each tool result next to the model's answer. Every command except `ask` (`path`, `who`, `scan`, `fix`) is deterministic and works without an LLM.

## The one modeling rule: permissions are edges

The main design decision is this: **every effective permission becomes an edge, never a JSON blob you query later.**

At ingest time, iamgraph evaluates each policy document and writes what it actually allows as relationships:

```text
User   -[:MEMBER_OF]->   Group
User/Group/Role -[:HAS_POLICY]-> Policy
Policy -[:GRANTS {kind:'access'}]->   Resource
Policy -[:GRANTS {kind:'assume'}]->   Role       // sts:AssumeRole + trust delegates to account
Policy -[:GRANTS {kind:'passrole'}]-> Role       // iam:PassRole + lambda:CreateFunction / ec2:RunInstances
User/Role -[:CAN_ASSUME {kind:'trust'}]-> Role   // trust policy names the principal directly

Pod -[:USES]-> ServiceAccount -[:BOUND_TO]-> K8sRole -[:GRANTS]-> Secret
ServiceAccount -[:ASSUMES_AWS {kind:'irsa'}]-> Role   // the bridge between K8s and AWS
```

Raw policy documents stay on the nodes, but only so remediation can show a patched version. No traversal ever reads them. Once permissions are edges, **an attack path is just a graph path**, and every security question becomes a traversal.

The `ASSUMES_AWS` edge is only created when *both* sides agree, as in real IRSA: the ServiceAccount's annotation names the role, and the role's OIDC trust `sub` condition matches the ServiceAccount. Because of that one edge, a pod-to-AWS-secret path needs no special code. It's the same query.

## Where FalkorDB carries the load

### 1. Escalation is a path problem, so ask for paths

Here is the whole "how can X reach Y" query:

```cypher
MATCH (s {uid: $src}), (t:Resource {uid: $dst})
CALL algo.SPpaths({sourceNode: s, targetNode: t,
                   relTypes: ["MEMBER_OF","HAS_POLICY","GRANTS","CAN_ASSUME",
                              "ASSUMES_AWS","USES","BOUND_TO"],
                   relDirection: 'outgoing', pathCount: $k, maxLen: 12})
YIELD path, pathWeight
RETURN nodes(path), relationships(path)
ORDER BY pathWeight
```

Role chaining, PassRole, stale trust policies and IRSA wildcards are all multi-hop, mixed-edge-type paths. In SQL each hop is another self-join or a loop in application code. Here it's one variable-length call. `algo.SPpaths` returns *several* alternative paths, which matters: it shows the agent (and you) that cutting one route may not be enough.

"Who can reach this secret?" follows the same pattern from the other direction: a `shortestPath` from every user and pod to the target, with each result marked expected or unexpected using the pod's declared `expected-access` annotation.

### 2. Graph algorithms answer "where should I fix it?"

Finding a path is half the job. The more useful question is which single change removes the most risk. FalkorDB's built-in betweenness centrality answers it directly:

```cypher
CALL algo.betweenness({relationshipTypes: [...], samplingSize: $nodes, samplingSeed: 42})
YIELD node, score
WHERE (node:Role OR node:Policy OR node:Group) AND score > 0
RETURN labels(node)[0], node.name, score ORDER BY score DESC
```

In the demo account this points at `prod-admin` and `ci-deploy`, the shared roles behind the role chain. No single policy document reveals that. It only shows up when you look at the shape of the whole graph.

### 3. `graph.copy()` turns "what if" into a cheap, verified experiment

This is the part I like most. `propose_fix` doesn't ask the LLM to guess a fix. It **simulates** fixes:

1. `graph.copy()` makes a scratch graph, so the live `iam` graph is never touched (a test checks this).
2. Every edge on the shortest path becomes a candidate with a real-world meaning: `MEMBER_OF` → remove from group, `HAS_POLICY` → detach policy, `CAN_ASSUME` → edit trust policy, `GRANTS` → narrow the statement, `ASSUMES_AWS` → remove the IRSA binding, `BOUND_TO` → delete the RoleBinding.
3. For each candidate, copy again, delete the edge(s), and re-run a reachability snapshot. Compare **exposures removed** against **collateral**, meaning legitimate access lost.
4. Apply the best cut and repeat until `shortestPath` returns nothing.

Collateral is measured carefully. Access that only exists through a full-admin policy *is* the bug, so losing it doesn't count against a fix. In practice the agent prefers fixes like this one for the `web-frontend` pod:

```diff
- "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:sub": "system:serviceaccount:shop:*"
+ "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:sub": "system:serviceaccount:shop:orders-api-sa"
```

```text
Exposures removed: 2   Legit access lost: none
verified on simulated graph: path is gone
```

The legitimate `orders-api` pod keeps its access, and the frontend loses access it never should have had. The answer comes with proof, which is what "agents that act on connected data" should mean.

### 4. One graph, two permission systems

AWS IAM and Kubernetes RBAC are usually audited by different tools and often by different teams. In iamgraph they're one graph joined by an edge, so the cross-boundary path `Pod → ServiceAccount → (IRSA) → Role → Policy → Secret` is found by exactly the same Cypher as a pure-IAM role chain.

## Try it

The repo ships a synthetic account and EKS cluster in real API shapes: 24 users, 21 roles, 13 pods, about 155 nodes and 206 edges. Six attack paths are planted among benign noise:

| Planted path | Escalation |
|---|---|
| `dev-intern` → `prod-db-credentials` | Role chain to `prod-admin` |
| `data-analyst` → `customer-pii` | `iam:PassRole *` + `lambda:CreateFunction` |
| `contractor-bob` → `prod-backups` | Stale trust policy still naming the contractor |
| `support-jane` → `payment-api-key` | `secretsmanager:GetSecretValue` on `*` |
| pod `web-frontend` → `prod-db-credentials` | IRSA trust wildcard `shop:*` |
| pod `ci-runner` → `stripe-webhook-key` | ClusterRoleBinding to a cluster-wide secret reader |

One command with only Docker:

```bash
docker compose run --rm app iamgraph scan
docker compose --profile app up web   # http://localhost:8000
```

The web UI draws the whole graph, highlights the attack path, marks the chosen cut as a red ✂ edge, and shows the diff and verification. FalkorDB Browser at http://localhost:3000 lets you run the raw Cypher yourself.

## Honest limits

The model is **allow-only**. `Deny` statements, most `Condition` blocks, permission boundaries, SCPs and resource-based policies aren't modeled yet, so results over-approximate reachability. A reported path is a candidate to review, not a proven exploit. PassRole escalation covers Lambda and EC2, and on the Kubernetes side only secret-read rules become edges. Each of these is a new edge type plus a fix kind, which the graph model makes easy to add.

## Where this goes next: from hackathon to guardrail

Running iamgraph once is useful. Running it **all the time** is the real goal. Here's how I plan to use it at work:

- **In the CI pipeline.** Every pull request that touches IAM policies, trust policies, Helm charts or RBAC manifests gets loaded into a scratch graph with the proposed change applied. If the change opens a *new* path from a non-admin principal to a sensitive resource, the pipeline fails and posts the traced path on the PR, along with the suggested least-privilege fix. Reviewers no longer have to imagine how four policies combine, because the graph shows them.
- **As a daily or weekly job.** A scheduled scan against the real account and cluster tracks production resources over time. New exposures, newly onboarded users or freelancers who can reach production secrets, and chokepoint roles that keep gaining trust relationships get flagged to the platform team before they turn into incidents.
- **For onboarding and offboarding.** When someone joins or leaves, `who_can_reach` and `blast_radius` make the review concrete: here is everything this person can actually reach, not just the groups we added them to.

The graph model already supports all of this. Because `propose_fix` works on `graph.copy()`, evaluating a pull request is the same idea: copy the graph, apply the change, re-run the reachability queries, and compare. What's left is plumbing: a real ingest from `aws iam get-account-authorization-details` and `kubectl`, a non-zero exit code when there are exposures, and a diff against the last known-good snapshot.

The development pace isn't going to slow down, and it shouldn't. But the platform team's visibility has to keep up with it. I think a graph that is always up to date and answers questions with evidence is the way to get there.

## Takeaway

IAM risk lives in the *connections* between permissions, not in any single permission. Once those connections are stored as edges in FalkorDB, finding paths, ranking chokepoints and simulating fixes all become short Cypher queries. The agent's job then is to ask the right ones and show its work.

What started as a hackathon entry is now the tool I want running behind every deploy: it quietly checks that a new hire, a freelancer or a Friday-evening merge hasn't left a path open to production.

**Demo video:** https://chidambaram27.github.io/iamgraph/video/
**Code:** https://github.com/chidambaram27/iamgraph
