"""LLM tool-calling loop: question -> graph tools on FalkorDB -> explained answer + fix."""

import json
import os
from collections.abc import Callable

from dotenv import load_dotenv
from falkordb import Graph
from openai import OpenAI

from iamgraph import tools as T

load_dotenv()

SYSTEM = """You are a cloud identity security agent. An AWS account's IAM and an EKS cluster's Kubernetes RBAC are
loaded into ONE FalkorDB graph, joined by IRSA (a K8s ServiceAccount annotated with an IAM role ARN, and trusted by
that role's OIDC `sub` condition, can act as the AWS role). Attack paths may cross from a pod into AWS.
You answer ONLY from graph tool results; never invent principals, paths or policies.

Principals: IAM users/roles/groups, K8s pods and service accounts. Targets: AWS resources and K8s secrets.
K8s names may repeat across namespaces; if a tool says a name is ambiguous, retry with `namespace/name`.

Workflow:
- "Can X reach Y?" -> find_attack_path. If reachable, ALSO call propose_fix for the same pair.
- "Who can access Y?" -> who_can_reach.  "What can X reach?" -> blast_radius.
- "What is risky / audit / scan?" -> scan_exposures, then rank_chokepoints.
- "Fix it / remediate" -> propose_fix.

Answer format (markdown, concise):
1. Verdict in one line. Say so explicitly if the path crosses from Kubernetes into AWS.
2. The attack path, copied verbatim from the tool's `chain`, one hop per line, explaining in plain words
   why each hop is allowed: group membership, policy statement Sid, sts:AssumeRole, iam:PassRole, trust policy;
   for K8s: pod runs as its service account (USES), RoleBinding/ClusterRoleBinding (BOUND_TO), RBAC rule on
   secrets (GRANTS), IRSA annotation + trust `sub` match (ASSUMES_AWS).
3. If you called propose_fix: the recommended fix summary and why it was chosen over the alternatives
   (fewest legitimate accesses lost, e.g. other pods sharing the role keep working), in 2-3 bullets. Do NOT reprint
   policy JSON/YAML, diffs or commands; the CLI already renders them. Say it was verified by re-running the path
   query on a simulated copy of the graph.
Users marked admin=true, and pods reaching resources listed in their expected_access, are expected; do not report
them as findings. who_can_reach marks both with expected=true.
Keep the whole answer under ~20 lines."""

SCHEMAS = [
    {"name": "find_attack_path", "description": "Shortest privilege-escalation paths from a principal (IAM user/role, K8s pod/service account) to a resource (AWS resource or K8s secret), including pod -> AWS paths via IRSA.",
     "parameters": {"type": "object", "properties": {
         "source": {"type": "string", "description": "User, role, pod or service account name, e.g. dev-intern, web-frontend, or namespace/name like shop/web-frontend"},
         "target": {"type": "string", "description": "Resource or K8s secret name, e.g. prod-db-credentials, stripe-webhook-key"}},
         "required": ["source", "target"]}},
    {"name": "propose_fix", "description": "Compute the least-collateral IAM or Kubernetes change (policy/trust edit, IRSA unbinding, RoleBinding removal, RBAC rule narrowing) that cuts every path from source to target, verified by simulation.",
     "parameters": {"type": "object", "properties": {
         "source": {"type": "string"}, "target": {"type": "string"}}, "required": ["source", "target"]}},
    {"name": "who_can_reach", "description": "Every actor (users, pods, standalone service accounts) that can reach a resource, with hop count and an `expected` flag (admin user, or pod that declares the resource in expected_access). Unexpected ones are findings.",
     "parameters": {"type": "object", "properties": {"resource": {"type": "string"}}, "required": ["resource"]}},
    {"name": "blast_radius", "description": "Every AWS role and resource (incl. K8s secrets) a principal can reach, directly or via escalation.",
     "parameters": {"type": "object", "properties": {"principal": {"type": "string"}}, "required": ["principal"]}},
    {"name": "scan_exposures", "description": "Account + cluster scan: every non-admin user, and every pod beyond its expected_access, that can reach a sensitive resource.",
     "parameters": {"type": "object", "properties": {}}},
    {"name": "rank_chokepoints", "description": "Betweenness centrality: roles/policies most escalation paths flow through, and most-exposed resources.",
     "parameters": {"type": "object", "properties": {}}},
]

GOLDEN = [
    "Can dev-intern reach prod-db-credentials? If so, fix it.",
    "Can the web-frontend pod reach prod-db-credentials?",
    "Can the ci-runner pod read stripe-webhook-key? Fix it.",
    "Scan the account and cluster: what is exposed, and where are the chokepoints?",
    "Who can access customer-pii?",
]

# Bulky fields the LLM does not need (raw node/edge lists, internal ids).
_DROP = {"nodes", "edges", "delete_edges", "cut_edge_ids", "document", "_trust_doc", "trust_doc", "rules"}


def _slim(obj):
    if isinstance(obj, dict):
        return {k: _slim(v) for k, v in obj.items() if k not in _DROP}
    if isinstance(obj, list):
        return [_slim(v) for v in obj]
    return obj


class Agent:
    def __init__(self, graph: Graph, on_tool: Callable[[str, dict, dict], None] | None = None):
        self.graph = graph
        self.client = OpenAI(base_url=os.getenv("OPENAI_BASE_URL") or None)
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        self.on_tool = on_tool
        self.messages: list[dict] = [{"role": "system", "content": SYSTEM}]

    def ask(self, question: str, max_steps: int = 6) -> str:
        self.messages.append({"role": "user", "content": question})
        for _ in range(max_steps):
            resp = self.client.chat.completions.create(
                model=self.model, messages=self.messages,
                tools=[{"type": "function", "function": s} for s in SCHEMAS],
            )
            msg = resp.choices[0].message
            self.messages.append(msg.model_dump(exclude_none=True))
            if not msg.tool_calls:
                return msg.content or ""
            for call in msg.tool_calls:
                args = json.loads(call.function.arguments or "{}")
                try:
                    result = T.TOOLS[call.function.name](self.graph, **args)
                except Exception as e:  # surface tool errors to the model instead of crashing
                    result = {"error": f"{type(e).__name__}: {e}"}
                if self.on_tool:
                    self.on_tool(call.function.name, args, result)
                self.messages.append({"role": "tool", "tool_call_id": call.id,
                                      "content": json.dumps(_slim(result), default=str)})
        return "Stopped: too many tool steps."
