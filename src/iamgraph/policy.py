"""IAM policy-document helpers shared by ingestion and remediation.

Simplifications (documented in README): only `Allow` statements are evaluated,
`Condition` blocks and `Deny` statements are ignored, `NotAction`/`NotResource`
are not supported.
"""

import copy
from fnmatch import fnmatchcase

ASSUME_ACTION = "sts:assumerole"
WEB_IDENTITY_ACTION = "sts:assumerolewithwebidentity"
PASSROLE_ACTION = "iam:passrole"

# A role trusted by one of these services can be "become" by anyone who can
# pass the role to that service and create compute in it.
PASSROLE_COMPUTE = {
    "lambda.amazonaws.com": "lambda:createfunction",
    "ec2.amazonaws.com": "ec2:runinstances",
}


def as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def allow_statements(doc: dict) -> list[tuple[int, dict]]:
    return [
        (i, s)
        for i, s in enumerate(as_list(doc.get("Statement")))
        if s.get("Effect") == "Allow"
    ]


def action_matches(pattern: str, action: str) -> bool:
    return fnmatchcase(action.lower(), pattern.lower())


def actions_for_service(actions: list[str], service: str) -> list[str]:
    """Statement actions that could apply to a resource of `service`."""
    out = []
    for a in actions:
        if a == "*" or a.lower().split(":", 1)[0] == service or fnmatchcase(service, a.lower().split(":", 1)[0]):
            out.append(a)
    return out


def arn_service(arn: str) -> str:
    return arn.split(":")[2]


def arn_matches(pattern: str, arn: str) -> bool:
    # S3 object-level patterns (bucket/*) also grant access to data in the bucket.
    return fnmatchcase(arn, pattern) or (
        arn.startswith("arn:aws:s3:::") and fnmatchcase(arn + "/x", pattern)
    )


def _oidc_subjects(condition: dict, provider: str) -> list[str]:
    host = provider.split(":oidc-provider/", 1)[-1]
    subs = []
    for op in ("StringEquals", "StringLike"):
        subs += as_list(condition.get(op, {}).get(f"{host}:sub"))
    return subs


def parse_trust(doc: dict, account: str) -> dict:
    """Return who a role trust policy allows: root (delegated to IAM), named ARNs, services,
    and federated OIDC (IRSA) providers with their allowed `sub` patterns."""
    root_forms = {account, f"arn:aws:iam::{account}:root", "*"}
    trust = {"root": False, "principals": {}, "services": set(), "federated": []}
    for i, s in allow_statements(doc):
        actions = as_list(s.get("Action"))
        principal = s.get("Principal", {})
        if any(action_matches(a, WEB_IDENTITY_ACTION) for a in actions) and isinstance(principal, dict):
            for provider in as_list(principal.get("Federated")):
                subs = _oidc_subjects(s.get("Condition", {}), provider) or ["*"]
                trust["federated"].append({"provider": provider, "sub": subs, "stmt": i})
        if not any(action_matches(a, ASSUME_ACTION) for a in actions):
            continue
        if principal == "*":
            principal = {"AWS": "*"}
        for p in as_list(principal.get("AWS")):
            if p in root_forms:
                trust["root"] = True
            else:
                trust["principals"][p] = i
        trust["services"].update(as_list(principal.get("Service")))
    return trust


def narrow_irsa_trust(doc: dict, subject: str, keep: list[str]) -> dict:
    """Trust doc with `subject` no longer allowed: matching `sub` patterns are replaced by the explicit
    `keep` subjects they cover; a federated statement left with no `sub` is dropped (never left open)."""
    out = []
    for s in as_list(doc.get("Statement")):
        principal = s.get("Principal")
        providers = as_list(principal.get("Federated")) if isinstance(principal, dict) else []
        if not providers:
            out.append(s)
            continue
        key = providers[0].split(":oidc-provider/", 1)[-1] + ":sub"
        s, emptied = copy.deepcopy(s), False
        for op in ("StringEquals", "StringLike"):
            values = as_list(s.get("Condition", {}).get(op, {}).get(key))
            if not values:
                continue
            new = []
            for v in values:
                for x in ([k for k in keep if fnmatchcase(k, v)] if fnmatchcase(subject, v) else [v]):
                    if x not in new:
                        new.append(x)
            if new:
                s["Condition"][op][key] = new if len(new) > 1 else new[0]
            else:
                emptied = True
        if not emptied:
            out.append(s)
    return {**doc, "Statement": out}
