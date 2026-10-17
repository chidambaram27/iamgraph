"""Synthetic AWS account generator.

Emits two files:
  aws_iam.json   - shaped like `aws iam get-account-authorization-details`
  resources.json - a resource inventory (ARN, type, sensitivity tag)
  planted.json   - ground truth for the planted attack paths (used by tests)

The org is generated from a fixed seed so every run is identical. Background
"noise" (teams, service roles, readonly roles) never touches sensitive data;
only the planted misconfigurations create escalation paths to it.
"""

import json
import random
import uuid
from pathlib import Path

ACCOUNT = "123456789012"
REGION = "us-east-1"
IAM = f"arn:aws:iam::{ACCOUNT}"
OIDC_HOST = f"oidc.eks.{REGION}.amazonaws.com/id/EXAMPLE"
OIDC_PROVIDER = f"{IAM}:oidc-provider/{OIDC_HOST}"

TEAMS = ["platform", "payments", "data", "mobile", "web", "growth"]
FIRST_NAMES = [
    "aarav", "maya", "liam", "zara", "noah", "isha", "omar", "lena", "kai", "priya",
    "diego", "sofia", "arjun", "emma", "yuki", "ravi", "nina", "leo", "ana", "sam",
    "tara", "ben", "mira", "felix", "ira", "jon", "kira", "vik", "lucy", "dev",
]


def doc(*statements: dict) -> dict:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(actions, resources, sid: str | None = None) -> dict:
    s = {"Effect": "Allow", "Action": actions, "Resource": resources}
    if sid:
        s = {"Sid": sid, **s}
    return s


def trust_root() -> dict:
    return doc({"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}, "Action": "sts:AssumeRole"})


def trust_service(service: str) -> dict:
    return doc({"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"})


def trust_principal(arn: str) -> dict:
    return doc({"Sid": "LegacyBackupAccess", "Effect": "Allow", "Principal": {"AWS": arn}, "Action": "sts:AssumeRole"})


def trust_irsa(namespace: str, service_account: str) -> dict:
    return doc({
        "Effect": "Allow", "Principal": {"Federated": OIDC_PROVIDER}, "Action": "sts:AssumeRoleWithWebIdentity",
        "Condition": {
            "StringLike": {f"{OIDC_HOST}:sub": f"system:serviceaccount:{namespace}:{service_account}"},
            "StringEquals": {f"{OIDC_HOST}:aud": "sts.amazonaws.com"},
        },
    })


class Account:
    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self.users: dict[str, dict] = {}
        self.groups: dict[str, dict] = {}
        self.roles: dict[str, dict] = {}
        self.policies: dict[str, dict] = {}
        self.resources: list[dict] = []

    def _id(self, prefix: str) -> str:
        return prefix + "".join(self.rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(17))

    # --- resources -----------------------------------------------------------
    def resource(self, type_: str, name: str, sensitive: bool = False) -> str:
        arn = {
            "s3": f"arn:aws:s3:::{name}",
            "secret": f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:{name}-{self._id('')[:6]}",
            "dynamodb": f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/{name}",
            "kms": f"arn:aws:kms:{REGION}:{ACCOUNT}:key/{uuid.UUID(int=self.rng.getrandbits(128))}",
            "rds": f"arn:aws:rds:{REGION}:{ACCOUNT}:db:{name}",
        }[type_]
        self.resources.append({
            "Arn": arn, "Name": name, "Type": type_,
            "Tags": {"sensitivity": "high" if sensitive else "internal"},
        })
        return arn

    # --- identities ----------------------------------------------------------
    def managed_policy(self, name: str, document: dict, aws_managed: bool = False) -> str:
        arn = f"arn:aws:iam::aws:policy/{name}" if aws_managed else f"{IAM}:policy/{name}"
        self.policies[name] = {
            "PolicyName": name, "PolicyId": self._id("ANPA"), "Arn": arn, "Path": "/",
            "DefaultVersionId": "v1", "AttachmentCount": 0, "IsAttachable": True,
            "PolicyVersionList": [{"Document": document, "VersionId": "v1", "IsDefaultVersion": True}],
        }
        return arn

    def _attach(self, entity: dict, policy: str):
        p = self.policies[policy]
        p["AttachmentCount"] += 1
        entity["AttachedManagedPolicies"].append({"PolicyName": p["PolicyName"], "PolicyArn": p["Arn"]})

    def group(self, name: str, managed=(), inline: dict | None = None) -> dict:
        g = {"GroupName": name, "GroupId": self._id("AGPA"), "Arn": f"{IAM}:group/{name}", "Path": "/",
             "GroupPolicyList": [], "AttachedManagedPolicies": []}
        for m in managed:
            self._attach(g, m)
        for pname, d in (inline or {}).items():
            g["GroupPolicyList"].append({"PolicyName": pname, "PolicyDocument": d})
        self.groups[name] = g
        return g

    def user(self, name: str, groups=(), managed=(), inline: dict | None = None, team: str = "") -> dict:
        u = {"UserName": name, "UserId": self._id("AIDA"), "Arn": f"{IAM}:user/{name}", "Path": "/",
             "GroupList": list(groups), "AttachedManagedPolicies": [], "UserPolicyList": [],
             "Tags": [{"Key": "team", "Value": team}] if team else []}
        for m in managed:
            self._attach(u, m)
        for pname, d in (inline or {}).items():
            u["UserPolicyList"].append({"PolicyName": pname, "PolicyDocument": d})
        self.users[name] = u
        return u

    def role(self, name: str, trust: dict, managed=(), inline: dict | None = None) -> dict:
        r = {"RoleName": name, "RoleId": self._id("AROA"), "Arn": f"{IAM}:role/{name}", "Path": "/",
             "AssumeRolePolicyDocument": trust, "RolePolicyList": [], "AttachedManagedPolicies": [], "Tags": []}
        for m in managed:
            self._attach(r, m)
        for pname, d in (inline or {}).items():
            r["RolePolicyList"].append({"PolicyName": pname, "PolicyDocument": d})
        self.roles[name] = r
        return r

    def export(self) -> dict:
        return {
            "UserDetailList": list(self.users.values()),
            "GroupDetailList": list(self.groups.values()),
            "RoleDetailList": list(self.roles.values()),
            "Policies": list(self.policies.values()),
            "IsTruncated": False,
        }


def build(seed: int = 42) -> tuple[dict, dict, list[dict]]:
    a = Account(seed)
    rng = a.rng

    # Sensitive crown jewels
    prod_db = a.resource("secret", "prod-db-credentials", sensitive=True)
    payment_key = a.resource("secret", "payment-api-key", sensitive=True)
    pii = a.resource("s3", "customer-pii", sensitive=True)
    backups = a.resource("s3", "prod-backups", sensitive=True)
    kms_key = a.resource("kms", "prod-data-key", sensitive=True)
    a.resource("rds", "prod-orders-db", sensitive=True)
    staging_db = a.resource("secret", "staging-db-credentials")
    a.resource("s3", "billing-reports")

    a.managed_policy("AdministratorAccess", doc(allow("*", "*")), aws_managed=True)
    a.managed_policy("ReadOnlyAccess", doc(allow(
        ["s3:List*", "dynamodb:Describe*", "secretsmanager:ListSecrets", "rds:Describe*", "kms:Describe*"], "*")),
        aws_managed=True)

    # --- background org (noise) ---------------------------------------------
    names = FIRST_NAMES[:]
    rng.shuffle(names)
    for team in TEAMS:
        artifacts = a.resource("s3", f"{team}-artifacts")
        events = a.resource("dynamodb", f"{team}-events")
        logs = a.resource("s3", f"{team}-logs")

        a.managed_policy(f"{team}-team-access", doc(
            allow(["s3:GetObject", "s3:PutObject"], [f"{artifacts}/*", artifacts], "TeamArtifacts"),
            allow(["dynamodb:Query", "dynamodb:GetItem"], events, "TeamEvents"),
        ))
        a.managed_policy(f"{team}-readonly-access", doc(
            allow(["s3:GetObject"], [f"{logs}/*", logs], "ReadLogs"),
            allow(["dynamodb:Scan"], events, "ReadEvents"),
        ))
        a.role(f"{team}-readonly", trust_root(), managed=[f"{team}-readonly-access"])
        a.role(f"{team}-ecs-task", trust_service("ecs-tasks.amazonaws.com"), managed=[f"{team}-team-access"])
        a.group(f"{team}-team", managed=[f"{team}-team-access", "ReadOnlyAccess"], inline={
            f"{team}-assume-readonly": doc(allow("sts:AssumeRole", f"{IAM}:role/{team}-readonly")),
        })
        for _ in range(rng.randint(2, 4)):
            a.user(f"{names.pop()}-{team}", groups=[f"{team}-team"], team=team)

    # Legit service roles that touch sensitive data (not reachable by humans)
    a.role("payments-api", trust_service("ecs-tasks.amazonaws.com"), inline={
        "payments-api-secrets": doc(allow("secretsmanager:GetSecretValue", payment_key)),
    })
    a.role("orders-service", trust_service("ecs-tasks.amazonaws.com"), inline={
        "orders-db-secret": doc(allow("secretsmanager:GetSecretValue", prod_db),
                                allow("kms:Decrypt", kms_key)),
    })
    a.role("OrganizationAccountAccessRole", trust_root(), managed=["AdministratorAccess"])

    # Legit admins
    a.group("Admins", managed=["AdministratorAccess"])
    a.user("alice-admin", groups=["Admins"], team="security")
    a.user("raj-sre", groups=["Admins"], team="platform")

    # --- PLANTED 1: wildcard role chain ---------------------------------------
    # Developers may assume "ci-*" roles; ci-deploy can assume prod-admin.
    a.managed_policy("ci-deploy-policy", doc(
        allow(["s3:PutObject"], "arn:aws:s3:::*-artifacts/*", "PushArtifacts"),
        allow("sts:AssumeRole", f"{IAM}:role/prod-admin", "DeployToProd"),
    ))
    a.managed_policy("ci-test-policy", doc(allow(["s3:GetObject"], "arn:aws:s3:::*-artifacts/*", "ReadArtifacts")))
    a.role("ci-deploy", trust_root(), managed=["ci-deploy-policy"])
    a.role("ci-test", trust_root(), managed=["ci-test-policy"])
    a.role("prod-admin", trust_root(), managed=["AdministratorAccess"])
    a.group("Developers", inline={
        "dev-assume-ci": doc(allow("sts:AssumeRole", f"{IAM}:role/ci-*", "AssumeCIRoles")),
        "dev-staging": doc(allow("secretsmanager:GetSecretValue", staging_db, "StagingSecrets")),
    })
    for n in ["dev-intern", "maria-dev", "tom-dev"]:
        a.user(n, groups=["Developers"], team="engineering")

    # --- PLANTED 2: iam:PassRole + lambda:CreateFunction ---------------------
    a.role("lambda-billing-exporter", trust_service("lambda.amazonaws.com"), inline={
        "billing-export": doc(
            allow(["s3:GetObject"], [f"{pii}/*", pii], "ReadCustomerData"),
            allow(["s3:PutObject"], "arn:aws:s3:::billing-reports/*", "WriteReports"),
        ),
    })
    a.user("data-analyst", groups=["data-team"], team="data", inline={
        "analyst-lambda-dev": doc(
            allow(["lambda:CreateFunction", "lambda:InvokeFunction", "lambda:UpdateFunctionCode"], "*", "LambdaDev"),
            allow("iam:PassRole", "*", "PassAnyRole"),
        ),
    })

    # --- PLANTED 3: stale explicit trust on a backup role --------------------
    a.user("contractor-bob", team="contractor", inline={
        "contractor-readonly": doc(allow(["s3:GetObject"], "arn:aws:s3:::web-artifacts/*", "WebArtifacts")),
    })
    a.role("legacy-backup", trust_principal(f"{IAM}:user/contractor-bob"), inline={
        "backup-access": doc(
            allow("s3:*", [backups, f"{backups}/*"], "BackupBucket"),
            allow("kms:Decrypt", kms_key, "DecryptBackups"),
        ),
    })

    # --- PLANTED 4: wildcard secret read for support ------------------------
    a.group("support-oncall", inline={
        "support-debug": doc(allow(["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"], "*", "DebugSecrets")),
    })
    a.user("support-jane", groups=["support-oncall"], team="support")

    # --- IRSA role for EKS (trusted by K8s service accounts via OIDC) --------
    # Meant for shop/orders, but the trust `sub` is a namespace wildcard (planted in gen_k8s).
    a.role("eks-orders-irsa", trust_irsa("shop", "*"), inline={
        "orders-irsa-secrets": doc(
            allow("secretsmanager:GetSecretValue", prod_db, "OrdersDbSecret"),
            allow("kms:Decrypt", kms_key, "DecryptOrders"),
        ),
    })

    planted = [
        {"id": "role-chain", "source": "dev-intern", "target": "prod-db-credentials",
         "via": ["Developers", "dev-assume-ci", "ci-deploy", "ci-deploy-policy", "prod-admin"]},
        {"id": "passrole-lambda", "source": "data-analyst", "target": "customer-pii",
         "via": ["analyst-lambda-dev", "lambda-billing-exporter"]},
        {"id": "stale-trust", "source": "contractor-bob", "target": "prod-backups",
         "via": ["legacy-backup"]},
        {"id": "wildcard-secrets", "source": "support-jane", "target": "payment-api-key",
         "via": ["support-oncall", "support-debug"]},
    ]
    return a.export(), {"Account": ACCOUNT, "Resources": a.resources}, planted


def write(out_dir: Path, seed: int = 42) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    auth, resources, planted = build(seed)
    (out_dir / "aws_iam.json").write_text(json.dumps(auth, indent=2))
    (out_dir / "resources.json").write_text(json.dumps(resources, indent=2))
    (out_dir / "planted.json").write_text(json.dumps(planted, indent=2))
    return out_dir
