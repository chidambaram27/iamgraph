"""Print propose_fix output for the planted cases (dev aid)."""

import json
import sys
import time

from iamgraph import tools as T
from iamgraph.db import get_graph

g = get_graph()
cases = [("dev-intern", "prod-db-credentials"), ("data-analyst", "customer-pii"),
         ("contractor-bob", "prod-backups"), ("support-jane", "payment-api-key")]
for s, t in cases:
    t0 = time.time()
    r = T.propose_fix(g, s, t)
    print("=====", s, t, round(time.time() - t0, 2), "verified", r["verified_no_path_after_fix"])
    for f in r["fixes"]:
        print(" *", f["summary"], "| removed", f["exposures_removed"], "| collateral", f["collateral"])
        print("   alts", f["alternatives_considered"])
        if "after" in f and "-v" in sys.argv:
            print("   after", json.dumps(f["after"]))
        if "command" in f:
            print("   cmd", f["command"])
