#!/usr/bin/env python3
"""Review/provision empty permanent source banks without reloading firewalld.

Runtime creation is not exposed by firewalld's public API. Activate the empty
banks during a separately reviewed maintenance window before large policies.
This command never reloads, changes rules, or replaces an existing ipset.
"""
import argparse
import json
import os
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--apply", action="store_true", help="create missing empty permanent definitions after review")
parser.add_argument("--confirm", default="", help="exact phrase: PROVISION EMPTY PRTHAK SOURCE BANKS")
args = parser.parse_args()


def command(*values):
    # universal_newlines keeps the one-time helper compatible with Python 3.6
    # supplied by older RHEL 8 images. The Go agent itself needs no Python.
    return subprocess.run(["firewall-cmd", *values], check=False, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)


def info(scope, name):
    result = command(*(["--permanent"] if scope == "permanent" else []), "--info-ipset=" + name)
    if result.returncode:
        if "INVALID_IPSET" in result.stderr or "does not exist" in result.stderr:
            return None
        raise SystemExit("Could not inspect an existing source bank; no mutation attempted")
    return result.stdout


plan = []
for bank in ("a", "b", "la", "lb"):
    for family, digit in (("inet", "4"), ("inet6", "6")):
        for slot in range(32):
            name = f"prthak_{bank}{digit}_{slot:02d}"
            existing = info("permanent", name)
            if existing is not None:
                fields = {key.strip(): value.strip() for line in existing.splitlines() if ":" in line for key, value in [line.split(":", 1)]}
                options = dict(option.split("=", 1) for option in fields.get("options", "").split())
                if fields.get("type") != "hash:net" or options.get("family", "inet") != family or set(options) - {"family", "hashsize", "maxelem"} or int(options.get("maxelem", "65536")) < 10000:
                    raise SystemExit("An existing bank has an unexpected definition; no source banks were changed")
            plan.append({"name": name, "family": family, "operation": "preserve" if existing else "create_empty_permanent"})

print(json.dumps({"definitions": plan, "creates": sum(item["operation"] == "create_empty_permanent" for item in plan), "runtime_activation": "Required during a separately reviewed firewall maintenance window; this command never reloads", "policy_time_reload": False}, indent=2))
if args.apply:
    if os.geteuid() != 0 or args.confirm != "PROVISION EMPTY PRTHAK SOURCE BANKS":
        raise SystemExit("Root and the exact reviewed confirmation phrase are required")
    for item in plan:
        if item["operation"] == "preserve":
            continue
        # Recheck immediately before creation; never replace a concurrent object.
        if info("permanent", item["name"]) is not None:
            raise SystemExit("Source bank changed after preview; inspect again")
        result = command("--permanent", "--new-ipset=" + item["name"], "--type=hash:net", "--option=family=" + item["family"], "--option=hashsize=1024", "--option=maxelem=16384")
        if result.returncode:
            raise SystemExit("Permanent provisioning stopped; already-created empty banks remain harmless and can be reviewed")
    print("Empty permanent banks provisioned. No rules changed and no runtime reload was performed.")
