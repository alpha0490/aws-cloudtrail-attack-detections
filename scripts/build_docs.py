#!/usr/bin/env python3
"""Regenerate the IR cheatsheet and the ATT&CK coverage matrix from the Sigma rules.

The Sigma rules under rules/ are the single source of truth. Run this after adding or
changing a rule so the docs stay in sync:

    python3 scripts/build_docs.py

Only dependency is PyYAML (`pip install pyyaml`).
"""
import glob
import os
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ATT&CK tactics in kill-chain order: (rules/ folder, display name, tactic id)
TACTICS = [
    ("initial-access", "Initial Access", "TA0001"),
    ("execution", "Execution", "TA0002"),
    ("persistence", "Persistence", "TA0003"),
    ("privilege-escalation", "Privilege Escalation", "TA0004"),
    ("defense-evasion", "Defense Evasion", "TA0005"),
    ("credential-access", "Credential Access", "TA0006"),
    ("discovery", "Discovery", "TA0007"),
    ("lateral-movement", "Lateral Movement", "TA0008"),
    ("collection", "Collection", "TA0009"),
    ("exfiltration", "Exfiltration", "TA0010"),
    ("impact", "Impact", "TA0040"),
]

# Authoritative ATT&CK technique names (sourced from MITRE ATT&CK / pySigma).
TECHNIQUE_NAMES = {
    "T1021.007": "Cloud Services",
    "T1069.003": "Cloud Groups",
    "T1070": "Indicator Removal",
    "T1078.004": "Cloud Accounts",
    "T1087.004": "Cloud Account",
    "T1098": "Account Manipulation",
    "T1098.001": "Additional Cloud Credentials",
    "T1098.003": "Additional Cloud Roles",
    "T1110": "Brute Force",
    "T1110.003": "Password Spraying",
    "T1136.003": "Cloud Account",
    "T1199": "Trusted Relationship",
    "T1485": "Data Destruction",
    "T1486": "Data Encrypted for Impact",
    "T1490": "Inhibit System Recovery",
    "T1496": "Resource Hijacking",
    "T1525": "Implant Internal Image",
    "T1526": "Cloud Service Discovery",
    "T1528": "Steal Application Access Token",
    "T1530": "Data from Cloud Storage",
    "T1531": "Account Access Removal",
    "T1537": "Transfer Data to Cloud Account",
    "T1538": "Cloud Service Dashboard",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1550": "Use Alternate Authentication Material",
    "T1550.001": "Application Access Token",
    "T1552": "Unsecured Credentials",
    "T1555.006": "Cloud Secrets Management Stores",
    "T1556.006": "Multi-Factor Authentication",
    "T1562": "Impair Defenses",
    "T1562.001": "Disable or Modify Tools",
    "T1562.008": "Disable or Modify Cloud Logs",
    "T1567": "Exfiltration Over Web Service",
    "T1578": "Modify Cloud Compute Infrastructure",
    "T1578.005": "Modify Cloud Compute Configurations",
    "T1580": "Cloud Infrastructure Discovery",
    "T1610": "Deploy Container",
    "T1648": "Serverless Execution",
    "T1651": "Cloud Administration Command",
}

# Notable AWS-relevant IaaS techniques not yet covered (kept honest; PRs welcome).
TODO_GAPS = [
    ("T1190", "Exploit Public-Facing Application", "Limited CloudTrail visibility; usually seen in app/WAF logs."),
    ("T1098.004", "SSH Authorized Keys", "Partially covered via EC2 key pairs; in-instance authorized_keys edits are not in CloudTrail."),
    ("T1213", "Data from Information Repositories", "e.g. CodeCommit/Wiki access patterns."),
    ("T1567.002", "Exfiltration to Cloud Storage", "Cross-account/3rd-party storage exfil paths."),
    ("T1606.002", "Forge Web Credentials: SAML Tokens", "Identity-provider side; correlate with sts:AssumeRoleWithSAML."),
    ("T1535", "Unused/Unsupported Cloud Regions", "Activity in normally-idle regions."),
    ("T1612", "Build Image on Host", "Container image build abuse."),
    ("T1619", "Cloud Storage Object Discovery", "Partially covered via S3 ListObjects."),
    ("T1484.002", "Trust Modification (Org/SCP)", "AWS Organizations policy/SCP tampering."),
    ("T1119", "Automated Collection", "Scripted multi-service data gathering."),
]


def mitre_link(tid):
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def tactic_link(taid):
    return "https://attack.mitre.org/tactics/" + taid + "/"


def esc(s):
    return str(s).replace("\n", " ").replace("|", "\\|").strip()


def first_sentence(text, limit=160):
    text = " ".join(str(text).split())
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0]
    return cut + "…"


def load_rules():
    """Return list of normalized rule dicts derived from every .yml under rules/."""
    rules = []
    for path in sorted(glob.glob(os.path.join(ROOT, "rules", "**", "*.yml"), recursive=True)):
        docs = [d for d in yaml.safe_load_all(open(path)) if d]
        corr = next((d for d in docs if "correlation" in d), None)
        base = next((d for d in docs if "detection" in d), None)
        main = corr or base
        if not main:
            continue
        rel = os.path.relpath(path, ROOT)
        tactic = rel.split(os.sep)[1]
        tech_ids = [t.split("attack.")[1].upper() for t in main.get("tags", [])
                    if t.startswith("attack.t")]

        events, fields = [], []
        det = (base or {}).get("detection", {})
        for name, block in det.items():
            if name in ("condition", "timeframe") or not isinstance(block, dict):
                continue
            for key in block:
                fbase = key.split("|")[0]
                if name.startswith("selection") and fbase == "eventName":
                    val = block[key]
                    events.extend(val if isinstance(val, list) else [val])
                elif fbase != "eventName" and fbase not in fields:
                    fields.append(fbase)

        note = "Level: **%s**." % main.get("level", "n/a")
        if corr:
            c = corr["correlation"]
            gb = ", ".join(c.get("group-by", []))
            cond = c.get("condition", {})
            gte = cond.get("gte")
            if c.get("type") == "value_count":
                note = "Correlation: ≥%s distinct `%s` / %s per `%s`. %s" % (
                    gte, cond.get("field"), c.get("timespan"), gb, note)
                fields.append(cond.get("field"))
            else:
                note = "Correlation: ≥%s events / %s per `%s`. %s" % (
                    gte, c.get("timespan"), gb, note)
            fields.extend(c.get("group-by", []))

        fps = main.get("falsepositives") or []
        if fps:
            note += " FP: " + first_sentence("; ".join(fps), 110)

        if not events:
            sel = det.get("selection", {}) if isinstance(det.get("selection"), dict) else {}
            events_disp = ", ".join("%s=%s" % (k.split("|")[0], v) for k, v in sel.items()) or "(see rule)"
        else:
            events_disp = ", ".join("`%s`" % e for e in dict.fromkeys(events))

        # always-useful IR context fields
        for ctx in ("userIdentity.arn", "sourceIPAddress", "userAgent", "awsRegion"):
            if ctx not in fields:
                fields.append(ctx)

        rules.append({
            "path": rel, "tactic": tactic, "title": main.get("title", rel),
            "tech_ids": tech_ids, "events_disp": events_disp,
            "indicates": first_sentence(main.get("description", "")),
            "fields": fields, "note": note,
        })
    return rules


def tname(tid):
    return TECHNIQUE_NAMES.get(tid, "")


def build_cheatsheet(rules):
    out = []
    out.append("# AWS CloudTrail Incident Responder Cheatsheet\n")
    out.append("Fast lookup of suspicious AWS CloudTrail activity, organized by MITRE ATT&CK tactic. "
               "Each row links to a ready-to-use [Sigma rule](../rules/). This file is generated from the "
               "rules by `scripts/build_docs.py` — do not edit by hand.\n")
    out.append("> **Tip:** the highest-signal fields to pivot on for almost any CloudTrail event are "
               "`userIdentity.arn`, `sourceIPAddress`, `userAgent`, `eventName`, and `awsRegion`.\n")
    # quick tactic index
    out.append("**Jump to:** " + " · ".join(
        "[%s](#%s)" % (name, name.lower().replace(" ", "-")) for _, name, _ in TACTICS) + "\n")

    by_tactic = {f: [] for f, _, _ in TACTICS}
    for r in rules:
        by_tactic.setdefault(r["tactic"], []).append(r)

    for folder, name, taid in TACTICS:
        rs = sorted(by_tactic.get(folder, []), key=lambda x: x["path"])
        out.append("\n## %s\n" % name)
        out.append("ATT&CK tactic: [%s](%s) — %d detection(s).\n" % (taid, tactic_link(taid), len(rs)))
        out.append("| Technique / Activity | ATT&CK ID | CloudTrail event(s) | What it indicates | "
                   "Key fields to inspect | Detection notes | Sigma rule |")
        out.append("|---|---|---|---|---|---|---|")
        for r in rs:
            ids = ", ".join("[%s](%s)" % (i, mitre_link(i)) for i in r["tech_ids"]) or "—"
            fields = ", ".join("`%s`" % f for f in r["fields"])
            fname = os.path.basename(r["path"])
            link = "[`%s`](../%s)" % (fname, r["path"])
            title = r["title"].replace("AWS ", "", 1)
            out.append("| %s | %s | %s | %s | %s | %s | %s |" % (
                esc(title), ids, esc(r["events_disp"]), esc(r["indicates"]),
                esc(fields), esc(r["note"]), link))
    out.append("")
    return "\n".join(out)


def build_matrix(rules):
    total = len(rules)
    tech_ids = sorted({i for r in rules for i in r["tech_ids"]})
    out = []
    out.append("# MITRE ATT&CK Cloud (IaaS / AWS) Coverage Matrix\n")
    out.append("Coverage of the ATT&CK Cloud (IaaS) matrix by the AWS CloudTrail Sigma rules in this repo. "
               "Generated from the rules by `scripts/build_docs.py` — do not edit by hand.\n")
    out.append("**Coverage:** %d rules across %d tactics and %d ATT&CK techniques/sub-techniques.\n"
               % (total, len([t for t in TACTICS if any(r['tactic'] == t[0] for r in rules)]), len(tech_ids)))
    out.append("Legend: ✅ covered (rule exists) · ☐ TODO (gap, contributions welcome).\n")

    by_tactic = {}
    for r in rules:
        by_tactic.setdefault(r["tactic"], []).append(r)

    out.append("## Coverage by tactic\n")
    for folder, name, taid in TACTICS:
        rs = by_tactic.get(folder, [])
        out.append("\n### %s ([%s](%s))\n" % (name, taid, tactic_link(taid)))
        # group rules by primary (first) technique id
        groups = {}
        for r in sorted(rs, key=lambda x: x["path"]):
            key = r["tech_ids"][0] if r["tech_ids"] else "—"
            groups.setdefault(key, []).append(r)
        out.append("| | ATT&CK ID | Technique | Rules |")
        out.append("|---|---|---|---|")
        for tid in sorted(groups):
            link = "[%s](%s)" % (tid, mitre_link(tid)) if tid != "—" else "—"
            files = ", ".join("[`%s`](../%s)" % (os.path.basename(x["path"]), x["path"])
                              for x in groups[tid])
            out.append("| ✅ | %s | %s | %s |" % (link, esc(tname(tid)), files))

    out.append("\n## Known gaps / TODO\n")
    out.append("AWS-relevant IaaS techniques not yet covered (or only partially). PRs welcome — "
               "see [CONTRIBUTING.md](../CONTRIBUTING.md).\n")
    out.append("| | ATT&CK ID | Technique | Note |")
    out.append("|---|---|---|---|")
    for tid, nm, note in TODO_GAPS:
        out.append("| ☐ | [%s](%s) | %s | %s |" % (tid, mitre_link(tid), esc(nm), esc(note)))
    out.append("")
    return "\n".join(out)


def main():
    rules = load_rules()
    with open(os.path.join(ROOT, "cheatsheet", "README.md"), "w") as f:
        f.write(build_cheatsheet(rules))
    with open(os.path.join(ROOT, "docs", "mitre-matrix.md"), "w") as f:
        f.write(build_matrix(rules))
    print("Built cheatsheet/README.md and docs/mitre-matrix.md from %d rules." % len(rules))


if __name__ == "__main__":
    main()
