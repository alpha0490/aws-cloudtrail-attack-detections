#!/usr/bin/env python3
"""Behavioral-detection model: classify rules, assign anomaly keys, emit first-seen detections.

A bare match on a high-volume event (e.g. `eventName=Invoke`) is noise. The detection is the
ANOMALY: "this principal did this when it never has before". This script:

  * classifies every rule as SIGNATURE (the event is the attack) or BEHAVIORAL (normal event, only
    suspicious when unconventional for the principal),
  * assigns each behavioral rule an explicit ANOMALY KEY (default: principal + action; sharper per-rule
    overrides),
  * emits native Elastic `new_terms` rules for the high-volume behavioral rules (first-seen over 90d),
  * writes behavioral-keys.yml + docs/fidelity-audit.md,
  * ENFORCES the bar: exits non-zero if an `alert`-tier rule is a bare match on a high-volume event.

Generated artifacts — regenerate with:  python3 scripts/build_behavioral.py
"""
import glob
import json
import os
import shutil
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Events that are constant chatter in a healthy account (a bare match = noise).
HIGH_VOL = {
    "Invoke", "GetObject", "PutObject", "ListObjects", "ListObjectsV2", "Decrypt", "GenerateDataKey",
    "GetCallerIdentity", "AssumeRole", "AssumeRoleWithWebIdentity", "AssumeRoleWithSAML",
    "GetParameter", "GetParameters", "GetParametersByPath", "GetSecretValue", "BatchGetSecretValue",
    "DescribeInstances", "DescribeSecurityGroups", "DescribeVpcs", "DescribeSnapshots", "DescribeImages",
    "DescribeAddresses", "DescribeRegions", "ListRegions", "GetRegions", "ListBuckets", "ListUsers",
    "ListRoles", "ListGroups", "ListPolicies", "GetAccountSummary", "ListAttachedUserPolicies",
    "ListAttachedRolePolicies", "ListGroupsForUser", "SimulatePrincipalPolicy", "DescribeOrganization",
    "ListAccounts", "ListOrganizationalUnitsForParent", "GetSessionToken", "GetFederationToken",
    "DownloadDBLogFilePortion", "DownloadCompleteDBLogFile", "GetAccountAuthorizationDetails",
    "RunTask", "StartTask", "SendCommand", "StartSession", "CreateGrant",
}

# Sharper anomaly keys than the default (principal + action). Field = what makes it "new".
ANOMALY_OVERRIDES = {
    "rules/execution/lambda-invoke.yml": ["userIdentity.arn", "requestParameters.functionName"],
    "rules/execution/ssm-send-command.yml": ["userIdentity.arn", "requestParameters.documentName"],
    "rules/execution/ssm-start-session.yml": ["userIdentity.arn", "requestParameters.target"],
    "rules/execution/ecs-run-task.yml": ["userIdentity.arn", "requestParameters.taskDefinition"],
    "rules/lateral-movement/sts-assume-role.yml": ["userIdentity.arn", "requestParameters.roleArn"],
    "rules/lateral-movement/sts-assume-role-cross-account.yml": ["userIdentity.arn", "requestParameters.roleArn"],
    "rules/credential-access/sts-assume-role-with-web-identity.yml": ["userIdentity.arn", "requestParameters.roleArn"],
    "rules/collection/s3-get-object.yml": ["userIdentity.arn", "requestParameters.bucketName"],
    "rules/collection/s3-mass-list-objects.yml": ["userIdentity.arn", "requestParameters.bucketName"],
    "rules/credential-access/secretsmanager-get-secret-value.yml": ["userIdentity.arn", "requestParameters.secretId"],
    "rules/credential-access/kms-decrypt.yml": ["userIdentity.arn", "sourceIPAddress"],
    "rules/credential-access/kms-create-grant.yml": ["userIdentity.arn", "requestParameters.keyId"],
}
DEFAULT_KEY = ["userIdentity.arn", "eventName"]

SEV = {"informational": ("low", 21), "low": ("low", 21), "medium": ("medium", 47),
       "high": ("high", 73), "critical": ("critical", 99)}


def classify(path):
    docs = [d for d in yaml.safe_load_all(open(path)) if d]
    corr = any("correlation" in d for d in docs)
    base = next((d for d in docs if "detection" in d), None)
    main = next((d for d in docs if "correlation" in d), None) or base
    tier = main.get("tier", "hunt")
    level = main.get("level", "low")
    events, discs = [], set()
    for name, blk in (base or {}).get("detection", {}).items():
        if name in ("condition", "timeframe") or not isinstance(blk, dict):
            continue
        for k, v in blk.items():
            f = k.split("|")[0]
            if f == "eventName":
                events += v if isinstance(v, list) else [v]
            elif f != "eventSource":
                discs.add(f)
    src = ""
    sel = (base or {}).get("detection", {}).get("selection", {})
    if isinstance(sel, dict):
        src = sel.get("eventSource", "")
    bare = not discs and not corr
    highvol = bool(events) and all(e in HIGH_VOL for e in events)
    if corr:
        cls = "correlation"
    elif discs:
        cls = "conditioned"
    elif highvol:
        cls = "bare+highvol"
    else:
        cls = "bare-rare"
    behavioral = cls == "bare+highvol"  # the bare match is junk -> deploy as anomaly
    return dict(tier=tier, level=level, events=events, src=src, cls=cls,
                behavioral=behavioral, highvol=highvol, bare=bare)


def kql(events, src):
    q = "eventName:(%s)" % " or ".join('"%s"' % e for e in events)
    if src:
        q += ' and eventSource:"%s"' % src
    return q


# anomaly resource field -> (Sumo alias, json path to extract or None if already extracted)
DIM = {
    "eventName": ("eventName", None),
    "sourceIPAddress": ("src_ip", None),
    "requestParameters.functionName": ("function_name", "requestParameters.functionName"),
    "requestParameters.roleArn": ("role_arn", "requestParameters.roleArn"),
    "requestParameters.bucketName": ("bucket", "requestParameters.bucketName"),
    "requestParameters.documentName": ("document", "requestParameters.documentName"),
    "requestParameters.target": ("target", "requestParameters.target"),
    "requestParameters.secretId": ("secret_id", "requestParameters.secretId"),
    "requestParameters.keyId": ("key_id", "requestParameters.keyId"),
    "requestParameters.taskDefinition": ("task_def", "requestParameters.taskDefinition"),
}


def sumo_query(title, events, src, key, rationale):
    """A complete, self-contained Sumo Logic first-seen query (the 90-day window is the baseline)."""
    resource = key[1] if len(key) > 1 else "eventName"
    alias, jpath = DIM.get(resource, ("dim", resource if resource.startswith("requestParameters") else None))
    kw = " OR ".join('"%s"' % e for e in events)
    ev = ('eventName = "%s"' % events[0] if len(events) == 1
          else "eventName in (%s)" % ", ".join('"%s"' % e for e in events))
    where = (['eventSource = "%s"' % src] if src else []) + ["(%s)" % ev, "isBlank(errorCode)"]
    L = [
        "// AWS CloudTrail behavioral first-seen — %s" % title,
        "// %s" % rationale,
        "// Run over a 90-DAY range; each row is a (principal, %s) pair first seen in the last 24h." % alias,
        "_sourceCategory=*cloudtrail* (%s)" % kw,
        '| json field=_raw "eventName", "eventSource", "errorCode", "userIdentity.arn",',
        '        "userIdentity.sessionContext.sessionIssuer.arn",',
        '        "sourceIPAddress", "awsRegion"%s' % ((',\n        "%s"' % jpath) if jpath else ""),
        '     as eventName, eventSource, errorCode, raw_arn, issuer_arn,',
        '        src_ip, region%s nodrop' % ((", %s" % alias) if jpath else ""),
        "| where %s" % " and ".join(where),
        "// normalize principal: assumed-role sessions collapse to the role (sessionIssuer); else the identity itself",
        "| if(isBlank(issuer_arn), raw_arn, issuer_arn) as principal",
    ]
    if jpath:
        L.append('| if(isBlank(%s), "unknown", %s) as %s' % (alias, alias, alias))
        if resource == "requestParameters.functionName":
            L.append('| replace(%s, /^arn:aws:lambda:[^:]+:\\d+:function:/, "") as %s' % (alias, alias))
    L += [
        "| min(_messagetime) as first_seen_ms, max(_messagetime) as last_seen_ms, count as events,",
        "      count_distinct(src_ip) as distinct_source_ips, count_distinct(region) as distinct_regions",
        "   by principal, %s" % alias,
        "| where first_seen_ms > (now() - 86400000)",
        '| formatDate(toLong(first_seen_ms), "yyyy-MM-dd HH:mm:ss", "UTC") as first_seen',
        '| formatDate(toLong(last_seen_ms),  "yyyy-MM-dd HH:mm:ss", "UTC") as last_seen',
        "| sort by first_seen_ms asc",
        "| fields principal, %s, first_seen, last_seen, events, distinct_source_ips, distinct_regions" % alias,
    ]
    return "\n".join(L) + "\n"


def main():
    rules = sorted(glob.glob(os.path.join(ROOT, "rules", "**", "*.yml"), recursive=True))
    for sub in ("elastic-newterms", "sumo"):  # clean stale generated queries
        d = os.path.join(ROOT, "dist", "behavioral", sub)
        if os.path.isdir(d):
            shutil.rmtree(d)
    audit = []
    keys = {}
    violations = []
    newterms_written = 0
    for path in rules:
        rel = os.path.relpath(path, ROOT)
        c = classify(path)
        audit.append((rel, c))
        # enforce: an alert must never be a bare high-volume match
        if c["tier"] == "alert" and c["cls"] == "bare+highvol":
            violations.append(rel)
        if c["behavioral"]:
            key = ANOMALY_OVERRIDES.get(rel, DEFAULT_KEY)
            keys[rel] = {"anomaly_key": key, "window": "90d",
                         "rationale": "first time this principal is seen with %s in 90 days"
                                      % (key[1] if len(key) > 1 else key[0])}
            # emit Elastic new_terms detection
            tactic = rel.split(os.sep)[1]
            stem = os.path.splitext(os.path.basename(rel))[0]
            sev, risk = SEV.get(c["level"], ("low", 21))
            nt = {
                "type": "new_terms", "language": "kuery", "index": ["logs-aws.cloudtrail-*", "aws-cloudtrail-*"],
                "name": "AWS first-seen: %s (behavioral)" % stem,
                "description": "Behavioral detection. Fires when (%s) is new for this principal in the "
                               "last 90 days. Source rule: %s. Adjust field names to your Elastic "
                               "CloudTrail mapping (e.g. aws.cloudtrail.* with the Fleet integration)."
                               % (", ".join(keys[rel]["anomaly_key"]), rel),
                "query": kql(c["events"], c["src"]),
                "new_terms_fields": keys[rel]["anomaly_key"],
                "history_window_start": "now-90d",
                "severity": sev, "risk_score": risk,
            }
            outdir = os.path.join(ROOT, "dist", "behavioral", "elastic-newterms", tactic)
            os.makedirs(outdir, exist_ok=True)
            with open(os.path.join(outdir, stem + ".json"), "w") as f:
                json.dump(nt, f, indent=2)
                f.write("\n")
            # full Sumo Logic first-seen query
            sdir = os.path.join(ROOT, "dist", "behavioral", "sumo", tactic)
            os.makedirs(sdir, exist_ok=True)
            with open(os.path.join(sdir, stem + ".sumo"), "w") as f:
                f.write(sumo_query(stem, c["events"], c["src"],
                                   keys[rel]["anomaly_key"], keys[rel]["rationale"]))
            newterms_written += 1

    with open(os.path.join(ROOT, "behavioral-keys.yml"), "w") as f:
        yaml.safe_dump(keys, f, sort_keys=True, default_flow_style=False, width=4096, allow_unicode=True)

    # fidelity audit doc
    from collections import Counter
    counts = Counter(c["cls"] for _, c in audit)
    md = ["# Fidelity audit\n",
          "Generated by `scripts/build_behavioral.py`. Classifies every rule by the "
          "[detection model](detection-model.md): **signature** (the event is the attack) vs "
          "**behavioral** (normal event, suspicious only when unconventional for the principal).\n",
          "| Class | Count | Meaning |", "|---|---|---|",
          "| `conditioned` | %d | matches a malicious condition (real signature) |" % counts["conditioned"],
          "| `correlation` | %d | threshold/sequence (real signature) |" % counts["correlation"],
          "| `bare-rare` | %d | bare event, but rare → the event is the attack (real signature) |" % counts["bare-rare"],
          "| `bare+highvol` | %d | bare match on a high-volume event → **deploy as behavioral (first-seen)** |" % counts["bare+highvol"],
          "",
          "**Enforced bar:** an `alert`-tier rule may never be `bare+highvol`. Violations: %s\n"
          % ("none ✅" if not violations else ", ".join(violations)),
          "## Behavioral rules and their anomaly keys\n",
          "| Rule | Anomaly key (what's \"new\") | Elastic new_terms |", "|---|---|---|"]
    for rel, c in audit:
        if c["behavioral"]:
            k = keys[rel]["anomaly_key"]
            stem = os.path.splitext(os.path.basename(rel))[0]
            tactic = rel.split(os.sep)[1]
            md.append("| `%s` | `%s` | [`%s.json`](../dist/behavioral/elastic-newterms/%s/%s.json) |"
                      % (rel, " + ".join(k), stem, tactic, stem))
    md.append("")
    with open(os.path.join(ROOT, "docs", "fidelity-audit.md"), "w") as f:
        f.write("\n".join(md) + "\n")

    print("Behavioral: %d new_terms rules, %d behavioral keys; classes=%s"
          % (newterms_written, len(keys), dict(counts)))
    if violations:
        print("FIDELITY VIOLATION — alert-tier bare+highvol rules:", violations, file=sys.stderr)
        return 1
    print("Fidelity bar OK: no alert-tier bare+high-volume rules.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
