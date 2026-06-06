#!/usr/bin/env python3
"""Logic tests for the AWS CloudTrail Sigma rules.

`sigma check` validates a rule's SCHEMA. This validates its LOGIC: every case in
tests/test_cases.yaml asserts that a rule fires on a true-positive CloudTrail event and
stays silent on a benign one. It implements the Sigma matching subset these rules use:

  * field equality (case-insensitive, the Sigma default)
  * value lists  -> OR
  * modifiers    -> |contains, |startswith, |endswith, |exists
  * boolean values
  * conditions   -> selection names combined with and / or / not / parentheses

Multi-document correlation rules are covered by `sigma check`, not here (they need an
event stream, not a single event).

Run:   python3 tests/run_tests.py        # exits non-zero on any failure
       pytest tests/run_tests.py         # also works under pytest
"""
import os
import re
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MISSING = object()


def flatten(obj, prefix=""):
    """Turn a nested CloudTrail event into dotted keys, e.g. userIdentity.type."""
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.update(flatten(v, "%s.%s" % (prefix, k) if prefix else k))
    elif isinstance(obj, list):
        out[prefix] = obj  # keep the list itself for membership checks
        for v in obj:       # and flatten dict elements under the same prefix (any-match)
            if isinstance(v, dict):
                out.update(flatten(v, prefix))
    else:
        out[prefix] = obj
    return out


def _as_bool(v):
    return v if isinstance(v, bool) else str(v).strip().lower() == "true"


def _sigma_regex(value):
    """Translate a Sigma value to a regex: `*` -> .* and `?` -> . (wildcards), `\\*`/`\\?` literal."""
    out, i = [], 0
    while i < len(value):
        c = value[i]
        if c == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1])); i += 2
        elif c == "*":
            out.append(".*"); i += 1
        elif c == "?":
            out.append("."); i += 1
        else:
            out.append(re.escape(c)); i += 1
    return "".join(out)


def _match_one(actual, expected, mods):
    if actual is MISSING:
        return False
    if isinstance(expected, bool):
        return _as_bool(actual) == expected
    a = str(actual)
    if "re" in mods:                      # |re modifier: value is a raw regex (case-sensitive)
        try:
            return re.search(str(expected), a) is not None
        except re.error:
            return False
    pat = _sigma_regex(str(expected))
    flags = re.IGNORECASE | re.DOTALL
    if "contains" in mods:
        return re.search(pat, a, flags) is not None
    if "startswith" in mods:
        return re.match(pat, a, flags) is not None
    if "endswith" in mods:
        return re.search(pat + r"\Z", a, flags) is not None
    return re.fullmatch(pat, a, flags) is not None  # Sigma default: full-value, case-insensitive


def _field_match(flat, key, expected):
    field, *mods = key.split("|")
    if "exists" in mods:
        present = any(k == field or k.startswith(field + ".") for k in flat)
        return present == bool(expected)
    actual = flat.get(field, MISSING)
    actuals = actual if isinstance(actual, list) else [actual]
    values = expected if isinstance(expected, list) else [expected]
    return any(_match_one(a, v, mods) for a in actuals for v in values)


def _selection_match(flat, sel):
    if isinstance(sel, dict):       # keys are AND-ed; a list value is OR-ed (handled above)
        return all(_field_match(flat, k, v) for k, v in sel.items())
    if isinstance(sel, list):       # list of maps -> OR
        return any(_selection_match(flat, s) for s in sel)
    raise ValueError("unsupported selection shape: %r" % type(sel))


_TOKEN = re.compile(r"\(|\)|[\w.*]+")


def _eval_condition(condition, sel_results):
    if condition in sel_results:    # the common "condition: selection" case
        return sel_results[condition]
    py = []
    for tok in _TOKEN.findall(condition):
        if tok in ("and", "or", "not", "(", ")"):
            py.append(tok)
        elif tok in sel_results:
            py.append("True" if sel_results[tok] else "False")
        else:
            raise ValueError("unsupported condition token %r in %r" % (tok, condition))
    return bool(eval(" ".join(py), {"__builtins__": {}}, {}))  # noqa: S307 (sanitized tokens only)


def rule_matches(rule, event):
    flat = flatten(event)
    det = rule["detection"]
    sel_results = {name: _selection_match(flat, block)
                   for name, block in det.items() if name != "condition"}
    return _eval_condition(det["condition"], sel_results)


def load_rule(rel):
    path = os.path.join(ROOT, rel)
    for doc in yaml.safe_load_all(open(path)):
        if doc and "detection" in doc:
            return doc
    raise ValueError("no detection document found in %s" % rel)


def _cases():
    with open(os.path.join(ROOT, "tests", "test_cases.yaml")) as fh:
        return yaml.safe_load(fh)


def run():
    cases = _cases()
    passed = failed = 0
    for case in cases:
        rule = load_rule(case["rule"])
        for kind, expected in (("positive", True), ("negative", False)):
            spec = case[kind]
            got = rule_matches(rule, spec["event"])
            if got == expected:
                passed += 1
            else:
                failed += 1
                print("  [FAIL] %s :: %s (%s) -> matched=%s, expected=%s"
                      % (case["rule"], kind, spec.get("note", ""), got, expected))
    print("\n%d/%d logic checks passed across %d rules."
          % (passed, passed + failed, len(cases)))
    return failed == 0


# ---- pytest entrypoint (one parametrized test per case) ---------------------
try:
    import pytest

    _PARAMS = [(c["rule"], k, c[k], exp)
               for c in _cases()
               for k, exp in (("positive", True), ("negative", False))]

    @pytest.mark.parametrize("rel,kind,spec,expected", _PARAMS)
    def test_rule_logic(rel, kind, spec, expected):
        assert rule_matches(load_rule(rel), spec["event"]) == expected
except ImportError:
    pass


if __name__ == "__main__":
    sys.exit(0 if run() else 1)
