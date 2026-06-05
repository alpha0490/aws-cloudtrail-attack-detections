# Tests

Two layers of validation guard these rules, and they catch different things:

| Layer | Tool | Catches |
|---|---|---|
| **Schema** | `sigma check rules/` | malformed YAML, bad/missing fields, invalid UUIDs, broken conditions, bad ATT&CK tags |
| **Logic** | `python3 tests/run_tests.py` | a rule that **doesn't fire** on a real attack, or **over-fires** on benign activity (typo'd `eventName`, wrong field path, broken `condition`) |

`sigma check` passing only means a rule is *well-formed* — not that it actually detects anything.
The logic tests close that gap.

## What the logic tests do

[`test_cases.yaml`](test_cases.yaml) pairs each covered rule with two sample CloudTrail events:

- a **positive** event that represents the attack — the rule **must** match it, and
- a **negative**, benign event — the rule **must not** match it.

[`run_tests.py`](run_tests.py) loads each rule's `detection:` block and evaluates it against both
events. It implements the Sigma matching subset these rules use: case-insensitive equality, value
lists (OR), the `contains` / `startswith` / `endswith` / `exists` modifiers, boolean values, and
conditions built from `and` / `or` / `not`. The negative cases are chosen to exercise the exact
discriminator (e.g. MFA used vs not, admin vs read-only policy ARN, GPU vs small instance type, an
instance profile present vs absent), so they fail loudly if a rule's logic drifts.

## Run it

```bash
python3 tests/run_tests.py      # standalone; exits non-zero on any failure
pytest tests/run_tests.py       # same cases, under pytest, if you prefer
```

CI runs the standalone form on every push/PR that touches `rules/`, `scripts/`, or `tests/`.

## Scope & honesty

- These are **unit tests of rule logic against synthetic events**, not end-to-end SIEM tests. They
  prove the detection logic is correct; they do **not** prove field names match your live CloudTrail
  schema, nor do they exercise the SIEM-side enrichment/baseline layer.
- The evaluator deliberately covers only the Sigma features these rules use. If you add a rule using
  a feature it doesn't support (e.g. `1 of selection_*`, `re`/regex modifiers, near/aggregation),
  extend `run_tests.py` alongside it.
- **Multi-document correlation rules** (brute force, password spray, access-denied burst) are not
  logic-tested here — they need an event stream, not a single event — so they rely on `sigma check`.
- For higher-fidelity validation, pair this with attack emulation
  ([Stratus Red Team](https://stratus-red-team.cloud/)): run the technique, then confirm the rule
  fires on the real CloudTrail event it produces. Cases carrying a `stratus:` key in
  `test_cases.yaml` are the synthetic stand-ins for those live runs — see
  [`../docs/validation-with-stratus.md`](../docs/validation-with-stratus.md).

## Adding a test when you add a rule

Append a block to `test_cases.yaml`:

```yaml
- rule: rules/<tactic>/<your-rule>.yml
  positive:
    note: what the attack looks like
    event: { eventSource: <svc>.amazonaws.com, eventName: <Action>, ... }
  negative:
    note: a benign event that must NOT match
    event: { eventSource: <svc>.amazonaws.com, eventName: <SomethingElse> }
```

Then run `python3 tests/run_tests.py` until green.
