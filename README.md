# env-doctor

Find the config that is set everywhere and read nowhere.

```console
$ env-doctor scan .
WARNING unused LEGACY_URL (.env:3)
    LEGACY_URL is declared here but never read
WARNING undeclared LOG_LEVEL (src/api/logging.py:12)
    LOG_LEVEL is read but not declared in any env file
WARNING case-mismatch API_KEY (.env:1)
    API_KEY is read but api_key is declared
ERROR   duplicate-declaration DEBUG (.env:4)
    DEBUG is declared twice in this file
INFO    dynamic-access (src/api/tenants.py:31)
    env name is computed at runtime, so it cannot be verified

1 error(s), 3 warning(s), 1 info(s)
6 file(s) scanned, 18 read(s), 24 declaration(s) in 2 env file(s)
```

## Why this exists

Every codebase accumulates env vars nobody reads. They are cheap to add and
expensive to remove, because removing one might break a deployment you cannot see.
So `.env.example` grows, the docs mention variables that were deleted two refactors
ago, and nobody can answer "is this still used?" without grepping.

The opposite failure is worse: code reads `SENTRY_DSN` and no template mentions it,
so staging works (it was set by hand once) and the next environment does not.

`env-doctor` compares the two sides and reports both directions:

- declared but never read (`unused`),
- read but declared nowhere (`undeclared`),
- declared and read with different capitalisation (`case-mismatch`),
- computed at runtime, so unverifiable (`dynamic-access`).

## Install

```console
git clone https://github.com/aiplusplus360/env-doctor
cd env-doctor
python -m pip install -e .
```

Python 3.9+. Zero dependencies.

## CLI

```console
env-doctor scan .                                      # discover .env files
env-doctor scan src/ --env .env --env .env.example      # explicit declarations
env-doctor scan . --ignore 'CI_*' --ignore 'GITHUB_*'   # skip injected vars
env-doctor scan . --json                                # machine-readable
env-doctor scan . --fail-on warning                     # stricter gate
env-doctor scan . --no-info                             # drop informational rules
env-doctor rules                                        # every rule and its fix
```

Discovered declaration files: `.env`, `.env.example`, `.env.sample`,
`.env.template`, `.env.dist`, `env.example`, `example.env`.

Exit codes: `0` clean at the requested severity, `1` findings at or above
`--fail-on` (default `error`, and only `duplicate-declaration` and
`secret-in-example` are errors), `2` unreadable file.

## What counts as a read

| Pattern | Mode |
| --- | --- |
| `os.environ["X"]`, `environ["X"]` | `required` |
| `os.environ.get("X")` | `required` |
| `os.environ.get("X", "d")`, `os.getenv("X", "d")` | `defaulted` |
| `getenv("X")` | `required` |
| `os.environ.setdefault("X", ...)` | `setdefault` |
| `os.environ[f"PREFIX_{x}"]`, `os.getenv(name)` | `dynamic` |

Comments are stripped before scanning, so a commented-out read does not keep a
variable alive — which is the whole point. Line numbers are preserved.

### Why dynamic access is reported instead of guessed

```python
key = f"TENANT_{tenant_id}_TOKEN"
token = os.environ[key]
```

A static scanner cannot know which names this reads. Reporting every
`TENANT_*` declaration as unused would invite someone to delete live
configuration, so the scanner reports the *site* instead and leaves the decision to
a human or an `--ignore 'TENANT_*'` pattern.

## Library

```python
from envdoctor import scan_paths, parse_env, analyze, gate

files, usages, dynamic = scan_paths(["src/", "scripts/"])
entries = parse_env(open(".env.example").read(), ".env.example")

findings = analyze(usages, entries, dynamic, ignore=["CI_*"])
if gate(findings, "error"):
    raise SystemExit(1)
```

`Finding`, `Usage`, and `EnvEntry` are small value objects; `analyze` is a pure
function of its inputs, which is why the 55-test suite runs in 35 ms.

## Secret detection in example files

`.env.example` is committed. A real credential pasted into it is a leak that a
`.gitignore` cannot help with. Two signals are used:

1. the key name looks sensitive (`SECRET`, `TOKEN`, `PASSWORD`, `API_KEY`, ...)
   and the value is at least 12 characters, or
2. the value matches a known token shape (`sk-...`, `ghp_...`, `xoxb-...`,
   `AKIA...`, `AIza...`) or is a long base64/hex blob.

Placeholders are excluded: `changeme`, `xxx`, `<your-key>`, `${VAR}`, `example`,
`dummy`, numbers, and empty strings. `.env` itself is never scanned for secrets —
only files whose name marks them as examples.

## Rules

| Rule | Severity | Trigger |
| --- | --- | --- |
| `unused` | warning | declared but never read |
| `undeclared` | warning | read but absent from every declaration file |
| `case-mismatch` | warning | declared and read with different case |
| `empty-declaration` | warning | declared with no value |
| `dynamic-access` | info | env name is computed |
| `duplicate-declaration` | error | same key twice in one file |
| `secret-in-example` | error | real-looking credential in an example file |

## JSON report

```json
{
  "total": 5,
  "errors": 1,
  "warnings": 3,
  "infos": 1,
  "by_rule": { "case-mismatch": 1, "duplicate-declaration": 1,
               "dynamic-access": 1, "undeclared": 1, "unused": 1 },
  "clean": false,
  "files_scanned": 6,
  "usages": 18,
  "declarations": 24,
  "dynamic": 1,
  "findings": [
    { "rule": "unused", "severity": "warning", "key": "LEGACY_URL",
      "file": ".env", "line": 3,
      "message": "LEGACY_URL is declared here but never read" }
  ],
  "env_files": [".env", ".env.example"],
  "scanned_files": ["app.py", "src/api/logging.py"]
}
```

## Limitations, stated plainly

- **Python-centric patterns.** `os.environ`, `os.getenv`, `getenv`, and `environ`
  are recognised. Shell `${VAR}`, Node `process.env`, and Go `os.Getenv` are not
  parsed yet; in a polyglot repo, point `scan` at the Python tree or add the
  patterns in `scan_text`.
- **Regex, not an AST.** A variable name assembled across lines is invisible.
- **No value semantics.** A `defaulted` read is not checked against the declared
  value; `env-doctor` compares names only.

Those are deliberate: the tool must run on any Python 3.9 box with no install,
including CI images where adding a parser is a procurement conversation.

## Testing

```console
python -m unittest discover -s tests -v   # 55 tests
python -m doctest envdoctor/core.py
```

## License

MIT.
