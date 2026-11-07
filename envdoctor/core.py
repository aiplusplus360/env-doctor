"""Find the config that is set everywhere and read nowhere.

Every codebase accumulates env vars nobody reads: an old ``REDIS_URL`` still in
``.env.example``, a ``LOG_LEVEL`` that was replaced by a config file, a
``STRIPE_KEY`` that only appears in a deleted branch. Meanwhile the variables that
*are* read are sometimes in no template at all, so they are missing the first time
the service runs somewhere new.

`env-doctor` scans source for reads and compares them to the declared set:

    >>> code = 'token = os.environ["API_TOKEN"]\\nlevel = os.getenv("LOG_LEVEL", "info")\\n'
    >>> usages, dynamic = scan_text(code, "app.py")
    >>> [(u.name, u.mode) for u in usages]
    [('API_TOKEN', 'required'), ('LOG_LEVEL', 'defaulted')]

    >>> env = parse_env("API_TOKEN=\\nLEGACY_URL=http://old\\n")
    >>> findings = analyze(usages, env, dynamic)
    >>> sorted(finding.rule for finding in findings)
    ['empty-declaration', 'undeclared', 'unused']

Statements with a computed key are reported rather than guessed at, because a
false "unused" on a dynamic prefix sends people deleting live configuration.
"""

from __future__ import annotations

import fnmatch
import os
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

__all__ = [
    "Finding",
    "Rule",
    "Usage",
    "EnvEntry",
    "Report",
    "SEVERITIES",
    "RULES",
    "SOURCE_SUFFIXES",
    "SKIP_DIRS",
    "DEFAULT_ENV_FILES",
    "scan_text",
    "scan_file",
    "scan_paths",
    "parse_env",
    "analyze",
    "summarise",
    "gate",
    "SEVERITY_ORDER",
]

SEVERITY_ORDER = {"info": 0, "warning": 1, "error": 2}
SEVERITIES = tuple(SEVERITY_ORDER)

SOURCE_SUFFIXES = (".py", ".js", ".mjs", ".ts", ".tsx", ".jsx", ".go", ".rb", ".php",
                   ".java", ".kt", ".rs", ".sh", ".bash", ".yml", ".yaml", ".toml",
                   ".ini", ".cfg", ".conf", ".env", ".tf", ".dockerfile")
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
             "env", "dist", "build", ".mypy_cache", ".pytest_cache", ".tox",
             ".idea", ".vscode", "target", "vendor"}
DEFAULT_ENV_FILES = (".env", ".env.example", ".env.sample", ".env.template",
                     ".env.dist", "env.example", "example.env")
EXAMPLE_MARKERS = (".example", ".sample", ".template", ".dist")

_NAME = r"[A-Za-z_][A-Za-z0-9_]*"
_ENV_ACCESS = re.compile(
    r"(?:os\.environ\.get|os\.getenv|environ\.get|getenv)\s*\(\s*"
    r"(?P<quote>['\"])(?P<name>" + _NAME + r")(?P=quote)(?P<rest>[^)]*)\)")
_ENV_INDEX = re.compile(
    r"(?:os\.environ|environ)\s*\[\s*(?P<quote>['\"])(?P<name>" + _NAME +
    r")(?P=quote)\s*\]")
_ENV_SETDEFAULT = re.compile(
    r"(?:os\.environ|environ)\.setdefault\s*\(\s*(?P<quote>['\"])(?P<name>" + _NAME +
    r")(?P=quote)")
_ENV_DYNAMIC = re.compile(
    r"(?:os\.environ|environ)\s*\[\s*(?![A-Za-z_'\"]\s*\])[^'\"\]\s]"
    r"|(?:os\.environ\.get|os\.getenv|environ\.get|getenv)\s*\(\s*[^'\"\)\s]")
_COMMENT = re.compile(r"(?<!\S)#.*$")
_EXPORT = re.compile(r"^export\s+")
_ENV_LINE = re.compile(r"^(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<value>.*)$")

_SECRET_VALUE = re.compile(
    r"^(?:sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|xox[bap]-[A-Za-z0-9-]{10,}"
    r"|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|[A-Za-z0-9+/]{32,}={0,2})$")
_PLACEHOLDER = re.compile(
    r"^(?:|x+|X+|\*+|\.\.\.|changeme|change_me|CHANGEME|todo|TODO|redacted|REDACTED"
    r"|placeholder|PLACEHOLDER|<[^>]*>|\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*"
    r"|your[-_ ][^ ]*|insert[-_ ][^ ]*|example|dummy|test|fake|none|null|true|false"
    r"|0|1|\d+)$", re.IGNORECASE)
_SECRET_KEY = re.compile(
    r"(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE_?KEY|CREDENTIAL|AUTH)", re.IGNORECASE)


class Finding:
    """One auditing result. ``key`` may be empty for file-level findings."""

    __slots__ = ("rule", "severity", "key", "file", "line", "message")

    def __init__(self, rule: str, severity: str, message: str, key: str = "",
                 file: str = "", line: int = 0) -> None:
        self.rule = rule
        self.severity = severity
        self.key = key
        self.file = file
        self.line = line
        self.message = message

    def as_dict(self) -> Dict[str, Any]:
        return {"rule": self.rule, "severity": self.severity, "key": self.key,
                "file": self.file, "line": self.line, "message": self.message}

    def __repr__(self) -> str:
        return "Finding(%s, %s, %r)" % (self.severity, self.rule, self.key)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Finding):
            return NotImplemented
        return (self.rule, self.key, self.file, self.line) == (
            other.rule, other.key, other.file, other.line)

    def __hash__(self) -> int:
        return hash((self.rule, self.key, self.file, self.line))


class Rule:
    __slots__ = ("code", "severity", "summary", "remediation")

    def __init__(self, code: str, severity: str, summary: str, remediation: str) -> None:
        self.code = code
        self.severity = severity
        self.summary = summary
        self.remediation = remediation

    def as_dict(self) -> Dict[str, str]:
        return {"code": self.code, "severity": self.severity, "summary": self.summary,
                "remediation": self.remediation}


RULES: Tuple[Rule, ...] = (
    Rule("unused", "warning", "declared in an env file but never read by the code",
         "delete it, or keep it deliberately with an ignore pattern"),
    Rule("undeclared", "warning", "read by the code but absent from every env template",
         "add it to .env.example so new environments are complete"),
    Rule("case-mismatch", "warning", "declared and read with different capitalisation",
         "use one spelling; most platforms are case-sensitive"),
    Rule("dynamic-access", "info", "env name is computed, so it cannot be verified",
         "use a literal name or annotate the prefix in an ignore list"),
    Rule("duplicate-declaration", "error", "the same key is declared twice in one file",
         "keep one definition"),
    Rule("secret-in-example", "error", "an example file contains a real-looking secret",
         "replace it with a placeholder and rotate the credential"),
    Rule("empty-declaration", "warning", "key is declared with no value",
         "use a placeholder so the expected format is visible"),
)


class Usage:
    """One place the code reads or writes an environment variable."""

    __slots__ = ("name", "file", "line", "mode")

    def __init__(self, name: str, file: str, line: int, mode: str) -> None:
        self.name = name
        self.file = file
        self.line = line
        self.mode = mode

    def as_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "file": self.file, "line": self.line, "mode": self.mode}

    def __repr__(self) -> str:
        return "Usage(%r, %s:%d, %s)" % (self.name, self.file, self.line, self.mode)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Usage):
            return NotImplemented
        return (self.name, self.file, self.line) == (other.name, other.file, other.line)

    def __hash__(self) -> int:
        return hash((self.name, self.file, self.line))


class EnvEntry:
    """One ``KEY=VALUE`` line from a dotenv file."""

    __slots__ = ("key", "value", "file", "line", "quoted", "exported")

    def __init__(self, key: str, value: str, file: str, line: int,
                 quoted: bool = False, exported: bool = False) -> None:
        self.key = key
        self.value = value
        self.file = file
        self.line = line
        self.quoted = quoted
        self.exported = exported

    @property
    def is_example(self) -> bool:
        lowered = self.file.lower()
        return any(marker in lowered for marker in EXAMPLE_MARKERS)

    def as_dict(self) -> Dict[str, Any]:
        return {"key": self.key, "file": self.file, "line": self.line,
                "value": self.value, "example": self.is_example}

    def __repr__(self) -> str:
        return "EnvEntry(%r, %s:%d)" % (self.key, self.file, self.line)


def _strip_comment(line: str) -> str:
    """Remove a trailing comment, keeping ``#`` inside quotes."""
    quote: Optional[str] = None
    for position, character in enumerate(line):
        if quote:
            if character == quote:
                quote = None
        elif character in "\"'":
            quote = character
        elif character == "#" and (position == 0 or line[position - 1].isspace()):
            return line[:position]
    return line


def scan_text(text: str, filename: str = "<text>") -> Tuple[List[Usage], List[Usage]]:
    """Find env access in one file. Returns ``(usages, dynamic)``.

    >>> usages, dynamic = scan_text('a = os.environ["A"]\\nb = os.getenv("B", "x")\\n')
    >>> [(u.name, u.mode) for u in usages]
    [('A', 'required'), ('B', 'defaulted')]
    >>> scan_text('os.environ[f"PREFIX_{name}"]')[1][0].mode
    'dynamic'
    """
    usages: List[Usage] = []
    dynamic: List[Usage] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = _COMMENT.sub("", raw)
        if not line.strip():
            continue
        matched = False
        for pattern, mode in ((_ENV_SETDEFAULT, "setdefault"),):
            for match in pattern.finditer(line):
                usages.append(Usage(match.group("name"), filename, number, mode))
                matched = True
        for match in _ENV_INDEX.finditer(line):
            usages.append(Usage(match.group("name"), filename, number, "required"))
            matched = True
        for match in _ENV_ACCESS.finditer(line):
            rest = match.group("rest").strip()
            mode = "defaulted" if rest.startswith(",") else "required"
            usages.append(Usage(match.group("name"), filename, number, mode))
            matched = True
        if not matched:
            for _match in _ENV_DYNAMIC.finditer(line):
                dynamic.append(Usage("<dynamic>", filename, number, "dynamic"))
                break
    usages.sort(key=lambda usage: (usage.line, usage.name))
    return usages, dynamic


def parse_env(text: str, filename: str = ".env") -> List[EnvEntry]:
    """Parse dotenv syntax: comments, ``export``, quotes, empty values.

    >>> [entry.key for entry in parse_env("A=1\\n# B=2\\nexport C=3\\nD=\\n")]
    ['A', 'C', 'D']
    >>> parse_env('E="two words"')[0].value
    'two words'
    """
    entries: List[EnvEntry] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = _strip_comment(raw).strip()
        if not line:
            continue
        exported = False
        if _EXPORT.match(line):
            exported = True
            line = _EXPORT.sub("", line).strip()
        match = _ENV_LINE.match(line)
        if not match:
            continue
        key = match.group("key")
        value = match.group("value").strip()
        quoted = False
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
            quoted = True
        entries.append(EnvEntry(key, value, filename, number, quoted, exported))
    return entries


def scan_file(path: str) -> Tuple[List[Usage], List[Usage]]:
    """Scan one file, decoding as UTF-8 and ignoring unreadable bytes."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as stream:
            return scan_text(stream.read(), path)
    except OSError:
        return [], []


def _looks_like_source(path: str) -> bool:
    name = os.path.basename(path)
    if name.startswith(".env"):
        return False
    lowered = name.lower()
    return any(lowered.endswith(suffix) for suffix in SOURCE_SUFFIXES)


def iter_source_files(root: str) -> Iterable[str]:
    """Yield candidate source files, skipping vendor and VCS directories."""
    if os.path.isfile(root):
        yield root
        return
    for directory, subdirectories, files in os.walk(root):
        subdirectories[:] = sorted(
            name for name in subdirectories if name not in SKIP_DIRS)
        for name in sorted(files):
            path = os.path.join(directory, name)
            if _looks_like_source(path):
                yield path


def scan_paths(paths: Sequence[str]) -> Tuple[List[str], List[Usage], List[Usage]]:
    """Scan many roots. Returns ``(scanned_files, usages, dynamic)``."""
    files: List[str] = []
    usages: List[Usage] = []
    dynamic: List[Usage] = []
    for root in paths:
        for path in iter_source_files(root):
            files.append(path)
            found, computed = scan_file(path)
            usages.extend(found)
            dynamic.extend(computed)
    return files, usages, dynamic


def _matches_ignore(key: str, patterns: Sequence[str]) -> bool:
    return any(fnmatch.fnmatchcase(key, pattern) for pattern in patterns)


def _secret_looking(entry: EnvEntry) -> bool:
    if not entry.is_example:
        return False
    value = entry.value.strip()
    if not value or _PLACEHOLDER.match(value):
        return False
    if value.startswith(("http://", "https://", "/", "./")):
        return False
    if _SECRET_KEY.search(entry.key):
        return len(value) >= 12
    return bool(_SECRET_VALUE.match(value)) and len(value) >= 24


def analyze(usages: Sequence[Usage], entries: Sequence[EnvEntry],
            dynamic: Sequence[Usage] = (), ignore: Sequence[str] = ()) -> List[Finding]:
    """Compare reads against declarations.

    ``entries`` may span several files; the file of each declaration is kept so a
    finding can say exactly where to delete something.

    >>> findings = analyze([Usage("A", "a.py", 1, "required")],
    ...                    parse_env("A=\\nB=1\\n", ".env"))
    >>> [(f.rule, f.key) for f in findings]
    [('empty-declaration', 'A'), ('unused', 'B')]
    """
    findings: List[Finding] = []
    declared: Dict[str, List[EnvEntry]] = {}
    for entry in entries:
        declared.setdefault(entry.key, []).append(entry)

    read_names = {usage.name for usage in usages if usage.mode != "dynamic"}
    read_lowered = {name.lower() for name in read_names}
    declared_names = set(declared)
    lowered_declared = {name.lower(): name for name in declared_names}

    seen_unused: Set[str] = set()
    for entry in entries:
        if entry.key in read_names or entry.key.lower() in read_lowered:
            continue
        if _matches_ignore(entry.key, ignore):
            continue
        if entry.key in seen_unused:
            continue
        seen_unused.add(entry.key)
        findings.append(Finding("unused", "warning",
                                "%s is declared here but never read" % entry.key,
                                entry.key, entry.file, entry.line))

    for entry in entries:
        if entry.value or _matches_ignore(entry.key, ignore):
            continue
        findings.append(Finding("empty-declaration", "warning",
                                "%s is declared with no value" % entry.key,
                                entry.key, entry.file, entry.line))

    if entries:
        for name in sorted(read_names - declared_names):
            if _matches_ignore(name, ignore):
                continue
            if name.lower() in lowered_declared:
                findings.append(Finding("case-mismatch", "warning",
                                        "%s is read but %s is declared"
                                        % (name, lowered_declared[name.lower()]), name))
                continue
            first = next(usage for usage in usages if usage.name == name)
            findings.append(Finding("undeclared", "warning",
                                    "%s is read but not declared in any env file" % name,
                                    name, first.file, first.line))

    by_file: Dict[str, Dict[str, EnvEntry]] = {}
    for entry in entries:
        by_file.setdefault(entry.file, {})
        earlier = by_file[entry.file].get(entry.key)
        if earlier is not None:
            findings.append(Finding("duplicate-declaration", "error",
                                    "%s is declared twice in this file" % entry.key,
                                    entry.key, entry.file, entry.line))
        else:
            by_file[entry.file][entry.key] = entry

    for entry in entries:
        if _secret_looking(entry):
            findings.append(Finding("secret-in-example", "error",
                                    "%s looks like a real credential in an example file"
                                    % entry.key, entry.key, entry.file, entry.line))

    for usage in dynamic:
        findings.append(Finding("dynamic-access", "info",
                                "env name is computed at runtime, so it cannot be verified",
                                "", usage.file, usage.line))

    findings.sort(key=lambda finding: (-SEVERITY_ORDER.get(finding.severity, 0),
                                       finding.key, finding.file, finding.line))
    return findings


class Report:
    """Findings plus counters for a CI summary."""

    __slots__ = ("findings", "files_scanned", "usages", "declarations", "dynamic")

    def __init__(self, findings: Sequence[Finding], files_scanned: int,
                 usages: int, declarations: int, dynamic: int) -> None:
        self.findings = list(findings)
        self.files_scanned = files_scanned
        self.usages = usages
        self.declarations = declarations
        self.dynamic = dynamic

    @property
    def clean(self) -> bool:
        return not any(finding.severity in ("error", "warning") for finding in self.findings)

    def as_dict(self) -> Dict[str, Any]:
        payload = summarise(self.findings)
        payload.update({"clean": self.clean, "files_scanned": self.files_scanned,
                        "usages": self.usages, "declarations": self.declarations,
                        "dynamic": self.dynamic,
                        "findings": [finding.as_dict() for finding in self.findings]})
        return payload

    def __repr__(self) -> str:
        return "Report(%d finding(s))" % len(self.findings)


def summarise(findings: Sequence[Finding]) -> Dict[str, Any]:
    """Counts by severity and by rule, plus a ``clean`` flag."""
    counts = {severity: 0 for severity in SEVERITIES}
    by_rule: Dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
        by_rule[finding.rule] = by_rule.get(finding.rule, 0) + 1
    return {
        "total": len(findings),
        "errors": counts["error"],
        "warnings": counts["warning"],
        "infos": counts["info"],
        "by_rule": dict(sorted(by_rule.items())),
        "clean": not any(f.severity in ("error", "warning") for f in findings),
    }


def gate(findings: Sequence[Finding], fail_on: str = "error") -> bool:
    """``True`` when the run should fail."""
    if fail_on == "never":
        return False
    if fail_on not in SEVERITY_ORDER:
        raise ValueError("fail_on must be one of %s or 'never'" % (SEVERITIES,))
    threshold = SEVERITY_ORDER[fail_on]
    return any(SEVERITY_ORDER.get(finding.severity, 0) >= threshold for finding in findings)
