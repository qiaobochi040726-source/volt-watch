"""Keep finding documentation in sync without running an audit or a reader."""

import ast
from fnmatch import fnmatchcase
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _finding_names(source):
    """Inspect constructors, including ones outside the CHECKS registry."""
    names = set()
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name) or node.func.id != "Finding":
            continue
        check = next((item.value for item in node.keywords if item.arg == "check"), None)
        assert isinstance(check, ast.Constant) and isinstance(check.value, str), (
            "Finding.check must be a literal string so documentation can be checked"
        )
        names.add(check.value)
    return names


def _emitted_names():
    # CHECKS invokes functions in checks.py, including through local wrappers.
    # Scan the whole module so a newly added check cannot escape this contract
    # before it is registered. audit() also appends auditor.degraded separately.
    return set().union(*(
        _finding_names((ROOT / "volt_watch" / name).read_text(encoding="utf-8"))
        for name in ("checks.py", "auditor.py")
    ))


def _table_names(markdown, section):
    """Read only leading backtick cells in the named level-two section."""
    inside = False
    names = []
    for line in markdown.splitlines():
        if line.startswith("## "):
            inside = line[3:].strip() == section
        if inside and line.lstrip().startswith("|"):
            cell = line.split("|", 2)[1].strip()
            if cell.startswith("`") and cell.endswith("`"):
                names.append(cell[1:-1])
    assert names, f"No check rows found in {section}"
    assert len(names) == len(set(names)), f"Duplicate check rows in {section}"
    return set(names)


def _assert_checks(documented, emitted):
    assert documented == emitted, (
        f"Missing check rows: {sorted(emitted - documented)}; "
        f"dead check rows: {sorted(documented - emitted)}"
    )


def _assert_privileges(patterns, emitted):
    covered = set()
    for pattern in patterns:
        matches = {name for name in emitted if fnmatchcase(name, pattern)}
        assert matches, f"Dead privileges row: {pattern}"
        covered.update(matches)
    assert covered == emitted, f"Missing privileges rows: {sorted(emitted - covered)}"


def test_readme_checks_match_finding_constructors():
    markdown = (ROOT / "README.md").read_text(encoding="utf-8")
    _assert_checks(_table_names(markdown, "Checks"), _emitted_names())


def test_readme_privileges_cover_findings_without_dead_rows():
    markdown = (ROOT / "README.md").read_text(encoding="utf-8")
    _assert_privileges(_table_names(markdown, "Privileges"), _emitted_names())


def test_ast_finds_nested_constructors_not_comments_or_strings():
    source = '''
# Finding(check="comment.not_a_check")
text = 'Finding(check="string.not_a_check")'
def check():
    return [Finding(check="x.y", severity="warning")]
'''
    assert _finding_names(source) == {"x.y"}


def test_dynamic_check_names_cannot_silently_escape_documentation():
    with pytest.raises(AssertionError, match="literal string"):
        _finding_names('Finding(check=check_name)')


def test_new_finding_without_a_check_row_fails():
    emitted = _finding_names('Finding(check="x.y")')
    with pytest.raises(AssertionError, match="Missing check rows"):
        _assert_checks(set(), emitted)


def test_removed_finding_with_a_check_row_fails():
    with pytest.raises(AssertionError, match="dead check rows"):
        _assert_checks({"x.y", "x.removed"}, {"x.y"})


def test_privileges_allow_existing_namespace_and_suffix_wildcards():
    _assert_privileges({"sshd.*", "power.unit_*"}, {
        "sshd.exposed", "sshd.root_login", "power.unit_failed", "power.unit_disabled",
    })


def test_new_finding_without_privileges_coverage_fails():
    with pytest.raises(AssertionError, match="Missing privileges rows"):
        _assert_privileges({"sshd.*"}, {"sshd.exposed", "new.check"})


def test_dead_privileges_row_fails_even_when_other_rows_cover_everything():
    with pytest.raises(AssertionError, match="Dead privileges row"):
        _assert_privileges({"sshd.*", "removed.*"}, {"sshd.exposed"})


def test_table_parser_stays_in_the_requested_section():
    markdown = '''## Checks
| Check | Meaning |
| --- | --- |
| `x.y` | a finding |
## Privileges
| `other.check` | yes |
'''
    assert _table_names(markdown, "Checks") == {"x.y"}


def test_missing_table_fails():
    with pytest.raises(AssertionError, match="No check rows"):
        _table_names("## Checks\nNo table here.", "Checks")


def test_duplicate_table_rows_fail():
    with pytest.raises(AssertionError, match="Duplicate check rows"):
        _table_names("## Checks\n| `x.y` | info |\n| `x.y` | info |", "Checks")
