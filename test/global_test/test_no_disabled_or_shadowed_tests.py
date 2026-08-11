"""Build-integrated hygiene gate against silent unit-test coverage loss.

This meta-test scans every test module in the package's ``test/`` tree and
FAILS the build (as part of the normal pytest run) when it finds either class
of silent coverage loss that has bitten this package before:

1. Duplicate test-function names in the same module. When two module-level
   functions share a name, Python keeps only the last definition, so the
   earlier same-named test is silently shadowed and never runs -- yet the
   suite stays green, hiding the lost coverage.

2. A module-level ``_test_``-prefixed function that pytest *would have
   collected and run* -- i.e. all of its parameters are pytest fixtures (or it
   has none). Pytest only collects names matching ``test_*``; renaming a real
   test to ``_test_...`` quietly disables it while leaving it looking like a
   test. Genuine helper functions are intentionally spared: they always take
   domain arguments (config, response, expected_value, ...) that pytest can
   never inject, which is exactly what makes them helpers rather than tests.

The check uses only the standard library (ast, os), runs inside the existing
pytest step, and adds negligible build time.
"""

import ast
import os
import re

# Pytest's built-in fixtures. A ``_test_``-prefixed function whose parameters
# are drawn entirely from these (plus any fixtures defined in the same module)
# is one pytest would have been able to collect and run -- so if it is
# ``_test_``-prefixed it is a disabled test, not a helper.
PYTEST_BUILTIN_FIXTURES = frozenset(
    {
        "mocker",
        "tmpdir",
        "tmp_path",
        "tmp_path_factory",
        "tmpdir_factory",
        "capsys",
        "capfd",
        "capsysbinary",
        "capfdbinary",
        "monkeypatch",
        "request",
        "caplog",
        "recwarn",
        "pytestconfig",
        "cache",
        "doctest_namespace",
        "record_property",
        "record_testsuite_property",
        "record_xml_attribute",
        "pytester",
        "testdir",
    }
)

# A name that pytest collects as a test (``test_...``) or that mimics one while
# being disabled (``_test_...``).
_TESTLIKE_NAME_RE = re.compile(r"^_?test_")

# Root of the package's own test tree (the parent of this file's directory).
TEST_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _parameter_names(func_node):
    """Return the parameter names of a function definition node."""
    args = func_node.args
    names = [arg.arg for arg in args.posonlyargs + args.args + args.kwonlyargs]
    if args.vararg is not None:
        names.append(args.vararg.arg)
    if args.kwarg is not None:
        names.append(args.kwarg.arg)
    return names


def _local_fixture_names(tree):
    """Return names of pytest fixtures defined at module level in this tree."""
    fixtures = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            # Matches @pytest.fixture, @pytest.fixture(...), @fixture, @fixture(...)
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            name = getattr(target, "attr", None) or getattr(target, "id", None)
            if name == "fixture":
                fixtures.add(node.name)
    return fixtures


def _scan_module(path):
    """Scan one test module. Return (duplicate_findings, disabled_findings)."""
    with open(path, "r") as handle:
        source = handle.read()
    tree = ast.parse(source, filename=path)

    valid_fixtures = PYTEST_BUILTIN_FIXTURES | _local_fixture_names(tree)

    duplicates = []
    disabled = []
    testlike_lines = {}

    # Only module-level functions matter: pytest collects tests at module scope,
    # and Python's last-definition-wins shadowing applies to module namespace.
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        name = node.name

        if _TESTLIKE_NAME_RE.match(name):
            testlike_lines.setdefault(name, []).append(node.lineno)

        if name.startswith("_test_"):
            params = [p for p in _parameter_names(node) if p != "self"]
            if all(param in valid_fixtures for param in params):
                disabled.append((name, node.lineno, params))

    for name, lines in testlike_lines.items():
        if len(lines) > 1:
            duplicates.append((name, lines))

    return duplicates, disabled


def _iter_test_modules(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for filename in filenames:
            if filename.endswith(".py"):
                yield os.path.join(dirpath, filename)


def _relative(path):
    return os.path.relpath(path, os.path.dirname(TEST_ROOT))


def test_no_duplicate_test_function_names():
    """No two test functions in the same module may share a name.

    A same-named later definition silently shadows the earlier one, so the
    shadowed test never runs while the suite stays green.
    """
    offenders = []
    for path in _iter_test_modules(TEST_ROOT):
        duplicates, _ = _scan_module(path)
        for name, lines in duplicates:
            offenders.append(
                "  %s: duplicate test function '%s' defined on lines %s "
                "(only the last definition runs; the earlier one(s) are "
                "silently shadowed)" % (_relative(path), name, lines)
            )

    assert not offenders, (
        "Found duplicate test-function names that silently shadow earlier "
        "tests. Rename or remove the duplicate(s):\n" + "\n".join(sorted(offenders))
    )


def test_no_disabled_underscore_prefixed_tests():
    """No module-level ``_test_``-prefixed function may look like a runnable test.

    Pytest collects only ``test_*``. A ``_test_``-prefixed function whose
    parameters are all pytest fixtures (or that takes none) is a test that has
    been silently disabled -- pytest will not collect it. Genuine helpers are
    spared because they take non-fixture domain arguments.
    """
    offenders = []
    for path in _iter_test_modules(TEST_ROOT):
        _, disabled = _scan_module(path)
        for name, lineno, params in disabled:
            offenders.append(
                "  %s:%d: function '%s(%s)' is '_test_'-prefixed with only "
                "fixture/no parameters -- pytest will NOT collect it, so it is "
                "a disabled test. Rename it to 'test_...' to run it, or give it "
                "a non-fixture parameter if it is truly a helper."
                % (_relative(path), lineno, name, ", ".join(params))
            )

    assert not offenders, (
        "Found '_test_'-prefixed functions that are disabled (uncollected) "
        "tests:\n" + "\n".join(sorted(offenders))
    )
