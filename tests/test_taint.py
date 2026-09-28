"""Source-to-sink evidence extraction.

These tests pin the behaviour the verifier agent depends on: a chain is only
useful if it names a real source, a real sink and the statements between them,
and a correctly bounded copy is not presented as an unbounded one.
"""
from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any, Dict, List

import pytest

from analyzers.structural_analyzer import StructuralAnalyzer
from analyzers.taint import taint_chains_for


def analyze(tmp_path: Path, code: str, name: str = "sample") -> Dict[str, Any]:
    path = tmp_path / name
    path.write_text(textwrap.dedent(code))
    return StructuralAnalyzer().analyze_file(path)


def proven(structure: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Chains with an actual source-to-sink path."""
    return [c for c in taint_chains_for(structure) if c["source_expression"]]


# -- structural index ----------------------------------------------------

def test_index_exposes_assignments_and_references(tmp_path):
    structure = analyze(
        tmp_path,
        """
        import os
        def run(argv):
            name = argv[1]
            os.system(name)
        """,
        "a.py",
    )
    assert structure["language"] == "python"
    assert [a["targets"] for a in structure["assignments"]] == [["name"]]
    assert any(r["text"] == "argv" for r in structure["references"])
    # Bare attribute/subscript reads are index entries, not just calls.
    assert any("argv" in r["text"] for r in structure["references"])


def test_index_captures_c_declarations_and_parameters(tmp_path):
    structure = analyze(
        tmp_path,
        """
        #include <string.h>
        void copy_in(char *in, int n) {
          char buf[10];
          char *alias = in;
          strcpy(buf, alias);
        }
        """,
        "a.c",
    )
    assert structure["language"] == "c"
    function = structure["functions"][0]
    assert set(function["parameters"]) == {"in", "n"}
    targets = [a["targets"] for a in structure["assignments"]]
    assert ["alias"] in targets
    assert any(name == "buf" for target in targets for name in target)


def test_c_functions_are_named(tmp_path):
    """A C function's name hangs off the declarator, not a `name` field.

    Without the declarator fallback every C function came back as
    `<anonymous>`, so reports could not say which function a finding was in.
    """
    structure = analyze(
        tmp_path,
        """
        void copy_in(char *in) { char buf[10]; strcpy(buf, in); }
        int main(int argc, char **argv) { return argc; }
        """,
        "a.c",
    )
    assert [f["name"] for f in structure["functions"]] == ["copy_in", "main"]


def test_cpp_function_names_and_reference_parameters(tmp_path):
    """Names for members, destructors, templates and qualified methods.

    Also pins the reference-parameter case: `const std::string& in` declares its
    name inside a `reference_declarator` that follows a `type_qualifier`, and
    losing it would hide the parameter as a taint source.
    """
    structure = analyze(
        tmp_path,
        """
        #include <string>
        struct S {
            void member_copy(const std::string& in) { (void)in; }
            ~S() {}
        };
        template <typename T>
        void tpl_copy(const T& in) { (void)in; }
        void Foo::qualified(const char* p) { (void)p; }
        """,
        "a.cpp",
    )
    functions = {f["name"]: f["parameters"] for f in structure["functions"]}
    assert functions["member_copy"] == ["in"]
    assert functions["tpl_copy"] == ["in"]
    assert functions["~S"] == []
    assert functions["Foo::qualified"] == ["p"]


def test_cpp_reference_parameter_is_a_taint_source(tmp_path):
    """The consequence of the previous test: the chain must still be found."""
    structure = analyze(
        tmp_path,
        """
        void copy_in(const std::string& in) {
          char buf[16];
          strcpy(buf, in.c_str());
        }
        """,
        "a.cpp",
    )
    chains = proven(structure)
    assert chains, "a reference parameter should be recognised as a source"
    assert any("strcpy" in c["sink_expression"] for c in chains)


def test_cpp_is_analysed_with_the_c_patterns(tmp_path):
    """A C++ file must not be skipped for want of a C++ pattern table.

    `cpp` has no entry of its own, so it reuses `c`. Had the lookup stayed
    strict, this file would have produced no chains and the chain gate would
    have read the silence as evidence that it was safe.
    """
    structure = analyze(
        tmp_path,
        """
        void copy_in(char *in) {
          char buf[16];
          strcpy(buf, in);
        }
        """,
        "a.cpp",
    )
    chains = proven(structure)
    assert chains
    assert chains[0]["cwe"] == "CWE-120"


def test_namespaced_cpp_sink_is_matched(tmp_path):
    """`std::strcpy` is `strcpy`; `::` is a scope separator like `.`.

    Both the head extractor and the pattern matcher have to know about `::`,
    since the extractor truncating at the first `::` is what made the matcher
    see a callee called `std`.
    """
    structure = analyze(
        tmp_path,
        """
        #include <cstring>
        void vulnerable_copy(const char *input) {
          char buffer[16];
          std::strcpy(buffer, input);
        }
        """,
        "a.cpp",
    )
    chains = proven(structure)
    assert chains, "a namespaced callee should still be recognised as a sink"
    assert "std::strcpy" in chains[0]["sink_expression"]


def test_sink_inside_a_namespace_is_still_matched(tmp_path):
    """Namespacing the file must not hide the sink.

    A namespace only changes the enclosing scope, so a `strcpy` inside one is
    the same sink as one at file scope.
    """
    structure = analyze(
        tmp_path,
        """
        namespace util {
          void copy_in(char *in) {
            char buf[16];
            strcpy(buf, in);
          }
        }
        """,
        "a.cpp",
    )
    assert proven(structure)


def test_index_records_file_scope_globals(tmp_path):
    structure = analyze(
        tmp_path,
        """
        #include <stdlib.h>
        extern int *example_badData;
        int *example_badData;
        void use_it(void) { sink(example_badData); }
        """,
        "a.c",
    )
    names = {name for entry in structure["globals"] for name in entry["names"]}
    assert "example_badData" in names


# -- source to sink ------------------------------------------------------

def test_three_step_chain_names_every_hop(tmp_path):
    structure = analyze(
        tmp_path,
        """
        import os, sys
        def run():
            name = sys.argv[1]
            command = "ls " + name
            os.system(command)
        """,
        "a.py",
    )
    chains = proven(structure)
    assert len(chains) == 1
    chain = chains[0]
    assert chain["cwe"] == "CWE-78"
    # The snippet starts with a blank line, so the body is one line lower.
    assert chain["source_line"] == 4
    assert chain["sink_line"] == 6
    assert chain["propagated"] is True
    assert "sys.argv[1]" in chain["chain"]
    # The intermediate binding must be visible, not just the endpoints.
    assert 'command <- "ls " + name' in chain["chain"]


def test_source_nested_in_sink_argument_is_a_complete_path(tmp_path):
    structure = analyze(
        tmp_path,
        """
        import os
        from flask import request
        def view():
            return os.system("ls " + request.args.get("q"))
        """,
        "a.py",
    )
    chains = proven(structure)
    assert len(chains) == 1
    assert chains[0]["taint_origin"] == "external-source"
    assert "request.args.get" in chains[0]["chain"]


def test_prefers_concrete_source_over_parameter_fallback(tmp_path):
    structure = analyze(
        tmp_path,
        """
        import os
        def view(request):
            os.system(request.args.get("q"))
        """,
        "a.py",
    )
    chains = proven(structure)
    assert len(chains) == 1
    assert chains[0]["taint_origin"] == "external-source"
    assert "parameter" not in chains[0]["chain"]


def test_c_parameter_is_labelled_as_parameter_origin(tmp_path):
    structure = analyze(
        tmp_path,
        """
        #include <string.h>
        void copy_in(char *in) {
          char buf[8];
          strcpy(buf, in);
        }
        """,
        "a.c",
    )
    chains = proven(structure)
    assert len(chains) == 1
    assert chains[0]["taint_origin"] == "parameter"
    assert chains[0]["cwe"] == "CWE-120"


def test_assignment_propagates_taint_through_pointer_alias(tmp_path):
    structure = analyze(
        tmp_path,
        """
        #include <string.h>
        void copy_in(const char *in) {
          char *alias = in;
          char buf[8];
          strcpy(buf, alias);
        }
        """,
        "a.c",
    )
    chains = proven(structure)
    assert len(chains) == 1
    assert "alias <- in" in chains[0]["chain"]


def test_untainted_sink_is_reported_without_a_path(tmp_path):
    structure = analyze(
        tmp_path,
        """
        import subprocess
        def safe(command):
            subprocess.run(["ls", "-l"], shell=False)
        """,
        "a.py",
    )
    chains = taint_chains_for(structure)
    assert len(chains) == 1
    assert chains[0]["source_expression"] == ""
    assert "no source-to-sink path" in chains[0]["chain"]


def test_sink_is_not_double_counted(tmp_path):
    """The callee appears as both a call and as attribute/identifier nodes."""
    structure = analyze(
        tmp_path,
        """
        import subprocess
        def run(command):
            subprocess.run(command, shell=True)
        """,
        "a.py",
    )
    assert len(taint_chains_for(structure)) == 1


def test_call_that_is_both_source_and_sink_yields_no_chain(tmp_path):
    """``fgets`` is a C source *and* a bounded-copy sink.

    Matching the source read against the whole call text made a single call look
    like a source-to-sink path, which would report a correctly bounded read as
    a finding. The inline match is restricted to the argument list, so the read
    only counts when a *different* call is the sink.
    """
    structure = analyze(
        tmp_path,
        """
        #include <stdio.h>
        void read_line(char *out) {
          char buf[32];
          fgets(buf, 32, stdin);
          strcpy(out, buf);
        }
        """,
        "a.c",
    )
    for chain in proven(structure):
        assert "fgets" not in chain["source_expression"]


def test_source_outside_the_argument_list_is_not_an_inline_path(tmp_path):
    """``open(join(base, safe)).read()`` does not make read() flow into open()."""
    structure = analyze(
        tmp_path,
        """
        import os
        def read_upload(name):
            safe = os.path.basename(name)
            return open(os.path.join("/srv/uploads", safe)).read()
        """,
        "a.py",
    )
    assert proven(structure) == []


# -- sanitizers and safe calling conventions -----------------------------

def test_sanitizer_neutralises_taint(tmp_path):
    structure = analyze(
        tmp_path,
        """
        import os
        def list_dir(path):
            os.system("ls " + os.path.basename(path))
        """,
        "a.py",
    )
    assert proven(structure) == []


def test_argument_list_is_not_a_shell_string(tmp_path):
    structure = analyze(
        tmp_path,
        """
        import subprocess
        def backup(name):
            subprocess.Popen(["pg_dump", name], shell=False)
        """,
        "a.py",
    )
    chain = proven(structure)[0]
    assert chain["mitigated"] is True
    assert chain["mitigation_rule"] == "argument-list"


def test_shell_false_is_a_mitigation(tmp_path):
    structure = analyze(
        tmp_path,
        """
        import subprocess
        def run(command):
            subprocess.call(command, shell=False)
        """,
        "a.py",
    )
    assert proven(structure)[0]["mitigation_rule"] == "no-shell"


def test_parameterised_query_is_a_mitigation(tmp_path):
    structure = analyze(
        tmp_path,
        """
        import sqlite3
        def find_user(connection, name):
            cursor = connection.cursor()
            cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
            return cursor.fetchall()
        """,
        "a.py",
    )
    assert proven(structure)[0]["mitigation_rule"] == "parameterised-query"


def test_string_built_query_is_not_mitigated(tmp_path):
    structure = analyze(
        tmp_path,
        """
        import sqlite3
        def find_user(connection, name):
            cursor = connection.cursor()
            cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)
            return cursor.fetchall()
        """,
        "a.py",
    )
    assert proven(structure)[0]["mitigated"] is False


def test_literal_eval_is_a_sanitizer(tmp_path):
    structure = analyze(
        tmp_path,
        """
        import ast
        def compute(expression):
            return ast.literal_eval(expression)
        """,
        "a.py",
    )
    assert proven(structure) == []


def test_eval_is_still_a_sink(tmp_path):
    structure = analyze(
        tmp_path,
        """
        def compute(expression):
            return eval(expression)
        """,
        "a.py",
    )
    assert proven(structure)[0]["cwe"] == "CWE-94"


# -- mitigation ----------------------------------------------------------

def test_constant_length_bound_is_flagged(tmp_path):
    structure = analyze(
        tmp_path,
        """
        #include <string.h>
        void copy_in(const char *in) {
          char buf[100];
          strncpy(buf, in, 100 - 1);
        }
        """,
        "a.c",
    )
    chain = proven(structure)[0]
    assert chain["mitigated"] is True
    assert "explicit length" in chain["mitigation"]


def test_length_derived_from_data_is_flagged(tmp_path):
    structure = analyze(
        tmp_path,
        """
        #include <string.h>
        void copy_in(const char *in) {
          char buf[100];
          memcpy(buf, in, (strlen(in) + 1) * sizeof(char));
        }
        """,
        "a.c",
    )
    assert proven(structure)[0]["mitigated"] is True


def test_destination_allocated_from_tainted_length_is_flagged(tmp_path):
    structure = analyze(
        tmp_path,
        """
        #include <stdlib.h>
        #include <string.h>
        void copy_in(const char *in) {
          char *dest = (char *)calloc(strlen(in) + 1, 1);
          strcpy(dest, in);
          free(dest);
        }
        """,
        "a.c",
    )
    chain = proven(structure)[0]
    assert chain["mitigated"] is True
    assert "allocated as" in chain["mitigation"]


def test_unbounded_copy_into_undersized_buffer_is_not_mitigated(tmp_path):
    """The constant size is real but the destination is the bug, so it stays."""
    structure = analyze(
        tmp_path,
        """
        #include <string.h>
        void copy_in(const char *in) {
          char buf[4];
          strcpy(buf, in);
        }
        """,
        "a.c",
    )
    chain = proven(structure)[0]
    assert chain["mitigated"] is False
    assert "[origin: parameter]" in chain["chain"]


# -- python families -----------------------------------------------------

@pytest.mark.parametrize(
    "code, cwe",
    [
        (
            """
            import yaml
            def load(payload):
                return yaml.load(payload)
            """,
            "CWE-502",
        ),
        (
            """
            from flask import render_template_string
            def view(request):
                return render_template_string(request.args.get("t"))
            """,
            "CWE-1336",
        ),
        (
            """
            import pickle
            def load(blob):
                return pickle.loads(blob)
            """,
            "CWE-502",
        ),
    ],
)
def test_python_families_map_to_expected_cwe(tmp_path, code, cwe):
    structure = analyze(tmp_path, code, "a.py")
    chains = proven(structure)
    assert chains and chains[0]["cwe"] == cwe


def test_unknown_language_yields_no_chains():
    assert taint_chains_for({"language": "java", "functions": []}) == []


def test_chain_is_json_serialisable(tmp_path):
    import json

    structure = analyze(
        tmp_path,
        """
        import os, sys
        def run():
            command = sys.argv[1]
            os.system(command)
        """,
        "a.py",
    )
    payload = json.loads(json.dumps(taint_chains_for(structure)))
    assert payload and payload[0]["chain"]
