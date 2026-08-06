"""
validator.py — Aegis AI Patch Guardrail

Layer 2 of the safety architecture. Before any AI-generated patch is stored
or sent to the frontend, it must pass through this module.

Why this matters:
- Small local LLMs like phi3:mini frequently hallucinate non-existent functions
  (e.g., Django's mark_safe() inside a Flask codebase) or forget to import
  libraries they reference.
- A patch that introduces a syntax error or NameError is MORE dangerous than
  the original vulnerability — it breaks the application entirely.

This module uses Python's built-in `ast` module (zero external dependencies)
to enforce three rules before a patch is accepted:
  1. The patch must be valid Python (SyntaxError check)
  2. The patch must not introduce new undefined names (NameError prevention)
  3. Any new names used must either be imported in the patch or exist in
     the original file's imports.
"""

import ast
from typing import Optional


# ==========================================
# PUBLIC API
# ==========================================

def validate_patch(original_code: str, secure_code: str, filepath: str = "unknown") -> dict:
    """
    Validates an AI-generated patch before it is accepted by the system.

    Args:
        original_code: The original vulnerable code snippet.
        secure_code:   The AI-generated replacement patch.
        filepath:      Source file path (used for log context only).

    Returns:
        {
            "valid":            bool   — True if the patch is safe to apply,
            "reason":           str    — Human-readable explanation,
            "rewrite_required": bool   — True if the AI should retry,
            "issues":           list   — Specific problems found,
        }
    """
    issues = []

    # ── Rule 1: Syntax Check ──────────────────────────────────────────────────
    try:
        patch_tree = ast.parse(secure_code)
    except SyntaxError as e:
        return {
            "valid": False,
            "reason": f"Patch has a SyntaxError on line {e.lineno}: {e.msg}",
            "rewrite_required": True,
            "issues": [f"SyntaxError: {e.msg} (line {e.lineno})"],
        }

    # ── Rule 2: Dangerous Pattern Detection ──────────────────────────────────
    DANGEROUS_CALLS = {
        "mark_safe":          "Django-specific; causes XSS in Flask/Jinja2 contexts.",
        "eval":               "Arbitrary code execution — never acceptable in a secure patch.",
        "exec":               "Arbitrary code execution — never acceptable in a secure patch.",
        "pickle.loads":       "Unsafe deserialization — introduces RCE risk.",
        "os.system":          "Command injection vector — use subprocess with shell=False instead.",
        "shell=True":         "Shell injection risk — always use shell=False with a list of args.",
        "__import__":         "Dynamic import can mask malicious module loading.",
    }

    patch_source = secure_code
    for pattern, reason in DANGEROUS_CALLS.items():
        if pattern in patch_source:
            issues.append(f"Dangerous pattern '{pattern}': {reason}")

    # ── Rule 3: Undefined Name Detection ─────────────────────────────────────
    # Parse names that the patch *uses* vs names it *defines or imports*
    patch_names_used = _get_names_used(patch_tree)
    patch_names_defined = _get_names_defined(patch_tree)

    # Parse the original file's top-level imports as a safe whitelist
    try:
        original_tree = ast.parse(original_code)
        original_imports = _get_imported_names(original_tree)
    except SyntaxError:
        original_imports = set()

    patch_imports = _get_imported_names(patch_tree)
    all_known_names = patch_names_defined | patch_imports | original_imports | _PYTHON_BUILTINS

    # Names used in the patch that aren't defined anywhere are likely hallucinations
    undefined = patch_names_used - all_known_names
    if undefined:
        issues.append(
            f"Potentially undefined names (possible hallucination): {', '.join(sorted(undefined))}"
        )

    # ── Final Verdict ─────────────────────────────────────────────────────────
    if issues:
        danger_issues = [i for i in issues if "Dangerous" in i]
        undefined_issues = [i for i in issues if "undefined" in i]

        # Dangerous patterns are hard-rejected (no retry)
        if danger_issues:
            return {
                "valid": False,
                "reason": f"Patch rejected — contains dangerous patterns: {'; '.join(danger_issues)}",
                "rewrite_required": False,   # Don't retry — escalate to human review
                "issues": issues,
            }

        # Undefined names are soft-rejected (AI should retry with better prompt)
        if undefined_issues:
            return {
                "valid": False,
                "reason": (
                    f"Patch likely contains hallucinated names. "
                    f"Suspected undefined: {', '.join(sorted(undefined))}. "
                    f"AI should retry with explicit import instructions."
                ),
                "rewrite_required": True,
                "issues": issues,
            }

    print(f"[VALIDATOR] ✓ Patch for {filepath} passed all safety checks.")
    return {
        "valid": True,
        "reason": "Patch passed syntax check, danger pattern scan, and name resolution.",
        "rewrite_required": False,
        "issues": [],
    }


# ==========================================
# INTERNAL HELPERS
# ==========================================

def _get_names_used(tree: ast.AST) -> set:
    """Collects all Name nodes used in an AST (calls, attribute accesses, etc.)"""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            # e.g., `os.path` → collect 'os'
            if isinstance(node.value, ast.Name):
                names.add(node.value.id)
    return names


def _get_names_defined(tree: ast.AST) -> set:
    """Collects names that the patch itself defines: functions, classes, variables."""
    defined = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            defined.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    defined.add(target.id)
        elif isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name):
                defined.add(node.target.id)
        elif isinstance(node, (ast.For, ast.comprehension)):
            target = getattr(node, 'target', None)
            if target and isinstance(target, ast.Name):
                defined.add(target.id)
        elif isinstance(node, ast.arg):
            defined.add(node.arg)
    return defined


def _get_imported_names(tree: ast.AST) -> set:
    """Collects all names brought into scope by import statements."""
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                # `import os` → 'os'; `import os as operating_system` → 'operating_system'
                imported.add(alias.asname if alias.asname else alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported.add(alias.asname if alias.asname else alias.name)
    return imported


# Common Python builtins that are always in scope — don't flag these as undefined
_PYTHON_BUILTINS = {
    "abs", "all", "any", "ascii", "bin", "bool", "breakpoint", "bytearray",
    "bytes", "callable", "chr", "classmethod", "compile", "complex",
    "copyright", "credits", "delattr", "dict", "dir", "divmod", "enumerate",
    "exit", "filter", "float", "format", "frozenset", "getattr", "globals",
    "hasattr", "hash", "help", "hex", "id", "input", "int", "isinstance",
    "issubclass", "iter", "len", "license", "list", "locals", "map", "max",
    "memoryview", "min", "next", "object", "oct", "open", "ord", "pow",
    "print", "property", "quit", "range", "repr", "reversed", "round",
    "set", "setattr", "slice", "sorted", "staticmethod", "str", "sum",
    "super", "tuple", "type", "vars", "zip",
    # Common exception names
    "Exception", "ValueError", "TypeError", "KeyError", "IndexError",
    "AttributeError", "RuntimeError", "StopIteration", "OSError",
    "IOError", "FileNotFoundError", "PermissionError", "NotImplementedError",
    "True", "False", "None", "self", "cls",
    # Flask / common web framework globals often present in app context
    "request", "app", "g", "current_app", "session", "abort", "redirect",
    "url_for", "render_template", "render_template_string", "jsonify",
    "make_response", "Response",
}
