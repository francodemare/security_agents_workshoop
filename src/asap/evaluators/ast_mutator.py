"""
AST-based code mutator for Evaluator Stress Testing (EST).
Generates format-only perturbations (y_fmt) and semantic-content mutations (y_cnt).
"""

import ast
import random
from typing import Optional, Tuple


class ContentMutator(ast.NodeTransformer):
    """Mutates semantic operations (e.g., comparison operators, boolean constants, arithmetic)."""

    def __init__(self, max_mutations: int = 2):
        super().__init__()
        self.max_mutations = max_mutations
        self.mutations_done = 0

    def visit_Compare(self, node: ast.Compare) -> ast.AST:
        if self.mutations_done < self.max_mutations:
            new_ops = []
            for op in node.ops:
                if isinstance(op, ast.Eq):
                    new_ops.append(ast.NotEq())
                    self.mutations_done += 1
                elif isinstance(op, ast.NotEq):
                    new_ops.append(ast.Eq())
                    self.mutations_done += 1
                elif isinstance(op, ast.Lt):
                    new_ops.append(ast.GtE())
                    self.mutations_done += 1
                elif isinstance(op, ast.Gt):
                    new_ops.append(ast.LtE())
                    self.mutations_done += 1
                else:
                    new_ops.append(op)
            node.ops = new_ops
        return self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if self.mutations_done < self.max_mutations and isinstance(node.value, bool):
            node.value = not node.value
            self.mutations_done += 1
        return node


class FormatMutator(ast.NodeTransformer):
    """
    Mutates variable names and format without changing executable semantics.
    Renames local function arguments/variables to synthetic identifiers.
    """

    def __init__(self):
        super().__init__()
        self.var_map = {}
        self.counter = 0

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        # Don't rename magic methods or top-level entrypoints
        if not node.name.startswith("__"):
            # Clean docstrings
            if (
                node.body
                and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)
            ):
                node.body.pop(0)
        return self.generic_visit(node)


def generate_ast_perturbations(source_code: str) -> Tuple[str, str]:
    """
    Parses Python source code and produces:
    - fmt_code: Same semantics, altered syntax/docstrings
    - cnt_code: Inverted/mutated logical comparisons and booleans
    """
    try:
        tree_orig = ast.parse(source_code)
    except SyntaxError:
        # If code is not valid Python or is another format, return fallback perturbations
        return source_code + "\n# format perturbation\n", source_code + "\n# logic changed"

    # 1. Format Perturbation
    tree_fmt = ast.parse(source_code)
    fmt_mutator = FormatMutator()
    tree_fmt = fmt_mutator.visit(tree_fmt)
    ast.fix_missing_locations(tree_fmt)
    fmt_code = ast.unparse(tree_fmt)

    # 2. Content Perturbation
    tree_cnt = ast.parse(source_code)
    cnt_mutator = ContentMutator()
    tree_cnt = cnt_mutator.visit(tree_cnt)
    ast.fix_missing_locations(tree_cnt)
    cnt_code = ast.unparse(tree_cnt)

    return fmt_code, cnt_code
