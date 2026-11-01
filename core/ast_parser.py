"""
CodeSanctum AI - Abstract Syntax Tree (AST) Security Analyzer
Deep syntactic inspection engine analyzing Python code structures for zero-day vulnerabilities.
"""

import ast
from typing import Dict, Any, List, Optional

class SecurityASTVisitor(ast.NodeVisitor):
    """AST Visitor that traverses syntax nodes and flags insecure coding patterns."""

    def __init__(self):
        self.nodes_visited = 0
        self.functions_found: List[str] = []
        self.imports_found: List[str] = []
        self.calls_found: List[Dict[str, Any]] = []
        self.hotspots: List[Dict[str, Any]] = []

    def visit_Import(self, node: ast.Import):
        self.nodes_visited += 1
        for alias in node.names:
            self.imports_found.append(alias.name)
            if alias.name in ["pickle", "shelve", "telnetlib"]:
                self.hotspots.append({
                    "line": node.lineno,
                    "node_type": "Import",
                    "target": alias.name,
                    "severity": "CRITICAL" if alias.name == "pickle" else "HIGH",
                    "issue": f"Import of high-risk serialization/networking module: '{alias.name}'"
                })
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        self.nodes_visited += 1
        if node.module:
            self.imports_found.append(node.module)
            if node.module in ["pickle", "shelve"]:
                self.hotspots.append({
                    "line": node.lineno,
                    "node_type": "ImportFrom",
                    "target": node.module,
                    "severity": "CRITICAL",
                    "issue": f"Direct import from dangerous module: '{node.module}'"
                })
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.nodes_visited += 1
        self.functions_found.append(node.name)
        # Check if function has authorization decorators or checks
        decorator_names = [d.id for d in node.decorator_list if isinstance(d, ast.Name)]
        if ("record" in node.name.lower() or "patient" in node.name.lower() or "billing" in node.name.lower()) and not decorator_names:
            self.hotspots.append({
                "line": node.lineno,
                "node_type": "FunctionDef",
                "target": node.name,
                "severity": "HIGH",
                "issue": f"Data-sensitive function '{node.name}' lacks RBAC authorization decorators"
            })
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        self.nodes_visited += 1
        call_name = ""
        if isinstance(node.func, ast.Name):
            call_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            call_name = node.func.attr

        # Check dangerous calls: pickle.loads, eval, exec, os.system
        if call_name in ["loads"] and any("pickle" in imp for imp in self.imports_found):
            self.hotspots.append({
                "line": node.lineno,
                "node_type": "Call",
                "target": f"pickle.{call_name}",
                "severity": "CRITICAL",
                "issue": "Insecure object deserialization via pickle.loads (arbitrary code execution)"
            })
        elif call_name in ["eval", "exec"]:
            self.hotspots.append({
                "line": node.lineno,
                "node_type": "Call",
                "target": call_name,
                "severity": "CRITICAL",
                "issue": f"Direct interpreter execution call: '{call_name}()'"
            })
        elif call_name == "execute":
            # Check if argument is a formatted string (JoinedStr)
            if node.args and isinstance(node.args[0], ast.JoinedStr):
                self.hotspots.append({
                    "line": node.lineno,
                    "node_type": "Call:execute",
                    "target": "db.execute(f-string)",
                    "severity": "CRITICAL",
                    "issue": "SQL query concatenation via f-string without parameter binding"
                })
        elif call_name == "open":
            # Check if opening dynamic file path without normalization
            self.hotspots.append({
                "line": node.lineno,
                "node_type": "Call:open",
                "target": "open()",
                "severity": "MEDIUM",
                "issue": "File system access detected: verify path traversal boundary enforcement"
            })

        self.calls_found.append({
            "line": node.lineno,
            "call": call_name
        })
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        self.nodes_visited += 1
        if isinstance(node.value, ast.JoinedStr):
            # Check if this f-string contains SQL-like keywords or is assigned to query/sql
            target_names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            contains_sql = False
            for part in node.value.values:
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    if any(kw in part.value.upper() for kw in ["SELECT", "FROM", "WHERE", "INSERT", "UPDATE", "DELETE"]):
                        contains_sql = True
                        break
            if contains_sql or any("query" in name.lower() or "sql" in name.lower() for name in target_names):
                self.hotspots.append({
                    "line": node.lineno,
                    "node_type": "JoinedStr",
                    "target": "f-string SQL query construction",
                    "severity": "CRITICAL",
                    "issue": "Dynamic SQL query concatenation via f-string without parameter binding"
                })
        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr):
        self.nodes_visited += 1
        # Also check standalone joined strings with SQL keywords
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                if any(kw in part.value.upper() for kw in ["SELECT", "INSERT", "UPDATE", "DELETE"]) and not any(h["line"] == node.lineno for h in self.hotspots):
                    self.hotspots.append({
                        "line": node.lineno,
                        "node_type": "JoinedStr",
                        "target": "f-string SQL template",
                        "severity": "CRITICAL",
                        "issue": "Unparameterized SQL string template formatting"
                    })
                    break
        self.generic_visit(node)


class ASTSecurityAnalyzer:
    """Orchestrates code AST decomposition, metric calculation, and AST tree extraction."""

    def analyze(self, code_str: str) -> Dict[str, Any]:
        """Parse source code string into AST, visit nodes, and generate security telemetry."""
        try:
            tree = ast.parse(code_str)
        except SyntaxError as e:
            return {
                "success": False,
                "error": f"Syntax error at line {e.lineno}: {e.msg}",
                "metrics": {},
                "hotspots": [],
                "tree_summary": []
            }

        visitor = SecurityASTVisitor()
        visitor.visit(tree)

        # Build hierarchical node summary for frontend visualization
        tree_summary = self._build_ast_summary(tree)

        # Estimate cyclomatic complexity
        decision_nodes = sum(1 for node in ast.walk(tree) if isinstance(node, (ast.If, ast.While, ast.For, ast.ExceptHandler)))
        complexity = decision_nodes + 1

        total_lines = len(code_str.strip().splitlines())

        return {
            "success": True,
            "metrics": {
                "total_lines": total_lines,
                "nodes_visited": visitor.nodes_visited,
                "functions_count": len(visitor.functions_found),
                "cyclomatic_complexity": complexity,
                "hotspots_count": len(visitor.hotspots),
                "imports": visitor.imports_found
            },
            "hotspots": visitor.hotspots,
            "functions": visitor.functions_found,
            "tree_summary": tree_summary
        }

    def _build_ast_summary(self, node: ast.AST, depth: int = 0) -> List[Dict[str, Any]]:
        """Extract a simplified JSON representation of the AST hierarchy (first 3 levels)."""
        summary = []
        if depth > 2:
            return summary

        for child in ast.iter_child_nodes(node):
            node_type = type(child).__name__
            node_info: Dict[str, Any] = {
                "type": node_type,
                "line": getattr(child, "lineno", None),
                "depth": depth
            }
            if isinstance(child, ast.FunctionDef):
                node_info["name"] = child.name
                node_info["args"] = [a.arg for a in child.args.args]
            elif isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    node_info["call"] = child.func.id
                elif isinstance(child.func, ast.Attribute):
                    node_info["call"] = child.func.attr
            elif isinstance(child, ast.Import):
                node_info["modules"] = [n.name for n in child.names]
            elif isinstance(child, ast.JoinedStr):
                node_info["name"] = "f-string template"

            children_summary = self._build_ast_summary(child, depth + 1)
            if children_summary:
                node_info["children"] = children_summary

            summary.append(node_info)
        return summary

ast_analyzer = ASTSecurityAnalyzer()
