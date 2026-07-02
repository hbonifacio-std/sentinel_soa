import ast
from pathlib import Path


WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
APPLICATION_DIR = WORKSPACE_ROOT / "core_orchestrator" / "application"
DOMAIN_DIR = WORKSPACE_ROOT / "core_orchestrator" / "domain"


def _python_files(base_dir: Path) -> list[Path]:
    return [
        path
        for path in base_dir.rglob("*.py")
        if "__pycache__" not in path.parts
    ]


def _imports_in_file(file_path: Path) -> list[str]:
    module = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))
    imports: list[str] = []

    for node in ast.walk(module):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        if isinstance(node, ast.ImportFrom) and node.module:
            imports.append(node.module)

    return imports


def _collect_violations(base_dir: Path, blocked_prefixes: tuple[str, ...]) -> list[str]:
    violations: list[str] = []
    for file_path in _python_files(base_dir):
        for imported_module in _imports_in_file(file_path):
            if imported_module.startswith(blocked_prefixes):
                rel_path = file_path.relative_to(WORKSPACE_ROOT)
                violations.append(f"{rel_path}: {imported_module}")
    return violations


def test_application_must_not_import_infrastructure() -> None:
    violations = _collect_violations(
        APPLICATION_DIR,
        blocked_prefixes=("core_orchestrator.infrastructure",),
    )
    assert not violations, "Imports prohibidos en application:\n" + "\n".join(violations)


def test_domain_must_not_import_application_or_infrastructure() -> None:
    violations = _collect_violations(
        DOMAIN_DIR,
        blocked_prefixes=("core_orchestrator.application", "core_orchestrator.infrastructure"),
    )
    assert not violations, "Imports prohibidos en domain:\n" + "\n".join(violations)


def test_use_cases_must_not_define_global_singleton_helpers() -> None:
    service_files = [
        file_path
        for file_path in _python_files(APPLICATION_DIR)
        if "services" in file_path.parts
    ]

    violations: list[str] = []
    forbidden_function_names = {"init_rules_engine", "get_rules_engine"}

    for file_path in service_files:
        tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))

        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id.endswith("_instance"):
                        rel_path = file_path.relative_to(WORKSPACE_ROOT)
                        violations.append(f"{rel_path}: singleton global `{target.id}`")

            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in forbidden_function_names:
                rel_path = file_path.relative_to(WORKSPACE_ROOT)
                violations.append(f"{rel_path}: helper singleton `{node.name}`")

    assert not violations, "Singleons globales detectados en casos de uso:\n" + "\n".join(violations)

