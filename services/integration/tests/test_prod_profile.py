"""Task 15 — production-profile invariants.

Asserts the split-container prod profile is byte-identical to the fat container
(same image, only SERVICES/command differ), uses `mem_limit` (never `deploy:`),
covers all five pipeline stages across four routers, and keeps the whole stack's
memory budget under the 8 GB WSL2 cap.
"""
from __future__ import annotations

import pathlib

import pytest

yaml = pytest.importorskip("yaml")

_ROOT = pathlib.Path(__file__).resolve().parents[3]
BASE = _ROOT / "docker-compose.yml"
PROD = _ROOT / "docker-compose.prod.yml"

APP_SERVICES = {
    "router-triage",
    "router-unpack",
    "router-analysis",
    "router-match-aggregate",
    "gateway",
    "notifier",
}
ROUTERS = {"router-triage", "router-unpack", "router-analysis", "router-match-aggregate"}
PROD_IMAGE = "firmosaurus-app:prod"
EIGHT_GIB_MIB = 8 * 1024


def _load(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _services(doc):
    return doc.get("services", {})


def _mem_mib(value) -> float:
    s = str(value).strip().lower()
    mult = {"k": 1 / 1024, "m": 1.0, "g": 1024.0}.get(s[-1], None)
    if mult is None:  # plain bytes
        return float(s) / (1024 * 1024)
    return float(s[:-1]) * mult


@pytest.fixture(scope="module")
def prod_services():
    return _services(_load(PROD))


def test_every_app_service_uses_the_same_image(prod_services):
    for name in APP_SERVICES:
        svc = prod_services[name]
        assert svc["image"] == PROD_IMAGE, f"{name} must use the shared image"
        # Built from the single Group-4 production Dockerfile.
        assert svc["build"]["dockerfile"] == "deploy/Dockerfile"
        assert svc["build"]["context"] == "."


def test_four_routers_cover_all_five_stages(prod_services):
    router_services = {n for n in prod_services if n in ROUTERS}
    assert router_services == ROUTERS  # exactly four routers

    covered: set[str] = set()
    for name in ROUTERS:
        services_env = str(prod_services[name]["environment"]["SERVICES"])
        covered.update(part.strip() for part in services_env.split(","))
    assert covered == {"triage", "unpack", "analysis", "match", "aggregate"}


def test_gateway_and_notifier_run_the_right_process(prod_services):
    assert "services.integration.app:app" in " ".join(prod_services["gateway"]["command"])
    assert "services.notifier.app:app" in " ".join(prod_services["notifier"]["command"])


def test_mem_limit_used_never_deploy(prod_services):
    for name, svc in prod_services.items():
        assert "mem_limit" in svc, f"{name} must set mem_limit"
        # deploy.resources.limits is silently ignored under plain `docker compose up`.
        assert "deploy" not in svc, f"{name} must not use deploy: for limits"


def test_total_memory_budget_under_8gib():
    total = 0.0
    for path in (BASE, PROD):
        for name, svc in _services(_load(path)).items():
            if "mem_limit" in svc:
                total += _mem_mib(svc["mem_limit"])
    assert total < EIGHT_GIB_MIB, f"total mem_limit {total:.0f} MiB exceeds 8 GiB"
    # Sanity: it should actually be a meaningful fraction of the budget, not ~0.
    assert total > 4096
