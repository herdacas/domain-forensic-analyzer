"""Demo data build: scenarios render offline and never leak analyst identifiers."""

import importlib.util
import json
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = sorted((PROJECT_ROOT / "docs" / "examples").glob("scenario_*.json"))


@pytest.fixture(scope="module")
def build_demo():
    spec = importlib.util.spec_from_file_location(
        "build_demo", PROJECT_ROOT / "scripts" / "build_demo.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def payload(build_demo, tmp_path_factory):
    out = tmp_path_factory.mktemp("demo") / "scenarios.js"
    build_demo.build(out)
    text = out.read_text(encoding="utf-8")
    prefix = "window.DFA_DEMO = "
    body = text[text.index(prefix) + len(prefix):].rstrip().rstrip(";")
    return text, json.loads(body)


def test_builds_every_example_scenario(payload):
    _, data = payload
    assert [s["id"] for s in data["scenarios"]] == ["A", "B", "C", "D"]
    assert len(EXAMPLES) == len(data["scenarios"])


def test_terminal_replay_contains_full_report(payload):
    _, data = payload
    for scenario in data["scenarios"]:
        terminal = scenario["terminal"]
        assert "DOMAIN FORENSIC ANALYZER - SESSION:" in terminal["header"]
        assert "FORENSIC ANALYSIS COMPLETE" in terminal["report"]
        assert len(terminal["progress"]["lines"]) == 11
        assert terminal["progress"]["done"].lstrip().startswith("[done] Analysis complete:")
        assert scenario["session_id"] in terminal["footer"]


def test_analyst_identifiers_are_masked(payload):
    text, _ = payload
    for path in EXAMPLES:
        analyst = json.loads(path.read_text(encoding="utf-8"))["analyst"]
        for secret in (analyst["external_ip"], analyst["system"]["hostname"],
                       analyst["system"]["username"]):
            assert secret not in text, f"{secret!r} from {path.name} leaked into demo data"


def test_opsec_uses_current_vpn_logic(payload):
    _, data = payload
    risk = {s["id"]: s["analyst"]["opsec"]["attribution_risk"] for s in data["scenarios"]}
    # Only the Linux VPN scan has a tunnel interface signal; NAT alone stays MEDIUM.
    assert risk == {"A": "MEDIUM", "B": "LOW", "C": "MEDIUM", "D": "MEDIUM"}
