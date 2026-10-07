"""Release wording must match technical reality."""

from pathlib import Path

ROOT = Path(__file__).parent.parent


def _read(name):
    # Explicit UTF-8: README/CHANGELOG contain non-ASCII and CI also runs on Windows (cp1252).
    return (ROOT / name).read_text(encoding="utf-8")


def test_readme_no_absolute_claims():
    readme = _read("README.md")

    absolute_phrases = [
        "complete intelligence picture",
        "definitive verdict",
    ]

    for phrase in absolute_phrases:
        if phrase in readme:
            raise AssertionError(f"README contains overpromising phrase: '{phrase}'")


def test_changelog_mentions_limitations():
    changelog = _read("CHANGELOG.md")
    assert "limitations" in changelog.lower()
    assert "1.0.0" in changelog


def test_readme_links_known_limitations():
    readme = _read("README.md")
    assert "## Known Limitations" in readme
    assert "## When to Use This Tool" in readme
    assert "docs/KNOWN_LIMITATIONS.md" in readme
    assert (ROOT / "docs/KNOWN_LIMITATIONS.md").exists()
