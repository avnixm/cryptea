"""Utilities for working with bundled resources."""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import Any, Iterable, List, Mapping, TYPE_CHECKING, cast

try:  # pragma: no cover - optional dependency
    from gi.repository import Gtk  # type: ignore[import]
except (ImportError, ValueError):  # pragma: no cover - headless tests
    Gtk = None  # type: ignore[assignment]

if TYPE_CHECKING:  # pragma: no cover - type checking only
    from gi.repository import Gtk as GtkType  # type: ignore[import]
else:
    GtkType = Any  # type: ignore[misc]

from .data_paths import help_dir, templates_dir, cheatsheets_dir
from .logger import configure_logging

_LOG = configure_logging()


class Resources:
    """Access to packaged UI definitions, help markdown, and templates."""

    def __init__(self) -> None:
        self._ui_pkg = 'ctf_helper.ui'
        self._help_pkg = 'ctf_helper.help'
        self._template_pkg = 'ctf_helper.templates'
        self._cheatsheet_pkg = 'ctf_helper.cheatsheets'

    def builder(self, name: str) -> GtkType.Builder:
        gtk = _require_gtk()
        builder = gtk.Builder()
        builder.add_from_string(self.ui_data(name))
        return builder

    def ui_data(self, name: str) -> str:
        return (resources.files(self._ui_pkg) / name).read_text(encoding='utf-8')

    def css_data(self) -> str:
        return self.ui_data('style.css')

    def css_provider(self) -> GtkType.CssProvider:
        gtk = _require_gtk()
        provider = gtk.CssProvider()
        provider.load_from_data(self.css_data().encode('utf-8'))
        return provider

    def help_topics(self) -> Iterable[str]:
        for entry in resources.files(self._help_pkg).iterdir():
            name = entry.name
            if name.endswith('.md'):
                yield name

    def load_help(self, name: str) -> str:
        return (resources.files(self._help_pkg) / name).read_text(encoding='utf-8')

    def ensure_help_extracted(self) -> List[Path]:
        extracted: List[Path] = []
        destination = help_dir()
        for topic in self.help_topics():
            target = destination / topic
            if target.exists():
                continue
            target.write_text(self.load_help(topic), encoding='utf-8')
            extracted.append(target)
        if extracted:
            _LOG.info("Extracted %s help topics to %s", len(extracted), destination)
        return extracted

    def template_index(self) -> Mapping[str, Mapping[str, str]]:
        content = (resources.files(self._template_pkg) / 'builtins.json').read_text(encoding='utf-8')
        data: Mapping[str, Mapping[str, str]] = json.loads(content)
        return data

    def ensure_templates_extracted(self) -> List[Path]:
        extracted: List[Path] = []
        destination = templates_dir()
        templates = self.template_index()
        for slug, meta in templates.items():
            target = destination / f"{slug}.json"
            if target.exists():
                continue
            target.write_text(json.dumps(meta, indent=2), encoding='utf-8')
            extracted.append(target)
        if extracted:
            _LOG.info("Extracted %s templates to %s", len(extracted), destination)
        return extracted


def _require_gtk() -> GtkType:
    if Gtk is None:
        raise RuntimeError("GTK is not available in this environment.")
    return cast(GtkType, Gtk)
