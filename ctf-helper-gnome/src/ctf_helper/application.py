"""Primary application entry point for GNOME CTF Helper."""

from __future__ import annotations

import inspect
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import gi  # type: ignore[import]

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gio, GLib, Gtk, Gdk, Pango  # type: ignore[import]

from . import config
from .data_paths import log_dir
from .dev_seed import seed_if_requested
from .logger import configure_logging
from .db import Database
from .manager.challenge_manager import ChallengeManager, STATUSES
from .manager.models import Challenge
from .manager.export_import import ExportImportManager
from .modules import ModuleRegistry
from .notes import MarkdownRenderer, NoteManager
from .offline_guard import OfflineGuard, OfflineViolation
from .resources import Resources

_LOG = configure_logging()


CATEGORY_COLORS: Dict[str, str] = {
    "crypto": "purple",
    "cryptography": "purple",
    "forensics": "blue",
    "reverse": "orange",
    "reverse engineering": "orange",
    "web": "teal",
    "web exploitation": "teal",
    "misc": "gray",
    "osint": "pink",
}

STATUS_STYLE_CLASSES: Dict[str, str] = {
    "Not Started": "status-not-started",
    "In Progress": "status-in-progress",
    "Completed": "status-completed",
}


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def _pill_label(text: str, color: str) -> Gtk.Label:
    label = Gtk.Label(label=text.title(), xalign=0)
    label.add_css_class("pill")
    label.add_css_class(f"pill-{color}")
    return label


def _status_chip(status: str) -> Gtk.Label:
    label = Gtk.Label(label=status, xalign=0)
    label.add_css_class("pill")
    label.add_css_class("status-pill")
    label.add_css_class(STATUS_STYLE_CLASSES.get(status, "status-not-started"))
    return label


def _clear_listbox(listbox: Gtk.ListBox) -> None:
    child = listbox.get_first_child()
    while child is not None:
        next_child = child.get_next_sibling()
        listbox.remove(child)
        child = next_child


def _clear_box(box: Gtk.Box) -> None:
    child = box.get_first_child()
    while child is not None:
        next_child = child.get_next_sibling()
        box.remove(child)
        child = next_child


def _clear_flowbox(flowbox: Gtk.FlowBox) -> None:
    child = flowbox.get_first_child()
    while child is not None:
        next_child = child.get_next_sibling()
        flowbox.remove(child)
        child = next_child


class ChallengeCard(Gtk.Button):
    """Compact card used on the challenges grid."""

    __gtype_name__ = "ChallengeCard"

    def __init__(self, challenge: Challenge, callback) -> None:
        super().__init__(valign=Gtk.Align.START, halign=Gtk.Align.FILL)
        self.challenge_id = challenge.id
        self.set_can_focus(True)
        self.set_focus_on_click(True)
        self.set_has_frame(False)
        self.add_css_class("challenge-card")
        self.set_hexpand(True)
        self.connect("clicked", lambda _btn: callback(self.challenge_id))

        wrapper = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=8,
            margin_top=4,
            margin_bottom=4,
            margin_start=4,
            margin_end=4,
        )

        header = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        title = Gtk.Label(xalign=0)
        title.set_markup(f"<b>{GLib.markup_escape_text(challenge.title)}</b>")
        title.add_css_class("title-4")
        header.append(title)

        chips = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        color = CATEGORY_COLORS.get(challenge.category.lower(), "gray")
        chips.append(_pill_label(challenge.category, color))
        chips.append(_status_chip(challenge.status))
        project_label = Gtk.Label(label=challenge.project, xalign=0)
        project_label.add_css_class("dim-label")
        chips.append(project_label)
        header.append(chips)
        wrapper.append(header)

        description = Gtk.Label(xalign=0, wrap=True)
        description.set_lines(3)
        description.set_ellipsize(Pango.EllipsizeMode.END)
        description.add_css_class("body-text")
        description.set_text(_truncate(challenge.description or "No description provided yet.", 200))
        wrapper.append(description)

        footer = Gtk.Label(xalign=0)
        footer.add_css_class("dim-label")
        footer.set_text(f"Updated {challenge.updated_at:%Y-%m-%d}")
        wrapper.append(footer)

        self.set_child(wrapper)


class MainWindow:
    """Controller for the main application window."""

    def __init__(self, app: "CTFHelperApplication") -> None:
        self.app = app
        self.window = Adw.ApplicationWindow(application=app)
        self.window.set_title("GNOME CTF Helper")
        self.window.set_default_size(1280, 820)
        self.window.connect("close-request", self._on_close_request)

        self.toast_overlay = Adw.ToastOverlay()
        self.window.set_content(self.toast_overlay)

        self._current_view: Tuple[str, Optional[str]] = ("challenges", None)
        self._search_query = ""
        self._active_challenge_id: Optional[int] = None
        self._metadata_timeout_id = 0
        self._flag_timeout_id = 0
        self._notes_changed_pending = False

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.toast_overlay.set_child(root)

        self._build_header(root)
        self._build_body(root)
        self._setup_responsive_sidebar()
        self._load_css()

        self.refresh_sidebar()
        self.refresh_main_content()

    # ------------------------------------------------------------------
    # UI construction helpers
    # ------------------------------------------------------------------
    def _build_header(self, root: Gtk.Box) -> None:
        header = Adw.HeaderBar()
        self.header_bar = header
        title = Adw.WindowTitle(title="GNOME CTF Helper", subtitle="Offline Workspace")
        header.set_title_widget(title)

        sidebar_toggle = Gtk.ToggleButton()
        sidebar_toggle.add_css_class("flat")
        sidebar_toggle.add_css_class("circular")
        sidebar_toggle.set_visible(False)
        toggle_content = Adw.ButtonContent()
        toggle_content.set_icon_name("sidebar-show-symbolic")
        sidebar_toggle.set_child(toggle_content)
        sidebar_toggle.connect("toggled", self._on_sidebar_toggle)
        header.pack_start(sidebar_toggle)
        self.sidebar_toggle = sidebar_toggle
        self.sidebar_toggle_content = toggle_content

        import_button = Gtk.Button.new_from_icon_name("document-open-symbolic")
        import_button.set_tooltip_text("Import challenges")
        import_button.connect("clicked", self._on_import_clicked)
        header.pack_start(import_button)

        export_button = Gtk.Button.new_from_icon_name("document-save-symbolic")
        export_button.set_tooltip_text("Export workspace")
        export_button.connect("clicked", self._on_export_clicked)
        header.pack_end(export_button)

        settings_button = Gtk.Button.new_from_icon_name("emblem-system-symbolic")
        settings_button.set_tooltip_text("Settings")
        settings_button.connect("clicked", lambda *_: self._show_not_implemented("Settings"))
        header.pack_end(settings_button)

        root.append(header)

    def _build_body(self, root: Gtk.Box) -> None:
        container = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        container.add_css_class("content-box")
        container.set_hexpand(True)
        container.set_vexpand(True)
        root.append(container)

        self.split_view = Adw.NavigationSplitView()
        self.split_view.set_min_sidebar_width(280)
        self.split_view.set_sidebar_width_fraction(0.3)
        self.split_view.set_hexpand(True)
        self.split_view.set_vexpand(True)
        container.append(self.split_view)

        # Sidebar
        sidebar_box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=8,
            margin_top=12,
            margin_bottom=0,
            margin_start=12,
            margin_end=12,
        )
        sidebar_box.add_css_class("sidebar")
        sidebar_box.set_hexpand(True)
        sidebar_box.set_vexpand(True)
        sidebar_box.set_valign(Gtk.Align.FILL)

        self.search_entry = Gtk.SearchEntry()
        self.search_entry.set_placeholder_text("Search challenges…")
        self.search_entry.connect("search-changed", self._on_search_changed)
        sidebar_box.append(self.search_entry)

        sidebar_add = Gtk.Button()
        sidebar_add.add_css_class("suggested-action")
        sidebar_add_content = Adw.ButtonContent()
        sidebar_add_content.set_icon_name("list-add-symbolic")
        sidebar_add_content.set_label("Add Challenge")
        sidebar_add.set_child(sidebar_add_content)
        sidebar_add.connect("clicked", self._on_add_clicked)
        sidebar_box.append(sidebar_add)

        self.sidebar_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
        self.sidebar_list.add_css_class("navigation-sidebar")
        self.sidebar_list.connect("row-selected", self._on_sidebar_selected)
        self.sidebar_list.set_vexpand(True)
        self.sidebar_list.set_valign(Gtk.Align.FILL)

        sidebar_scroller = Gtk.ScrolledWindow()
        sidebar_scroller.set_has_frame(False)
        sidebar_scroller.add_css_class("sidebar-scroller")
        sidebar_scroller.set_child(self.sidebar_list)
        sidebar_scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        sidebar_scroller.set_hexpand(True)
        sidebar_scroller.set_vexpand(True)
        sidebar_scroller.set_propagate_natural_height(False)
        sidebar_box.append(sidebar_scroller)

        self.sidebar_page = Adw.NavigationPage(child=sidebar_box)
        self.sidebar_page.set_title("Browse")
        self.sidebar_page.set_can_pop(False)
        self.sidebar_page.set_tag("sidebar")
        self.sidebar_page.set_hexpand(True)
        self.sidebar_page.set_vexpand(True)
        self.sidebar_page.set_valign(Gtk.Align.FILL)
        self.split_view.set_sidebar(self.sidebar_page)

        # Content stack
        self.content_stack = Adw.ViewStack()
        self.content_page = Adw.NavigationPage(child=self.content_stack)
        self.content_page.set_title("Workspace")
        self.content_page.set_can_pop(False)
        self.content_page.set_hexpand(True)
        self.content_page.set_vexpand(True)
        self.content_page.set_valign(Gtk.Align.FILL)
        self.split_view.set_content(self.content_page)

        # Challenges stack
        self.challenge_stack = Adw.ViewStack()
        self.content_stack.add_titled(self.challenge_stack, "challenges", "Challenges")

        self.cards_flowbox = Gtk.FlowBox()
        self.cards_flowbox.set_selection_mode(Gtk.SelectionMode.NONE)
        self.cards_flowbox.set_max_children_per_line(4)
        self.cards_flowbox.set_min_children_per_line(1)
        # Use 16px spacing per GNOME HIG requirements and allow cards to size evenly
        self.cards_flowbox.set_row_spacing(16)
        self.cards_flowbox.set_column_spacing(16)
        # Keep homogeneous so cards align nicely; if later we need variable sizes, toggle this
        self.cards_flowbox.set_homogeneous(True)
        self.cards_flowbox.set_halign(Gtk.Align.FILL)
        self.cards_flowbox.set_hexpand(True)
        self.cards_flowbox.set_margin_top(16)
        self.cards_flowbox.set_margin_bottom(16)
        self.cards_flowbox.set_margin_start(16)
        self.cards_flowbox.set_margin_end(16)

        cards_scroller = Gtk.ScrolledWindow()
        cards_scroller.set_hexpand(True)
        cards_scroller.set_vexpand(True)
        cards_scroller.set_child(self.cards_flowbox)
        cards_scroller.add_css_class("cards-scroller")
        # Wrap each card in a holder to give consistent outer margin if needed
        self.challenge_stack.add_named(cards_scroller, "cards")

        self.challenge_placeholder = Adw.StatusPage(
            icon_name="system-run-symbolic",
            title="No challenges yet",
            description="Create your first challenge to start tracking progress.",
        )
        self.challenge_stack.add_named(self.challenge_placeholder, "empty")

        detail_scroller = Gtk.ScrolledWindow()
        detail_scroller.set_hexpand(True)
        detail_scroller.set_vexpand(True)
        detail_scroller.set_child(self._build_detail_view())
        self.challenge_stack.add_named(detail_scroller, "detail")

        # Tools view
        self.tools_container = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=16,
            margin_top=16,
            margin_bottom=16,
            margin_start=16,
            margin_end=16,
        )
        tools_scroller = Gtk.ScrolledWindow()
        tools_scroller.set_hexpand(True)
        tools_scroller.set_vexpand(True)
        tools_scroller.set_child(self.tools_container)
        self.content_stack.add_titled(tools_scroller, "tools", "Tools")

        tools_header = Gtk.Label(xalign=0)
        tools_header.add_css_class("title-3")
        tools_header.set_name("tools_header")
        self.tools_container.append(tools_header)
        self.tools_header = tools_header

        self.tools_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.tools_container.append(self.tools_list)

        output_frame = Gtk.Frame(label="Result")
        output_frame.add_css_class("flat")
        self.tool_output_view = Gtk.TextView()
        self.tool_output_view.set_editable(False)
        self.tool_output_view.set_wrap_mode(Gtk.WrapMode.WORD)
        output_frame.set_child(self.tool_output_view)
        self.tools_container.append(output_frame)

    def _setup_responsive_sidebar(self) -> None:
        self._sidebar_collapse_width = 960
        self.split_view.set_collapsed(False)
        self.split_view.set_show_content(True)
        narrow_condition = Adw.BreakpointCondition.parse(
            f"max-width: {self._sidebar_collapse_width}px"
        )
        wide_condition = Adw.BreakpointCondition.parse(
            f"min-width: {self._sidebar_collapse_width + 1}px"
        )
        self._sidebar_breakpoint_narrow = Adw.Breakpoint.new(narrow_condition)
        self._sidebar_breakpoint_narrow.add_setter(self.split_view, "collapsed", True)
        self.window.add_breakpoint(self._sidebar_breakpoint_narrow)

        self._sidebar_breakpoint_wide = Adw.Breakpoint.new(wide_condition)
        self._sidebar_breakpoint_wide.add_setter(self.split_view, "collapsed", False)
        self._sidebar_breakpoint_wide.add_setter(self.split_view, "show-content", True)
        self.window.add_breakpoint(self._sidebar_breakpoint_wide)

        self.split_view.connect("notify::collapsed", self._on_split_view_collapsed)
        self._sync_sidebar_toggle()

    def _on_split_view_collapsed(self, _split_view: Adw.NavigationSplitView, _param) -> None:
        if not self.split_view.get_collapsed():
            self.split_view.set_show_content(True)
        self._sync_sidebar_toggle()

    def _on_sidebar_toggle(self, button: Gtk.ToggleButton) -> None:
        self.split_view.set_show_content(not button.get_active())
        self._sync_sidebar_toggle()

    def _sync_sidebar_toggle(self) -> None:
        collapsed = self.split_view.get_collapsed()
        self.sidebar_toggle.set_visible(collapsed)
        if not collapsed:
            if self.sidebar_toggle.get_active():
                self.sidebar_toggle.handler_block_by_func(self._on_sidebar_toggle)
                self.sidebar_toggle.set_active(False)
                self.sidebar_toggle.handler_unblock_by_func(self._on_sidebar_toggle)
            self.sidebar_toggle_content.set_icon_name("sidebar-show-symbolic")
            return

        sidebar_visible = not self.split_view.get_show_content()
        if self.sidebar_toggle.get_active() != sidebar_visible:
            self.sidebar_toggle.handler_block_by_func(self._on_sidebar_toggle)
            self.sidebar_toggle.set_active(sidebar_visible)
            self.sidebar_toggle.handler_unblock_by_func(self._on_sidebar_toggle)
        icon = "sidebar-hide-symbolic" if sidebar_visible else "sidebar-show-symbolic"
        self.sidebar_toggle_content.set_icon_name(icon)

    def _build_detail_view(self) -> Gtk.Box:
        box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=16,
            margin_top=24,
            margin_bottom=24,
            margin_start=24,
            margin_end=24,
        )

        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        back_button = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_button.set_tooltip_text("Back to challenges")
        back_button.connect("clicked", lambda *_: self._show_cards())
        header_row.append(back_button)

        title_column = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        title_label = Gtk.Label(xalign=0)
        title_label.add_css_class("title-2")
        title_label.set_text("Challenge")
        self.detail_title_label = title_label
        title_column.append(title_label)

        meta_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        project_label = Gtk.Label(xalign=0)
        project_label.add_css_class("dim-label")
        self.detail_project_label = project_label
        category_label = Gtk.Label(xalign=0)
        category_label.add_css_class("dim-label")
        self.detail_category_label = category_label
        status_chip = _status_chip("Not Started")
        self.detail_status_chip = status_chip
        meta_row.append(project_label)
        meta_row.append(category_label)
        meta_row.append(status_chip)
        title_column.append(meta_row)

        header_row.append(title_column)
        box.append(header_row)

        form_grid = Gtk.Grid(column_spacing=12, row_spacing=12)
        form_grid.attach(Gtk.Label(label="Title", xalign=0), 0, 0, 1, 1)
        self.title_entry = Gtk.Entry()
        form_grid.attach(self.title_entry, 1, 0, 1, 1)

        form_grid.attach(Gtk.Label(label="Project", xalign=0), 0, 1, 1, 1)
        self.project_entry = Gtk.Entry()
        form_grid.attach(self.project_entry, 1, 1, 1, 1)

        form_grid.attach(Gtk.Label(label="Category", xalign=0), 0, 2, 1, 1)
        self.category_entry = Gtk.Entry()
        form_grid.attach(self.category_entry, 1, 2, 1, 1)

        form_grid.attach(Gtk.Label(label="Difficulty", xalign=0), 0, 3, 1, 1)
        self.difficulty_combo = Gtk.ComboBoxText()
        for item in ["easy", "medium", "hard"]:
            self.difficulty_combo.append(item, item.title())
        form_grid.attach(self.difficulty_combo, 1, 3, 1, 1)

        form_grid.attach(Gtk.Label(label="Flag", xalign=0), 0, 4, 1, 1)
        self.flag_entry = Gtk.Entry()
        form_grid.attach(self.flag_entry, 1, 4, 1, 1)

        form_grid.attach(Gtk.Label(label="Status", xalign=0), 0, 5, 1, 1)
        self.status_combo = Gtk.ComboBoxText()
        for status in STATUSES:
            self.status_combo.append(status, status)
        form_grid.attach(self.status_combo, 1, 5, 1, 1)

        box.append(form_grid)

        description_section = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        description_section.append(Gtk.Label(label="Description", xalign=0))
        description_scroller = Gtk.ScrolledWindow()
        description_scroller.set_hexpand(True)
        description_scroller.set_vexpand(True)
        self.description_view = Gtk.TextView()
        self.description_view.set_wrap_mode(Gtk.WrapMode.WORD)
        description_scroller.set_child(self.description_view)
        description_section.append(description_scroller)
        box.append(description_section)

        notes_paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        notes_paned.set_wide_handle(True)
        notes_paned.set_shrink_start_child(False)
        notes_paned.set_shrink_end_child(True)

        notes_editor = Gtk.ScrolledWindow()
        notes_editor.set_hexpand(True)
        notes_editor.set_vexpand(True)
        self.notes_view = Gtk.TextView()
        self.notes_view.set_wrap_mode(Gtk.WrapMode.WORD)
        self.notes_view.add_css_class("notes-editor")
        notes_buffer = self.notes_view.get_buffer()
        notes_buffer.connect("changed", self._on_notes_changed)
        notes_editor.set_child(self.notes_view)
        notes_paned.set_start_child(notes_editor)

        preview_scroller = Gtk.ScrolledWindow()
        preview_scroller.set_hexpand(True)
        preview_scroller.set_vexpand(True)
        self.notes_preview = Gtk.TextView()
        self.notes_preview.set_editable(False)
        self.notes_preview.add_css_class("notes-preview")
        preview_scroller.set_child(self.notes_preview)
        notes_paned.set_end_child(preview_scroller)
        box.append(notes_paned)

        status_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        self.status_label = Gtk.Label(xalign=1)
        self.status_label.add_css_class("dim-label")
        status_row.append(self.status_label)
        box.append(status_row)

        # Signal wiring for metadata autosave
        self.title_entry.connect("changed", lambda *_: self._schedule_metadata_save())
        self.project_entry.connect("changed", lambda *_: self._schedule_metadata_save())
        self.category_entry.connect("changed", lambda *_: self._schedule_metadata_save())
        self.difficulty_combo.connect("changed", lambda *_: self._schedule_metadata_save())
        self.description_view.get_buffer().connect("changed", lambda *_: self._schedule_metadata_save())
        self.status_combo.connect("changed", lambda *_: self._schedule_metadata_save())
        self.flag_entry.connect("changed", lambda *_: self._schedule_flag_save())

        return box

    def _load_css(self) -> None:
        provider = self.app.resources.css_provider()
        display = self.window.get_display()
        if display is None:
            return
        Gtk.StyleContext.add_provider_for_display(display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

    # ------------------------------------------------------------------
    # Sidebar & navigation
    # ------------------------------------------------------------------
    def refresh_sidebar(self) -> None:
        _clear_listbox(self.sidebar_list)

        self._append_sidebar_heading("Challenges")
        self._append_sidebar_item("challenges", "emblem-favorite-symbolic", "All Challenges", selectable=True)

        self._append_sidebar_heading("Tools")
        self._append_sidebar_item("tools", "applications-system-symbolic", "All Tools", selectable=True)

        category_icons = {
            "Crypto": "emblem-lock-symbolic",
            "Forensics": "folder-symbolic",
            "Reverse Engineering": "applications-engineering-symbolic",
            "Web Exploitation": "network-server-symbolic",
            "Misc": "applications-system-symbolic",
        }

        for category in sorted(self.app.module_registry.categories(), key=str.lower):
            row = Gtk.ListBoxRow()
            row.set_name(self._encode_view_name("tool", category))
            row.add_css_class("sidebar-row")
            item_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8, margin_start=18, margin_end=12, margin_top=4, margin_bottom=4)
            icon_name = category_icons.get(category, "applications-system-symbolic")
            item_box.append(Gtk.Image.new_from_icon_name(icon_name))
            item_box.append(Gtk.Label(label=category, xalign=0))
            row.set_child(item_box)
            self.sidebar_list.append(row)

        self._select_sidebar_row()

    def _append_sidebar_heading(self, text: str) -> None:
        row = Gtk.ListBoxRow()
        row.set_selectable(False)
        row.set_sensitive(False)
        label = Gtk.Label(label=text, xalign=0)
        label.add_css_class("sidebar-section")
        row.set_child(label)
        self.sidebar_list.append(row)

    def _append_sidebar_item(self, name: str, icon: str, label: str, *, selectable: bool) -> None:
        row = Gtk.ListBoxRow()
        row.set_name(name)
        row.set_selectable(selectable)
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8, margin_start=12, margin_end=12, margin_top=4, margin_bottom=4)
        box.append(Gtk.Image.new_from_icon_name(icon))
        box.append(Gtk.Label(label=label, xalign=0))
        row.set_child(box)
        self.sidebar_list.append(row)

    def _append_sidebar_separator(self) -> None:
        row = Gtk.ListBoxRow()
        row.set_selectable(False)
        row.set_sensitive(False)
        separator = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
        row.set_child(separator)
        self.sidebar_list.append(row)

    def _select_sidebar_row(self) -> None:
        target_name = self._encode_view_name(*self._current_view)
        child = self.sidebar_list.get_first_child()
        while child is not None:
            if isinstance(child, Gtk.ListBoxRow) and child.get_name() == target_name:
                self.sidebar_list.select_row(child)
                return
            child = child.get_next_sibling()

    # ------------------------------------------------------------------
    # Main content routing
    # ------------------------------------------------------------------
    def refresh_main_content(self) -> None:
        view, payload = self._current_view
        if view == "challenges":
            self._show_challenges(payload)
        elif view == "project":
            self._show_challenges(payload)
        elif view == "tools":
            self._show_tools(payload)
        else:
            self._show_challenges(None)

    def _encode_view_name(self, view: str, payload: Optional[str]) -> str:
        if payload is None:
            return view
        return f"{view}::{payload}"

    def _on_sidebar_selected(self, _listbox: Gtk.ListBox, row: Optional[Gtk.ListBoxRow]) -> None:
        if row is None:
            return
        name = row.get_name() or "challenges"
        if name.startswith("project::"):
            project = name.split("::", 1)[1]
            self._current_view = ("project", project)
        elif name.startswith("tool::"):
            category = name.split("::", 1)[1]
            self._current_view = ("tools", category)
        else:
            self._current_view = (name, None)
        self.refresh_main_content()
        if self.split_view.get_collapsed():
            self.split_view.set_show_content(True)
            if self.sidebar_toggle.get_active():
                self.sidebar_toggle.handler_block_by_func(self._on_sidebar_toggle)
                self.sidebar_toggle.set_active(False)
                self.sidebar_toggle.handler_unblock_by_func(self._on_sidebar_toggle)
            self._sync_sidebar_toggle()

    def _show_challenges(self, project: Optional[str]) -> None:
        self.content_stack.set_visible_child_name("challenges")

        challenges = self.app.challenge_manager.list_challenges()
        query = self.search_entry.get_text().strip().lower()

        filtered: List[Challenge] = []
        for challenge in challenges:
            if project and challenge.project != project:
                continue
            if query and all(
                query not in value
                for value in [
                    challenge.title.lower(),
                    challenge.project.lower(),
                    challenge.category.lower(),
                    challenge.status.lower(),
                    (challenge.description or "").lower(),
                ]
            ):
                continue
            filtered.append(challenge)

        if not filtered:
            if project:
                self.challenge_placeholder.set_title("No challenges for this project")
                self.challenge_placeholder.set_description("Add or import challenges to begin tracking this project.")
            elif query:
                self.challenge_placeholder.set_title("No matches found")
                self.challenge_placeholder.set_description("Try a different search or clear the filter.")
            else:
                self.challenge_placeholder.set_title("No challenges yet")
                self.challenge_placeholder.set_description("Create your first challenge to start tracking progress.")
            self.challenge_stack.set_visible_child_name("empty")
            _clear_flowbox(self.cards_flowbox)
            return

        self.challenge_stack.set_visible_child_name("cards")
        _clear_flowbox(self.cards_flowbox)

        for challenge in filtered:
            card = ChallengeCard(challenge, self._open_challenge_detail)
            child = Gtk.FlowBoxChild()
            child.add_css_class("challenge-card-holder")
            child.set_valign(Gtk.Align.START)
            child.set_halign(Gtk.Align.FILL)
            child.set_hexpand(True)
            child.set_margin_top(8)
            child.set_margin_bottom(8)
            child.set_margin_start(8)
            child.set_margin_end(8)
            child.set_child(card)
            self.cards_flowbox.append(child)

    def _show_tools(self, category: Optional[str]) -> None:
        self.content_stack.set_visible_child_name("tools")
        grouped = self.app.module_registry.by_category()
        if category is not None and category not in grouped:
            category = None
        if category is None:
            if grouped:
                category = sorted(grouped.keys())[0]
            else:
                category = ""

        _clear_box(self.tools_list)
        if not grouped:
            self.tools_header.set_text("No offline tools available")
            self._set_tool_output("")
            return

        if category and category in grouped:
            self.tools_header.set_text(f"{category} tools")
            for tool in grouped[category]:
                row = Adw.ActionRow(title=tool.name, subtitle=getattr(tool, "description", ""))
                run_button = Gtk.Button.new_from_icon_name("media-playback-start-symbolic")
                run_button.set_tooltip_text("Run tool")
                run_button.connect("clicked", lambda _btn, t=tool: self._run_tool(t))
                row.add_suffix(run_button)
                row.set_activatable(True)
                row.connect("activated", lambda _row, t=tool: self._run_tool(t))
                self.tools_list.append(row)
        else:
            self.tools_header.set_text("Offline tools")
            prompt = Gtk.Label(label="Select a tool category from the sidebar to get started.", xalign=0)
            prompt.add_css_class("dim-label")
            self.tools_list.append(prompt)

    # ------------------------------------------------------------------
    # Challenge detail handling
    # ------------------------------------------------------------------
    def _open_challenge_detail(self, challenge_id: int) -> None:
        try:
            challenge = self.app.challenge_manager.get_challenge(challenge_id)
        except ValueError:
            self._set_status_message("Challenge no longer exists")
            return
        self._active_challenge_id = challenge_id
        self._populate_detail(challenge)
        self.challenge_stack.set_visible_child_name("detail")

    def _show_cards(self) -> None:
        self.challenge_stack.set_visible_child_name("cards")

    def _focus_challenge_card(self, challenge_id: int) -> bool:
        child = self.cards_flowbox.get_first_child()
        while child is not None:
            card = child.get_child()
            if isinstance(card, ChallengeCard) and card.challenge_id == challenge_id:
                card.grab_focus()
                self.cards_flowbox.scroll_to(child, False, 0.0, 0.0)
                break
            child = child.get_next_sibling()
        return False

    def _populate_detail(self, challenge: Challenge) -> None:
        self.detail_title_label.set_text(challenge.title)
        self.detail_project_label.set_text(f"Project · {challenge.project}")
        self.detail_category_label.set_text(f"Category · {challenge.category}")
        for cls in list(self.detail_status_chip.get_css_classes()):
            if cls.startswith("status-"):
                self.detail_status_chip.remove_css_class(cls)
        self.detail_status_chip.add_css_class(STATUS_STYLE_CLASSES.get(challenge.status, "status-not-started"))
        self.detail_status_chip.set_label(challenge.status)

        self.title_entry.set_text(challenge.title)
        self.project_entry.set_text(challenge.project)
        self.category_entry.set_text(challenge.category)
        self.difficulty_combo.set_active_id(challenge.difficulty.lower())
        self.status_combo.set_active_id(challenge.status if challenge.status in STATUSES else STATUSES[0])
        buffer = self.description_view.get_buffer()
        buffer.set_text(challenge.description)
        self.flag_entry.set_text(challenge.flag or "")
        self._set_notes_text(self.app.note_manager.load_markdown(challenge.id))
        self._set_status_message(
            f"Updated {challenge.updated_at:%Y-%m-%d %H:%M} • Created {challenge.created_at:%Y-%m-%d %H:%M}"
        )

    # ------------------------------------------------------------------
    # User actions
    # ------------------------------------------------------------------
    def _on_search_changed(self, entry: Gtk.SearchEntry) -> None:
        self._search_query = entry.get_text().strip()
        if self._current_view[0] not in {"challenges", "project"}:
            self._current_view = ("challenges", None)
            self._select_sidebar_row()
        self.refresh_main_content()

    def _on_add_clicked(self, _button: Optional[Gtk.Button] = None) -> None:
        dialog = ChallengeDialog(self.window)
        response = dialog.present()
        if response == "ok":
            data = dialog.collect()
            challenge = self.app.challenge_manager.create_challenge(**data)
            self.toast_overlay.add_toast(Adw.Toast.new("Challenge created"))
            self._current_view = ("challenges", None)
            self.refresh_sidebar()
            self.refresh_main_content()
            self._show_cards()
            GLib.idle_add(self._focus_challenge_card, challenge.id)
        dialog.destroy()

    def _on_import_clicked(self, _button: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative.new("Import .ctfpack", self.window, Gtk.FileChooserAction.OPEN, None, None)
        dialog.set_modal(True)
        filter_pack = Gtk.FileFilter()
        filter_pack.set_name("CTF Packs")
        filter_pack.add_pattern("*.ctfpack")
        dialog.add_filter(filter_pack)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                path = Path(file.get_path())
                self.app.export_import.import_from_path(path)
                self.toast_overlay.add_toast(Adw.Toast.new("Imported challenges"))
                self.refresh_sidebar()
                self.refresh_main_content()
        dialog.destroy()

    def _on_export_clicked(self, _button: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative.new("Export .ctfpack", self.window, Gtk.FileChooserAction.SAVE, None, None)
        dialog.set_modal(True)
        dialog.set_current_name("ctf-helper.ctfpack")
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                path = Path(file.get_path())
                if path.suffix != ".ctfpack":
                    path = path.with_suffix(".ctfpack")
                self.app.export_import.export_to_path(path)
                self.toast_overlay.add_toast(Adw.Toast.new("Workspace exported"))
        dialog.destroy()

    def _run_native_dialog(self, dialog: Gtk.FileChooserNative) -> int:
        response_holder: Dict[str, int] = {}
        loop = GLib.MainLoop()

        def on_response(_dialog: Gtk.FileChooserNative, response: int) -> None:
            response_holder["response"] = response
            loop.quit()

        dialog.connect("response", on_response)
        dialog.show()
        loop.run()
        response = response_holder.get("response")
        return response if response is not None else Gtk.ResponseType.CANCEL

    # ------------------------------------------------------------------
    # Notes & metadata persistence
    # ------------------------------------------------------------------
    def _on_notes_changed(self, buffer: Gtk.TextBuffer) -> None:
        if self._active_challenge_id is None:
            return
        start, end = buffer.get_bounds()
        text = buffer.get_text(start, end, True)
        self._update_preview(text)
        if self._notes_changed_pending:
            return
        self._notes_changed_pending = True
        GLib.timeout_add_seconds(2, self._autosave_notes, text)

    def _autosave_notes(self, text: str) -> bool:
        if self._active_challenge_id is None:
            return False
        self.app.note_manager.save_markdown(self._active_challenge_id, text)
        self._notes_changed_pending = False
        self._set_status_message("Notes saved")
        return False

    def _set_notes_text(self, text: str) -> None:
        buffer = self.notes_view.get_buffer()
        buffer.handler_block_by_func(self._on_notes_changed)
        buffer.set_text(text)
        buffer.handler_unblock_by_func(self._on_notes_changed)
        self._update_preview(text)

    def _update_preview(self, markdown: str) -> None:
        rendered = self.app.markdown_renderer.render(markdown)
        plain_text = re.sub(r"<[^>]+>", "", rendered)
        buffer = Gtk.TextBuffer()
        buffer.set_text(plain_text, -1)
        self.notes_preview.set_buffer(buffer)

    def _schedule_metadata_save(self) -> None:
        if self._active_challenge_id is None:
            return
        if self._metadata_timeout_id:
            return
        self._metadata_timeout_id = GLib.timeout_add_seconds(1, self._flush_metadata)

    def _flush_metadata(self) -> bool:
        self._metadata_timeout_id = 0
        if self._active_challenge_id is None:
            return False
        title = self.title_entry.get_text() or "Untitled"
        project = self.project_entry.get_text() or "General"
        category = self.category_entry.get_text() or "misc"
        difficulty = self.difficulty_combo.get_active_id() or "medium"
        status = self.status_combo.get_active_id() or STATUSES[0]
        buffer = self.description_view.get_buffer()
        start, end = buffer.get_bounds()
        description = buffer.get_text(start, end, True)
        challenge = self.app.challenge_manager.update_challenge(
            self._active_challenge_id,
            title=title,
            project=project,
            category=category,
            difficulty=difficulty,
            status=status,
            description=description,
        )
        self._set_status_message("Details saved")
        detail_visible = self.challenge_stack.get_visible_child_name() == "detail"
        self.refresh_sidebar()
        self.refresh_main_content()
        if detail_visible:
            self._populate_detail(challenge)
            self.challenge_stack.set_visible_child_name("detail")
        return False

    def _schedule_flag_save(self) -> None:
        if self._active_challenge_id is None:
            return
        if self._flag_timeout_id:
            return
        self._flag_timeout_id = GLib.timeout_add_seconds(1, self._flush_flag)

    def _flush_flag(self) -> bool:
        self._flag_timeout_id = 0
        if self._active_challenge_id is None:
            return False
        self.app.challenge_manager.set_flag(self._active_challenge_id, self.flag_entry.get_text() or None)
        self._set_status_message("Flag saved")
        return False

    # ------------------------------------------------------------------
    # Tools utilities
    # ------------------------------------------------------------------
    def _run_tool(self, tool) -> None:
        params = self._prompt_for_parameters(tool)
        if params is None:
            return
        try:
            result = tool.run(**params)
        except Exception as exc:  # pragma: no cover - runtime guard
            self._set_tool_output(f"Error: {exc}")
            return
        body = getattr(result, "body", str(result))
        self._set_tool_output(body)

    def _set_tool_output(self, text: str) -> None:
        buffer = self.tool_output_view.get_buffer()
        buffer.set_text(text)

    def _prompt_for_parameters(self, tool) -> Optional[Dict[str, str]]:
        signature = inspect.signature(tool.run)
        parameters = [(name, param) for name, param in signature.parameters.items() if name != "self"]
        if not parameters:
            return {}

        entries: Dict[str, Gtk.Entry] = {}
        dialog = Adw.Dialog.new()
        dialog.set_heading(f"Run {tool.name}")
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("run", "Run")
        dialog.set_close_response("cancel")
        dialog.set_default_response("run")

        grid = Gtk.Grid(column_spacing=8, row_spacing=8, margin_top=12, margin_bottom=12, margin_start=12, margin_end=12)
        dialog.set_content(grid)

        row = 0
        for name, param in parameters:
            label = Gtk.Label(label=name.replace('_', ' ').title(), xalign=0)
            entry = Gtk.Entry()
            if param.default is not inspect._empty:
                entry.set_text(str(param.default))
            if param.annotation is Path:
                entry.set_placeholder_text("Path to file")
            grid.attach(label, 0, row, 1, 1)
            grid.attach(entry, 1, row, 1, 1)
            entries[name] = entry
            row += 1

        response_holder: Dict[str, str] = {}
        loop = GLib.MainLoop()

        def on_response(_dialog: Adw.Dialog, response: str) -> None:
            response_holder["id"] = response
            loop.quit()

        dialog.connect("response", on_response)
        dialog.present(self.window)
        loop.run()
        dialog.close()

        if response_holder.get("id") != "run":
            return None

        values: Dict[str, str] = {}
        for name, entry in entries.items():
            values[name] = entry.get_text()
        return values

    # ------------------------------------------------------------------
    # Status & lifecycle
    # ------------------------------------------------------------------
    def _set_status_message(self, text: str) -> None:
        self.status_label.set_text(text)

    def _show_not_implemented(self, feature: str) -> None:
        self.toast_overlay.add_toast(Adw.Toast.new(f"{feature} isn’t available yet"))

    def trigger_new_challenge(self) -> None:
        self._on_add_clicked()

    def focus_search(self) -> None:
        self.search_entry.grab_focus()

    def present(self) -> None:
        self.window.present()

    def _on_close_request(self, *_args) -> bool:
        self.app.shutdown()
        return False


class ChallengeDialog:
    """Simple modal dialog for creating a challenge."""

    def __init__(self, parent: Adw.ApplicationWindow) -> None:
        self.dialog = Adw.MessageDialog.new(parent, "New Challenge", "Fill in metadata for the new challenge.")
        self.dialog.add_response("cancel", "Cancel")
        self.dialog.add_response("ok", "Create")
        self.dialog.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=12, margin_bottom=12, margin_start=12, margin_end=12)
        self.title_entry = Gtk.Entry(placeholder_text="Challenge title")
        self.project_entry = Gtk.Entry(placeholder_text="Project / track")
        self.category_entry = Gtk.Entry(placeholder_text="Category")
        self.status_combo = Gtk.ComboBoxText()
        for status in STATUSES:
            self.status_combo.append(status, status)
        self.status_combo.set_active_id(STATUSES[0])
        self.difficulty_combo = Gtk.ComboBoxText()
        for item in ["easy", "medium", "hard"]:
            self.difficulty_combo.append(item, item.title())
        self.difficulty_combo.set_active_id("medium")
        self.description_view = Gtk.TextView()
        self.description_view.set_wrap_mode(Gtk.WrapMode.WORD)
        box.append(self.title_entry)
        box.append(self.project_entry)
        box.append(self.category_entry)
        box.append(self.status_combo)
        box.append(self.difficulty_combo)
        box.append(self.description_view)
        self.dialog.set_extra_child(box)

    def present(self) -> str:
        loop = GLib.MainLoop()
        response_holder: Dict[str, str] = {}

        def on_response(_dialog: Adw.MessageDialog, response: str) -> None:
            response_holder["response"] = response
            loop.quit()

        self.dialog.connect("response", on_response)
        self.dialog.present()
        loop.run()
        return response_holder.get("response", "cancel")

    def collect(self) -> Dict[str, str]:
        buffer = self.description_view.get_buffer()
        start, end = buffer.get_bounds()
        return {
            "title": self.title_entry.get_text() or "Untitled",
            "project": self.project_entry.get_text() or "General",
            "category": self.category_entry.get_text() or "misc",
            "status": self.status_combo.get_active_id() or STATUSES[0],
            "difficulty": self.difficulty_combo.get_active_id() or "medium",
            "description": buffer.get_text(start, end, True),
        }

    def destroy(self) -> None:
        self.dialog.destroy()


class CTFHelperApplication(Adw.Application):
    def __init__(self) -> None:
        super().__init__(application_id=config.APP_ID, flags=Gio.ApplicationFlags.FLAGS_NONE)
        self.resources = Resources()
        self.offline_guard = OfflineGuard()
        self.module_registry = ModuleRegistry()
        self.database = Database()
        self.challenge_manager = ChallengeManager(self.database)
        self.note_manager = NoteManager(self.challenge_manager)
        self.export_import = ExportImportManager(self.challenge_manager)
        self.markdown_renderer = MarkdownRenderer()
        self.main_window: Optional[MainWindow] = None
        self._diagnostics_cache: Optional[str] = None
        self._pending_warnings: List[str] = []

    # ------------------------------------------------------------------
    def do_startup(self) -> None:  # type: ignore[override]
        Adw.Application.do_startup(self)
        self._install_actions()
        self._register_css()

    def do_activate(self) -> None:  # type: ignore[override]
        try:
            self.offline_guard.enforce()
        except OfflineViolation as exc:
            self._notify_offline_violation(str(exc))
        if not self.main_window:
            self.resources.ensure_help_extracted()
            self.main_window = MainWindow(self)
            seed_if_requested(self.challenge_manager, self.note_manager)
            self._flush_pending_warnings()
        self.main_window.present()

    # ------------------------------------------------------------------
    def _install_actions(self) -> None:
        self._add_simple_action("copy_diagnostics", self.copy_diagnostics)
        self._add_simple_action("open_logs", self.open_logs)
        self._add_simple_action("about", self.show_about)
        self._add_simple_action("new_challenge", self._action_new_challenge)
        self._add_simple_action("focus_search", self._action_focus_search)
        self.set_accels_for_action("app.new_challenge", ["<Primary>n"])
        self.set_accels_for_action("app.focus_search", ["<Primary>f"])

    def _add_simple_action(self, name: str, callback) -> None:
        action = Gio.SimpleAction.new(name, None)
        action.connect("activate", lambda _a, _p: callback())
        self.add_action(action)

    def _register_css(self) -> None:
        provider = self.resources.css_provider()
        display = Gdk.Display.get_default() or self.get_display()
        if display is None:
            return
        Gtk.StyleContext.add_provider_for_display(display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

    # ------------------------------------------------------------------
    def copy_diagnostics(self) -> None:
        diagnostics = self._collect_diagnostics()
        display = self.get_display()
        if display is None:
            return
        clipboard = display.get_clipboard()
        clipboard.set_text(diagnostics)

    def open_logs(self) -> None:
        folder = Gio.File.new_for_path(str(log_dir()))
        launcher = Gtk.FileLauncher.new(folder)
        launcher.launch(self.get_active_window(), None, None)

    def show_about(self) -> None:
        about = Adw.AboutWindow(
            application_name=config.APP_NAME,
            application_icon="org.example.CTFHelper",
            developer_name="GNOME CTF Helper Team",
            version=config.APP_VERSION,
            comments="An offline-first companion for Capture the Flag study.",
            license_type=Gtk.License.GPL_3_0,
            issue_url="file:///app/share/ctf-helper/help/getting_started.md",
        )
        about.present()

    def shutdown(self) -> None:
        _LOG.info("Shutting down application")
        self.database.close()

    def _notify_offline_violation(self, message: str) -> None:
        _LOG.warning("Offline guard warning: %s", message)
        if self.main_window:
            toast = Adw.Toast.new(message)
            toast.set_priority(Adw.ToastPriority.HIGH)
            self.main_window.toast_overlay.add_toast(toast)
            return
        # Defer displaying until the main window is ready
        if message not in self._pending_warnings:
            self._pending_warnings.append(message)

    def _flush_pending_warnings(self) -> None:
        if not self.main_window:
            return
        for message in self._pending_warnings:
            toast = Adw.Toast.new(message)
            toast.set_priority(Adw.ToastPriority.HIGH)
            self.main_window.toast_overlay.add_toast(toast)
        self._pending_warnings.clear()

    def _collect_diagnostics(self) -> str:
        if self._diagnostics_cache:
            return self._diagnostics_cache
        payload = {
            "version": config.APP_VERSION,
            "offline": config.OFFLINE_BUILD,
            "challenges": len(self.challenge_manager.list_challenges()),
            "logs": str(log_dir()),
        }
        self._diagnostics_cache = json.dumps(payload, indent=2)
        return self._diagnostics_cache

    def _action_new_challenge(self) -> None:
        if self.main_window:
            self.main_window.trigger_new_challenge()

    def _action_focus_search(self) -> None:
        if self.main_window:
            self.main_window.focus_search()


def run() -> None:
    app = CTFHelperApplication()
    app.run(None)
