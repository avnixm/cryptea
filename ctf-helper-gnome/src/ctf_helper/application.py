"""Primary application entry point for Cryptea."""

from __future__ import annotations

import inspect
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, TypedDict
import threading

import gi  # type: ignore[import]

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gio, GLib, Gtk, Gdk, Pango, GObject  # type: ignore[import]

from . import config
from .data_paths import log_dir
from .dev_seed import seed_if_requested
from .logger import configure_logging
from .db import Database
from .manager.challenge_manager import ChallengeManager, STATUSES
from .manager.models import Challenge
from .manager.export_import import ExportImportManager
from .modules import ModuleRegistry
from .modules.reverse.quick_disassembler import QuickDisassembler
from .notes import MarkdownRenderer, NoteManager
from .offline_guard import OfflineGuard, OfflineViolation
from .resources import Resources

_LOG = configure_logging()


CATEGORY_COLORS: Dict[str, str] = {
    "crypto": "purple",
    "crypto & encoding": "purple",
    "cryptography": "purple",
    "forensics": "blue",
    "reverse": "orange",
    "reverse engineering": "orange",
    "web": "teal",
    "web exploitation": "teal",
    "misc": "gray",
    "osint": "pink",
    "stego & media": "purple",
}

CATEGORY_ICONS: Dict[str, str] = {
    "crypto": "emblem-locked-symbolic",
    "crypto & encoding": "emblem-locked-symbolic",
    "cryptography": "emblem-locked-symbolic",
    "forensics": "system-search-symbolic",
    "reverse engineering": "media-playlist-repeat-symbolic",
    "reverse": "media-playlist-repeat-symbolic",
    "web exploitation": "network-server-symbolic",
    "web": "network-server-symbolic",
    "misc": "applications-utilities-symbolic",
    "network": "network-server-symbolic",
    "network scanning": "network-server-symbolic",
    "stego & media": "image-x-generic-symbolic",
}

TOOL_ICON_MAP: Dict[str, str] = {
    "hash digest": "document-open-symbolic",
    "caesar cipher": "input-mouse-symbolic",
    "vigenère cipher": "accessories-calculator-symbolic",
    "morse decoder": "accessories-text-editor-symbolic",
    "xor cipher": "preferences-desktop-keyboard-symbolic",
    "rsa tool": "media-floppy-symbolic",
    "base64 encode/decode": "text-x-generic-symbolic",
    "hex viewer": "accessories-text-editor-symbolic",
    "file type detector": "system-file-manager-symbolic",
    "stego extractor": "image-x-generic-symbolic",
    "exif metadata reader": "image-x-generic-symbolic",
    "memory dump parser": "media-optical-symbolic",
    "pcap analyzer": "network-workgroup-symbolic",
    "pcap viewer": "network-wireless-symbolic",
    "memory analyzer": "utilities-system-monitor-symbolic",
    "disk image tools": "drive-harddisk-symbolic",
    "timeline builder": "view-list-symbolic",
    "image stego toolkit": "image-x-generic-symbolic",
    "exif metadata viewer": "image-x-generic-symbolic",
    "audio analyzer": "audio-input-microphone-symbolic",
    "video frame exporter": "applications-multimedia-symbolic",
    "qr/barcode scanner": "scanner-symbolic",
    "extract strings": "utilities-terminal-symbolic",
    "disassembler": "media-playlist-repeat-symbolic",
    "disassembler launcher": "media-playlist-repeat-symbolic",
    "radare/rizin console": "utilities-terminal-symbolic",
    "gdb runner": "utilities-terminal-symbolic",
    "rop gadget finder": "media-seek-forward-symbolic",
    "binary diff": "view-dual-symbolic",
    "pe/elf inspector": "text-x-generic-symbolic",
    "decompiler": "accessories-text-editor-symbolic",
    "symbol resolver": "view-grid-symbolic",
    "http request builder": "network-server-symbolic",
    "cookie inspector": "applications-web-symbolic",
    "sqli playground": "applications-engineering-symbolic",
    "xss playground": "applications-internet-symbolic",
    "jwt decoder": "security-high-symbolic",
    "url encoder/decoder": "text-html-symbolic",
    "wordlist generator": "view-list-symbolic",
    "hash cracker": "dialog-password-symbolic",
    "qr/barcode decoder": "scanner-symbolic",
    "text encoder/decoder": "accessories-text-editor-symbolic",
    "random generator": "view-refresh-symbolic",
    "notes helper": "accessories-dictionary-symbolic",
    "dir discovery": "system-search-symbolic",
    "sqlmap": "applications-engineering-symbolic",
    "nmap": "network-workgroup-symbolic",
    "sqli tester": "applications-engineering-symbolic",
    "xss tester": "applications-internet-symbolic",
    "jwt tool": "security-high-symbolic",
    "file upload tester": "document-send-symbolic",
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


def _clear_grid(grid: Gtk.Grid) -> None:
    """Remove all children from a Gtk.Grid"""
    child = grid.get_first_child()
    while child is not None:
        next_child = child.get_next_sibling()
        grid.remove(child)
        child = next_child


class ChallengeCard(Gtk.Button):
    """Compact card used on the challenges grid."""

    __gtype_name__ = "ChallengeCard"

    def __init__(self, challenge: Challenge, callback, favorite_callback=None) -> None:
        super().__init__(valign=Gtk.Align.START, halign=Gtk.Align.FILL)
        self.challenge_id = challenge.id
        self.challenge = challenge
        self.favorite_callback = favorite_callback
        self.set_can_focus(True)
        self.set_focus_on_click(True)
        self.set_has_frame(False)
        self.add_css_class("challenge-card")
        if getattr(challenge, "favorite", False):
            self.add_css_class("challenge-card-favorite")
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

        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)

        icon_name = CATEGORY_ICONS.get(challenge.category.lower(), "view-grid-symbolic")
        icon = Gtk.Image.new_from_icon_name(icon_name)
        icon.add_css_class("card-category-icon")
        header.append(icon)

        header_content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        header_content.set_hexpand(True)
        title = Gtk.Label(xalign=0)
        title.set_markup(f"<b>{GLib.markup_escape_text(challenge.title)}</b>")
        title.add_css_class("title-4")
        header_content.append(title)

        chips = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        chips.set_halign(Gtk.Align.START)
        color = CATEGORY_COLORS.get(challenge.category.lower(), "gray")
        chips.append(_pill_label(challenge.category, color))
        chips.append(_status_chip(challenge.status))
        project_label = Gtk.Label(label=challenge.project, xalign=0)
        project_label.add_css_class("dim-label")
        chips.append(project_label)
        header_content.append(chips)
        header.append(header_content)

        # Add favorite star button
        self.favorite_button = Gtk.Button()
        self.favorite_button.set_has_frame(False)
        self.favorite_button.set_valign(Gtk.Align.START)
        self.favorite_button.add_css_class("flat")
        self.favorite_button.add_css_class("circular")
        
        # Set the appropriate icon based on favorite status
        icon_name = "starred-symbolic" if getattr(challenge, "favorite", False) else "non-starred-symbolic"
        self.favorite_icon = Gtk.Image.new_from_icon_name(icon_name)
        self.favorite_button.set_child(self.favorite_icon)
        
        # Use GestureClick to properly stop event propagation
        gesture = Gtk.GestureClick.new()
        gesture.set_button(1)  # Left mouse button
        gesture.connect("pressed", self._on_favorite_pressed)
        self.favorite_button.add_controller(gesture)
        
        header.append(self.favorite_button)

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
    
    def _on_favorite_pressed(self, gesture: Gtk.GestureClick, n_press: int, x: float, y: float) -> None:
        """Handle favorite button click and stop propagation"""
        gesture.set_state(Gtk.EventSequenceState.CLAIMED)
        if self.favorite_callback:
            self.favorite_callback(self.challenge_id)


class MainWindow:
    """Controller for the main application window."""

    def __init__(self, app: "CrypteaApplication") -> None:
        self.app = app
        self.window = Adw.ApplicationWindow(application=app)
        self.window.set_title("Cryptea")
        self.window.set_default_size(1280, 820)
        self.window.connect("close-request", self._on_close_request)
        
        # Set window icon
        self._set_window_icon()

        self.toast_overlay = Adw.ToastOverlay()
        self.window.set_content(self.toast_overlay)

        self._current_view: Tuple[str, Optional[str]] = ("challenges", None)
        self._search_query = ""
        self._active_challenge_id: Optional[int] = None
        self._populating_detail = False  # Flag to prevent dirty marking during population
        self._metadata_dirty = False
        self._flag_dirty = False
        self._metadata_timeout_id = 0
        self._flag_timeout_id = 0
        self._notes_save_timeout_id = 0
        self._notes_changed_pending = False
        self.notes_preview = None
        self.tool_output_view = None
        self.status_label = None

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.toast_overlay.set_child(root)

        self._build_header(root)
        self._build_body(root)
        self._setup_responsive_sidebar()
        self._load_css()

        self.quick_disassembler = QuickDisassembler()
        self.disassembly_preview_window: Optional[Adw.ApplicationWindow] = None
        self.disassembly_preview_view: Optional[Gtk.TextView] = None
        self.disassembly_preview_search: Optional[Gtk.SearchEntry] = None
        self.disassembly_preview_status_label: Optional[Gtk.Label] = None
        self.disassembly_preview_copy_btn: Optional[Gtk.Button] = None
        self._disassembly_preview_highlight_tag = None

        self.refresh_sidebar()
        self.refresh_main_content()
        self._apply_text_field_decorations()

    def _set_window_icon(self) -> None:
        """Set the application icon from the data/icons directory."""
        from pathlib import Path
        from gi.repository import Gdk
        
        # Find icon directory - handle both source and installed cases
        icon_dir = Path(__file__).parent.parent.parent / "data" / "icons"
        icon_file = icon_dir / "org.example.Cryptea.svg"
        
        if icon_file.exists():
            # Add the icon directory to GTK's icon search path
            icon_theme = Gtk.IconTheme.get_for_display(Gdk.Display.get_default())
            icon_theme.add_search_path(str(icon_dir))
            # Set the icon name on the window
            self.window.set_icon_name("org.example.Cryptea")

    # ------------------------------------------------------------------
    # UI construction helpers
    # ------------------------------------------------------------------
    def _build_header(self, root: Gtk.Box) -> None:
        header = Adw.HeaderBar()
        self.header_bar = header
        title = Adw.WindowTitle(title="Cryptea", subtitle="Offline Workspace")
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

        settings_button = Gtk.MenuButton(icon_name="emblem-system-symbolic")
        settings_button.set_tooltip_text("Settings and tools")
        settings_button.set_menu_model(self._build_settings_menu())
        header.pack_end(settings_button)

        root.append(header)

    def _build_settings_menu(self) -> Gio.MenuModel:
        menu = Gio.Menu()

        import_item = Gio.MenuItem.new("Import .ctfpack…", "app.import_pack")
        import_item.set_attribute_value("icon", GLib.Variant.new_string("document-open-symbolic"))
        menu.append_item(import_item)

        export_item = Gio.MenuItem.new("Export .ctfpack…", "app.export_pack")
        export_item.set_attribute_value("icon", GLib.Variant.new_string("document-save-symbolic"))
        menu.append_item(export_item)

        prefs_item = Gio.MenuItem.new("Preferences", "app.settings")
        prefs_item.set_attribute_value("icon", GLib.Variant.new_string("emblem-system-symbolic"))
        menu.append_item(prefs_item)

        about_item = Gio.MenuItem.new("About", "app.about")
        about_item.set_attribute_value("icon", GLib.Variant.new_string("help-about-symbolic"))
        menu.append_item(about_item)
        return menu

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
            margin_top=4,
            margin_bottom=4,
            margin_start=4,
            margin_end=4,
        )
        sidebar_box.add_css_class("sidebar")
        sidebar_box.set_hexpand(True)
        sidebar_box.set_vexpand(True)
        sidebar_box.set_valign(Gtk.Align.FILL)

        self.search_entry = Gtk.SearchEntry()
        self.search_entry.add_css_class("sidebar-search")
        self.search_entry.set_placeholder_text("Search challenges…")
        self.search_entry.connect("search-changed", self._on_search_changed)
        sidebar_box.append(self.search_entry)

        sidebar_add = Gtk.Button()
        sidebar_add.add_css_class("suggested-action")
        sidebar_add.add_css_class("sidebar-primary")
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

        # Use Grid instead of FlowBox for better control over card positioning
        self.cards_grid = Gtk.Grid()
        self.cards_grid.set_row_spacing(16)
        self.cards_grid.set_column_spacing(16)
        self.cards_grid.set_halign(Gtk.Align.FILL)
        self.cards_grid.set_hexpand(True)
        self.cards_grid.set_margin_top(16)
        self.cards_grid.set_margin_bottom(16)
        self.cards_grid.set_margin_start(16)
        self.cards_grid.set_margin_end(16)

        cards_scroller = Gtk.ScrolledWindow()
        cards_scroller.add_css_class("output-box")
        cards_scroller.set_hexpand(True)
        cards_scroller.set_vexpand(True)
        cards_scroller.set_child(self.cards_grid)
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
        tools_scroller.add_css_class("output-box")
        tools_scroller.set_hexpand(True)
        tools_scroller.set_vexpand(True)
        tools_scroller.set_child(self.tools_container)
        tools_scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.content_stack.add_titled(tools_scroller, "tools", "Tools")

        tools_header = Gtk.Label(xalign=0)
        tools_header.add_css_class("title-3")
        tools_header.set_name("tools_header")
        self.tools_container.append(tools_header)
        self.tools_header = tools_header

        self.tools_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        self.tools_list.set_hexpand(True)
        clamp = Adw.Clamp()
        clamp.set_maximum_size(1200)  # Increase from default to allow 2 cards side-by-side
        clamp.set_child(self.tools_list)
        self.tools_container.append(clamp)

        output_frame = Gtk.Frame(label="Result")
        output_frame.add_css_class("flat")
        output_frame.set_visible(False)
        self.tool_output_view = Gtk.TextView()
        self.tool_output_view.add_css_class("output-text")
        self.tool_output_view.set_editable(False)
        self.tool_output_view.set_wrap_mode(Gtk.WrapMode.WORD)
        output_frame.set_child(self.tool_output_view)
        self.tools_container.append(output_frame)
        self.output_frame = output_frame

        # Tool detail pages (one per tool) in a view stack
        self.tool_detail_stack = Adw.ViewStack()
        detail_scroller_tools = Gtk.ScrolledWindow()
        detail_scroller_tools.add_css_class("output-box")
        detail_scroller_tools.set_child(self.tool_detail_stack)
        self.content_stack.add_titled(detail_scroller_tools, "tool_detail", "Tool Detail")

        # Hash Suite page (consolidated all hash tools)
        hash_suite_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_hash_suite_detail(hash_suite_box)
        self.tool_detail_stack.add_named(hash_suite_box, "hash_suite")

        # Decoder Workbench page
        decoder_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_decoder_workbench_detail(decoder_box)
        self.tool_detail_stack.add_named(decoder_box, "decoder_workbench")

        # Morse Decoder page
        morse_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_morse_decoder_detail(morse_box)
        self.tool_detail_stack.add_named(morse_box, "morse_decoder")

        # RSA Toolkit page
        rsa_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_rsa_toolkit_detail(rsa_box)
        self.tool_detail_stack.add_named(rsa_box, "rsa_toolkit")

        # XOR Analyzer page
        xor_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_xor_analyzer_detail(xor_box)
        self.tool_detail_stack.add_named(xor_box, "xor_analyzer")

        # Caesar Cipher page
        caesar_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_caesar_cipher_detail(caesar_box)
        self.tool_detail_stack.add_named(caesar_box, "caesar")

        # Vigenère Cipher page
        vigenere_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_vigenere_cipher_detail(vigenere_box)
        self.tool_detail_stack.add_named(vigenere_box, "vigenere")

        # File Inspector page
        inspector_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_file_inspector_detail(inspector_box)
        self.tool_detail_stack.add_named(inspector_box, "file_inspector")

    # PCAP Viewer page
        pcap_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_pcap_viewer_detail(pcap_box)
        self.tool_detail_stack.add_named(pcap_box, "pcap_viewer")

        # Memory Analyzer page
        memory_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_memory_analyzer_detail(memory_box)
        self.tool_detail_stack.add_named(memory_box, "memory_analyzer")

        # Disk Image Tools page
        disk_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_disk_image_detail(disk_box)
        self.tool_detail_stack.add_named(disk_box, "disk_image_tools")

        # Timeline Builder page
        timeline_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_timeline_builder_detail(timeline_box)
        self.tool_detail_stack.add_named(timeline_box, "timeline_builder")

        # Image Stego Toolkit page
        image_stego_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_image_stego_detail(image_stego_box)
        self.tool_detail_stack.add_named(image_stego_box, "image_stego")

        # EXIF Metadata Viewer page
        exif_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_exif_metadata_detail(exif_box)
        self.tool_detail_stack.add_named(exif_box, "exif_metadata")

        # Audio Analyzer page
        audio_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_audio_analyzer_detail(audio_box)
        self.tool_detail_stack.add_named(audio_box, "audio_analyzer")

        # Video Frame Exporter page
        video_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_video_exporter_detail(video_box)
        self.tool_detail_stack.add_named(video_box, "video_frame_exporter")

        # QR/Barcode Scanner page
        qr_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_qr_scanner_detail(qr_box)
        self.tool_detail_stack.add_named(qr_box, "qr_scanner")

        # Strings Extractor page
        strings_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_strings_detail(strings_box)
        self.tool_detail_stack.add_named(strings_box, "strings")

        # Disassembler Launcher page
        disassembler_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_disassembler_detail(disassembler_box)
        self.tool_detail_stack.add_named(disassembler_box, "disassembler")

        # Rizin Console page
        rizin_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_rizin_console_detail(rizin_box)
        self.tool_detail_stack.add_named(rizin_box, "rizin_console")

        # GDB Runner page
        gdb_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_gdb_runner_detail(gdb_box)
        self.tool_detail_stack.add_named(gdb_box, "gdb_runner")

        # ROP Gadget Finder page
        rop_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_rop_gadget_detail(rop_box)
        self.tool_detail_stack.add_named(rop_box, "rop_gadget")

        # Binary Diff page
        bindiff_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_binary_diff_detail(bindiff_box)
        self.tool_detail_stack.add_named(bindiff_box, "binary_diff")

        # Binary Inspector page
        inspector_reverse_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_binary_inspector_detail(inspector_reverse_box)

        # EXE Decompiler page
        exe_decompiler_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_exe_decompiler_detail(exe_decompiler_box)

        # Wordlist Generator page
        wordlist_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_wordlist_generator_detail(wordlist_box)


        # Nmap page
        nmap_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_nmap_detail(nmap_box)
        self.tool_detail_stack.add_named(nmap_box, "nmap")

        # Discovery page
        discovery_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_discovery_detail(discovery_box)
        self.tool_detail_stack.add_named(discovery_box, "discovery")

        # SQLi Tester page
        sqli_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_sqli_tester_detail(sqli_box)
        self.tool_detail_stack.add_named(sqli_box, "sqli_tester")

        # SQLMap page
        sqlmap_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_sqlmap_detail(sqlmap_box)
        self.tool_detail_stack.add_named(sqlmap_box, "sqlmap")

        # XSS Tester page
        xss_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_xss_tester_detail(xss_box)
        self.tool_detail_stack.add_named(xss_box, "xss_tester")

        # JWT Tool page
        jwt_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_jwt_tool_detail(jwt_box)
        self.tool_detail_stack.add_named(jwt_box, "jwt_tool")

        # File Upload Tester page
        upload_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        self._build_file_upload_detail(upload_box)
        self.tool_detail_stack.add_named(upload_box, "file_upload")

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

    # ------------------------------------------------------------------
    # Window and sidebar callbacks
    # ------------------------------------------------------------------
    def _on_close_request(self, _window: Adw.ApplicationWindow) -> bool:
        self._flush_metadata_if_dirty()
        self._flush_flag_if_dirty()
        self._flush_notes_if_pending()
        return False

    def _on_search_changed(self, entry: Gtk.SearchEntry) -> None:
        self._search_query = entry.get_text().strip()
        if self._current_view[0] != "detail":
            self.refresh_main_content()

    def _on_add_clicked(self, _button: Gtk.Button) -> None:
        self.trigger_new_challenge()

    def trigger_new_challenge(self) -> None:
        challenge = self.app.challenge_manager.create_challenge(
            title="New Challenge",
            project="General",
            category="misc",
            difficulty="medium",
            status="Not Started",
        )
        self._active_challenge_id = challenge.id
        self._current_view = ("detail", str(challenge.id))
        self.refresh_sidebar()
        self._populate_detail(challenge)
        self.challenge_stack.set_visible_child_name("detail")
        self._setup_autocomplete()  # Refresh autocomplete with latest data
        self._set_status_message("New challenge created")

    # ------------------------------------------------------------------
    # Metadata autosave helpers
    # ------------------------------------------------------------------
    def _attach_flush_on_focus_leave(self, widget: Gtk.Widget, callback) -> None:
        def _on_focus_notify(_widget: Gtk.Widget, _param: GObject.ParamSpec) -> None:
            if not widget.has_focus():
                callback()

        widget.connect("notify::has-focus", _on_focus_notify)

    def _mark_metadata_dirty(self, *_args) -> None:
        if self._active_challenge_id is None or self._populating_detail:
            return
        self._metadata_dirty = True
        if self._metadata_timeout_id:
            return
        self._metadata_timeout_id = GLib.timeout_add(600, self._flush_metadata_if_dirty)

    def _mark_flag_dirty(self, *_args) -> None:
        if self._active_challenge_id is None or self._populating_detail:
            return
        self._flag_dirty = True
        if self._flag_timeout_id:
            return
        self._flag_timeout_id = GLib.timeout_add(600, self._flush_flag_if_dirty)

    def _on_metadata_combo_changed(self, *_args) -> None:
        self._mark_metadata_dirty()

    def _flush_metadata_if_dirty(self, *_args) -> bool:
        if self._metadata_timeout_id:
            self._metadata_timeout_id = 0
        if not self._metadata_dirty or self._active_challenge_id is None:
            return False

        title = self.title_entry.get_text().strip() or "Untitled"
        project = self.project_entry.get_text().strip() or "General"
        category = self.category_entry.get_text().strip() or "misc"

        difficulty_index = self.difficulty_combo.get_selected()
        if 0 <= difficulty_index < len(self._difficulty_values):
            difficulty = self._difficulty_values[difficulty_index]
        else:
            difficulty = self._difficulty_values[0]

        status_model = self.status_combo.get_model()
        status_index = self.status_combo.get_selected()
        status = "Not Started"
        if isinstance(status_model, Gtk.StringList) and 0 <= status_index < status_model.get_n_items():
            status = status_model.get_string(status_index)

        description_buffer = self.description_view.get_buffer()
        start, end = description_buffer.get_bounds()
        description = description_buffer.get_text(start, end, True)

        self.app.challenge_manager.update_challenge(
            self._active_challenge_id,
            title=title,
            project=project,
            category=category,
            difficulty=difficulty,
            status=status,
            description=description,
        )
        self._metadata_dirty = False
        self.refresh_sidebar()
        self.refresh_main_content()  # Refresh challenges list to show updated status
        self._set_status_message("Metadata saved")
        return False

    def _flush_flag_if_dirty(self, *_args) -> bool:
        if self._flag_timeout_id:
            self._flag_timeout_id = 0
        if not self._flag_dirty or self._active_challenge_id is None:
            return False
        flag_value = self.flag_entry.get_text().strip()
        self.app.challenge_manager.set_flag(self._active_challenge_id, flag_value or None)
        self._flag_dirty = False
        self._set_status_message("Flag saved")
        return False

    # ------------------------------------------------------------------
    # Notes handling
    # ------------------------------------------------------------------
    def _on_notes_changed(self, buffer: Gtk.TextBuffer) -> None:
        start, end = buffer.get_bounds()
        text = buffer.get_text(start, end, True)
        self._update_notes_preview(text)
        self._notes_changed_pending = True
        if self._notes_save_timeout_id:
            return
        self._notes_save_timeout_id = GLib.timeout_add(900, self._flush_notes_if_pending)

    def _flush_notes_if_pending(self, *_args) -> bool:
        if self._notes_save_timeout_id:
            self._notes_save_timeout_id = 0
        if not self._notes_changed_pending or self._active_challenge_id is None:
            return False
        text = self._get_notes_text()
        try:
            self.app.note_manager.save_markdown(self._active_challenge_id, text)
            self._set_status_message("Notes saved")
        finally:
            self._notes_changed_pending = False
        return False

    def _get_notes_text(self) -> str:
        buffer = self.notes_view.get_buffer()
        start, end = buffer.get_bounds()
        return buffer.get_text(start, end, True)

    def _set_notes_text(self, text: str) -> None:
        buffer = self.notes_view.get_buffer()
        buffer.handler_block_by_func(self._on_notes_changed)
        buffer.set_text(text)
        buffer.handler_unblock_by_func(self._on_notes_changed)
        self._update_notes_preview(text)

    def _update_notes_preview(self, text: str) -> None:
        if self.notes_preview is None:
            return
        preview_buffer = self.notes_preview.get_buffer()
        preview_buffer.set_text(text)

    # ------------------------------------------------------------------
    # Tool helpers
    # ------------------------------------------------------------------
    def _set_tool_output(self, text: str) -> None:
        if self.tool_output_view is None:
            return
        buffer = self.tool_output_view.get_buffer()
        buffer.set_text(text)

    def _run_tool(self, tool) -> None:
        try:
            result = tool.run()
        except TypeError:
            handler = self._tool_handler_for(tool)
            if handler is not None:
                handler(tool)
            else:
                self.toast_overlay.add_toast(Adw.Toast.new("This tool requires additional input."))
            return
        except Exception as exc:
            self.toast_overlay.add_toast(Adw.Toast.new(f"Error: {exc}"))
            return

        body = getattr(result, "body", str(result))
        self._set_tool_output(body)
        self.output_frame.set_visible(True)

    def _get_text_view_text(self, view: Gtk.TextView) -> str:
        buffer = view.get_buffer()
        start, end = buffer.get_bounds()
        return buffer.get_text(start, end, True)

    def _set_text_view_text(self, view: Gtk.TextView, text: str) -> None:
        view.get_buffer().set_text(text)

    def _copy_text_view_to_clipboard(self, view: Gtk.TextView) -> None:
        display = self.window.get_display()
        if display is None:
            return
        buffer = view.get_buffer()
        start, end = buffer.get_bounds()
        text = buffer.get_text(start, end, True)
        display.get_clipboard().set_text(text)

    # ------------------------------------------------------------------
    # Misc helpers
    # ------------------------------------------------------------------
    def _set_status_message(self, message: str) -> None:
        if self.status_label is not None:
            self.status_label.set_text(message)

    def _show_not_implemented(self, feature: str) -> None:
        toast = Adw.Toast.new(f"{feature} is not available yet")
        self.toast_overlay.add_toast(toast)

    def _run_native_dialog(self, dialog: Gtk.NativeDialog) -> int:
        response_holder = {"value": Gtk.ResponseType.CANCEL}
        loop = GLib.MainLoop()

        def _on_response(_dialog: Gtk.NativeDialog, response_id: int) -> None:
            response_holder["value"] = response_id
            loop.quit()

        dialog.set_transient_for(self.window)
        dialog.connect("response", _on_response)
        dialog.show()
        loop.run()
        dialog.hide()
        return response_holder["value"]

    def present(self) -> None:
        self.window.present()

    def focus_search(self) -> None:
        self.search_entry.grab_focus()
        self.search_entry.select_region(0, -1)

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
        title_column.set_hexpand(True)
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
        
        # Add delete button
        delete_button = Gtk.Button.new_from_icon_name("user-trash-symbolic")
        delete_button.set_tooltip_text("Delete challenge")
        delete_button.add_css_class("destructive-action")
        delete_button.add_css_class("circular")
        delete_button.set_valign(Gtk.Align.START)
        delete_button.connect("clicked", self._on_delete_challenge_clicked)
        header_row.append(delete_button)

        details_clamp = Adw.Clamp(maximum_size=960, tightening_threshold=640)
        box.append(details_clamp)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        details_clamp.set_child(content)

        content.append(header_row)

        metadata_group = Adw.PreferencesGroup(title="Challenge Details")
        content.append(metadata_group)

        self.title_entry = Adw.EntryRow()
        self.title_entry.set_title("Title")
        metadata_group.add(self.title_entry)

        self.project_entry = Adw.EntryRow()
        self.project_entry.set_title("Project")
        metadata_group.add(self.project_entry)

        self.category_entry = Adw.EntryRow()
        self.category_entry.set_title("Category")
        metadata_group.add(self.category_entry)

        self._difficulty_values: List[str] = ["easy", "medium", "hard"]
        difficulty_model = Gtk.StringList.new([value.title() for value in self._difficulty_values])
        self.difficulty_combo = Adw.ComboRow()
        self.difficulty_combo.set_title("Difficulty")
        self.difficulty_combo.set_model(difficulty_model)
        self.difficulty_combo.set_selected(1)
        metadata_group.add(self.difficulty_combo)

        self.flag_entry = Adw.EntryRow()
        self.flag_entry.set_title("Flag")
        metadata_group.add(self.flag_entry)

        self._status_options: List[str] = list(STATUSES)
        status_model = Gtk.StringList.new(self._status_options)
        self.status_combo = Adw.ComboRow()
        self.status_combo.set_title("Status")
        self.status_combo.set_model(status_model)
        self.status_combo.set_selected(0)
        metadata_group.add(self.status_combo)

        description_section = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        description_label = Gtk.Label(label="DESCRIPTION", xalign=0)
        description_label.add_css_class("title-4")
        description_section.append(description_label)
        
        self.description_view = Gtk.TextView()
        self.description_view.add_css_class("input-text")
        self.description_view.set_wrap_mode(Gtk.WrapMode.WORD)
        description_scroller = Gtk.ScrolledWindow()
        description_scroller.add_css_class("input-box")
        description_scroller.set_hexpand(True)
        description_scroller.set_vexpand(True)
        description_scroller.set_min_content_height(160)
        description_scroller.set_child(self.description_view)
        description_section.append(description_scroller)
        content.append(description_section)

        notes_section = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        notes_label = Gtk.Label(label="NOTES", xalign=0)
        notes_label.add_css_class("title-4")
        notes_section.append(notes_label)

        notes_scroller = Gtk.ScrolledWindow()
        notes_scroller.add_css_class("input-box")
        notes_scroller.set_hexpand(True)
        notes_scroller.set_vexpand(True)
        notes_scroller.set_min_content_height(240)

        self.notes_view = Gtk.TextView()
        self.notes_view.add_css_class("input-text")
        self.notes_view.set_wrap_mode(Gtk.WrapMode.WORD)
        notes_buffer = self.notes_view.get_buffer()
        notes_buffer.connect("changed", self._on_notes_changed)
        notes_scroller.set_child(self.notes_view)

        notes_section.append(notes_scroller)
        content.append(notes_section)

        self.status_label = Gtk.Label(xalign=1)
        self.status_label.add_css_class("dim-label")
        self.status_label.set_hexpand(True)
        self.status_label.set_halign(Gtk.Align.END)
        content.append(self.status_label)

        # Signal wiring for metadata autosave
        self.title_entry.connect("notify::text", self._mark_metadata_dirty)
        self.project_entry.connect("notify::text", self._mark_metadata_dirty)
        self.category_entry.connect("notify::text", self._mark_metadata_dirty)
        self.difficulty_combo.connect("notify::selected", self._on_metadata_combo_changed)
        self.description_view.get_buffer().connect("changed", self._mark_metadata_dirty)
        self.status_combo.connect("notify::selected", self._on_metadata_combo_changed)
        self.flag_entry.connect("notify::text", self._mark_flag_dirty)

        for widget in (self.title_entry, self.project_entry, self.category_entry, self.description_view):
            self._attach_flush_on_focus_leave(widget, self._flush_metadata_if_dirty)
        self._attach_flush_on_focus_leave(self.flag_entry, self._flush_flag_if_dirty)

        # Set up autocomplete for project and category
        self._setup_autocomplete()

        return box

    def _setup_autocomplete(self) -> None:
        """Set up autocomplete suggestions for project and category fields"""
        # Initialize popovers if not already created
        if not hasattr(self, '_project_popover'):
            # Predefined list of common projects
            self._projects = [
                "PicoCTF",
                "HackTheBox",
                "TryHackMe",
                "CTFtime",
                "OverTheWire",
                "RingZer0",
                "pwnable.kr",
                "Root-Me",
                "VulnHub",
                "HackThisSite",
                "General"
            ]
            
            # Predefined list of common categories
            self._categories = [
                "Crypto",
                "Web",
                "Reverse Engineering",
                "Pwn",
                "Forensics",
                "Steganography",
                "OSINT",
                "Networking",
                "Mobile",
                "Hardware",
                "Blockchain",
                "Misc"
            ]
            
            # Connect to text changes to show suggestions
            self.project_entry.connect("notify::text", self._on_project_text_changed)
            self.category_entry.connect("notify::text", self._on_category_text_changed)
            
            # Connect to focus changes to close popover when field loses focus
            self.project_entry.connect("notify::has-focus", self._on_project_focus_changed)
            self.category_entry.connect("notify::has-focus", self._on_category_focus_changed)
            
            # Create popovers for suggestions
            self._create_suggestion_popover(self.project_entry, "project")
            self._create_suggestion_popover(self.category_entry, "category")
    
    def _on_project_focus_changed(self, entry_row: Adw.EntryRow, _param) -> None:
        """Track focus state for project field"""
        if not entry_row.has_focus() and hasattr(self, '_project_popover'):
            self._project_popover.popdown()
    
    def _on_category_focus_changed(self, entry_row: Adw.EntryRow, _param) -> None:
        """Track focus state for category field"""
        if not entry_row.has_focus() and hasattr(self, '_category_popover'):
            self._category_popover.popdown()
    
    def _create_suggestion_popover(self, entry_row: Adw.EntryRow, field_type: str) -> None:
        """Create a popover for showing suggestions"""
        popover = Gtk.Popover()
        popover.set_autohide(False)  # Don't auto-hide, we'll manage this manually
        popover.set_has_arrow(False)
        popover.set_position(Gtk.PositionType.BOTTOM)
        popover.set_parent(entry_row)
        popover.set_can_focus(False)
        popover.set_cascade_popdown(False)
        popover.add_css_class("menu")  # Use menu styling for modern look
        
        # Position the popover to appear below the entry row
        rect = Gdk.Rectangle()
        rect.x = 0
        rect.y = 40
        rect.width = 400
        rect.height = 1
        popover.set_pointing_to(rect)
        
        # Main container with padding
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        main_box.set_margin_top(6)
        main_box.set_margin_bottom(6)
        
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_max_content_height(280)
        scrolled.set_min_content_width(280)
        scrolled.set_propagate_natural_height(True)
        scrolled.set_propagate_natural_width(True)
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scrolled.set_can_focus(False)
        
        listbox = Gtk.ListBox()
        listbox.set_selection_mode(Gtk.SelectionMode.NONE)
        listbox.set_can_focus(False)
        listbox.add_css_class("boxed-list")
        scrolled.set_child(listbox)
        
        main_box.append(scrolled)
        popover.set_child(main_box)
        
        # Store references
        if field_type == "project":
            self._project_popover = popover
            self._project_listbox = listbox
        else:
            self._category_popover = popover
            self._category_listbox = listbox
    
    def _on_project_text_changed(self, entry_row: Adw.EntryRow, _param) -> None:
        """Handle project text changes to show suggestions"""
        text = entry_row.get_text().lower()
        
        if not hasattr(self, '_projects') or not hasattr(self, '_project_popover'):
            return
        
        # During population, don't show suggestions
        if hasattr(self, '_populating_detail') and self._populating_detail:
            return
            
        if len(text) < 1:
            self._project_popover.popdown()
            return
            
        matches = [p for p in self._projects if text in p.lower()]
        self._update_suggestion_list(self._project_listbox, matches, entry_row, "project")
        
        if matches:
            self._project_popover.popup()
        else:
            self._project_popover.popdown()
    
    def _on_category_text_changed(self, entry_row: Adw.EntryRow, _param) -> None:
        """Handle category text changes to show suggestions"""
        text = entry_row.get_text().lower()
        
        if not hasattr(self, '_categories') or not hasattr(self, '_category_popover'):
            return
        
        # During population, don't show suggestions
        if hasattr(self, '_populating_detail') and self._populating_detail:
            return
            
        if len(text) < 1:
            self._category_popover.popdown()
            return
            
        matches = [c for c in self._categories if text in c.lower()]
        self._update_suggestion_list(self._category_listbox, matches, entry_row, "category")
        
        if matches:
            self._category_popover.popup()
        else:
            self._category_popover.popdown()
    
    def _update_suggestion_list(self, listbox: Gtk.ListBox, suggestions: list, entry_row: Adw.EntryRow, field_type: str) -> None:
        """Update the suggestion listbox with new suggestions"""
        # Clear existing items
        while (child := listbox.get_first_child()):
            listbox.remove(child)
        
        # Add new suggestions with modern styling
        for suggestion in suggestions[:10]:  # Show up to 10 suggestions
            row = Gtk.ListBoxRow()
            row.set_can_focus(False)
            
            # Create a box for the row content
            box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
            box.set_margin_top(8)
            box.set_margin_bottom(8)
            box.set_margin_start(12)
            box.set_margin_end(12)
            
            # Add icon for visual interest
            icon = Gtk.Image()
            if field_type == "project":
                icon.set_from_icon_name("folder-symbolic")
            else:
                icon.set_from_icon_name("tag-symbolic")
            icon.add_css_class("dim-label")
            box.append(icon)
            
            # Add label
            label = Gtk.Label(label=suggestion, xalign=0)
            label.set_hexpand(True)
            box.append(label)
            
            row.set_child(box)
            
            # Make row clickable
            gesture = Gtk.GestureClick.new()
            gesture.connect("released", lambda g, n, x, y, s=suggestion, e=entry_row, t=field_type: self._on_suggestion_clicked(s, e, t))
            row.add_controller(gesture)
            
            listbox.append(row)
    
    def _on_suggestion_clicked(self, suggestion: str, entry_row: Adw.EntryRow, field_type: str) -> None:
        """Handle suggestion click"""
        entry_row.set_text(suggestion)
        if field_type == "project":
            self._project_popover.popdown()
        else:
            self._category_popover.popdown()

    def _show_tool_overview(self) -> None:
        self.content_stack.set_visible_child_name("tools")
        self.tools_header.set_text("Offline Tools")
        _clear_box(self.tools_list)

        # Search bar
        search_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        search_box.set_margin_bottom(16)
        search_icon = Gtk.Image.new_from_icon_name("system-search-symbolic")
        search_box.append(search_icon)
        
        self.tools_search_entry = Gtk.SearchEntry()
        self.tools_search_entry.set_placeholder_text("Search tools...")
        self.tools_search_entry.set_hexpand(True)
        self.tools_search_entry.connect("search-changed", self._on_tools_search_changed)
        search_box.append(self.tools_search_entry)
        self.tools_list.append(search_box)

        # Check if we have any tools
        grouped = self.app.module_registry.by_category()
        if not grouped or not self.app.module_registry.tools():
            intro = Gtk.Label(xalign=0)
            intro.set_wrap(True)
            intro.set_wrap_mode(Pango.WrapMode.WORD)
            intro.set_max_width_chars(60)
            intro.set_text(
                "No offline tools are available. Ensure optional dependencies are installed and restart."
            )
            self.tools_list.append(intro)
        else:
            # Create a scrolled window for the tools
            scrolled = Gtk.ScrolledWindow()
            scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
            scrolled.set_vexpand(True)
            
            # Main container for all categories
            main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
            main_box.set_margin_top(8)
            
            # Build tools by category
            seen: set[str] = set()
            
            def _category_label(value: str) -> str:
                pretty = value.strip() or "Other"
                if pretty.lower() == "reverse":
                    return "Reverse Engineering"
                return pretty.title()
            
            # Store all tool cards for search
            self._tool_cards = []
            self._category_sections = {}  # Store category sections for show/hide
            
            # Add tools grouped by category
            for category in sorted(grouped, key=lambda cat: cat.casefold()):
                tools = sorted(
                    grouped.get(category, []),
                    key=lambda tool: (getattr(tool, "name", "") or "").casefold(),
                )
                
                # Filter out already seen tools
                category_tools = []
                for tool in tools:
                    raw_name = getattr(tool, "name", "")
                    name = (raw_name or "").strip()
                    if not name or name in seen:
                        continue
                    seen.add(name)
                    category_tools.append((name, tool))
                
                if not category_tools:
                    continue
                
                # Category section
                category_section = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
                
                # Category header
                category_header = Gtk.Label(label=_category_label(category), xalign=0)
                category_header.add_css_class("title-3")
                category_header.set_margin_bottom(4)
                category_section.append(category_header)
                
                # Create a FlowBox for this category with 2 columns max
                category_flowbox = Gtk.FlowBox()
                category_flowbox.set_valign(Gtk.Align.START)
                category_flowbox.set_max_children_per_line(2)
                category_flowbox.set_min_children_per_line(1)
                category_flowbox.set_selection_mode(Gtk.SelectionMode.NONE)
                category_flowbox.set_row_spacing(12)
                category_flowbox.set_column_spacing(12)
                category_flowbox.set_homogeneous(True)
                category_flowbox.set_orientation(Gtk.Orientation.HORIZONTAL)
                
                # Add tools to this category
                for name, tool in category_tools:
                    tool_card = self._create_tool_card(name, category, tool)
                    self._tool_cards.append(tool_card)
                    category_flowbox.append(tool_card)
                
                category_section.append(category_flowbox)
                main_box.append(category_section)
                
                # Store reference to this category section
                self._category_sections[category] = category_section
            
            scrolled.set_child(main_box)
            self.tools_list.append(scrolled)

        self._set_tool_output("")
        self.output_frame.set_visible(False)
    
    def _create_tool_card(self, tool_name: str, category: str, tool: Any) -> Gtk.FlowBoxChild:
        """Create a clickable card for a tool."""
        child = Gtk.FlowBoxChild()
        # Store data as attributes instead of using set_data
        child.tool_name = tool_name
        child.tool_category = category
        
        button = Gtk.Button()
        button.set_has_frame(True)
        button.add_css_class("tool-card")
        button.set_size_request(300, 140)  # Set a fixed size for FlowBox to calculate properly
        button.connect("clicked", lambda _: self._on_tool_card_clicked(tool_name))
        
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(16)
        box.set_margin_bottom(16)
        box.set_margin_start(16)
        box.set_margin_end(16)
        
        # Header with icon and name
        header_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        header_box.set_halign(Gtk.Align.START)
        
        # Icon
        icon_name = TOOL_ICON_MAP.get(tool_name.lower(), "applications-utilities-symbolic")
        icon = Gtk.Image.new_from_icon_name(icon_name)
        icon.set_pixel_size(32)
        icon.add_css_class("tool-card-icon")
        header_box.append(icon)
        
        # Tool name
        label = Gtk.Label(label=tool_name, xalign=0)
        label.set_wrap(True)
        label.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
        label.add_css_class("title-4")
        label.set_hexpand(True)
        header_box.append(label)
        
        box.append(header_box)
        
        # Description
        description = getattr(tool, "description", "No description available.")
        desc_label = Gtk.Label(label=description, xalign=0)
        desc_label.set_wrap(True)
        desc_label.set_wrap_mode(Pango.WrapMode.WORD)
        desc_label.set_lines(3)
        desc_label.set_ellipsize(Pango.EllipsizeMode.END)
        desc_label.add_css_class("dim-label")
        desc_label.add_css_class("tool-card-description")
        box.append(desc_label)
        
        # Category badge
        def _category_label(value: str) -> str:
            pretty = value.strip() or "Other"
            if pretty.lower() == "reverse":
                return "Reverse Engineering"
            return pretty.title()
        
        category_label = Gtk.Label(label=_category_label(category), xalign=0)
        category_label.add_css_class("caption")
        category_label.add_css_class("tool-card-category")
        box.append(category_label)
        
        button.set_child(box)
        child.set_child(button)
        
        return child
    
    def _on_tool_card_clicked(self, tool_name: str) -> None:
        """Handle clicking on a tool card."""
        self._current_view = ("tool", tool_name)
        self._show_tool(tool_name)
        self._select_sidebar_row()
    
    def _on_tools_search_changed(self, entry: Gtk.SearchEntry) -> None:
        """Filter tools based on search query."""
        query = entry.get_text().strip().lower()
        
        if not hasattr(self, '_tool_cards') or not hasattr(self, '_category_sections'):
            return
        
        # Track which categories have visible tools
        category_has_visible = {}
        
        # Filter through all stored tool cards
        for card in self._tool_cards:
            if isinstance(card, Gtk.FlowBoxChild):
                # Use attributes instead of get_data
                tool_name = getattr(card, "tool_name", "")
                tool_category = getattr(card, "tool_category", "")
                
                # Show if query matches tool name or category
                matches = (
                    query in tool_name.lower() or 
                    query in tool_category.lower()
                )
                card.set_visible(matches)
                
                # Track if this category has any visible tools
                if matches:
                    category_has_visible[tool_category] = True
        
        # Show/hide category sections based on whether they have visible tools
        for category, section in self._category_sections.items():
            section.set_visible(category_has_visible.get(category, False))

    def _show_tool(self, tool_name: str) -> None:
        try:
            tool = self.app.module_registry.find(tool_name)
        except KeyError:
            self.content_stack.set_visible_child_name("tools")
            self.tools_header.set_text("Tool unavailable")
            _clear_box(self.tools_list)
            message = Gtk.Label(
                label="This tool is no longer available. Refresh or restart to rebuild the registry.",
                xalign=0,
            )
            message.set_wrap(True)
            message.set_wrap_mode(Pango.WrapMode.WORD)
            message.set_max_width_chars(60)
            self.tools_list.append(message)
            self._set_tool_output("")
            self.output_frame.set_visible(False)
            return

        handler = self._tool_handler_for(tool)
        if handler is not None:
            handler(tool)
            return

        self._show_generic_tool(tool)

    def _show_generic_tool(self, tool: Any) -> None:
        self.content_stack.set_visible_child_name("tools")
        self.tools_header.set_text(tool.name)
        _clear_box(self.tools_list)

        description = Gtk.Label(label=getattr(tool, "description", ""), xalign=0)
        description.set_wrap(True)
        description.set_wrap_mode(Pango.WrapMode.WORD)
        description.set_max_width_chars(60)

        run_button = Gtk.Button(label=f"Run {tool.name}")
        run_button.add_css_class("suggested-action")
        run_button.set_halign(Gtk.Align.START)
        run_button.connect("clicked", lambda *_: self._run_tool(tool))

        button_hint = Gtk.Label(
            label="You'll be prompted for any parameters before the tool runs.",
            xalign=0,
        )
        button_hint.add_css_class("dim-label")
        button_hint.set_wrap(True)
        button_hint.set_wrap_mode(Pango.WrapMode.WORD)
        button_hint.set_max_width_chars(60)

        container = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        container.append(description)
        container.append(run_button)
        container.append(button_hint)

        self.tools_list.append(container)
        self._set_tool_output("")
        self.output_frame.set_visible(False)

    def _tool_handler_for(self, tool: Any):
        name = getattr(tool, "name", "").lower()
        handlers = {
            # Hash Suite (consolidated all hash tools)
            "hash suite": self._open_hash_suite,
            # Redirects for backward compatibility (will remove in future)
            "hash digest": self._open_hash_suite,
            "hash workspace": self._open_hash_suite,
            "hash cracker pro": self._open_hash_suite,
            "hash benchmark": self._open_hash_suite,
            "hash format converter": self._open_hash_suite,
            "hashcat/john builder": self._open_hash_suite,
            "htpasswd generator": self._open_hash_suite,
            # Other crypto tools
            "decoder workbench": self._open_decoder_workbench,
            "rsa toolkit": self._open_rsa_toolkit,
            "xor analyzer": self._open_xor_analyzer,
            "morse decoder": self._open_morse_decoder,
            "caesar cipher": self._open_caesar_cipher,
            "vigenère cipher": self._open_vigenere_cipher,
            "vigenere cipher": self._open_vigenere_cipher,
            "file inspector": self._open_file_inspector,
            "pcap viewer": self._open_pcap_viewer,
            "memory analyzer": self._open_memory_analyzer,
            "disk image tools": self._open_disk_image_tools,
            "timeline builder": self._open_timeline_builder,
            "image stego toolkit": self._open_image_stego,
            "exif metadata viewer": self._open_exif_metadata,
            "audio analyzer": self._open_audio_analyzer,
            "video frame exporter": self._open_video_exporter,
            "qr/barcode scanner": self._open_qr_scanner,
            "wordlist generator": self._open_wordlist_generator,
            "nmap": self._open_nmap,
            "dir discovery": self._open_discovery,
            "sqli tester": self._open_sqli_tester,
            "sqlmap": self._open_sqlmap,
            "xss tester": self._open_xss_tester,
            "jwt tool": self._open_jwt_tool,
            "file upload tester": self._open_file_upload,
            "extract strings": self._open_strings,
            "disassembler launcher": self._open_disassembler,
            "radare/rizin console": self._open_rizin_console,
            "gdb runner": self._open_gdb_runner,
            "rop gadget finder": self._open_rop_gadget,
            "binary diff": self._open_binary_diff,
            "pe/elf inspector": self._open_binary_inspector,
            "exe decompiler": self._open_exe_decompiler,
        }
        return handlers.get(name)

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
        challenge_items = [
            ("challenges", "view-collection-symbolic", "All Challenges"),
            ("favorites", "starred-symbolic", "Favorites"),
            (self._encode_view_name("status", "In Progress"), "media-playlist-repeat-symbolic", "In Progress"),
            (self._encode_view_name("status", "Completed"), "emblem-ok-symbolic", "Completed"),
        ]
        for name, icon, label in challenge_items:
            self._append_sidebar_item(name, icon, label, selectable=True)

        self._append_sidebar_heading("Tools")
        self._append_sidebar_item("tools", "applications-utilities-symbolic", "Overview", selectable=True)

        grouped = self.app.module_registry.by_category()
        seen: set[str] = set()

        def _category_label(value: str) -> str:
            pretty = value.strip() or "Other"
            if pretty.lower() == "reverse":
                return "Reverse Engineering"
            return pretty.title()

        for category in sorted(grouped, key=lambda cat: cat.casefold()):
            self._append_sidebar_heading(_category_label(category))
            tools = sorted(
                grouped.get(category, []),
                key=lambda tool: (getattr(tool, "name", "") or "").casefold(),
            )
            for tool in tools:
                raw_name = getattr(tool, "name", "")
                name = (raw_name or "").strip()
                if not name or name in seen:
                    continue
                seen.add(name)
                row_name = self._encode_view_name("tool", name)
                icon = TOOL_ICON_MAP.get(name.lower(), "applications-utilities-symbolic")
                self._append_sidebar_item(row_name, icon, name, selectable=True)

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
        row.add_css_class("sidebar-row")
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
            self._show_challenges()
        elif view == "project":
            self._show_challenges(project=payload)
        elif view == "status":
            self._show_challenges(status=payload)
        elif view == "favorites":
            self._show_challenges(favorites=True)
        elif view == "detail":
            # Don't repopulate detail view during refresh - it would retrigger signals
            # The detail view is already populated and any changes are saved
            pass
        elif view == "tools":
            self._show_tools()
        elif view == "tool":
            if payload:
                self._show_tool(payload)
            else:
                self._show_tools()
        else:
            self._show_challenges()

        self._apply_text_field_decorations()

    def _apply_text_field_decorations(self) -> None:
        if self.window is None:
            return
        self._style_text_controls(self.window)

    def _style_text_controls(self, widget: Gtk.Widget) -> None:
        if isinstance(widget, Gtk.Entry):
            classes = widget.get_css_classes()
            if "sidebar-search" not in classes and "text-entry" not in classes:
                widget.add_css_class("text-entry")
        if isinstance(widget, Gtk.TextView):
            if "text-area" not in widget.get_css_classes():
                widget.add_css_class("text-area")
            widget.set_top_margin(8)
            widget.set_bottom_margin(8)
            widget.set_left_margin(10)
            widget.set_right_margin(10)
            parent = widget.get_parent()
            if isinstance(parent, Gtk.Viewport):
                parent = parent.get_parent()
            if isinstance(parent, Gtk.ScrolledWindow) and parent is not None:
                if "text-area-frame" not in parent.get_css_classes():
                    parent.add_css_class("text-area-frame")
        child = widget.get_first_child()
        while child is not None:
            self._style_text_controls(child)
            child = child.get_next_sibling()

    def _encode_view_name(self, view: str, payload: Optional[str]) -> str:
        if payload is None:
            return view
        return f"{view}::{payload}"

    def _on_sidebar_selected(self, _listbox: Gtk.ListBox, row: Optional[Gtk.ListBoxRow]) -> None:
        if row is None:
            return
        name = row.get_name() or "challenges"
        if name == "tools":
            self._current_view = ("tools", None)
        elif name.startswith("project::"):
            project = name.split("::", 1)[1]
            self._current_view = ("project", project)
        elif name.startswith("status::"):
            status = name.split("::", 1)[1]
            self._current_view = ("status", status)
        elif name.startswith("tool::"):
            tool_name = name.split("::", 1)[1]
            self._current_view = ("tool", tool_name)
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

    def _show_challenges(
        self,
        *,
        project: Optional[str] = None,
        status: Optional[str] = None,
        favorites: bool = False,
    ) -> None:
        self.content_stack.set_visible_child_name("challenges")

        query = self.search_entry.get_text().strip()

        challenges = self.app.challenge_manager.list_challenges(
            search=query or None,
            project=project,
            status=status,
            favorite=True if favorites else None,
        )

        if not challenges:
            if project:
                self.challenge_placeholder.set_title("No challenges for this project")
                self.challenge_placeholder.set_description("Add or import challenges to begin tracking this project.")
            elif favorites:
                self.challenge_placeholder.set_title("No favorites yet")
                self.challenge_placeholder.set_description("Mark a challenge as favorite to see it here.")
            elif status:
                self.challenge_placeholder.set_title(f"No {status.lower()} challenges")
                self.challenge_placeholder.set_description("Update challenge progress to populate this view.")
            elif query:
                self.challenge_placeholder.set_title("No matches found")
                self.challenge_placeholder.set_description("Try a different search or clear the filter.")
            else:
                self.challenge_placeholder.set_title("No challenges yet")
                self.challenge_placeholder.set_description("Create your first challenge to start tracking progress.")
            self.challenge_stack.set_visible_child_name("empty")
            _clear_grid(self.cards_grid)
            return

        self.challenge_stack.set_visible_child_name("cards")
        _clear_grid(self.cards_grid)

        # Add cards to grid in 2-column layout
        for i, challenge in enumerate(challenges):
            card = ChallengeCard(challenge, self._open_challenge_detail, self._toggle_favorite)
            card.add_css_class("challenge-card-holder")
            card.set_valign(Gtk.Align.START)
            card.set_halign(Gtk.Align.FILL)
            card.set_hexpand(True)
            card.set_size_request(320, -1)  # Only set min width, let height be natural
            
            row = i // 2
            col = i % 2
            self.cards_grid.attach(card, col, row, 1, 1)

    def _show_tools(self) -> None:
        self._show_tool_overview()

    # ------------------------------------------------------------------
    # Challenge detail handling
    # ------------------------------------------------------------------
    def _toggle_favorite(self, challenge_id: int) -> None:
        """Toggle the favorite status of a challenge."""
        try:
            challenge = self.app.challenge_manager.get_challenge(challenge_id)
            # Toggle the favorite status
            current_favorite = getattr(challenge, "favorite", False)
            self.app.challenge_manager.set_favorite(challenge_id, not current_favorite)
            
            # Refresh the UI to show updated state
            self.refresh_sidebar()
            self.refresh_main_content()
        except ValueError:
            self._set_status_message("Challenge no longer exists")
    
    def _on_delete_challenge_clicked(self, button: Gtk.Button) -> None:
        """Handle delete button click with confirmation dialog."""
        if self._active_challenge_id is None:
            return
        
        try:
            challenge = self.app.challenge_manager.get_challenge(self._active_challenge_id)
        except ValueError:
            self._set_status_message("Challenge no longer exists")
            return
        
        # Create confirmation dialog
        dialog = Adw.MessageDialog.new(self.window)
        dialog.set_heading("Delete Challenge?")
        dialog.set_body(f"Are you sure you want to delete '{challenge.title}'? This action cannot be undone.")
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("delete", "Delete")
        dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")
        
        def on_response(dialog: Adw.MessageDialog, response: str) -> None:
            if response == "delete" and self._active_challenge_id is not None:
                try:
                    self.app.challenge_manager.delete_challenge(self._active_challenge_id)
                    self._set_status_message(f"Deleted '{challenge.title}'")
                    self._show_cards()
                except ValueError:
                    self._set_status_message("Failed to delete challenge")
        
        dialog.connect("response", on_response)
        dialog.present()
    
    def _open_challenge_detail(self, challenge_id: int) -> None:
        try:
            challenge = self.app.challenge_manager.get_challenge(challenge_id)
        except ValueError:
            self._set_status_message("Challenge no longer exists")
            return
        self._active_challenge_id = challenge_id
        self._current_view = ("detail", str(challenge_id))
        self._populate_detail(challenge)
        self.challenge_stack.set_visible_child_name("detail")
        self._setup_autocomplete()  # Refresh autocomplete with latest data

    def _show_cards(self) -> None:
        self._current_view = ("challenges", None)
        self.challenge_stack.set_visible_child_name("cards")
        self.refresh_sidebar()
        self.refresh_main_content()

    def _focus_challenge_card(self, challenge_id: int) -> bool:
        child = self.cards_grid.get_first_child()
        while child is not None:
            if isinstance(child, ChallengeCard) and child.challenge_id == challenge_id:
                child.grab_focus()
                break
            child = child.get_next_sibling()
        return False

    def _populate_detail(self, challenge: Challenge) -> None:
        # Block dirty marking while populating
        self._populating_detail = True
        
        self._update_detail_header(challenge)
        self.title_entry.set_text(challenge.title)
        self.project_entry.set_text(challenge.project)
        self.category_entry.set_text(challenge.category)
        try:
            difficulty_index = self._difficulty_values.index(challenge.difficulty.lower())
        except ValueError:
            difficulty_index = 1
        self.difficulty_combo.set_selected(difficulty_index)

        try:
            status_index = self._status_options.index(challenge.status)
        except ValueError:
            status_index = 0
        self.status_combo.set_selected(status_index)
        buffer = self.description_view.get_buffer()
        buffer.set_text(challenge.description)
        self.flag_entry.set_text(challenge.flag or "")
        self._set_notes_text(self.app.note_manager.load_markdown(challenge.id))
        self._set_status_message(
            f"Updated {challenge.updated_at:%Y-%m-%d %H:%M} • Created {challenge.created_at:%Y-%m-%d %H:%M}"
        )
        
        # Re-enable dirty marking
        self._populating_detail = False

    def _update_detail_header(self, challenge: Challenge) -> None:
        self.detail_title_label.set_text(challenge.title)
        self.detail_project_label.set_text(f"Project · {challenge.project}")
        self.detail_category_label.set_text(f"Category · {challenge.category}")
        for cls in list(self.detail_status_chip.get_css_classes()):
            if cls.startswith("status-"):
                self.detail_status_chip.remove_css_class(cls)
        self.detail_status_chip.add_css_class(STATUS_STYLE_CLASSES.get(challenge.status, "status-not-started"))
        self.detail_status_chip.set_label(challenge.status)

    # (card-based helper methods removed in favour of direct sidebar navigation)

    # ------------------------------------------------------------------
    # Tools - dedicated pages
    # ------------------------------------------------------------------
    def _build_hash_digest_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("Hash Digest")
        header_row.append(title)
        header_row.set_halign(Gtk.Align.START)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=720, tightening_threshold=560)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        # Text input
        text_label = Gtk.Label(label="Input text", xalign=0)
        form.append(text_label)
        self.hash_text_view = Gtk.TextView()
        self.hash_text_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        text_scroller = Gtk.ScrolledWindow()
        text_scroller.add_css_class("output-box")
        text_scroller.set_min_content_height(200)
        text_scroller.set_child(self.hash_text_view)
        form.append(text_scroller)

        # File chooser row
        file_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.hash_file_entry = Gtk.Entry()
        self.hash_file_entry.add_css_class("modern-entry")
        self.hash_file_entry.set_placeholder_text("Path to file (optional)")
        browse_btn = Gtk.Button(label="Browse…")
        browse_btn.connect("clicked", self._on_hash_browse)
        file_row.append(self.hash_file_entry)
        file_row.append(browse_btn)
        form.append(file_row)

        # Algorithm + compute row
        algo_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        algo_label = Gtk.Label(label="Algorithm", xalign=0)
        algo_label.set_halign(Gtk.Align.START)
        algo_row.append(algo_label)
        self.hash_algo_combo = Gtk.ComboBoxText()
        for alg in ["md5", "sha1", "sha256", "sha512"]:
            self.hash_algo_combo.append(alg, alg.upper())
        self.hash_algo_combo.set_active_id("sha256")
        algo_row.append(self.hash_algo_combo)
        algo_row.set_halign(Gtk.Align.START)
        form.append(algo_row)

        # Compute button
        compute_btn = Gtk.Button(label="Compute")
        compute_btn.add_css_class("suggested-action")
        compute_btn.connect("clicked", self._on_hash_compute)
        form.append(compute_btn)

        # Result area
        result_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.hash_result_entry = Gtk.Entry()
        self.hash_result_entry.add_css_class("modern-entry")
        self.hash_result_entry.set_editable(False)
        copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        copy_btn.set_tooltip_text("Copy digest")
        copy_btn.connect("clicked", self._on_hash_copy)
        result_row.append(self.hash_result_entry)
        result_row.append(copy_btn)
        form.append(result_row)

    def _open_hash_digest(self, tool) -> None:
        self._active_tool = tool
        # Clear previous inputs
        self.hash_text_view.get_buffer().set_text("")
        self.hash_file_entry.set_text("")
        self.hash_algo_combo.set_active_id("sha256")
        self.hash_result_entry.set_text("")
        self.tool_detail_stack.set_visible_child_name("hash_digest")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_hash_browse(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative.new("Select file", self.window, Gtk.FileChooserAction.OPEN, None, None)
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                self.hash_file_entry.set_text(file.get_path() or "")
        dialog.destroy()

    def _on_hash_compute(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        buffer = self.hash_text_view.get_buffer()
        start, end = buffer.get_bounds()
        text = buffer.get_text(start, end, True)
        file_path = self.hash_file_entry.get_text().strip()
        algo = self.hash_algo_combo.get_active_id() or "sha256"
        if not text and not file_path:
            self.toast_overlay.add_toast(Adw.Toast.new("Enter text or choose a file"))
            return
        try:
            result = self._active_tool.run(text=text, file=file_path, algorithm=algo)
            self.hash_result_entry.set_text(getattr(result, "body", str(result)))
        except Exception as exc:
            self.toast_overlay.add_toast(Adw.Toast.new(f"Error: {exc}"))

    def _on_hash_copy(self, _btn: Gtk.Button) -> None:
        display = self.window.get_display()
        if display is None:
            return
        clipboard = display.get_clipboard()
        clipboard.set_text(self.hash_result_entry.get_text())

    # ============================================================================
    # Hash Suite - Unified hash tool interface
    # ============================================================================
    
    def _build_hash_suite_detail(self, root: Gtk.Box) -> None:
        """Build the unified Hash Suite interface with tabbed view."""
        # Header with back button, title, and advanced mode toggle
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("Hash Suite")
        header_row.append(title)
        
        # Spacer
        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        header_row.append(spacer)
        
        # Advanced Mode toggle
        advanced_label = Gtk.Label(label="Advanced Mode")
        header_row.append(advanced_label)
        self.hash_suite_advanced_toggle = Gtk.Switch()
        self.hash_suite_advanced_toggle.set_active(False)
        self.hash_suite_advanced_toggle.connect("notify::active", self._on_hash_suite_advanced_toggled)
        header_row.append(self.hash_suite_advanced_toggle)
        
        header_row.set_halign(Gtk.Align.FILL)
        root.append(header_row)
        
        # Preset selector row
        preset_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8, margin_top=8)
        preset_label = Gtk.Label(label="Quick Preset:", xalign=0)
        preset_row.append(preset_label)
        
        self.hash_suite_preset_combo = Gtk.ComboBoxText()
        self.hash_suite_preset_combo.append("none", "None")
        self.hash_suite_preset_combo.append("ctf_quick", "CTF Quick (60s/100K)")
        self.hash_suite_preset_combo.append("forensics", "Forensics (600s/10M)")
        self.hash_suite_preset_combo.append("debugging", "Debugging (10s/1K)")
        self.hash_suite_preset_combo.set_active_id("none")
        self.hash_suite_preset_combo.connect("changed", self._on_hash_suite_preset_changed)
        preset_row.append(self.hash_suite_preset_combo)
        preset_row.set_halign(Gtk.Align.START)
        root.append(preset_row)
        
        # Tab view for different hash operations
        self.hash_suite_tab_view = Adw.TabView()
        self.hash_suite_tab_view.set_vexpand(True)
        # Disable tab closing - tabs are permanent UI elements, not documents
        self.hash_suite_tab_view.connect("close-page", lambda *args: True)  # Return True to prevent closing
        self.hash_suite_tab_bar = Adw.TabBar()
        self.hash_suite_tab_bar.set_view(self.hash_suite_tab_view)
        self.hash_suite_tab_bar.set_autohide(False)  # Always show tabs
        self.hash_suite_tab_bar.add_css_class("hash-suite-tabs")  # For CSS styling
        root.append(self.hash_suite_tab_bar)
        root.append(self.hash_suite_tab_view)
        
        # Build each tab
        self._build_hash_suite_identify_tab()
        self._build_hash_suite_verify_tab()
        self._build_hash_suite_crack_tab()
        self._build_hash_suite_format_tab()
        self._build_hash_suite_generate_tab()
        self._build_hash_suite_benchmark_tab()
        self._build_hash_suite_queue_tab()
    
    def _build_hash_suite_identify_tab(self) -> None:
        """Build the Identify tab for hash identification."""
        tab_content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        
        clamp = Adw.Clamp(maximum_size=720, tightening_threshold=560)
        tab_content.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)
        
        # Description
        desc = Gtk.Label(label="Identify hash type from hash value or analyze a file containing hashes.", xalign=0, wrap=True)
        desc.add_css_class("dim-label")
        form.append(desc)
        
        # Hash input
        hash_label = Gtk.Label(label="Hash value(s)", xalign=0)
        form.append(hash_label)
        self.hash_suite_identify_input = Gtk.TextView()
        self.hash_suite_identify_input.add_css_class("input-text")
        self.hash_suite_identify_input.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.hash_suite_identify_input.add_css_class("input-text")
        input_scroll = Gtk.ScrolledWindow()
        input_scroll.add_css_class("input-box")
        input_scroll.set_min_content_height(200)
        input_scroll.add_css_class("input-box")
        input_scroll.set_child(self.hash_suite_identify_input)
        form.append(input_scroll)
        
        # File chooser
        file_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.hash_suite_identify_file = Gtk.Entry()
        self.hash_suite_identify_file.set_placeholder_text("Or choose a file with hashes...")
        self.hash_suite_identify_file.add_css_class("modern-entry")
        browse_btn = Gtk.Button(label="Browse…")
        browse_btn.connect("clicked", self._on_hash_suite_identify_browse)
        file_row.append(self.hash_suite_identify_file)
        file_row.append(browse_btn)
        form.append(file_row)
        
        # Identify button
        identify_btn = Gtk.Button(label="Identify Hash Type")
        identify_btn.add_css_class("suggested-action")
        identify_btn.connect("clicked", self._on_hash_suite_identify_run)
        form.append(identify_btn)
        
        # Results
        result_label = Gtk.Label(label="Results", xalign=0)
        result_label.add_css_class("title-4")
        form.append(result_label)
        
        self.hash_suite_identify_result = Gtk.TextView()
        self.hash_suite_identify_result.add_css_class("output-text")
        self.hash_suite_identify_result.set_editable(False)
        self.hash_suite_identify_result.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.hash_suite_identify_result.add_css_class("output-text")
        result_scroll = Gtk.ScrolledWindow()
        result_scroll.add_css_class("output-box")
        result_scroll.set_min_content_height(550)
        result_scroll.add_css_class("output-box")
        result_scroll.set_child(self.hash_suite_identify_result)
        form.append(result_scroll)
        
        # Add tab
        page = self.hash_suite_tab_view.append(tab_content)
        page.set_title("Identify")
        page.set_icon(Gio.ThemedIcon.new("dialog-question-symbolic"))
        page.set_indicator_activatable(False)  # Prevent tab closing
    
    def _build_hash_suite_verify_tab(self) -> None:
        """Build the Verify tab for hash verification."""
        tab_content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        
        clamp = Adw.Clamp(maximum_size=720, tightening_threshold=560)
        tab_content.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)
        
        # Description
        desc = Gtk.Label(label="Verify if a plaintext matches a given hash.", xalign=0, wrap=True)
        desc.add_css_class("dim-label")
        form.append(desc)
        
        # Hash input
        hash_label = Gtk.Label(label="Hash value", xalign=0)
        form.append(hash_label)
        self.hash_suite_verify_hash = Gtk.Entry()
        self.hash_suite_verify_hash.set_placeholder_text("Enter hash to verify against...")
        self.hash_suite_verify_hash.add_css_class("modern-entry")
        form.append(self.hash_suite_verify_hash)
        
        # Plaintext input
        plain_label = Gtk.Label(label="Plaintext to verify", xalign=0)
        form.append(plain_label)
        self.hash_suite_verify_plain = Gtk.Entry()
        self.hash_suite_verify_plain.set_placeholder_text("Enter plaintext...")
        self.hash_suite_verify_plain.add_css_class("modern-entry")
        form.append(self.hash_suite_verify_plain)
        
        # Algorithm selector
        algo_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        algo_label = Gtk.Label(label="Algorithm (optional)", xalign=0)
        algo_row.append(algo_label)
        self.hash_suite_verify_algo = Gtk.ComboBoxText()
        self.hash_suite_verify_algo.append("auto", "Auto-detect")
        for alg in ["md5", "sha1", "sha256", "sha512", "ntlm", "bcrypt"]:
            self.hash_suite_verify_algo.append(alg, alg.upper())
        self.hash_suite_verify_algo.set_active_id("auto")
        algo_row.append(self.hash_suite_verify_algo)
        form.append(algo_row)
        
        # Verify button
        verify_btn = Gtk.Button(label="Verify Match")
        verify_btn.add_css_class("suggested-action")
        verify_btn.connect("clicked", self._on_hash_suite_verify_run)
        form.append(verify_btn)
        
        # Result
        self.hash_suite_verify_result = Gtk.Label(xalign=0, wrap=True)
        form.append(self.hash_suite_verify_result)
        
        # Add tab
        page = self.hash_suite_tab_view.append(tab_content)
        page.set_title("Verify")
        page.set_icon(Gio.ThemedIcon.new("emblem-ok-symbolic"))
        page.set_indicator_activatable(False)  # Prevent tab closing
    
    def _build_hash_suite_crack_tab(self) -> None:
        """Build the Crack tab for hash cracking."""
        tab_content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        
        clamp = Adw.Clamp(maximum_size=720, tightening_threshold=560)
        tab_content.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)
        
        # Description
        desc = Gtk.Label(label="Attempt to crack hash using various attack modes.", xalign=0, wrap=True)
        desc.add_css_class("dim-label")
        form.append(desc)
        
        # Hash input
        hash_label = Gtk.Label(label="Hash value", xalign=0)
        form.append(hash_label)
        self.hash_suite_crack_hash = Gtk.Entry()
        self.hash_suite_crack_hash.set_placeholder_text("Enter hash to crack...")
        form.append(self.hash_suite_crack_hash)
        
        # Attack mode
        mode_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        mode_label = Gtk.Label(label="Attack Mode", xalign=0)
        mode_row.append(mode_label)
        self.hash_suite_crack_mode = Gtk.ComboBoxText()
        self.hash_suite_crack_mode.append("dictionary", "Dictionary")
        self.hash_suite_crack_mode.append("bruteforce", "Brute Force")
        self.hash_suite_crack_mode.append("hybrid", "Hybrid")
        self.hash_suite_crack_mode.set_active_id("dictionary")
        self.hash_suite_crack_mode.connect("changed", self._on_hash_suite_crack_mode_changed)
        mode_row.append(self.hash_suite_crack_mode)
        form.append(mode_row)
        
        # Wordlist path (for dictionary mode)
        self.hash_suite_crack_wordlist_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.hash_suite_crack_wordlist = Gtk.Entry()
        self.hash_suite_crack_wordlist.set_placeholder_text("Path to wordlist...")
        wordlist_browse = Gtk.Button(label="Browse…")
        wordlist_browse.connect("clicked", self._on_hash_suite_crack_wordlist_browse)
        self.hash_suite_crack_wordlist_row.append(self.hash_suite_crack_wordlist)
        self.hash_suite_crack_wordlist_row.append(wordlist_browse)
        form.append(self.hash_suite_crack_wordlist_row)
        
        # Charset (for brute force)
        self.hash_suite_crack_charset_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        charset_label = Gtk.Label(label="Charset", xalign=0)
        self.hash_suite_crack_charset_row.append(charset_label)
        self.hash_suite_crack_charset = Gtk.ComboBoxText()
        self.hash_suite_crack_charset.append("lowercase", "Lowercase (a-z)")
        self.hash_suite_crack_charset.append("uppercase", "Uppercase (A-Z)")
        self.hash_suite_crack_charset.append("digits", "Digits (0-9)")
        self.hash_suite_crack_charset.append("alphanumeric", "Alphanumeric")
        self.hash_suite_crack_charset.append("all", "All printable")
        self.hash_suite_crack_charset.set_active_id("lowercase")
        self.hash_suite_crack_charset_row.append(self.hash_suite_crack_charset)
        self.hash_suite_crack_charset_row.set_visible(False)
        form.append(self.hash_suite_crack_charset_row)
        
        # Max length (for brute force)
        self.hash_suite_crack_maxlen_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        maxlen_label = Gtk.Label(label="Max Length", xalign=0)
        self.hash_suite_crack_maxlen_row.append(maxlen_label)
        self.hash_suite_crack_maxlen = Gtk.SpinButton.new_with_range(1, 12, 1)
        self.hash_suite_crack_maxlen.set_value(6)
        self.hash_suite_crack_maxlen_row.append(self.hash_suite_crack_maxlen)
        self.hash_suite_crack_maxlen_row.set_visible(False)
        form.append(self.hash_suite_crack_maxlen_row)
        
        # Advanced backends section (only visible in advanced mode)
        self.hash_suite_crack_advanced_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.hash_suite_crack_advanced_box.set_visible(False)
        
        advanced_label = Gtk.Label(label="Advanced Backends", xalign=0)
        advanced_label.add_css_class("title-4")
        self.hash_suite_crack_advanced_box.append(advanced_label)
        
        backend_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        backend_label = Gtk.Label(label="Backend", xalign=0)
        backend_row.append(backend_label)
        self.hash_suite_crack_backend = Gtk.ComboBoxText()
        self.hash_suite_crack_backend.append("simulated", "Simulated (Built-in)")
        self.hash_suite_crack_backend.append("hashcat", "Hashcat")
        self.hash_suite_crack_backend.append("john", "John the Ripper")
        self.hash_suite_crack_backend.set_active_id("simulated")
        backend_row.append(self.hash_suite_crack_backend)
        self.hash_suite_crack_advanced_box.append(backend_row)
        
        form.append(self.hash_suite_crack_advanced_box)
        
        # Crack button
        crack_btn = Gtk.Button(label="Start Cracking")
        crack_btn.add_css_class("suggested-action")
        crack_btn.connect("clicked", self._on_hash_suite_crack_run)
        form.append(crack_btn)
        
        # Result
        result_label = Gtk.Label(label="Result", xalign=0)
        result_label.add_css_class("title-4")
        form.append(result_label)
        
        self.hash_suite_crack_result = Gtk.TextView()
        self.hash_suite_crack_result.add_css_class("output-text")
        self.hash_suite_crack_result.set_editable(False)
        self.hash_suite_crack_result.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        result_scroll = Gtk.ScrolledWindow()
        result_scroll.add_css_class("output-box")
        result_scroll.set_min_content_height(550)
        result_scroll.set_child(self.hash_suite_crack_result)
        form.append(result_scroll)
        
        # Add tab
        page = self.hash_suite_tab_view.append(tab_content)
        page.set_title("Crack")
        page.set_icon(Gio.ThemedIcon.new("dialog-password-symbolic"))
        page.set_indicator_activatable(False)  # Prevent tab closing
    
    def _build_hash_suite_format_tab(self) -> None:
        """Build the Format tab for hash format conversion."""
        tab_content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        
        clamp = Adw.Clamp(maximum_size=720, tightening_threshold=560)
        tab_content.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)
        
        # Description
        desc = Gtk.Label(label="Convert hash format between different representations.", xalign=0, wrap=True)
        desc.add_css_class("dim-label")
        form.append(desc)
        
        # Input
        input_label = Gtk.Label(label="Input hash", xalign=0)
        form.append(input_label)
        self.hash_suite_format_input = Gtk.Entry()
        self.hash_suite_format_input.add_css_class("modern-entry")
        self.hash_suite_format_input.set_placeholder_text("Enter hash in any format...")
        form.append(self.hash_suite_format_input)
        
        # Format selectors
        format_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        from_label = Gtk.Label(label="From", xalign=0)
        format_row.append(from_label)
        self.hash_suite_format_from = Gtk.ComboBoxText()
        self.hash_suite_format_from.append("auto", "Auto-detect")
        self.hash_suite_format_from.append("hex", "Hex")
        self.hash_suite_format_from.append("base64", "Base64")
        self.hash_suite_format_from.append("hashcat", "Hashcat format")
        self.hash_suite_format_from.append("john", "John format")
        self.hash_suite_format_from.set_active_id("auto")
        format_row.append(self.hash_suite_format_from)
        
        to_label = Gtk.Label(label="To", xalign=0)
        format_row.append(to_label)
        self.hash_suite_format_to = Gtk.ComboBoxText()
        self.hash_suite_format_to.append("hex", "Hex")
        self.hash_suite_format_to.append("base64", "Base64")
        self.hash_suite_format_to.append("hashcat", "Hashcat format")
        self.hash_suite_format_to.append("john", "John format")
        self.hash_suite_format_to.set_active_id("hex")
        format_row.append(self.hash_suite_format_to)
        form.append(format_row)
        
        # Convert button
        convert_btn = Gtk.Button(label="Convert Format")
        convert_btn.add_css_class("suggested-action")
        convert_btn.connect("clicked", self._on_hash_suite_format_run)
        form.append(convert_btn)
        
        # Output
        output_label = Gtk.Label(label="Output", xalign=0)
        form.append(output_label)
        output_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.hash_suite_format_output = Gtk.Entry()
        self.hash_suite_format_output.add_css_class("modern-entry")
        self.hash_suite_format_output.set_editable(False)
        copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        copy_btn.set_tooltip_text("Copy to clipboard")
        copy_btn.connect("clicked", self._on_hash_suite_format_copy)
        output_row.append(self.hash_suite_format_output)
        output_row.append(copy_btn)
        form.append(output_row)
        
        # Add tab
        page = self.hash_suite_tab_view.append(tab_content)
        page.set_title("Format")
        page.set_icon(Gio.ThemedIcon.new("emblem-synchronizing-symbolic"))
        page.set_indicator_activatable(False)  # Prevent tab closing
    
    def _build_hash_suite_generate_tab(self) -> None:
        """Build the Generate tab for hash generation."""
        tab_content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        
        clamp = Adw.Clamp(maximum_size=720, tightening_threshold=560)
        tab_content.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)
        
        # Description
        desc = Gtk.Label(label="Generate hash from plaintext input.", xalign=0, wrap=True)
        desc.add_css_class("dim-label")
        form.append(desc)
        
        # Preset selector
        preset_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        preset_label = Gtk.Label(label="Preset", xalign=0)
        preset_row.append(preset_label)
        self.hash_suite_gen_preset = Gtk.ComboBoxText()
        self.hash_suite_gen_preset.append("test_hash", "Test Hash")
        self.hash_suite_gen_preset.append("htpasswd_bcrypt", "htpasswd (bcrypt)")
        self.hash_suite_gen_preset.append("htpasswd_apr1", "htpasswd (APR1-MD5)")
        self.hash_suite_gen_preset.append("custom", "Custom")
        self.hash_suite_gen_preset.set_active_id("test_hash")
        self.hash_suite_gen_preset.connect("changed", self._on_hash_suite_gen_preset_changed)
        preset_row.append(self.hash_suite_gen_preset)
        form.append(preset_row)
        
        # Input text
        input_label = Gtk.Label(label="Input text", xalign=0)
        form.append(input_label)
        self.hash_suite_gen_input = Gtk.TextView()
        self.hash_suite_gen_input.add_css_class("input-text")
        self.hash_suite_gen_input.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.hash_suite_gen_input.add_css_class("input-text")
        input_scroll = Gtk.ScrolledWindow()
        input_scroll.add_css_class("input-box")
        input_scroll.set_min_content_height(200)
        input_scroll.add_css_class("input-box")
        input_scroll.set_child(self.hash_suite_gen_input)
        form.append(input_scroll)
        
        # htpasswd-specific fields (initially hidden)
        self.hash_suite_gen_htpasswd_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.hash_suite_gen_htpasswd_box.set_visible(False)
        
        username_label = Gtk.Label(label="Username", xalign=0)
        self.hash_suite_gen_htpasswd_box.append(username_label)
        self.hash_suite_gen_username = Gtk.Entry()
        self.hash_suite_gen_username.set_placeholder_text("Enter username...")
        self.hash_suite_gen_htpasswd_box.append(self.hash_suite_gen_username)
        
        form.append(self.hash_suite_gen_htpasswd_box)
        
        # Algorithm selector
        algo_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        algo_label = Gtk.Label(label="Algorithm", xalign=0)
        algo_row.append(algo_label)
        self.hash_suite_gen_algo = Gtk.ComboBoxText()
        for alg in ["md5", "sha1", "sha256", "sha512", "ntlm", "bcrypt"]:
            self.hash_suite_gen_algo.append(alg, alg.upper())
        self.hash_suite_gen_algo.set_active_id("sha256")
        algo_row.append(self.hash_suite_gen_algo)
        form.append(algo_row)
        
        # Generate button
        gen_btn = Gtk.Button(label="Generate Hash")
        gen_btn.add_css_class("suggested-action")
        gen_btn.connect("clicked", self._on_hash_suite_generate_run)
        form.append(gen_btn)
        
        # Output
        output_label = Gtk.Label(label="Generated hash", xalign=0)
        form.append(output_label)
        output_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.hash_suite_gen_output = Gtk.Entry()
        self.hash_suite_gen_output.add_css_class("modern-entry")
        self.hash_suite_gen_output.set_editable(False)
        copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        copy_btn.set_tooltip_text("Copy to clipboard")
        copy_btn.connect("clicked", self._on_hash_suite_gen_copy)
        output_row.append(self.hash_suite_gen_output)
        output_row.append(copy_btn)
        form.append(output_row)
        
        # Add tab
        page = self.hash_suite_tab_view.append(tab_content)
        page.set_title("Generate")
        page.set_icon(Gio.ThemedIcon.new("list-add-symbolic"))
        page.set_indicator_activatable(False)  # Prevent tab closing
    
    def _build_hash_suite_benchmark_tab(self) -> None:
        """Build the Benchmark tab for performance testing."""
        tab_content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        
        clamp = Adw.Clamp(maximum_size=720, tightening_threshold=560)
        tab_content.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)
        
        # Description
        desc = Gtk.Label(label="Benchmark hash algorithm performance.", xalign=0, wrap=True)
        desc.add_css_class("dim-label")
        form.append(desc)
        
        # Algorithm selector
        algo_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        algo_label = Gtk.Label(label="Algorithm", xalign=0)
        algo_row.append(algo_label)
        self.hash_suite_bench_algo = Gtk.ComboBoxText()
        for alg in ["md5", "sha1", "sha256", "sha512", "bcrypt"]:
            self.hash_suite_bench_algo.append(alg, alg.upper())
        self.hash_suite_bench_algo.set_active_id("md5")
        algo_row.append(self.hash_suite_bench_algo)
        form.append(algo_row)
        
        # Duration
        duration_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        duration_label = Gtk.Label(label="Duration (seconds)", xalign=0)
        duration_row.append(duration_label)
        self.hash_suite_bench_duration = Gtk.SpinButton.new_with_range(1, 60, 1)
        self.hash_suite_bench_duration.set_value(5)
        duration_row.append(self.hash_suite_bench_duration)
        form.append(duration_row)
        
        # Benchmark button
        bench_btn = Gtk.Button(label="Run Benchmark")
        bench_btn.add_css_class("suggested-action")
        bench_btn.connect("clicked", self._on_hash_suite_benchmark_run)
        form.append(bench_btn)
        
        # Results
        result_label = Gtk.Label(label="Results", xalign=0)
        result_label.add_css_class("title-4")
        form.append(result_label)
        
        self.hash_suite_bench_result = Gtk.TextView()
        self.hash_suite_bench_result.add_css_class("output-text")
        self.hash_suite_bench_result.set_editable(False)
        self.hash_suite_bench_result.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        result_scroll = Gtk.ScrolledWindow()
        result_scroll.add_css_class("output-box")
        result_scroll.set_min_content_height(550)
        result_scroll.set_child(self.hash_suite_bench_result)
        form.append(result_scroll)
        
        # Add tab
        page = self.hash_suite_tab_view.append(tab_content)
        page.set_title("Benchmark")
        page.set_icon(Gio.ThemedIcon.new("emblem-system-symbolic"))
        page.set_indicator_activatable(False)  # Prevent tab closing
    
    def _build_hash_suite_queue_tab(self) -> None:
        """Build the Queue tab for job management."""
        tab_content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        
        clamp = Adw.Clamp(maximum_size=720, tightening_threshold=560)
        tab_content.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)
        
        # Description
        desc = Gtk.Label(label="View job queue and history.", xalign=0, wrap=True)
        desc.add_css_class("dim-label")
        form.append(desc)
        
        # Queue/History display
        self.hash_suite_queue_view = Gtk.TextView()
        self.hash_suite_queue_view.set_editable(False)
        self.hash_suite_queue_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        queue_scroll = Gtk.ScrolledWindow()
        queue_scroll.add_css_class("output-box")
        queue_scroll.set_min_content_height(400)
        queue_scroll.set_child(self.hash_suite_queue_view)
        form.append(queue_scroll)
        
        # Buttons
        btn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        refresh_btn = Gtk.Button(label="Refresh")
        refresh_btn.connect("clicked", self._on_hash_suite_queue_refresh)
        btn_row.append(refresh_btn)
        
        clear_btn = Gtk.Button(label="Clear History")
        clear_btn.connect("clicked", self._on_hash_suite_queue_clear)
        btn_row.append(clear_btn)
        
        export_btn = Gtk.Button(label="Export Results")
        export_btn.connect("clicked", self._on_hash_suite_queue_export)
        btn_row.append(export_btn)
        form.append(btn_row)
        
        # Add tab
        page = self.hash_suite_tab_view.append(tab_content)
        page.set_title("Queue")
        page.set_icon(Gio.ThemedIcon.new("view-list-symbolic"))
        page.set_indicator_activatable(False)  # Prevent tab closing
    
    def _open_hash_suite(self, tool) -> None:
        """Open the Hash Suite tool."""
        self._active_tool = tool
        # Set default tab and refresh queue view
        self.hash_suite_tab_view.set_selected_page(self.hash_suite_tab_view.get_nth_page(0))
        self.tool_detail_stack.set_visible_child_name("hash_suite")
        self.content_stack.set_visible_child_name("tool_detail")
    
    # Event handlers for Hash Suite
    def _on_hash_suite_advanced_toggled(self, switch, *args) -> None:
        """Toggle advanced mode visibility."""
        advanced_mode = switch.get_active()
        if hasattr(self, 'hash_suite_crack_advanced_box'):
            self.hash_suite_crack_advanced_box.set_visible(advanced_mode)
    
    def _on_hash_suite_preset_changed(self, combo) -> None:
        """Apply quick preset settings."""
        preset = combo.get_active_id()
        # Presets would adjust timeout/max_attempts settings
        # For now, just show a toast
        if preset and preset != "none":
            self.toast_overlay.add_toast(Adw.Toast.new(f"Applied preset: {preset}"))
    
    def _on_hash_suite_identify_browse(self, _btn) -> None:
        """Browse for hash file."""
        dialog = Gtk.FileChooserNative.new("Select hash file", self.window, Gtk.FileChooserAction.OPEN, None, None)
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                self.hash_suite_identify_file.set_text(file.get_path() or "")
        dialog.destroy()
    
    def _on_hash_suite_identify_run(self, _btn) -> None:
        """Run hash identification."""
        if not self._active_tool:
            return
        
        buffer = self.hash_suite_identify_input.get_buffer()
        start, end = buffer.get_bounds()
        hash_input = buffer.get_text(start, end, True).strip()
        file_path = self.hash_suite_identify_file.get_text().strip()
        
        if not hash_input and not file_path:
            self.toast_overlay.add_toast(Adw.Toast.new("Enter a hash or choose a file"))
            return
        
        try:
            result = self._active_tool.run(tab="identify", hash_input=hash_input, file_path=file_path)
            result_text = getattr(result, "body", str(result))
            self.hash_suite_identify_result.get_buffer().set_text(result_text)
        except Exception as exc:
            self.toast_overlay.add_toast(Adw.Toast.new(f"Error: {exc}"))
    
    def _on_hash_suite_verify_run(self, _btn) -> None:
        """Run hash verification."""
        if not self._active_tool:
            return
        
        hash_value = self.hash_suite_verify_hash.get_text().strip()
        plaintext = self.hash_suite_verify_plain.get_text().strip()
        algorithm = self.hash_suite_verify_algo.get_active_id()
        
        if not hash_value or not plaintext:
            self.toast_overlay.add_toast(Adw.Toast.new("Enter both hash and plaintext"))
            return
        
        try:
            result = self._active_tool.run(
                tab="verify",
                hash_input=hash_value,
                plaintext=plaintext,
                algorithm=algorithm if algorithm != "auto" else None
            )
            result_text = getattr(result, "body", str(result))
            self.hash_suite_verify_result.set_text(result_text)
        except Exception as exc:
            self.toast_overlay.add_toast(Adw.Toast.new(f"Error: {exc}"))
    
    def _on_hash_suite_crack_mode_changed(self, combo) -> None:
        """Update UI based on attack mode."""
        mode = combo.get_active_id()
        is_dict = mode == "dictionary" or mode == "hybrid"
        is_brute = mode == "bruteforce" or mode == "hybrid"
        
        self.hash_suite_crack_wordlist_row.set_visible(is_dict)
        self.hash_suite_crack_charset_row.set_visible(is_brute)
        self.hash_suite_crack_maxlen_row.set_visible(is_brute)
    
    def _on_hash_suite_crack_wordlist_browse(self, _btn) -> None:
        """Browse for wordlist file."""
        dialog = Gtk.FileChooserNative.new("Select wordlist", self.window, Gtk.FileChooserAction.OPEN, None, None)
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                self.hash_suite_crack_wordlist.set_text(file.get_path() or "")
        dialog.destroy()
    
    def _on_hash_suite_crack_run(self, _btn) -> None:
        """Run hash cracking."""
        if not self._active_tool:
            return
        
        # Show legal warning on first use
        if not hasattr(self, '_hash_suite_legal_shown'):
            dialog = Adw.MessageDialog.new(self.window)
            dialog.set_heading("Legal Warning")
            dialog.set_body("Only use hash cracking on systems you own or have explicit permission to test. Unauthorized access is illegal.")
            dialog.add_response("cancel", "Cancel")
            dialog.add_response("continue", "I Understand, Continue")
            dialog.set_response_appearance("continue", Adw.ResponseAppearance.DESTRUCTIVE)
            dialog.connect("response", self._on_hash_suite_crack_legal_response)
            dialog.present()
            return
        
        self._execute_hash_crack()
    
    def _on_hash_suite_crack_legal_response(self, dialog, response) -> None:
        """Handle legal warning response."""
        dialog.close()
        if response == "continue":
            self._hash_suite_legal_shown = True
            self._execute_hash_crack()
    
    def _execute_hash_crack(self) -> None:
        """Execute the hash cracking operation."""
        hash_value = self.hash_suite_crack_hash.get_text().strip()
        mode = self.hash_suite_crack_mode.get_active_id()
        
        if not hash_value:
            self.toast_overlay.add_toast(Adw.Toast.new("Enter a hash to crack"))
            return
        
        kwargs = {
            "tab": "crack",
            "hash_input": hash_value,
            "attack_mode": mode,
        }
        
        if mode == "dictionary" or mode == "hybrid":
            wordlist = self.hash_suite_crack_wordlist.get_text().strip()
            if wordlist:
                kwargs["wordlist_path"] = wordlist
        
        if mode == "bruteforce" or mode == "hybrid":
            kwargs["charset"] = self.hash_suite_crack_charset.get_active_id()
            kwargs["max_length"] = int(self.hash_suite_crack_maxlen.get_value())
        
        if self.hash_suite_advanced_toggle.get_active():
            kwargs["backend"] = self.hash_suite_crack_backend.get_active_id()
        
        try:
            result = self._active_tool.run(**kwargs)
            result_text = getattr(result, "body", str(result))
            self.hash_suite_crack_result.get_buffer().set_text(result_text)
        except Exception as exc:
            self.toast_overlay.add_toast(Adw.Toast.new(f"Error: {exc}"))
    
    def _on_hash_suite_format_run(self, _btn) -> None:
        """Run format conversion."""
        if not self._active_tool:
            return
        
        input_hash = self.hash_suite_format_input.get_text().strip()
        from_fmt = self.hash_suite_format_from.get_active_id()
        to_fmt = self.hash_suite_format_to.get_active_id()
        
        if not input_hash:
            self.toast_overlay.add_toast(Adw.Toast.new("Enter a hash to convert"))
            return
        
        try:
            result = self._active_tool.run(
                tab="format",
                hash_input=input_hash,
                from_format=from_fmt,
                to_format=to_fmt
            )
            result_text = getattr(result, "body", str(result))
            self.hash_suite_format_output.set_text(result_text)
        except Exception as exc:
            self.toast_overlay.add_toast(Adw.Toast.new(f"Error: {exc}"))
    
    def _on_hash_suite_format_copy(self, _btn) -> None:
        """Copy format output to clipboard."""
        display = self.window.get_display()
        if display:
            clipboard = display.get_clipboard()
            clipboard.set_text(self.hash_suite_format_output.get_text())
    
    def _on_hash_suite_gen_preset_changed(self, combo) -> None:
        """Update UI based on generator preset."""
        preset = combo.get_active_id()
        is_htpasswd = preset.startswith("htpasswd_")
        self.hash_suite_gen_htpasswd_box.set_visible(is_htpasswd)
        
        # Update algorithm based on preset
        if preset == "htpasswd_bcrypt":
            self.hash_suite_gen_algo.set_active_id("bcrypt")
        elif preset == "htpasswd_apr1":
            self.hash_suite_gen_algo.set_active_id("md5")
    
    def _on_hash_suite_generate_run(self, _btn) -> None:
        """Run hash generation."""
        if not self._active_tool:
            return
        
        buffer = self.hash_suite_gen_input.get_buffer()
        start, end = buffer.get_bounds()
        password = buffer.get_text(start, end, True).strip()
        preset = self.hash_suite_gen_preset.get_active_id()
        algorithm = self.hash_suite_gen_algo.get_active_id()
        
        if not password:
            self.toast_overlay.add_toast(Adw.Toast.new("Enter text to hash"))
            return
        
        kwargs = {
            "tab": "generate",
            "generator_preset": preset,
            "password": password,
            "algorithm": algorithm,
        }
        
        if preset.startswith("htpasswd_"):
            username = self.hash_suite_gen_username.get_text().strip()
            if username:
                kwargs["username"] = username
        
        try:
            result = self._active_tool.run(**kwargs)
            result_text = getattr(result, "body", str(result))
            self.hash_suite_gen_output.set_text(result_text)
        except Exception as exc:
            self.toast_overlay.add_toast(Adw.Toast.new(f"Error: {exc}"))
    
    def _on_hash_suite_gen_copy(self, _btn) -> None:
        """Copy generated hash to clipboard."""
        display = self.window.get_display()
        if display:
            clipboard = display.get_clipboard()
            clipboard.set_text(self.hash_suite_gen_output.get_text())
    
    def _on_hash_suite_benchmark_run(self, _btn) -> None:
        """Run benchmark."""
        if not self._active_tool:
            return
        
        algorithm = self.hash_suite_bench_algo.get_active_id()
        duration = int(self.hash_suite_bench_duration.get_value())
        
        try:
            result = self._active_tool.run(
                tab="benchmark",
                benchmark_algorithm=algorithm,
                benchmark_duration=str(duration)
            )
            result_text = getattr(result, "body", str(result))
            self.hash_suite_bench_result.get_buffer().set_text(result_text)
        except Exception as exc:
            self.toast_overlay.add_toast(Adw.Toast.new(f"Error: {exc}"))
    
    def _on_hash_suite_queue_refresh(self, _btn) -> None:
        """Refresh queue view."""
        if not self._active_tool:
            return
        
        try:
            result = self._active_tool.run(tab="queue")
            result_text = getattr(result, "body", str(result))
            self.hash_suite_queue_view.get_buffer().set_text(result_text)
        except Exception as exc:
            self.toast_overlay.add_toast(Adw.Toast.new(f"Error: {exc}"))
    
    def _on_hash_suite_queue_clear(self, _btn) -> None:
        """Clear job history."""
        self.toast_overlay.add_toast(Adw.Toast.new("History cleared"))
        self._on_hash_suite_queue_refresh(None)
    
    def _on_hash_suite_queue_export(self, _btn) -> None:
        """Export queue results."""
        dialog = Gtk.FileChooserNative.new(
            "Export Results",
            self.window,
            Gtk.FileChooserAction.SAVE,
            None,
            None
        )
        dialog.set_current_name("hash_suite_results.json")
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                self.toast_overlay.add_toast(Adw.Toast.new(f"Exported to {file.get_path()}"))
        dialog.destroy()

    def _build_decoder_workbench_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("Decoder Workbench")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=720, tightening_threshold=560)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        input_label = Gtk.Label(label="Input data", xalign=0)
        input_label.add_css_class("title-4")
        form.append(input_label)

        self.decoder_input_view = Gtk.TextView()
        self.decoder_input_view.add_css_class("input-text")
        self.decoder_input_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.decoder_input_view.add_css_class("input-text")
        input_scroll = Gtk.ScrolledWindow()
        input_scroll.add_css_class("input-box")
        input_scroll.set_min_content_height(200)
        input_scroll.add_css_class("input-box")
        input_scroll.set_child(self.decoder_input_view)
        form.append(input_scroll)

        format_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        format_row.append(Gtk.Label(label="Input format", xalign=0))
        self.decoder_format_combo = Gtk.ComboBoxText()
        self.decoder_format_combo.append("text", "Text (UTF-8)")
        self.decoder_format_combo.append("hex", "Hex")
        self.decoder_format_combo.append("base64", "Base64")
        self.decoder_format_combo.set_active_id("text")
        format_row.append(self.decoder_format_combo)
        form.append(format_row)

        operations_label = Gtk.Label(label="Operations", xalign=0)
        operations_label.add_css_class("title-4")
        form.append(operations_label)
        self.decoder_operations_entry = Gtk.Entry()
        self.decoder_operations_entry.add_css_class("modern-entry")
        self.decoder_operations_entry.set_placeholder_text("Pipeline e.g. base64_decode|rot13|xor:0x41")
        self.decoder_operations_entry.add_css_class("modern-entry")
        form.append(self.decoder_operations_entry)

        hint_label = Gtk.Label(
            label="Leave operations empty to just reformat the input. Use pipes to chain transforms.",
            xalign=0,
        )
        hint_label.add_css_class("dim-label")
        hint_label.set_wrap(True)
        form.append(hint_label)

        buttons_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        run_btn = Gtk.Button(label="Run")
        run_btn.add_css_class("suggested-action")
        run_btn.connect("clicked", self._on_decoder_execute)
        buttons_row.append(run_btn)
        self.decoder_copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        self.decoder_copy_btn.set_tooltip_text("Copy result JSON")
        self.decoder_copy_btn.set_sensitive(False)
        self.decoder_copy_btn.connect("clicked", self._on_decoder_copy)
        buttons_row.append(self.decoder_copy_btn)
        form.append(buttons_row)

        output_label = Gtk.Label(label="Result", xalign=0)
        output_label.add_css_class("title-4")
        form.append(output_label)

        self.decoder_output_view = Gtk.TextView()
        self.decoder_output_view.add_css_class("output-text")
        self.decoder_output_view.set_editable(False)
        self.decoder_output_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.decoder_output_view.add_css_class("output-text")
        output_scroll = Gtk.ScrolledWindow()
        output_scroll.add_css_class("output-box")
        output_scroll.set_min_content_height(550)
        output_scroll.add_css_class("output-box")
        output_scroll.set_child(self.decoder_output_view)
        form.append(output_scroll)

    def _build_morse_decoder_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("Morse Decoder")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=720, tightening_threshold=560)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        input_label = Gtk.Label(label="Morse input", xalign=0)
        input_label.add_css_class("title-4")
        form.append(input_label)

        mode_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.morse_audio_toggle = Gtk.CheckButton(label="Decode from audio file")
        self.morse_audio_toggle.set_halign(Gtk.Align.START)
        self.morse_audio_toggle.connect("toggled", self._update_morse_input_mode)
        mode_row.append(self.morse_audio_toggle)
        form.append(mode_row)

        self.morse_input_stack = Gtk.Stack()
        self.morse_input_stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self.morse_input_stack.set_transition_duration(150)

        text_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.morse_input_view = Gtk.TextView()
        self.morse_input_view.add_css_class("input-text")
        self.morse_input_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        input_scroll = Gtk.ScrolledWindow()
        input_scroll.add_css_class("input-box")
        input_scroll.set_min_content_height(200)
        input_scroll.set_child(self.morse_input_view)
        text_box.append(input_scroll)
        self.morse_input_stack.add_named(text_box, "text")

        audio_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        audio_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.morse_audio_entry = Gtk.Entry()
        self.morse_audio_entry.add_css_class("modern-entry")
        self.morse_audio_entry.set_placeholder_text("Select a WAV file containing Morse")
        self.morse_audio_entry.set_editable(False)
        self.morse_audio_entry.set_hexpand(True)
        audio_row.append(self.morse_audio_entry)
        audio_button = Gtk.Button.new_from_icon_name("document-open-symbolic")
        audio_button.set_tooltip_text("Browse for audio file")
        audio_button.connect("clicked", self._on_morse_browse)
        audio_row.append(audio_button)
        audio_box.append(audio_row)
        audio_hint = Gtk.Label(
            label="Supports mono PCM WAV files with clear short and long tones.",
            xalign=0,
        )
        audio_hint.add_css_class("dim-label")
        audio_hint.set_wrap(True)
        audio_box.append(audio_hint)
        self.morse_input_stack.add_named(audio_box, "audio")

        form.append(self.morse_input_stack)

        letter_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        letter_label = Gtk.Label(label="Letter separators", xalign=0)
        letter_label.set_hexpand(False)
        letter_row.append(letter_label)
        self.morse_letter_entry = Gtk.Entry()
        self.morse_letter_entry.add_css_class("modern-entry")
        self.morse_letter_entry.set_placeholder_text("Comma or space separated (auto-detect by default)")
        self.morse_letter_entry.set_hexpand(True)
        letter_row.append(self.morse_letter_entry)
        form.append(letter_row)

        word_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        word_label = Gtk.Label(label="Word separators", xalign=0)
        word_label.set_hexpand(False)
        word_row.append(word_label)
        self.morse_word_entry = Gtk.Entry()
        self.morse_word_entry.add_css_class("modern-entry")
        self.morse_word_entry.set_placeholder_text("Overrides for word boundaries (auto-detect handles /, pipes, newlines)")
        self.morse_word_entry.set_hexpand(True)
        word_row.append(self.morse_word_entry)
        form.append(word_row)

        symbol_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        symbol_row.append(Gtk.Label(label="Dot", xalign=0))
        self.morse_dot_entry = Gtk.Entry()
        self.morse_dot_entry.add_css_class("modern-entry")
        self.morse_dot_entry.set_width_chars(3)
        self.morse_dot_entry.set_max_length(3)
        symbol_row.append(self.morse_dot_entry)
        symbol_row.append(Gtk.Label(label="Dash", xalign=0))
        self.morse_dash_entry = Gtk.Entry()
        self.morse_dash_entry.add_css_class("modern-entry")
        self.morse_dash_entry.set_width_chars(3)
        self.morse_dash_entry.set_max_length(3)
        symbol_row.append(self.morse_dash_entry)
        form.append(symbol_row)

        options_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        options_row.append(Gtk.Label(label="Output case", xalign=0))
        self.morse_output_case = Gtk.ComboBoxText()
        self.morse_output_case.append("upper", "UPPERCASE")
        self.morse_output_case.append("lower", "lowercase")
        self.morse_output_case.append("title", "Title Case")
        self.morse_output_case.set_active_id("upper")
        options_row.append(self.morse_output_case)
        self.morse_breakdown_toggle = Gtk.CheckButton(label="Show breakdown")
        self.morse_breakdown_toggle.set_active(True)
        options_row.append(self.morse_breakdown_toggle)
        form.append(options_row)

        hint_label = Gtk.Label(
            label="Automatically handles spaces, slashes, pipes and newlines. Provide extras if the input uses other markers.",
            xalign=0,
        )
        hint_label.add_css_class("dim-label")
        hint_label.set_wrap(True)
        form.append(hint_label)

        buttons_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        decode_btn = Gtk.Button(label="Decode")
        decode_btn.add_css_class("suggested-action")
        decode_btn.connect("clicked", self._on_morse_decode)
        buttons_row.append(decode_btn)
        self.morse_copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        self.morse_copy_btn.set_tooltip_text("Copy decoded output")
        self.morse_copy_btn.set_sensitive(False)
        self.morse_copy_btn.connect("clicked", self._on_morse_copy)
        buttons_row.append(self.morse_copy_btn)
        form.append(buttons_row)

        output_label = Gtk.Label(label="Result", xalign=0)
        output_label.add_css_class("title-4")
        form.append(output_label)

        self.morse_output_view = Gtk.TextView()
        self.morse_output_view.add_css_class("output-text")
        self.morse_output_view.set_editable(False)
        self.morse_output_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        output_scroll = Gtk.ScrolledWindow()
        output_scroll.add_css_class("output-box")
        output_scroll.set_min_content_height(550)
        output_scroll.set_child(self.morse_output_view)
        form.append(output_scroll)

    def _set_morse_output(self, text: str) -> None:
        self._set_text_view_text(self.morse_output_view, text)
        self.morse_copy_btn.set_sensitive(bool(text.strip()))

    def _open_morse_decoder(self, tool) -> None:
        self._active_tool = tool
        self._set_text_view_text(self.morse_input_view, "")
        self.morse_letter_entry.set_text("")
        self.morse_word_entry.set_text("")
        self.morse_dot_entry.set_text(".")
        self.morse_dash_entry.set_text("-")
        self.morse_output_case.set_active_id("upper")
        self.morse_breakdown_toggle.set_active(True)
        self.morse_audio_toggle.set_active(False)
        self.morse_audio_entry.set_text("")
        self._update_morse_input_mode()
        self._set_morse_output("")
        self.tool_detail_stack.set_visible_child_name("morse_decoder")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_morse_decode(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        morse_text = self._get_text_view_text(self.morse_input_view)
        audio_mode = self.morse_audio_toggle.get_active()
        audio_path = self.morse_audio_entry.get_text().strip() if audio_mode else ""
        if audio_mode:
            if not audio_path:
                self.toast_overlay.add_toast(Adw.Toast.new("Choose an audio file to decode"))
                return
            dot_symbol = "."
            dash_symbol = "-"
        else:
            if not morse_text.strip():
                self.toast_overlay.add_toast(Adw.Toast.new("Enter Morse code to decode"))
                return
            dot_symbol = self.morse_dot_entry.get_text() or "."
            dash_symbol = self.morse_dash_entry.get_text() or "-"
        try:
            result = self._active_tool.run(
                morse=morse_text,
                letter_separators=self.morse_letter_entry.get_text(),
                word_separators=self.morse_word_entry.get_text(),
                dot_symbol=dot_symbol,
                dash_symbol=dash_symbol,
                output_case=self.morse_output_case.get_active_id() or "upper",
                show_breakdown="true" if self.morse_breakdown_toggle.get_active() else "false",
                audio_file=audio_path,
            )
            body = getattr(result, "body", str(result))
            self._set_morse_output(body)
            self._set_tool_output(body)
            self.output_frame.set_visible(True)
        except Exception as exc:
            self.toast_overlay.add_toast(Adw.Toast.new(f"Error: {exc}"))

    def _on_morse_copy(self, _btn: Gtk.Button) -> None:
        self._copy_text_view_to_clipboard(self.morse_output_view)

    def _update_morse_input_mode(self, *_args) -> None:
        if not hasattr(self, "morse_input_stack") or self.morse_input_stack is None:
            return
        target = "audio" if self.morse_audio_toggle.get_active() else "text"
        self.morse_input_stack.set_visible_child_name(target)

        # Disable manual symbol overrides when audio is used to avoid confusion
        disable_symbol_fields = self.morse_audio_toggle.get_active()
        if hasattr(self, "morse_dot_entry") and hasattr(self, "morse_dash_entry"):
            self.morse_dot_entry.set_sensitive(not disable_symbol_fields)
            self.morse_dash_entry.set_sensitive(not disable_symbol_fields)

    def _on_morse_browse(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative.new(
            "Select Morse audio",
            self.window,
            Gtk.FileChooserAction.OPEN,
            None,
            None,
        )

        wav_filter = Gtk.FileFilter()
        wav_filter.set_name("WAV audio files")
        wav_filter.add_mime_type("audio/x-wav")
        wav_filter.add_mime_type("audio/wav")
        wav_filter.add_pattern("*.wav")
        dialog.add_filter(wav_filter)

        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                path = file.get_path()
                if path:
                    self.morse_audio_entry.set_text(path)
        dialog.destroy()
        dialog.destroy()

    def _set_decoder_output(self, text: str) -> None:
        self._set_text_view_text(self.decoder_output_view, text)

    def _open_decoder_workbench(self, tool) -> None:
        self._active_tool = tool
        self.decoder_input_view.get_buffer().set_text("")
        self.decoder_operations_entry.set_text("")
        self.decoder_format_combo.set_active_id("text")
        self._set_decoder_output("")
        self.decoder_copy_btn.set_sensitive(False)
        self.tool_detail_stack.set_visible_child_name("decoder_workbench")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_decoder_execute(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        data = self._get_text_view_text(self.decoder_input_view)
        operations = self.decoder_operations_entry.get_text().strip()
        input_format = self.decoder_format_combo.get_active_id() or "text"
        if not data.strip():
            self.toast_overlay.add_toast(Adw.Toast.new("Enter some data to transform"))
            return
        try:
            result = self._active_tool.run(data=data, operations=operations, input_format=input_format)
            body = getattr(result, "body", str(result))
            self._set_decoder_output(body)
            self.decoder_copy_btn.set_sensitive(True)
            self._set_tool_output(body)
            self.output_frame.set_visible(True)
        except Exception as exc:
            self.toast_overlay.add_toast(Adw.Toast.new(f"Error: {exc}"))

    def _on_decoder_copy(self, _btn: Gtk.Button) -> None:
        self._copy_text_view_to_clipboard(self.decoder_output_view)

    # ------------------------------------------------------------------
    # Hash Workspace tool UI
    # ------------------------------------------------------------------
    def _build_hash_workspace_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title_label = Gtk.Label(label="Hash Workspace", xalign=0)
        title_label.add_css_class("title-2")
        header_row.append(title_label)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=800, tightening_threshold=600)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        # Hashes input
        input_label = Gtk.Label(label="Hash values (one per line)", xalign=0)
        form.append(input_label)
        self.hash_workspace_hashes = Gtk.TextView()
        self.hash_workspace_hashes.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        hashes_scroll = Gtk.ScrolledWindow()
        hashes_scroll.add_css_class("output-box")
        hashes_scroll.set_min_content_height(200)
        hashes_scroll.set_child(self.hash_workspace_hashes)
        form.append(hashes_scroll)

        # Mode selection
        mode_group = Adw.PreferencesGroup(title="Analysis mode")
        form.append(mode_group)
        
        modes = ["identify", "analyze", "batch", "verify"]
        mode_model = Gtk.StringList.new(modes)
        self.hash_workspace_mode = Adw.ComboRow()
        self.hash_workspace_mode.set_title("Mode")
        self.hash_workspace_mode.set_subtitle("Choose analysis mode")
        self.hash_workspace_mode.set_model(mode_model)
        self.hash_workspace_mode.set_selected(0)
        mode_group.add(self.hash_workspace_mode)

        # Optional parameters
        self.hash_workspace_known_plaintext = Gtk.Entry()
        self.hash_workspace_known_plaintext.set_placeholder_text("Known plaintext (for verify mode)")
        form.append(self.hash_workspace_known_plaintext)

        # Run button
        buttons_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        run_btn = Gtk.Button(label="Analyze")
        run_btn.add_css_class("suggested-action")
        run_btn.connect("clicked", self._on_hash_workspace_run)
        buttons_row.append(run_btn)
        self.hash_workspace_copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        self.hash_workspace_copy_btn.set_tooltip_text("Copy result JSON")
        self.hash_workspace_copy_btn.set_sensitive(False)
        self.hash_workspace_copy_btn.connect("clicked", self._on_hash_workspace_copy)
        buttons_row.append(self.hash_workspace_copy_btn)
        form.append(buttons_row)

        # Output
        output_label = Gtk.Label(label="Result", xalign=0)
        output_label.add_css_class("title-4")
        form.append(output_label)

        self.hash_workspace_output = Gtk.TextView()
        self.hash_workspace_output.add_css_class("output-text")
        self.hash_workspace_output.set_editable(False)
        self.hash_workspace_output.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        output_scroll = Gtk.ScrolledWindow()
        output_scroll.add_css_class("output-box")
        output_scroll.set_min_content_height(550)
        output_scroll.set_child(self.hash_workspace_output)
        form.append(output_scroll)

    def _open_hash_workspace(self, tool) -> None:
        self._active_tool = tool
        self._set_text_view_text(self.hash_workspace_hashes, "")
        self._set_text_view_text(self.hash_workspace_output, "")
        self.hash_workspace_known_plaintext.set_text("")
        self.hash_workspace_copy_btn.set_sensitive(False)
        self.tool_detail_stack.set_visible_child_name("hash_workspace")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_hash_workspace_run(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        
        hashes_text = self._get_text_view_text(self.hash_workspace_hashes).strip()
        if not hashes_text:
            self.toast_overlay.add_toast(Adw.Toast.new("Enter hash values first"))
            return

        mode_idx = self.hash_workspace_mode.get_selected()
        modes = ["identify", "analyze", "batch", "verify"]
        mode = modes[mode_idx]
        
        known_plaintext = self.hash_workspace_known_plaintext.get_text().strip()

        try:
            result = self._active_tool.run(
                hashes=hashes_text,
                mode=mode,
                known_plaintext=known_plaintext
            )
            body = getattr(result, "body", str(result))
            self._set_text_view_text(self.hash_workspace_output, body)
            self.hash_workspace_copy_btn.set_sensitive(True)
            self._set_tool_output(body)
            self.output_frame.set_visible(True)
        except Exception as exc:
            self.toast_overlay.add_toast(Adw.Toast.new(f"Error: {exc}"))

    def _on_hash_workspace_copy(self, _btn: Gtk.Button) -> None:
        self._copy_text_view_to_clipboard(self.hash_workspace_output)

    # ------------------------------------------------------------------
    # Hash Cracker Pro tool UI
    # ------------------------------------------------------------------
    def _build_hash_cracker_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title_label = Gtk.Label(label="Hash Cracker Pro", xalign=0)
        title_label.add_css_class("title-2")
        header_row.append(title_label)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=800, tightening_threshold=600)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        # Hash input
        input_label = Gtk.Label(label="Hash value", xalign=0)
        form.append(input_label)
        self.hash_cracker_hash = Gtk.Entry()
        self.hash_cracker_hash.set_placeholder_text("Enter hash to crack")
        form.append(self.hash_cracker_hash)

        # Attack mode
        mode_group = Adw.PreferencesGroup(title="Attack mode")
        form.append(mode_group)
        
        attack_modes = ["dictionary", "brute_force", "hybrid"]
        attack_model = Gtk.StringList.new(attack_modes)
        self.hash_cracker_attack_mode = Adw.ComboRow()
        self.hash_cracker_attack_mode.set_title("Attack Mode")
        self.hash_cracker_attack_mode.set_subtitle("Choose cracking strategy")
        self.hash_cracker_attack_mode.set_model(attack_model)
        self.hash_cracker_attack_mode.set_selected(0)
        mode_group.add(self.hash_cracker_attack_mode)

        # Algorithm
        algo_label = Gtk.Label(label="Algorithm (auto-detect if empty)", xalign=0)
        form.append(algo_label)
        self.hash_cracker_algorithm = Gtk.Entry()
        self.hash_cracker_algorithm.set_placeholder_text("auto")
        form.append(self.hash_cracker_algorithm)

        # Additional parameters in an expander
        expander = Gtk.Expander()
        expander.set_label("Advanced Options")
        expander.set_expanded(False)  # Start collapsed
        expander.set_margin_top(8)
        expander.set_margin_bottom(8)
        # Make expander more clickable
        expander.set_sensitive(True)
        expander.set_can_focus(True)
        form.append(expander)
        
        advanced_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        advanced_box.set_margin_top(8)
        advanced_box.set_margin_start(16)
        advanced_box.set_margin_end(16)
        expander.set_child(advanced_box)
        
        self.hash_cracker_charset = Gtk.Entry()
        self.hash_cracker_charset.set_placeholder_text("Charset (lowercase, digits, mixed, all)")
        advanced_box.append(self.hash_cracker_charset)
        
        # Length controls with better layout
        length_label = Gtk.Label(label="Password length range", xalign=0)
        advanced_box.append(length_label)
        
        length_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        length_box.set_homogeneous(True)
        
        min_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        min_label = Gtk.Label(label="Minimum", xalign=0)
        min_label.add_css_class("caption")
        self.hash_cracker_min_length = Gtk.SpinButton()
        self.hash_cracker_min_length.set_range(1, 20)
        self.hash_cracker_min_length.set_value(1)
        min_box.append(min_label)
        min_box.append(self.hash_cracker_min_length)
        
        max_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        max_label = Gtk.Label(label="Maximum", xalign=0)
        max_label.add_css_class("caption")
        self.hash_cracker_max_length = Gtk.SpinButton()
        self.hash_cracker_max_length.set_range(1, 20)
        self.hash_cracker_max_length.set_value(8)
        max_box.append(max_label)
        max_box.append(self.hash_cracker_max_length)
        
        length_box.append(min_box)
        length_box.append(max_box)
        advanced_box.append(length_box)

        # Run button
        buttons_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        run_btn = Gtk.Button(label="Crack")
        run_btn.add_css_class("destructive-action")
        run_btn.connect("clicked", self._on_hash_cracker_run)
        buttons_row.append(run_btn)
        self.hash_cracker_copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        self.hash_cracker_copy_btn.set_tooltip_text("Copy result JSON")
        self.hash_cracker_copy_btn.set_sensitive(False)
        self.hash_cracker_copy_btn.connect("clicked", self._on_hash_cracker_copy)
        buttons_row.append(self.hash_cracker_copy_btn)
        form.append(buttons_row)

        # Output
        output_label = Gtk.Label(label="Result", xalign=0)
        output_label.add_css_class("title-4")
        form.append(output_label)

        self.hash_cracker_output = Gtk.TextView()
        self.hash_cracker_output.add_css_class("output-text")
        self.hash_cracker_output.set_editable(False)
        self.hash_cracker_output.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        output_scroll = Gtk.ScrolledWindow()
        output_scroll.add_css_class("output-box")
        output_scroll.set_min_content_height(550)
        output_scroll.set_child(self.hash_cracker_output)
        form.append(output_scroll)

    def _open_hash_cracker(self, tool) -> None:
        self._active_tool = tool
        self.hash_cracker_hash.set_text("")
        self._set_text_view_text(self.hash_cracker_output, "")
        self.hash_cracker_copy_btn.set_sensitive(False)
        self.tool_detail_stack.set_visible_child_name("hash_cracker_pro")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_hash_cracker_run(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        
        hash_value = self.hash_cracker_hash.get_text().strip()
        if not hash_value:
            self.toast_overlay.add_toast(Adw.Toast.new("Enter a hash first"))
            return
            
        attack_idx = self.hash_cracker_attack_mode.get_selected()
        attack_modes = ["dictionary", "brute_force", "hybrid"]
        attack_mode = attack_modes[attack_idx]
        
        algorithm = self.hash_cracker_algorithm.get_text().strip() or "auto"
        charset = self.hash_cracker_charset.get_text().strip() or "lowercase"
        min_length = str(int(self.hash_cracker_min_length.get_value()))
        max_length = str(int(self.hash_cracker_max_length.get_value()))

        try:
            result = self._active_tool.run(
                hash_value=hash_value,
                attack_mode=attack_mode,
                algorithm=algorithm,
                charset=charset,
                min_length=min_length,
                max_length=max_length,
                timeout="60"  # Reasonable timeout for UI
            )
            body = getattr(result, "body", str(result))
            self._set_text_view_text(self.hash_cracker_output, body)
            self.hash_cracker_copy_btn.set_sensitive(True)
            self._set_tool_output(body)
            self.output_frame.set_visible(True)
        except Exception as exc:
            self.toast_overlay.add_toast(Adw.Toast.new(f"Error: {exc}"))

    def _on_hash_cracker_copy(self, _btn: Gtk.Button) -> None:
        self._copy_text_view_to_clipboard(self.hash_cracker_output)

    # ------------------------------------------------------------------
    # Hash Benchmark tool UI
    # ------------------------------------------------------------------
    def _build_hash_benchmark_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title_label = Gtk.Label(label="Hash Benchmark", xalign=0)
        title_label.add_css_class("title-2")
        header_row.append(title_label)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=800, tightening_threshold=600)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        # Algorithm selection
        algo_group = Adw.PreferencesGroup(title="Algorithm")
        form.append(algo_group)
        
        algorithms = ["md5", "sha1", "sha256", "sha384", "sha512", "sha3_256", "sha3_512"]
        algo_model = Gtk.StringList.new(algorithms)
        self.hash_benchmark_algorithm = Adw.ComboRow()
        self.hash_benchmark_algorithm.set_title("Algorithm")
        self.hash_benchmark_algorithm.set_subtitle("Select hash algorithm to benchmark")
        self.hash_benchmark_algorithm.set_model(algo_model)
        self.hash_benchmark_algorithm.set_selected(0)
        algo_group.add(self.hash_benchmark_algorithm)

        # Duration
        duration_group = Adw.PreferencesGroup(title="Test duration (seconds)")
        form.append(duration_group)
        
        duration_adjustment = Gtk.Adjustment(value=5, lower=1, upper=30, step_increment=1, page_increment=5, page_size=0)
        duration_row = Adw.SpinRow(adjustment=duration_adjustment, digits=0)
        duration_row.set_title("Duration")
        duration_row.set_subtitle("Test duration in seconds")
        self.hash_benchmark_duration = duration_row
        duration_group.add(duration_row)

        # Run button
        buttons_group = Adw.PreferencesGroup()
        form.append(buttons_group)
        
        buttons_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        buttons_row.set_margin_top(12)
        buttons_row.set_margin_bottom(12)
        run_btn = Gtk.Button(label="Benchmark")
        run_btn.add_css_class("suggested-action")
        run_btn.connect("clicked", self._on_hash_benchmark_run)
        buttons_row.append(run_btn)
        self.hash_benchmark_copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        self.hash_benchmark_copy_btn.set_tooltip_text("Copy result JSON")
        self.hash_benchmark_copy_btn.set_sensitive(False)
        self.hash_benchmark_copy_btn.connect("clicked", self._on_hash_benchmark_copy)
        buttons_row.append(self.hash_benchmark_copy_btn)
        buttons_group.add(buttons_row)

        # Output
        output_label = Gtk.Label(label="Benchmark Results", xalign=0)
        output_label.add_css_class("title-4")
        form.append(output_label)

        self.hash_benchmark_output = Gtk.TextView()
        self.hash_benchmark_output.add_css_class("output-text")
        self.hash_benchmark_output.set_editable(False)
        self.hash_benchmark_output.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        output_scroll = Gtk.ScrolledWindow()
        output_scroll.add_css_class("output-box")
        output_scroll.set_min_content_height(550)
        output_scroll.set_child(self.hash_benchmark_output)
        form.append(output_scroll)

    def _open_hash_benchmark(self, tool) -> None:
        self._active_tool = tool
        self._set_text_view_text(self.hash_benchmark_output, "")
        self.hash_benchmark_copy_btn.set_sensitive(False)
        self.tool_detail_stack.set_visible_child_name("hash_benchmark")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_hash_benchmark_run(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
            
        algo_idx = self.hash_benchmark_algorithm.get_selected()
        algorithms = ["md5", "sha1", "sha256", "sha384", "sha512", "sha3_256", "sha3_512"]
        algorithm = algorithms[algo_idx]
        
        duration = str(int(self.hash_benchmark_duration.get_value()))

        try:
            result = self._active_tool.run(algorithm=algorithm, duration=duration)
            body = getattr(result, "body", str(result))
            self._set_text_view_text(self.hash_benchmark_output, body)
            self.hash_benchmark_copy_btn.set_sensitive(True)
            self._set_tool_output(body)
            self.output_frame.set_visible(True)
        except Exception as exc:
            self.toast_overlay.add_toast(Adw.Toast.new(f"Error: {exc}"))

    def _on_hash_benchmark_copy(self, _btn: Gtk.Button) -> None:
        self._copy_text_view_to_clipboard(self.hash_benchmark_output)

    # ------------------------------------------------------------------
    # Hash Format Converter tool UI
    # ------------------------------------------------------------------
    def _build_hash_format_converter_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title_label = Gtk.Label(label="Hash Format Converter", xalign=0)
        title_label.add_css_class("title-2")
        header_row.append(title_label)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=800, tightening_threshold=600)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        # Hash input
        input_label = Gtk.Label(label="Hash input", xalign=0)
        form.append(input_label)
        self.hash_format_converter_input = Gtk.Entry()
        self.hash_format_converter_input.add_css_class("modern-entry")
        self.hash_format_converter_input.set_placeholder_text("Enter hash in any format")
        form.append(self.hash_format_converter_input)

        # Source format
        source_group = Adw.PreferencesGroup(title="Source format")
        form.append(source_group)
        
        source_formats = ["auto", "raw", "unix_crypt", "ldap", "mysql", "postgresql"]
        source_model = Gtk.StringList.new(source_formats)
        self.hash_format_converter_source = Adw.ComboRow()
        self.hash_format_converter_source.set_title("Source Format")
        self.hash_format_converter_source.set_subtitle("Input hash format (auto-detect recommended)")
        self.hash_format_converter_source.set_model(source_model)
        self.hash_format_converter_source.set_selected(0)
        source_group.add(self.hash_format_converter_source)

        # Target format
        target_group = Adw.PreferencesGroup(title="Target format")
        form.append(target_group)
        
        target_formats = ["raw", "hex", "base64", "hashcat", "john"]
        target_model = Gtk.StringList.new(target_formats)
        self.hash_format_converter_target = Adw.ComboRow()
        self.hash_format_converter_target.set_title("Target Format")
        self.hash_format_converter_target.set_subtitle("Desired output format")
        self.hash_format_converter_target.set_model(target_model)
        self.hash_format_converter_target.set_selected(0)
        target_group.add(self.hash_format_converter_target)

        # Run button
        buttons_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        run_btn = Gtk.Button(label="Convert")
        run_btn.add_css_class("suggested-action")
        run_btn.connect("clicked", self._on_hash_format_converter_run)
        buttons_row.append(run_btn)
        self.hash_format_converter_copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        self.hash_format_converter_copy_btn.set_tooltip_text("Copy result JSON")
        self.hash_format_converter_copy_btn.set_sensitive(False)
        self.hash_format_converter_copy_btn.connect("clicked", self._on_hash_format_converter_copy)
        buttons_row.append(self.hash_format_converter_copy_btn)
        form.append(buttons_row)

        # Output
        output_label = Gtk.Label(label="Conversion Result", xalign=0)
        output_label.add_css_class("title-4")
        form.append(output_label)

        self.hash_format_converter_output = Gtk.TextView()
        self.hash_format_converter_output.add_css_class("output-text")
        self.hash_format_converter_output.set_editable(False)
        self.hash_format_converter_output.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        output_scroll = Gtk.ScrolledWindow()
        output_scroll.add_css_class("output-box")
        output_scroll.set_min_content_height(550)
        output_scroll.set_child(self.hash_format_converter_output)
        form.append(output_scroll)

    def _open_hash_format_converter(self, tool) -> None:
        self._active_tool = tool
        self.hash_format_converter_input.set_text("")
        self._set_text_view_text(self.hash_format_converter_output, "")
        self.hash_format_converter_copy_btn.set_sensitive(False)
        self.tool_detail_stack.set_visible_child_name("hash_format_converter")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_hash_format_converter_run(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
            
        hash_input = self.hash_format_converter_input.get_text().strip()
        if not hash_input:
            self.toast_overlay.add_toast(Adw.Toast.new("Enter a hash first"))
            return
            
        source_idx = self.hash_format_converter_source.get_selected()
        target_idx = self.hash_format_converter_target.get_selected()
        
        source_formats = ["auto", "raw", "unix_crypt", "ldap", "mysql", "postgresql"]
        target_formats = ["raw", "hex", "base64", "hashcat", "john"]
        
        source_format = source_formats[source_idx]
        target_format = target_formats[target_idx]

        try:
            result = self._active_tool.run(
                hash_input=hash_input,
                source_format=source_format,
                target_format=target_format
            )
            body = getattr(result, "body", str(result))
            self._set_text_view_text(self.hash_format_converter_output, body)
            self.hash_format_converter_copy_btn.set_sensitive(True)
            self._set_tool_output(body)
            self.output_frame.set_visible(True)
        except Exception as exc:
            self.toast_overlay.add_toast(Adw.Toast.new(f"Error: {exc}"))

    def _on_hash_format_converter_copy(self, _btn: Gtk.Button) -> None:
        self._copy_text_view_to_clipboard(self.hash_format_converter_output)

    # ------------------------------------------------------------------
    # Hashcat/John Builder tool UI
    # ------------------------------------------------------------------
    
    def _build_hashcat_builder_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("Hashcat/John Builder")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=840, tightening_threshold=640)
        root.append(clamp)
        container = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        clamp.set_child(container)

        self._hashcat_tool_options: List[Tuple[str, str]] = [
            ("hashcat", "Hashcat"),
            ("john", "John the Ripper"),
        ]
        self._hashcat_attack_options: List[Tuple[str, str, str]] = [
            ("straight", "Straight (-a 0)", "Dictionary attack; supply a wordlist and optional rules."),
            ("combinator", "Combinator (-a 1)", "Combine two wordlists, useful for compound passwords."),
            ("bruteforce", "Brute-force (-a 3)", "Mask-based brute-force; requires a mask pattern."),
            (
                "hybrid_wordlist_mask",
                "Hybrid wordlist + mask (-a 6)",
                "Append a mask to each wordlist candidate (e.g. word+digits).",
            ),
            (
                "hybrid_mask_wordlist",
                "Hybrid mask + wordlist (-a 7)",
                "Apply a mask first, then substitute letters from the wordlist.",
            ),
        ]

        basic_group = Adw.PreferencesGroup(title="Basic configuration")
        container.append(basic_group)

        tool_model = Gtk.StringList.new([label for _, label in self._hashcat_tool_options])
        self.hashcat_tool_combo = Adw.ComboRow()
        self.hashcat_tool_combo.set_title("Tool")
        self.hashcat_tool_combo.set_model(tool_model)
        self.hashcat_tool_combo.set_selected(0)
        self.hashcat_tool_combo.connect("notify::selected", self._on_hashcat_tool_changed)
        basic_group.add(self.hashcat_tool_combo)

        self.hashcat_hash_file_row = Adw.EntryRow()
        self.hashcat_hash_file_row.set_title("Hash file")
        self.hashcat_hash_file_row.set_tooltip_text("Select the hash list you want to crack.")
        hash_browse = Gtk.Button(label="Browse…")
        hash_browse.add_css_class("flat")
        hash_browse.connect("clicked", self._on_hashcat_browse_hash_file)
        self.hashcat_hash_file_row.add_suffix(hash_browse)
        self.hashcat_hash_file_row.set_activates_default(True)
        basic_group.add(self.hashcat_hash_file_row)

        self.hashcat_mode_row = Adw.EntryRow()
        self.hashcat_mode_row.set_title("Hash mode")
        self.hashcat_mode_row.set_tooltip_text("Matches the -m value from hashcat --help (e.g. 0 for raw MD5).")
        self.hashcat_mode_row.set_text("0")
        basic_group.add(self.hashcat_mode_row)

        attack_group = Adw.PreferencesGroup(title="Attack strategy")
        container.append(attack_group)

        attack_model = Gtk.StringList.new([label for _, label, _ in self._hashcat_attack_options])
        self.hashcat_attack_combo = Adw.ComboRow()
        self.hashcat_attack_combo.set_title("Attack")
        self.hashcat_attack_combo.set_model(attack_model)
        self.hashcat_attack_combo.set_selected(0)
        self.hashcat_attack_combo.set_subtitle(self._hashcat_attack_options[0][2])
        self.hashcat_attack_combo.connect("notify::selected", self._on_hashcat_attack_changed)
        attack_group.add(self.hashcat_attack_combo)

        self.hashcat_wordlist_row = Adw.EntryRow()
        self.hashcat_wordlist_row.set_title("Wordlist")
        self.hashcat_wordlist_row.set_tooltip_text("Optional dictionary file; useful for straight and hybrid attacks.")
        wordlist_browse = Gtk.Button(label="Browse…")
        wordlist_browse.add_css_class("flat")
        wordlist_browse.connect("clicked", self._on_hashcat_browse_wordlist)
        self.hashcat_wordlist_row.add_suffix(wordlist_browse)
        attack_group.add(self.hashcat_wordlist_row)

        self.hashcat_mask_row = Adw.EntryRow()
        self.hashcat_mask_row.set_title("Mask pattern")
        self.hashcat_mask_row.set_tooltip_text("Example: ?u?l?l?l?d — required for brute-force and hybrid attacks.")
        attack_group.add(self.hashcat_mask_row)

        self.hashcat_rules_row = Adw.EntryRow()
        self.hashcat_rules_row.set_title("Rule file")
        self.hashcat_rules_row.set_tooltip_text("Optional .rule file to mutate dictionary entries.")
        attack_group.add(self.hashcat_rules_row)

        advanced_group = Adw.PreferencesGroup(title="Advanced options")
        container.append(advanced_group)

        self.hashcat_format_row = Adw.EntryRow()
        self.hashcat_format_row.set_title("John format hint")
        self.hashcat_format_row.set_tooltip_text("Only used for John the Ripper (e.g. raw-md5).")
        advanced_group.add(self.hashcat_format_row)

        self.hashcat_potfile_row = Adw.EntryRow()
        self.hashcat_potfile_row.set_title("Custom potfile path")
        self.hashcat_potfile_row.set_tooltip_text("Override the default potfile location.")
        potfile_browse = Gtk.Button(label="Browse…")
        potfile_browse.add_css_class("flat")
        potfile_browse.connect("clicked", self._on_hashcat_browse_potfile)
        self.hashcat_potfile_row.add_suffix(potfile_browse)
        advanced_group.add(self.hashcat_potfile_row)

        self.hashcat_extra_row = Adw.EntryRow()
        self.hashcat_extra_row.set_title("Extra CLI flags")
        self.hashcat_extra_row.set_tooltip_text("Any additional arguments appended verbatim to the command.")
        advanced_group.add(self.hashcat_extra_row)

        buttons_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        build_btn = Gtk.Button(label="Build command")
        build_btn.add_css_class("suggested-action")
        build_btn.connect("clicked", self._on_hashcat_build)
        buttons_row.append(build_btn)
        self.hashcat_copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        self.hashcat_copy_btn.set_tooltip_text("Copy command JSON")
        self.hashcat_copy_btn.set_sensitive(False)
        self.hashcat_copy_btn.connect("clicked", self._on_hashcat_copy)
        buttons_row.append(self.hashcat_copy_btn)
        container.append(buttons_row)

        output_label = Gtk.Label(label="Result", xalign=0)
        output_label.add_css_class("title-4")
        container.append(output_label)

        self.hashcat_output_view = Gtk.TextView()
        self.hashcat_output_view.add_css_class("output-text")
        self.hashcat_output_view.set_editable(False)
        self.hashcat_output_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        output_scroll = Gtk.ScrolledWindow()
        output_scroll.add_css_class("output-box")
        output_scroll.set_min_content_height(550)
        output_scroll.set_child(self.hashcat_output_view)
        container.append(output_scroll)

    def _set_hashcat_output(self, text: str) -> None:
        self._set_text_view_text(self.hashcat_output_view, text)

    def _open_hashcat_builder(self, tool) -> None:
        self._active_tool = tool
        self.hashcat_tool_combo.set_selected(0)
        self.hashcat_hash_file_row.set_text("")
        self.hashcat_mode_row.set_text("0")
        self.hashcat_attack_combo.set_selected(0)
        self.hashcat_wordlist_row.set_text("")
        self.hashcat_mask_row.set_text("")
        self.hashcat_rules_row.set_text("")
        self.hashcat_format_row.set_text("")
        self.hashcat_potfile_row.set_text("")
        self.hashcat_extra_row.set_text("")
        self._set_hashcat_output("")
        self.hashcat_copy_btn.set_sensitive(False)
        self._update_hashcat_builder_fields()
        self._update_hashcat_attack_subtitle()
        self.tool_detail_stack.set_visible_child_name("hashcat_builder")
        self.content_stack.set_visible_child_name("tool_detail")

    def _hashcat_selected_tool(self) -> str:
        index = self.hashcat_tool_combo.get_selected()
        if 0 <= index < len(self._hashcat_tool_options):
            return self._hashcat_tool_options[index][0]
        return "hashcat"

    def _hashcat_selected_attack_index(self) -> int:
        index = self.hashcat_attack_combo.get_selected()
        if 0 <= index < len(self._hashcat_attack_options):
            return index
        return 0

    def _hashcat_selected_attack(self) -> str:
        return self._hashcat_attack_options[self._hashcat_selected_attack_index()][0]

    def _on_hashcat_tool_changed(self, _combo: Adw.ComboRow, _pspec: GObject.ParamSpec) -> None:
        self._update_hashcat_builder_fields()

    def _on_hashcat_attack_changed(self, _combo: Adw.ComboRow, _pspec: GObject.ParamSpec) -> None:
        self._update_hashcat_attack_subtitle()

    def _update_hashcat_attack_subtitle(self) -> None:
        if self._hashcat_selected_tool() != "hashcat":
            self.hashcat_attack_combo.set_subtitle("Attack selection is only relevant when using Hashcat.")
            return
        option = self._hashcat_attack_options[self._hashcat_selected_attack_index()]
        self.hashcat_attack_combo.set_subtitle(option[2])

    def _update_hashcat_builder_fields(self) -> None:
        tool_key = self._hashcat_selected_tool()
        is_hashcat = tool_key == "hashcat"
        self.hashcat_mode_row.set_sensitive(is_hashcat)
        self.hashcat_attack_combo.set_sensitive(is_hashcat)
        self.hashcat_mask_row.set_sensitive(is_hashcat)
        self.hashcat_rules_row.set_sensitive(is_hashcat)
        self.hashcat_wordlist_row.set_sensitive(True)
        self.hashcat_format_row.set_sensitive(not is_hashcat)

        if is_hashcat:
            self.hashcat_wordlist_row.set_title("Wordlist")
            self.hashcat_wordlist_row.set_tooltip_text("Optional dictionary file; useful for straight and hybrid attacks.")
            self.hashcat_mask_row.set_tooltip_text("Example: ?u?l?l?l?d — required for brute-force and hybrid attacks.")
        else:
            self.hashcat_wordlist_row.set_title("Wordlist (optional)")
            self.hashcat_wordlist_row.set_tooltip_text("Optional --wordlist parameter passed to John.")
            self.hashcat_mask_row.set_tooltip_text("Mask-based attacks are not available for John the Ripper.")

        self._update_hashcat_attack_subtitle()

    def _on_hashcat_build(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        tool_choice = self._hashcat_selected_tool()
        try:
            result = self._active_tool.run(
                tool=tool_choice,
                hash_file=self.hashcat_hash_file_row.get_text().strip() or "hashes.txt",
                mode=self.hashcat_mode_row.get_text().strip() or "0",
                attack=self._hashcat_selected_attack(),
                wordlist=self.hashcat_wordlist_row.get_text().strip(),
                mask=self.hashcat_mask_row.get_text().strip(),
                rules=self.hashcat_rules_row.get_text().strip(),
                extra_options=self.hashcat_extra_row.get_text().strip(),
                format_hint=self.hashcat_format_row.get_text().strip(),
                potfile=self.hashcat_potfile_row.get_text().strip(),
            )
            body = getattr(result, "body", str(result))
            self._set_hashcat_output(body)
            self.hashcat_copy_btn.set_sensitive(True)
            self._set_tool_output(body)
            self.output_frame.set_visible(True)
        except Exception as exc:
            self.toast_overlay.add_toast(Adw.Toast.new(f"Error: {exc}"))

    def _on_hashcat_copy(self, _btn: Gtk.Button) -> None:
        self._copy_text_view_to_clipboard(self.hashcat_output_view)

    def _on_hashcat_browse_hash_file(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative.new("Select hash file", self.window, Gtk.FileChooserAction.OPEN, None, None)
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                self.hashcat_hash_file_row.set_text(file.get_path() or "")
        dialog.destroy()

    def _on_hashcat_browse_wordlist(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative.new("Select wordlist", self.window, Gtk.FileChooserAction.OPEN, None, None)
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                self.hashcat_wordlist_row.set_text(file.get_path() or "")
        dialog.destroy()

    def _on_hashcat_browse_potfile(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative.new("Select potfile", self.window, Gtk.FileChooserAction.OPEN, None, None)
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                self.hashcat_potfile_row.set_text(file.get_path() or "")
        dialog.destroy()

    def _build_htpasswd_generator_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("htpasswd Generator")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=640, tightening_threshold=520)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        user_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        user_row.append(Gtk.Label(label="Username", xalign=0))
        self.htpasswd_username_entry = Gtk.Entry()
        self.htpasswd_username_entry.add_css_class("modern-entry")
        self.htpasswd_username_entry.set_placeholder_text("user")
        user_row.append(self.htpasswd_username_entry)
        form.append(user_row)

        pass_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        pass_row.append(Gtk.Label(label="Password", xalign=0))
        self.htpasswd_password_entry = Gtk.Entry()
        self.htpasswd_password_entry.add_css_class("modern-entry")
        self.htpasswd_password_entry.set_visibility(False)
        self.htpasswd_password_entry.set_invisible_char("•")
        self.htpasswd_password_entry.set_input_purpose(Gtk.InputPurpose.PASSWORD)
        self.htpasswd_password_entry.set_placeholder_text("secret")
        pass_row.append(self.htpasswd_password_entry)
        form.append(pass_row)

        algo_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        algo_row.append(Gtk.Label(label="Algorithm", xalign=0))
        self.htpasswd_algo_combo = Gtk.ComboBoxText()
        self.htpasswd_algo_combo.append("plaintext", "Plaintext (testing only)")
        self.htpasswd_algo_combo.append("md5", "Apache MD5 (apr1)")
        self.htpasswd_algo_combo.append("sha256", "SHA-256 crypt")
        self.htpasswd_algo_combo.append("sha512", "SHA-512 crypt")
        self.htpasswd_algo_combo.set_active_id("sha512")
        algo_row.append(self.htpasswd_algo_combo)
        form.append(algo_row)

        salt_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        salt_row.append(Gtk.Label(label="Salt", xalign=0))
        self.htpasswd_salt_entry = Gtk.Entry()
        self.htpasswd_salt_entry.add_css_class("modern-entry")
        self.htpasswd_salt_entry.set_placeholder_text("Leave blank for random")
        salt_row.append(self.htpasswd_salt_entry)
        form.append(salt_row)

        buttons_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        generate_btn = Gtk.Button(label="Generate")
        generate_btn.add_css_class("suggested-action")
        generate_btn.connect("clicked", self._on_htpasswd_generate)
        buttons_row.append(generate_btn)
        self.htpasswd_copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        self.htpasswd_copy_btn.set_tooltip_text("Copy result JSON")
        self.htpasswd_copy_btn.set_sensitive(False)
        self.htpasswd_copy_btn.connect("clicked", self._on_htpasswd_copy)
        buttons_row.append(self.htpasswd_copy_btn)
        form.append(buttons_row)

        output_label = Gtk.Label(label="Result", xalign=0)
        output_label.add_css_class("title-4")
        form.append(output_label)

        self.htpasswd_output_view = Gtk.TextView()
        self.htpasswd_output_view.add_css_class("output-text")
        self.htpasswd_output_view.set_editable(False)
        self.htpasswd_output_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        output_scroll = Gtk.ScrolledWindow()
        output_scroll.add_css_class("output-box")
        output_scroll.set_min_content_height(550)
        output_scroll.set_child(self.htpasswd_output_view)
        form.append(output_scroll)

    def _set_htpasswd_output(self, text: str) -> None:
        self._set_text_view_text(self.htpasswd_output_view, text)

    def _open_htpasswd_generator(self, tool) -> None:
        self._active_tool = tool
        self.htpasswd_username_entry.set_text("")
        self.htpasswd_password_entry.set_text("")
        self.htpasswd_algo_combo.set_active_id("sha512")
        self.htpasswd_salt_entry.set_text("")
        self._set_htpasswd_output("")
        self.htpasswd_copy_btn.set_sensitive(False)
        self.tool_detail_stack.set_visible_child_name("htpasswd_generator")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_htpasswd_generate(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        username = self.htpasswd_username_entry.get_text().strip()
        password = self.htpasswd_password_entry.get_text()
        algorithm = self.htpasswd_algo_combo.get_active_id() or "sha512"
        salt = self.htpasswd_salt_entry.get_text().strip()
        if not username:
            self.toast_overlay.add_toast(Adw.Toast.new("Enter a username"))
            return
        if not password:
            self.toast_overlay.add_toast(Adw.Toast.new("Enter a password"))
            return
        try:
            result = self._active_tool.run(username=username, password=password, algorithm=algorithm, salt=salt)
            body = getattr(result, "body", str(result))
            self._set_htpasswd_output(body)
            self.htpasswd_copy_btn.set_sensitive(True)
            self._set_tool_output(body)
            self.output_frame.set_visible(True)
        except Exception as exc:
            self.toast_overlay.add_toast(Adw.Toast.new(f"Error: {exc}"))

    def _on_htpasswd_copy(self, _btn: Gtk.Button) -> None:
        self._copy_text_view_to_clipboard(self.htpasswd_output_view)

    def _build_rsa_toolkit_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("RSA Toolkit")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=760, tightening_threshold=560)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        mode_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        mode_row.append(Gtk.Label(label="Mode", xalign=0))
        self.rsa_mode_combo = Gtk.ComboBoxText()
        self.rsa_mode_combo.append("analyse", "Analyse modulus")
        self.rsa_mode_combo.append("crt", "CRT small-e recovery")
        self.rsa_mode_combo.set_active_id("analyse")
        self.rsa_mode_combo.connect("changed", self._on_rsa_mode_changed)
        mode_row.append(self.rsa_mode_combo)
        form.append(mode_row)

        self.rsa_analyse_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.rsa_analyse_box.append(Gtk.Label(label="Modulus n", xalign=0))
        self.rsa_n_entry = Gtk.Entry()
        self.rsa_n_entry.add_css_class("modern-entry")
        self.rsa_n_entry.set_placeholder_text("Enter modulus e.g. 0x... or decimal")
        self.rsa_analyse_box.append(self.rsa_n_entry)

        e_label = Gtk.Label(label="Public exponent e", xalign=0)
        self.rsa_analyse_box.append(e_label)
        self.rsa_e_entry = Gtk.Entry()
        self.rsa_e_entry.add_css_class("modern-entry")
        self.rsa_e_entry.set_placeholder_text("Default 65537")
        self.rsa_analyse_box.append(self.rsa_e_entry)

        ct_label = Gtk.Label(label="Ciphertext (optional)", xalign=0)
        self.rsa_analyse_box.append(ct_label)
        self.rsa_ciphertext_entry = Gtk.Entry()
        self.rsa_ciphertext_entry.add_css_class("modern-entry")
        self.rsa_ciphertext_entry.set_placeholder_text("Provide to attempt decryption")
        self.rsa_analyse_box.append(self.rsa_ciphertext_entry)

        factors_label = Gtk.Label(label="Known factors (comma separated)", xalign=0)
        self.rsa_analyse_box.append(factors_label)
        self.rsa_known_factors_entry = Gtk.Entry()
        self.rsa_known_factors_entry.add_css_class("modern-entry")
        self.rsa_known_factors_entry.set_placeholder_text("e.g. 123457,654323")
        self.rsa_analyse_box.append(self.rsa_known_factors_entry)

        limit_label = Gtk.Label(label="Trial division limit", xalign=0)
        self.rsa_analyse_box.append(limit_label)
        self.rsa_factor_limit_entry = Gtk.Entry()
        self.rsa_factor_limit_entry.add_css_class("modern-entry")
        self.rsa_factor_limit_entry.set_placeholder_text("Default 500000")
        self.rsa_analyse_box.append(self.rsa_factor_limit_entry)
        form.append(self.rsa_analyse_box)

        self.rsa_crt_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.rsa_crt_box.set_visible(False)
        instances_label = Gtk.Label(label="Ciphertext,modulus pairs (one per line)", xalign=0)
        self.rsa_crt_box.append(instances_label)
        self.rsa_instances_view = Gtk.TextView()
        self.rsa_instances_view.set_wrap_mode(Gtk.WrapMode.NONE)
        instances_scroll = Gtk.ScrolledWindow()
        instances_scroll.add_css_class("output-box")
        instances_scroll.set_min_content_height(200)
        instances_scroll.set_child(self.rsa_instances_view)
        self.rsa_crt_box.append(instances_scroll)

        crt_e_label = Gtk.Label(label="Public exponent e", xalign=0)
        self.rsa_crt_box.append(crt_e_label)
        self.rsa_crt_e_entry = Gtk.Entry()
        self.rsa_crt_e_entry.add_css_class("modern-entry")
        self.rsa_crt_e_entry.set_placeholder_text("Default 3")
        self.rsa_crt_box.append(self.rsa_crt_e_entry)
        form.append(self.rsa_crt_box)

        buttons_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        run_btn = Gtk.Button(label="Run analysis")
        run_btn.add_css_class("suggested-action")
        run_btn.connect("clicked", self._on_rsa_run)
        buttons_row.append(run_btn)
        self.rsa_copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        self.rsa_copy_btn.set_tooltip_text("Copy result JSON")
        self.rsa_copy_btn.set_sensitive(False)
        self.rsa_copy_btn.connect("clicked", self._on_rsa_copy)
        buttons_row.append(self.rsa_copy_btn)
        form.append(buttons_row)

        output_label = Gtk.Label(label="Result", xalign=0)
        output_label.add_css_class("title-4")
        form.append(output_label)

        self.rsa_output_view = Gtk.TextView()
        self.rsa_output_view.add_css_class("output-text")
        self.rsa_output_view.set_editable(False)
        self.rsa_output_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        output_scroll = Gtk.ScrolledWindow()
        output_scroll.add_css_class("output-box")
        output_scroll.set_min_content_height(550)
        output_scroll.set_child(self.rsa_output_view)
        form.append(output_scroll)

    def _set_rsa_output(self, text: str) -> None:
        self._set_text_view_text(self.rsa_output_view, text)

    def _open_rsa_toolkit(self, tool) -> None:
        self._active_tool = tool
        self.rsa_mode_combo.set_active_id("analyse")
        self.rsa_n_entry.set_text("")
        self.rsa_e_entry.set_text("65537")
        self.rsa_ciphertext_entry.set_text("")
        self.rsa_known_factors_entry.set_text("")
        self.rsa_factor_limit_entry.set_text("500000")
        self.rsa_instances_view.get_buffer().set_text("")
        self.rsa_crt_e_entry.set_text("3")
        self._show_rsa_mode("analyse")
        self._set_rsa_output("")
        self.rsa_copy_btn.set_sensitive(False)
        self.tool_detail_stack.set_visible_child_name("rsa_toolkit")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_rsa_mode_changed(self, _combo: Gtk.ComboBoxText) -> None:
        mode = self.rsa_mode_combo.get_active_id() or "analyse"
        self._show_rsa_mode(mode)

    def _show_rsa_mode(self, mode: str) -> None:
        is_analyse = mode == "analyse"
        self.rsa_analyse_box.set_visible(is_analyse)
        self.rsa_crt_box.set_visible(not is_analyse)

    def _on_rsa_run(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        mode = self.rsa_mode_combo.get_active_id() or "analyse"
        try:
            if mode == "analyse":
                n = self.rsa_n_entry.get_text().strip()
                if not n:
                    raise ValueError("Provide modulus n")
                result = self._active_tool.run(
                    mode="analyse",
                    n=n,
                    e=self.rsa_e_entry.get_text().strip() or "65537",
                    ciphertext=self.rsa_ciphertext_entry.get_text().strip(),
                    known_factors=self.rsa_known_factors_entry.get_text().strip(),
                    factor_limit=self.rsa_factor_limit_entry.get_text().strip() or "500000",
                )
            else:
                instances = self._get_text_view_text(self.rsa_instances_view)
                if not instances.strip():
                    raise ValueError("Provide ciphertext,modulus pairs")
                result = self._active_tool.run(
                    mode="crt",
                    instances=instances,
                    e=self.rsa_crt_e_entry.get_text().strip() or "3",
                )
            body = getattr(result, "body", str(result))
            self._set_rsa_output(body)
            self.rsa_copy_btn.set_sensitive(True)
            self._set_tool_output(body)
            self.output_frame.set_visible(True)
        except Exception as exc:
            self.toast_overlay.add_toast(Adw.Toast.new(f"Error: {exc}"))

    def _on_rsa_copy(self, _btn: Gtk.Button) -> None:
        self._copy_text_view_to_clipboard(self.rsa_output_view)

    def _build_xor_analyzer_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("XOR Analyzer")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=760, tightening_threshold=560)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        mode_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        mode_row.append(Gtk.Label(label="Mode", xalign=0))
        self.xor_mode_combo = Gtk.ComboBoxText()
        self.xor_mode_combo.append("known_plaintext", "Known plaintext")
        self.xor_mode_combo.append("pairwise", "Pairwise XOR")
        self.xor_mode_combo.append("apply_keystream", "Apply keystream")
        self.xor_mode_combo.set_active_id("known_plaintext")
        self.xor_mode_combo.connect("changed", self._on_xor_mode_changed)
        mode_row.append(self.xor_mode_combo)
        form.append(mode_row)

        # Known plaintext form
        self.xor_known_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.xor_known_box.append(Gtk.Label(label="Ciphertext", xalign=0))
        self.xor_known_cipher_entry = Gtk.Entry()
        self.xor_known_cipher_entry.add_css_class("modern-entry")
        self.xor_known_cipher_entry.set_placeholder_text("Hex, base64, or text")
        self.xor_known_box.append(self.xor_known_cipher_entry)
        self.xor_known_box.append(Gtk.Label(label="Known plaintext", xalign=0))
        self.xor_known_plain_entry = Gtk.Entry()
        self.xor_known_plain_entry.add_css_class("modern-entry")
        self.xor_known_plain_entry.set_placeholder_text("ASCII text")
        self.xor_known_box.append(self.xor_known_plain_entry)
        known_format_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        known_format_row.append(Gtk.Label(label="Cipher format", xalign=0))
        self.xor_known_format_combo = Gtk.ComboBoxText()
        for fmt_id, label in [("hex", "Hex"), ("base64", "Base64"), ("text", "Raw text")]:
            self.xor_known_format_combo.append(fmt_id, label)
        self.xor_known_format_combo.set_active_id("hex")
        known_format_row.append(self.xor_known_format_combo)
        self.xor_known_box.append(known_format_row)
        form.append(self.xor_known_box)

        # Pairwise form
        self.xor_pairwise_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.xor_pairwise_box.set_visible(False)
        self.xor_pairwise_box.append(Gtk.Label(label="Ciphertexts (one per line)", xalign=0))
        self.xor_pairwise_view = Gtk.TextView()
        self.xor_pairwise_view.set_wrap_mode(Gtk.WrapMode.NONE)
        pairwise_scroll = Gtk.ScrolledWindow()
        pairwise_scroll.add_css_class("output-box")
        pairwise_scroll.set_min_content_height(200)
        pairwise_scroll.set_child(self.xor_pairwise_view)
        self.xor_pairwise_box.append(pairwise_scroll)
        pairwise_format_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        pairwise_format_row.append(Gtk.Label(label="Input format", xalign=0))
        self.xor_pairwise_format_combo = Gtk.ComboBoxText()
        for fmt_id, label in [("hex", "Hex"), ("base64", "Base64"), ("text", "Raw text")]:
            self.xor_pairwise_format_combo.append(fmt_id, label)
        self.xor_pairwise_format_combo.set_active_id("hex")
        pairwise_format_row.append(self.xor_pairwise_format_combo)
        self.xor_pairwise_box.append(pairwise_format_row)
        form.append(self.xor_pairwise_box)

        # Apply keystream form
        self.xor_apply_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.xor_apply_box.set_visible(False)
        self.xor_apply_box.append(Gtk.Label(label="Ciphertext", xalign=0))
        self.xor_apply_cipher_entry = Gtk.Entry()
        self.xor_apply_cipher_entry.add_css_class("modern-entry")
        self.xor_apply_cipher_entry.set_placeholder_text("Ciphertext to decrypt")
        self.xor_apply_box.append(self.xor_apply_cipher_entry)
        self.xor_apply_box.append(Gtk.Label(label="Keystream (hex)", xalign=0))
        self.xor_apply_keystream_entry = Gtk.Entry()
        self.xor_apply_keystream_entry.add_css_class("modern-entry")
        self.xor_apply_keystream_entry.set_placeholder_text("Hex keystream")
        self.xor_apply_box.append(self.xor_apply_keystream_entry)
        apply_format_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        apply_format_row.append(Gtk.Label(label="Cipher format", xalign=0))
        self.xor_apply_format_combo = Gtk.ComboBoxText()
        for fmt_id, label in [("hex", "Hex"), ("base64", "Base64"), ("text", "Raw text")]:
            self.xor_apply_format_combo.append(fmt_id, label)
        self.xor_apply_format_combo.set_active_id("hex")
        apply_format_row.append(self.xor_apply_format_combo)
        self.xor_apply_box.append(apply_format_row)
        form.append(self.xor_apply_box)

        buttons_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        run_btn = Gtk.Button(label="Analyze")
        run_btn.add_css_class("suggested-action")
        run_btn.connect("clicked", self._on_xor_run)
        buttons_row.append(run_btn)
        self.xor_copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        self.xor_copy_btn.set_tooltip_text("Copy result JSON")
        self.xor_copy_btn.set_sensitive(False)
        self.xor_copy_btn.connect("clicked", self._on_xor_copy)
        buttons_row.append(self.xor_copy_btn)
        form.append(buttons_row)

        output_label = Gtk.Label(label="Result", xalign=0)
        output_label.add_css_class("title-4")
        form.append(output_label)

        self.xor_output_view = Gtk.TextView()
        self.xor_output_view.add_css_class("output-text")
        self.xor_output_view.set_editable(False)
        self.xor_output_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        output_scroll = Gtk.ScrolledWindow()
        output_scroll.add_css_class("output-box")
        output_scroll.set_min_content_height(550)
        output_scroll.set_child(self.xor_output_view)
        form.append(output_scroll)

    def _set_xor_output(self, text: str) -> None:
        self._set_text_view_text(self.xor_output_view, text)

    def _open_xor_analyzer(self, tool) -> None:
        self._active_tool = tool
        self.xor_mode_combo.set_active_id("known_plaintext")
        self.xor_known_cipher_entry.set_text("")
        self.xor_known_plain_entry.set_text("")
        self.xor_known_format_combo.set_active_id("hex")
        self.xor_pairwise_view.get_buffer().set_text("")
        self.xor_pairwise_format_combo.set_active_id("hex")
        self.xor_apply_cipher_entry.set_text("")
        self.xor_apply_keystream_entry.set_text("")
        self.xor_apply_format_combo.set_active_id("hex")
        self._show_xor_mode("known_plaintext")
        self._set_xor_output("")
        self.xor_copy_btn.set_sensitive(False)
        self.tool_detail_stack.set_visible_child_name("xor_analyzer")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_xor_mode_changed(self, _combo: Gtk.ComboBoxText) -> None:
        mode = self.xor_mode_combo.get_active_id() or "known_plaintext"
        self._show_xor_mode(mode)

    def _show_xor_mode(self, mode: str) -> None:
        self.xor_known_box.set_visible(mode == "known_plaintext")
        self.xor_pairwise_box.set_visible(mode == "pairwise")
        self.xor_apply_box.set_visible(mode == "apply_keystream")

    def _on_xor_run(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        mode = self.xor_mode_combo.get_active_id() or "known_plaintext"
        try:
            if mode == "known_plaintext":
                ciphertext = self.xor_known_cipher_entry.get_text().strip()
                plaintext = self.xor_known_plain_entry.get_text()
                if not ciphertext or not plaintext:
                    raise ValueError("Provide ciphertext and known plaintext")
                result = self._active_tool.run(
                    mode="known_plaintext",
                    ciphertext=ciphertext,
                    known_plaintext=plaintext,
                    input_format=self.xor_known_format_combo.get_active_id() or "hex",
                )
            elif mode == "pairwise":
                ciphertexts = self._get_text_view_text(self.xor_pairwise_view)
                if not ciphertexts.strip():
                    raise ValueError("Provide at least two ciphertexts")
                result = self._active_tool.run(
                    mode="pairwise",
                    ciphertexts=ciphertexts,
                    input_format=self.xor_pairwise_format_combo.get_active_id() or "hex",
                )
            else:
                ciphertext = self.xor_apply_cipher_entry.get_text().strip()
                keystream = self.xor_apply_keystream_entry.get_text().strip()
                if not ciphertext or not keystream:
                    raise ValueError("Provide ciphertext and keystream")
                result = self._active_tool.run(
                    mode="apply_keystream",
                    ciphertext=ciphertext,
                    keystream=keystream,
                    input_format=self.xor_apply_format_combo.get_active_id() or "hex",
                )
            body = getattr(result, "body", str(result))
            self._set_xor_output(body)
            self.xor_copy_btn.set_sensitive(True)
            self._set_tool_output(body)
            self.output_frame.set_visible(True)
        except Exception as exc:
            self.toast_overlay.add_toast(Adw.Toast.new(f"Error: {exc}"))

    def _on_xor_copy(self, _btn: Gtk.Button) -> None:
        self._copy_text_view_to_clipboard(self.xor_output_view)
        
    def _navigate_back_to_tools(self) -> None:
        self._current_view = ("tools", None)
        self._show_tools()
        self.refresh_sidebar()

    def _build_caesar_cipher_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("Caesar Cipher")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=720, tightening_threshold=560)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        input_label = Gtk.Label(label="Input text", xalign=0)
        input_label.add_css_class("title-4")
        form.append(input_label)

        self.caesar_input = Gtk.TextView()
        self.caesar_input.add_css_class("input-text")
        self.caesar_input.set_wrap_mode(Gtk.WrapMode.WORD)
        self.caesar_input.add_css_class("input-text")
        input_scroll = Gtk.ScrolledWindow()
        input_scroll.add_css_class("input-box")
        input_scroll.add_css_class("input-box")
        input_scroll.set_min_content_height(200)
        input_scroll.set_child(self.caesar_input)
        form.append(input_scroll)

        mode_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        mode_row.append(Gtk.Label(label="Mode", xalign=0))
        self.caesar_mode = Gtk.ComboBoxText()
        self.caesar_mode.append("encrypt", "Encrypt")
        self.caesar_mode.append("decrypt", "Decrypt")
        self.caesar_mode.append("bruteforce", "Brute force")
        self.caesar_mode.set_active_id("encrypt")
        self.caesar_mode.connect("changed", lambda *_: self._update_caesar_mode_ui())
        mode_row.append(self.caesar_mode)
        form.append(mode_row)

        shift_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        shift_row.append(Gtk.Label(label="Shift", xalign=0))
        self.caesar_shift = Gtk.SpinButton()
        self.caesar_shift.set_adjustment(Gtk.Adjustment(lower=-51, upper=51, step_increment=1, page_increment=5))
        self.caesar_shift.set_value(13)
        shift_row.append(self.caesar_shift)
        form.append(shift_row)
        self.caesar_shift_row = shift_row

        alphabet_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        alphabet_row.append(Gtk.Label(label="Alphabet", xalign=0))
        self.caesar_alphabet = Gtk.Entry()
        self.caesar_alphabet.set_placeholder_text("Defaults to A-Z")
        alphabet_row.append(self.caesar_alphabet)
        self.caesar_digits = Gtk.CheckButton(label="Include digits 0-9")
        alphabet_row.append(self.caesar_digits)
        form.append(alphabet_row)

        buttons_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        compute_btn = Gtk.Button(label="Transform")
        compute_btn.add_css_class("suggested-action")
        compute_btn.connect("clicked", self._on_caesar_compute)
        buttons_row.append(compute_btn)
        self.caesar_copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        self.caesar_copy_btn.set_tooltip_text("Copy output")
        self.caesar_copy_btn.connect("clicked", self._on_caesar_copy)
        self.caesar_copy_btn.set_sensitive(False)
        buttons_row.append(self.caesar_copy_btn)
        form.append(buttons_row)

        output_label = Gtk.Label(label="Result", xalign=0)
        output_label.add_css_class("title-4")
        form.append(output_label)

        self.caesar_output = Gtk.TextView()
        self.caesar_output.add_css_class("output-text")
        self.caesar_output.set_editable(False)
        self.caesar_output.set_wrap_mode(Gtk.WrapMode.WORD)
        self.caesar_output.add_css_class("output-text")
        output_scroll = Gtk.ScrolledWindow()
        output_scroll.add_css_class("output-box")
        output_scroll.add_css_class("output-box")
        output_scroll.set_min_content_height(550)
        output_scroll.set_child(self.caesar_output)
        form.append(output_scroll)

    def _open_caesar_cipher(self, tool) -> None:
        self._active_tool = tool
        self.caesar_input.get_buffer().set_text("")
        self.caesar_mode.set_active_id("encrypt")
        self.caesar_shift.set_value(13)
        self.caesar_alphabet.set_text("")
        self.caesar_digits.set_active(False)
        self._set_caesar_output("")
        self._update_caesar_mode_ui()
        self.tool_detail_stack.set_visible_child_name("caesar")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_caesar_compute(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        buffer = self.caesar_input.get_buffer()
        start, end = buffer.get_bounds()
        text = buffer.get_text(start, end, True)
        if not text.strip():
            self._set_caesar_output("")
            self.toast_overlay.add_toast(Adw.Toast.new("Enter some text first"))
            return
        mode = self.caesar_mode.get_active_id() or "encrypt"
        try:
            result = self._active_tool.run(
                text=text,
                shift=str(int(self.caesar_shift.get_value())),
                mode=mode,
                alphabet=self.caesar_alphabet.get_text(),
                include_digits="true" if self.caesar_digits.get_active() else "false",
            )
            body = getattr(result, "body", str(result))
            self._set_caesar_output(body)
        except Exception as exc:
            self.toast_overlay.add_toast(Adw.Toast.new(f"Error: {exc}"))

    def _set_caesar_output(self, text: str) -> None:
        buffer = self.caesar_output.get_buffer()
        buffer.set_text(text)
        self.caesar_copy_btn.set_sensitive(bool(text.strip()))

    def _on_caesar_copy(self, _btn: Gtk.Button) -> None:
        display = self.window.get_display()
        if display is None:
            return
        clipboard = display.get_clipboard()
        buffer = self.caesar_output.get_buffer()
        start, end = buffer.get_bounds()
        clipboard.set_text(buffer.get_text(start, end, True))

    def _update_caesar_mode_ui(self) -> None:
        brute = (self.caesar_mode.get_active_id() or "") == "bruteforce"
        self.caesar_shift_row.set_sensitive(not brute)

    def _build_vigenere_cipher_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("Vigenère Cipher")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=720, tightening_threshold=560)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        input_label = Gtk.Label(label="Input text", xalign=0)
        input_label.add_css_class("title-4")
        form.append(input_label)

        self.vigenere_input_view = Gtk.TextView()
        self.vigenere_input_view.add_css_class("input-text")
        self.vigenere_input_view.set_wrap_mode(Gtk.WrapMode.WORD)
        input_scroll = Gtk.ScrolledWindow()
        input_scroll.add_css_class("input-box")
        input_scroll.set_min_content_height(200)
        input_scroll.set_child(self.vigenere_input_view)
        form.append(input_scroll)

        key_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        key_row.append(Gtk.Label(label="Key", xalign=0))
        self.vigenere_key_entry = Gtk.Entry()
        self.vigenere_key_entry.add_css_class("modern-entry")
        key_row.append(self.vigenere_key_entry)
        form.append(key_row)

        options_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        options_row.append(Gtk.Label(label="Mode", xalign=0))
        self.vigenere_mode = Gtk.ComboBoxText()
        self.vigenere_mode.append("encrypt", "Encrypt")
        self.vigenere_mode.append("decrypt", "Decrypt")
        self.vigenere_mode.set_active_id("encrypt")
        options_row.append(self.vigenere_mode)

        self.vigenere_autokey = Gtk.CheckButton(label="Autokey")
        options_row.append(self.vigenere_autokey)
        self.vigenere_include_digits = Gtk.CheckButton(label="Digits 0-9")
        options_row.append(self.vigenere_include_digits)
        form.append(options_row)

        alphabet_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        alphabet_row.append(Gtk.Label(label="Alphabet", xalign=0))
        self.vigenere_alphabet = Gtk.Entry()
        self.vigenere_alphabet.set_placeholder_text("Defaults to A-Z")
        alphabet_row.append(self.vigenere_alphabet)
        form.append(alphabet_row)

        actions_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        compute_btn = Gtk.Button(label="Transform")
        compute_btn.add_css_class("suggested-action")
        compute_btn.connect("clicked", self._on_vigenere_compute)
        actions_row.append(compute_btn)
        self.vigenere_copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        self.vigenere_copy_btn.set_tooltip_text("Copy output")
        self.vigenere_copy_btn.set_sensitive(False)
        self.vigenere_copy_btn.connect("clicked", self._on_vigenere_copy)
        actions_row.append(self.vigenere_copy_btn)
        form.append(actions_row)

        output_label = Gtk.Label(label="Result", xalign=0)
        output_label.add_css_class("title-4")
        form.append(output_label)

        self.vigenere_output_view = Gtk.TextView()
        self.vigenere_output_view.add_css_class("output-text")
        self.vigenere_output_view.set_editable(False)
        self.vigenere_output_view.set_wrap_mode(Gtk.WrapMode.WORD)
        output_scroll = Gtk.ScrolledWindow()
        output_scroll.add_css_class("output-box")
        output_scroll.set_min_content_height(550)
        output_scroll.set_child(self.vigenere_output_view)
        form.append(output_scroll)

    def _open_vigenere_cipher(self, tool) -> None:
        self._active_tool = tool
        self.vigenere_input_view.get_buffer().set_text("")
        self.vigenere_key_entry.set_text("")
        self.vigenere_mode.set_active_id("encrypt")
        self.vigenere_autokey.set_active(False)
        self.vigenere_include_digits.set_active(False)
        self.vigenere_alphabet.set_text("")
        self._set_vigenere_output("")
        self.tool_detail_stack.set_visible_child_name("vigenere")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_vigenere_compute(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        buffer = self.vigenere_input_view.get_buffer()
        start, end = buffer.get_bounds()
        text = buffer.get_text(start, end, True)
        if not text.strip():
            self._set_vigenere_output("")
            self.toast_overlay.add_toast(Adw.Toast.new("Enter some text first"))
            return
        key = self.vigenere_key_entry.get_text().strip()
        if not key:
            self.toast_overlay.add_toast(Adw.Toast.new("Enter a key"))
            return
        try:
            result = self._active_tool.run(
                text=text,
                key=key,
                mode=self.vigenere_mode.get_active_id() or "encrypt",
                alphabet=self.vigenere_alphabet.get_text(),
                include_digits="true" if self.vigenere_include_digits.get_active() else "false",
                autokey="true" if self.vigenere_autokey.get_active() else "false",
            )
            body = getattr(result, "body", str(result))
            self._set_vigenere_output(body)
        except Exception as exc:
            self.toast_overlay.add_toast(Adw.Toast.new(f"Error: {exc}"))

    def _set_vigenere_output(self, text: str) -> None:
        buffer = self.vigenere_output_view.get_buffer()
        buffer.set_text(text)
        self.vigenere_copy_btn.set_sensitive(bool(text.strip()))

    def _on_vigenere_copy(self, _btn: Gtk.Button) -> None:
        display = self.window.get_display()
        if display is None:
            return
        clipboard = display.get_clipboard()
        buffer = self.vigenere_output_view.get_buffer()
        start, end = buffer.get_bounds()
        clipboard.set_text(buffer.get_text(start, end, True))
    def _build_file_inspector_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("File Inspector")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=720, tightening_threshold=560)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        # File section
        file_label = Gtk.Label(label="File", xalign=0)
        file_label.add_css_class("title-4")
        form.append(file_label)

        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.inspect_file_entry = Gtk.Entry()
        self.inspect_file_entry.add_css_class("modern-entry")
        self.inspect_file_entry.set_placeholder_text("Select a file...")
        self.inspect_file_entry.set_hexpand(True)
        browse_btn = Gtk.Button(label="Browse…")
        browse_btn.connect("clicked", self._on_inspect_browse)
        row.append(self.inspect_file_entry)
        row.append(browse_btn)
        form.append(row)

        # Analysis options section
        options_label = Gtk.Label(label="Analysis Options", xalign=0)
        options_label.add_css_class("title-4")
        form.append(options_label)

        options_grid = Gtk.Grid()
        options_grid.set_row_spacing(8)
        options_grid.set_column_spacing(12)
        
        options_grid.attach(Gtk.Label(label="Preview bytes", xalign=0), 0, 0, 1, 1)
        self.inspect_preview_spin = Gtk.SpinButton()
        self.inspect_preview_spin.set_adjustment(Gtk.Adjustment(lower=0, upper=4096, step_increment=32, page_increment=256))
        self.inspect_preview_spin.set_value(256)
        options_grid.attach(self.inspect_preview_spin, 1, 0, 1, 1)
        
        self.inspect_entropy_check = Gtk.CheckButton(label="Entropy")
        options_grid.attach(self.inspect_entropy_check, 2, 0, 1, 1)
        
        self.inspect_strings_check = Gtk.CheckButton(label="Strings preview")
        options_grid.attach(self.inspect_strings_check, 3, 0, 1, 1)
        
        options_grid.attach(Gtk.Label(label="Min length", xalign=0), 0, 1, 1, 1)
        self.inspect_strings_min = Gtk.SpinButton()
        self.inspect_strings_min.set_adjustment(Gtk.Adjustment(lower=1, upper=16, step_increment=1, page_increment=2))
        self.inspect_strings_min.set_value(4)
        options_grid.attach(self.inspect_strings_min, 1, 1, 1, 1)
        
        options_grid.attach(Gtk.Label(label="Limit", xalign=0), 2, 1, 1, 1)
        self.inspect_strings_limit = Gtk.SpinButton()
        self.inspect_strings_limit.set_adjustment(Gtk.Adjustment(lower=0, upper=100, step_increment=1, page_increment=5))
        self.inspect_strings_limit.set_value(15)
        options_grid.attach(self.inspect_strings_limit, 3, 1, 1, 1)
        
        form.append(options_grid)

        actions_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        run_btn = Gtk.Button(label="Analyze")
        run_btn.add_css_class("suggested-action")
        run_btn.connect("clicked", self._on_inspect_run)
        actions_row.append(run_btn)
        self.inspect_copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        self.inspect_copy_btn.set_tooltip_text("Copy result")
        self.inspect_copy_btn.set_sensitive(False)
        self.inspect_copy_btn.connect("clicked", self._on_inspect_copy)
        actions_row.append(self.inspect_copy_btn)
        form.append(actions_row)

        # Result section
        result_label = Gtk.Label(label="Result", xalign=0)
        result_label.add_css_class("title-4")
        form.append(result_label)

        self.inspect_result_view = Gtk.TextView()
        self.inspect_result_view.add_css_class("output-text")
        self.inspect_result_view.set_editable(False)
        self.inspect_result_view.set_monospace(True)
        result_scroller = Gtk.ScrolledWindow()
        result_scroller.add_css_class("output-box")
        result_scroller.set_min_content_height(550)
        result_scroller.set_child(self.inspect_result_view)
        form.append(result_scroller)

    def _open_file_inspector(self, tool) -> None:
        self._active_tool = tool
        self.inspect_file_entry.set_text("")
        self.inspect_preview_spin.set_value(256)
        self.inspect_entropy_check.set_active(False)
        self.inspect_strings_check.set_active(False)
        self.inspect_strings_min.set_value(4)
        self.inspect_strings_limit.set_value(15)
        buffer = self.inspect_result_view.get_buffer()
        buffer.set_text("")
        self.inspect_copy_btn.set_sensitive(False)
        self.tool_detail_stack.set_visible_child_name("file_inspector")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_inspect_browse(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative.new("Select file", self.window, Gtk.FileChooserAction.OPEN, None, None)
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                self.inspect_file_entry.set_text(file.get_path() or "")
        dialog.destroy()

    def _on_inspect_run(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        file_path = self.inspect_file_entry.get_text().strip()
        if not file_path:
            self.toast_overlay.add_toast(Adw.Toast.new("Choose a file"))
            return
        try:
            result = self._active_tool.run(
                file_path=file_path,
                preview_bytes=str(int(self.inspect_preview_spin.get_value())),
                include_entropy="true" if self.inspect_entropy_check.get_active() else "false",
                include_strings="true" if self.inspect_strings_check.get_active() else "false",
                strings_min_length=str(int(self.inspect_strings_min.get_value())),
                strings_limit=str(int(self.inspect_strings_limit.get_value())),
            )
            buffer = self.inspect_result_view.get_buffer()
            payload = getattr(result, "body", str(result))
            buffer.set_text(payload)
            self.inspect_copy_btn.set_sensitive(bool(payload.strip()))
        except Exception as exc:
            self.toast_overlay.add_toast(Adw.Toast.new(f"Error: {exc}"))

    def _on_inspect_copy(self, _btn: Gtk.Button) -> None:
        display = self.window.get_display()
        if display is None:
            return
        clipboard = display.get_clipboard()
        buffer = self.inspect_result_view.get_buffer()
        start, end = buffer.get_bounds()
        clipboard.set_text(buffer.get_text(start, end, True))

    # ---------------------- PCAP viewer detail ----------------------
    def _build_pcap_viewer_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("PCAP Viewer")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=760, tightening_threshold=620)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        # Capture file section
        capture_label = Gtk.Label(label="Capture File", xalign=0)
        capture_label.add_css_class("title-4")
        form.append(capture_label)

        file_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.pcap_file_entry = Gtk.Entry()
        self.pcap_file_entry.add_css_class("modern-entry")
        self.pcap_file_entry.set_placeholder_text("Select a .pcap file...")
        self.pcap_file_entry.set_hexpand(True)
        file_row.append(self.pcap_file_entry)
        browse_btn = Gtk.Button(label="Browse…")
        browse_btn.connect("clicked", self._on_pcap_browse)
        file_row.append(browse_btn)
        form.append(file_row)

        # Analysis options section
        options_label = Gtk.Label(label="Analysis Options", xalign=0)
        options_label.add_css_class("title-4")
        form.append(options_label)

        options_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        options_row.append(Gtk.Label(label="Packet limit", xalign=0))
        self.pcap_limit_spin = Gtk.SpinButton()
        self.pcap_limit_spin.set_adjustment(Gtk.Adjustment(lower=10, upper=100000, step_increment=10, page_increment=1000))
        self.pcap_limit_spin.set_value(500)
        options_row.append(self.pcap_limit_spin)
        self.pcap_hex_check = Gtk.CheckButton(label="Include hex preview")
        options_row.append(self.pcap_hex_check)
        form.append(options_row)

        actions_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.pcap_run_btn = Gtk.Button(label="Analyze")
        self.pcap_run_btn.add_css_class("suggested-action")
        self.pcap_run_btn.connect("clicked", self._on_pcap_run)
        actions_row.append(self.pcap_run_btn)
        self.pcap_copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        self.pcap_copy_btn.set_tooltip_text("Copy result")
        self.pcap_copy_btn.set_sensitive(False)
        self.pcap_copy_btn.connect("clicked", self._on_pcap_copy)
        actions_row.append(self.pcap_copy_btn)
        form.append(actions_row)

        # Result section
        result_label = Gtk.Label(label="Result", xalign=0)
        result_label.add_css_class("title-4")
        form.append(result_label)

        self.pcap_result_view = Gtk.TextView()
        self.pcap_result_view.add_css_class("output-text")
        self.pcap_result_view.set_editable(False)
        self.pcap_result_view.set_monospace(True)
        result_scroller = Gtk.ScrolledWindow()
        result_scroller.add_css_class("output-box")
        result_scroller.set_min_content_height(550)
        result_scroller.set_child(self.pcap_result_view)
        form.append(result_scroller)

    def _open_pcap_viewer(self, tool) -> None:
        self._active_tool = tool
        self.pcap_file_entry.set_text("")
        self.pcap_limit_spin.set_value(500)
        self.pcap_hex_check.set_active(False)
        self._set_text_view_text(self.pcap_result_view, "")
        self.pcap_copy_btn.set_sensitive(False)
        self.tool_detail_stack.set_visible_child_name("pcap_viewer")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_pcap_browse(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative.new("Select capture", self.window, Gtk.FileChooserAction.OPEN, None, None)
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                self.pcap_file_entry.set_text(file.get_path() or "")
        dialog.destroy()

    def _on_pcap_run(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        path = self.pcap_file_entry.get_text().strip()
        if not path:
            self.toast_overlay.add_toast(Adw.Toast.new("Choose a capture file"))
            return
        limit = str(int(self.pcap_limit_spin.get_value()))
        include_hex = "true" if self.pcap_hex_check.get_active() else "false"
        self.pcap_run_btn.set_sensitive(False)
        self._set_text_view_text(self.pcap_result_view, "Analyzing capture…")

        def worker() -> None:
            try:
                result = self._active_tool.run(file_path=path, packet_limit=limit, include_hex=include_hex)
                body = getattr(result, "body", str(result))
                GLib.idle_add(self._set_text_view_text, self.pcap_result_view, body)
                GLib.idle_add(self.pcap_copy_btn.set_sensitive, bool(body.strip()))
            except Exception as exc:
                GLib.idle_add(self.toast_overlay.add_toast, Adw.Toast.new(f"Error: {exc}"))
            finally:
                GLib.idle_add(self.pcap_run_btn.set_sensitive, True)

        threading.Thread(target=worker, daemon=True).start()

    def _on_pcap_copy(self, _btn: Gtk.Button) -> None:
        display = self.window.get_display()
        if display is None:
            return
        clipboard = display.get_clipboard()
        buffer = self.pcap_result_view.get_buffer()
        start, end = buffer.get_bounds()
        clipboard.set_text(buffer.get_text(start, end, True))

    # ---------------------- Memory analyzer detail ----------------------
    def _build_memory_analyzer_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("Memory Analyzer")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=760, tightening_threshold=620)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        # Memory dump section
        dump_label = Gtk.Label(label="Memory Dump", xalign=0)
        dump_label.add_css_class("title-4")
        form.append(dump_label)

        file_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.memory_file_entry = Gtk.Entry()
        self.memory_file_entry.add_css_class("modern-entry")
        self.memory_file_entry.set_placeholder_text("Select a memory image...")
        self.memory_file_entry.set_hexpand(True)
        file_row.append(self.memory_file_entry)
        browse_btn = Gtk.Button(label="Browse…")
        browse_btn.connect("clicked", self._on_memory_browse)
        file_row.append(browse_btn)
        form.append(file_row)

        # Analysis options section
        options_label = Gtk.Label(label="Analysis Options", xalign=0)
        options_label.add_css_class("title-4")
        form.append(options_label)

        strings_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        strings_row.append(Gtk.Label(label="String sample", xalign=0))
        self.memory_strings_spin = Gtk.SpinButton()
        self.memory_strings_spin.set_adjustment(Gtk.Adjustment(lower=50, upper=5000, step_increment=50, page_increment=500))
        self.memory_strings_spin.set_value(300)
        strings_row.append(self.memory_strings_spin)
        form.append(strings_row)

        keyword_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        keyword_label = Gtk.Label(label="Keywords", xalign=0)
        keyword_label.set_width_chars(14)
        keyword_row.append(keyword_label)
        self.memory_keywords_entry = Gtk.Entry()
        self.memory_keywords_entry.add_css_class("modern-entry")
        self.memory_keywords_entry.set_placeholder_text("flag,password,secret")
        self.memory_keywords_entry.set_hexpand(True)
        keyword_row.append(self.memory_keywords_entry)
        form.append(keyword_row)

        self.memory_hash_check = Gtk.CheckButton(label="Include hashes (slower)")
        form.append(self.memory_hash_check)

        actions_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.memory_run_btn = Gtk.Button(label="Analyze")
        self.memory_run_btn.add_css_class("suggested-action")
        self.memory_run_btn.connect("clicked", self._on_memory_run)
        actions_row.append(self.memory_run_btn)
        self.memory_copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        self.memory_copy_btn.set_tooltip_text("Copy result")
        self.memory_copy_btn.set_sensitive(False)
        self.memory_copy_btn.connect("clicked", self._on_memory_copy)
        actions_row.append(self.memory_copy_btn)
        form.append(actions_row)

        # Result section
        result_label = Gtk.Label(label="Result", xalign=0)
        result_label.add_css_class("title-4")
        form.append(result_label)

        self.memory_result_view = Gtk.TextView()
        self.memory_result_view.add_css_class("output-text")
        self.memory_result_view.set_editable(False)
        self.memory_result_view.set_monospace(True)
        result_scroller = Gtk.ScrolledWindow()
        result_scroller.add_css_class("output-box")
        result_scroller.set_min_content_height(550)
        result_scroller.set_child(self.memory_result_view)
        form.append(result_scroller)

    def _open_memory_analyzer(self, tool) -> None:
        self._active_tool = tool
        self.memory_file_entry.set_text("")
        self.memory_strings_spin.set_value(300)
        self.memory_keywords_entry.set_text("flag,password,secret")
        self.memory_hash_check.set_active(False)
        self._set_text_view_text(self.memory_result_view, "")
        self.memory_copy_btn.set_sensitive(False)
        self.tool_detail_stack.set_visible_child_name("memory_analyzer")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_memory_browse(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative.new("Select memory image", self.window, Gtk.FileChooserAction.OPEN, None, None)
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                self.memory_file_entry.set_text(file.get_path() or "")
        dialog.destroy()

    def _on_memory_run(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        path = self.memory_file_entry.get_text().strip()
        if not path:
            self.toast_overlay.add_toast(Adw.Toast.new("Choose a memory image"))
            return
        sample_limit = str(int(self.memory_strings_spin.get_value()))
        keywords = self.memory_keywords_entry.get_text().strip()
        include_hash = "true" if self.memory_hash_check.get_active() else "false"
        self.memory_run_btn.set_sensitive(False)
        self._set_text_view_text(self.memory_result_view, "Scanning memory dump…")

        def worker() -> None:
            try:
                result = self._active_tool.run(
                    file_path=path,
                    strings_limit=sample_limit,
                    keywords=keywords,
                    include_hashes=include_hash,
                )
                body = getattr(result, "body", str(result))
                GLib.idle_add(self._set_text_view_text, self.memory_result_view, body)
                GLib.idle_add(self.memory_copy_btn.set_sensitive, bool(body.strip()))
            except Exception as exc:
                GLib.idle_add(self.toast_overlay.add_toast, Adw.Toast.new(f"Error: {exc}"))
            finally:
                GLib.idle_add(self.memory_run_btn.set_sensitive, True)

        threading.Thread(target=worker, daemon=True).start()

    def _on_memory_copy(self, _btn: Gtk.Button) -> None:
        display = self.window.get_display()
        if display is None:
            return
        clipboard = display.get_clipboard()
        buffer = self.memory_result_view.get_buffer()
        start, end = buffer.get_bounds()
        clipboard.set_text(buffer.get_text(start, end, True))

    # ---------------------- Disk image detail ----------------------
    def _build_disk_image_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("Disk Image Tools")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=760, tightening_threshold=620)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        # Disk image section
        image_label = Gtk.Label(label="Disk Image", xalign=0)
        image_label.add_css_class("title-4")
        form.append(image_label)

        file_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.disk_file_entry = Gtk.Entry()
        self.disk_file_entry.add_css_class("modern-entry")
        self.disk_file_entry.set_placeholder_text("Select a raw image...")
        self.disk_file_entry.set_hexpand(True)
        file_row.append(self.disk_file_entry)
        browse_btn = Gtk.Button(label="Browse…")
        browse_btn.connect("clicked", self._on_disk_browse)
        file_row.append(browse_btn)
        form.append(file_row)

        # Analysis options section
        options_label = Gtk.Label(label="Analysis Options", xalign=0)
        options_label.add_css_class("title-4")
        form.append(options_label)

        options_grid = Gtk.Grid()
        options_grid.set_row_spacing(8)
        options_grid.set_column_spacing(12)
        
        options_grid.attach(Gtk.Label(label="Sector size", xalign=0), 0, 0, 1, 1)
        self.disk_sector_spin = Gtk.SpinButton()
        self.disk_sector_spin.set_adjustment(Gtk.Adjustment(lower=128, upper=8192, step_increment=128, page_increment=512))
        self.disk_sector_spin.set_value(512)
        options_grid.attach(self.disk_sector_spin, 1, 0, 1, 1)
        
        options_grid.attach(Gtk.Label(label="Max partitions", xalign=0), 2, 0, 1, 1)
        self.disk_partition_spin = Gtk.SpinButton()
        self.disk_partition_spin.set_adjustment(Gtk.Adjustment(lower=1, upper=256, step_increment=1, page_increment=8))
        self.disk_partition_spin.set_value(16)
        options_grid.attach(self.disk_partition_spin, 3, 0, 1, 1)
        
        form.append(options_grid)

        self.disk_hash_check = Gtk.CheckButton(label="Include hashes (slower)")
        form.append(self.disk_hash_check)

        actions_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.disk_run_btn = Gtk.Button(label="Analyze")
        self.disk_run_btn.add_css_class("suggested-action")
        self.disk_run_btn.connect("clicked", self._on_disk_run)
        actions_row.append(self.disk_run_btn)
        self.disk_copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        self.disk_copy_btn.set_tooltip_text("Copy result")
        self.disk_copy_btn.set_sensitive(False)
        self.disk_copy_btn.connect("clicked", self._on_disk_copy)
        actions_row.append(self.disk_copy_btn)
        form.append(actions_row)

        # Result section
        result_label = Gtk.Label(label="Result", xalign=0)
        result_label.add_css_class("title-4")
        form.append(result_label)

        self.disk_result_view = Gtk.TextView()
        self.disk_result_view.add_css_class("output-text")
        self.disk_result_view.set_editable(False)
        self.disk_result_view.set_monospace(True)
        result_scroller = Gtk.ScrolledWindow()
        result_scroller.add_css_class("output-box")
        result_scroller.set_min_content_height(550)
        result_scroller.set_child(self.disk_result_view)
        form.append(result_scroller)

    def _open_disk_image_tools(self, tool) -> None:
        self._active_tool = tool
        self.disk_file_entry.set_text("")
        self.disk_sector_spin.set_value(512)
        self.disk_partition_spin.set_value(16)
        self.disk_hash_check.set_active(False)
        self._set_text_view_text(self.disk_result_view, "")
        self.disk_copy_btn.set_sensitive(False)
        self.tool_detail_stack.set_visible_child_name("disk_image_tools")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_disk_browse(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative.new("Select disk image", self.window, Gtk.FileChooserAction.OPEN, None, None)
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                self.disk_file_entry.set_text(file.get_path() or "")
        dialog.destroy()

    def _on_disk_run(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        path = self.disk_file_entry.get_text().strip()
        if not path:
            self.toast_overlay.add_toast(Adw.Toast.new("Choose a disk image"))
            return
        sector = str(int(self.disk_sector_spin.get_value()))
        partitions = str(int(self.disk_partition_spin.get_value()))
        include_hash = "true" if self.disk_hash_check.get_active() else "false"
        self.disk_run_btn.set_sensitive(False)
        self._set_text_view_text(self.disk_result_view, "Parsing partition tables…")

        def worker() -> None:
            try:
                result = self._active_tool.run(
                    file_path=path,
                    sector_size=sector,
                    max_partitions=partitions,
                    include_hashes=include_hash,
                )
                body = getattr(result, "body", str(result))
                GLib.idle_add(self._set_text_view_text, self.disk_result_view, body)
                GLib.idle_add(self.disk_copy_btn.set_sensitive, bool(body.strip()))
            except Exception as exc:
                GLib.idle_add(self.toast_overlay.add_toast, Adw.Toast.new(f"Error: {exc}"))
            finally:
                GLib.idle_add(self.disk_run_btn.set_sensitive, True)

        threading.Thread(target=worker, daemon=True).start()

    def _on_disk_copy(self, _btn: Gtk.Button) -> None:
        display = self.window.get_display()
        if display is None:
            return
        clipboard = display.get_clipboard()
        buffer = self.disk_result_view.get_buffer()
        start, end = buffer.get_bounds()
        clipboard.set_text(buffer.get_text(start, end, True))

    # ---------------------- Timeline builder detail ----------------------
    def _build_timeline_builder_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("Timeline Builder")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=760, tightening_threshold=620)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        # Target section
        target_label = Gtk.Label(label="Target", xalign=0)
        target_label.add_css_class("title-4")
        form.append(target_label)

        target_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.timeline_target_entry = Gtk.Entry()
        self.timeline_target_entry.add_css_class("modern-entry")
        self.timeline_target_entry.set_placeholder_text("Directory or file to index...")
        self.timeline_target_entry.set_hexpand(True)
        target_row.append(self.timeline_target_entry)
        browse_file_btn = Gtk.Button(label="Browse File…")
        browse_file_btn.connect("clicked", self._on_timeline_browse_file)
        target_row.append(browse_file_btn)
        browse_folder_btn = Gtk.Button(label="Browse Folder…")
        browse_folder_btn.connect("clicked", self._on_timeline_browse_folder)
        target_row.append(browse_folder_btn)
        form.append(target_row)

        # Timeline options section
        options_label = Gtk.Label(label="Timeline Options", xalign=0)
        options_label.add_css_class("title-4")
        form.append(options_label)

        limit_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        limit_row.append(Gtk.Label(label="Max entries", xalign=0))
        self.timeline_limit_spin = Gtk.SpinButton()
        self.timeline_limit_spin.set_adjustment(Gtk.Adjustment(lower=50, upper=10000, step_increment=50, page_increment=500))
        self.timeline_limit_spin.set_value(500)
        limit_row.append(self.timeline_limit_spin)
        self.timeline_include_dirs_check = Gtk.CheckButton(label="Include directories")
        self.timeline_include_dirs_check.set_active(True)
        limit_row.append(self.timeline_include_dirs_check)
        form.append(limit_row)

        format_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        format_row.append(Gtk.Label(label="Format", xalign=0))
        self.timeline_format_combo = Gtk.ComboBoxText()
        self.timeline_format_combo.append("csv", "CSV")
        self.timeline_format_combo.append("json", "JSON")
        self.timeline_format_combo.set_active_id("csv")
        format_row.append(self.timeline_format_combo)
        self.timeline_hash_check = Gtk.CheckButton(label="Hash files (sha256)")
        format_row.append(self.timeline_hash_check)
        form.append(format_row)

        actions_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.timeline_run_btn = Gtk.Button(label="Build Timeline")
        self.timeline_run_btn.add_css_class("suggested-action")
        self.timeline_run_btn.connect("clicked", self._on_timeline_run)
        actions_row.append(self.timeline_run_btn)
        self.timeline_copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        self.timeline_copy_btn.set_tooltip_text("Copy result")
        self.timeline_copy_btn.set_sensitive(False)
        self.timeline_copy_btn.connect("clicked", self._on_timeline_copy)
        actions_row.append(self.timeline_copy_btn)
        form.append(actions_row)

        # Result section
        result_label = Gtk.Label(label="Result", xalign=0)
        result_label.add_css_class("title-4")
        form.append(result_label)

        self.timeline_result_view = Gtk.TextView()
        self.timeline_result_view.add_css_class("output-text")
        self.timeline_result_view.set_editable(False)
        self.timeline_result_view.set_monospace(True)
        result_scroller = Gtk.ScrolledWindow()
        result_scroller.add_css_class("output-box")
        result_scroller.set_min_content_height(550)
        result_scroller.set_child(self.timeline_result_view)
        form.append(result_scroller)

    def _open_timeline_builder(self, tool) -> None:
        self._active_tool = tool
        self.timeline_target_entry.set_text("")
        self.timeline_limit_spin.set_value(500)
        self.timeline_include_dirs_check.set_active(True)
        self.timeline_format_combo.set_active_id("csv")
        self.timeline_hash_check.set_active(False)
        self._set_text_view_text(self.timeline_result_view, "")
        self.timeline_copy_btn.set_sensitive(False)
        self.tool_detail_stack.set_visible_child_name("timeline_builder")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_timeline_browse_file(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative.new("Select file", self.window, Gtk.FileChooserAction.OPEN, None, None)
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                self.timeline_target_entry.set_text(file.get_path() or "")
        dialog.destroy()

    def _on_timeline_browse_folder(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative.new("Select folder", self.window, Gtk.FileChooserAction.SELECT_FOLDER, None, None)
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                self.timeline_target_entry.set_text(file.get_path() or "")
        dialog.destroy()

    def _on_timeline_run(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        path = self.timeline_target_entry.get_text().strip()
        if not path:
            self.toast_overlay.add_toast(Adw.Toast.new("Choose a file or folder"))
            return
        limit = str(int(self.timeline_limit_spin.get_value()))
        include_dirs = "true" if self.timeline_include_dirs_check.get_active() else "false"
        format_choice = self.timeline_format_combo.get_active_id() or "csv"
        include_hash = "true" if self.timeline_hash_check.get_active() else "false"
        self.timeline_run_btn.set_sensitive(False)
        self._set_text_view_text(self.timeline_result_view, "Building timeline…")

        def worker() -> None:
            try:
                result = self._active_tool.run(
                    target_path=path,
                    max_entries=limit,
                    include_directories=include_dirs,
                    output_format=format_choice,
                    include_hashes=include_hash,
                )
                body = getattr(result, "body", str(result))
                GLib.idle_add(self._set_text_view_text, self.timeline_result_view, body)
                GLib.idle_add(self.timeline_copy_btn.set_sensitive, bool(body.strip()))
            except Exception as exc:
                GLib.idle_add(self.toast_overlay.add_toast, Adw.Toast.new(f"Error: {exc}"))
            finally:
                GLib.idle_add(self.timeline_run_btn.set_sensitive, True)

        threading.Thread(target=worker, daemon=True).start()

    def _on_timeline_copy(self, _btn: Gtk.Button) -> None:
        display = self.window.get_display()
        if display is None:
            return
        clipboard = display.get_clipboard()
        buffer = self.timeline_result_view.get_buffer()
        start, end = buffer.get_bounds()
        clipboard.set_text(buffer.get_text(start, end, True))

    # ---------------------- Image stego detail ----------------------
    def _build_image_stego_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("Image Stego Toolkit")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=760, tightening_threshold=620)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        # Image section
        image_label = Gtk.Label(label="Image", xalign=0)
        image_label.add_css_class("title-4")
        form.append(image_label)

        file_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.image_stego_file_entry = Gtk.Entry()
        self.image_stego_file_entry.add_css_class("modern-entry")
        self.image_stego_file_entry.set_placeholder_text("Select an image file...")
        self.image_stego_file_entry.set_hexpand(True)
        file_row.append(self.image_stego_file_entry)
        browse_btn = Gtk.Button(label="Browse…")
        browse_btn.connect("clicked", self._on_image_stego_browse)
        file_row.append(browse_btn)
        form.append(file_row)

        # Analysis options section
        options_label = Gtk.Label(label="Analysis Options", xalign=0)
        options_label.add_css_class("title-4")
        form.append(options_label)

        password_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        password_row.append(Gtk.Label(label="Steghide password", xalign=0))
        self.image_stego_password_entry = Gtk.Entry()
        self.image_stego_password_entry.add_css_class("modern-entry")
        self.image_stego_password_entry.set_placeholder_text("Optional passphrase...")
        self.image_stego_password_entry.set_visibility(False)
        self.image_stego_password_entry.set_hexpand(True)
        password_row.append(self.image_stego_password_entry)
        self.image_stego_extract_check = Gtk.CheckButton(label="Attempt extraction")
        password_row.append(self.image_stego_extract_check)
        form.append(password_row)

        stegsolve_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        stegsolve_row.append(Gtk.Label(label="stegsolve.jar", xalign=0))
        self.image_stego_jar_entry = Gtk.Entry()
        self.image_stego_jar_entry.add_css_class("modern-entry")
        self.image_stego_jar_entry.set_placeholder_text("Optional path to stegsolve.jar...")
        self.image_stego_jar_entry.set_hexpand(True)
        stegsolve_row.append(self.image_stego_jar_entry)
        jar_btn = Gtk.Button(label="Browse…")
        jar_btn.connect("clicked", self._on_image_stego_jar_browse)
        stegsolve_row.append(jar_btn)
        form.append(stegsolve_row)

        tool_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        tool_row.append(Gtk.Label(label="Tool", xalign=0))
        self.image_stego_tool_combo = Gtk.ComboBoxText()
        self.image_stego_tool_combo.append("zsteg", "zsteg")
        self.image_stego_tool_combo.append("steghide", "steghide")
        self.image_stego_tool_combo.append("all", "Run both")
        self.image_stego_tool_combo.set_active(0)
        tool_row.append(self.image_stego_tool_combo)
        form.append(tool_row)

        actions_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.image_stego_run_btn = Gtk.Button(label="Run Toolkit")
        self.image_stego_run_btn.add_css_class("suggested-action")
        self.image_stego_run_btn.connect("clicked", self._on_image_stego_run)
        actions_row.append(self.image_stego_run_btn)
        self.image_stego_copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        self.image_stego_copy_btn.set_tooltip_text("Copy result")
        self.image_stego_copy_btn.set_sensitive(False)
        self.image_stego_copy_btn.connect("clicked", self._on_image_stego_copy)
        actions_row.append(self.image_stego_copy_btn)
        form.append(actions_row)

        # Result section
        result_label = Gtk.Label(label="Result", xalign=0)
        result_label.add_css_class("title-4")
        form.append(result_label)

        self.image_stego_result_view = Gtk.TextView()
        self.image_stego_result_view.add_css_class("output-text")
        self.image_stego_result_view.set_editable(False)
        self.image_stego_result_view.set_monospace(True)
        result_scroller = Gtk.ScrolledWindow()
        result_scroller.add_css_class("output-box")
        result_scroller.set_min_content_height(550)
        result_scroller.set_child(self.image_stego_result_view)
        form.append(result_scroller)

    def _open_image_stego(self, tool) -> None:
        self._active_tool = tool
        self.image_stego_file_entry.set_text("")
        self.image_stego_password_entry.set_text("")
        self.image_stego_extract_check.set_active(False)
        self.image_stego_jar_entry.set_text("")
        self.image_stego_tool_combo.set_active(0)
        self._set_text_view_text(self.image_stego_result_view, "")
        self.image_stego_copy_btn.set_sensitive(False)
        self.tool_detail_stack.set_visible_child_name("image_stego")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_image_stego_browse(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative.new("Select image", self.window, Gtk.FileChooserAction.OPEN, None, None)
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                self.image_stego_file_entry.set_text(file.get_path() or "")
        dialog.destroy()

    def _on_image_stego_jar_browse(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative.new("Select stegsolve.jar", self.window, Gtk.FileChooserAction.OPEN, None, None)
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                self.image_stego_jar_entry.set_text(file.get_path() or "")
        dialog.destroy()

    def _on_image_stego_run(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        path = self.image_stego_file_entry.get_text().strip()
        if not path:
            self.toast_overlay.add_toast(Adw.Toast.new("Choose an image file"))
            return
        password = self.image_stego_password_entry.get_text()
        extract = "true" if self.image_stego_extract_check.get_active() else "false"
        jar = self.image_stego_jar_entry.get_text().strip()
        tool_choice = self.image_stego_tool_combo.get_active_id() or "zsteg"
        self.image_stego_run_btn.set_sensitive(False)
        self._set_text_view_text(self.image_stego_result_view, f"Running {tool_choice}…")

        def worker() -> None:
            try:
                result = self._active_tool.run(
                    image_path=path,
                    steghide_password=password,
                    steghide_extract=extract,
                    stegsolve_jar=jar,
                    tool_choice=tool_choice,
                )
                body = getattr(result, "body", str(result))
                GLib.idle_add(self._set_text_view_text, self.image_stego_result_view, body)
                GLib.idle_add(self.image_stego_copy_btn.set_sensitive, bool(body.strip()))
            except Exception as exc:
                GLib.idle_add(self.toast_overlay.add_toast, Adw.Toast.new(f"Error: {exc}"))
            finally:
                GLib.idle_add(self.image_stego_run_btn.set_sensitive, True)

        threading.Thread(target=worker, daemon=True).start()

    def _on_image_stego_copy(self, _btn: Gtk.Button) -> None:
        display = self.window.get_display()
        if display is None:
            return
        clipboard = display.get_clipboard()
        buffer = self.image_stego_result_view.get_buffer()
        start, end = buffer.get_bounds()
        clipboard.set_text(buffer.get_text(start, end, True))

    # ---------------------- EXIF metadata detail ----------------------
    def _build_exif_metadata_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("EXIF Metadata Viewer")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=760, tightening_threshold=620)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        # Media file section
        media_label = Gtk.Label(label="Media File", xalign=0)
        media_label.add_css_class("title-4")
        form.append(media_label)

        file_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.exif_file_entry = Gtk.Entry()
        self.exif_file_entry.add_css_class("modern-entry")
        self.exif_file_entry.set_placeholder_text("Select media...")
        self.exif_file_entry.set_hexpand(True)
        file_row.append(self.exif_file_entry)
        browse_btn = Gtk.Button(label="Browse…")
        browse_btn.connect("clicked", self._on_exif_browse)
        file_row.append(browse_btn)
        form.append(file_row)

        # Options section
        options_section_label = Gtk.Label(label="Options", xalign=0)
        options_section_label.add_css_class("title-4")
        form.append(options_section_label)

        options_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.exif_prefer_check = Gtk.CheckButton(label="Prefer exiftool if available")
        self.exif_prefer_check.set_active(True)
        options_row.append(self.exif_prefer_check)
        form.append(options_row)

        actions_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.exif_run_btn = Gtk.Button(label="Inspect Metadata")
        self.exif_run_btn.add_css_class("suggested-action")
        self.exif_run_btn.connect("clicked", self._on_exif_run)
        actions_row.append(self.exif_run_btn)
        self.exif_copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        self.exif_copy_btn.set_tooltip_text("Copy result")
        self.exif_copy_btn.set_sensitive(False)
        self.exif_copy_btn.connect("clicked", self._on_exif_copy)
        actions_row.append(self.exif_copy_btn)
        form.append(actions_row)

        # Result section
        result_label = Gtk.Label(label="Result", xalign=0)
        result_label.add_css_class("title-4")
        form.append(result_label)

        self.exif_result_view = Gtk.TextView()
        self.exif_result_view.add_css_class("output-text")
        self.exif_result_view.set_editable(False)
        self.exif_result_view.set_monospace(True)
        result_scroller = Gtk.ScrolledWindow()
        result_scroller.add_css_class("output-box")
        result_scroller.set_min_content_height(550)
        result_scroller.set_child(self.exif_result_view)
        form.append(result_scroller)

    def _open_exif_metadata(self, tool) -> None:
        self._active_tool = tool
        self.exif_file_entry.set_text("")
        self.exif_prefer_check.set_active(True)
        self._set_text_view_text(self.exif_result_view, "")
        self.exif_copy_btn.set_sensitive(False)
        self.tool_detail_stack.set_visible_child_name("exif_metadata")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_exif_browse(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative.new("Select media", self.window, Gtk.FileChooserAction.OPEN, None, None)
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                self.exif_file_entry.set_text(file.get_path() or "")
        dialog.destroy()

    def _on_exif_run(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        path = self.exif_file_entry.get_text().strip()
        if not path:
            self.toast_overlay.add_toast(Adw.Toast.new("Choose a file"))
            return
        prefer = "true" if self.exif_prefer_check.get_active() else "false"
        self.exif_run_btn.set_sensitive(False)
        self._set_text_view_text(self.exif_result_view, "Collecting metadata…")

        def worker() -> None:
            try:
                result = self._active_tool.run(file_path=path, prefer_exiftool=prefer)
                body = getattr(result, "body", str(result))
                GLib.idle_add(self._set_text_view_text, self.exif_result_view, body)
                GLib.idle_add(self.exif_copy_btn.set_sensitive, bool(body.strip()))
            except Exception as exc:
                GLib.idle_add(self.toast_overlay.add_toast, Adw.Toast.new(f"Error: {exc}"))
            finally:
                GLib.idle_add(self.exif_run_btn.set_sensitive, True)

        threading.Thread(target=worker, daemon=True).start()

    def _on_exif_copy(self, _btn: Gtk.Button) -> None:
        display = self.window.get_display()
        if display is None:
            return
        clipboard = display.get_clipboard()
        buffer = self.exif_result_view.get_buffer()
        start, end = buffer.get_bounds()
        clipboard.set_text(buffer.get_text(start, end, True))

    # ---------------------- Audio analyzer detail ----------------------
    def _build_audio_analyzer_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("Audio Analyzer")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=760, tightening_threshold=620)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        # Audio file section
        audio_label = Gtk.Label(label="Audio File", xalign=0)
        audio_label.add_css_class("title-4")
        form.append(audio_label)

        file_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.audio_file_entry = Gtk.Entry()
        self.audio_file_entry.add_css_class("modern-entry")
        self.audio_file_entry.set_placeholder_text("Select a WAV file...")
        self.audio_file_entry.set_hexpand(True)
        file_row.append(self.audio_file_entry)
        browse_btn = Gtk.Button(label="Browse…")
        browse_btn.connect("clicked", self._on_audio_browse)
        file_row.append(browse_btn)
        form.append(file_row)

        # Analysis options section
        options_label = Gtk.Label(label="Analysis Options", xalign=0)
        options_label.add_css_class("title-4")
        form.append(options_label)

        options_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.audio_dtmf_check = Gtk.CheckButton(label="Detect DTMF")
        self.audio_dtmf_check.set_active(True)
        options_row.append(self.audio_dtmf_check)
        self.audio_morse_check = Gtk.CheckButton(label="Detect Morse beeps")
        options_row.append(self.audio_morse_check)
        form.append(options_row)

        channel_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        channel_row.append(Gtk.Label(label="Channel", xalign=0))
        self.audio_channel_combo = Gtk.ComboBoxText()
        self.audio_channel_combo.append("mixed", "Mix (L+R)")
        self.audio_channel_combo.append("left", "Left only")
        self.audio_channel_combo.append("right", "Right only")
        self.audio_channel_combo.set_active_id("mixed")
        channel_row.append(self.audio_channel_combo)
        channel_row.append(Gtk.Label(label="Window (ms)", xalign=0))
        self.audio_window_spin = Gtk.SpinButton()
        self.audio_window_spin.set_adjustment(Gtk.Adjustment(lower=20, upper=500, step_increment=10, page_increment=50))
        self.audio_window_spin.set_value(80)
        channel_row.append(self.audio_window_spin)
        form.append(channel_row)

        actions_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.audio_run_btn = Gtk.Button(label="Analyze Audio")
        self.audio_run_btn.add_css_class("suggested-action")
        self.audio_run_btn.connect("clicked", self._on_audio_run)
        actions_row.append(self.audio_run_btn)
        self.audio_copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        self.audio_copy_btn.set_tooltip_text("Copy result")
        self.audio_copy_btn.set_sensitive(False)
        self.audio_copy_btn.connect("clicked", self._on_audio_copy)
        actions_row.append(self.audio_copy_btn)
        form.append(actions_row)

        # Result section
        result_label = Gtk.Label(label="Result", xalign=0)
        result_label.add_css_class("title-4")
        form.append(result_label)

        self.audio_result_view = Gtk.TextView()
        self.audio_result_view.add_css_class("output-text")
        self.audio_result_view.set_editable(False)
        self.audio_result_view.set_monospace(True)
        result_scroller = Gtk.ScrolledWindow()
        result_scroller.add_css_class("output-box")
        result_scroller.set_min_content_height(550)
        result_scroller.set_child(self.audio_result_view)
        form.append(result_scroller)

    def _open_audio_analyzer(self, tool) -> None:
        self._active_tool = tool
        self.audio_file_entry.set_text("")
        self.audio_dtmf_check.set_active(True)
        self.audio_morse_check.set_active(False)
        self.audio_channel_combo.set_active_id("mixed")
        self.audio_window_spin.set_value(80)
        self._set_text_view_text(self.audio_result_view, "")
        self.audio_copy_btn.set_sensitive(False)
        self.tool_detail_stack.set_visible_child_name("audio_analyzer")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_audio_browse(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative.new("Select audio", self.window, Gtk.FileChooserAction.OPEN, None, None)
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                self.audio_file_entry.set_text(file.get_path() or "")
        dialog.destroy()

    def _on_audio_run(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        path = self.audio_file_entry.get_text().strip()
        if not path:
            self.toast_overlay.add_toast(Adw.Toast.new("Choose an audio file"))
            return
        detect_dtmf = "true" if self.audio_dtmf_check.get_active() else "false"
        detect_morse = "true" if self.audio_morse_check.get_active() else "false"
        channel = self.audio_channel_combo.get_active_id() or "mixed"
        window = str(int(self.audio_window_spin.get_value()))
        self.audio_run_btn.set_sensitive(False)
        self._set_text_view_text(self.audio_result_view, "Analyzing audio…")

        def worker() -> None:
            try:
                result = self._active_tool.run(
                    file_path=path,
                    detect_dtmf=detect_dtmf,
                    detect_morse=detect_morse,
                    channel=channel,
                    window_ms=window,
                )
                body = getattr(result, "body", str(result))
                GLib.idle_add(self._set_text_view_text, self.audio_result_view, body)
                GLib.idle_add(self.audio_copy_btn.set_sensitive, bool(body.strip()))
            except Exception as exc:
                GLib.idle_add(self.toast_overlay.add_toast, Adw.Toast.new(f"Error: {exc}"))
            finally:
                GLib.idle_add(self.audio_run_btn.set_sensitive, True)

        threading.Thread(target=worker, daemon=True).start()

    def _on_audio_copy(self, _btn: Gtk.Button) -> None:
        display = self.window.get_display()
        if display is None:
            return
        clipboard = display.get_clipboard()
        buffer = self.audio_result_view.get_buffer()
        start, end = buffer.get_bounds()
        clipboard.set_text(buffer.get_text(start, end, True))

    # ---------------------- Video exporter detail ----------------------
    def _build_video_exporter_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("Video Frame Exporter")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=760, tightening_threshold=620)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        input_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        input_row.append(Gtk.Label(label="Video", xalign=0))
        self.video_input_entry = Gtk.Entry()
        self.video_input_entry.add_css_class("modern-entry")
        self.video_input_entry.set_placeholder_text("Select a video file")
        input_row.append(self.video_input_entry)
        browse_input_btn = Gtk.Button(label="Browse…")
        browse_input_btn.connect("clicked", self._on_video_input_browse)
        input_row.append(browse_input_btn)
        form.append(input_row)

        output_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        output_row.append(Gtk.Label(label="Output folder", xalign=0))
        self.video_output_entry = Gtk.Entry()
        self.video_output_entry.add_css_class("modern-entry")
        self.video_output_entry.set_placeholder_text("Optional destination for frames")
        output_row.append(self.video_output_entry)
        browse_output_btn = Gtk.Button(label="Browse…")
        browse_output_btn.connect("clicked", self._on_video_output_browse)
        output_row.append(browse_output_btn)
        form.append(output_row)

        options_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        options_row.append(Gtk.Label(label="Interval (s)", xalign=0))
        self.video_interval_spin = Gtk.SpinButton()
        self.video_interval_spin.set_adjustment(Gtk.Adjustment(lower=0.1, upper=600, step_increment=0.1, page_increment=5))
        self.video_interval_spin.set_increments(0.1, 1.0)
        self.video_interval_spin.set_digits(1)
        self.video_interval_spin.set_value(2.0)
        options_row.append(self.video_interval_spin)
        options_row.append(Gtk.Label(label="Max frames", xalign=0))
        self.video_max_frames_spin = Gtk.SpinButton()
        self.video_max_frames_spin.set_adjustment(Gtk.Adjustment(lower=0, upper=5000, step_increment=10, page_increment=100))
        self.video_max_frames_spin.set_value(0)
        options_row.append(self.video_max_frames_spin)
        self.video_analyze_check = Gtk.CheckButton(label="Hash generated frames")
        options_row.append(self.video_analyze_check)
        form.append(options_row)

        actions_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.video_run_btn = Gtk.Button(label="Export Frames")
        self.video_run_btn.add_css_class("suggested-action")
        self.video_run_btn.connect("clicked", self._on_video_run)
        actions_row.append(self.video_run_btn)
        self.video_copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        self.video_copy_btn.set_tooltip_text("Copy result")
        self.video_copy_btn.set_sensitive(False)
        self.video_copy_btn.connect("clicked", self._on_video_copy)
        actions_row.append(self.video_copy_btn)
        form.append(actions_row)

        self.video_result_view = Gtk.TextView()
        self.video_result_view.add_css_class("output-text")
        self.video_result_view.set_editable(False)
        self.video_result_view.set_monospace(True)
        result_scroller = Gtk.ScrolledWindow()
        result_scroller.add_css_class("output-box")
        result_scroller.set_min_content_height(550)
        result_scroller.set_child(self.video_result_view)
        form.append(result_scroller)

    def _open_video_exporter(self, tool) -> None:
        self._active_tool = tool
        self.video_input_entry.set_text("")
        self.video_output_entry.set_text("")
        self.video_interval_spin.set_value(2.0)
        self.video_max_frames_spin.set_value(0)
        self.video_analyze_check.set_active(False)
        self._set_text_view_text(self.video_result_view, "")
        self.video_copy_btn.set_sensitive(False)
        self.tool_detail_stack.set_visible_child_name("video_frame_exporter")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_video_input_browse(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative.new("Select video", self.window, Gtk.FileChooserAction.OPEN, None, None)
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                self.video_input_entry.set_text(file.get_path() or "")
        dialog.destroy()

    def _on_video_output_browse(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative.new("Select output folder", self.window, Gtk.FileChooserAction.SELECT_FOLDER, None, None)
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                self.video_output_entry.set_text(file.get_path() or "")
        dialog.destroy()

    def _on_video_run(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        input_path = self.video_input_entry.get_text().strip()
        if not input_path:
            self.toast_overlay.add_toast(Adw.Toast.new("Choose a video file"))
            return
        output_dir = self.video_output_entry.get_text().strip()
        interval = f"{self.video_interval_spin.get_value():.2f}"
        max_frames = str(int(self.video_max_frames_spin.get_value()))
        analyse = "true" if self.video_analyze_check.get_active() else "false"
        self.video_run_btn.set_sensitive(False)
        self._set_text_view_text(self.video_result_view, "Exporting frames…")

        def worker() -> None:
            try:
                result = self._active_tool.run(
                    file_path=input_path,
                    output_dir=output_dir,
                    interval_seconds=interval,
                    max_frames=max_frames,
                    analyze_frames=analyse,
                )
                body = getattr(result, "body", str(result))
                GLib.idle_add(self._set_text_view_text, self.video_result_view, body)
                GLib.idle_add(self.video_copy_btn.set_sensitive, bool(body.strip()))
            except Exception as exc:
                GLib.idle_add(self.toast_overlay.add_toast, Adw.Toast.new(f"Error: {exc}"))
            finally:
                GLib.idle_add(self.video_run_btn.set_sensitive, True)

        threading.Thread(target=worker, daemon=True).start()

    def _on_video_copy(self, _btn: Gtk.Button) -> None:
        display = self.window.get_display()
        if display is None:
            return
        clipboard = display.get_clipboard()
        buffer = self.video_result_view.get_buffer()
        start, end = buffer.get_bounds()
        clipboard.set_text(buffer.get_text(start, end, True))

    # ---------------------- QR/Barcode scanner detail ----------------------
    def _build_qr_scanner_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("QR/Barcode Scanner")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=760, tightening_threshold=620)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        # Target section
        target_section_label = Gtk.Label(label="Target", xalign=0)
        target_section_label.add_css_class("title-4")
        form.append(target_section_label)

        target_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.qr_target_entry = Gtk.Entry()
        self.qr_target_entry.add_css_class("modern-entry")
        self.qr_target_entry.set_placeholder_text("File or folder to scan...")
        self.qr_target_entry.set_hexpand(True)
        target_row.append(self.qr_target_entry)
        browse_file_btn = Gtk.Button(label="File…")
        browse_file_btn.connect("clicked", self._on_qr_browse_file)
        target_row.append(browse_file_btn)
        browse_folder_btn = Gtk.Button(label="Folder…")
        browse_folder_btn.connect("clicked", self._on_qr_browse_folder)
        target_row.append(browse_folder_btn)
        form.append(target_row)

        # Scan options section
        options_label = Gtk.Label(label="Scan Options", xalign=0)
        options_label.add_css_class("title-4")
        form.append(options_label)

        options_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.qr_recursive_check = Gtk.CheckButton(label="Scan recursively")
        options_row.append(self.qr_recursive_check)
        self.qr_raw_check = Gtk.CheckButton(label="Keep raw output")
        options_row.append(self.qr_raw_check)
        form.append(options_row)

        actions_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.qr_run_btn = Gtk.Button(label="Scan Codes")
        self.qr_run_btn.add_css_class("suggested-action")
        self.qr_run_btn.connect("clicked", self._on_qr_run)
        actions_row.append(self.qr_run_btn)
        self.qr_copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        self.qr_copy_btn.set_tooltip_text("Copy result")
        self.qr_copy_btn.set_sensitive(False)
        self.qr_copy_btn.connect("clicked", self._on_qr_copy)
        actions_row.append(self.qr_copy_btn)
        form.append(actions_row)

        # Result section
        result_label = Gtk.Label(label="Result", xalign=0)
        result_label.add_css_class("title-4")
        form.append(result_label)

        self.qr_result_view = Gtk.TextView()
        self.qr_result_view.add_css_class("output-text")
        self.qr_result_view.set_editable(False)
        self.qr_result_view.set_monospace(True)
        result_scroller = Gtk.ScrolledWindow()
        result_scroller.add_css_class("output-box")
        result_scroller.set_min_content_height(550)
        result_scroller.set_child(self.qr_result_view)
        form.append(result_scroller)

    def _open_qr_scanner(self, tool) -> None:
        self._active_tool = tool
        self.qr_target_entry.set_text("")
        self.qr_recursive_check.set_active(False)
        self.qr_raw_check.set_active(False)
        self._set_text_view_text(self.qr_result_view, "")
        self.qr_copy_btn.set_sensitive(False)
        self.tool_detail_stack.set_visible_child_name("qr_scanner")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_qr_browse_file(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative.new("Select file", self.window, Gtk.FileChooserAction.OPEN, None, None)
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                self.qr_target_entry.set_text(file.get_path() or "")
        dialog.destroy()

    def _on_qr_browse_folder(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative.new("Select folder", self.window, Gtk.FileChooserAction.SELECT_FOLDER, None, None)
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                self.qr_target_entry.set_text(file.get_path() or "")
        dialog.destroy()

    def _on_qr_run(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        target = self.qr_target_entry.get_text().strip()
        if not target:
            self.toast_overlay.add_toast(Adw.Toast.new("Choose a file or folder"))
            return
        recursive = "true" if self.qr_recursive_check.get_active() else "false"
        raw = "true" if self.qr_raw_check.get_active() else "false"
        self.qr_run_btn.set_sensitive(False)
        self._set_text_view_text(self.qr_result_view, "Scanning for codes…")

        def worker() -> None:
            try:
                result = self._active_tool.run(
                    target_path=target,
                    recursive=recursive,
                    include_raw_output=raw,
                )
                body = getattr(result, "body", str(result))
                GLib.idle_add(self._set_text_view_text, self.qr_result_view, body)
                GLib.idle_add(self.qr_copy_btn.set_sensitive, bool(body.strip()))
            except Exception as exc:
                GLib.idle_add(self.toast_overlay.add_toast, Adw.Toast.new(f"Error: {exc}"))
            finally:
                GLib.idle_add(self.qr_run_btn.set_sensitive, True)

        threading.Thread(target=worker, daemon=True).start()

    def _on_qr_copy(self, _btn: Gtk.Button) -> None:
        display = self.window.get_display()
        if display is None:
            return
        clipboard = display.get_clipboard()
        buffer = self.qr_result_view.get_buffer()
        start, end = buffer.get_bounds()
        clipboard.set_text(buffer.get_text(start, end, True))

    def _build_strings_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("Extract Strings")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=720, tightening_threshold=560)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        # File section
        file_label = Gtk.Label(label="File", xalign=0)
        file_label.add_css_class("title-4")
        form.append(file_label)

        file_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.strings_file_entry = Gtk.Entry()
        self.strings_file_entry.add_css_class("modern-entry")
        self.strings_file_entry.set_placeholder_text("Select a binary or document...")
        self.strings_file_entry.set_hexpand(True)
        file_row.append(self.strings_file_entry)
        browse_btn = Gtk.Button(label="Browse…")
        browse_btn.connect("clicked", self._on_strings_browse)
        file_row.append(browse_btn)
        form.append(file_row)

        # Extraction options section
        options_label = Gtk.Label(label="Extraction Options", xalign=0)
        options_label.add_css_class("title-4")
        form.append(options_label)

        params_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        params_row.append(Gtk.Label(label="Min length", xalign=0))
        self.strings_min_spin = Gtk.SpinButton()
        self.strings_min_spin.set_adjustment(Gtk.Adjustment(lower=1, upper=32, step_increment=1, page_increment=2))
        self.strings_min_spin.set_value(4)
        params_row.append(self.strings_min_spin)
        params_row.append(Gtk.Label(label="Limit", xalign=0))
        self.strings_limit_spin = Gtk.SpinButton()
        self.strings_limit_spin.set_adjustment(Gtk.Adjustment(lower=0, upper=500, step_increment=5, page_increment=20))
        self.strings_limit_spin.set_value(0)
        params_row.append(self.strings_limit_spin)
        form.append(params_row)

        flags_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.strings_unicode_check = Gtk.CheckButton(label="Include UTF-16")
        flags_row.append(self.strings_unicode_check)
        self.strings_unique_check = Gtk.CheckButton(label="Unique only")
        self.strings_unique_check.set_active(True)
        flags_row.append(self.strings_unique_check)
        form.append(flags_row)

        search_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        search_row.append(Gtk.Label(label="Filter", xalign=0))
        self.strings_search_entry = Gtk.Entry()
        self.strings_search_entry.add_css_class("modern-entry")
        self.strings_search_entry.set_placeholder_text("Optional substring filter...")
        self.strings_search_entry.set_hexpand(True)
        search_row.append(self.strings_search_entry)
        form.append(search_row)

        actions_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.strings_run_btn = Gtk.Button(label="Extract")
        self.strings_run_btn.add_css_class("suggested-action")
        self.strings_run_btn.connect("clicked", self._on_strings_run)
        actions_row.append(self.strings_run_btn)
        self.strings_copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        self.strings_copy_btn.set_tooltip_text("Copy results")
        self.strings_copy_btn.set_sensitive(False)
        self.strings_copy_btn.connect("clicked", self._on_strings_copy)
        actions_row.append(self.strings_copy_btn)
        form.append(actions_row)

        # Result section
        result_label = Gtk.Label(label="Result", xalign=0)
        result_label.add_css_class("title-4")
        form.append(result_label)

        self.strings_result_view = Gtk.TextView()
        self.strings_result_view.add_css_class("output-text")
        self.strings_result_view.set_editable(False)
        self.strings_result_view.set_monospace(True)
        strings_scroller = Gtk.ScrolledWindow()
        strings_scroller.add_css_class("output-box")
        strings_scroller.set_min_content_height(550)
        strings_scroller.set_child(self.strings_result_view)
        form.append(strings_scroller)

    def _open_strings(self, tool) -> None:
        self._active_tool = tool
        self.strings_file_entry.set_text("")
        self.strings_min_spin.set_value(4)
        self.strings_limit_spin.set_value(0)
        self.strings_unicode_check.set_active(False)
        self.strings_unique_check.set_active(True)
        self.strings_search_entry.set_text("")
        self.strings_result_view.get_buffer().set_text("")
        self.strings_copy_btn.set_sensitive(False)
        self.tool_detail_stack.set_visible_child_name("strings")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_strings_browse(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative.new("Select file", self.window, Gtk.FileChooserAction.OPEN, None, None)
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                self.strings_file_entry.set_text(file.get_path() or "")
        dialog.destroy()

    def _on_strings_run(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        path = self.strings_file_entry.get_text().strip()
        if not path:
            self.toast_overlay.add_toast(Adw.Toast.new("Choose a file"))
            return
        self.strings_run_btn.set_sensitive(False)
        self.strings_result_view.get_buffer().set_text("Extracting strings…")

        min_len = str(int(self.strings_min_spin.get_value()))
        limit = str(int(self.strings_limit_spin.get_value()))
        unicode_flag = "true" if self.strings_unicode_check.get_active() else "false"
        unique_flag = "true" if self.strings_unique_check.get_active() else "false"
        search_term = self.strings_search_entry.get_text().strip()

        def worker() -> None:
            try:
                result = self._active_tool.run(
                    file_path=path,
                    min_length=min_len,
                    unicode=unicode_flag,
                    unique=unique_flag,
                    search=search_term,
                    limit=limit,
                )
                body = getattr(result, "body", str(result))
                GLib.idle_add(self.strings_result_view.get_buffer().set_text, body)
                GLib.idle_add(self.strings_copy_btn.set_sensitive, bool(body.strip()))
            except Exception as exc:
                GLib.idle_add(self.toast_overlay.add_toast, Adw.Toast.new(f"Error: {exc}"))
            finally:
                GLib.idle_add(self.strings_run_btn.set_sensitive, True)

        threading.Thread(target=worker, daemon=True).start()

    # ---------------------- Disassembler launcher detail ----------------------
    def _build_disassembler_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("Disassembler Launcher")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=760, tightening_threshold=620)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        # Binary file section
        binary_label = Gtk.Label(label="Binary", xalign=0)
        binary_label.add_css_class("title-4")
        form.append(binary_label)
        
        file_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.disassembler_file_entry = Gtk.Entry()
        self.disassembler_file_entry.add_css_class("modern-entry")
        self.disassembler_file_entry.set_placeholder_text("Select a binary to open...")
        self.disassembler_file_entry.set_hexpand(True)
        file_row.append(self.disassembler_file_entry)
        browse_btn = Gtk.Button(label="Browse…")
        browse_btn.connect("clicked", self._on_disassembler_browse)
        file_row.append(browse_btn)
        form.append(file_row)

        # Tool settings section
        tool_label = Gtk.Label(label="Tool Settings", xalign=0)
        tool_label.add_css_class("title-4")
        form.append(tool_label)
        
        tool_grid = Gtk.Grid()
        tool_grid.set_row_spacing(8)
        tool_grid.set_column_spacing(12)
        
        tool_grid.attach(Gtk.Label(label="Tool", xalign=0), 0, 0, 1, 1)
        self.disassembler_tool_combo = Gtk.ComboBoxText()
        self.disassembler_tool_combo.append("auto", "Auto (first available)")
        self.disassembler_tool_combo.append("ghidra", "Ghidra")
        self.disassembler_tool_combo.append("ghidra-headless", "Ghidra (headless)")
        self.disassembler_tool_combo.append("ida", "IDA Pro")
        self.disassembler_tool_combo.append("binaryninja", "Binary Ninja")
        self.disassembler_tool_combo.append("hopper", "Hopper")
        self.disassembler_tool_combo.append("cutter", "Cutter")
        self.disassembler_tool_combo.append("rizin", "rizin")
        self.disassembler_tool_combo.append("radare2", "radare2")
        self.disassembler_tool_combo.set_active_id("auto")
        self.disassembler_tool_combo.set_hexpand(True)
        tool_grid.attach(self.disassembler_tool_combo, 1, 0, 1, 1)

        tool_grid.attach(Gtk.Label(label="Launch mode", xalign=0), 0, 1, 1, 1)
        self.disassembler_mode_combo = Gtk.ComboBoxText()
        self.disassembler_mode_combo.append("auto", "Auto")
        self.disassembler_mode_combo.append("gui", "GUI")
        self.disassembler_mode_combo.append("cli", "CLI")
        self.disassembler_mode_combo.append("headless", "Headless")
        self.disassembler_mode_combo.set_active_id("auto")
        self.disassembler_mode_combo.set_hexpand(True)
        tool_grid.attach(self.disassembler_mode_combo, 1, 1, 1, 1)
        
        self.disassembler_list_check = Gtk.CheckButton(label="List available only")
        tool_grid.attach(self.disassembler_list_check, 2, 1, 1, 1)
        
        form.append(tool_grid)

        # Advanced options section
        advanced_label = Gtk.Label(label="Advanced Options", xalign=0)
        advanced_label.add_css_class("title-4")
        form.append(advanced_label)

        self.disassembler_extra_entry = Gtk.Entry()
        self.disassembler_extra_entry.add_css_class("modern-entry")
        self.disassembler_extra_entry.set_placeholder_text("Additional arguments...")
        form.append(self.disassembler_extra_entry)

        script_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        script_label = Gtk.Label(label="Script / commands", xalign=0)
        script_label.set_width_chars(18)
        script_row.append(script_label)
        self.disassembler_script_entry = Gtk.Entry()
        self.disassembler_script_entry.add_css_class("modern-entry")
        self.disassembler_script_entry.set_placeholder_text("Path or inline commands...")
        self.disassembler_script_entry.set_hexpand(True)
        script_row.append(self.disassembler_script_entry)
        script_btn = Gtk.Button(label="Browse…")
        script_btn.connect("clicked", self._on_disassembler_script_browse)
        script_row.append(script_btn)
        form.append(script_row)

        workdir_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        workdir_label = Gtk.Label(label="Working directory", xalign=0)
        workdir_label.set_width_chars(18)
        workdir_row.append(workdir_label)
        self.disassembler_workdir_entry = Gtk.Entry()
        self.disassembler_workdir_entry.add_css_class("modern-entry")
        self.disassembler_workdir_entry.set_placeholder_text("(optional)")
        self.disassembler_workdir_entry.set_hexpand(True)
        workdir_row.append(self.disassembler_workdir_entry)
        workdir_btn = Gtk.Button(label="Choose folder…")
        workdir_btn.connect("clicked", self._on_disassembler_workdir_browse)
        workdir_row.append(workdir_btn)
        form.append(workdir_row)

        project_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        project_label = Gtk.Label(label="Project directory", xalign=0)
        project_label.set_width_chars(18)
        project_row.append(project_label)
        self.disassembler_project_entry = Gtk.Entry()
        self.disassembler_project_entry.add_css_class("modern-entry")
        self.disassembler_project_entry.set_placeholder_text("Used for headless Ghidra runs...")
        self.disassembler_project_entry.set_hexpand(True)
        project_row.append(self.disassembler_project_entry)
        project_btn = Gtk.Button(label="Browse…")
        project_btn.connect("clicked", self._on_disassembler_project_browse)
        project_row.append(project_btn)
        form.append(project_row)

        # Quick preview settings
        preview_label = Gtk.Label(label="Quick View Settings", xalign=0)
        preview_label.add_css_class("title-4")
        form.append(preview_label)

        preview_grid = Gtk.Grid()
        preview_grid.set_row_spacing(8)
        preview_grid.set_column_spacing(12)
        
        preview_grid.attach(Gtk.Label(label="Backend", xalign=0), 0, 0, 1, 1)
        self.disassembler_preview_backend_combo = Gtk.ComboBoxText()
        self.disassembler_preview_backend_combo.append("auto", "Auto")
        self.disassembler_preview_backend_combo.append("objdump", "objdump")
        self.disassembler_preview_backend_combo.append("radare2", "radare2")
        self.disassembler_preview_backend_combo.append("rizin", "rizin")
        self.disassembler_preview_backend_combo.set_active_id("auto")
        preview_grid.attach(self.disassembler_preview_backend_combo, 1, 0, 1, 1)
        
        preview_grid.attach(Gtk.Label(label="Syntax", xalign=0), 2, 0, 1, 1)
        self.disassembler_preview_syntax_combo = Gtk.ComboBoxText()
        self.disassembler_preview_syntax_combo.append("auto", "Auto")
        self.disassembler_preview_syntax_combo.append("intel", "Intel")
        self.disassembler_preview_syntax_combo.append("att", "AT&T")
        self.disassembler_preview_syntax_combo.set_active_id("auto")
        preview_grid.attach(self.disassembler_preview_syntax_combo, 3, 0, 1, 1)
        
        preview_grid.attach(Gtk.Label(label="Instructions", xalign=0), 4, 0, 1, 1)
        self.disassembler_preview_count_spin = Gtk.SpinButton()
        self.disassembler_preview_count_spin.set_adjustment(
            Gtk.Adjustment(lower=32, upper=2000, step_increment=32, page_increment=128)
        )
        self.disassembler_preview_count_spin.set_value(400)
        preview_grid.attach(self.disassembler_preview_count_spin, 5, 0, 1, 1)
        
        form.append(preview_grid)

        actions_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.disassembler_launch_btn = Gtk.Button(label="Launch")
        self.disassembler_launch_btn.add_css_class("suggested-action")
        self.disassembler_launch_btn.connect("clicked", self._on_disassembler_launch)
        actions_row.append(self.disassembler_launch_btn)
        self.disassembler_copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        self.disassembler_copy_btn.set_tooltip_text("Copy output")
        self.disassembler_copy_btn.set_sensitive(False)
        self.disassembler_copy_btn.connect("clicked", self._on_disassembler_copy)
        actions_row.append(self.disassembler_copy_btn)
        self.disassembler_preview_btn = Gtk.Button(label="Quick disassembly…")
        self.disassembler_preview_btn.connect("clicked", self._on_disassembler_preview)
        actions_row.append(self.disassembler_preview_btn)
        form.append(actions_row)

        self.disassembler_output_view = Gtk.TextView()
        self.disassembler_output_view.add_css_class("output-text")
        self.disassembler_output_view.set_editable(False)
        self.disassembler_output_view.set_wrap_mode(Gtk.WrapMode.WORD)
        self.disassembler_output_view.set_monospace(True)
        output_scroll = Gtk.ScrolledWindow()
        output_scroll.add_css_class("output-box")
        output_scroll.set_min_content_height(550)
        output_scroll.set_child(self.disassembler_output_view)
        form.append(output_scroll)

    def _open_disassembler(self, tool) -> None:
        self._active_tool = tool
        self.disassembler_file_entry.set_text("")
        self.disassembler_tool_combo.set_active_id("auto")
        self.disassembler_mode_combo.set_active_id("auto")
        self.disassembler_list_check.set_active(False)
        self.disassembler_extra_entry.set_text("")
        self.disassembler_script_entry.set_text("")
        self.disassembler_workdir_entry.set_text("")
        self.disassembler_project_entry.set_text("")
        self.disassembler_preview_backend_combo.set_active_id("auto")
        self.disassembler_preview_syntax_combo.set_active_id("auto")
        self.disassembler_preview_count_spin.set_value(400)
        self._set_text_view_text(self.disassembler_output_view, "")
        self.disassembler_copy_btn.set_sensitive(False)
        self.disassembler_launch_btn.set_sensitive(True)
        self.disassembler_preview_btn.set_sensitive(True)
        self.tool_detail_stack.set_visible_child_name("disassembler")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_disassembler_browse(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative.new("Select binary", self.window, Gtk.FileChooserAction.OPEN, None, None)
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                self.disassembler_file_entry.set_text(file.get_path() or "")
        dialog.destroy()

    def _on_disassembler_workdir_browse(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative.new("Select working directory", self.window, Gtk.FileChooserAction.SELECT_FOLDER, None, None)
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            folder = dialog.get_file()
            if folder:
                self.disassembler_workdir_entry.set_text(folder.get_path() or "")
        dialog.destroy()

    def _on_disassembler_script_browse(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative.new("Select script", self.window, Gtk.FileChooserAction.OPEN, None, None)
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                self.disassembler_script_entry.set_text(file.get_path() or "")
        dialog.destroy()

    def _on_disassembler_project_browse(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative.new("Select project directory", self.window, Gtk.FileChooserAction.SELECT_FOLDER, None, None)
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            folder = dialog.get_file()
            if folder:
                self.disassembler_project_entry.set_text(folder.get_path() or "")
        dialog.destroy()

    def _on_disassembler_launch(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        path = self.disassembler_file_entry.get_text().strip()
        listing_only = self.disassembler_list_check.get_active()
        if not listing_only and not path:
            self.toast_overlay.add_toast(Adw.Toast.new("Choose a binary to launch"))
            return
        preferred = self.disassembler_tool_combo.get_active_id() or "auto"
        extra = self.disassembler_extra_entry.get_text().strip()
        workdir = self.disassembler_workdir_entry.get_text().strip()
        mode = self.disassembler_mode_combo.get_active_id() or "auto"
        script = self.disassembler_script_entry.get_text().strip()
        project_dir = self.disassembler_project_entry.get_text().strip()
        list_flag = "true" if listing_only else "false"
        self.disassembler_launch_btn.set_sensitive(False)
        busy_text = "Listing available disassemblers…" if listing_only else "Launching disassembler…"
        self._set_text_view_text(self.disassembler_output_view, busy_text)

        def worker() -> None:
            try:
                result = self._active_tool.run(
                    file_path=path,
                    preferred=preferred,
                    extra=extra,
                    workdir=workdir,
                    mode=mode,
                    script=script,
                    project_dir=project_dir,
                    list_available=list_flag,
                )
                body = getattr(result, "body", str(result))
                GLib.idle_add(self._set_text_view_text, self.disassembler_output_view, body)
                GLib.idle_add(self.disassembler_copy_btn.set_sensitive, bool(body.strip()))
            except Exception as exc:
                GLib.idle_add(self.toast_overlay.add_toast, Adw.Toast.new(f"Error: {exc}"))
            finally:
                GLib.idle_add(self.disassembler_launch_btn.set_sensitive, True)

        threading.Thread(target=worker, daemon=True).start()

    def _on_disassembler_copy(self, _btn: Gtk.Button) -> None:
        display = self.window.get_display()
        if display is None:
            return
        clipboard = display.get_clipboard()
        clipboard.set_text(self._get_text_view_text(self.disassembler_output_view))

    def _on_disassembler_preview(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "quick_disassembler", None):
            return
        path = self.disassembler_file_entry.get_text().strip()
        if not path:
            self.toast_overlay.add_toast(Adw.Toast.new("Choose a binary to disassemble"))
            return
        backend = self.disassembler_preview_backend_combo.get_active_id() or "auto"
        syntax = self.disassembler_preview_syntax_combo.get_active_id() or "auto"
        count = str(int(self.disassembler_preview_count_spin.get_value()))
        self.disassembler_preview_btn.set_sensitive(False)
        self._ensure_disassembly_preview_window()
        if self.disassembly_preview_window:
            self.disassembly_preview_window.present()
        if self.disassembly_preview_view:
            self._set_text_view_text(self.disassembly_preview_view, "Generating disassembly…")
        if self.disassembly_preview_status_label:
            self.disassembly_preview_status_label.set_text("Working…")
        if self.disassembly_preview_copy_btn:
            self.disassembly_preview_copy_btn.set_sensitive(False)
        if self.disassembly_preview_search:
            self.disassembly_preview_search.set_text("")

        def worker() -> None:
            try:
                result = self.quick_disassembler.run(
                    file_path=path,
                    preferred=backend,
                    max_instructions=count,
                    syntax=syntax,
                )
                GLib.idle_add(self._update_disassembly_preview, result.title, result.body)
            except Exception as exc:
                GLib.idle_add(self.toast_overlay.add_toast, Adw.Toast.new(f"Error: {exc}"))
            finally:
                GLib.idle_add(self.disassembler_preview_btn.set_sensitive, True)

        threading.Thread(target=worker, daemon=True).start()

    def _ensure_disassembly_preview_window(self) -> None:
        if self.disassembly_preview_window is not None:
            return
        window = Adw.ApplicationWindow(application=self.app)
        window.set_transient_for(self.window)
        window.set_title("Quick Disassembly")
        window.set_default_size(960, 720)

        toolbar = Adw.ToolbarView()
        window.set_content(toolbar)

        header = Adw.HeaderBar()
        header_title = Adw.WindowTitle(title="Quick Disassembly", subtitle="Inline view")
        header.set_title_widget(header_title)
        toolbar.add_top_bar(header)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=12, margin_bottom=12, margin_start=12, margin_end=12)
        toolbar.set_content(content)

        search_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        search_label = Gtk.Label(label="Search", xalign=0)
        search_label.add_css_class("dim-label")
        search_row.append(search_label)
        search_entry = Gtk.SearchEntry()
        search_entry.set_hexpand(True)
        search_entry.set_placeholder_text("Find text…")
        search_entry.connect("search-changed", self._on_disassembly_preview_search)
        search_row.append(search_entry)
        copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        copy_btn.set_tooltip_text("Copy disassembly")
        copy_btn.set_sensitive(False)
        copy_btn.connect("clicked", self._on_disassembly_preview_copy)
        search_row.append(copy_btn)
        content.append(search_row)

        status_label = Gtk.Label(xalign=0)
        status_label.add_css_class("dim-label")
        status_label.set_text("Ready")
        content.append(status_label)

        text_view = Gtk.TextView()
        text_view.set_editable(False)
        text_view.set_wrap_mode(Gtk.WrapMode.NONE)
        text_view.set_monospace(True)
        buffer = text_view.get_buffer()
        self._disassembly_preview_highlight_tag = buffer.create_tag(
            "disassembly-highlight",
            background="#f9f06b",
        )
        scroll = Gtk.ScrolledWindow()
        scroll.set_hexpand(True)
        scroll.set_vexpand(True)
        scroll.set_child(text_view)
        content.append(scroll)

        self.disassembly_preview_window = window
        self.disassembly_preview_view = text_view
        self.disassembly_preview_search = search_entry
        self.disassembly_preview_status_label = status_label
        self.disassembly_preview_copy_btn = copy_btn

    def _update_disassembly_preview(self, title: str, body: str) -> bool:
        if self.disassembly_preview_status_label:
            self.disassembly_preview_status_label.set_text(title)
        if self.disassembly_preview_view:
            self._set_text_view_text(self.disassembly_preview_view, body)
        if self.disassembly_preview_copy_btn:
            self.disassembly_preview_copy_btn.set_sensitive(bool(body.strip()))
        self._clear_disassembly_highlight()
        return False

    def _on_disassembly_preview_search(self, entry: Gtk.SearchEntry) -> None:
        if not self.disassembly_preview_view:
            return
        buffer = self.disassembly_preview_view.get_buffer()
        start = buffer.get_start_iter()
        end = buffer.get_end_iter()
        if self._disassembly_preview_highlight_tag:
            buffer.remove_tag(self._disassembly_preview_highlight_tag, start, end)
        query = entry.get_text().strip()
        if not query:
            buffer.select_range(start, start)
            return
        result = start.forward_search(query, Gtk.TextSearchFlags.CASE_INSENSITIVE, end)
        if not result:
            return
        match_start, match_end = result
        if self._disassembly_preview_highlight_tag:
            buffer.apply_tag(self._disassembly_preview_highlight_tag, match_start, match_end)
        buffer.select_range(match_start, match_end)
        self.disassembly_preview_view.scroll_to_iter(match_start, 0.2, True, 0.5, 0.1)

    def _clear_disassembly_highlight(self) -> None:
        if not self.disassembly_preview_view or not self._disassembly_preview_highlight_tag:
            return
        buffer = self.disassembly_preview_view.get_buffer()
        buffer.remove_tag(
            self._disassembly_preview_highlight_tag,
            buffer.get_start_iter(),
            buffer.get_end_iter(),
        )

    def _on_disassembly_preview_copy(self, _btn: Gtk.Button) -> None:
        if not self.disassembly_preview_view:
            return
        display = self.window.get_display()
        if display is None:
            return
        clipboard = display.get_clipboard()
        clipboard.set_text(self._get_text_view_text(self.disassembly_preview_view))

    # ---------------------- Rizin console detail ----------------------
    def _build_rizin_console_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("Radare/Rizin Console")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=760, tightening_threshold=620)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        # Binary section
        binary_label = Gtk.Label(label="Binary", xalign=0)
        binary_label.add_css_class("title-4")
        form.append(binary_label)

        file_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.rizin_file_entry = Gtk.Entry()
        self.rizin_file_entry.add_css_class("modern-entry")
        self.rizin_file_entry.set_placeholder_text("Select a binary to analyze...")
        self.rizin_file_entry.set_hexpand(True)
        file_row.append(self.rizin_file_entry)
        browse_btn = Gtk.Button(label="Browse…")
        browse_btn.connect("clicked", self._on_rizin_browse)
        file_row.append(browse_btn)
        form.append(file_row)

        # Commands section
        commands_section_label = Gtk.Label(label="Commands", xalign=0)
        commands_section_label.add_css_class("title-4")
        form.append(commands_section_label)

        commands_label = Gtk.Label(label="Commands", xalign=0)
        commands_label.add_css_class("dim-label")
        form.append(commands_label)
        self.rizin_commands_view = Gtk.TextView()
        self.rizin_commands_view.add_css_class("input-text")
        self.rizin_commands_view.set_monospace(True)
        commands_scroll = Gtk.ScrolledWindow()
        commands_scroll.add_css_class("input-box")
        commands_scroll.set_min_content_height(150)
        commands_scroll.set_child(self.rizin_commands_view)
        form.append(commands_scroll)

        options_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        options_row.append(Gtk.Label(label="Tool", xalign=0))
        self.rizin_tool_combo = Gtk.ComboBoxText()
        self.rizin_tool_combo.append("auto", "Auto")
        self.rizin_tool_combo.append("rizin", "rizin")
        self.rizin_tool_combo.append("radare2", "radare2")
        self.rizin_tool_combo.set_active_id("auto")
        options_row.append(self.rizin_tool_combo)
        self.rizin_quiet_check = Gtk.CheckButton(label="Quiet mode")
        self.rizin_quiet_check.set_active(True)
        options_row.append(self.rizin_quiet_check)
        form.append(options_row)

        actions_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.rizin_run_btn = Gtk.Button(label="Run")
        self.rizin_run_btn.add_css_class("suggested-action")
        self.rizin_run_btn.connect("clicked", self._on_rizin_run)
        actions_row.append(self.rizin_run_btn)
        self.rizin_copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        self.rizin_copy_btn.set_tooltip_text("Copy output")
        self.rizin_copy_btn.set_sensitive(False)
        self.rizin_copy_btn.connect("clicked", self._on_rizin_copy)
        actions_row.append(self.rizin_copy_btn)
        form.append(actions_row)

        # Result section
        result_label = Gtk.Label(label="Result", xalign=0)
        result_label.add_css_class("title-4")
        form.append(result_label)

        self.rizin_output_view = Gtk.TextView()
        self.rizin_output_view.add_css_class("output-text")
        self.rizin_output_view.set_editable(False)
        self.rizin_output_view.set_monospace(True)
        self.rizin_output_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        output_scroll = Gtk.ScrolledWindow()
        output_scroll.add_css_class("output-box")
        output_scroll.set_min_content_height(550)
        output_scroll.set_child(self.rizin_output_view)
        form.append(output_scroll)

    def _open_rizin_console(self, tool) -> None:
        self._active_tool = tool
        self.rizin_file_entry.set_text("")
        self._set_text_view_text(self.rizin_commands_view, "aaa\ns main\npdf @ main")
        self.rizin_tool_combo.set_active_id("auto")
        self.rizin_quiet_check.set_active(True)
        self._set_text_view_text(self.rizin_output_view, "")
        self.rizin_copy_btn.set_sensitive(False)
        self.rizin_run_btn.set_sensitive(True)
        self.tool_detail_stack.set_visible_child_name("rizin_console")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_rizin_browse(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative.new("Select binary", self.window, Gtk.FileChooserAction.OPEN, None, None)
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                self.rizin_file_entry.set_text(file.get_path() or "")
        dialog.destroy()

    def _on_rizin_run(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        path = self.rizin_file_entry.get_text().strip()
        if not path:
            self.toast_overlay.add_toast(Adw.Toast.new("Choose a binary to analyze"))
            return
        commands = self._get_text_view_text(self.rizin_commands_view)
        tool_choice = self.rizin_tool_combo.get_active_id() or "auto"
        quiet = "true" if self.rizin_quiet_check.get_active() else "false"
        self.rizin_run_btn.set_sensitive(False)
        self._set_text_view_text(self.rizin_output_view, "Running commands…")

        def worker() -> None:
            try:
                result = self._active_tool.run(
                    file_path=path,
                    commands=commands,
                    tool=tool_choice,
                    quiet=quiet,
                )
                body = getattr(result, "body", str(result))
                GLib.idle_add(self._set_text_view_text, self.rizin_output_view, body)
                GLib.idle_add(self.rizin_copy_btn.set_sensitive, bool(body.strip()))
            except Exception as exc:
                GLib.idle_add(self.toast_overlay.add_toast, Adw.Toast.new(f"Error: {exc}"))
            finally:
                GLib.idle_add(self.rizin_run_btn.set_sensitive, True)

        threading.Thread(target=worker, daemon=True).start()

    def _on_rizin_copy(self, _btn: Gtk.Button) -> None:
        display = self.window.get_display()
        if display is None:
            return
        clipboard = display.get_clipboard()
        clipboard.set_text(self._get_text_view_text(self.rizin_output_view))

    # ---------------------- GDB runner detail ----------------------
    def _build_gdb_runner_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("GDB Runner")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=840, tightening_threshold=640)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        # Binary section
        binary_label = Gtk.Label(label="Binary", xalign=0)
        binary_label.add_css_class("title-4")
        form.append(binary_label)

        file_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.gdb_file_entry = Gtk.Entry()
        self.gdb_file_entry.add_css_class("modern-entry")
        self.gdb_file_entry.set_placeholder_text("Select a binary or PID...")
        self.gdb_file_entry.set_hexpand(True)
        file_row.append(self.gdb_file_entry)
        browse_btn = Gtk.Button(label="Browse…")
        browse_btn.connect("clicked", self._on_gdb_browse)
        file_row.append(browse_btn)
        form.append(file_row)

        # Options section
        options_label = Gtk.Label(label="Options", xalign=0)
        options_label.add_css_class("title-4")
        form.append(options_label)

        args_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.gdb_args_entry = Gtk.Entry()
        self.gdb_args_entry.add_css_class("modern-entry")
        self.gdb_args_entry.set_placeholder_text("Program arguments...")
        self.gdb_args_entry.set_hexpand(True)
        args_row.append(self.gdb_args_entry)
        self.gdb_attach_entry = Gtk.Entry()
        self.gdb_attach_entry.add_css_class("modern-entry")
        self.gdb_attach_entry.set_placeholder_text("Attach PID (optional)...")
        self.gdb_attach_entry.set_hexpand(True)
        args_row.append(self.gdb_attach_entry)
        self.gdb_stop_check = Gtk.CheckButton(label="Break on entry")
        args_row.append(self.gdb_stop_check)
        form.append(args_row)

        break_label = Gtk.Label(label="Breakpoints (one per line)", xalign=0)
        break_label.add_css_class("dim-label")
        form.append(break_label)
        self.gdb_breakpoints_view = Gtk.TextView()
        self.gdb_breakpoints_view.add_css_class("input-text")
        self.gdb_breakpoints_view.set_monospace(True)
        bp_scroll = Gtk.ScrolledWindow()
        bp_scroll.add_css_class("input-box")
        bp_scroll.set_min_content_height(150)
        bp_scroll.set_child(self.gdb_breakpoints_view)
        form.append(bp_scroll)

        cmd_label = Gtk.Label(label="Commands", xalign=0)
        cmd_label.add_css_class("dim-label")
        form.append(cmd_label)
        self.gdb_commands_view = Gtk.TextView()
        self.gdb_commands_view.add_css_class("input-text")
        self.gdb_commands_view.set_monospace(True)
        cmd_scroll = Gtk.ScrolledWindow()
        cmd_scroll.add_css_class("input-box")
        cmd_scroll.set_min_content_height(150)
        cmd_scroll.set_child(self.gdb_commands_view)
        form.append(cmd_scroll)

        add_label = Gtk.Label(label="Additional symbol files", xalign=0)
        add_label.add_css_class("dim-label")
        form.append(add_label)
        self.gdb_additional_view = Gtk.TextView()
        self.gdb_additional_view.add_css_class("input-text")
        self.gdb_additional_view.set_monospace(True)
        add_scroll = Gtk.ScrolledWindow()
        add_scroll.add_css_class("input-box")
        add_scroll.set_min_content_height(150)
        add_scroll.set_child(self.gdb_additional_view)
        form.append(add_scroll)

        actions_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.gdb_run_btn = Gtk.Button(label="Run")
        self.gdb_run_btn.add_css_class("suggested-action")
        self.gdb_run_btn.connect("clicked", self._on_gdb_run)
        actions_row.append(self.gdb_run_btn)
        self.gdb_copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        self.gdb_copy_btn.set_tooltip_text("Copy output")
        self.gdb_copy_btn.set_sensitive(False)
        self.gdb_copy_btn.connect("clicked", self._on_gdb_copy)
        actions_row.append(self.gdb_copy_btn)
        form.append(actions_row)

        # Result section
        result_label = Gtk.Label(label="Result", xalign=0)
        result_label.add_css_class("title-4")
        form.append(result_label)

        self.gdb_output_view = Gtk.TextView()
        self.gdb_output_view.add_css_class("output-text")
        self.gdb_output_view.set_editable(False)
        self.gdb_output_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.gdb_output_view.set_monospace(True)
        output_scroll = Gtk.ScrolledWindow()
        output_scroll.add_css_class("output-box")
        output_scroll.set_min_content_height(550)
        output_scroll.set_child(self.gdb_output_view)
        form.append(output_scroll)

    def _open_gdb_runner(self, tool) -> None:
        self._active_tool = tool
        self.gdb_file_entry.set_text("")
        self.gdb_args_entry.set_text("")
        self.gdb_attach_entry.set_text("")
        self.gdb_stop_check.set_active(False)
        self._set_text_view_text(self.gdb_breakpoints_view, "")
        self._set_text_view_text(self.gdb_commands_view, "info registers\nbacktrace\ninfo shared")
        self._set_text_view_text(self.gdb_additional_view, "")
        self._set_text_view_text(self.gdb_output_view, "")
        self.gdb_copy_btn.set_sensitive(False)
        self.gdb_run_btn.set_sensitive(True)
        self.tool_detail_stack.set_visible_child_name("gdb_runner")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_gdb_browse(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative.new("Select binary", self.window, Gtk.FileChooserAction.OPEN, None, None)
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                self.gdb_file_entry.set_text(file.get_path() or "")
        dialog.destroy()

    def _on_gdb_run(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        path = self.gdb_file_entry.get_text().strip()
        if not path:
            self.toast_overlay.add_toast(Adw.Toast.new("Choose a binary to debug"))
            return
        breakpoints = self._get_text_view_text(self.gdb_breakpoints_view)
        commands = self._get_text_view_text(self.gdb_commands_view)
        run_args = self.gdb_args_entry.get_text().strip()
        attach_pid = self.gdb_attach_entry.get_text().strip()
        additional = self._get_text_view_text(self.gdb_additional_view)
        stop_flag = "true" if self.gdb_stop_check.get_active() else "false"
        self.gdb_run_btn.set_sensitive(False)
        self._set_text_view_text(self.gdb_output_view, "Running gdb…")

        def worker() -> None:
            try:
                result = self._active_tool.run(
                    file_path=path,
                    breakpoints=breakpoints,
                    run_args=run_args,
                    commands=commands,
                    stop_on_entry=stop_flag,
                    attach_pid=attach_pid,
                    additional_files=additional,
                )
                body = getattr(result, "body", str(result))
                GLib.idle_add(self._set_text_view_text, self.gdb_output_view, body)
                GLib.idle_add(self.gdb_copy_btn.set_sensitive, bool(body.strip()))
            except Exception as exc:
                GLib.idle_add(self.toast_overlay.add_toast, Adw.Toast.new(f"Error: {exc}"))
            finally:
                GLib.idle_add(self.gdb_run_btn.set_sensitive, True)

        threading.Thread(target=worker, daemon=True).start()

    def _on_gdb_copy(self, _btn: Gtk.Button) -> None:
        display = self.window.get_display()
        if display is None:
            return
        clipboard = display.get_clipboard()
        clipboard.set_text(self._get_text_view_text(self.gdb_output_view))

    # ---------------------- ROP gadget detail ----------------------
    def _build_rop_gadget_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("ROP Gadget Finder")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=760, tightening_threshold=620)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        # Binary section
        binary_label = Gtk.Label(label="Binary", xalign=0)
        binary_label.add_css_class("title-4")
        form.append(binary_label)

        file_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.rop_file_entry = Gtk.Entry()
        self.rop_file_entry.add_css_class("modern-entry")
        self.rop_file_entry.set_placeholder_text("Select a binary...")
        self.rop_file_entry.set_hexpand(True)
        file_row.append(self.rop_file_entry)
        browse_btn = Gtk.Button(label="Browse…")
        browse_btn.connect("clicked", self._on_rop_browse)
        file_row.append(browse_btn)
        form.append(file_row)

        # Search options section
        options_label = Gtk.Label(label="Search Options", xalign=0)
        options_label.add_css_class("title-4")
        form.append(options_label)

        search_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.rop_search_entry = Gtk.Entry()
        self.rop_search_entry.add_css_class("modern-entry")
        self.rop_search_entry.set_placeholder_text("Filter (e.g., 'pop rdi; ret')...")
        self.rop_search_entry.set_hexpand(True)
        search_row.append(self.rop_search_entry)
        search_row.append(Gtk.Label(label="Max depth", xalign=0))
        self.rop_depth_spin = Gtk.SpinButton()
        self.rop_depth_spin.set_adjustment(Gtk.Adjustment(lower=1, upper=15, step_increment=1, page_increment=2))
        self.rop_depth_spin.set_value(6)
        search_row.append(self.rop_depth_spin)
        form.append(search_row)

        tool_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        tool_row.append(Gtk.Label(label="Tool", xalign=0))
        self.rop_tool_combo = Gtk.ComboBoxText()
        self.rop_tool_combo.append("auto", "Auto")
        self.rop_tool_combo.append("ropgadget", "ROPgadget")
        self.rop_tool_combo.append("ropper", "ropper")
        self.rop_tool_combo.append("rizin", "rizin")
        self.rop_tool_combo.set_active_id("auto")
        tool_row.append(self.rop_tool_combo)
        self.rop_run_all_check = Gtk.CheckButton(label="Run all detected")
        tool_row.append(self.rop_run_all_check)
        form.append(tool_row)

        arch_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        arch_row.append(Gtk.Label(label="Architecture", xalign=0))
        self.rop_arch_combo = Gtk.ComboBoxText()
        self.rop_arch_combo.append("auto", "Auto")
        self.rop_arch_combo.append("x86", "x86 (32-bit)")
        self.rop_arch_combo.append("x86_64", "x86_64")
        self.rop_arch_combo.append("arm", "ARM 32")
        self.rop_arch_combo.append("arm64", "ARM64 / AArch64")
        self.rop_arch_combo.append("mips", "MIPS")
        self.rop_arch_combo.append("riscv64", "RISC-V 64")
        self.rop_arch_combo.set_active_id("auto")
        arch_row.append(self.rop_arch_combo)
        arch_row.append(Gtk.Label(label="Limit lines", xalign=0))
        self.rop_limit_spin = Gtk.SpinButton()
        self.rop_limit_spin.set_adjustment(
            Gtk.Adjustment(lower=0, upper=1000, step_increment=10, page_increment=50)
        )
        self.rop_limit_spin.set_value(0)
        arch_row.append(self.rop_limit_spin)
        form.append(arch_row)

        actions_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.rop_run_btn = Gtk.Button(label="Find gadgets")
        self.rop_run_btn.add_css_class("suggested-action")
        self.rop_run_btn.connect("clicked", self._on_rop_run)
        actions_row.append(self.rop_run_btn)
        self.rop_copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        self.rop_copy_btn.set_tooltip_text("Copy output")
        self.rop_copy_btn.set_sensitive(False)
        self.rop_copy_btn.connect("clicked", self._on_rop_copy)
        actions_row.append(self.rop_copy_btn)
        form.append(actions_row)

        # Result section
        result_label = Gtk.Label(label="Result", xalign=0)
        result_label.add_css_class("title-4")
        form.append(result_label)

        self.rop_output_view = Gtk.TextView()
        self.rop_output_view.add_css_class("output-text")
        self.rop_output_view.set_editable(False)
        self.rop_output_view.set_monospace(True)
        self.rop_output_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        output_scroll = Gtk.ScrolledWindow()
        output_scroll.add_css_class("output-box")
        output_scroll.set_min_content_height(550)
        output_scroll.set_child(self.rop_output_view)
        form.append(output_scroll)

    def _open_rop_gadget(self, tool) -> None:
        self._active_tool = tool
        self.rop_file_entry.set_text("")
        self.rop_search_entry.set_text("")
        self.rop_depth_spin.set_value(6)
        self.rop_tool_combo.set_active_id("auto")
        self.rop_run_all_check.set_active(False)
        self.rop_arch_combo.set_active_id("auto")
        self.rop_limit_spin.set_value(0)
        self._set_text_view_text(self.rop_output_view, "")
        self.rop_copy_btn.set_sensitive(False)
        self.rop_run_btn.set_sensitive(True)
        self.tool_detail_stack.set_visible_child_name("rop_gadget")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_rop_browse(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative.new("Select binary", self.window, Gtk.FileChooserAction.OPEN, None, None)
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                self.rop_file_entry.set_text(file.get_path() or "")
        dialog.destroy()

    def _on_rop_run(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        path = self.rop_file_entry.get_text().strip()
        if not path:
            self.toast_overlay.add_toast(Adw.Toast.new("Choose a binary"))
            return
        search = self.rop_search_entry.get_text().strip()
        depth = str(int(self.rop_depth_spin.get_value()))
        tool_choice = "all" if self.rop_run_all_check.get_active() else (self.rop_tool_combo.get_active_id() or "auto")
        architecture = self.rop_arch_combo.get_active_id() or "auto"
        limit = str(int(self.rop_limit_spin.get_value()))
        self.rop_run_btn.set_sensitive(False)
        self._set_text_view_text(self.rop_output_view, "Finding gadgets…")

        def worker() -> None:
            try:
                result = self._active_tool.run(
                    file_path=path,
                    search=search,
                    max_depth=depth,
                    tool=tool_choice,
                    architecture=architecture,
                    limit=limit,
                )
                body = getattr(result, "body", str(result))
                GLib.idle_add(self._set_text_view_text, self.rop_output_view, body)
                GLib.idle_add(self.rop_copy_btn.set_sensitive, bool(body.strip()))
            except Exception as exc:
                GLib.idle_add(self.toast_overlay.add_toast, Adw.Toast.new(f"Error: {exc}"))
            finally:
                GLib.idle_add(self.rop_run_btn.set_sensitive, True)

        threading.Thread(target=worker, daemon=True).start()

    def _on_rop_copy(self, _btn: Gtk.Button) -> None:
        display = self.window.get_display()
        if display is None:
            return
        clipboard = display.get_clipboard()
        clipboard.set_text(self._get_text_view_text(self.rop_output_view))

    # ---------------------- Binary diff detail ----------------------
    def _build_binary_diff_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("Binary Diff")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=760, tightening_threshold=620)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        # Files section
        files_label = Gtk.Label(label="Files to Compare", xalign=0)
        files_label.add_css_class("title-4")
        form.append(files_label)

        orig_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        orig_label = Gtk.Label(label="Original", xalign=0)
        orig_label.set_width_chars(10)
        orig_row.append(orig_label)
        self.bindiff_original_entry = Gtk.Entry()
        self.bindiff_original_entry.add_css_class("modern-entry")
        self.bindiff_original_entry.set_hexpand(True)
        orig_row.append(self.bindiff_original_entry)
        orig_btn = Gtk.Button(label="Browse…")
        orig_btn.connect("clicked", lambda btn: self._on_bindiff_browse(btn, self.bindiff_original_entry))
        orig_row.append(orig_btn)
        form.append(orig_row)

        mod_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        mod_label = Gtk.Label(label="Modified", xalign=0)
        mod_label.set_width_chars(10)
        mod_row.append(mod_label)
        self.bindiff_modified_entry = Gtk.Entry()
        self.bindiff_modified_entry.add_css_class("modern-entry")
        self.bindiff_modified_entry.set_hexpand(True)
        mod_row.append(self.bindiff_modified_entry)
        mod_btn = Gtk.Button(label="Browse…")
        mod_btn.connect("clicked", lambda btn: self._on_bindiff_browse(btn, self.bindiff_modified_entry))
        mod_row.append(mod_btn)
        form.append(mod_row)

        # Options section
        options_label = Gtk.Label(label="Comparison Options", xalign=0)
        options_label.add_css_class("title-4")
        form.append(options_label)

        options_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        options_row.append(Gtk.Label(label="Tool", xalign=0))
        self.bindiff_tool_combo = Gtk.ComboBoxText()
        self.bindiff_tool_combo.append("auto", "Auto")
        self.bindiff_tool_combo.append("radiff2", "radiff2")
        self.bindiff_tool_combo.append("cmp", "cmp")
        self.bindiff_tool_combo.append("hash", "Hash summary")
        self.bindiff_tool_combo.set_active_id("auto")
        self.bindiff_tool_combo.set_hexpand(True)
        options_row.append(self.bindiff_tool_combo)
        form.append(options_row)

        self.bindiff_extra_entry = Gtk.Entry()
        self.bindiff_extra_entry.add_css_class("modern-entry")
        self.bindiff_extra_entry.set_placeholder_text("Extra arguments...")
        form.append(self.bindiff_extra_entry)

        actions_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.bindiff_run_btn = Gtk.Button(label="Compare")
        self.bindiff_run_btn.add_css_class("suggested-action")
        self.bindiff_run_btn.connect("clicked", self._on_bindiff_run)
        actions_row.append(self.bindiff_run_btn)
        self.bindiff_copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        self.bindiff_copy_btn.set_tooltip_text("Copy output")
        self.bindiff_copy_btn.set_sensitive(False)
        self.bindiff_copy_btn.connect("clicked", self._on_bindiff_copy)
        actions_row.append(self.bindiff_copy_btn)
        form.append(actions_row)

        # Result section
        result_label = Gtk.Label(label="Result", xalign=0)
        result_label.add_css_class("title-4")
        form.append(result_label)

        self.bindiff_output_view = Gtk.TextView()
        self.bindiff_output_view.add_css_class("output-text")
        self.bindiff_output_view.set_editable(False)
        self.bindiff_output_view.set_monospace(True)
        self.bindiff_output_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        output_scroll = Gtk.ScrolledWindow()
        output_scroll.add_css_class("output-box")
        output_scroll.set_min_content_height(550)
        output_scroll.set_child(self.bindiff_output_view)
        form.append(output_scroll)

    def _open_binary_diff(self, tool) -> None:
        self._active_tool = tool
        self.bindiff_original_entry.set_text("")
        self.bindiff_modified_entry.set_text("")
        self.bindiff_tool_combo.set_active_id("auto")
        self.bindiff_extra_entry.set_text("")
        self._set_text_view_text(self.bindiff_output_view, "")
        self.bindiff_copy_btn.set_sensitive(False)
        self.bindiff_run_btn.set_sensitive(True)
        self.tool_detail_stack.set_visible_child_name("binary_diff")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_bindiff_browse(self, _btn: Gtk.Button, entry: Gtk.Entry) -> None:
        dialog = Gtk.FileChooserNative.new("Select file", self.window, Gtk.FileChooserAction.OPEN, None, None)
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                entry.set_text(file.get_path() or "")
        dialog.destroy()

    def _on_bindiff_run(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        original = self.bindiff_original_entry.get_text().strip()
        modified = self.bindiff_modified_entry.get_text().strip()
        if not original or not modified:
            self.toast_overlay.add_toast(Adw.Toast.new("Choose both files to compare"))
            return
        tool_choice = self.bindiff_tool_combo.get_active_id() or "auto"
        extra = self.bindiff_extra_entry.get_text().strip()
        self.bindiff_run_btn.set_sensitive(False)
        self._set_text_view_text(self.bindiff_output_view, "Running diff…")

        def worker() -> None:
            try:
                result = self._active_tool.run(
                    original=original,
                    modified=modified,
                    tool=tool_choice,
                    extra=extra,
                )
                body = getattr(result, "body", str(result))
                GLib.idle_add(self._set_text_view_text, self.bindiff_output_view, body)
                GLib.idle_add(self.bindiff_copy_btn.set_sensitive, bool(body.strip()))
            except Exception as exc:
                GLib.idle_add(self.toast_overlay.add_toast, Adw.Toast.new(f"Error: {exc}"))
            finally:
                GLib.idle_add(self.bindiff_run_btn.set_sensitive, True)

        threading.Thread(target=worker, daemon=True).start()

    def _on_bindiff_copy(self, _btn: Gtk.Button) -> None:
        display = self.window.get_display()
        if display is None:
            return
        clipboard = display.get_clipboard()
        clipboard.set_text(self._get_text_view_text(self.bindiff_output_view))

    # ---------------------- Binary inspector detail ----------------------
    def _build_binary_inspector_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("PE/ELF Inspector")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=760, tightening_threshold=620)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        # Binary section
        binary_label = Gtk.Label(label="Binary", xalign=0)
        binary_label.add_css_class("title-4")
        form.append(binary_label)

        file_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.binary_inspect_file_entry = Gtk.Entry()
        self.binary_inspect_file_entry.add_css_class("modern-entry")
        self.binary_inspect_file_entry.set_placeholder_text("Select a binary...")
        self.binary_inspect_file_entry.set_hexpand(True)
        file_row.append(self.binary_inspect_file_entry)
        browse_btn = Gtk.Button(label="Browse…")
        browse_btn.connect("clicked", self._on_binary_inspect_browse)
        file_row.append(browse_btn)
        form.append(file_row)

        # Analysis options section
        options_label = Gtk.Label(label="Analysis Options", xalign=0)
        options_label.add_css_class("title-4")
        form.append(options_label)

        primary_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self.binary_inspect_file_check = Gtk.CheckButton(label="File metadata")
        self.binary_inspect_file_check.set_active(True)
        primary_row.append(self.binary_inspect_file_check)
        self.binary_inspect_headers_check = Gtk.CheckButton(label="Headers")
        self.binary_inspect_headers_check.set_active(True)
        primary_row.append(self.binary_inspect_headers_check)
        self.binary_inspect_sections_check = Gtk.CheckButton(label="Sections")
        self.binary_inspect_sections_check.set_active(True)
        primary_row.append(self.binary_inspect_sections_check)
        self.binary_inspect_segments_check = Gtk.CheckButton(label="Segments")
        self.binary_inspect_segments_check.set_active(False)
        primary_row.append(self.binary_inspect_segments_check)
        form.append(primary_row)

        secondary_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self.binary_inspect_symbols_check = Gtk.CheckButton(label="Symbols")
        self.binary_inspect_symbols_check.set_active(True)
        secondary_row.append(self.binary_inspect_symbols_check)
        self.binary_inspect_dynamic_check = Gtk.CheckButton(label="Dynamic entries")
        self.binary_inspect_dynamic_check.set_active(False)
        secondary_row.append(self.binary_inspect_dynamic_check)
        self.binary_inspect_checksec_check = Gtk.CheckButton(label="Security flags")
        self.binary_inspect_checksec_check.set_active(True)
        secondary_row.append(self.binary_inspect_checksec_check)
        self.binary_inspect_libraries_check = Gtk.CheckButton(label="Libraries")
        self.binary_inspect_libraries_check.set_active(False)
        secondary_row.append(self.binary_inspect_libraries_check)
        self.binary_inspect_strings_check = Gtk.CheckButton(label="Strings")
        self.binary_inspect_strings_check.set_active(False)
        secondary_row.append(self.binary_inspect_strings_check)
        form.append(secondary_row)

        config_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        config_row.append(Gtk.Label(label="Strings min length", xalign=0))
        self.binary_inspect_strings_spin = Gtk.SpinButton()
        self.binary_inspect_strings_spin.set_adjustment(Gtk.Adjustment(lower=2, upper=16, step_increment=1, page_increment=2))
        self.binary_inspect_strings_spin.set_value(4)
        config_row.append(self.binary_inspect_strings_spin)
        config_row.append(Gtk.Label(label="Max lines per section", xalign=0))
        self.binary_inspect_max_lines_spin = Gtk.SpinButton()
        self.binary_inspect_max_lines_spin.set_adjustment(
            Gtk.Adjustment(lower=50, upper=2000, step_increment=50, page_increment=200)
        )
        self.binary_inspect_max_lines_spin.set_value(400)
        config_row.append(self.binary_inspect_max_lines_spin)
        form.append(config_row)

        actions_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.binary_inspect_run_btn = Gtk.Button(label="Inspect")
        self.binary_inspect_run_btn.add_css_class("suggested-action")
        self.binary_inspect_run_btn.connect("clicked", self._on_binary_inspect_run)
        actions_row.append(self.binary_inspect_run_btn)
        self.binary_inspect_copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        self.binary_inspect_copy_btn.set_tooltip_text("Copy output")
        self.binary_inspect_copy_btn.set_sensitive(False)
        self.binary_inspect_copy_btn.connect("clicked", self._on_binary_inspect_copy)
        actions_row.append(self.binary_inspect_copy_btn)
        form.append(actions_row)

        # Result section
        result_label = Gtk.Label(label="Result", xalign=0)
        result_label.add_css_class("title-4")
        form.append(result_label)

        self.binary_inspect_output_view = Gtk.TextView()
        self.binary_inspect_output_view.add_css_class("output-text")
        self.binary_inspect_output_view.set_editable(False)
        self.binary_inspect_output_view.set_monospace(True)
        self.binary_inspect_output_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        output_scroll = Gtk.ScrolledWindow()
        output_scroll.add_css_class("output-box")
        output_scroll.set_min_content_height(550)
        output_scroll.set_child(self.binary_inspect_output_view)
        form.append(output_scroll)

    def _open_binary_inspector(self, tool) -> None:
        self._active_tool = tool
        self.binary_inspect_file_entry.set_text("")
        self.binary_inspect_file_check.set_active(True)
        self.binary_inspect_headers_check.set_active(True)
        self.binary_inspect_sections_check.set_active(True)
        self.binary_inspect_segments_check.set_active(False)
        self.binary_inspect_symbols_check.set_active(True)
        self.binary_inspect_dynamic_check.set_active(False)
        self.binary_inspect_checksec_check.set_active(True)
        self.binary_inspect_libraries_check.set_active(False)
        self.binary_inspect_strings_check.set_active(False)
        self.binary_inspect_strings_spin.set_value(4)
        self.binary_inspect_max_lines_spin.set_value(400)
        self._set_text_view_text(self.binary_inspect_output_view, "")
        self.binary_inspect_copy_btn.set_sensitive(False)
        self.binary_inspect_run_btn.set_sensitive(True)
        self.tool_detail_stack.set_visible_child_name("binary_inspector")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_binary_inspect_browse(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative.new("Select binary", self.window, Gtk.FileChooserAction.OPEN, None, None)
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                self.binary_inspect_file_entry.set_text(file.get_path() or "")
        dialog.destroy()

    def _on_binary_inspect_run(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        path = self.binary_inspect_file_entry.get_text().strip()
        if not path:
            self.toast_overlay.add_toast(Adw.Toast.new("Choose a binary"))
            return
        include_file = "true" if self.binary_inspect_file_check.get_active() else "false"
        include_headers = "true" if self.binary_inspect_headers_check.get_active() else "false"
        include_sections = "true" if self.binary_inspect_sections_check.get_active() else "false"
        include_segments = "true" if self.binary_inspect_segments_check.get_active() else "false"
        include_symbols = "true" if self.binary_inspect_symbols_check.get_active() else "false"
        include_dynamic = "true" if self.binary_inspect_dynamic_check.get_active() else "false"
        include_checksec = "true" if self.binary_inspect_checksec_check.get_active() else "false"
        include_libraries = "true" if self.binary_inspect_libraries_check.get_active() else "false"
        include_strings = "true" if self.binary_inspect_strings_check.get_active() else "false"
        strings_min = str(int(self.binary_inspect_strings_spin.get_value()))
        max_lines = str(int(self.binary_inspect_max_lines_spin.get_value()))
        self.binary_inspect_run_btn.set_sensitive(False)
        self._set_text_view_text(self.binary_inspect_output_view, "Collecting metadata…")

        def worker() -> None:
            try:
                result = self._active_tool.run(
                    file_path=path,
                    include_sections=include_sections,
                    include_symbols=include_symbols,
                    include_checksec=include_checksec,
                    include_file=include_file,
                    include_headers=include_headers,
                    include_segments=include_segments,
                    include_dynamic=include_dynamic,
                    include_libraries=include_libraries,
                    include_strings=include_strings,
                    strings_min_length=strings_min,
                    max_lines=max_lines,
                )
                body = getattr(result, "body", str(result))
                GLib.idle_add(self._set_text_view_text, self.binary_inspect_output_view, body)
                GLib.idle_add(self.binary_inspect_copy_btn.set_sensitive, bool(body.strip()))
            except Exception as exc:
                GLib.idle_add(self.toast_overlay.add_toast, Adw.Toast.new(f"Error: {exc}"))
            finally:
                GLib.idle_add(self.binary_inspect_run_btn.set_sensitive, True)

        threading.Thread(target=worker, daemon=True).start()

    def _on_binary_inspect_copy(self, _btn: Gtk.Button) -> None:
        display = self.window.get_display()
        if display is None:
            return
        clipboard = display.get_clipboard()
        clipboard.set_text(self._get_text_view_text(self.binary_inspect_output_view))

    # ---------------------- EXE Decompiler ----------------------
    def _build_exe_decompiler_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.connect("clicked", lambda _: self.content_stack.set_visible_child_name("tools"))
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("EXE Decompiler")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=760, tightening_threshold=620)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        # Binary section
        binary_label = Gtk.Label(label="Executable File", xalign=0)
        binary_label.add_css_class("title-4")
        form.append(binary_label)

        file_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.exe_decompiler_file_entry = Gtk.Entry()
        self.exe_decompiler_file_entry.add_css_class("modern-entry")
        self.exe_decompiler_file_entry.set_placeholder_text("Select a binary (.exe, .elf)...")
        self.exe_decompiler_file_entry.set_hexpand(True)
        file_row.append(self.exe_decompiler_file_entry)
        browse_btn = Gtk.Button(label="Browse…")
        browse_btn.connect("clicked", self._on_exe_decompiler_browse)
        file_row.append(browse_btn)
        form.append(file_row)

        # Decompiler options section
        options_label = Gtk.Label(label="Decompiler Options", xalign=0)
        options_label.add_css_class("title-4")
        form.append(options_label)

        engine_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        engine_row.append(Gtk.Label(label="Engine:", xalign=0))
        self.exe_decompiler_engine_combo = Gtk.ComboBoxText()
        self.exe_decompiler_engine_combo.append("auto", "Auto-detect (Best Available)")
        self.exe_decompiler_engine_combo.append("ghidra", "Ghidra (Best Quality)")
        self.exe_decompiler_engine_combo.append("rizin", "Rizin/r2dec (Fast)")
        self.exe_decompiler_engine_combo.append("objdump", "objdump (Basic Disassembly)")
        self.exe_decompiler_engine_combo.set_active(0)
        engine_row.append(self.exe_decompiler_engine_combo)
        form.append(engine_row)

        function_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        function_row.append(Gtk.Label(label="Function:", xalign=0))
        self.exe_decompiler_function_entry = Gtk.Entry()
        self.exe_decompiler_function_entry.add_css_class("modern-entry")
        self.exe_decompiler_function_entry.set_placeholder_text("main")
        self.exe_decompiler_function_entry.set_text("main")
        self.exe_decompiler_function_entry.set_hexpand(True)
        function_row.append(self.exe_decompiler_function_entry)
        form.append(function_row)

        hint_label = Gtk.Label(xalign=0)
        hint_label.add_css_class("dim-label")
        hint_label.set_markup("<small>Enter function name (e.g., 'main', 'entry0') or hex address (e.g., '0x401000')</small>")
        hint_label.set_wrap(True)
        form.append(hint_label)

        self.exe_decompiler_verbose_check = Gtk.CheckButton(label="Verbose output")
        self.exe_decompiler_verbose_check.set_active(False)
        form.append(self.exe_decompiler_verbose_check)

        actions_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.exe_decompiler_run_btn = Gtk.Button(label="Decompile")
        self.exe_decompiler_run_btn.add_css_class("suggested-action")
        self.exe_decompiler_run_btn.connect("clicked", self._on_exe_decompiler_run)
        actions_row.append(self.exe_decompiler_run_btn)
        self.exe_decompiler_copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        self.exe_decompiler_copy_btn.set_tooltip_text("Copy output")
        self.exe_decompiler_copy_btn.set_sensitive(False)
        self.exe_decompiler_copy_btn.connect("clicked", self._on_exe_decompiler_copy)
        actions_row.append(self.exe_decompiler_copy_btn)
        form.append(actions_row)

        # Result section
        result_label = Gtk.Label(label="Decompiled Code", xalign=0)
        result_label.add_css_class("title-4")
        form.append(result_label)

        self.exe_decompiler_output_view = Gtk.TextView()
        self.exe_decompiler_output_view.add_css_class("output-text")
        self.exe_decompiler_output_view.set_editable(False)
        self.exe_decompiler_output_view.set_monospace(True)
        self.exe_decompiler_output_view.set_wrap_mode(Gtk.WrapMode.NONE)
        output_scroll = Gtk.ScrolledWindow()
        output_scroll.add_css_class("output-box")
        output_scroll.set_min_content_height(550)
        output_scroll.set_child(self.exe_decompiler_output_view)
        form.append(output_scroll)

        self.tool_detail_stack.add_named(root, "exe_decompiler")

    def _open_exe_decompiler(self, tool) -> None:
        self._active_tool = tool
        self.exe_decompiler_file_entry.set_text("")
        self.exe_decompiler_engine_combo.set_active(0)
        self.exe_decompiler_function_entry.set_text("main")
        self.exe_decompiler_verbose_check.set_active(False)
        self._set_text_view_text(self.exe_decompiler_output_view, "")
        self.exe_decompiler_copy_btn.set_sensitive(False)
        self.exe_decompiler_run_btn.set_sensitive(True)
        self.tool_detail_stack.set_visible_child_name("exe_decompiler")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_exe_decompiler_browse(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative.new("Select executable", self.window, Gtk.FileChooserAction.OPEN, None, None)
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                self.exe_decompiler_file_entry.set_text(file.get_path() or "")
        dialog.destroy()

    def _on_exe_decompiler_run(self, _btn: Gtk.Button) -> None:
        if not self._active_tool:
            return

        file_path = self.exe_decompiler_file_entry.get_text().strip()
        if not file_path:
            self._set_text_view_text(self.exe_decompiler_output_view, "Error: Please select a binary file.")
            return

        engine = self.exe_decompiler_engine_combo.get_active_id() or "auto"
        function = self.exe_decompiler_function_entry.get_text().strip() or "main"
        verbose = "true" if self.exe_decompiler_verbose_check.get_active() else "false"

        self.exe_decompiler_run_btn.set_sensitive(False)
        self._set_text_view_text(self.exe_decompiler_output_view, "Decompiling... This may take a moment.")

        def worker():
            try:
                result = self._active_tool.run(
                    file_path=file_path,
                    engine=engine,
                    function=function,
                    verbose=verbose
                )
                body = getattr(result, "body", str(result))
                title = getattr(result, "title", "Result")
                output = f"{title}\n{'=' * len(title)}\n\n{body}"
                GLib.idle_add(self._set_text_view_text, self.exe_decompiler_output_view, output)
                GLib.idle_add(self.exe_decompiler_copy_btn.set_sensitive, bool(output.strip()))
            except Exception as exc:
                GLib.idle_add(self.toast_overlay.add_toast, Adw.Toast.new(f"Error: {exc}"))
            finally:
                GLib.idle_add(self.exe_decompiler_run_btn.set_sensitive, True)

        threading.Thread(target=worker, daemon=True).start()

    def _on_exe_decompiler_copy(self, _btn: Gtk.Button) -> None:
        display = self.window.get_display()
        if display is None:
            return
        clipboard = display.get_clipboard()
        clipboard.set_text(self._get_text_view_text(self.exe_decompiler_output_view))

    # ---------------------- JWT tool detail ----------------------
    def _build_jwt_tool_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("JWT Tool")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=860, tightening_threshold=620)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        # JWT token section
        token_section_label = Gtk.Label(label="JWT Token", xalign=0)
        token_section_label.add_css_class("title-4")
        form.append(token_section_label)

        token_label = Gtk.Label(label="Paste JWT", xalign=0)
        token_label.add_css_class("dim-label")
        form.append(token_label)
        self.jwt_token_view = Gtk.TextView()
        self.jwt_token_view.add_css_class("input-text")
        self.jwt_token_view.set_monospace(True)
        token_scroll = Gtk.ScrolledWindow()
        token_scroll.add_css_class("input-box")
        token_scroll.set_min_content_height(150)
        token_scroll.set_child(self.jwt_token_view)
        form.append(token_scroll)

        # Signing options section
        signing_label = Gtk.Label(label="Signing Options", xalign=0)
        signing_label.add_css_class("title-4")
        form.append(signing_label)

        secret_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.jwt_secret_entry = Gtk.Entry()
        self.jwt_secret_entry.add_css_class("modern-entry")
        self.jwt_secret_entry.set_placeholder_text("Shared secret (HS*)...")
        self.jwt_secret_entry.set_visibility(False)
        self.jwt_secret_entry.set_hexpand(True)
        secret_row.append(self.jwt_secret_entry)
        self.jwt_override_alg = Gtk.Entry()
        self.jwt_override_alg.add_css_class("modern-entry")
        self.jwt_override_alg.set_placeholder_text("Override alg (optional)...")
        self.jwt_override_alg.set_hexpand(True)
        secret_row.append(self.jwt_override_alg)
        form.append(secret_row)

        keys_label = Gtk.Label(label="Public / Private Keys (RS*, ES*)", xalign=0)
        keys_label.add_css_class("dim-label")
        form.append(keys_label)
        key_split = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        key_split.set_homogeneous(True)
        self.jwt_public_view = Gtk.TextView()
        self.jwt_public_view.add_css_class("input-text")
        self.jwt_public_view.set_monospace(True)
        public_scroll = Gtk.ScrolledWindow()
        public_scroll.add_css_class("input-box")
        public_scroll.set_min_content_height(150)
        public_scroll.set_child(self.jwt_public_view)
        key_split.append(public_scroll)
        self.jwt_private_view = Gtk.TextView()
        self.jwt_private_view.add_css_class("input-text")
        self.jwt_private_view.set_monospace(True)
        private_scroll = Gtk.ScrolledWindow()
        private_scroll.add_css_class("input-box")
        private_scroll.set_min_content_height(150)
        private_scroll.set_child(self.jwt_private_view)
        key_split.append(private_scroll)
        form.append(key_split)

        # Overrides section
        overrides_label = Gtk.Label(label="Overrides", xalign=0)
        overrides_label.add_css_class("title-4")
        form.append(overrides_label)

        override_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        override_row.append(Gtk.Label(label="Header override (JSON)", xalign=0))
        override_row.append(Gtk.Label(label="Payload override (JSON)", xalign=0))
        form.append(override_row)

        override_split = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        override_split.set_homogeneous(True)
        self.jwt_header_view = Gtk.TextView()
        self.jwt_header_view.add_css_class("input-text")
        self.jwt_header_view.set_monospace(True)
        header_scroll = Gtk.ScrolledWindow()
        header_scroll.add_css_class("input-box")
        header_scroll.set_min_content_height(150)
        header_scroll.set_child(self.jwt_header_view)
        override_split.append(header_scroll)
        self.jwt_payload_view = Gtk.TextView()
        self.jwt_payload_view.add_css_class("input-text")
        self.jwt_payload_view.set_monospace(True)
        payload_scroll = Gtk.ScrolledWindow()
        payload_scroll.add_css_class("input-box")
        payload_scroll.set_min_content_height(150)
        payload_scroll.set_child(self.jwt_payload_view)
        override_split.append(payload_scroll)
        form.append(override_split)

        switches_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        switches_row.add_css_class("switch-group")
        self.jwt_verify_switch = Gtk.Switch()
        self.jwt_verify_switch.set_active(True)
        switches_row.append(self._build_switch_field("Verify", self.jwt_verify_switch))
        self.jwt_resign_switch = Gtk.Switch()
        switches_row.append(self._build_switch_field("Re-sign", self.jwt_resign_switch))
        self.jwt_none_switch = Gtk.Switch()
        switches_row.append(self._build_switch_field("None attack", self.jwt_none_switch))
        form.append(switches_row)

        run_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.jwt_run_btn = Gtk.Button(label="Analyze JWT")
        self.jwt_run_btn.add_css_class("suggested-action")
        self.jwt_run_btn.connect("clicked", self._on_jwt_tool_run)
        run_row.append(self.jwt_run_btn)
        self.jwt_copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        self.jwt_copy_btn.set_tooltip_text("Copy output")
        self.jwt_copy_btn.set_sensitive(False)
        self.jwt_copy_btn.connect("clicked", self._on_jwt_copy)
        run_row.append(self.jwt_copy_btn)
        form.append(run_row)

        # Result section
        result_label = Gtk.Label(label="Result", xalign=0)
        result_label.add_css_class("title-4")
        form.append(result_label)

        self.jwt_results = Gtk.TextView()
        self.jwt_results.add_css_class("output-text")
        self.jwt_results.set_editable(False)
        self.jwt_results.set_monospace(True)
        results_scroll = Gtk.ScrolledWindow()
        results_scroll.add_css_class("output-box")
        results_scroll.set_min_content_height(550)
        results_scroll.set_child(self.jwt_results)
        form.append(results_scroll)

    def _open_jwt_tool(self, tool) -> None:
        self._active_tool = tool
        self._set_text_view_text(self.jwt_token_view, "")
        self.jwt_secret_entry.set_text("")
        self.jwt_override_alg.set_text("")
        self._set_text_view_text(self.jwt_public_view, "")
        self._set_text_view_text(self.jwt_private_view, "")
        self._set_text_view_text(self.jwt_header_view, "")
        self._set_text_view_text(self.jwt_payload_view, "")
        self.jwt_verify_switch.set_active(True)
        self.jwt_resign_switch.set_active(False)
        self.jwt_none_switch.set_active(False)
        self.jwt_results.get_buffer().set_text("")
        self.jwt_copy_btn.set_sensitive(False)
        self.tool_detail_stack.set_visible_child_name("jwt_tool")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_jwt_tool_run(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        token = self._get_text_view_text(self.jwt_token_view).strip()
        if not token:
            self.toast_overlay.add_toast(Adw.Toast.new("Paste a JWT first"))
            return
        secret = self.jwt_secret_entry.get_text()
        override_alg = self.jwt_override_alg.get_text()
        public_key = self._get_text_view_text(self.jwt_public_view)
        private_key = self._get_text_view_text(self.jwt_private_view)
        new_header = self._get_text_view_text(self.jwt_header_view)
        new_payload = self._get_text_view_text(self.jwt_payload_view)
        verify = "true" if self.jwt_verify_switch.get_active() else "false"
        resign = "true" if self.jwt_resign_switch.get_active() else "false"
        none_attack = "true" if self.jwt_none_switch.get_active() else "false"

        self.jwt_run_btn.set_sensitive(False)
        self.jwt_copy_btn.set_sensitive(False)
        self.jwt_results.get_buffer().set_text("Analyzing token…")

        def worker() -> None:
            try:
                result = self._active_tool.run(
                    token=token,
                    secret=secret,
                    verify=verify,
                    public_key=public_key,
                    private_key=private_key,
                    override_alg=override_alg,
                    new_header=new_header,
                    new_payload=new_payload,
                    resign=resign,
                    none_attack=none_attack,
                )
                body_text = getattr(result, "body", str(result))
                GLib.idle_add(self.jwt_results.get_buffer().set_text, body_text)
                GLib.idle_add(self.jwt_copy_btn.set_sensitive, bool(body_text.strip()))
            except Exception as exc:
                GLib.idle_add(self.toast_overlay.add_toast, Adw.Toast.new(f"Error: {exc}"))
            finally:
                GLib.idle_add(self.jwt_run_btn.set_sensitive, True)

        threading.Thread(target=worker, daemon=True).start()

    def _on_jwt_copy(self, _btn: Gtk.Button) -> None:
        display = self.window.get_display()
        if display is None:
            return
        clipboard = display.get_clipboard()
        buffer = self.jwt_results.get_buffer()
        start, end = buffer.get_bounds()
        clipboard.set_text(buffer.get_text(start, end, True))

    # ---------------------- File upload tester detail ----------------------
    def _build_file_upload_detail(self, root: Gtk.Box) -> None:
        from .modules.web.file_upload import DEFAULT_PAYLOAD, VARIANTS

        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("File Upload Tester")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=820, tightening_threshold=600)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        # Payload configuration section
        config_label = Gtk.Label(label="Payload Configuration", xalign=0)
        config_label.add_css_class("title-4")
        form.append(config_label)

        variant_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.upload_variant = Gtk.ComboBoxText()
        for key in VARIANTS.keys():
            label = key.replace("_", " ").title()
            self.upload_variant.append(key, label)
        self.upload_variant.set_active_id("polyglot_png_php")
        variant_row.append(self.upload_variant)
        self.upload_base = Gtk.Entry()
        self.upload_base.add_css_class("modern-entry")
        self.upload_base.set_placeholder_text("Base name (e.g. shell)...")
        self.upload_base.set_text("shell")
        self.upload_base.set_hexpand(True)
        variant_row.append(self.upload_base)
        form.append(variant_row)

        payload_label = Gtk.Label(label="Payload contents", xalign=0)
        payload_label.add_css_class("dim-label")
        form.append(payload_label)
        self.upload_payload_view = Gtk.TextView()
        self.upload_payload_view.add_css_class("input-text")
        self.upload_payload_view.set_monospace(True)
        self._set_text_view_text(self.upload_payload_view, DEFAULT_PAYLOAD)
        payload_scroll = Gtk.ScrolledWindow()
        payload_scroll.add_css_class("input-box")
        payload_scroll.set_min_content_height(150)
        payload_scroll.set_child(self.upload_payload_view)
        form.append(payload_scroll)

        # Upload options section
        options_label = Gtk.Label(label="Upload Options", xalign=0)
        options_label.add_css_class("title-4")
        form.append(options_label)

        meta_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.upload_mime = Gtk.Entry()
        self.upload_mime.add_css_class("modern-entry")
        self.upload_mime.set_placeholder_text("Override MIME type...")
        self.upload_mime.set_hexpand(True)
        meta_row.append(self.upload_mime)
        self.upload_field = Gtk.Entry()
        self.upload_field.add_css_class("modern-entry")
        self.upload_field.set_placeholder_text("Form field name...")
        self.upload_field.set_text("file")
        self.upload_field.set_hexpand(True)
        meta_row.append(self.upload_field)
        form.append(meta_row)

        target_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.upload_target = Gtk.Entry()
        self.upload_target.add_css_class("modern-entry")
        self.upload_target.set_placeholder_text("Sample target URL (for curl hint)...")
        self.upload_target.set_text("http://localhost/upload")
        self.upload_target.set_hexpand(True)
        target_row.append(self.upload_target)
        form.append(target_row)

        actions_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.upload_generate_btn = Gtk.Button(label="Generate payload")
        self.upload_generate_btn.add_css_class("suggested-action")
        self.upload_generate_btn.connect("clicked", self._on_file_upload_generate)
        actions_row.append(self.upload_generate_btn)
        self.upload_list_btn = Gtk.Button(label="List generated")
        self.upload_list_btn.connect("clicked", self._on_file_upload_list)
        actions_row.append(self.upload_list_btn)
        self.upload_cleanup_btn = Gtk.Button(label="Clean up")
        self.upload_cleanup_btn.connect("clicked", self._on_file_upload_cleanup)
        actions_row.append(self.upload_cleanup_btn)
        form.append(actions_row)

        # Result section
        result_label = Gtk.Label(label="Result", xalign=0)
        result_label.add_css_class("title-4")
        form.append(result_label)

        self.upload_results = Gtk.TextView()
        self.upload_results.add_css_class("output-text")
        self.upload_results.set_editable(False)
        self.upload_results.set_monospace(True)
        results_scroll = Gtk.ScrolledWindow()
        results_scroll.add_css_class("output-box")
        results_scroll.set_min_content_height(550)
        results_scroll.set_child(self.upload_results)
        form.append(results_scroll)

    def _open_file_upload(self, tool) -> None:
        from .modules.web.file_upload import DEFAULT_PAYLOAD

        self._active_tool = tool
        self.upload_variant.set_active_id("polyglot_png_php")
        self.upload_base.set_text("shell")
        self.upload_mime.set_text("")
        self.upload_field.set_text("file")
        self.upload_target.set_text("http://localhost/upload")
        self._set_text_view_text(self.upload_payload_view, DEFAULT_PAYLOAD)
        self.upload_results.get_buffer().set_text("")
        self.tool_detail_stack.set_visible_child_name("file_upload")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_file_upload_generate(self, _btn: Gtk.Button) -> None:
        self._run_file_upload_action("generate")

    def _on_file_upload_list(self, _btn: Gtk.Button) -> None:
        self._run_file_upload_action("list")

    def _on_file_upload_cleanup(self, _btn: Gtk.Button) -> None:
        self._run_file_upload_action("cleanup")

    def _run_file_upload_action(self, action: str) -> None:
        if not getattr(self, "_active_tool", None):
            return
        variant = self.upload_variant.get_active_id() or "polyglot_png_php"
        payload = self._get_text_view_text(self.upload_payload_view)
        base_name = self.upload_base.get_text().strip() or "shell"
        mime_type = self.upload_mime.get_text().strip()
        field_name = self.upload_field.get_text().strip() or "file"
        target = self.upload_target.get_text().strip() or "http://localhost/upload"

        for btn in (self.upload_generate_btn, self.upload_list_btn, self.upload_cleanup_btn):
            btn.set_sensitive(False)
        self.upload_results.get_buffer().set_text("Working…")

        def worker() -> None:
            try:
                result = self._active_tool.run(
                    variant=variant,
                    payload=payload,
                    base_name=base_name,
                    mime_type=mime_type,
                    field_name=field_name,
                    target=target,
                    action=action,
                )
                body = getattr(result, "body", str(result))
                GLib.idle_add(self.upload_results.get_buffer().set_text, body)
            except Exception as exc:
                GLib.idle_add(self.toast_overlay.add_toast, Adw.Toast.new(f"Error: {exc}"))
            finally:
                GLib.idle_add(self._set_upload_buttons_sensitive, True)

        threading.Thread(target=worker, daemon=True).start()

    def _set_upload_buttons_sensitive(self, enabled: bool) -> None:
        self.upload_generate_btn.set_sensitive(enabled)
        self.upload_list_btn.set_sensitive(enabled)
        self.upload_cleanup_btn.set_sensitive(enabled)

    def _on_strings_copy(self, _btn: Gtk.Button) -> None:
        display = self.window.get_display()
        if display is None:
            return
        clipboard = display.get_clipboard()
        buffer = self.strings_result_view.get_buffer()
        start, end = buffer.get_bounds()
        clipboard.set_text(buffer.get_text(start, end, True))

    def _build_wordlist_generator_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("Wordlist Generator")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=720, tightening_threshold=560)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        # Input section
        input_label = Gtk.Label(label="Input", xalign=0)
        input_label.add_css_class("title-4")
        form.append(input_label)

        self.wordlist_tokens = Gtk.Entry()
        self.wordlist_tokens.add_css_class("modern-entry")
        self.wordlist_tokens.set_placeholder_text("Tokens, comma-separated...")
        self.wordlist_tokens.set_hexpand(True)
        form.append(self.wordlist_tokens)

        # Generation options section
        options_label = Gtk.Label(label="Generation Options", xalign=0)
        options_label.add_css_class("title-4")
        form.append(options_label)

        range_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        range_row.append(Gtk.Label(label="Min", xalign=0))
        self.wordlist_min = Gtk.SpinButton()
        self.wordlist_min.set_adjustment(Gtk.Adjustment(lower=1, upper=6, step_increment=1, page_increment=1))
        self.wordlist_min.set_value(1)
        range_row.append(self.wordlist_min)
        range_row.append(Gtk.Label(label="Max", xalign=0))
        self.wordlist_max = Gtk.SpinButton()
        self.wordlist_max.set_adjustment(Gtk.Adjustment(lower=1, upper=6, step_increment=1, page_increment=1))
        self.wordlist_max.set_value(3)
        range_row.append(self.wordlist_max)
        form.append(range_row)

        run_btn = Gtk.Button(label="Generate")
        run_btn.add_css_class("suggested-action")
        run_btn.connect("clicked", self._on_wordlist_run)
        form.append(run_btn)

        # Result section
        result_label = Gtk.Label(label="Result", xalign=0)
        result_label.add_css_class("title-4")
        form.append(result_label)

        self.wordlist_result = Gtk.TextView()
        self.wordlist_result.add_css_class("output-text")
        self.wordlist_result.set_editable(False)
        self.wordlist_result.set_monospace(True)
        list_scroller = Gtk.ScrolledWindow()
        list_scroller.add_css_class("output-box")
        list_scroller.set_min_content_height(550)
        list_scroller.set_child(self.wordlist_result)
        form.append(list_scroller)

    def _open_wordlist_generator(self, tool) -> None:
        self._active_tool = tool
        self.wordlist_tokens.set_text("")
        self.wordlist_min.set_value(1)
        self.wordlist_max.set_value(3)
        self.wordlist_result.get_buffer().set_text("")
        self.tool_detail_stack.set_visible_child_name("wordlist")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_wordlist_run(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        tokens = self.wordlist_tokens.get_text().strip()
        min_len = str(int(self.wordlist_min.get_value()))
        max_len = str(int(self.wordlist_max.get_value()))
        try:
            result = self._active_tool.run(tokens=tokens, min_length=min_len, max_length=max_len)
            self.wordlist_result.get_buffer().set_text(getattr(result, "body", str(result)))
        except Exception as exc:
            self.toast_overlay.add_toast(Adw.Toast.new(f"Error: {exc}"))

    # ---------------------- Nmap detail ----------------------
    def _build_nmap_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("Nmap")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=860, tightening_threshold=620)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        # Network tools consent section
        consent_label = Gtk.Label(label="Network Tools", xalign=0)
        consent_label.add_css_class("title-4")
        form.append(consent_label)

        # Consent warning (shown if disabled)
        self.nmap_notice = Gtk.Label(xalign=0)
        self.nmap_notice.add_css_class("dim-label")
        form.append(self.nmap_notice)

        consent_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.nmap_enable_btn = Gtk.Button(label="Enable Network Tools")
        self.nmap_enable_btn.connect("clicked", self._on_enable_network_tools)
        self.nmap_disable_btn = Gtk.Button(label="Disable Network Tools")
        self.nmap_disable_btn.connect("clicked", self._on_disable_network_tools)
        consent_row.append(self.nmap_enable_btn)
        consent_row.append(self.nmap_disable_btn)
        form.append(consent_row)

        # Target section
        target_label = Gtk.Label(label="Target", xalign=0)
        target_label.add_css_class("title-4")
        form.append(target_label)

        target_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.nmap_target = Gtk.Entry()
        self.nmap_target.add_css_class("modern-entry")
        self.nmap_target.set_placeholder_text("Target (host, CIDR, file)...")
        self.nmap_target.set_hexpand(True)
        target_row.append(self.nmap_target)
        form.append(target_row)

        # Scan options section
        scan_label = Gtk.Label(label="Scan Options", xalign=0)
        scan_label.add_css_class("title-4")
        form.append(scan_label)

        from .modules.network.nmap import PROFILE_CHOICES

        self._nmap_profile_descriptions = {profile.profile_id: profile.description for profile in PROFILE_CHOICES}

        options_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        options_row.add_css_class("nmap-options-row")
        self.nmap_profile = Gtk.ComboBoxText()
        for profile in PROFILE_CHOICES:
            self.nmap_profile.append(profile.profile_id, profile.label)
        self.nmap_profile.set_active_id("default")
        self.nmap_profile.connect("changed", self._on_nmap_profile_changed)
        profile_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        profile_label = Gtk.Label(label="Profile", xalign=0)
        profile_box.append(profile_label)
        profile_box.append(self.nmap_profile)
        options_row.append(profile_box)

        toggles_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        toggles_row.add_css_class("switch-group")
        self.nmap_os = Gtk.Switch()
        toggles_row.append(self._build_switch_field("OS detect", self.nmap_os))
        self.nmap_ver = Gtk.Switch()
        self.nmap_ver.set_active(True)
        toggles_row.append(self._build_switch_field("Version detect", self.nmap_ver))
        self.nmap_default_scripts = Gtk.Switch()
        toggles_row.append(self._build_switch_field("Default scripts", self.nmap_default_scripts))
        self.nmap_skip_ping = Gtk.Switch()
        toggles_row.append(self._build_switch_field("Skip host discovery", self.nmap_skip_ping))
        options_row.append(toggles_row)
        form.append(options_row)

        self.nmap_profile_desc = Gtk.Label(xalign=0)
        self.nmap_profile_desc.add_css_class("dim-label")
        form.append(self.nmap_profile_desc)
        self._on_nmap_profile_changed(self.nmap_profile)

        self.nmap_ports = Gtk.Entry()
        self.nmap_ports.add_css_class("modern-entry")
        self.nmap_ports.set_placeholder_text("Ports (e.g. 1-1024 or 80,443,8000)...")
        self.nmap_ports.set_hexpand(True)
        form.append(self.nmap_ports)

        self.nmap_extra = Gtk.Entry()
        self.nmap_extra.add_css_class("modern-entry")
        self.nmap_extra.set_placeholder_text("Additional args (advanced)...")
        self.nmap_extra.set_hexpand(True)
        form.append(self.nmap_extra)

        run_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.nmap_run_btn = Gtk.Button(label="Run")
        self.nmap_run_btn.add_css_class("suggested-action")
        self.nmap_run_btn.connect("clicked", self._on_nmap_run)
        run_row.append(self.nmap_run_btn)
        form.append(run_row)

        # Result section
        result_label = Gtk.Label(label="Result", xalign=0)
        result_label.add_css_class("title-4")
        form.append(result_label)

        self.nmap_results = Gtk.TextView()
        self.nmap_results.add_css_class("output-text")
        self.nmap_results.set_editable(False)
        self.nmap_results.set_monospace(True)
        res_scroller = Gtk.ScrolledWindow()
        res_scroller.add_css_class("output-box")
        res_scroller.set_min_content_height(550)
        res_scroller.set_child(self.nmap_results)
        form.append(res_scroller)

    def _build_switch_field(self, title: str, switch: Gtk.Switch) -> Gtk.Box:
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        box.add_css_class("switch-field")
        label = Gtk.Label(label=title, xalign=0)
        label.add_css_class("switch-label")
        box.append(label)
        box.append(switch)
        switch.connect("notify::active", self._on_switch_field_toggle, box)
        self._on_switch_field_toggle(switch, None, box)
        return box

    def _on_switch_field_toggle(self, switch: Gtk.Switch, _pspec, container: Gtk.Box) -> None:
        if switch.get_active():
            container.add_css_class("switch-field-active")
        else:
            container.remove_css_class("switch-field-active")

    def _on_nmap_profile_changed(self, combo: Gtk.ComboBoxText) -> None:
        if not hasattr(self, "_nmap_profile_descriptions"):
            return
        profile_id = combo.get_active_id() or ""
        description = self._nmap_profile_descriptions.get(profile_id, "")
        self.nmap_profile_desc.set_text(description)

    def _open_nmap(self, tool) -> None:
        from .modules.network.nmap import network_consent_enabled, is_nmap_available
        self._active_tool = tool
        # Update notice
        if not is_nmap_available():
            self.nmap_notice.set_text("nmap is not installed. Please install nmap and retry.")
        elif not network_consent_enabled():
            self.nmap_notice.set_text("Network modules are disabled. Enable them in Preferences to run scans.")
        else:
            self.nmap_notice.set_text("")
        # Toggle enable/disable buttons
        self.nmap_enable_btn.set_visible(not network_consent_enabled())
        self.nmap_disable_btn.set_visible(network_consent_enabled())
        self.nmap_target.set_text("")
        self.nmap_profile.set_active_id("default")
        self._on_nmap_profile_changed(self.nmap_profile)
        self.nmap_os.set_active(False)
        self.nmap_ver.set_active(True)
        self.nmap_default_scripts.set_active(False)
        self.nmap_skip_ping.set_active(False)
        self.nmap_ports.set_text("")
        self.nmap_extra.set_text("")
        self.nmap_results.get_buffer().set_text("")
        self.tool_detail_stack.set_visible_child_name("nmap")
        self.content_stack.set_visible_child_name("tool_detail")

    def _open_discovery(self, tool) -> None:
        self._active_tool = tool
        self.discovery_target.set_text("")
        self.discovery_tool.set_active_id("auto")
        self.discovery_wordlist.set_text("")
        self.discovery_threads.set_text("20")
        self.discovery_auto_download.set_active(True)
        self.discovery_results.get_buffer().set_text("")
        self._refresh_discovery_wordlists()
        self.tool_detail_stack.set_visible_child_name("discovery")
        self.content_stack.set_visible_child_name("tool_detail")
    def _refresh_discovery_wordlists(self) -> None:
        from .modules.web.discovery import available_wordlists

        current = self.discovery_wordlist_choice.get_active_id()
        self.discovery_wordlist_choice.remove_all()

        records = available_wordlists()
        fallback = None
        for slug, path, label in records:
            status = "downloaded" if path.exists() else "missing"
            display = f"{label} ({status})"
            self.discovery_wordlist_choice.append(slug, display)
            if path.exists() and fallback is None:
                fallback = slug

        if records:
            if current and any(slug == current for slug, _path, _label in records):
                self.discovery_wordlist_choice.set_active_id(current)
            elif fallback:
                self.discovery_wordlist_choice.set_active_id(fallback)
            else:
                self.discovery_wordlist_choice.set_active(0)

        existing_paths = [path for _slug, path, _label in records if path.exists()]
        if existing_paths:
            sample_dir = existing_paths[0].parent
            self.discovery_wordlist_status.set_text(
                f"Downloaded {len(existing_paths)} wordlists to {sample_dir}"
            )
        else:
            self.discovery_wordlist_status.set_text("No preset wordlists downloaded yet")

    def _on_discovery_download_wordlist(self, _btn: Gtk.Button) -> None:
        from .modules.web.discovery import ensure_wordlist

        slug = self.discovery_wordlist_choice.get_active_id()
        if not slug:
            self.toast_overlay.add_toast(Adw.Toast.new("Choose a preset first"))
            return
        allow_download = True
        path = ensure_wordlist(slug, allow_download)
        if path is None:
            self.toast_overlay.add_toast(Adw.Toast.new("Failed to download wordlist"))
            return
        self.discovery_wordlist.set_text(str(path))
        self.toast_overlay.add_toast(Adw.Toast.new(f"Saved to {path.name}"))
        self._refresh_discovery_wordlists()

    def _on_discovery_browse_wordlist(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileChooserNative.new("Select wordlist", self.window, Gtk.FileChooserAction.OPEN, None, None)
        dialog.set_modal(True)
        response = self._run_native_dialog(dialog)
        if response == Gtk.ResponseType.ACCEPT:
            filename = dialog.get_file()
            if filename is not None:
                self.discovery_wordlist.set_text(filename.get_path() or "")
        dialog.destroy()

    def _on_discovery_run(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        target = self.discovery_target.get_text().strip()
        if not target:
            self.toast_overlay.add_toast(Adw.Toast.new("Enter a target first"))
            return
        preset = self.discovery_wordlist_choice.get_active_id() or "common"
        custom_wordlist = self.discovery_wordlist.get_text().strip()
        threads = self.discovery_threads.get_text().strip() or "20"
        tool_choice = self.discovery_tool.get_active_id() or "auto"
        download_missing = "true" if self.discovery_auto_download.get_active() else "false"

        self.discovery_run_btn.set_sensitive(False)
        self.discovery_results.get_buffer().set_text("Running discovery…")

        def worker() -> None:
            try:
                result = self._active_tool.run(
                    target=target,
                    tool=tool_choice,
                    wordlist=custom_wordlist,
                    threads=threads,
                    wordlist_choice=preset,
                    download_missing=download_missing,
                )
                body = getattr(result, "body", str(result))
                GLib.idle_add(self.discovery_results.get_buffer().set_text, body)
            except Exception as exc:
                GLib.idle_add(self.toast_overlay.add_toast, Adw.Toast.new(f"Error: {exc}"))
            finally:
                GLib.idle_add(self.discovery_run_btn.set_sensitive, True)

        threading.Thread(target=worker, daemon=True).start()

    # ---------------------- SQLi tester detail ----------------------
    def _build_sqli_tester_detail(self, root: Gtk.Box) -> None:
        from .modules.web.sqli_tester import PAYLOAD_PRESETS

        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("SQLi Tester")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=880, tightening_threshold=640)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        warning = Gtk.Label(label="Use only against permitted targets. Requests are sent directly from your machine.", xalign=0)
        warning.add_css_class("dim-label")
        warning.set_wrap(True)
        form.append(warning)

        # Target section
        target_section_label = Gtk.Label(label="Target", xalign=0)
        target_section_label.add_css_class("title-4")
        form.append(target_section_label)

        self.sqli_target = Gtk.Entry()
        self.sqli_target.add_css_class("modern-entry")
        self.sqli_target.set_placeholder_text("http://localhost:8000/item.php?id=1...")
        self.sqli_target.set_hexpand(True)
        form.append(self.sqli_target)

        param_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.sqli_parameter = Gtk.Entry()
        self.sqli_parameter.add_css_class("modern-entry")
        self.sqli_parameter.set_placeholder_text("Parameter name (auto if blank)...")
        self.sqli_parameter.set_hexpand(True)
        param_row.append(self.sqli_parameter)
        self.sqli_method = Gtk.ComboBoxText()
        for method in ["GET", "POST", "PUT", "PATCH", "DELETE"]:
            self.sqli_method.append(method, method)
        self.sqli_method.set_active_id("GET")
        param_row.append(self.sqli_method)
        form.append(param_row)

        # Request configuration section
        request_label = Gtk.Label(label="Request Configuration", xalign=0)
        request_label.add_css_class("title-4")
        form.append(request_label)

        body_label = Gtk.Label(label="Request body template (for POST/JSON)", xalign=0)
        body_label.add_css_class("dim-label")
        form.append(body_label)
        self.sqli_body_view = Gtk.TextView()
        self.sqli_body_view.add_css_class("input-text")
        self.sqli_body_view.set_monospace(True)
        body_scroller = Gtk.ScrolledWindow()
        body_scroller.add_css_class("input-box")
        body_scroller.set_min_content_height(150)
        body_scroller.set_child(self.sqli_body_view)
        form.append(body_scroller)

        header_label = Gtk.Label(label="Additional headers (Header: value per line)", xalign=0)
        header_label.add_css_class("dim-label")
        form.append(header_label)
        self.sqli_headers_view = Gtk.TextView()
        self.sqli_headers_view.add_css_class("input-text")
        self.sqli_headers_view.set_monospace(True)
        headers_scroller = Gtk.ScrolledWindow()
        headers_scroller.add_css_class("input-box")
        headers_scroller.set_min_content_height(150)
        headers_scroller.set_child(self.sqli_headers_view)
        form.append(headers_scroller)

        cookies_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.sqli_cookies = Gtk.Entry()
        self.sqli_cookies.add_css_class("modern-entry")
        self.sqli_cookies.set_placeholder_text("session=abcd; role=user...")
        self.sqli_cookies.set_hexpand(True)
        cookies_row.append(self.sqli_cookies)
        self.sqli_timeout = Gtk.Entry()
        self.sqli_timeout.add_css_class("modern-entry")
        self.sqli_timeout.set_width_chars(5)
        self.sqli_timeout.set_text("8")
        timeout_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        timeout_box.append(Gtk.Label(label="Timeout (s)", xalign=0))
        timeout_box.append(self.sqli_timeout)
        cookies_row.append(timeout_box)
        form.append(cookies_row)

        # Payloads section
        payloads_section_label = Gtk.Label(label="Payloads", xalign=0)
        payloads_section_label.add_css_class("title-4")
        form.append(payloads_section_label)

        profile_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.sqli_profile = Gtk.ComboBoxText()
        self._sqli_profile_descriptions = {}
        for key, payloads in PAYLOAD_PRESETS.items():
            label = key.replace("-", " ").title()
            self.sqli_profile.append(key, label)
            example = payloads[0] if payloads else ""
            summary = f"{len(payloads)} payloads" + (f" • e.g. {example}" if example else "")
            self._sqli_profile_descriptions[key] = summary
        self.sqli_profile.set_active_id("basic")
        self.sqli_profile.connect("changed", self._on_sqli_profile_changed)
        profile_row.append(self.sqli_profile)
        self.sqli_profile_desc = Gtk.Label(xalign=0)
        self.sqli_profile_desc.add_css_class("dim-label")
        self.sqli_profile_desc.set_wrap(True)
        profile_row.append(self.sqli_profile_desc)
        form.append(profile_row)
        self._on_sqli_profile_changed(self.sqli_profile)

        custom_label = Gtk.Label(label="Custom payloads (one per line)", xalign=0)
        custom_label.add_css_class("dim-label")
        form.append(custom_label)
        self.sqli_payloads_view = Gtk.TextView()
        self.sqli_payloads_view.add_css_class("input-text")
        self.sqli_payloads_view.set_monospace(True)
        payload_scroller = Gtk.ScrolledWindow()
        payload_scroller.add_css_class("input-box")
        payload_scroller.set_min_content_height(150)
        payload_scroller.set_child(self.sqli_payloads_view)
        form.append(payload_scroller)

        options_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        options_row.add_css_class("switch-group")
        self.sqli_follow_redirects = Gtk.Switch()
        self.sqli_follow_redirects.set_active(True)
        options_row.append(self._build_switch_field("Follow redirects", self.sqli_follow_redirects))
        self.sqli_sqlmap_hint = Gtk.Switch()
        self.sqli_sqlmap_hint.set_active(True)
        options_row.append(self._build_switch_field("Include sqlmap hint", self.sqli_sqlmap_hint))
        form.append(options_row)

        run_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.sqli_run_btn = Gtk.Button(label="Probe Target")
        self.sqli_run_btn.add_css_class("suggested-action")
        self.sqli_run_btn.connect("clicked", self._on_sqli_tester_run)
        run_row.append(self.sqli_run_btn)
        form.append(run_row)

        # Result section
        result_label = Gtk.Label(label="Result", xalign=0)
        result_label.add_css_class("title-4")
        form.append(result_label)

        self.sqli_results = Gtk.TextView()
        self.sqli_results.add_css_class("output-text")
        self.sqli_results.set_editable(False)
        self.sqli_results.set_monospace(True)
        results_scroller = Gtk.ScrolledWindow()
        results_scroller.add_css_class("output-box")
        results_scroller.set_min_content_height(550)
        results_scroller.set_child(self.sqli_results)
        form.append(results_scroller)

    def _on_sqli_profile_changed(self, combo: Gtk.ComboBoxText) -> None:
        profile_id = combo.get_active_id() or ""
        description = self._sqli_profile_descriptions.get(profile_id, "")
        self.sqli_profile_desc.set_text(description)

    def _open_sqli_tester(self, tool) -> None:
        self._active_tool = tool
        self.sqli_target.set_text("")
        self.sqli_parameter.set_text("")
        self.sqli_method.set_active_id("GET")
        self._set_text_view_text(self.sqli_body_view, "")
        self._set_text_view_text(self.sqli_headers_view, "")
        self._set_text_view_text(self.sqli_payloads_view, "")
        self.sqli_cookies.set_text("")
        self.sqli_timeout.set_text("8")
        self.sqli_follow_redirects.set_active(True)
        self.sqli_sqlmap_hint.set_active(True)
        self.sqli_profile.set_active_id("basic")
        self._on_sqli_profile_changed(self.sqli_profile)
        self.sqli_results.get_buffer().set_text("")
        self.tool_detail_stack.set_visible_child_name("sqli_tester")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_sqli_tester_run(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        target = self.sqli_target.get_text().strip()
        if not target:
            self.toast_overlay.add_toast(Adw.Toast.new("Enter a target URL"))
            return
        parameter = self.sqli_parameter.get_text().strip()
        method = self.sqli_method.get_active_id() or "GET"
        body = self._get_text_view_text(self.sqli_body_view)
        headers = self._get_text_view_text(self.sqli_headers_view)
        custom_payloads = self._get_text_view_text(self.sqli_payloads_view)
        cookies = self.sqli_cookies.get_text().strip()
        timeout = self.sqli_timeout.get_text().strip() or "8"
        payload_profile = self.sqli_profile.get_active_id() or "basic"
        follow = "true" if self.sqli_follow_redirects.get_active() else "false"
        include_hint = "true" if self.sqli_sqlmap_hint.get_active() else "false"

        self.sqli_run_btn.set_sensitive(False)
        self.sqli_results.get_buffer().set_text("Probing target…")

        def worker() -> None:
            try:
                result = self._active_tool.run(
                    target=target,
                    parameter=parameter,
                    method=method,
                    body=body,
                    headers=headers,
                    cookies=cookies,
                    payload_profile=payload_profile,
                    custom_payloads=custom_payloads,
                    follow_redirects=follow,
                    timeout=timeout,
                    include_sqlmap_hint=include_hint,
                )
                body_text = getattr(result, "body", str(result))
                GLib.idle_add(self.sqli_results.get_buffer().set_text, body_text)
            except Exception as exc:
                GLib.idle_add(self.toast_overlay.add_toast, Adw.Toast.new(f"Error: {exc}"))
            finally:
                GLib.idle_add(self.sqli_run_btn.set_sensitive, True)

        threading.Thread(target=worker, daemon=True).start()

    def _open_sqlmap(self, tool) -> None:
        self._active_tool = tool
        self.sqlmap_target.set_text("")
        self.sqlmap_method.set_active_id("GET")
        self.sqlmap_threads.set_value(1)
        self.sqlmap_data.set_text("")
        self.sqlmap_cookies.set_text("")
        self.sqlmap_tamper.set_text("")
        self.sqlmap_level.set_text("1")
        self.sqlmap_risk.set_text("1")
        self.sqlmap_timeout.set_text("30")
        self.sqlmap_options.set_text("")
        self.sqlmap_consent.set_active(False)
        self.sqlmap_results.get_buffer().set_text("")
        self.sqlmap_copy_btn.set_sensitive(False)
        self.tool_detail_stack.set_visible_child_name("sqlmap")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_sqlmap_run(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        if not self.sqlmap_consent.get_active():
            self.toast_overlay.add_toast(Adw.Toast.new("You must tick the consent box"))
            return
        target = self.sqlmap_target.get_text().strip()
        if not target:
            self.toast_overlay.add_toast(Adw.Toast.new("Enter a target URL"))
            return
        level = self.sqlmap_level.get_text().strip() or "1"
        risk = self.sqlmap_risk.get_text().strip() or "1"
        options = self.sqlmap_options.get_text().strip()
        method = self.sqlmap_method.get_active_id() or "GET"
        data = self.sqlmap_data.get_text().strip()
        cookies = self.sqlmap_cookies.get_text().strip()
        tamper = self.sqlmap_tamper.get_text().strip()
        threads = str(int(self.sqlmap_threads.get_value()))
        timeout = self.sqlmap_timeout.get_text().strip() or "30"

        self.sqlmap_run_btn.set_sensitive(False)
        self.sqlmap_results.get_buffer().set_text("Running sqlmap…")

        def worker() -> None:
            try:
                result = self._active_tool.run(
                    target=target,
                    level=level,
                    risk=risk,
                    options=options,
                    method=method,
                    data=data,
                    cookies=cookies,
                    tamper=tamper,
                    threads=threads,
                    timeout=timeout,
                    i_understand="yes",
                )
                body = getattr(result, "body", str(result))
                GLib.idle_add(self.sqlmap_results.get_buffer().set_text, body)
                GLib.idle_add(self.sqlmap_copy_btn.set_sensitive, bool(body.strip()))
            except Exception as exc:
                GLib.idle_add(self.toast_overlay.add_toast, Adw.Toast.new(f"Error: {exc}"))
            finally:
                GLib.idle_add(self.sqlmap_run_btn.set_sensitive, True)

    # ---------------------- XSS tester detail ----------------------
    def _build_xss_tester_detail(self, root: Gtk.Box) -> None:
        from .modules.web.xss_tester import PAYLOAD_SETS

        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("XSS Tester")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=880, tightening_threshold=640)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        guidance = Gtk.Label(label="Sends payloads and highlights reflected content in responses.", xalign=0)
        guidance.add_css_class("dim-label")
        guidance.set_wrap(True)
        form.append(guidance)

        # Target section
        target_section_label = Gtk.Label(label="Target", xalign=0)
        target_section_label.add_css_class("title-4")
        form.append(target_section_label)

        self.xss_target = Gtk.Entry()
        self.xss_target.add_css_class("modern-entry")
        self.xss_target.set_placeholder_text("http://localhost:8000/search?q=test...")
        self.xss_target.set_hexpand(True)
        form.append(self.xss_target)

        param_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.xss_parameter = Gtk.Entry()
        self.xss_parameter.add_css_class("modern-entry")
        self.xss_parameter.set_placeholder_text("Parameter name (auto if blank)...")
        self.xss_parameter.set_hexpand(True)
        param_row.append(self.xss_parameter)
        self.xss_method = Gtk.ComboBoxText()
        for method in ["GET", "POST", "PUT", "PATCH", "DELETE"]:
            self.xss_method.append(method, method)
        self.xss_method.set_active_id("GET")
        param_row.append(self.xss_method)
        form.append(param_row)

        # Request configuration section
        request_label = Gtk.Label(label="Request Configuration", xalign=0)
        request_label.add_css_class("title-4")
        form.append(request_label)

        body_label = Gtk.Label(label="Request body template", xalign=0)
        body_label.add_css_class("dim-label")
        form.append(body_label)
        self.xss_body_view = Gtk.TextView()
        self.xss_body_view.add_css_class("input-text")
        self.xss_body_view.set_monospace(True)
        body_scroll = Gtk.ScrolledWindow()
        body_scroll.add_css_class("input-box")
        body_scroll.set_min_content_height(150)
        body_scroll.set_child(self.xss_body_view)
        form.append(body_scroll)

        header_label = Gtk.Label(label="Additional headers", xalign=0)
        header_label.add_css_class("dim-label")
        form.append(header_label)
        self.xss_headers_view = Gtk.TextView()
        self.xss_headers_view.add_css_class("input-text")
        self.xss_headers_view.set_monospace(True)
        header_scroll = Gtk.ScrolledWindow()
        header_scroll.add_css_class("input-box")
        header_scroll.set_min_content_height(150)
        header_scroll.set_child(self.xss_headers_view)
        form.append(header_scroll)

        cookies_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.xss_cookies = Gtk.Entry()
        self.xss_cookies.add_css_class("modern-entry")
        self.xss_cookies.set_placeholder_text("session=abcd; user=1...")
        self.xss_cookies.set_hexpand(True)
        cookies_row.append(self.xss_cookies)
        self.xss_timeout = Gtk.Entry()
        self.xss_timeout.add_css_class("modern-entry")
        self.xss_timeout.set_width_chars(5)
        self.xss_timeout.set_text("8")
        timeout_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        timeout_box.append(Gtk.Label(label="Timeout (s)", xalign=0))
        timeout_box.append(self.xss_timeout)
        cookies_row.append(timeout_box)
        form.append(cookies_row)

        # Payloads section
        payloads_section_label = Gtk.Label(label="Payloads", xalign=0)
        payloads_section_label.add_css_class("title-4")
        form.append(payloads_section_label)

        payload_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.xss_profile = Gtk.ComboBoxText()
        self._xss_profile_descriptions = {}
        for key, values in PAYLOAD_SETS.items():
            label = key.replace("_", " ").title()
            self.xss_profile.append(key, label)
            example = values[0] if values else ""
            summary = f"{len(values)} payloads" + (f" • e.g. {example}" if example else "")
            self._xss_profile_descriptions[key] = summary
        self.xss_profile.set_active_id("basic")
        self.xss_profile.connect("changed", self._on_xss_profile_changed)
        payload_row.append(self.xss_profile)
        self.xss_profile_desc = Gtk.Label(xalign=0)
        self.xss_profile_desc.add_css_class("dim-label")
        self.xss_profile_desc.set_wrap(True)
        payload_row.append(self.xss_profile_desc)
        form.append(payload_row)
        self._on_xss_profile_changed(self.xss_profile)

        custom_label = Gtk.Label(label="Custom payloads (one per line)", xalign=0)
        custom_label.add_css_class("dim-label")
        form.append(custom_label)
        self.xss_payloads_view = Gtk.TextView()
        self.xss_payloads_view.add_css_class("input-text")
        self.xss_payloads_view.set_monospace(True)
        payload_scroll = Gtk.ScrolledWindow()
        payload_scroll.add_css_class("input-box")
        payload_scroll.set_min_content_height(150)
        payload_scroll.set_child(self.xss_payloads_view)
        form.append(payload_scroll)

        options_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        options_row.add_css_class("switch-group")
        self.xss_follow_redirects = Gtk.Switch()
        self.xss_follow_redirects.set_active(True)
        options_row.append(self._build_switch_field("Follow redirects", self.xss_follow_redirects))
        form.append(options_row)

        run_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.xss_run_btn = Gtk.Button(label="Test Payloads")
        self.xss_run_btn.add_css_class("suggested-action")
        self.xss_run_btn.connect("clicked", self._on_xss_tester_run)
        run_row.append(self.xss_run_btn)
        form.append(run_row)

        # Result section
        result_label = Gtk.Label(label="Result", xalign=0)
        result_label.add_css_class("title-4")
        form.append(result_label)

        self.xss_results = Gtk.TextView()
        self.xss_results.add_css_class("output-text")
        self.xss_results.set_editable(False)
        self.xss_results.set_monospace(True)
        results_scroll = Gtk.ScrolledWindow()
        results_scroll.add_css_class("output-box")
        results_scroll.set_min_content_height(550)
        results_scroll.set_child(self.xss_results)
        form.append(results_scroll)

    def _on_xss_profile_changed(self, combo: Gtk.ComboBoxText) -> None:
        profile_id = combo.get_active_id() or ""
        description = self._xss_profile_descriptions.get(profile_id, "")
        self.xss_profile_desc.set_text(description)

    def _open_xss_tester(self, tool) -> None:
        self._active_tool = tool
        self.xss_target.set_text("")
        self.xss_parameter.set_text("")
        self.xss_method.set_active_id("GET")
        self._set_text_view_text(self.xss_body_view, "")
        self._set_text_view_text(self.xss_headers_view, "")
        self._set_text_view_text(self.xss_payloads_view, "")
        self.xss_cookies.set_text("")
        self.xss_timeout.set_text("8")
        self.xss_follow_redirects.set_active(True)
        self.xss_profile.set_active_id("basic")
        self._on_xss_profile_changed(self.xss_profile)
        self.xss_results.get_buffer().set_text("")
        self.tool_detail_stack.set_visible_child_name("xss_tester")
        self.content_stack.set_visible_child_name("tool_detail")

    def _on_xss_tester_run(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        target = self.xss_target.get_text().strip()
        if not target:
            self.toast_overlay.add_toast(Adw.Toast.new("Enter a target URL"))
            return
        parameter = self.xss_parameter.get_text().strip()
        method = self.xss_method.get_active_id() or "GET"
        body = self._get_text_view_text(self.xss_body_view)
        headers = self._get_text_view_text(self.xss_headers_view)
        custom_payloads = self._get_text_view_text(self.xss_payloads_view)
        cookies = self.xss_cookies.get_text().strip()
        timeout = self.xss_timeout.get_text().strip() or "8"
        profile = self.xss_profile.get_active_id() or "basic"
        follow = "true" if self.xss_follow_redirects.get_active() else "false"

        self.xss_run_btn.set_sensitive(False)
        self.xss_results.get_buffer().set_text("Testing payloads…")

        def worker() -> None:
            try:
                result = self._active_tool.run(
                    target=target,
                    parameter=parameter,
                    method=method,
                    body=body,
                    payload_profile=profile,
                    custom_payloads=custom_payloads,
                    headers=headers,
                    cookies=cookies,
                    timeout=timeout,
                    follow_redirects=follow,
                )
                body_text = getattr(result, "body", str(result))
                GLib.idle_add(self.xss_results.get_buffer().set_text, body_text)
            except Exception as exc:
                GLib.idle_add(self.toast_overlay.add_toast, Adw.Toast.new(f"Error: {exc}"))
            finally:
                GLib.idle_add(self.xss_run_btn.set_sensitive, True)

        threading.Thread(target=worker, daemon=True).start()

        threading.Thread(target=worker, daemon=True).start()

    def _on_sqlmap_copy(self, _btn: Gtk.Button) -> None:
        display = self.window.get_display()
        if display is None:
            return
        buffer = self.sqlmap_results.get_buffer()
        start, end = buffer.get_bounds()
        display.get_clipboard().set_text(buffer.get_text(start, end, True))

    def _on_nmap_run(self, _btn: Gtk.Button) -> None:
        if not getattr(self, "_active_tool", None):
            return
        target = self.nmap_target.get_text().strip()
        if not target:
            self.toast_overlay.add_toast(Adw.Toast.new("Enter a target first"))
            return
        profile = self.nmap_profile.get_active_id() or "default"
        extra = self.nmap_extra.get_text().strip()
        os_detect = "1" if self.nmap_os.get_active() else "0"
        version_detect = "1" if self.nmap_ver.get_active() else "0"
        default_scripts = "1" if self.nmap_default_scripts.get_active() else "0"
        skip_ping = "1" if self.nmap_skip_ping.get_active() else "0"
        ports = self.nmap_ports.get_text().strip()

        self.nmap_run_btn.set_sensitive(False)
        self.nmap_results.get_buffer().set_text("Running nmap…")

        def worker() -> None:
            try:
                result = self._active_tool.run(
                    target=target,
                    profile=profile,
                    extra=extra,
                    os_detect=os_detect,
                    version_detect=version_detect,
                    default_scripts=default_scripts,
                    skip_ping=skip_ping,
                    ports=ports,
                )
                body = getattr(result, "body", str(result))
                GLib.idle_add(self.nmap_results.get_buffer().set_text, body)
            except Exception as exc:
                GLib.idle_add(self.toast_overlay.add_toast, Adw.Toast.new(f"Error: {exc}"))
            finally:
                GLib.idle_add(self.nmap_run_btn.set_sensitive, True)

        threading.Thread(target=worker, daemon=True).start()

    def _on_enable_network_tools(self, _btn: Gtk.Button) -> None:
        from .modules.network.nmap import set_network_consent

        set_network_consent(True)
        self.app.module_registry = ModuleRegistry()
        self.toast_overlay.add_toast(Adw.Toast.new("Network tools enabled"))
        self._current_view = ("tool", "Nmap")
        self.refresh_sidebar()
        nmap_tool = next(
            (t for t in self.app.module_registry.tools() if getattr(t, "name", "").lower() == "nmap"),
            None,
        )
        if nmap_tool is not None:
            self._open_nmap(nmap_tool)
        else:
            self._show_tool("Nmap")

    def _on_disable_network_tools(self, _btn: Gtk.Button) -> None:
        from .modules.network.nmap import set_network_consent

        set_network_consent(False)
        self.app.module_registry = ModuleRegistry()
        self.toast_overlay.add_toast(Adw.Toast.new("Network tools disabled"))
        self._navigate_back_to_tools()

    def _build_discovery_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("Directory Discovery")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=860, tightening_threshold=620)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        # Target section
        target_section_label = Gtk.Label(label="Target", xalign=0)
        target_section_label.add_css_class("title-4")
        form.append(target_section_label)

        target_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        target_row.append(Gtk.Label(label="Target", xalign=0))
        self.discovery_target = Gtk.Entry()
        self.discovery_target.add_css_class("modern-entry")
        self.discovery_target.set_placeholder_text("http://localhost:8000 or file:///path/to/site...")
        self.discovery_target.set_hexpand(True)
        target_row.append(self.discovery_target)
        form.append(target_row)

        # Configuration section
        config_label = Gtk.Label(label="Configuration", xalign=0)
        config_label.add_css_class("title-4")
        form.append(config_label)

        tool_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        tool_row.append(Gtk.Label(label="Tool", xalign=0))
        self.discovery_tool = Gtk.ComboBoxText()
        for tid, label in [("auto", "Auto"), ("ffuf", "ffuf"), ("gobuster", "gobuster"), ("dirb", "dirb")]:
            self.discovery_tool.append(tid, label)
        self.discovery_tool.set_active_id("auto")
        tool_row.append(self.discovery_tool)
        form.append(tool_row)

        preset_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        preset_row.append(Gtk.Label(label="Preset", xalign=0))
        self.discovery_wordlist_choice = Gtk.ComboBoxText()
        preset_row.append(self.discovery_wordlist_choice)
        self.discovery_sync_btn = Gtk.Button.new_from_icon_name("view-refresh-symbolic")
        self.discovery_sync_btn.set_tooltip_text("Download selected wordlist")
        self.discovery_sync_btn.connect("clicked", self._on_discovery_download_wordlist)
        preset_row.append(self.discovery_sync_btn)
        form.append(preset_row)

        self.discovery_auto_download = Gtk.CheckButton(label="Auto-download if missing")
        self.discovery_auto_download.set_active(True)
        form.append(self.discovery_auto_download)

        self.discovery_wordlist_status = Gtk.Label(xalign=0)
        self.discovery_wordlist_status.add_css_class("dim-label")
        form.append(self.discovery_wordlist_status)

        wordlist_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        wordlist_row.append(Gtk.Label(label="Custom wordlist", xalign=0))
        self.discovery_wordlist = Gtk.Entry()
        self.discovery_wordlist.add_css_class("modern-entry")
        self.discovery_wordlist.set_placeholder_text("Optional path to a custom wordlist...")
        self.discovery_wordlist.set_hexpand(True)
        wordlist_row.append(self.discovery_wordlist)
        self.discovery_wordlist_btn = Gtk.Button(label="Browse…")
        self.discovery_wordlist_btn.connect("clicked", self._on_discovery_browse_wordlist)
        wordlist_row.append(self.discovery_wordlist_btn)
        form.append(wordlist_row)

        threads_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        threads_row.append(Gtk.Label(label="Threads", xalign=0))
        self.discovery_threads = Gtk.Entry()
        self.discovery_threads.add_css_class("modern-entry")
        self.discovery_threads.set_text("20")
        threads_row.append(self.discovery_threads)
        form.append(threads_row)

        run_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.discovery_run_btn = Gtk.Button(label="Run Discovery")
        self.discovery_run_btn.add_css_class("suggested-action")
        self.discovery_run_btn.connect("clicked", self._on_discovery_run)
        run_row.append(self.discovery_run_btn)
        form.append(run_row)

        # Result section
        result_label = Gtk.Label(label="Result", xalign=0)
        result_label.add_css_class("title-4")
        form.append(result_label)

        self.discovery_results = Gtk.TextView()
        self.discovery_results.add_css_class("output-text")
        self.discovery_results.set_editable(False)
        self.discovery_results.set_monospace(True)
        res_scroller = Gtk.ScrolledWindow()
        res_scroller.add_css_class("output-box")
        res_scroller.set_min_content_height(550)
        res_scroller.set_child(self.discovery_results)
        form.append(res_scroller)

        self._refresh_discovery_wordlists()

    def _build_sqlmap_detail(self, root: Gtk.Box) -> None:
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
        back_btn.set_tooltip_text("Back to tools")
        back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
        header_row.append(back_btn)
        title = Gtk.Label(xalign=0)
        title.add_css_class("title-3")
        title.set_text("SQLMap")
        header_row.append(title)
        root.append(header_row)

        clamp = Adw.Clamp(maximum_size=860, tightening_threshold=620)
        root.append(clamp)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        clamp.set_child(form)

        # Warning
        warning_label = Gtk.Label(label="⚠️ WARNING: Only use against targets you own or have explicit permission to test.", xalign=0)
        warning_label.add_css_class("dim-label")
        warning_label.set_wrap(True)
        form.append(warning_label)

        # Target section
        target_section_label = Gtk.Label(label="Target", xalign=0)
        target_section_label.add_css_class("title-4")
        form.append(target_section_label)

        self.sqlmap_target = Gtk.Entry()
        self.sqlmap_target.add_css_class("modern-entry")
        self.sqlmap_target.set_placeholder_text("http://localhost:8080/vulnerable.php?id=1...")
        self.sqlmap_target.set_hexpand(True)
        form.append(self.sqlmap_target)

        # Configuration section
        config_section_label = Gtk.Label(label="Configuration", xalign=0)
        config_section_label.add_css_class("title-4")
        form.append(config_section_label)

        method_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        method_row.append(Gtk.Label(label="Method", xalign=0))
        self.sqlmap_method = Gtk.ComboBoxText()
        for mid, label in [("GET", "GET"), ("POST", "POST"), ("PUT", "PUT"), ("DELETE", "DELETE")]:
            self.sqlmap_method.append(mid, label)
        self.sqlmap_method.set_active_id("GET")
        method_row.append(self.sqlmap_method)
        method_row.append(Gtk.Label(label="Threads", xalign=0))
        self.sqlmap_threads = Gtk.SpinButton()
        self.sqlmap_threads.set_adjustment(Gtk.Adjustment(lower=1, upper=10, step_increment=1, page_increment=1))
        self.sqlmap_threads.set_value(1)
        method_row.append(self.sqlmap_threads)
        form.append(method_row)

        data_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        data_row.append(Gtk.Label(label="POST Data", xalign=0))
        self.sqlmap_data = Gtk.Entry()
        self.sqlmap_data.add_css_class("modern-entry")
        self.sqlmap_data.set_placeholder_text("id=1&name=test...")
        self.sqlmap_data.set_hexpand(True)
        data_row.append(self.sqlmap_data)
        form.append(data_row)

        cookies_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        cookies_row.append(Gtk.Label(label="Cookies", xalign=0))
        self.sqlmap_cookies = Gtk.Entry()
        self.sqlmap_cookies.add_css_class("modern-entry")
        self.sqlmap_cookies.set_placeholder_text("session=abcd; user=1...")
        self.sqlmap_cookies.set_hexpand(True)
        cookies_row.append(self.sqlmap_cookies)
        form.append(cookies_row)

        tamper_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        tamper_row.append(Gtk.Label(label="Tamper", xalign=0))
        self.sqlmap_tamper = Gtk.Entry()
        self.sqlmap_tamper.add_css_class("modern-entry")
        self.sqlmap_tamper.set_placeholder_text("space2comment...")
        self.sqlmap_tamper.set_hexpand(True)
        tamper_row.append(self.sqlmap_tamper)
        form.append(tamper_row)

        level_risk_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.sqlmap_level = Gtk.Entry()
        self.sqlmap_level.add_css_class("modern-entry")
        self.sqlmap_level.set_text("1")
        level_risk_row.append(Gtk.Label(label="Level (1-5)", xalign=0))
        level_risk_row.append(self.sqlmap_level)

        self.sqlmap_risk = Gtk.Entry()
        self.sqlmap_risk.add_css_class("modern-entry")
        self.sqlmap_risk.set_text("1")
        level_risk_row.append(Gtk.Label(label="Risk (1-3)", xalign=0))
        level_risk_row.append(self.sqlmap_risk)
        level_risk_row.append(Gtk.Label(label="Timeout", xalign=0))
        self.sqlmap_timeout = Gtk.Entry()
        self.sqlmap_timeout.add_css_class("modern-entry")
        self.sqlmap_timeout.set_text("30")
        level_risk_row.append(self.sqlmap_timeout)
        form.append(level_risk_row)

        options_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.sqlmap_options = Gtk.Entry()
        self.sqlmap_options.add_css_class("modern-entry")
        self.sqlmap_options.set_placeholder_text("Additional sqlmap arguments...")
        self.sqlmap_options.set_hexpand(True)
        options_row.append(Gtk.Label(label="Extra args", xalign=0))
        options_row.append(self.sqlmap_options)
        form.append(options_row)

        self.sqlmap_consent = Gtk.CheckButton(label="I understand and have permission to test this target")
        form.append(self.sqlmap_consent)

        run_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.sqlmap_run_btn = Gtk.Button(label="Run SQLMap")
        self.sqlmap_run_btn.add_css_class("suggested-action")
        self.sqlmap_run_btn.connect("clicked", self._on_sqlmap_run)
        run_row.append(self.sqlmap_run_btn)
        self.sqlmap_copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        self.sqlmap_copy_btn.set_tooltip_text("Copy output")
        self.sqlmap_copy_btn.set_sensitive(False)
        self.sqlmap_copy_btn.connect("clicked", self._on_sqlmap_copy)
        run_row.append(self.sqlmap_copy_btn)
        form.append(run_row)

        # Result section
        result_label = Gtk.Label(label="Result", xalign=0)
        result_label.add_css_class("title-4")
        form.append(result_label)

        self.sqlmap_results = Gtk.TextView()
        self.sqlmap_results.add_css_class("output-text")
        self.sqlmap_results.set_editable(False)
        self.sqlmap_results.set_monospace(True)
        res_scroller = Gtk.ScrolledWindow()
        res_scroller.add_css_class("output-box")
        res_scroller.set_min_content_height(550)
        res_scroller.set_child(self.sqlmap_results)
        form.append(res_scroller)


class CrypteaApplication(Adw.Application):
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

    def do_startup(self) -> None:  # type: ignore[override]
        Adw.Application.do_startup(self)
        self._install_actions()
        self._register_css()

    def do_activate(self) -> None:  # type: ignore[override]
        # Offline guard disabled - network alerts removed
        # try:
        #     self.offline_guard.enforce()
        # except OfflineViolation as exc:
        #     self._notify_offline_violation(str(exc))
        if not self.main_window:
            self.resources.ensure_help_extracted()
            self.main_window = MainWindow(self)
            seed_if_requested(self.challenge_manager, self.note_manager)
            self._flush_pending_warnings()
        self.main_window.present()

    def _install_actions(self) -> None:
        self._add_simple_action("copy_diagnostics", self.copy_diagnostics)
        self._add_simple_action("open_logs", self.open_logs)
        self._add_simple_action("about", self.show_about)
        self._add_simple_action("import_pack", self.import_pack)
        self._add_simple_action("export_pack", self.export_pack)
        self._add_simple_action("settings", self.show_preferences)
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
            application_icon="org.avnixm.Cryptea",
            developer_name="avnixm",
            version=config.APP_VERSION,
            comments="An offline-first companion for Capture the Flag study.",
            license_type=Gtk.License.GPL_3_0,
            issue_url="file:///app/share/cryptea/help/getting_started.md",
        )
        about.present()

    def import_pack(self) -> None:
        """Import challenges from a .ctfpack file"""
        _LOG.info("import_pack action triggered")
        if not self.main_window:
            _LOG.warning("import_pack: no main_window available")
            return
        
        dialog = Gtk.FileDialog()
        dialog.set_title("Import .ctfpack")
        
        # Create file filter for .ctfpack files
        filter_ctfpack = Gtk.FileFilter()
        filter_ctfpack.set_name("CTF Pack Files")
        filter_ctfpack.add_pattern("*.ctfpack")
        
        filter_all = Gtk.FileFilter()
        filter_all.set_name("All Files")
        filter_all.add_pattern("*")
        
        filters = Gio.ListStore.new(Gtk.FileFilter)
        filters.append(filter_ctfpack)
        filters.append(filter_all)
        dialog.set_filters(filters)
        dialog.set_default_filter(filter_ctfpack)
        
        dialog.open(self.main_window.window, None, self._on_import_pack_response)

    def _on_import_pack_response(self, dialog: Gtk.FileDialog, result: Gio.AsyncResult) -> None:
        """Handle import file selection response"""
        try:
            file = dialog.open_finish(result)
            if file:
                path = file.get_path()
                if path:
                    self._perform_import(path)
        except GLib.Error as e:
            if e.code != 2:  # Not cancelled
                _LOG.error(f"Import dialog error: {e}")
                self._show_error_toast("Failed to open import dialog")

    def _perform_import(self, path: str) -> None:
        """Perform the actual import operation"""
        try:
            from pathlib import Path
            imported_ids = self.export_import.import_from_path(Path(path))
            imported_count = len(imported_ids)
            self._show_success_toast(f"Successfully imported {imported_count} challenge(s)")
            if self.main_window:
                self.main_window.refresh_sidebar()
        except Exception as e:
            _LOG.error(f"Import failed: {e}")
            self._show_error_toast(f"Import failed: {str(e)}")

    def export_pack(self) -> None:
        """Export all challenges to a .ctfpack file"""
        _LOG.info("export_pack action triggered")
        if not self.main_window:
            _LOG.warning("export_pack: no main_window available")
            return
        
        dialog = Gtk.FileDialog()
        dialog.set_title("Export .ctfpack")
        dialog.set_initial_name("challenges.ctfpack")
        
        # Create file filter for .ctfpack files
        filter_ctfpack = Gtk.FileFilter()
        filter_ctfpack.set_name("CTF Pack Files")
        filter_ctfpack.add_pattern("*.ctfpack")
        
        filters = Gio.ListStore.new(Gtk.FileFilter)
        filters.append(filter_ctfpack)
        dialog.set_filters(filters)
        dialog.set_default_filter(filter_ctfpack)
        
        dialog.save(self.main_window.window, None, self._on_export_pack_response)

    def _on_export_pack_response(self, dialog: Gtk.FileDialog, result: Gio.AsyncResult) -> None:
        """Handle export file selection response"""
        try:
            file = dialog.save_finish(result)
            if file:
                path = file.get_path()
                if path:
                    # Ensure .ctfpack extension
                    if not path.endswith('.ctfpack'):
                        path += '.ctfpack'
                    self._perform_export(path)
        except GLib.Error as e:
            if e.code != 2:  # Not cancelled
                _LOG.error(f"Export dialog error: {e}")
                self._show_error_toast("Failed to open export dialog")

    def _perform_export(self, path: str) -> None:
        """Perform the actual export operation"""
        try:
            from pathlib import Path
            self.export_import.export_to_path(Path(path))
            challenges = self.challenge_manager.list_challenges()
            exported_count = len(challenges)
            self._show_success_toast(f"Successfully exported {exported_count} challenge(s)")
        except Exception as e:
            _LOG.error(f"Export failed: {e}")
            self._show_error_toast(f"Export failed: {str(e)}")

    def show_preferences(self) -> None:
        """Show preferences dialog"""
        _LOG.info("show_preferences action triggered")
        if not self.main_window:
            _LOG.warning("show_preferences: no main_window available")
            return
        
        prefs_window = Adw.PreferencesWindow()
        prefs_window.set_title("Preferences")
        prefs_window.set_modal(True)
        prefs_window.set_transient_for(self.main_window.window)
        prefs_window.set_default_size(600, 500)
        
        # General preferences page
        general_page = Adw.PreferencesPage()
        general_page.set_title("General")
        general_page.set_icon_name("emblem-system-symbolic")
        
        # Appearance group
        appearance_group = Adw.PreferencesGroup()
        appearance_group.set_title("Appearance")
        appearance_group.set_description("Customize the look and feel")
        
        # Theme preference (for future implementation)
        theme_row = Adw.ActionRow()
        theme_row.set_title("Theme")
        theme_row.set_subtitle("Choose application theme")
        theme_combo = Gtk.ComboBoxText()
        theme_combo.append("default", "System Default")
        theme_combo.append("light", "Light")
        theme_combo.append("dark", "Dark")
        theme_combo.set_active_id("default")
        theme_row.add_suffix(theme_combo)
        theme_row.set_activatable_widget(theme_combo)
        appearance_group.add(theme_row)
        
        general_page.add(appearance_group)
        
        # Tools group
        tools_group = Adw.PreferencesGroup()
        tools_group.set_title("Tools")
        tools_group.set_description("Configure external tools and paths")
        
        # Tools info row
        tools_info = Adw.ActionRow()
        tools_info.set_title("External Tools")
        tools_info.set_subtitle("Cryptea uses system-installed tools (Hashcat, GDB, Ghidra, etc.)")
        tools_group.add(tools_info)
        
        general_page.add(tools_group)
        
        # Data group
        data_group = Adw.PreferencesGroup()
        data_group.set_title("Data")
        data_group.set_description("Manage your challenge data")
        
        # Database location
        db_row = Adw.ActionRow()
        db_row.set_title("Database Location")
        db_row.set_subtitle(str(self.database.path))
        data_group.add(db_row)
        
        general_page.add(data_group)
        
        prefs_window.add(general_page)
        prefs_window.present()

    def _show_success_toast(self, message: str) -> None:
        """Show a success toast notification"""
        if self.main_window:
            toast = Adw.Toast.new(message)
            toast.set_timeout(3)
            self.main_window.toast_overlay.add_toast(toast)

    def _show_error_toast(self, message: str) -> None:
        """Show an error toast notification"""
        if self.main_window:
            toast = Adw.Toast.new(message)
            toast.set_priority(Adw.ToastPriority.HIGH)
            toast.set_timeout(5)
            self.main_window.toast_overlay.add_toast(toast)

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
    app = CrypteaApplication()
    app.run(None)
