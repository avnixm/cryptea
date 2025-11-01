"""
Cheat Sheet Panel UI
GNOME 49-style single-pane CRUD interface for managing custom cheat sheets.
"""

from __future__ import annotations

import logging
from datetime import datetime
from gi.repository import Gtk, Adw, GLib, Gdk, Pango, Gio

from ..cheatsheets.custom_manager import CustomCheatSheetManager, CustomCheatSheet

logger = logging.getLogger(__name__)


class CheatSheetRow(Adw.ActionRow):
    """A row representing a cheat sheet in the list."""
    
    def __init__(self, cheatsheet: CustomCheatSheet, on_edit, on_delete):
        super().__init__()
        self.cheatsheet = cheatsheet
        self.on_edit = on_edit
        self.on_delete = on_delete
        
        # Title
        self.set_title(cheatsheet.title)
        self.set_title_lines(1)
        self.add_css_class("cheatsheet-row")
        
        # Subtitle with snippet and date
        snippet = cheatsheet.get_snippet(100)
        try:
            date_obj = datetime.fromisoformat(cheatsheet.date_modified.replace('Z', '+00:00'))
            date_str = date_obj.strftime("%Y-%m-%d %H:%M")
        except Exception:
            date_str = cheatsheet.date_modified
        
        if snippet:
            self.set_subtitle(f"{snippet} • {date_str}")
        else:
            self.set_subtitle(f"Modified: {date_str}")
        
        self.set_subtitle_lines(2)
        
        # Three-dot menu button
        menu_button = Gtk.MenuButton()
        menu_button.set_icon_name("view-more-symbolic")
        menu_button.add_css_class("flat")
        menu_button.set_valign(Gtk.Align.CENTER)
        menu_button.set_tooltip_text("More options")
        
        # Popover menu
        popover = Gtk.PopoverMenu()
        
        # Menu model
        menu = Gio.Menu()
        
        edit_action = Gio.SimpleAction.new("edit", None)
        edit_action.connect("activate", lambda action, param: on_edit(cheatsheet))
        
        delete_action = Gio.SimpleAction.new("delete", None)
        delete_action.connect("activate", lambda action, param: on_delete(cheatsheet))
        
        menu.append("Edit", "row.edit")
        menu.append("Delete", "row.delete")
        
        popover.set_menu_model(menu)
        
        # Action group for the menu
        action_group = Gio.SimpleActionGroup()
        action_group.add_action(edit_action)
        action_group.add_action(delete_action)
        self.insert_action_group("row", action_group)
        
        menu_button.set_popover(popover)
        
        self.add_suffix(menu_button)
        self.set_activatable(True)


class CheatSheetEditDialog(Adw.Dialog):
    """Dialog for adding/editing a cheat sheet."""
    
    def __init__(self, parent: Adw.ApplicationWindow, cheatsheet: CustomCheatSheet | None = None):
        super().__init__()
        self.set_modal(True)
        self.set_transient_for(parent)
        self.cheatsheet = cheatsheet
        self.parent_window = parent
        
        # Title
        if cheatsheet:
            title_text = "Edit Cheat Sheet"
        else:
            title_text = "Add Cheat Sheet"
        
        # Content box with padding
        content = Adw.PreferencesPage()
        content.set_margin_top(12)
        content.set_margin_bottom(12)
        content.set_margin_start(12)
        content.set_margin_end(12)
        
        # Title group
        title_group = Adw.PreferencesGroup()
        title_group.set_title("Title")
        
        self.title_entry = Gtk.Entry()
        self.title_entry.set_placeholder_text("Enter cheat sheet title...")
        if cheatsheet:
            self.title_entry.set_text(cheatsheet.title)
        self.title_entry.set_hexpand(True)
        title_group.add(self.title_entry)
        content.add(title_group)
        
        # Content group
        content_group = Adw.PreferencesGroup()
        content_group.set_title("Content")
        
        # Content text view with scrolled window
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_min_content_height(300)
        scrolled.set_max_content_height(500)
        scrolled.set_vexpand(True)
        scrolled.set_hexpand(True)
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        
        self.content_text = Gtk.TextView()
        self.content_text.set_wrap_mode(Gtk.WrapMode.WORD)
        self.content_text.set_monospace(False)
        self.content_text.set_hexpand(True)
        self.content_text.set_vexpand(True)
        self.content_text.set_margin_top(6)
        self.content_text.set_margin_bottom(6)
        self.content_text.set_margin_start(6)
        self.content_text.set_margin_end(6)
        
        buffer = self.content_text.get_buffer()
        if cheatsheet:
            buffer.set_text(cheatsheet.content)
        else:
            buffer.set_text("")
        
        scrolled.set_child(self.content_text)
        content_group.add(scrolled)
        content.add(content_group)
        
        # Buttons group
        buttons_group = Adw.PreferencesGroup()
        buttons_group.set_margin_top(12)
        
        buttons_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        buttons_box.set_halign(Gtk.Align.END)
        
        cancel_btn = Gtk.Button(label="Cancel")
        cancel_btn.add_css_class("flat")
        cancel_btn.connect("clicked", lambda btn: self.close())
        buttons_box.append(cancel_btn)
        
        save_btn = Gtk.Button(label="Save")
        save_btn.add_css_class("suggested-action")
        save_btn.connect("clicked", self._on_save_clicked)
        buttons_box.append(save_btn)
        
        buttons_group.add(buttons_box)
        content.add(buttons_group)
        
        self.set_content(content)
        
        # Connect Enter key to save
        self.title_entry.connect("activate", lambda entry: save_btn.emit("activate"))
        
        # Focus title entry
        self.title_entry.grab_focus()
    
    def _on_save_clicked(self, button: Gtk.Button):
        """Handle save button click."""
        title = self.title_entry.get_text().strip()
        if not title:
            # Show error dialog
            error_dialog = Adw.MessageDialog(
                transient_for=self.parent_window,
                heading="Title Required",
                body="Please enter a title for the cheat sheet.",
            )
            error_dialog.add_response("ok", "OK")
            error_dialog.set_default_response("ok")
            error_dialog.present()
            return
        
        # Emit response with "save"
        self.response("save")
        self.close()
    
    def get_values(self) -> tuple[str, str]:
        """Get the title and content values."""
        title = self.title_entry.get_text().strip()
        buffer = self.content_text.get_buffer()
        start_iter = buffer.get_start_iter()
        end_iter = buffer.get_end_iter()
        content = buffer.get_text(start_iter, end_iter, False)
        return title, content


class CheatSheetPanel(Gtk.Box):
    """Main panel for managing custom cheat sheets with GNOME 49-style UI."""
    
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        
        self.manager = CustomCheatSheetManager()
        
        # Build UI
        self._build_header()
        self._build_content()
        
        # Load and display cheat sheets
        self._refresh_list()
    
    def _build_header(self):
        """Build the header with search and add button."""
        header_box = Adw.HeaderBar()
        header_box.add_css_class("flat")
        
        # Search bar container
        search_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        search_box.set_margin_start(12)
        search_box.set_margin_end(12)
        search_box.set_margin_top(12)
        search_box.set_margin_bottom(12)
        
        self.search_entry = Gtk.SearchEntry()
        self.search_entry.set_placeholder_text("Search cheat sheets...")
        self.search_entry.set_hexpand(True)
        self.search_entry.connect("search-changed", self._on_search_changed)
        self.search_entry.connect("changed", self._on_search_changed)
        search_box.append(self.search_entry)
        
        # Add button
        add_button = Gtk.Button()
        add_button.set_icon_name("list-add-symbolic")
        add_button.set_tooltip_text("Add Cheat Sheet")
        add_button.add_css_class("suggested-action")
        add_button.connect("clicked", self._on_add_clicked)
        search_box.append(add_button)
        
        self.append(search_box)
    
    def _build_content(self):
        """Build the main content area."""
        # Scrolled window
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scrolled.set_vexpand(True)
        scrolled.set_hexpand(True)
        
        # Preferences page (GNOME-style list)
        self.preferences_page = Adw.PreferencesPage()
        self.preferences_page.add_css_class("cheatsheet-page")
        
        # Preferences group
        self.preferences_group = Adw.PreferencesGroup()
        self.preferences_group.set_title("Cheat Sheets")
        self.preferences_page.add(self.preferences_group)
        
        scrolled.set_child(self.preferences_page)
        self.append(scrolled)
    
    def _refresh_list(self, search_query: str = ""):
        """Refresh the cheat sheet list."""
        # Clear existing rows by removing and recreating the group
        old_group = self.preferences_group
        self.preferences_group = Adw.PreferencesGroup()
        self.preferences_group.set_title("Cheat Sheets")
        self.preferences_page.remove(old_group)
        self.preferences_page.add(self.preferences_group)
        
        # Get cheat sheets
        if search_query:
            cheatsheets = self.manager.search(search_query)
        else:
            cheatsheets = self.manager.get_all()
        
        # Show empty state if no cheat sheets
        if not cheatsheets:
            empty_row = Adw.ActionRow()
            empty_row.set_title("No cheat sheets yet" if not search_query else "No results found")
            empty_row.set_subtitle("Click the + button to create your first cheat sheet" if not search_query else "Try a different search query")
            empty_row.set_activatable(False)
            empty_row.add_css_class("dim-label")
            self.preferences_group.add(empty_row)
            return
        
        # Add rows
        for cheatsheet in cheatsheets:
            row = CheatSheetRow(
                cheatsheet,
                on_edit=self._on_edit_clicked,
                on_delete=self._on_delete_clicked
            )
            # Connect activation - row already has cheatsheet stored
            row.connect("activated", lambda r: self._on_row_activated(r))
            self.preferences_group.add(row)
    
    def _on_row_activated(self, row: CheatSheetRow):
        """Handle row activation (click)."""
        self._on_edit_clicked(row.cheatsheet)
    
    def _on_search_changed(self, entry: Gtk.SearchEntry):
        """Handle search text change."""
        query = entry.get_text().strip()
        self._refresh_list(query)
    
    def _show_toast(self, message: str):
        """Show a toast notification by finding the toast overlay in parent hierarchy."""
        widget = self
        while widget:
            if isinstance(widget, Adw.ToastOverlay):
                toast = Adw.Toast.new(message)
                toast.set_timeout(2)
                widget.add_toast(toast)
                return
            widget = widget.get_parent()
        
        # Fallback: log
        logger.info(f"Toast (no overlay found): {message}")
    
    def _get_window(self) -> Adw.ApplicationWindow | None:
        """Get the application window from the widget hierarchy."""
        widget = self
        while widget:
            if isinstance(widget, Adw.ApplicationWindow):
                return widget
            widget = widget.get_parent()
        return None
    
    def _on_add_clicked(self, button: Gtk.Button):
        """Handle add button click."""
        window = self._get_window()
        if window:
            dialog = CheatSheetEditDialog(window, cheatsheet=None)
            dialog.connect("response", self._on_dialog_response, None)
            dialog.present()
    
    def _on_edit_clicked(self, cheatsheet: CustomCheatSheet):
        """Handle edit action."""
        window = self._get_window()
        if window:
            dialog = CheatSheetEditDialog(window, cheatsheet=cheatsheet)
            dialog.connect("response", self._on_dialog_response, cheatsheet)
            dialog.present()
    
    def _on_delete_clicked(self, cheatsheet: CustomCheatSheet):
        """Handle delete action."""
        window = self._get_window()
        if not window:
            return
        
        # Show confirmation dialog
        dialog = Adw.MessageDialog(
            transient_for=window,
            heading="Delete Cheat Sheet?",
            body=f"Are you sure you want to delete \"{cheatsheet.title}\"? This action cannot be undone.",
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("delete", "Delete")
        dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.connect("response", self._on_delete_response, cheatsheet)
        dialog.present()
    
    def _on_delete_response(self, dialog: Adw.MessageDialog, response: str, cheatsheet: CustomCheatSheet):
        """Handle delete confirmation response."""
        if response == "delete":
            self.manager.delete(cheatsheet.id)
            self._refresh_list()
            # Clear search if active
            query = self.search_entry.get_text().strip()
            if query:
                self.search_entry.set_text("")
            
            # Show success toast
            self._show_toast(f"Deleted {cheatsheet.title}")
        
        dialog.close()
    
    def _on_dialog_response(self, dialog: CheatSheetEditDialog, response: str, cheatsheet: CustomCheatSheet | None):
        """Handle edit dialog response."""
        if response == "save":
            title, content = dialog.get_values()
            
            if cheatsheet:
                # Update existing
                self.manager.update(cheatsheet.id, title, content)
                toast_msg = f"Updated {title}"
            else:
                # Create new
                self.manager.create(title, content)
                toast_msg = f"Created {title}"
            
            self._refresh_list()
            # Clear search to show new/updated item
            query = self.search_entry.get_text().strip()
            if query:
                self.search_entry.set_text("")
            
            # Show success toast
            self._show_toast(toast_msg)
        
        dialog.close()
