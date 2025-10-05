"""
Template selection dialog for creating challenges from templates
"""
from pathlib import Path
from typing import Optional, Callable
import gi
import logging

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, GObject

from ..manager.templates import TemplateManager, ChallengeTemplate

logger = logging.getLogger(__name__)


class TemplateDialog(Adw.Dialog):
    """Dialog for selecting and previewing challenge templates"""
    
    def __init__(self, parent: Gtk.Window, callback: Optional[Callable[[ChallengeTemplate], None]] = None):
        super().__init__()
        self.set_title("Create from Template")
        self.set_content_width(700)
        self.set_content_height(600)
        
        self.parent_window = parent
        self.callback = callback
        self.template_manager = TemplateManager()
        self.templates: list[ChallengeTemplate] = []
        self.selected_template: Optional[ChallengeTemplate] = None
        
        # Build UI
        self._build_ui()
        
        # Load templates
        self._load_templates()
        
        # Initially disable create button until a template is selected
        self.create_button.set_sensitive(False)
    
    def _build_ui(self) -> None:
        """Build the dialog UI programmatically"""
        # Create toolbar view
        toolbar_view = Adw.ToolbarView()
        
        # Header bar
        header_bar = Adw.HeaderBar()
        header_bar.set_show_title(True)
        
        # Cancel button
        self.cancel_button = Gtk.Button(label="Cancel")
        self.cancel_button.connect("clicked", self._on_cancel_clicked)
        header_bar.pack_start(self.cancel_button)
        
        # Create button
        self.create_button = Gtk.Button(label="Create")
        self.create_button.add_css_class("suggested-action")
        self.create_button.connect("clicked", self._on_create_clicked)
        header_bar.pack_end(self.create_button)
        
        toolbar_view.add_top_bar(header_bar)
        
        # Main content box
        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        
        # Template list section
        list_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        list_box.set_margin_start(24)
        list_box.set_margin_end(24)
        list_box.set_margin_top(18)
        list_box.set_margin_bottom(18)
        
        list_label = Gtk.Label(label="Choose a template", xalign=0)
        list_label.add_css_class("title-3")
        list_box.append(list_label)
        
        # Scrolled window for template list
        list_scroll = Gtk.ScrolledWindow()
        list_scroll.set_vexpand(True)
        list_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        list_scroll.set_min_content_height(200)
        
        self.template_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
        self.template_list.add_css_class("boxed-list")
        self.template_list.connect("row-selected", self._on_template_selected)
        list_scroll.set_child(self.template_list)
        
        list_box.append(list_scroll)
        content_box.append(list_box)
        
        # Separator
        separator = Gtk.Separator()
        content_box.append(separator)
        
        # Preview section
        preview_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        preview_box.set_margin_start(24)
        preview_box.set_margin_end(24)
        preview_box.set_margin_top(18)
        preview_box.set_margin_bottom(18)
        
        preview_label = Gtk.Label(label="Template Details", xalign=0)
        preview_label.add_css_class("title-3")
        preview_box.append(preview_label)
        
        # Preview group
        preview_group = Adw.PreferencesGroup()
        
        self.title_row = Adw.ActionRow(title="Title")
        self.title_row.set_subtitle_selectable(True)
        preview_group.add(self.title_row)
        
        self.category_row = Adw.ActionRow(title="Category")
        self.category_row.set_subtitle_selectable(True)
        preview_group.add(self.category_row)
        
        self.difficulty_row = Adw.ActionRow(title="Difficulty")
        self.difficulty_row.set_subtitle_selectable(True)
        preview_group.add(self.difficulty_row)
        
        self.tags_row = Adw.ActionRow(title="Tags")
        self.tags_row.set_subtitle_selectable(True)
        preview_group.add(self.tags_row)
        
        preview_box.append(preview_group)
        
        # Description label
        desc_label = Gtk.Label(label="Description", xalign=0)
        desc_label.add_css_class("caption-heading")
        preview_box.append(desc_label)
        
        # Description preview
        desc_scroll = Gtk.ScrolledWindow()
        desc_scroll.set_vexpand(True)
        desc_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        desc_scroll.set_min_content_height(100)
        
        self.description_preview = Gtk.TextView(editable=False, wrap_mode=Gtk.WrapMode.WORD)
        self.description_preview.set_left_margin(12)
        self.description_preview.set_right_margin(12)
        self.description_preview.set_top_margin(12)
        self.description_preview.set_bottom_margin(12)
        self.description_preview.add_css_class("card")
        desc_scroll.set_child(self.description_preview)
        
        preview_box.append(desc_scroll)
        content_box.append(preview_box)
        
        toolbar_view.set_content(content_box)
        self.set_child(toolbar_view)

    
    def _load_templates(self) -> None:
        """Load templates from TemplateManager and populate the list"""
        try:
            self.templates = self.template_manager.list_templates()
            logger.info(f"Loaded {len(self.templates)} templates")
            
            # Clear existing rows
            while True:
                row = self.template_list.get_row_at_index(0)
                if row is None:
                    break
                self.template_list.remove(row)
            
            # Add template rows
            for template in self.templates:
                row = self._create_template_row(template)
                self.template_list.append(row)
            
            # Select first template if available
            if self.templates:
                first_row = self.template_list.get_row_at_index(0)
                if first_row:
                    self.template_list.select_row(first_row)
                    
        except Exception as e:
            logger.error(f"Failed to load templates: {e}")
    
    def _create_template_row(self, template: ChallengeTemplate) -> Adw.ActionRow:
        """Create a list row for a template"""
        row = Adw.ActionRow()
        row.set_title(template.title)
        
        # Create subtitle with category and difficulty
        subtitle = f"{template.category} • {template.difficulty.capitalize()}"
        row.set_subtitle(subtitle)
        
        # Add chevron icon
        chevron = Gtk.Image.new_from_icon_name("go-next-symbolic")
        chevron.add_css_class("dim-label")
        row.add_suffix(chevron)
        
        # Store template reference
        row.template = template
        
        return row
    
    def _on_template_selected(self, listbox: Gtk.ListBox, row: Optional[Gtk.ListBoxRow]) -> None:
        """Handle template selection"""
        if row is None:
            self.selected_template = None
            self.create_button.set_sensitive(False)
            self._clear_preview()
            return
        
        # Get template from row
        if hasattr(row, 'template'):
            self.selected_template = row.template
            if self.selected_template:
                self._update_preview(self.selected_template)
                self.create_button.set_sensitive(True)
    
    def _update_preview(self, template: ChallengeTemplate) -> None:
        """Update preview pane with template details"""
        # Update info rows
        self.title_row.set_subtitle(template.title)
        self.category_row.set_subtitle(template.category)
        self.difficulty_row.set_subtitle(template.difficulty.capitalize())
        
        # Format tags
        if template.tags:
            tags_text = ", ".join(template.tags)
        else:
            tags_text = "None"
        self.tags_row.set_subtitle(tags_text)
        
        # Update description
        buffer = self.description_preview.get_buffer()
        buffer.set_text(template.description)
    
    def _clear_preview(self) -> None:
        """Clear the preview pane"""
        self.title_row.set_subtitle("")
        self.category_row.set_subtitle("")
        self.difficulty_row.set_subtitle("")
        self.tags_row.set_subtitle("")
        buffer = self.description_preview.get_buffer()
        buffer.set_text("")
    
    def _on_cancel_clicked(self, button: Gtk.Button) -> None:
        """Handle cancel button click"""
        self.close()
    
    def _on_create_clicked(self, button: Gtk.Button) -> None:
        """Handle create button click"""
        if self.selected_template and self.callback:
            self.callback(self.selected_template)
        self.close()


def show_template_dialog(parent: Gtk.Window, callback: Callable[[ChallengeTemplate], None]) -> None:
    """
    Show the template selection dialog
    
    Args:
        parent: Parent window
        callback: Function to call with selected template when Create is clicked
    """
    dialog = TemplateDialog(parent, callback)
    dialog.present(parent)
