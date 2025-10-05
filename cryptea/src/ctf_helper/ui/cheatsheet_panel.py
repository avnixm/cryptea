"""
Cheat Sheet Panel UI
GTK4/Libadwaita interface for browsing offline cheat sheets.
Tabbed interface similar to Hash Suite.
"""

import logging
from gi.repository import Gtk, Adw, GLib, Gdk, Pango

from ..cheatsheets.loader import CheatSheetLoader, CheatSheet

logger = logging.getLogger(__name__)


class CheatSheetPanel(Gtk.Box):
    """Main panel for displaying cheat sheets with tabbed interface."""
    
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        
        self.loader = CheatSheetLoader()
        self.current_category = None
        self.current_sheet = None
        
        # Build UI
        self._build_header()
        self._build_tabs()
        self._build_content()
        
        # Load data immediately instead of using idle_add
        self._load_data()
    
    def _build_header(self):
        """Build the header with search bar."""
        header_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        header_box.add_css_class("toolbar")
        
        # Search bar
        search_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        search_box.set_margin_start(12)
        search_box.set_margin_end(12)
        search_box.set_margin_top(12)
        search_box.set_margin_bottom(6)
        
        self.search_entry = Gtk.SearchEntry()
        self.search_entry.set_placeholder_text("Search cheat sheets...")
        self.search_entry.set_hexpand(True)
        # GTK4 SearchEntry uses "search-changed" signal
        self.search_entry.connect("search-changed", self._on_search_changed)
        # Also connect to "changed" as backup
        self.search_entry.connect("changed", self._on_search_changed)
        logger.info("Search entry signals connected")
        search_box.append(self.search_entry)
        
        header_box.append(search_box)
        
        self.append(header_box)
    
    def _build_tabs(self):
        """Build the category tabs using Gtk.Notebook."""
        # Use Gtk.Notebook for proper tab interface
        self.notebook = Gtk.Notebook()
        self.notebook.set_vexpand(True)
        self.notebook.set_show_border(False)
        self.notebook.set_tab_pos(Gtk.PositionType.TOP)
        self.notebook.set_scrollable(True)
        
        # Connect to page switch to track current category
        self.notebook.connect("switch-page", self._on_tab_switched)
        
        # Store for later reference
        self.tab_buttons = {}
        self.category_map = {}  # Map page index to category name
        
        self.append(self.notebook)
        
        logger.info(f"Notebook tabs built")
    
    def _build_content(self):
        """Build the main content area - not needed with Notebook."""
        # Content is built per-tab in _create_category_page
        pass
    
    def _load_data(self):
        """Load cheat sheets data."""
        try:
            logger.info("Starting to load cheat sheets...")
            self.loader.load_all()
            
            # Create tabs for each category
            categories = self.loader.get_categories()
            logger.info(f"Found categories: {categories}")
            
            if not categories:
                logger.warning("No categories found!")
                return
            
            for category in categories:
                logger.info(f"Adding tab for category: {category}")
                self._add_category_tab(category)
            
            # Select first category
            if categories:
                logger.info(f"Selecting first category: {categories[0]}")
                self.notebook.set_current_page(0)
                self.current_category = categories[0]
            
            logger.info(f"Successfully loaded {len(categories)} categories")
            
        except Exception as e:
            logger.error(f"Error loading cheat sheets: {e}", exc_info=True)
    
    def _add_category_tab(self, category: str):
        """Add a tab for a category using Gtk.Notebook."""
        logger.info(f"Adding tab for category: {category}")
        
        # Create content page for category
        page_widget = self._create_category_page(category)
        
        # Create tab label
        tab_label = Gtk.Label(label=category)
        
        # Add to notebook (tabs are not closeable by default in Gtk.Notebook)
        page_num = self.notebook.append_page(page_widget, tab_label)
        self.notebook.set_tab_reorderable(page_widget, False)
        
        self.tab_buttons[category] = page_num
        self.category_map[page_num] = category  # Store mapping
        
        logger.info(f"Tab added for category: {category} at position {page_num}")
    
    def _create_category_page(self, category: str):
        """Create content page for a category."""
        # Main container
        page_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        
        # Sheet list on left, content on right
        paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        paned.set_vexpand(True)
        paned.set_position(250)
        
        # Left: List of sheets in category
        left_scrolled = Gtk.ScrolledWindow()
        left_scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        
        sheet_list = Gtk.ListBox()
        sheet_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        sheet_list.add_css_class("navigation-sidebar")
        
        sheets = self.loader.get_sheets_by_category(category)
        logger.info(f"Creating page for {category} with {len(sheets)} sheets")
        
        for sheet in sheets:
            row = self._create_sheet_row(sheet)
            sheet_list.append(row)
        
        sheet_list.connect("row-selected", self._on_sheet_selected, category)
        left_scrolled.set_child(sheet_list)
        paned.set_start_child(left_scrolled)
        
        # Right: Sheet content display
        right_scrolled = Gtk.ScrolledWindow()
        right_scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)  # No horizontal scroll, vertical when needed
        right_scrolled.set_hexpand(True)  # Expand to fill available space
        right_scrolled.set_vexpand(True)
        
        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        content_box.set_name(f"content_{category}")
        
        # Empty state
        empty_state = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        empty_state.set_valign(Gtk.Align.CENTER)
        empty_state.set_halign(Gtk.Align.CENTER)
        empty_state.set_margin_top(48)
        empty_state.set_margin_bottom(48)
        
        empty_icon = Gtk.Image.new_from_icon_name("text-x-generic-symbolic")
        empty_icon.set_pixel_size(48)
        empty_icon.add_css_class("dim-label")
        empty_state.append(empty_icon)
        
        empty_label = Gtk.Label(label="Select a cheat sheet")
        empty_label.add_css_class("dim-label")
        empty_state.append(empty_label)
        
        content_box.append(empty_state)
        right_scrolled.set_child(content_box)
        paned.set_end_child(right_scrolled)
        
        page_box.append(paned)
        return page_box
    
    def _create_sheet_row(self, sheet: CheatSheet) -> Gtk.ListBoxRow:
        """Create a row for a sheet."""
        row = Gtk.ListBoxRow()
        row.sheet = sheet  # Store as Python attribute instead of set_data()
        
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        box.set_margin_start(12)
        box.set_margin_end(12)
        box.set_margin_top(8)
        box.set_margin_bottom(8)
        
        title = Gtk.Label(label=sheet.title)
        title.set_xalign(0)
        title.set_wrap(True)
        title.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
        title.add_css_class("heading")
        box.append(title)
        
        if sheet.description:
            desc = Gtk.Label(label=sheet.description[:100] + "..." if len(sheet.description) > 100 else sheet.description)
            desc.set_xalign(0)
            desc.set_wrap(True)
            desc.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
            desc.add_css_class("dim-label")
            desc.add_css_class("caption")
            box.append(desc)
        
        row.set_child(box)
        return row
    
    def _on_sheet_selected(self, listbox: Gtk.ListBox, row: Gtk.ListBoxRow, category: str):
        """Handle sheet selection."""
        if not row:
            return
        
        sheet = getattr(row, 'sheet', None)  # Get Python attribute instead of get_data()
        if not sheet:
            return
        
        self.current_sheet = sheet
        self._display_sheet(sheet, category)
    
    def _display_sheet(self, sheet: CheatSheet, category: str):
        """Display a cheat sheet."""
        logger.info(f"=== DISPLAY_SHEET CALLED ===")
        logger.info(f"Sheet: {sheet.title}")
        logger.info(f"Sheet.entries: {len(sheet.entries) if sheet.entries else 'None/Empty'}")
        
        # Find the current page in the notebook
        current_page = self.notebook.get_current_page()
        if current_page == -1:
            logger.error("No current page in notebook!")
            return
        
        page_widget = self.notebook.get_nth_page(current_page)
        if not page_widget:
            logger.error("No page widget found!")
            return
        
        # Get the paned widget
        paned = page_widget.get_first_child()
        if not paned or not isinstance(paned, Gtk.Paned):
            logger.error(f"Paned widget issue: {paned}, type: {type(paned)}")
            return
        
        # Get the right scrolled window
        right_scrolled = paned.get_end_child()
        if not right_scrolled:
            logger.error("No right_scrolled widget!")
            return
        
        logger.info("Creating content box...")
        
        # Create new content
        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        content_box.set_margin_start(24)
        content_box.set_margin_end(24)
        content_box.set_margin_top(24)
        content_box.set_margin_bottom(24)
        content_box.set_visible(True)  # Ensure visible
        
        # Title
        title_label = Gtk.Label(label=f"<span size='x-large' weight='bold'>{sheet.title}</span>")
        title_label.set_use_markup(True)
        title_label.set_xalign(0)
        title_label.set_margin_bottom(8)
        content_box.append(title_label)
        
        # Description
        if sheet.description:
            desc_label = Gtk.Label(label=sheet.description)
            desc_label.set_xalign(0)
            desc_label.set_wrap(True)
            desc_label.set_wrap_mode(Pango.WrapMode.WORD)
            desc_label.add_css_class("dim-label")
            desc_label.set_margin_bottom(24)
            content_box.append(desc_label)
        
        # Category badge
        badge_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        badge_box.set_halign(Gtk.Align.START)
        badge_box.set_margin_bottom(24)
        
        category_label = Gtk.Label(label=sheet.category)
        category_label.add_css_class("badge")
        category_label.add_css_class("caption")
        badge_box.append(category_label)
        content_box.append(badge_box)
        
        # Entries
        logger.info(f"Sheet.entries check: {sheet.entries is not None}, bool: {bool(sheet.entries)}")
        if sheet.entries:
            logger.info(f"Adding {len(sheet.entries)} entries...")
            for i, entry in enumerate(sheet.entries):
                logger.info(f"  Creating entry {i+1}: {entry.get('name', 'NO NAME')}")
                entry_widget = self._create_entry_widget(entry)
                content_box.append(entry_widget)
            logger.info("All entries added!")
        else:
            logger.warning("No entries to display!")
        
        logger.info("Setting child on right_scrolled...")
        right_scrolled.set_child(content_box)
        logger.info("Display complete!")
    
    def _create_entry_widget(self, entry: dict) -> Gtk.Widget:
        """Create widget for a cheat sheet entry."""
        entry_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        entry_box.set_margin_bottom(32)
        entry_box.set_visible(True)  # Ensure visible
        
        # Entry title
        if "name" in entry:
            name_label = Gtk.Label(label=f"<b>{entry['name']}</b>")
            name_label.set_use_markup(True)
            name_label.set_xalign(0)
            name_label.set_wrap(True)
            name_label.set_wrap_mode(Pango.WrapMode.WORD)
            name_label.set_visible(True)  # Ensure visible
            entry_box.append(name_label)
        
        # Description
        if "desc" in entry:
            desc_label = Gtk.Label(label=entry['desc'])
            desc_label.set_xalign(0)
            desc_label.set_wrap(True)
            desc_label.set_wrap_mode(Pango.WrapMode.WORD)
            desc_label.add_css_class("dim-label")
            entry_box.append(desc_label)
        
        # Code example
        if "example" in entry:
            code_box = self._create_code_block(entry['example'])
            entry_box.append(code_box)
        
        # Flag hint
        if "flag_hint" in entry:
            hint_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            hint_box.add_css_class("card")
            hint_box.set_margin_top(8)
            
            hint_icon = Gtk.Image.new_from_icon_name("dialog-information-symbolic")
            hint_icon.set_valign(Gtk.Align.START)
            hint_icon.set_margin_top(4)
            hint_box.append(hint_icon)
            
            hint_label = Gtk.Label(label=f"<b>Tip:</b> {entry['flag_hint']}")
            hint_label.set_use_markup(True)
            hint_label.set_xalign(0)
            hint_label.set_wrap(True)
            hint_label.set_wrap_mode(Pango.WrapMode.WORD)
            hint_box.append(hint_label)
            
            entry_box.append(hint_box)
        
        return entry_box
    
    def _create_code_block(self, code: str) -> Gtk.Widget:
        """Create a code block with copy button."""
        # Outer container with rounded corners
        outer_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        outer_box.set_margin_top(6)
        outer_box.set_margin_bottom(6)
        
        code_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        code_box.add_css_class("card")
        code_box.add_css_class("cheatsheet-code-block")
        code_box.set_overflow(Gtk.Overflow.HIDDEN)  # Clip to rounded corners
        
        # Header with copy button
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        header.set_margin_start(12)
        header.set_margin_end(12)
        header.set_margin_top(12)
        header.set_margin_bottom(8)
        
        code_label = Gtk.Label(label="Code Example")
        code_label.set_xalign(0)
        code_label.set_hexpand(True)
        code_label.add_css_class("caption")
        code_label.add_css_class("dim-label")
        header.append(code_label)
        
        copy_button = Gtk.Button()
        copy_button.set_icon_name("edit-copy-symbolic")
        copy_button.set_tooltip_text("Copy to clipboard")
        copy_button.add_css_class("flat")
        copy_button.connect("clicked", self._on_copy_clicked, code)
        header.append(copy_button)
        
        code_box.append(header)
        
        # Separator
        separator = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
        code_box.append(separator)
        
        # Code text with word wrapping enabled
        text_view = Gtk.TextView()
        text_view.set_editable(False)
        text_view.set_monospace(True)
        text_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)  # Enable word wrapping
        text_view.set_margin_start(16)
        text_view.set_margin_end(16)
        text_view.set_margin_top(16)
        text_view.set_margin_bottom(16)
        text_view.set_left_margin(8)
        text_view.set_right_margin(8)
        text_view.set_top_margin(8)
        text_view.set_bottom_margin(8)
        text_view.set_hexpand(True)  # Expand horizontally to fill container
        
        buffer = text_view.get_buffer()
        buffer.set_text(code)
        
        # Scrolled window for long code - horizontal scrolling disabled, vertical only when needed
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)  # No horizontal scroll, vertical when needed
        scrolled.set_min_content_height(200)  # Minimum height to see content (increased for better readability)
        scrolled.set_max_content_height(1200)  # Maximum height before scrolling - allows much more content to be visible
        scrolled.set_vexpand(False)
        scrolled.set_hexpand(True)  # Expand horizontally to fill container
        scrolled.set_has_frame(False)
        scrolled.set_child(text_view)
        
        # Wrapper box with rounded corners and background
        wrapper = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        wrapper.add_css_class("code-wrapper")
        wrapper.append(scrolled)
        
        code_box.append(wrapper)
        
        outer_box.append(code_box)
        return outer_box
    
    def _on_copy_clicked(self, button: Gtk.Button, text: str):
        """Handle copy button click."""
        clipboard = Gdk.Display.get_default().get_clipboard()
        clipboard.set(text)
        
        # Show feedback
        button.set_icon_name("emblem-ok-symbolic")
        GLib.timeout_add(1000, lambda: button.set_icon_name("edit-copy-symbolic"))
    
    def _on_search_changed(self, entry: Gtk.SearchEntry):
        """Handle search text change."""
        query = entry.get_text().strip()
        
        logger.info(f"Search changed: '{query}'")
        
        if not query:
            # If search is cleared, reload the current category
            logger.info("Search cleared, refreshing current category")
            if self.current_category:
                self._refresh_current_category()
            return
        
        # Filter sheets by search query
        results = self.loader.search(query)
        logger.info(f"Search: '{query}' - {len(results)} results found")
        
        # Display search results in the current tab
        current_page = self.notebook.get_current_page()
        logger.info(f"Current notebook page: {current_page}")
        
        if current_page == -1:
            logger.error("No current page!")
            return
        
        page_widget = self.notebook.get_nth_page(current_page)
        if not page_widget:
            logger.error("No page widget found!")
            return
        
        logger.info(f"Page widget type: {type(page_widget)}")
        
        # Get the paned widget
        paned = page_widget.get_first_child()
        if not paned:
            logger.error("No first child!")
            return
            
        logger.info(f"Paned type: {type(paned)}")
        
        if not isinstance(paned, Gtk.Paned):
            logger.error(f"First child is not Paned, it's {type(paned)}")
            return
        
        # Get the left scrolled window with the list
        left_scrolled = paned.get_start_child()
        if not left_scrolled:
            logger.error("No left_scrolled widget!")
            return
        
        logger.info(f"Left scrolled type: {type(left_scrolled)}")
        
        # Get the existing listbox
        sheet_list = left_scrolled.get_child()
        if not sheet_list:
            logger.error("No sheet_list child!")
            return
            
        logger.info(f"Sheet list type: {type(sheet_list)}")
        
        # ScrolledWindow might have a Viewport, get through it
        if isinstance(sheet_list, Gtk.Viewport):
            logger.info("Found Viewport, getting its child...")
            sheet_list = sheet_list.get_child()
            if not sheet_list:
                logger.error("No child in Viewport!")
                return
            logger.info(f"Viewport child type: {type(sheet_list)}")
        
        if not isinstance(sheet_list, Gtk.ListBox):
            logger.error(f"Child is not ListBox, it's {type(sheet_list)}")
            return
        
        logger.info(f"Found ListBox, clearing and updating with {len(results)} results")
        
        # Clear the current list
        while True:
            row = sheet_list.get_row_at_index(0)
            if row is None:
                break
            sheet_list.remove(row)
        
        logger.info("List cleared")
        
        # Add filtered results
        if results:
            for i, sheet in enumerate(results):
                row = self._create_sheet_row(sheet)
                sheet_list.append(row)
                logger.info(f"  Added: {sheet.title}")
            
            logger.info("Selecting first result...")
            # Select first result
            first_row = sheet_list.get_row_at_index(0)
            if first_row:
                sheet_list.select_row(first_row)
                logger.info("First result selected")
        else:
            logger.info("No results, showing 'no results' message")
            # Show "no results" message
            no_results_row = Gtk.ListBoxRow()
            no_results_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            no_results_box.set_margin_start(12)
            no_results_box.set_margin_end(12)
            no_results_box.set_margin_top(24)
            no_results_box.set_margin_bottom(24)
            
            icon = Gtk.Image.new_from_icon_name("edit-find-symbolic")
            icon.set_pixel_size(48)
            icon.add_css_class("dim-label")
            no_results_box.append(icon)
            
            label = Gtk.Label(label="No results found")
            label.add_css_class("dim-label")
            no_results_box.append(label)
            
            no_results_row.set_child(no_results_box)
            no_results_row.set_activatable(False)
            sheet_list.append(no_results_row)
        
        logger.info("Search update complete")
    
    def _refresh_current_category(self):
        """Refresh the current category view after search is cleared."""
        current_page = self.notebook.get_current_page()
        if current_page == -1:
            return
        
        page_widget = self.notebook.get_nth_page(current_page)
        if not page_widget:
            return
        
        # Get the paned widget
        paned = page_widget.get_first_child()
        if not paned or not isinstance(paned, Gtk.Paned):
            return
        
        # Get the left scrolled window with the list
        left_scrolled = paned.get_start_child()
        if not left_scrolled:
            return
        
        # Get the existing listbox
        sheet_list = left_scrolled.get_child()
        
        # ScrolledWindow might have a Viewport, get through it
        if sheet_list and isinstance(sheet_list, Gtk.Viewport):
            sheet_list = sheet_list.get_child()
        
        if not sheet_list or not isinstance(sheet_list, Gtk.ListBox):
            return
        
        # Clear the current list
        while True:
            row = sheet_list.get_row_at_index(0)
            if row is None:
                break
            sheet_list.remove(row)
        
        # Reload sheets for current category
        if self.current_category:
            sheets = self.loader.get_sheets_by_category(self.current_category)
            for sheet in sheets:
                row = self._create_sheet_row(sheet)
                sheet_list.append(row)
    
    def _on_tab_switched(self, notebook: Gtk.Notebook, page: Gtk.Widget, page_num: int):
        """Handle tab switch to track current category."""
        # Update current category based on page number
        if page_num in self.category_map:
            self.current_category = self.category_map[page_num]
            logger.info(f"Switched to category: {self.current_category}")
            
            # Clear search when switching tabs
            if self.search_entry.get_text():
                self.search_entry.set_text("")
