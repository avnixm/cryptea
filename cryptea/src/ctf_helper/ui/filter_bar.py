"""Filter and sort bar for challenge list."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk, GObject

if TYPE_CHECKING:
    pass


class FilterBar(Gtk.Box):
    """A filter and sort bar for challenges."""

    __gsignals__ = {
        "filter-changed": (GObject.SignalFlags.RUN_FIRST, None, ()),
    }

    def __init__(self) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.add_css_class("filter-bar")

        # Filter state
        self._category: Optional[str] = None
        self._difficulty: Optional[str] = None
        self._status: Optional[str] = None
        self._tags: List[str] = []
        self._favorites_only: bool = False
        self._sort_by: str = "updated"  # updated, created, title, difficulty, category
        self._sort_order: str = "desc"  # asc, desc

        self._build_ui()

    def _build_ui(self) -> None:
        """Build the filter bar UI."""
        # Main toolbar box
        toolbar_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        toolbar_box.set_margin_start(12)
        toolbar_box.set_margin_end(12)
        toolbar_box.set_margin_top(6)
        toolbar_box.set_margin_bottom(6)

        # Filter label
        filter_label = Gtk.Label(label="Filter:")
        filter_label.add_css_class("heading")
        toolbar_box.append(filter_label)

        # Category dropdown
        self.category_dropdown = Gtk.DropDown()
        categories = Gtk.StringList()
        categories.append("All Categories")
        categories.append("Crypto")
        categories.append("Web")
        categories.append("Forensics")
        categories.append("Reverse Engineering")
        categories.append("Pwn")
        categories.append("Misc")
        categories.append("OSINT")
        self.category_dropdown.set_model(categories)
        self.category_dropdown.set_selected(0)
        self.category_dropdown.connect("notify::selected", self._on_category_changed)
        toolbar_box.append(self.category_dropdown)

        # Difficulty dropdown
        self.difficulty_dropdown = Gtk.DropDown()
        difficulties = Gtk.StringList()
        difficulties.append("All Difficulties")
        difficulties.append("Easy")
        difficulties.append("Medium")
        difficulties.append("Hard")
        self.difficulty_dropdown.set_model(difficulties)
        self.difficulty_dropdown.set_selected(0)
        self.difficulty_dropdown.connect("notify::selected", self._on_difficulty_changed)
        toolbar_box.append(self.difficulty_dropdown)

        # Status dropdown
        self.status_dropdown = Gtk.DropDown()
        statuses = Gtk.StringList()
        statuses.append("All Statuses")
        statuses.append("Not Started")
        statuses.append("In Progress")
        statuses.append("Completed")
        self.status_dropdown.set_model(statuses)
        self.status_dropdown.set_selected(0)
        self.status_dropdown.connect("notify::selected", self._on_status_changed)
        toolbar_box.append(self.status_dropdown)

        # Favorites toggle
        self.favorites_toggle = Gtk.ToggleButton()
        self.favorites_toggle.set_icon_name("starred-symbolic")
        self.favorites_toggle.set_tooltip_text("Show favorites only")
        self.favorites_toggle.connect("toggled", self._on_favorites_toggled)
        toolbar_box.append(self.favorites_toggle)

        # Spacer
        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        toolbar_box.append(spacer)

        # Sort label
        sort_label = Gtk.Label(label="Sort:")
        sort_label.add_css_class("heading")
        toolbar_box.append(sort_label)

        # Sort by dropdown
        self.sort_dropdown = Gtk.DropDown()
        sort_options = Gtk.StringList()
        sort_options.append("Recently Updated")
        sort_options.append("Recently Created")
        sort_options.append("Title (A-Z)")
        sort_options.append("Difficulty")
        sort_options.append("Category")
        self.sort_dropdown.set_model(sort_options)
        self.sort_dropdown.set_selected(0)
        self.sort_dropdown.connect("notify::selected", self._on_sort_changed)
        toolbar_box.append(self.sort_dropdown)

        # Sort order button
        self.sort_order_button = Gtk.Button()
        self.sort_order_button.set_icon_name("view-sort-descending-symbolic")
        self.sort_order_button.set_tooltip_text("Sort order: Descending")
        self.sort_order_button.connect("clicked", self._on_sort_order_clicked)
        toolbar_box.append(self.sort_order_button)

        # Clear filters button
        self.clear_button = Gtk.Button()
        self.clear_button.set_icon_name("edit-clear-all-symbolic")
        self.clear_button.set_tooltip_text("Clear all filters")
        self.clear_button.connect("clicked", self._on_clear_clicked)
        self.clear_button.set_sensitive(False)
        toolbar_box.append(self.clear_button)

        self.append(toolbar_box)

        # Active filters chips box
        self.chips_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self.chips_box.set_margin_start(12)
        self.chips_box.set_margin_end(12)
        self.chips_box.set_margin_bottom(6)
        self.chips_revealer = Gtk.Revealer()
        self.chips_revealer.set_child(self.chips_box)
        self.chips_revealer.set_reveal_child(False)
        self.append(self.chips_revealer)

        # Separator
        separator = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
        self.append(separator)

    def _on_category_changed(self, dropdown: Gtk.DropDown, _param: GObject.ParamSpec) -> None:
        """Handle category filter change."""
        selected = dropdown.get_selected()
        if selected == 0:
            self._category = None
        else:
            model = dropdown.get_model()
            if model:
                self._category = model.get_string(selected)
        self._update_chips()
        self.emit("filter-changed")

    def _on_difficulty_changed(self, dropdown: Gtk.DropDown, _param: GObject.ParamSpec) -> None:
        """Handle difficulty filter change."""
        selected = dropdown.get_selected()
        if selected == 0:
            self._difficulty = None
        else:
            model = dropdown.get_model()
            if model:
                self._difficulty = model.get_string(selected)
        self._update_chips()
        self.emit("filter-changed")

    def _on_status_changed(self, dropdown: Gtk.DropDown, _param: GObject.ParamSpec) -> None:
        """Handle status filter change."""
        selected = dropdown.get_selected()
        if selected == 0:
            self._status = None
        else:
            model = dropdown.get_model()
            if model:
                self._status = model.get_string(selected)
        self._update_chips()
        self.emit("filter-changed")

    def _on_favorites_toggled(self, toggle: Gtk.ToggleButton) -> None:
        """Handle favorites toggle."""
        self._favorites_only = toggle.get_active()
        self._update_chips()
        self.emit("filter-changed")

    def _on_sort_changed(self, dropdown: Gtk.DropDown, _param: GObject.ParamSpec) -> None:
        """Handle sort option change."""
        selected = dropdown.get_selected()
        sort_map = {
            0: "updated",
            1: "created",
            2: "title",
            3: "difficulty",
            4: "category",
        }
        self._sort_by = sort_map.get(selected, "updated")
        self.emit("filter-changed")

    def _on_sort_order_clicked(self, _button: Gtk.Button) -> None:
        """Toggle sort order."""
        if self._sort_order == "desc":
            self._sort_order = "asc"
            self.sort_order_button.set_icon_name("view-sort-ascending-symbolic")
            self.sort_order_button.set_tooltip_text("Sort order: Ascending")
        else:
            self._sort_order = "desc"
            self.sort_order_button.set_icon_name("view-sort-descending-symbolic")
            self.sort_order_button.set_tooltip_text("Sort order: Descending")
        self.emit("filter-changed")

    def _on_clear_clicked(self, _button: Gtk.Button) -> None:
        """Clear all filters."""
        self.category_dropdown.set_selected(0)
        self.difficulty_dropdown.set_selected(0)
        self.status_dropdown.set_selected(0)
        self.favorites_toggle.set_active(False)
        self._tags = []
        self._update_chips()
        self.emit("filter-changed")

    def _update_chips(self) -> None:
        """Update active filter chips display."""
        # Clear existing chips
        child = self.chips_box.get_first_child()
        while child is not None:
            next_child = child.get_next_sibling()
            self.chips_box.remove(child)
            child = next_child

        has_filters = False

        # Add chips for active filters
        if self._category:
            chip = self._create_chip(f"Category: {self._category}", lambda: self._remove_category())
            self.chips_box.append(chip)
            has_filters = True

        if self._difficulty:
            chip = self._create_chip(f"Difficulty: {self._difficulty}", lambda: self._remove_difficulty())
            self.chips_box.append(chip)
            has_filters = True

        if self._status:
            chip = self._create_chip(f"Status: {self._status}", lambda: self._remove_status())
            self.chips_box.append(chip)
            has_filters = True

        if self._favorites_only:
            chip = self._create_chip("Favorites Only", lambda: self._remove_favorites())
            self.chips_box.append(chip)
            has_filters = True

        for tag in self._tags:
            chip = self._create_chip(f"Tag: {tag}", lambda t=tag: self._remove_tag(t))
            self.chips_box.append(chip)
            has_filters = True

        # Show/hide chips box
        self.chips_revealer.set_reveal_child(has_filters)
        self.clear_button.set_sensitive(has_filters)

    def _create_chip(self, label: str, on_remove: Callable[[], None]) -> Gtk.Box:
        """Create a filter chip."""
        chip = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        chip.add_css_class("filter-chip")

        chip_label = Gtk.Label(label=label)
        chip_label.add_css_class("caption")
        chip.append(chip_label)

        remove_button = Gtk.Button()
        remove_button.set_icon_name("window-close-symbolic")
        remove_button.add_css_class("flat")
        remove_button.add_css_class("circular")
        remove_button.connect("clicked", lambda _: on_remove())
        chip.append(remove_button)

        return chip

    def _remove_category(self) -> None:
        """Remove category filter."""
        self.category_dropdown.set_selected(0)

    def _remove_difficulty(self) -> None:
        """Remove difficulty filter."""
        self.difficulty_dropdown.set_selected(0)

    def _remove_status(self) -> None:
        """Remove status filter."""
        self.status_dropdown.set_selected(0)

    def _remove_favorites(self) -> None:
        """Remove favorites filter."""
        self.favorites_toggle.set_active(False)

    def _remove_tag(self, tag: str) -> None:
        """Remove a tag filter."""
        if tag in self._tags:
            self._tags.remove(tag)
            self._update_chips()
            self.emit("filter-changed")

    # Public API
    def get_filters(self) -> Dict[str, Any]:
        """Get current filter values."""
        return {
            "category": self._category,
            "difficulty": self._difficulty,
            "status": self._status,
            "tags": self._tags.copy(),
            "favorites_only": self._favorites_only,
            "sort_by": self._sort_by,
            "sort_order": self._sort_order,
        }

    def reset(self) -> None:
        """Reset all filters to default."""
        self._on_clear_clicked(None)
