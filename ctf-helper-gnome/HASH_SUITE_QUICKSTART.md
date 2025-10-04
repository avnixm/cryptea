# Hash Suite - Quick Integration Guide

## ✅ Phase 1: Backend (COMPLETE)

- [x] Created `hash_suite.py` with unified HashSuite class
- [x] Updated registry to use single Hash Suite tool
- [x] Removed 7 duplicate hash tool registrations
- [x] Tested registry loading

## ⏳ Phase 2: UI Integration (TODO)

### Step 1: Update Tool Handler Mapping

**File:** `src/ctf_helper/application.py` (~line 1210)

**Remove these handlers:**
```python
"hash digest": self._open_hash_digest,
"hash workspace": self._open_hash_workspace,
"hash cracker pro": self._open_hash_cracker,
"hash benchmark": self._open_hash_benchmark,
"hash format converter": self._open_hash_format_converter,
"hashcat/john builder": self._open_hashcat_builder,
"htpasswd generator": self._open_htpasswd_generator,
```

**Add single handler:**
```python
"hash suite": self._open_hash_suite,
```

### Step 2: Remove Old UI Build Methods

**File:** `src/ctf_helper/application.py` (various locations)

**Delete these methods:**
- `_build_hash_digest_detail()`
- `_build_hash_workspace_detail()`
- `_build_hash_cracker_detail()`
- `_build_hash_benchmark_detail()`
- `_build_hash_format_converter_detail()`
- `_build_hashcat_builder_detail()`
- `_build_htpasswd_generator_detail()`
- All associated `_open_*` and `_on_*` handlers

### Step 3: Remove Old UI Page Registrations

**File:** `src/ctf_helper/application.py` (~lines 505-550)

**Remove these page additions:**
```python
hash_box = Gtk.Box(...)
self._build_hash_digest_detail(hash_box)
self.tool_detail_stack.add_named(hash_box, "hash_digest")
# ...and all other hash tool pages
```

### Step 4: Add Hash Suite UI

**File:** `src/ctf_helper/application.py`

**Add page registration (~line 505):**
```python
# Hash Suite page (consolidated all hash tools)
hash_suite_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
self._build_hash_suite_detail(hash_suite_box)
self.tool_detail_stack.add_named(hash_suite_box, "hash_suite")
```

**Add build method (new section):**
```python
def _build_hash_suite_detail(self, root: Gtk.Box) -> None:
    """Build unified Hash Suite UI with tabs."""
    
    # Header with back button and advanced mode toggle
    header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    header.set_margin_top(16)
    header.set_margin_start(16)
    header.set_margin_end(16)
    
    back_btn = Gtk.Button.new_from_icon_name("go-previous-symbolic")
    back_btn.set_tooltip_text("Back to tools")
    back_btn.connect("clicked", lambda *_: self._navigate_back_to_tools())
    header.append(back_btn)
    
    title = Gtk.Label(label="Hash Suite", xalign=0, hexpand=True)
    title.add_css_class("title-2")
    header.append(title)
    
    # Advanced mode toggle
    self.hash_suite_advanced_switch = Gtk.Switch()
    self.hash_suite_advanced_switch.set_tooltip_text(
        "Show advanced backend options (Hashcat/John). Use with care."
    )
    advanced_label = Gtk.Label(label="Advanced Mode")
    advanced_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    advanced_box.append(advanced_label)
    advanced_box.append(self.hash_suite_advanced_switch)
    header.append(advanced_box)
    
    root.append(header)
    
    # Preset selector
    preset_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    preset_bar.set_margin_start(16)
    preset_bar.set_margin_end(16)
    preset_bar.set_margin_top(8)
    
    preset_label = Gtk.Label(label="Quick Preset:")
    preset_bar.append(preset_label)
    
    self.hash_suite_preset_combo = Gtk.ComboBoxText()
    self.hash_suite_preset_combo.append("ctf_quick", "CTF Quick")
    self.hash_suite_preset_combo.append("forensics", "Forensics")
    self.hash_suite_preset_combo.append("debugging", "Debugging")
    self.hash_suite_preset_combo.set_active(0)
    preset_bar.append(self.hash_suite_preset_combo)
    
    root.append(preset_bar)
    
    # Tab view
    self.hash_suite_tab_view = Adw.TabView()
    self.hash_suite_tab_bar = Adw.TabBar()
    self.hash_suite_tab_bar.set_view(self.hash_suite_tab_view)
    
    root.append(self.hash_suite_tab_bar)
    root.append(self.hash_suite_tab_view)
    
    # Create tabs
    self._build_hash_suite_identify_tab()
    self._build_hash_suite_verify_tab()
    self._build_hash_suite_crack_tab()
    self._build_hash_suite_format_tab()
    self._build_hash_suite_generate_tab()
    self._build_hash_suite_benchmark_tab()
    self._build_hash_suite_queue_tab()
```

### Step 5: Implement Tab Build Methods

Each tab needs a build method like:

```python
def _build_hash_suite_identify_tab(self) -> None:
    """Build Identify tab."""
    page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
    page.set_margin_top(16)
    page.set_margin_bottom(16)
    page.set_margin_start(16)
    page.set_margin_end(16)
    
    # Add widgets for hash identification
    # Input area, results display, quick action buttons
    
    tab_page = self.hash_suite_tab_view.append(page)
    tab_page.set_title("Identify")
    tab_page.set_icon(Gio.ThemedIcon.new("dialog-question-symbolic"))
```

### Step 6: Add Handler Methods

```python
def _open_hash_suite(self, tool) -> None:
    """Open Hash Suite."""
    self._active_tool = tool
    self.tool_detail_stack.set_visible_child_name("hash_suite")
    self.content_stack.set_visible_child_name("tool_detail")

def _on_hash_suite_identify_run(self, _btn: Gtk.Button) -> None:
    """Run identification."""
    if not getattr(self, "_active_tool", None):
        return
    
    hash_input = self.hash_suite_identify_entry.get_text().strip()
    if not hash_input:
        self.toast_overlay.add_toast(Adw.Toast.new("Enter a hash first"))
        return
    
    try:
        result = self._active_tool.run(tab="identify", hash_input=hash_input)
        # Display results
    except Exception as exc:
        self.toast_overlay.add_toast(Adw.Toast.new(f"Error: {exc}"))
```

### Step 7: Add Legal Warning Modal

```python
def _show_hash_suite_legal_warning(self, callback):
    """Show legal warning before heavy operations."""
    dialog = Adw.MessageDialog.new(self.window)
    dialog.set_heading("Authorized Use Only")
    dialog.set_body(
        "Only test passwords/hashes you own or are authorized to test. "
        "Misuse may be illegal. Continue?"
    )
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("continue", "I Understand & Continue")
    dialog.set_response_appearance("continue", Adw.ResponseAppearance.DESTRUCTIVE)
    dialog.connect("response", lambda d, r: callback() if r == "continue" else None)
    dialog.present()
```

### Step 8: Add Keyboard Shortcut

**File:** `src/ctf_helper/application.py` (keyboard handler section)

```python
def _setup_keyboard_shortcuts(self):
    # ... existing shortcuts ...
    
    # Ctrl+Shift+H to open Hash Suite
    self.create_action(
        "open-hash-suite",
        lambda *_: self._quick_open_hash_suite(),
        ["<Ctrl><Shift>h"]
    )

def _quick_open_hash_suite(self):
    """Quick keyboard shortcut to open Hash Suite."""
    tool = self.registry.find("Hash Suite")
    self._open_hash_suite(tool)
```

## Testing Checklist

After implementing Phase 2:

- [ ] Hash Suite appears in sidebar (no other hash tools)
- [ ] Clicking Hash Suite opens tabbed interface
- [ ] All 7 tabs are accessible
- [ ] Tab content displays correctly
- [ ] Advanced mode toggle shows/hides advanced options
- [ ] Preset selector changes settings
- [ ] Run buttons execute operations
- [ ] Results display in UI
- [ ] Legal warning appears on first crack job
- [ ] Ctrl+Shift+H shortcut works
- [ ] Export buttons function

## Quick Test Commands

```bash
# Test registry
python -c "from src.ctf_helper.modules.registry import ModuleRegistry; r = ModuleRegistry(); print([t.name for t in r.tools() if 'hash' in t.name.lower()])"

# Test Hash Suite backend
python -c "from src.ctf_helper.modules.crypto.hash_suite import HashSuite; hs = HashSuite(); print(hs.run(tab='identify', hash_input='5d41402abc4b2a76b9719d911017c592'))"

# Run app
python run.py
```

## Migration Path for Existing Code

If you have existing tests or code using old hash tools:

**Old:**
```python
from ctf_helper.modules.crypto.hash_tools import HashWorkspaceTool
result = HashWorkspaceTool().run(hashes="abc123", mode="identify")
```

**New:**
```python
from ctf_helper.modules.crypto.hash_suite import HashSuite
result = HashSuite().run(tab="identify", hash_input="abc123")
```

## Notes

- The backend is fully functional and tested
- UI integration is straightforward but requires ~500-800 lines of code
- Each tab can be implemented incrementally
- Advanced features can be gated behind the toggle
- All old functionality is preserved in the new Hash Suite

---

**Ready to implement?** Start with Step 1 (handler mapping) and work through each step sequentially.
