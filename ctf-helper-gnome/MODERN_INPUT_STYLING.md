# Modern GNOME Input Styling - Applied

## Summary

Applied modern GNOME design language to all input boxes with:
- **Rounded corners** (8px for text areas, 6px for entries)
- **Accent color borders** when focused (uses GNOME's @accent_bg_color)
- **Smooth transitions** (200ms cubic-bezier easing)
- **Proper theming** (integrates with GNOME color palette)

## CSS Classes Added

### 1. `.input-box` (ScrolledWindow for TextViews)
```css
scrolledwindow.input-box {
  border-radius: 8px;
  border: 1px solid alpha(@borders, 0.5);
  background-color: @view_bg_color;
  transition: all 200ms cubic-bezier(0.25, 0.46, 0.45, 0.94);
}

scrolledwindow.input-box:focus-within {
  border-color: @accent_bg_color;
  box-shadow: inset 0 0 0 1px @accent_bg_color;
  background-color: @view_bg_color;
}
```

**Effect:**
- Rounded corners container
- Subtle gray border when unfocused
- **Accent color border** (blue/purple depending on GNOME theme) when focused
- Smooth transition animation

### 2. `.input-text` (TextView content)
```css
textview.input-text {
  background: transparent;
  padding: 8px;
  font-family: "Source Code Pro", "Monospace", monospace;
  font-size: 10.5pt;
}
```

**Effect:**
- Monospace font for code/hash input
- Proper padding inside the box
- Transparent background (container handles styling)

### 3. `.modern-entry` (Entry fields)
```css
entry.modern-entry {
  border-radius: 6px;
  min-height: 32px;
  padding: 6px 10px;
  border: 1px solid alpha(@borders, 0.5);
  background-color: @view_bg_color;
  transition: all 200ms cubic-bezier(0.25, 0.46, 0.45, 0.94);
}

entry.modern-entry:focus {
  border-color: @accent_bg_color;
  box-shadow: inset 0 0 0 1px @accent_bg_color;
  background-color: @view_bg_color;
}
```

**Effect:**
- Rounded corners (6px, slightly less than text areas)
- Proper height and padding
- **Accent color border** when focused
- Smooth transitions

### 4. `.output-box` (Result displays)
```css
scrolledwindow.output-box {
  border-radius: 8px;
  border: 1px solid alpha(@borders, 0.3);
  background-color: alpha(@view_bg_color, 0.5);
}
```

**Effect:**
- Subtle rounded corners
- Lighter border (read-only appearance)
- Semi-transparent background

### 5. `.output-text` (Result content)
```css
textview.output-text {
  background: transparent;
  padding: 8px;
  font-family: "Source Code Pro", "Monospace", monospace;
  font-size: 10pt;
}
```

**Effect:**
- Monospace font for results
- Slightly smaller than input (10pt vs 10.5pt)

## Files Modified

### 1. `data/style.css`
- Added all new CSS classes for modern input styling
- Uses GNOME color variables (@accent_bg_color, @view_bg_color, @borders)
- Includes smooth transitions and focus states

### 2. `src/ctf_helper/application.py`
Applied CSS classes to widgets in:

**Decoder Workbench:**
- Input TextView: `input-text` + ScrolledWindow: `input-box`
- Operations Entry: `modern-entry`
- Output TextView: `output-text` + ScrolledWindow: `output-box`

**Hash Suite - Identify Tab:**
- Hash input TextView: `input-text` + ScrolledWindow: `input-box`
- File path Entry: `modern-entry`
- Results TextView: `output-text` + ScrolledWindow: `output-box`

**Hash Suite - Verify Tab:**
- Hash Entry: `modern-entry`
- Plaintext Entry: `modern-entry`

**Hash Suite - Generate Tab:**
- Input TextView: `input-text` + ScrolledWindow: `input-box`

## Visual Behavior

### Before (Default GTK)
```
┌─────────────────────────────────────┐
│ Text input                          │  <- Sharp corners
│                                     │  <- No focus indicator
└─────────────────────────────────────┘
```

### After (Modern GNOME)
```
╭─────────────────────────────────────╮
│ Text input                          │  <- Rounded corners
│                                     │  <- Subtle border
╰─────────────────────────────────────╯

When focused:
╭═════════════════════════════════════╮  <- Accent color border
║ Text input▊                         ║  <- Active appearance
║                                     ║  <- Inset shadow
╰═════════════════════════════════════╯
```

## GNOME Theme Integration

The styling uses GNOME's semantic color variables:

- **@accent_bg_color** - Primary accent (blue in Adwaita, varies by theme)
- **@view_bg_color** - Background for input fields
- **@borders** - Standard border color

This means:
- ✅ Works with **all GNOME themes** (Adwaita, Adwaita Dark, custom themes)
- ✅ Respects user's **accent color** choice
- ✅ Adapts to **light/dark** mode automatically
- ✅ Follows **GNOME HIG** (Human Interface Guidelines)

## Examples

### Decoder Workbench
```
Input data: [Rounded text box with accent border when focused]
Operations: [Rounded entry with modern styling]
Result:     [Subtle rounded output box]
```

### Hash Suite
```
Hash value(s): [Rounded text area, accent color when typing]
File path:     [Rounded entry, accent color when focused]
Results:       [Subtle output styling]
```

## Testing

**To see the new styling:**
1. Restart the application: `python run.py`
2. Open **Decoder Workbench**
3. Click in the "Input data" box
4. **Notice:**
   - Rounded corners (8px radius)
   - Accent color border appears (blue/purple)
   - Smooth transition animation
   - Monospace font
5. Try typing - border stays highlighted
6. Click outside - border returns to subtle gray
7. Try the Operations entry - same modern styling with 6px radius

**Compare with other tools:**
- Other tools still use default styling (for now)
- Decoder Workbench and Hash Suite showcase the new design

## Benefits

### User Experience
- ✅ **Visual hierarchy** - Clear focus indicators
- ✅ **Modern appearance** - Matches GNOME 40+ design
- ✅ **Better feedback** - Users know which field is active
- ✅ **Consistency** - All input fields styled the same

### Technical
- ✅ **Theme-aware** - Works with any GNOME theme
- ✅ **Accessible** - High contrast focus indicators
- ✅ **Performant** - CSS transitions are GPU-accelerated
- ✅ **Maintainable** - Simple CSS classes, easy to extend

## Future Enhancements

**Can be applied to:**
- [ ] All other tool input fields (RSA, Caesar, XOR, etc.)
- [ ] Search boxes
- [ ] Challenge note editors
- [ ] Settings dialogs
- [ ] Any other Entry or TextView widgets

**Just add the CSS classes:**
```python
# For TextView:
text_view.add_css_class("input-text")
scroll_window.add_css_class("input-box")

# For Entry:
entry.add_css_class("modern-entry")
```

## Design Philosophy

This styling follows GNOME's modern design principles:

1. **Clarity** - Clear visual states (unfocused, focused)
2. **Simplicity** - Minimal, elegant design
3. **Consistency** - Same patterns throughout the app
4. **Accessibility** - High contrast, clear focus indicators
5. **Beauty** - Smooth animations, proper spacing

The accent color border on focus is a key GNOME 40+ pattern seen in:
- GNOME Settings
- GNOME Text Editor
- GNOME Calendar
- Files (Nautilus)

Now your CTF Helper app follows the same design language!

---

**Status:** ✅ Complete  
**Date:** October 4, 2025  
**Impact:** Enhanced visual design for Decoder Workbench and Hash Suite  
**Next:** Can be rolled out to all other tools as needed
