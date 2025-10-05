# Cheat Sheet UI Fix - Testing Guide

## Quick Start Testing

### 1. Launch the Application
```bash
cd /home/avnixm/Documents/cryptea/cryptea
./run.py
```

### 2. Navigate to Cheat Sheets
- Click on the **"Resources"** or **"Cheat Sheets"** tab in the main navigation
- You should see category tabs: **Crypto**, **Forensics**, **Web**, **Binary**, **OSINT**, etc.

### 3. Open a Code-Heavy Cheat Sheet
- Click the **"Crypto"** tab
- Select **"Caesar Cipher & ROT13"** from the left sidebar
- This cheat sheet has multiple long code examples - perfect for testing

## Detailed Test Cases

### ✅ Test Case 1: No Horizontal Scrolling
**Objective**: Verify code blocks don't create horizontal scrollbars

**Steps**:
1. Open "Caesar Cipher & ROT13" cheat sheet
2. Scroll down to "Caesar Cipher Brute Force" entry
3. Look at the code example with the long Python heredoc

**Expected Result**:
- ✅ No horizontal scrollbar appears
- ✅ Long lines wrap at the edge of the container
- ✅ Monospace font is preserved
- ✅ Code remains readable despite wrapping

**Failure Indicators**:
- ❌ Horizontal scrollbar appears
- ❌ Text overflows the container
- ❌ Font changes to proportional

---

### ✅ Test Case 2: Word Wrapping Behavior
**Objective**: Verify intelligent word wrapping at appropriate boundaries

**Steps**:
1. Find a code block with natural word boundaries (bash commands)
2. Find a code block with very long tokens (URLs, hashes)

**Expected Result**:
- ✅ Commands wrap at spaces when possible
- ✅ Long tokens break mid-character when necessary
- ✅ No text is hidden or truncated
- ✅ Wrapped lines maintain left indentation

**Examples to Check**:
- Bash commands: Should break at pipe `|` or semicolon `;`
- Python strings: Should break at appropriate points
- Long URLs: Should break character-by-character if needed

---

### ✅ Test Case 3: Vertical Scrolling (Long Content)
**Objective**: Verify vertical scrolling activates for content > 600px

**Steps**:
1. Open "Caesar Cipher & ROT13"
2. View the "Caesar Cipher Brute Force" entry (has ~50 lines of code)

**Expected Result**:
- ✅ Code block shows ~20-25 lines initially
- ✅ Vertical scrollbar appears on the right side
- ✅ Scrolling is smooth and responsive
- ✅ No horizontal scrollbar at any scroll position

**Measurement**:
- Code blocks should max out at approximately 600px height
- Use browser DevTools or screen ruler to verify

---

### ✅ Test Case 4: Short Code Snippets
**Objective**: Verify minimal height for small code blocks

**Steps**:
1. Find a cheat sheet with short examples (1-3 lines)
2. Check "ROT13 Quick Decode" section

**Expected Result**:
- ✅ Code block is compact (no excessive white space)
- ✅ Height matches content (no 600px empty box)
- ✅ Minimum height is ~100px for readability
- ✅ Copy button is still easily accessible

---

### ✅ Test Case 5: Window Resize Responsiveness
**Objective**: Verify layout adapts to window size changes

**Steps**:
1. Open "Caesar Cipher & ROT13" cheat sheet
2. Resize window from 800px wide to 1920px wide
3. Also test narrow widths (600px, 400px if supported)

**Expected Result**:
- ✅ Code blocks expand/contract smoothly
- ✅ Word wrapping adjusts to new width
- ✅ No horizontal scrollbars at any width
- ✅ Text remains readable at all sizes
- ✅ No layout "jumping" or flickering

**Specific Checks**:
- **Narrow (800px)**: More lines due to wrapping
- **Wide (1920px)**: Fewer lines, longer per line
- **Very narrow (<600px)**: Still functional, heavy wrapping

---

### ✅ Test Case 6: Tab Switching
**Objective**: Verify consistent behavior across all categories

**Steps**:
1. Open "Caesar Cipher & ROT13" (Crypto tab)
2. Switch to **Forensics** tab → open any cheat sheet with code
3. Switch to **Web** tab → open "XSS Vectors"
4. Switch back to **Crypto** tab

**Expected Result**:
- ✅ Each category renders code blocks identically
- ✅ No horizontal scrollbars in any category
- ✅ Layout is consistent across tabs
- ✅ Previous selection is maintained when returning to a tab

---

### ✅ Test Case 7: Copy-to-Clipboard Functionality
**Objective**: Verify copy button still works after changes

**Steps**:
1. Open any cheat sheet with code examples
2. Click the **copy button** (clipboard icon) in a code block header
3. Paste the clipboard contents into a text editor

**Expected Result**:
- ✅ Button changes to checkmark icon briefly
- ✅ Clipboard contains the full code (unmodified)
- ✅ Line breaks are preserved correctly
- ✅ No extra formatting is added

**Test with**:
- Multi-line bash scripts
- Python heredocs
- Long single-line commands

---

### ✅ Test Case 8: Multiple Code Blocks
**Objective**: Verify consistent rendering of multiple examples

**Steps**:
1. Open "Frequency Analysis Detection" entry
2. Scroll through all code examples

**Expected Result**:
- ✅ All code blocks have same width
- ✅ Vertical spacing is uniform (32px between entries)
- ✅ Each block can scroll independently
- ✅ No overlapping or misalignment

---

### ✅ Test Case 9: Mixed Content Entries
**Objective**: Verify layout with text + code + hints

**Steps**:
1. Open "ROT13 Quick Decode" entry
2. Check the combination of:
   - Title (bold)
   - Description (gray text)
   - Code block
   - Flag hint (blue info box)

**Expected Result**:
- ✅ Proper spacing between elements
- ✅ Hint box doesn't overlap code
- ✅ All text is readable
- ✅ Icon alignment is correct

---

### ✅ Test Case 10: Theme Consistency
**Objective**: Verify appearance matches Cryptea's dark theme

**Steps**:
1. Open any cheat sheet
2. Compare code block styling with other UI elements

**Expected Result**:
- ✅ Background color matches theme (semi-transparent)
- ✅ Text color is white/light gray
- ✅ Borders are subtle (alpha-blended)
- ✅ Monospace font (Source Code Pro or fallback)
- ✅ Rounded corners (12px outer, 10px inner)

**If light theme exists**:
- Test switching themes
- Verify colors adapt appropriately

---

## Edge Case Testing

### 🧪 Edge Case 1: Extremely Long Lines
**Test**: Code with 200+ character lines (hash strings, Base64)

**Expected**: 
- Should wrap character-by-character
- No horizontal overflow
- Still readable (though wrapped)

---

### 🧪 Edge Case 2: Tabs and Indentation
**Test**: Python code with heavy indentation

**Expected**:
- Indentation is preserved
- Wrapping respects indent level
- Code structure remains clear

---

### 🧪 Edge Case 3: Special Characters
**Test**: Code with Unicode, emoji, or special symbols

**Expected**:
- All characters render correctly
- No character corruption
- Wrapping handles multi-byte characters

---

### 🧪 Edge Case 4: Empty Code Blocks
**Test**: Cheat sheet with empty `"example": ""`

**Expected**:
- Shows placeholder or minimal height
- No broken layout
- No JavaScript errors

---

## Performance Testing

### ⚡ Performance Check 1: Scroll Performance
1. Open cheat sheet with 10+ entries
2. Rapidly scroll up and down

**Expected**: 
- Smooth 60fps scrolling
- No lag or stuttering
- Instant response to scroll wheel

---

### ⚡ Performance Check 2: Tab Switch Speed
1. Rapidly switch between category tabs

**Expected**:
- Instant tab switching (<100ms)
- No loading delay
- Smooth transitions

---

### ⚡ Performance Check 3: Window Resize Performance
1. Rapidly resize window

**Expected**:
- Layout updates smoothly
- No visible reflow lag
- Text wrapping recalculates instantly

---

## Accessibility Testing

### ♿ Keyboard Navigation
1. Use **Tab** key to navigate through UI
2. Use **Arrow keys** in code blocks

**Expected**:
- Focus indicators visible
- All elements reachable by keyboard
- Scrolling works with arrow keys

---

### ♿ Screen Reader Compatibility
1. Enable screen reader (Orca on Linux)
2. Navigate through cheat sheet

**Expected**:
- Code is announced as "code block"
- Content is readable in order
- Copy button is announced

---

### ♿ High Contrast Mode
1. Enable high contrast theme
2. Check code block visibility

**Expected**:
- Text remains readable
- Borders are visible
- Sufficient contrast ratio (4.5:1 minimum)

---

## Regression Testing

### 🔄 Test Unchanged Features
Verify these features still work:

- ✅ Search bar filters cheat sheets
- ✅ Sidebar navigation
- ✅ Empty state when no sheet selected
- ✅ Category badges display correctly
- ✅ Markdown formatting in descriptions
- ✅ Link clicking (if any links present)

---

## Bug Report Template

If you find issues, report using this format:

```markdown
## Bug: [Short Description]

**Severity**: Critical / High / Medium / Low

**Steps to Reproduce**:
1. Open Cryptea
2. Navigate to [category]
3. Select [cheat sheet]
4. [Specific action]

**Expected Behavior**:
[What should happen]

**Actual Behavior**:
[What actually happens]

**Screenshots**:
[Attach screenshots if possible]

**Environment**:
- OS: [Ubuntu 22.04 / Fedora 38 / etc.]
- GTK Version: [4.x.x]
- Screen Size: [1920x1080]
- Display Scale: [100% / 125% / 150%]

**Additional Context**:
[Any other relevant information]
```

---

## Success Criteria

All tests pass if:

1. ✅ **No horizontal scrollbars** appear in any code block
2. ✅ **All text is readable** without manual scrolling
3. ✅ **Word wrapping** works intelligently
4. ✅ **Responsive layout** adapts to window size
5. ✅ **Performance** is smooth (60fps)
6. ✅ **Theme consistency** maintained
7. ✅ **Copy functionality** works correctly
8. ✅ **No regressions** in existing features

---

## Automated Testing (Future)

Consider adding these automated tests:

```python
# tests/test_cheatsheet_ui.py

def test_no_horizontal_scroll():
    """Verify ScrolledWindow has NEVER policy for horizontal"""
    panel = CheatSheetPanel()
    # Find code block ScrolledWindow
    assert scrolled.get_policy()[0] == Gtk.PolicyType.NEVER

def test_word_wrap_enabled():
    """Verify TextView has WORD_CHAR wrap mode"""
    panel = CheatSheetPanel()
    # Find TextView in code block
    assert text_view.get_wrap_mode() == Gtk.WrapMode.WORD_CHAR

def test_expansion_properties():
    """Verify widgets have proper expansion settings"""
    panel = CheatSheetPanel()
    assert text_view.get_hexpand() == True
    assert scrolled.get_hexpand() == True
```

---

## Contact

For questions or issues with testing:
- Check `CHEATSHEET_FIX_SUMMARY.md` for implementation details
- Review git commit history for change rationale
- Open an issue on the project repository

---

**Happy Testing! 🚀**
