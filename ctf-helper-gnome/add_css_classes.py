#!/usr/bin/env python3
"""
Script to automatically add CSS classes to all TextView and Entry widgets
in the application.py file for modern GNOME styling.
"""

import re

# Read the application.py file
with open('src/ctf_helper/application.py', 'r') as f:
    content = f.read()

modifications_made = 0

# Find all ScrolledWindow creations and add CSS class
# Pattern: ANY_VAR = Gtk.ScrolledWindow() followed by ANY_VAR.set_child(self.TEXTVIEW)
scrolled_pattern = r'(        )(\w+) = Gtk\.ScrolledWindow\(\)\n((?:        (?!        \2\.set_child).*\n)*?)(        \2\.set_child\(self\.(\w+)\))'

def add_scrolled_class(match):
    global modifications_made
    indent = match.group(1)
    scroll_var = match.group(2)
    middle_lines = match.group(3)
    set_child_line = match.group(4)
    widget_name = match.group(5)
    
    # Skip if already has add_css_class
    if 'add_css_class' in middle_lines:
        return match.group(0)
    
    # Determine if it's input or output
    if '_input' in widget_name or widget_name.endswith('_input_view'):
        css_class = 'input-box'
    else:
        css_class = 'output-box'
    
    modifications_made += 1
    return f'{indent}{scroll_var} = Gtk.ScrolledWindow()\n{indent}{scroll_var}.add_css_class("{css_class}")\n{middle_lines}{set_child_line}'

content = re.sub(scrolled_pattern, add_scrolled_class, content)

# Write the modified content back
with open('src/ctf_helper/application.py', 'w') as f:
    f.write(content)

print(f"✅ Successfully added CSS classes to {modifications_made} ScrolledWindow widgets!")
print("Restart the application to see the rounded corners on all result boxes.")
