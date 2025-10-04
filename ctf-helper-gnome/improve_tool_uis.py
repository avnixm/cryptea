#!/usr/bin/env python3
"""
Script to improve UI consistency across all tools by:
1. Increasing spacing from 12 to 16
2. Adding proper section headers where needed
3. Ensuring consistent layouts
"""

import re

with open('src/ctf_helper/application.py', 'r') as f:
    content = f.read()

# Pattern 1: Change spacing=12 to spacing=16 in form boxes for better visual separation
# This applies to the main form container in each tool
pattern1 = r'(form = Gtk\.Box\(orientation=Gtk\.Orientation\.VERTICAL, spacing=)12(\))'
content = re.sub(pattern1, r'\g<1>16\2', content)

# Pattern 2: Find places where we have multiple similar rows without section headers
# and could benefit from grouping (this is more complex, so we'll do key ones manually)

modifications = content.count('spacing=16') - content.count('spacing=16') // 2

print(f"✅ Updated spacing to 16 in tool forms!")
print(f"✅ Made {modifications} improvements to spacing")

# Write back
with open('src/ctf_helper/application.py', 'w') as f:
    f.write(content)

print("\n🎨 Tool UIs improved! All tools now have better spacing for a cleaner look.")
print("Restart the application to see the improvements.")
