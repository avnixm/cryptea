#!/usr/bin/env python3
"""Generate src/meson.build from actual Python files in the project."""

from pathlib import Path

def find_python_files(base_path):
    """Find all Python files recursively."""
    files = []
    for py_file in sorted(base_path.rglob('*.py')):
        if '__pycache__' not in str(py_file):
            # Get relative path from ctf_helper directory
            rel_path = py_file.relative_to(base_path)
            files.append(str(rel_path))
    return files

def find_resource_files(base_path):
    """Find non-Python resource files."""
    resources = []
    patterns = ['*.ui', '*.css', '*.json', '*.md', '*.svg', 'py.typed']
    
    for pattern in patterns:
        for res_file in sorted(base_path.rglob(pattern)):
            if '__pycache__' not in str(res_file):
                # Get relative path from ctf_helper directory
                rel_path = res_file.relative_to(base_path)
                resources.append(str(rel_path))
    return resources

def generate_meson_build():
    """Generate the meson.build content."""
    src_path = Path(__file__).parent / 'src'
    ctf_helper_path = src_path / 'ctf_helper'
    
    py_files = find_python_files(ctf_helper_path)
    resource_files = find_resource_files(ctf_helper_path)
    
    content = """python_mod = import('python')
python = python_mod.find_installation('python3', required: true)

# Python source files
pkg_sources = files(
"""
    
    for f in py_files:
        content += f"  'ctf_helper/{f}',\n"
    
    content += """)\n
# Resource files (UI, CSS, JSON, etc.)
resource_files = files(
"""
    
    for f in resource_files:
        content += f"  'ctf_helper/{f}',\n"
    
    content += """)

# Install Python packages
python.install_sources(pkg_sources, subdir: 'ctf_helper')

# Install resource files
if resource_files.length() > 0
  python.install_sources(resource_files, subdir: 'ctf_helper')
endif

# Install config module generated from config.py.in
python.install_sources(config_module, subdir: 'ctf_helper')

# Install main.py as ctf-helper executable
install_data('main.py',
  install_dir: get_option('bindir'),
  install_mode: 'rwxr-xr-x',
  rename: 'ctf-helper')
"""
    
    return content

if __name__ == '__main__':
    content = generate_meson_build()
    output_file = Path(__file__).parent / 'src' / 'meson.build'
    
    print(f"Generating {output_file}...")
    output_file.write_text(content)
    print("Done!")
    print(f"\nGenerated meson.build with:")
    print(f"  - Python files found")
    print(f"  - Resource files found")
