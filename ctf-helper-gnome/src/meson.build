python_mod = import('python')
python = python_mod.find_installation('python3', required: true)

# Install the entire ctf_helper package tree
install_subdir('ctf_helper',
  install_dir: python.get_install_dir(),
  exclude_files: ['__pycache__'],
  exclude_directories: ['__pycache__'])

# Install config module generated from config.py.in
python.install_sources(config_module, subdir: 'ctf_helper')

# Install main.py as ctf-helper executable
install_data('main.py',
  install_dir: get_option('bindir'),
  install_mode: 'rwxr-xr-x',
  rename: 'ctf-helper')
