python_mod = import('python')
python = python_mod.find_installation('python3', required: true)

pkg_sources = files(
  'ctf_helper/__init__.py',
  'ctf_helper/config.py',
  'ctf_helper/application.py',
  'ctf_helper/offline_guard.py',
  'ctf_helper/data_paths.py',
  'ctf_helper/db.py',
  'ctf_helper/logger.py',
  'ctf_helper/resources.py',
  'ctf_helper/dev_seed.py',
  'ctf_helper/notes/__init__.py',
  'ctf_helper/notes/manager.py',
  'ctf_helper/notes/editor.py',
  'ctf_helper/manager/__init__.py',
  'ctf_helper/manager/challenge_manager.py',
  'ctf_helper/manager/export_import.py',
  'ctf_helper/manager/models.py',
  'ctf_helper/modules/__init__.py',
  'ctf_helper/modules/base.py',
  'ctf_helper/modules/registry.py',
  'ctf_helper/modules/crypto/__init__.py',
  'ctf_helper/modules/crypto/hash_tools.py',
  'ctf_helper/modules/crypto/classic_ciphers.py',
  'ctf_helper/modules/forensics/__init__.py',
  'ctf_helper/modules/forensics/file_inspector.py',
  'ctf_helper/modules/reverse/__init__.py',
  'ctf_helper/modules/reverse/bin_analysis.py',
  'ctf_helper/modules/web/__init__.py',
  'ctf_helper/modules/web/offline_payloads.py',
  'ctf_helper/modules/misc/__init__.py',
  'ctf_helper/modules/misc/wordlist_generator.py'
)

resource_files = files(
  'ctf_helper/ui/__init__.py',
  'ctf_helper/ui/main_window.ui',
  'ctf_helper/ui/offline_link_dialog.ui',
  'ctf_helper/ui/style.css',
  'ctf_helper/templates/__init__.py',
  'ctf_helper/templates/builtins.json',
  'ctf_helper/help/__init__.py',
  'ctf_helper/help/getting_started.md',
  'ctf_helper/help/glossary.md'
)

python.install_sources(pkg_sources + resource_files, subdir: 'ctf_helper')
python.install_sources(config_module, subdir: 'ctf_helper')
python.install_sources(files('py.typed'), subdir: 'ctf_helper')

python.install_script('main.py', install_dir: get_option('bindir'), rename: 'ctf-helper')
