project('ctf-helper-gnome', 'python',
  version: '0.1.0',
  license: 'GPL-3.0-or-later',
  meson_version: '>=0.64.0',
  default_options: ['warning_level=2'])

python_mod = import('python')
python = python_mod.find_installation('python3', required: true)

offline_opt = get_option('offline-build')
dev_profile_opt = get_option('dev-profile')

conf = configuration_data()
conf.set('OFFLINE_BUILD', offline_opt ? 'True' : 'False')
conf.set('DEV_PROFILE_ENABLED', dev_profile_opt ? 'True' : 'False')

config_module = configure_file(
  input: 'src/ctf_helper/config.py.in',
  output: 'build_config.py',
  configuration: conf
)

subdir('src')
subdir('data')
subdir('build-aux')

install_data('README.md', install_dir: join_paths(get_option('datadir'), 'doc', 'ctf-helper-gnome'))
