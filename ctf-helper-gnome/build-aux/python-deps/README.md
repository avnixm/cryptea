# Offline Python Wheels

Place pre-downloaded wheels for the following packages in this directory before building the Flatpak:

- markdown2
- PyNaCl
- cryptography
- pygobject (provided by the runtime)

The build manifest installs packages using `pip3 --no-index --find-links=python-deps` to comply with the offline policy.
