# GNOME CTF Helper (Offline Edition)

GNOME CTF Helper is a 100% offline desktop companion for Capture the Flag training. It ships challenge management, Markdown note taking, offline tool modules, and bundled documentation without ever touching the network.

## Features

- **Offline-first**: No network sockets, analytics, or update checks.
- **Challenge tracker** with SQLite storage under `~/.local/share/ctf-helper/`.
- **Markdown notes** with live preview and autosave snapshots.
- **Local tooling** for crypto, forensics, reverse engineering, and web exploitation drills.
- **Export/Import** via `.ctfpack` archives for air-gapped transfers.
- **Bundled docs and templates** stored locally and rendered in-app.

## Repository Layout

```
src/                  Application sources (PyGObject + Libadwaita)
data/                 Installable assets (desktop file, help, templates)
build-aux/            Flatpak manifest and vendored wheels placeholder
tests/                Offline unit tests and fixtures
```

## Running from Source

Ensure Python 3.11+, GTK4, Libadwaita, and PyGObject are installed locally. Then:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --no-index --find-links=build-aux/python-deps markdown2 PyNaCl cryptography
python3 src/main.py
```

Set `OFFLINE_BUILD=1` in your environment to enable additional runtime checks when running from source (the default).

## Building with Meson

```bash
meson setup builddir -Doffline-build=true
meson compile -C builddir
meson install -C builddir --destdir=dist
```

The Meson build generates `ctf_helper/build_config.py` to freeze the offline posture at build time.

## Flatpak Packaging

1. Download wheel files for the required Python packages and place them in `build-aux/python-deps/`.
2. Build the Flatpak app bundle:

```bash
flatpak-builder --force-clean builddir build-aux/org.example.CTFHelper.Devel.json --install-deps-from=flathub --user
```

The manifest **does not grant network permissions** and mounts only:

- `--socket=wayland`
- `--filesystem=xdg-data/ctf-helper:rw`
- `--filesystem=xdg-documents:rw`

## Air-Gapped Installation

1. Build the Flatpak bundle on a trusted machine.
2. Export the repository:

```bash
flatpak build-bundle builddir ctf-helper.flatpak org.example.CTFHelper
```

3. Transfer the `.flatpak` file via removable media and install it offline:

```bash
flatpak install --user ctf-helper.flatpak
```

## Offline QA Checklist

- Disconnect all networking hardware and launch the app.
- Confirm challenge creation, note editing, flag storage, and exports succeed.
- Open the Tools tab and run each offline module.
- Verify the help tab renders bundled Markdown.
- Inspect `~/.local/share/ctf-helper/logs/` for runtime logs (copy manually if needed).

## Development Fixtures

Enable the Meson option `-Ddev-profile=true` (or set `DEV_PROFILE_ENABLED=1`) to seed sample challenges for UI testing. Test assets live under `tests/assets/`.

## License

GPL-3.0-or-later.
