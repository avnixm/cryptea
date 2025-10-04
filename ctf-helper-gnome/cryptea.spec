Name:           cryptea
Version:        0.1.0
Release:        1%{?dist}
Summary:        Offline-first toolbox for Capture the Flag exercises

License:        GPL-3.0-or-later
URL:            https://github.com/avnixm/cryptea
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  meson >= 0.64.0
BuildRequires:  python3-devel >= 3.11
BuildRequires:  python3-gobject
BuildRequires:  gtk4-devel
BuildRequires:  libadwaita-devel
BuildRequires:  desktop-file-utils
BuildRequires:  appstream

Requires:       python3 >= 3.11
Requires:       python3-gobject
Requires:       gtk4
Requires:       libadwaita
Requires:       python3-cryptography
Requires:       python3-pycryptodome
Requires:       python3-markdown2
Requires:       python3-pynacl

%description
Cryptea is an offline-first GTK4/Libadwaita application designed for
Capture the Flag (CTF) exercises and security research. It provides
40+ tools across 6 categories including cryptography, forensics,
reverse engineering, web exploitation, and more.

Features:
- Challenge management with favorites and notes
- Comprehensive crypto tools (Caesar, Vigenère, RSA, hashing, etc.)
- Forensics tools (PCAP viewer, file carving, metadata extraction)
- Reverse engineering tools (disassemblers, decompilers, PE/ELF inspection)
- Media analysis (image analysis, audio tools, steganography)
- Web exploitation tools (JWT, SQL injection tester, etc.)
- Offline operation with no external dependencies

%prep
%autosetup -n cryptea

%build
%meson
%meson_build

%install
%meson_install

%check
desktop-file-validate %{buildroot}%{_datadir}/applications/org.avnixm.Cryptea.desktop

%files
%license LICENSE
%doc README.md
%{_bindir}/cryptea
%{_datadir}/applications/org.avnixm.Cryptea.desktop
%{_datadir}/icons/hicolor/scalable/apps/org.avnixm.Cryptea.svg
%{_datadir}/doc/cryptea/README.md
%{python3_sitelib}/ctf_helper/

%changelog
* Sat Oct 04 2025 avnixm <avnixm@users.noreply.github.com> - 0.1.0-1
- Initial release
- Added 40+ CTF tools across 6 categories
- Implemented challenge management with favorites
- Added PCAP/PCAPNG viewer with packet analysis
- Included comprehensive crypto and forensics tools
- Custom black app icon for GNOME integration
