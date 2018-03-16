
Debian
====================
This directory contains files used to package crowcoind/crowcoin-qt
for Debian-based Linux systems. If you compile crowcoind/crowcoin-qt yourself, there are some useful files here.

## crowcoin: URI support ##


crowcoin-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install crowcoin-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your crowcoin-qt binary to `/usr/bin`
and the `../../share/pixmaps/crowcoin128.png` to `/usr/share/pixmaps`

crowcoin-qt.protocol (KDE)

