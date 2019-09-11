#!/bin/bash
# SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
# SPDX-License-Identifier: GPL-3.0-only

VERIFPALVN="0.6.3"

/bin/echo "Verifpal Quick Installer and Updater"
/bin/echo "for Linux and macOS"
/bin/echo "https://verifpal.com"
/bin/echo "------------------------------------"

if [[ "$OSTYPE" == "linux-gnu" ]]; then
	VERIFPALWD=$(pwd)
	VERIFPALOS="linux"
	VERIFPALDL="https://source.symbolic.software/verifpal/verifpal/releases/download/${VERIFPALVN}/verifpal_linux.zip"
elif [[ "$OSTYPE" == "darwin"* ]]; then
	VERIFPALWD=$(pwd)
	VERIFPALOS="darwin"
	VERIFPALDL="https://source.symbolic.software/verifpal/verifpal/releases/download/${VERIFPALVN}/verifpal_macos.zip"
else
	/bin/echo ""
	/bin/echo "This installer is for Linux and macOS only."
	/bin/echo "Please visit https://verifpal.com/source for other platforms."
	sleep 1
	/bin/echo "Exiting."
	exit 1
fi

sleep 1
/bin/echo ""
/bin/echo "We will install Verifpal ${VERIFPALVN} in: /usr/local/bin/verifpal"
/bin/echo "Verifpal examples: /usr/local/share/verifpal/examples/"
/bin/echo "Press Enter to continue, or Ctrl+C to quit."
read </dev/tty

/bin/echo -n "[Verifpal] Preparing work folder..." 
rm -rf /tmp/verifpal
mkdir /tmp/verifpal
cd /tmp/verifpal
/bin/echo " OK"

/bin/echo "[Verifpal] Downloading latest Verifpal..."
curl -# -L -o verifpal.zip $VERIFPALDL

/bin/echo -n "[Verifpal] Decompresing archive..."
unzip -qq verifpal.zip
/bin/echo "  OK"

/bin/echo "[Verifpal] Admin access required."
sudo false

/bin/echo -n "[Verifpal] Installing Verifpal..."
sudo mkdir -p /usr/local/share/verifpal
sudo rm -f /usr/local/bin/verifpal
sudo rm -rf /usr/local/share/verifpal/*
sudo mv verifpal /usr/local/bin/verifpal
sudo mv README.md LICENSES examples /usr/local/share/verifpal/.
sudo chmod -R 755 /usr/local/bin/verifpal
sudo chmod -R 755 /usr/local/share/verifpal
/bin/echo "   OK"

/bin/echo -n "[Verifpal] Cleaning up..."
cd $VERIFPALWD
rm -rf /tmp/verifpal
/bin/echo "           OK"

/bin/echo ""
/bin/echo "OK! Type verifpal to get started."
/bin/echo "Download the Verifpal User Manual: https://verifpal.com"
