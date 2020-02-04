#!/bin/bash
# SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
# SPDX-License-Identifier: GPL-3.0-only

# Scoop
curl -sL "https://source.symbolic.software/verifpal/verifpal/releases/download/${DRONE_TAG}/verifpal_${DRONE_TAG:1}_windows_amd64.zip" -O
SCOOP_HASH=$(sha256sum verifpal_${DRONE_TAG:1}_windows_amd64.zip | cut -d " " -f 1)
rm -f "verifpal_${DRONE_TAG:1}_windows_amd64.zip"
sed -i -e "s/\d{1,3}\.\d{1,3}\.\d{1,3}/${DRONE_TAG}/g" bucket/verifpal.json
sed -i -e "s/[a-f0-9]{64}/${SCOOP_HASH}/g" bucket/verifpal.json
echo "[Verifpal] Scoop bucket updated."

# Homebrew

curl -sL "https://source.symbolic.software/verifpal/verifpal/archive/${DRONE_TAG}.zip" -O
BREW_HASH=$(sha256sum ${DRONE_TAG}.zip | cut -d " " -f 1)
rm -f "${DRONE_TAG}.zip"
sed -i -e "s/\d{1,3}\.\d{1,3}\.\d{1,3}/${DRONE_TAG}/g" HomebrewFormula/verifpal.rb
sed -i -e "s/[a-f0-9]{64}/${BREW_HASH}/g" HomebrewFormula/verifpal.rb
echo "[Verifpal] Homebrew formula updated."