#!/bin/bash
# SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
# SPDX-License-Identifier: GPL-3.0-only

curl -sL "https://source.symbolic.software/verifpal/verifpal/archive/${DRONE_TAG}.zip" -O
BREW_HASH=$(sha256sum ${DRONE_TAG}.zip | cut -d " " -f 1)
rm -f "${DRONE_TAG}.zip"

sed -i -e "s/archive\\/v\\([0-9]\\|.\\)\\+.zip/archive\\/${DRONE_TAG}.zip/g" HomebrewFormula/verifpal.rb
sed -i -e "s/sha256 \\\"[a-f0-9]\\+\\\"/sha256 \\\"${BREW_HASH}\\\"/g" HomebrewFormula/verifpal.rb

echo "[Verifpal] Homebrew formula updated."