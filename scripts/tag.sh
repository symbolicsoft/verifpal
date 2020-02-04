#!/bin/bash
# SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
# SPDX-License-Identifier: GPL-3.0-only

echo -n "[Verifpal] Enter version: "
read VERSION

if [[ "$OSTYPE" == "darwin"* ]]; then
	gsed -i -e "s/version = \"\([0-9]\|.\)\+\"/version = \"${VERSION}\"/g" cmd/verifpal/main.go
else
	sed -i -e "s/version = \"\([0-9]\|.\)\+\"/version = \"${VERSION}\"/g" cmd/verifpal/main.go
fi

git commit -am "Verifpal ${VERSION}" &> /dev/null
git push &> /dev/null
git tag -a "v${VERSION}" -m "Verifpal ${VERSION}" &> /dev/null
git push origin "v${VERSION}" &> /dev/null

echo "[Verifpal] Verifpal ${VERSION} tagged."
