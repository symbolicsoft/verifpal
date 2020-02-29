#!/bin/bash
# SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
# SPDX-License-Identifier: GPL-3.0-only

snapcraft clean
snapcraft
snapcraft push --release=stable *.snap
rm *.snap