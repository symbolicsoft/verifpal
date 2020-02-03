#!/bin/bash
# SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
# SPDX-License-Identifier: GPL-3.0-only

EMAIL_TEXT="$(cat assets/email.txt)"
EMAIL_TEXT="${EMAIL_TEXT//0TAG0/${DRONE_TAG}}"

curl -s --user "api:${MAILGUN_TOKEN}" \
    https://api.eu.mailgun.net/v3/drone.symbolic.software/messages \
    -F from="Symbolic Software Drone <drone@drone.symbolic.software>" \
    -F to="verifpal@lists.symbolic.software" \
    -F subject="[ANNOUNCE] Verifpal ${DRONE_TAG}" \
    -F text="${EMAIL_TEXT}" &> /dev/null

echo "[Verifpal] Email sent."