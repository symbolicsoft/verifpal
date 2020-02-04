#!/bin/sh
# SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
# SPDX-License-Identifier: GPL-3.0-only  
  
mkdir -p $HOME/.ssh
echo "$GIT_PUSH_SSH_KEY" > $HOME/.ssh/id_ed25519
chmod -R 700 $HOME/.ssh
ssh-keyscan source.symbolic.software > $HOME/.ssh/known_hosts
git config --global user.name "Drone"
git config --global user.email "drone@drone.symbolic.software"