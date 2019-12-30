# SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
# SPDX-License-Identifier: GPL-3.0-only

class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers"
  homepage "https://verifpal.com"
  url "https://source.symbolic.software/verifpal/verifpal/archive/0.7.8.zip"
  sha256 "95671a45401aeefdb99fc530c43cb86943a5d9aca0e801188aa55985c4ed9f9e"

  depends_on "go" => :build

  def install
    mkdir bin
	system "go", "build", "-trimpath", "-gcflags", "-e", "-ldflags", "-s -w", "-o", bin, "verifpal.com/cmd/..."
    prefix.install_metafiles
  end
end
