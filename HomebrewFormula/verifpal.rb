# SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
# SPDX-License-Identifier: GPL-3.0-only

class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers"
  homepage "https://verifpal.com"
  url "https://source.symbolic.software/verifpal/verifpal/archive/0.7.8.zip"
  sha256 "3843f2b6d82d942830d90076b51a98996579dc5dc94ff504f2a22e5010bfb900"

  depends_on "go" => :build

  def install
    mkdir bin
	system "go", "build", "-trimpath", "-gcflags", "-e", "-ldflags", "-s -w", "-o", bin, "verifpal.com/cmd/..."
    prefix.install_metafiles
  end
end
