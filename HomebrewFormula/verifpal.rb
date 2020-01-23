# SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
# SPDX-License-Identifier: GPL-3.0-only

class Verifpal < Formula
	desc "Cryptographic protocol analysis for students and engineers"
	homepage "https://verifpal.com"
	url "https://source.symbolic.software/verifpal/verifpal/archive/v0.9.12.zip"
	sha256 "bfa273985c8e0cfdca300a07234affa4e09635153f47f0ce78c63b22f3ab271c"

	depends_on "go" => :build

	def install
		mkdir bin
		system "go", "build", "-trimpath", "-gcflags", "-e", "-ldflags", "-s -w", "-o", bin, "verifpal.com/cmd/..."
		prefix.install_metafiles
	end
end
