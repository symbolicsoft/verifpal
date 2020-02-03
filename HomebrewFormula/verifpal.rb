# SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
# SPDX-License-Identifier: GPL-3.0-only

class Verifpal < Formula
	desc "Cryptographic protocol analysis for students and engineers"
	homepage "https://verifpal.com"
	url "https://source.symbolic.software/verifpal/verifpal/archive/v0.9.21.zip"
	sha256 "f222f7eb594c5b56da2a1827784c8d4925152d81f1ad0b78f1d33d2534e4661b"

	depends_on "go" => :build

	def install
		mkdir bin
		system "go", "build", "-trimpath", "-gcflags", "-e", "-ldflags", "-s -w", "-o", bin, "verifpal.com/cmd/..."
		prefix.install_metafiles
	end
end
