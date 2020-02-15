# SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
# SPDX-License-Identifier: GPL-3.0-only

class Verifpal < Formula
	desc "Cryptographic protocol analysis for students and engineers"
	homepage "https://verifpal.com"
	url "https://source.symbolic.software/verifpal/verifpal/archive/v0.11.4.zip"
	sha256 "24b4da925f5e4db5edff0eefee8b7b5a56176096e6b97a8bb5f4250a53ccd0ca"

	depends_on "go" => :build

	def install
		mkdir bin
		system "go", "build", "-trimpath", "-gcflags", "-e", "-ldflags", "-s -w", "-o", bin, "verifpal.com/cmd/..."
		prefix.install_metafiles
	end
end
