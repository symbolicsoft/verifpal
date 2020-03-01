# SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
# SPDX-License-Identifier: GPL-3.0-only

class Verifpal < Formula
	desc "Cryptographic protocol analysis for students and engineers"
	homepage "https://verifpal.com"
	url "https://source.symbolic.software/verifpal/verifpal/archive/v0.11.7.zip"
	sha256 "d6a20b2b1653bb0b9c8fbd9d1e9a5ef2fbe48998802ce4c43770dbdab99e6a12"

	depends_on "go" => :build

	def install
		mkdir bin
		system "go", "build", "-trimpath", "-gcflags", "-e", "-ldflags", "-s -w", "-o", bin, "verifpal.com/cmd/..."
		prefix.install_metafiles
	end
end
