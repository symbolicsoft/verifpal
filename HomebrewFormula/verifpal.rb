# SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
# SPDX-License-Identifier: GPL-3.0-only

class Verifpal < Formula
	desc "Cryptographic protocol analysis for students and engineers"
	homepage "https://verifpal.com"
	url "https://source.symbolic.software/verifpal/verifpal/archive/v0.8.7.zip"
	sha256 "a4b41d474a6a3b990b331479d027c0b0f04017b8068f7c131d0ea54e6607fd38"

	depends_on "go" => :build

	def install
		mkdir bin
		system "go", "build", "-trimpath", "-gcflags", "-e", "-ldflags", "-s -w", "-o", bin, "verifpal.com/cmd/..."
		prefix.install_metafiles
	end
end
