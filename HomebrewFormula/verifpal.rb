# typed: false
# frozen_string_literal: true

class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers."
  homepage "https://verifpal.com"
  version "0.53.0"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.53.0/verifpal_0.53.0_darwin_amd64.zip"
      sha256 "477b5c884a8358ff95c7fd350238f9c02ad9df8bba80f00746787fb27e1cb50a"

      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.53.0/verifpal_0.53.0_darwin_arm64.zip"
      sha256 "b2a943a5524ff2791bbf334cfbf1dc58f9ca67b05d744c2d765d8d8df5774565"

      def install
        bin.install "verifpal"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.53.0/verifpal_0.53.0_linux_amd64.zip"
      sha256 "af1a4c5ed00e2507fa048f3dd91e2a4f19ac02c12c3b058ed5745a1b244acebb"
      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.53.0/verifpal_0.53.0_linux_arm64.zip"
      sha256 "c98bac0c83f8215a1b12b1fe9631fad06030d7e5bf248a5b17eeec7b72302d5f"
      def install
        bin.install "verifpal"
      end
    end
  end
end
