# typed: false
# frozen_string_literal: true

class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers."
  homepage "https://verifpal.com"
  version "1.3.4"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.3.4/verifpal_1.3.4_darwin_amd64.zip"
      sha256 "b68ad3838629d800bc0c90ee03b387d49e866b9147adf154fdaedbb3de3006d6"

      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.3.4/verifpal_1.3.4_darwin_arm64.zip"
      sha256 "996a0a9fba58448a41dc289e8795f4cb6a8b0f7a7fff348702327a9609791d92"

      def install
        bin.install "verifpal"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.3.4/verifpal_1.3.4_linux_amd64.zip"
      sha256 "42996b129081d96ebb308b903b9fdeaf8bc4d7f627a0312fe2074e26cc47def5"
      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.3.4/verifpal_1.3.4_linux_arm64.zip"
      sha256 "b178f21b4b75fd0425fa9628bc1f8d3e16c3c8162b4369be01738d26b83caf2d"
      def install
        bin.install "verifpal"
      end
    end
  end
end
