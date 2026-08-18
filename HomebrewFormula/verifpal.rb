# typed: false
# frozen_string_literal: true

class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers."
  homepage "https://verifpal.com"
  version "1.0.1"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.0.1/verifpal_1.0.1_darwin_amd64.zip"
      sha256 "671036ec9b238d19af546041b0254d6001aea6d01bd506a761e4cdc254870613"

      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.0.1/verifpal_1.0.1_darwin_arm64.zip"
      sha256 "22b7328a7a5dbdd5321edb426f4b933a8c16f7535c303d8e23b57e45e74aa51e"

      def install
        bin.install "verifpal"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.0.1/verifpal_1.0.1_linux_amd64.zip"
      sha256 "0651ac8b1e80a242b10e2482a3e93084411bb03dc01e098a13bf376b9aa4d6c3"
      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.0.1/verifpal_1.0.1_linux_arm64.zip"
      sha256 "b1396045df154713e0ab71e98e8c3db14823fae7f20f0cd71deeae887543a974"
      def install
        bin.install "verifpal"
      end
    end
  end
end
