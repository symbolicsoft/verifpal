# typed: false
# frozen_string_literal: true

class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers."
  homepage "https://verifpal.com"
  version "0.60.1"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.60.1/verifpal_0.60.1_darwin_amd64.zip"
      sha256 "95db2b2c0a15c3fbd32b03c8ff16fc1d1c76a333521dcae4fe6a6c06a77cf935"

      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.60.1/verifpal_0.60.1_darwin_arm64.zip"
      sha256 "7d880e9d9f3c6b64965dc985385d79b786fc5d52a8159135d62bbd203b556f83"

      def install
        bin.install "verifpal"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.60.1/verifpal_0.60.1_linux_amd64.zip"
      sha256 "745c83322756c854a4148471360216fcec6d95cb0e8a07006f80e804d64c69a0"
      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.60.1/verifpal_0.60.1_linux_arm64.zip"
      sha256 "df07929ddbe01c91474e0e62e9ee2b2e1710a7423aa6f915af1aca5f79fe0ad0"
      def install
        bin.install "verifpal"
      end
    end
  end
end
