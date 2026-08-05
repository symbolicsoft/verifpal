# typed: false
# frozen_string_literal: true

class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers."
  homepage "https://verifpal.com"
  version "0.60.2"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.60.2/verifpal_0.60.2_darwin_amd64.zip"
      sha256 "f8a34b136e37128f0444bd4b8a6ae84097e4e7d94c278667c4a1d46511f63948"

      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.60.2/verifpal_0.60.2_darwin_arm64.zip"
      sha256 "3c24683e542e6d89779e3f320684a4cca39786e9b83982a6accca0a28cd4c3da"

      def install
        bin.install "verifpal"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.60.2/verifpal_0.60.2_linux_amd64.zip"
      sha256 "9048cdcf1fa36aa1aea426cae40d1c5bc5f427068025013cd2ad4822f8680f5f"
      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.60.2/verifpal_0.60.2_linux_arm64.zip"
      sha256 "135a0facf0e416a3c478b4b605362f67775b25a79a8c2a17244971853ec1d3e7"
      def install
        bin.install "verifpal"
      end
    end
  end
end
