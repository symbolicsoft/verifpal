# typed: false
# frozen_string_literal: true

class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers."
  homepage "https://verifpal.com"
  version "1.0.4"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.0.4/verifpal_1.0.4_darwin_amd64.zip"
      sha256 "f04e693e8fe9c377c9d6074840fc3f93c83d0d294c379dd99f56a8fcfa58600d"

      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.0.4/verifpal_1.0.4_darwin_arm64.zip"
      sha256 "36081d18cef052c1ac92a2610541129e0bb80f50b2879576654fffc7e0c60a46"

      def install
        bin.install "verifpal"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.0.4/verifpal_1.0.4_linux_amd64.zip"
      sha256 "dbcb81f6b5cdb7a7aff9082b9c679abc6eb58d21bbf856112c88fa207ff90aef"
      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.0.4/verifpal_1.0.4_linux_arm64.zip"
      sha256 "d777440454bf2e6aac45081e5e1eaa809a62f03f5183d50c9a81cf33ec27b1b8"
      def install
        bin.install "verifpal"
      end
    end
  end
end
