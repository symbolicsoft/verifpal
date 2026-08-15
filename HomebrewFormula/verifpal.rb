# typed: false
# frozen_string_literal: true

class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers."
  homepage "https://verifpal.com"
  version "1.0.0"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.0.0/verifpal_1.0.0_darwin_amd64.zip"
      sha256 "5fc4d791a78ff5e62b71c9807b38b95dbd6778bed15735590f2e4fc644c9c0a2"

      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.0.0/verifpal_1.0.0_darwin_arm64.zip"
      sha256 "18338d52e85a0b945e2ec305ece8d873d6574bf7e44935a17ee85b4f85b57a53"

      def install
        bin.install "verifpal"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.0.0/verifpal_1.0.0_linux_amd64.zip"
      sha256 "def35df625346b79205186b3ff7d3530f7f3306cbeff7d58de08ca664c9fe7d7"
      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.0.0/verifpal_1.0.0_linux_arm64.zip"
      sha256 "8b11fb22ab8f4eca1104aaf2426fc6a526900a361abce8b5c2ced4ea1d7425f7"
      def install
        bin.install "verifpal"
      end
    end
  end
end
