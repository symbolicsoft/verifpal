# typed: false
# frozen_string_literal: true

class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers."
  homepage "https://verifpal.com"
  version "0.80.0"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.80.0/verifpal_0.80.0_darwin_amd64.zip"
      sha256 "9e84d9c120e0dc4c82ffa8ca9e6cbf7ac6724ec92c3eae3f099d02866d31f3f3"

      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.80.0/verifpal_0.80.0_darwin_arm64.zip"
      sha256 "ff2108ca49fd7ddd80917e2c740ce4297c236b909b8670f636eea9966196b99e"

      def install
        bin.install "verifpal"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.80.0/verifpal_0.80.0_linux_amd64.zip"
      sha256 "313c2e4cc70462cdf8e8c9a0587e9e9ac8bb7c7220f872f2a727c0ffc4b592db"
      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.80.0/verifpal_0.80.0_linux_arm64.zip"
      sha256 "82a57e8c2928b5e2d37effd57df4b706739e4eb459cb853824d8307766efa4b0"
      def install
        bin.install "verifpal"
      end
    end
  end
end
