# typed: false
# frozen_string_literal: true

class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers."
  homepage "https://verifpal.com"
  version "1.3.0"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.3.0/verifpal_1.3.0_darwin_amd64.zip"
      sha256 "60de4a340802441af30d0340bf4c41126c305398a849d0332fde7ae0d8536b61"

      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.3.0/verifpal_1.3.0_darwin_arm64.zip"
      sha256 "f36405ff1d8326382769a332a63e763841fae84af0da671cadba459051be0bb2"

      def install
        bin.install "verifpal"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.3.0/verifpal_1.3.0_linux_amd64.zip"
      sha256 "14395dbfc65a026f14b050e6490c2c8ef3d5317a576fe2e86eaa85138ae16647"
      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.3.0/verifpal_1.3.0_linux_arm64.zip"
      sha256 "982160f38ef83cba73af30d6821f8ee90f98ff0e2f33aac1d3b2cfa0399138b5"
      def install
        bin.install "verifpal"
      end
    end
  end
end
