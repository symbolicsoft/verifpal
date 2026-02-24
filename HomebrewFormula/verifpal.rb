# typed: false
# frozen_string_literal: true

class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers."
  homepage "https://verifpal.com"
  version "0.40.2"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.40.2/verifpal_0.40.2_darwin_amd64.zip"
      sha256 "1fb7ccc9a629f5b0aded9cd11c80771f849215daa7660fed6ed9e9f4da76116d"

      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.40.2/verifpal_0.40.2_darwin_arm64.zip"
      sha256 "0233e3aa8a1b3811e5355594960d85e5c33a31311360ea9c2e91011ea523d9e5"

      def install
        bin.install "verifpal"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.40.2/verifpal_0.40.2_linux_amd64.zip"
      sha256 "ad393281c392bccdb03b38caab051a517bb155cb17f171b2ee37a9db00ea250a"
      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.40.2/verifpal_0.40.2_linux_arm64.zip"
      sha256 "e0a80500f5125307724c34beb329e3309a4ebf55ace352c57891b893ab68c0f8"
      def install
        bin.install "verifpal"
      end
    end
  end
end
