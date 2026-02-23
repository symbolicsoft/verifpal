# typed: false
# frozen_string_literal: true

class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers."
  homepage "https://verifpal.com"
  version "0.40.1"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.40.1/verifpal_0.40.1_darwin_amd64.zip"
      sha256 "9e450345eea252c7b2892e68a12be42ddbfd8e4fee884f3063deda3177eebd79"

      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.40.1/verifpal_0.40.1_darwin_arm64.zip"
      sha256 "b7cd4f05f0b13adf2ef7cfb93aa9aa1ad8d3d5f51f7bd24cf27db037f564b104"

      def install
        bin.install "verifpal"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.40.1/verifpal_0.40.1_linux_amd64.zip"
      sha256 "615f57e3b4be8274d158179f7b3e215b81023cd842f709f281a084249dfbb2ef"
      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.40.1/verifpal_0.40.1_linux_arm64.zip"
      sha256 "a47e85743637d36f36728460e97fa76e35d00ecb3ff7534a48500815879b219b"
      def install
        bin.install "verifpal"
      end
    end
  end
end
