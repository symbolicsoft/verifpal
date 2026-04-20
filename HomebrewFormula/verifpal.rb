# typed: false
# frozen_string_literal: true

class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers."
  homepage "https://verifpal.com"
  version "0.51.0"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.51.0/verifpal_0.51.0_darwin_amd64.zip"
      sha256 "4d018a15f7ba864f056bfa1229a086b24c844e95e46afb7594886e6d61b1cf2e"

      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.51.0/verifpal_0.51.0_darwin_arm64.zip"
      sha256 "3199dfd79e272a681985310ec43c808d424420d2a4d3374afd384a6927271711"

      def install
        bin.install "verifpal"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.51.0/verifpal_0.51.0_linux_amd64.zip"
      sha256 "dba2c08b65cd17a0e20a7c6889a74a901b993824d59985cdfecf9878a9e2f309"
      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.51.0/verifpal_0.51.0_linux_arm64.zip"
      sha256 "9c6bfec8668bf350913eb1e4d3b711359caffaf16f98ebcd736798cec3b8a19a"
      def install
        bin.install "verifpal"
      end
    end
  end
end
