# typed: false
# frozen_string_literal: true

class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers."
  homepage "https://verifpal.com"
  version "1.0.2"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.0.2/verifpal_1.0.2_darwin_amd64.zip"
      sha256 "d1de4686369d59cade13482d4b46020964a6a87250d1f605609160ce6608cb79"

      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.0.2/verifpal_1.0.2_darwin_arm64.zip"
      sha256 "45354eeaeb326f28ae3a33038a010f7b7a02210784dcac52381bef45e82faf45"

      def install
        bin.install "verifpal"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.0.2/verifpal_1.0.2_linux_amd64.zip"
      sha256 "e67767bcb154e72995993a714e84a02edc76c081c0a2fee6512a08f1a1df57b3"
      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.0.2/verifpal_1.0.2_linux_arm64.zip"
      sha256 "9a63fb3f28bfc211446ced589032d32c13ee4dd6a6f8fe40a726f3e6208d3772"
      def install
        bin.install "verifpal"
      end
    end
  end
end
