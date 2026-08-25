# typed: false
# frozen_string_literal: true

class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers."
  homepage "https://verifpal.com"
  version "1.2.5"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.2.5/verifpal_1.2.5_darwin_amd64.zip"
      sha256 "45f325633612bf525ef96e8187afd2da29ec8be7b128495fbc1f91d5b0104605"

      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.2.5/verifpal_1.2.5_darwin_arm64.zip"
      sha256 "347be4f5f445ca3573975c78ca845d65e5a2f40e497dbf1894ab783654203c2d"

      def install
        bin.install "verifpal"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.2.5/verifpal_1.2.5_linux_amd64.zip"
      sha256 "afbc48b13ef5a5e3aa5d1d7432678a6d416c599f0c91461bd3f929abf041faf3"
      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.2.5/verifpal_1.2.5_linux_arm64.zip"
      sha256 "34f3258af70e85a1b9ae1d6c2b6769d62f9439410f6be7d071f1ed6f268c093e"
      def install
        bin.install "verifpal"
      end
    end
  end
end
