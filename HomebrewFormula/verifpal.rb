# typed: false
# frozen_string_literal: true

class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers."
  homepage "https://verifpal.com"
  version "1.2.1"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.2.1/verifpal_1.2.1_darwin_amd64.zip"
      sha256 "b1fd1194c8a4d46a682d739cf17f6dde4d3c526f3548a2f1f5143c2f860fd210"

      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.2.1/verifpal_1.2.1_darwin_arm64.zip"
      sha256 "83718a0408d1bbed28c155ba4eb8370c30ad33acb2b6fb355fb1e4a0a17e3f9e"

      def install
        bin.install "verifpal"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.2.1/verifpal_1.2.1_linux_amd64.zip"
      sha256 "ab588df0939c477e5b1eaaaf59a0b37695f8c60998d20fd5eb661ffe771c3ad8"
      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.2.1/verifpal_1.2.1_linux_arm64.zip"
      sha256 "d297a76737f4b7f73c771897ba9e594942e109b730f44c1b2949c51a7e58c575"
      def install
        bin.install "verifpal"
      end
    end
  end
end
