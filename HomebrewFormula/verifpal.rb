# typed: false
# frozen_string_literal: true

class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers."
  homepage "https://verifpal.com"
  version "1.2.4"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.2.4/verifpal_1.2.4_darwin_amd64.zip"
      sha256 "cee77a8aac2e92651331b0b66a15769fd163cb86d1099e2ca9655edde07e8764"

      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.2.4/verifpal_1.2.4_darwin_arm64.zip"
      sha256 "7e3f75cbce5f59040fe7f2ca93cb5b32f1ee795fbec26dd531d6c7537010cf3b"

      def install
        bin.install "verifpal"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.2.4/verifpal_1.2.4_linux_amd64.zip"
      sha256 "62070a9f5d13aa0f33d5cb007b26d9471aa915748c0f8bbf960b11cc6f8b7f8d"
      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.2.4/verifpal_1.2.4_linux_arm64.zip"
      sha256 "c9ab412a00620a4689e30fc6db7444b6b78fca3b6c77853b3b4448327d079db0"
      def install
        bin.install "verifpal"
      end
    end
  end
end
