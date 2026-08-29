# typed: false
# frozen_string_literal: true

class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers."
  homepage "https://verifpal.com"
  version "1.3.5"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.3.5/verifpal_1.3.5_darwin_amd64.zip"
      sha256 "f7b34ecb9209c19307ab5d3f857cb7b24638154798a7284fd0094eb041dc54d4"

      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.3.5/verifpal_1.3.5_darwin_arm64.zip"
      sha256 "320667b7337b277b55e3395a0272298ef3081533e6f148e6b6c33eea6d7e5607"

      def install
        bin.install "verifpal"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.3.5/verifpal_1.3.5_linux_amd64.zip"
      sha256 "8eddaf9610ffb5efeeb8c846b4f4a0efe93564f6b7d59d80b257bd85812a8ab3"
      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.3.5/verifpal_1.3.5_linux_arm64.zip"
      sha256 "08474519175792faa82f0840a27554932de3912cb84e3236f8a7e0620200ea49"
      def install
        bin.install "verifpal"
      end
    end
  end
end
