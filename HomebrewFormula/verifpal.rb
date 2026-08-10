# typed: false
# frozen_string_literal: true

class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers."
  homepage "https://verifpal.com"
  version "0.80.1"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.80.1/verifpal_0.80.1_darwin_amd64.zip"
      sha256 "3a2738ed17d13d04ed7600f4ce382063ba4ec52f90da405495b6172907ce10ae"

      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.80.1/verifpal_0.80.1_darwin_arm64.zip"
      sha256 "50b16689d92993f3fa39f283d5bf1d71795a2c315c7adac412bab9d0704040bf"

      def install
        bin.install "verifpal"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.80.1/verifpal_0.80.1_linux_amd64.zip"
      sha256 "91cb4b87c29ae2d5dbfc07b684026fbe450dbd0385d716fa6f5a329488764476"
      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.80.1/verifpal_0.80.1_linux_arm64.zip"
      sha256 "eb89f9178ffefe352da2101fb437f2124131a31902d3ee7b55c933f36f53de7e"
      def install
        bin.install "verifpal"
      end
    end
  end
end
