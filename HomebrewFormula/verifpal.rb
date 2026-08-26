# typed: false
# frozen_string_literal: true

class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers."
  homepage "https://verifpal.com"
  version "1.3.1"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.3.1/verifpal_1.3.1_darwin_amd64.zip"
      sha256 "7975bde6c722691ae55bca09a75527912ee10db49f63ac8aadb9a85367c91e67"

      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.3.1/verifpal_1.3.1_darwin_arm64.zip"
      sha256 "45afb8682ab9e96592f48f71df6498e980fe49b6b6f8d21678f367e41b30b459"

      def install
        bin.install "verifpal"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.3.1/verifpal_1.3.1_linux_amd64.zip"
      sha256 "0faa50eb6bf686876ab07374e3b46602d59e8122116ff797595d98b10b345e40"
      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.3.1/verifpal_1.3.1_linux_arm64.zip"
      sha256 "1c3ccec33bf825f635e2dcbad83ca8bcf2efb1d61229cab8803d6a504e0ce66f"
      def install
        bin.install "verifpal"
      end
    end
  end
end
