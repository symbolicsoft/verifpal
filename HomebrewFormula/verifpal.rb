# typed: false
# frozen_string_literal: true

class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers."
  homepage "https://verifpal.com"
  version "1.3.2"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.3.2/verifpal_1.3.2_darwin_amd64.zip"
      sha256 "9bbedf5c6000fb7fb272003702b18dc86e3a36f87f5768653695f20f26c5263d"

      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.3.2/verifpal_1.3.2_darwin_arm64.zip"
      sha256 "984257e4acbd94ca69adc83e707211c934248f8ad73cf8361fbfbbfcd1540975"

      def install
        bin.install "verifpal"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.3.2/verifpal_1.3.2_linux_amd64.zip"
      sha256 "c9985f1bf49fc38b0f6f346840f01d3ce11b7b950e5c3718df25e5b7835247ea"
      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.3.2/verifpal_1.3.2_linux_arm64.zip"
      sha256 "e768764ec1b94c70ccf424c54fe0d77463b650dcfdf540f1cfa6e6804dbe6c56"
      def install
        bin.install "verifpal"
      end
    end
  end
end
