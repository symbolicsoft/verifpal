# typed: false
# frozen_string_literal: true

class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers."
  homepage "https://verifpal.com"
  version "0.52.0"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.52.0/verifpal_0.52.0_darwin_amd64.zip"
      sha256 "667ad6713d01babd5840b5df13eff39ecd4f35fedde3e5b9479ef1aebc735992"

      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.52.0/verifpal_0.52.0_darwin_arm64.zip"
      sha256 "342c8b9518b7e35c92fbc6073e8892abb38247289308e2b7144d661c84559900"

      def install
        bin.install "verifpal"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.52.0/verifpal_0.52.0_linux_amd64.zip"
      sha256 "e75e6b6737ba1c5965ad9dc71daec0993ded44d553dfb682f9dac182654700c1"
      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.52.0/verifpal_0.52.0_linux_arm64.zip"
      sha256 "076063796704db921349a889bd518e3418ebc11c7192d719c67e102887d9ea66"
      def install
        bin.install "verifpal"
      end
    end
  end
end
