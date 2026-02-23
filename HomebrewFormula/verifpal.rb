# typed: false
# frozen_string_literal: true

class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers."
  homepage "https://verifpal.com"
  version "0.40.0"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.40.0/verifpal_0.40.0_darwin_amd64.zip"
      sha256 "4e540819ac9810e25b3ac6321d591b85ebd3d855062d6006c65349d3339517d4"

      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.40.0/verifpal_0.40.0_darwin_arm64.zip"
      sha256 "836792afce4f0787f70a18f7d4e308e34bf7f8e0478311ea50157d3eae570475"

      def install
        bin.install "verifpal"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.40.0/verifpal_0.40.0_linux_amd64.zip"
      sha256 "228d7242386cc337c59cb5d27ba79c1212c07e59fac8f9d5abb7d4debe1b0470"
      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.40.0/verifpal_0.40.0_linux_arm64.zip"
      sha256 "46ec48972372fcb76b6bfc52142351637e62caea8ab659c8ba3bd4af4dc71be8"
      def install
        bin.install "verifpal"
      end
    end
  end
end
