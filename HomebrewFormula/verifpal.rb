# typed: false
# frozen_string_literal: true

class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers."
  homepage "https://verifpal.com"
  version "0.50.0"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.50.0/verifpal_0.50.0_darwin_amd64.zip"
      sha256 "c68da01bb891fef75a41f46dc06e7759001968154bc21d72e700b45a5873acf3"

      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.50.0/verifpal_0.50.0_darwin_arm64.zip"
      sha256 "536a4668a37eb0659c277d0f08204246db05c4e0c6f5acfb48195193950c0c6c"

      def install
        bin.install "verifpal"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.50.0/verifpal_0.50.0_linux_amd64.zip"
      sha256 "754a894e8507788db9dab23c851768a07ab56a4bfbbd33986f939d4ba1e1750e"
      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.50.0/verifpal_0.50.0_linux_arm64.zip"
      sha256 "5fcfa8b83b8defb8d634e05bcadc13feebef8fc3ea5016688aabb73691bef8ed"
      def install
        bin.install "verifpal"
      end
    end
  end
end
