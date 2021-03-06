# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers."
  homepage "https://verifpal.com"
  version "0.27.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://source.symbolic.software/verifpal/verifpal/-/releases/v0.27.0/downloads/verifpal_0.27.0_macos_arm64.zip"
      sha256 "b7028b8d9597e69cf7b98d674e8716d411b9653ad739a421af54ebc07dcfde21"

      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.intel?
      url "https://source.symbolic.software/verifpal/verifpal/-/releases/v0.27.0/downloads/verifpal_0.27.0_macos_amd64.zip"
      sha256 "da67dbcb2b03e531b051eac7863d17eddd5300bd278acbe350c7b9e9f6fd525c"

      def install
        bin.install "verifpal"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://source.symbolic.software/verifpal/verifpal/-/releases/v0.27.0/downloads/verifpal_0.27.0_linux_arm64.zip"
      sha256 "ce0ae9673105b7296ad2685d90ed68441cff88f5db50574240f0d8d4dc52aa2e"

      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.intel?
      url "https://source.symbolic.software/verifpal/verifpal/-/releases/v0.27.0/downloads/verifpal_0.27.0_linux_amd64.zip"
      sha256 "e72861098d117603f4f0eccc5571de07cfc72354bb759e9db0c38886b780a617"

      def install
        bin.install "verifpal"
      end
    end
  end
end
