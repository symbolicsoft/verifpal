# typed: false
# frozen_string_literal: true

class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers."
  homepage "https://verifpal.com"
  version "1.1.0"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.1.0/verifpal_1.1.0_darwin_amd64.zip"
      sha256 "2ffa773fab93b369af8f40e38a75153531c0fe46dc17ea30627f9cad864caabe"

      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.1.0/verifpal_1.1.0_darwin_arm64.zip"
      sha256 "ebbbd223f100996c0808ba94f38231d5719e04b3dcd24de250d479aeabf889fe"

      def install
        bin.install "verifpal"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.1.0/verifpal_1.1.0_linux_amd64.zip"
      sha256 "2e3f3014b3b75ea8860bfbfde8fbca73382ffe10db80ea01c2df125020d303aa"
      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.1.0/verifpal_1.1.0_linux_arm64.zip"
      sha256 "9cfe1acfb574073046199dc48a754c1cfd6be1b353545c6cac38bc2b877a7c6c"
      def install
        bin.install "verifpal"
      end
    end
  end
end
