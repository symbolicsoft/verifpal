# typed: false
# frozen_string_literal: true

class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers."
  homepage "https://verifpal.com"
  version "1.3.3"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.3.3/verifpal_1.3.3_darwin_amd64.zip"
      sha256 "66c0d4a9585d545a40ec4fa49c327ccc1f9cc1528c3938848c56639114e414e4"

      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.3.3/verifpal_1.3.3_darwin_arm64.zip"
      sha256 "fceb4cc77616aa52ff37f6c1475e9d181e6407104c67b32e1dfbf12b6da1e027"

      def install
        bin.install "verifpal"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.3.3/verifpal_1.3.3_linux_amd64.zip"
      sha256 "9595c4037277d233a5cce74291dab6de492a32a3752e348beee55ceb7a877eee"
      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.3.3/verifpal_1.3.3_linux_arm64.zip"
      sha256 "582493c44a2936c863d81b78cf0ebb9ec852b3653afc8ae66600947f1d58367c"
      def install
        bin.install "verifpal"
      end
    end
  end
end
