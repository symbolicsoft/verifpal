# typed: false
# frozen_string_literal: true

class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers."
  homepage "https://verifpal.com"
  version "1.2.0"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.2.0/verifpal_1.2.0_darwin_amd64.zip"
      sha256 "c148c079cd7f873f6b145ce4cc75de3ea52b62466f57ec6e339d7e98a3ecbe0d"

      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.2.0/verifpal_1.2.0_darwin_arm64.zip"
      sha256 "b95d9f1925d3edce7b717ed46a0886937adb0d150d9ae9b31d14175c833d86bb"

      def install
        bin.install "verifpal"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.2.0/verifpal_1.2.0_linux_amd64.zip"
      sha256 "1728b6ecaf3689328270a22618206dc012a8e089781695c8fa1bf7e2f12689a3"
      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.2.0/verifpal_1.2.0_linux_arm64.zip"
      sha256 "7eb7a424368df2bcada0acb759b240167f5fe62daf260a3d797faef60a34915c"
      def install
        bin.install "verifpal"
      end
    end
  end
end
