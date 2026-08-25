# typed: false
# frozen_string_literal: true

class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers."
  homepage "https://verifpal.com"
  version "1.2.2"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.2.2/verifpal_1.2.2_darwin_amd64.zip"
      sha256 "71ed88629fe124304c1b537c00378f72275a05644ad7429fc6f22cf53b98537e"

      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.2.2/verifpal_1.2.2_darwin_arm64.zip"
      sha256 "c32c18907337e08d0de5233c546b56aa481ec33602797a014c29d8624e6d04c0"

      def install
        bin.install "verifpal"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.2.2/verifpal_1.2.2_linux_amd64.zip"
      sha256 "a21586aa6b0a58b75d8bcce2190d6e6df234eaa3859c8b8d1d6d7a7a4c8baa83"
      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.2.2/verifpal_1.2.2_linux_arm64.zip"
      sha256 "26a302c78994775c28ae0234b063aacac39e415338cac4c5cbb306c58977c3dd"
      def install
        bin.install "verifpal"
      end
    end
  end
end
