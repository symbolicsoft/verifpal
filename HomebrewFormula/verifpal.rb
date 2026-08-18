# typed: false
# frozen_string_literal: true

class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers."
  homepage "https://verifpal.com"
  version "1.0.3"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.0.3/verifpal_1.0.3_darwin_amd64.zip"
      sha256 "200c94d42b7298689723d0f7d40b533e67fa04f46bb7f5c72b0cec1fb8cc08a9"

      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.0.3/verifpal_1.0.3_darwin_arm64.zip"
      sha256 "32550702b7e95c4a0549b22934c05c44d3633e7f0d546095f022f882ac201d89"

      def install
        bin.install "verifpal"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.0.3/verifpal_1.0.3_linux_amd64.zip"
      sha256 "570156f4384bf3d674ed8a70a818983f6d3403f353ff5c94a17db4ad2649852c"
      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.0.3/verifpal_1.0.3_linux_arm64.zip"
      sha256 "0205c68db819b184b6a6516793c6591d785b76d63aac540fda6bded27c4b07e2"
      def install
        bin.install "verifpal"
      end
    end
  end
end
