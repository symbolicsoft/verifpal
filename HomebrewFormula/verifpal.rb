# typed: false
# frozen_string_literal: true

class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers."
  homepage "https://verifpal.com"
  version "1.2.3"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.2.3/verifpal_1.2.3_darwin_amd64.zip"
      sha256 "1973c8b64194bde213b913e74ac16117016801f040b735c5f818ffed2147c11d"

      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.2.3/verifpal_1.2.3_darwin_arm64.zip"
      sha256 "b24df834c41b61d0193e0b3609807ca85cfbc8564d59b5277213cc49b26f7d9c"

      def install
        bin.install "verifpal"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.2.3/verifpal_1.2.3_linux_amd64.zip"
      sha256 "e8d4e46c6ed84a7735e12192396a58af4cac7298a2fb4ccf6b6f0c3dec32a63b"
      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v1.2.3/verifpal_1.2.3_linux_arm64.zip"
      sha256 "905faf5e95602544a5d7217609a8c81235e5829010d2b860d51c179bb44e726a"
      def install
        bin.install "verifpal"
      end
    end
  end
end
