# typed: false
# frozen_string_literal: true

class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers."
  homepage "https://verifpal.com"
  version "0.70.0"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.70.0/verifpal_0.70.0_darwin_amd64.zip"
      sha256 "df1c1357e4b34c1023a20d2db301a3e8fc30104502585064bc7c233b1ec38780"

      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.70.0/verifpal_0.70.0_darwin_arm64.zip"
      sha256 "9ef061d2f6d361f18d7fe9b863a169b770a1f57b7f7581103273082cdcd499ac"

      def install
        bin.install "verifpal"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.70.0/verifpal_0.70.0_linux_amd64.zip"
      sha256 "58fe81c51e8c6863aedb5525412d5b887496843782d9e19b52c9e99f50ba6ba0"
      def install
        bin.install "verifpal"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/symbolicsoft/verifpal/releases/download/v0.70.0/verifpal_0.70.0_linux_arm64.zip"
      sha256 "b4061d7c55f180e574f1c05c94de39ebe8bfc9e05dc65327cb7f69c3718f7ed1"
      def install
        bin.install "verifpal"
      end
    end
  end
end
