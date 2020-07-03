# This file was generated by GoReleaser. DO NOT EDIT.
class Verifpal < Formula
  desc "Cryptographic protocol analysis for students and engineers."
  homepage "https://verifpal.com"
  version "0.14.8"
  bottle :unneeded

  if OS.mac?
    url "https://source.symbolic.software/verifpal/verifpal/uploads/c7b5fa2329b8392ee8887d52ef8707f4/verifpal_0.14.8_macos_amd64.zip"
    sha256 "8bc400cf2fa9788cc5c4d39cd92f722cfe0c59eb285deb6e102a694d2121859b"
  elsif OS.linux?
    if Hardware::CPU.intel?
      url "https://source.symbolic.software/verifpal/verifpal/uploads/74b3cb124c06bdfc579d0dc206b4ed7d/verifpal_0.14.8_linux_amd64.zip"
      sha256 "f192fd75f4ee6cc3f91e408aa9d9be2c4fd724506d3639cc16bdbeec4703ccff"
    end
  end

  def install
    bin.install "verifpal"
  end
end
