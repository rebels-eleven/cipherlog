# Homebrew tap formula for the cipherlog CLI. Install with
#   brew tap rebels-eleven/cipherlog https://github.com/rebels-eleven/cipherlog
#   brew install cipherlog
# The release workflow (.github/workflows/release.yml) rewrites the version and every sha256 line below (each line
# names its target in the trailing comment) and commits this file to main.
class Cipherlog < Formula
  desc "Create keys for and open cipherlog encrypted app logs"
  homepage "https://github.com/rebels-eleven/cipherlog"
  version "0.1.0-alpha.1"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/rebels-eleven/cipherlog/releases/download/0.1.0-alpha.1/cipherlog-0.1.0-alpha.1-aarch64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000" # aarch64-apple-darwin
    end
    on_intel do
      url "https://github.com/rebels-eleven/cipherlog/releases/download/0.1.0-alpha.1/cipherlog-0.1.0-alpha.1-x86_64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000" # x86_64-apple-darwin
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/rebels-eleven/cipherlog/releases/download/0.1.0-alpha.1/cipherlog-0.1.0-alpha.1-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000" # aarch64-unknown-linux-gnu
    end
    on_intel do
      url "https://github.com/rebels-eleven/cipherlog/releases/download/0.1.0-alpha.1/cipherlog-0.1.0-alpha.1-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000" # x86_64-unknown-linux-gnu
    end
  end

  def install
    bin.install "cipherlog"
  end

  test do
    assert_equal version.to_s, shell_output("#{bin}/cipherlog --version").strip
    assert_match "cipherlog keygen", shell_output("#{bin}/cipherlog --help")
  end
end
