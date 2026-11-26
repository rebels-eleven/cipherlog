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
      sha256 "167da12d70a6d18153335f879261eff5d205c245aa6146bd732629f6784d6e4f" # aarch64-apple-darwin
    end
    on_intel do
      url "https://github.com/rebels-eleven/cipherlog/releases/download/0.1.0-alpha.1/cipherlog-0.1.0-alpha.1-x86_64-apple-darwin.tar.gz"
      sha256 "58dab0f9b3af5dfb7ad6849c018deed07bac853540d0d45dd44a0cf437ef9986" # x86_64-apple-darwin
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/rebels-eleven/cipherlog/releases/download/0.1.0-alpha.1/cipherlog-0.1.0-alpha.1-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "419a843be59634d2ea764cea1df086af028e38d1f7a63aa77984117baa5d63e8" # aarch64-unknown-linux-gnu
    end
    on_intel do
      url "https://github.com/rebels-eleven/cipherlog/releases/download/0.1.0-alpha.1/cipherlog-0.1.0-alpha.1-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "7fbe1ceae779cf4c3368115562f16dbf62edc5dc24a965a0978627fcac668490" # x86_64-unknown-linux-gnu
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
