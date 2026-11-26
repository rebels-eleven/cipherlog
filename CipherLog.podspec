Pod::Spec.new do |s|
  s.name             = 'CipherLog'
  s.version          = '0.1.0-alpha.1'
  s.summary          = 'App logs written to files encrypted at write time to the developer\'s public key.'
  s.description      = <<-DESC
    CipherLog writes your app's log lines to files on the device and encrypts them as it writes, to your
    X25519 public key (HPKE + ChaCha20-Poly1305, raw deflate). The app can append but cannot read what it wrote;
    only the holder of the private key can. A drop-in for os.Logger (CipherLogger), one start call per process,
    and an armored support bundle that goes through mail filters. File format cipherlog-v1 (SPEC.md), shared
    with the Android/JVM library and the CLI reader.
  DESC
  s.homepage         = 'https://github.com/rebels-eleven/cipherlog'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'rebels11' => 'hello@rebels11.com' }
  s.source           = { :git => 'https://github.com/rebels-eleven/cipherlog.git', :tag => s.version.to_s }

  s.ios.deployment_target = '17.0'
  s.osx.deployment_target = '14.0'
  s.swift_versions   = ['5.9', '6.0']

  s.source_files     = 'ios/Sources/CipherLog/**/*.swift'
  s.frameworks       = 'CryptoKit'
  # Raw deflate through the system zlib, like `linkedLibrary("z")` in Package.swift.
  s.libraries        = 'z'
  # The privacy manifest: the required-reason APIs the library calls (file timestamps, disk space).
  s.resource_bundles = { 'CipherLog_Privacy' => ['ios/Sources/CipherLog/PrivacyInfo.xcprivacy'] }
end
