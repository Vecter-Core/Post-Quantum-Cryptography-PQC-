Gem::Specification.new do |s|
  s.name        = "vpqc"
  s.version     = "0.0.1"
  s.summary     = "Post-quantum cryptography with safe defaults (pre-release, unaudited)"
  s.description = "Ruby binding over the vpqc Rust core (hybrid X25519+ML-KEM-768, ML-DSA) through its C ABI."
  s.authors     = ["vpqc contributors"]
  s.license     = "Apache-2.0"
  s.homepage    = "https://github.com/Vecter-Core/Post-Quantum-Cryptography-PQC-"
  s.required_ruby_version = ">= 3.0"
  s.files       = Dir["lib/**/*.rb"] + ["README.md"]
  s.add_dependency "ffi", "~> 1.16"
end
