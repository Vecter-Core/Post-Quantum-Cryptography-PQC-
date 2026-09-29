# frozen_string_literal: true

require "minitest/autorun"
require "securerandom"
require_relative "../lib/vpqc"

class VpqcTest < Minitest::Test
  PROFILES = %i[standard fast_auth cnsa2].freeze

  def test_abi_version
    assert_equal 1, Vpqc.abi_version >> 16
  end

  def test_encrypt_round_trip_all_profiles
    PROFILES.each do |p|
      keys = Vpqc.generate_encryption_keypair(p)
      sealed = Vpqc.seal(keys.public, "secret", aad: "ctx")
      assert_equal "secret".b, Vpqc.unseal(keys.secret, sealed, aad: "ctx"), p.to_s
    end
  end

  def test_decryption_failures
    a = Vpqc.generate_encryption_keypair
    b = Vpqc.generate_encryption_keypair
    sealed = Vpqc.seal(a.public, "secret", aad: "one")
    assert_raises(Vpqc::DecryptionError) { Vpqc.unseal(a.secret, sealed, aad: "two") }
    assert_raises(Vpqc::DecryptionError) { Vpqc.unseal(b.secret, sealed, aad: "one") }
    [0, 6, 12, 500, sealed.bytesize - 1].each do |i|
      bad = sealed.dup
      bad.setbyte(i, bad.getbyte(i) ^ 1)
      assert_raises(Vpqc::Error, "tamper at #{i}") { Vpqc.unseal(a.secret, bad, aad: "one") }
    end
  end

  def test_empty_plaintext
    k = Vpqc.generate_encryption_keypair
    assert_equal "".b, Vpqc.unseal(k.secret, Vpqc.seal(k.public, ""))
  end

  def test_sign_verify
    PROFILES.each do |p|
      k = Vpqc.generate_signing_keypair(p)
      sig = Vpqc.sign(k.secret, "msg", context: "app/v1")
      assert_nil Vpqc.verify(k.public, "msg", sig, context: "app/v1")
      assert Vpqc.valid?(k.public, "msg", sig, context: "app/v1")
      refute Vpqc.valid?(k.public, "msg", sig, context: "app/v2")
      assert_raises(Vpqc::VerificationError) { Vpqc.verify(k.public, "other", sig, context: "app/v1") }
    end
  end

  def test_invalid_inputs
    s = Vpqc.generate_signing_keypair
    assert_raises(Vpqc::InvalidInputError) { Vpqc.seal(s.public, "x") }
    assert_raises(Vpqc::InvalidInputError) { Vpqc.sign(s.secret, "m", context: "x" * 256) }
    assert_raises(Vpqc::InvalidInputError) { Vpqc.seal(Vpqc::PublicKey.from_bytes("\x01\x02\x03"), "x") }
    assert_raises(Vpqc::InvalidInputError) { Vpqc.generate_encryption_keypair(:nope) }
  end

  def test_key_text
    k = Vpqc.generate_encryption_keypair
    text = k.public.to_text
    assert text.start_with?("-----BEGIN VPQC PUBLIC KEY-----")
    assert_equal k.public, Vpqc::PublicKey.from_text(text)
    sk = Vpqc::SecretKey.from_text(k.secret.to_text)
    assert_equal "x".b, Vpqc.unseal(sk, Vpqc.seal(k.public, "x"))
    assert_raises(Vpqc::Error) { Vpqc::PublicKey.from_text(k.secret.to_text) }
  end

  def test_secret_key_is_not_leaked
    k = Vpqc.generate_encryption_keypair
    assert_equal "SecretKey(<redacted>)", k.secret.to_s
    assert_equal "SecretKey(<redacted>)", k.secret.inspect
    assert_raises(TypeError) { Marshal.dump(k.secret) }
    sealed = Vpqc.seal(k.public, "x")
    k.secret.destroy
    assert_raises(Vpqc::Error) { Vpqc.unseal(k.secret, sealed) }
  end

  def test_large_message
    k = Vpqc.generate_encryption_keypair
    data = SecureRandom.random_bytes(1 << 20)
    assert_equal data, Vpqc.unseal(k.secret, Vpqc.seal(k.public, data))
  end
end
