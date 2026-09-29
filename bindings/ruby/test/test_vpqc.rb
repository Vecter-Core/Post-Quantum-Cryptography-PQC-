# frozen_string_literal: true

require "minitest/autorun"
require "securerandom"
require_relative "../lib/vpqc"

class VpqcTest < Minitest::Test
  PROFILES = %i[standard fast_auth cnsa2 high].freeze

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

  def test_protected_secret_key
    k = Vpqc.generate_encryption_keypair
    text = k.secret.to_protected_text("mật khẩu đủ dài", memory_kib: 8192)
    assert text.start_with?("-----BEGIN VPQC PROTECTED SECRET KEY-----")
    assert Vpqc::SecretKey.protected?(text)
    refute Vpqc::SecretKey.protected?(k.secret.to_text)
    sk = Vpqc::SecretKey.from_protected(text, "mật khẩu đủ dài")
    assert_equal k.secret.to_bytes, sk.to_bytes
    assert_equal "p".b, Vpqc.unseal(sk, Vpqc.seal(k.public, "p"))
    assert_raises(Vpqc::DecryptionError) { Vpqc::SecretKey.from_protected(text, "wrong") }
    assert_raises(Vpqc::InvalidInputError) { k.secret.to_protected_text("x", memory_kib: 1024) }
    assert_raises(Vpqc::InvalidInputError) { k.secret.to_protected_text("") }
    assert_operator(Vpqc.abi_version & 0xffff, :>=, 1)
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

  def test_file_streaming
    require "tmpdir"
    Dir.mktmpdir do |dir|
      k = Vpqc.generate_encryption_keypair
      data = SecureRandom.random_bytes(3_000_000)
      File.binwrite("#{dir}/in", data)
      assert_equal data.bytesize, Vpqc.encrypt_file(k.public, "#{dir}/in", "#{dir}/enc", aad: "ctx")
      assert_equal data.bytesize, Vpqc.decrypt_file(k.secret, "#{dir}/enc", "#{dir}/out", aad: "ctx")
      assert_equal data, File.binread("#{dir}/out")
      assert_raises(Vpqc::DecryptionError) { Vpqc.decrypt_file(k.secret, "#{dir}/enc", "#{dir}/bad", aad: "x") }
      refute File.exist?("#{dir}/bad")
      assert_raises(Vpqc::IOError) { Vpqc.encrypt_file(k.public, "#{dir}/missing", "#{dir}/o") }
    end
  end

  def test_multi_recipient_and_rewrap
    require "tmpdir"
    Dir.mktmpdir do |dir|
      a = Vpqc.generate_encryption_keypair
      b = Vpqc.generate_encryption_keypair(:high)
      c = Vpqc.generate_encryption_keypair(:cnsa2)
      File.binwrite("#{dir}/in", "for the team")
      Vpqc.encrypt_file_multi([a.public, b.public], "#{dir}/in", "#{dir}/enc", aad: "t")
      [a, b].each_with_index do |k, i|
        Vpqc.decrypt_file(k.secret, "#{dir}/enc", "#{dir}/out#{i}", aad: "t")
        assert_equal "for the team", File.binread("#{dir}/out#{i}")
      end
      assert_raises(Vpqc::DecryptionError) { Vpqc.decrypt_file(c.secret, "#{dir}/enc", "#{dir}/x", aad: "t") }
      Vpqc.rewrap_file(b.secret, [b.public, c.public], "#{dir}/enc", "#{dir}/re", aad: "t")
      Vpqc.decrypt_file(c.secret, "#{dir}/re", "#{dir}/out2", aad: "t")
      assert_equal "for the team", File.binread("#{dir}/out2")
      assert_raises(Vpqc::DecryptionError) { Vpqc.decrypt_file(a.secret, "#{dir}/re", "#{dir}/y", aad: "t") }
    end
  end
end
