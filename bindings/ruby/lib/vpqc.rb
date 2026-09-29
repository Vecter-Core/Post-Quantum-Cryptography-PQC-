# frozen_string_literal: true

require "ffi"
require_relative "vpqc/native"

# Post-quantum cryptography with safe defaults. Pre-release and unaudited.
module Vpqc
  PROFILES = { standard: 1, fast_auth: 2, cnsa2: 3, high: 4 }.freeze

  # Base class for failures reported by the native library.
  class Error < StandardError
    attr_reader :code

    def initialize(message = nil, code = nil)
      super(message)
      @code = code
    end
  end

  # Decryption failed: wrong key, wrong context, or tampered data.
  class DecryptionError < Error; end

  # A signature is not valid for this key, message and context.
  class VerificationError < Error; end

  # A key, envelope or argument is malformed or of the wrong kind.
  class InvalidInputError < Error; end

  # An operating-system I/O error (file not found, permission denied, ...).
  class IOError < Error; end

  # An encoded public key. Safe to share.
  class PublicKey
    attr_reader :bytes

    def self.from_bytes(bytes)
      new(bytes.b.freeze)
    end

    def self.from_text(text)
      new(Native.key_from_text(Native::KEY_PUBLIC, text))
    end

    def initialize(bytes)
      @bytes = bytes
    end

    def to_text
      Native.key_to_text(Native::KEY_PUBLIC, @bytes)
    end

    def ==(other)
      other.is_a?(PublicKey) && other.bytes == @bytes
    end

    def to_s
      "PublicKey(#{@bytes.bytesize} bytes)"
    end
    alias inspect to_s
  end

  # An encoded secret key. Never printed or inspected.
  class SecretKey
    def self.from_bytes(bytes)
      new(bytes.b)
    end

    def self.from_text(text)
      new(Native.key_from_text(Native::KEY_SECRET, text))
    end

    def initialize(bytes)
      @bytes = bytes
    end

    # Binary encoding (unencrypted).
    def to_bytes
      raw.dup
    end

    # Armored text (unencrypted).
    def to_text
      Native.key_to_text(Native::KEY_SECRET, raw)
    end

    # @api private
    def raw
      raise Error, "secret key has been destroyed" if @bytes.nil?

      @bytes
    end

    # Overwrites this instance's copy of the key. Ruby may keep other copies in memory.
    def destroy
      @bytes&.replace("\0" * @bytes.bytesize)
      @bytes = nil
    end

    def to_s
      "SecretKey(<redacted>)"
    end
    alias inspect to_s

    def marshal_dump
      raise TypeError, "SecretKey cannot be marshalled"
    end
  end

  # A freshly generated key pair.
  KeyPair = Struct.new(:public, :secret)

  class << self
    def generate_encryption_keypair(profile = :standard)
      pub, sec = Native.keygen(profile_id(profile), true)
      KeyPair.new(PublicKey.from_bytes(pub), SecretKey.from_bytes(sec))
    end

    def generate_signing_keypair(profile = :standard)
      pub, sec = Native.keygen(profile_id(profile), false)
      KeyPair.new(PublicKey.from_bytes(pub), SecretKey.from_bytes(sec))
    end

    # Encrypt +plaintext+ to +public_key+. +aad+ is authenticated context that +unseal+ needs again.
    def seal(public_key, plaintext, aad: "")
      Native.call3(:vpqc_seal, public_key.bytes, plaintext, aad)
    end

    # Decrypt a sealed message. Raises Vpqc::DecryptionError for a wrong key, wrong +aad+
    # or any modification.
    def unseal(secret_key, sealed, aad: "")
      Native.call3(:vpqc_open, secret_key.raw, sealed, aad)
    end

    # Sign under a mandatory domain-separation +context+ (at most 255 bytes).
    def sign(secret_key, message, context:)
      Native.call3(:vpqc_sign, secret_key.raw, message, context)
    end

    # Raises Vpqc::VerificationError if the signature is not valid.
    def verify(public_key, message, signature, context:)
      Native.verify(public_key.bytes, message, context, signature)
      nil
    end

    # Like #verify but returns a boolean for a bad signature. Malformed keys still raise.
    def valid?(public_key, message, signature, context:)
      verify(public_key, message, signature, context: context)
      true
    rescue VerificationError
      false
    end

    # Encrypt a file of any size in constant memory. Returns plaintext bytes.
    def encrypt_file(public_key, input, output, aad: "")
      Native.file(:vpqc_encrypt_file, public_key.bytes, aad, input, output)
    end

    # Encrypt a file for several recipients (1 to 32); each decrypts with #decrypt_file and their
    # own secret key. With one recipient this still writes the envelope format, so recipients can
    # later be changed with #rewrap_file (key rotation).
    def encrypt_file_multi(public_keys, input, output, aad: "")
      Native.file_multi(nil, public_keys.map(&:bytes), aad, input, output)
    end

    # Change the recipients of a multi-recipient file without re-encrypting it. secret_key must
    # belong to a current recipient; removing someone does not revoke what they already read.
    def rewrap_file(secret_key, public_keys, input, output, aad: "")
      Native.file_multi(secret_key.raw, public_keys.map(&:bytes), aad, input, output)
    end

    # Decrypt a file produced by #encrypt_file. The output appears only if the whole stream
    # verifies; raises Vpqc::DecryptionError otherwise.
    def decrypt_file(secret_key, input, output, aad: "")
      Native.file(:vpqc_decrypt_file, secret_key.raw, aad, input, output)
    end

    def abi_version
      Native.abi_version
    end

    private

    def profile_id(profile)
      PROFILES.fetch(profile.to_s.tr("-", "_").to_sym) do
        raise InvalidInputError.new("unknown profile #{profile.inspect}; expected one of #{PROFILES.keys.inspect}", 5)
      end
    end
  end
end
