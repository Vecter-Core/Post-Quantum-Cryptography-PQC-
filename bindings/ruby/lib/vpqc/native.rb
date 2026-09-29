# frozen_string_literal: true

module Vpqc
  # Bindings to the C ABI (vpqc.h) via the ffi gem. @api private
  module Native
    extend FFI::Library

    KEY_PUBLIC = 1
    KEY_SECRET = 2

    lib = ENV["VPQC_LIBRARY"]
    ffi_lib(lib && !lib.empty? ? lib : "vpqc_ffi")

    # struct vpqc_buf { uint8_t *ptr; size_t len; }
    class Buf < FFI::Struct
      layout :ptr, :pointer, :len, :size_t
    end

    attach_function :vpqc_abi_version, [], :uint32
    attach_function :vpqc_error_message, [:int], :string
    attach_function :vpqc_buf_free, [:pointer], :void
    attach_function :vpqc_encryption_keygen, %i[int pointer pointer], :int
    attach_function :vpqc_signing_keygen, %i[int pointer pointer], :int
    attach_function :vpqc_seal, %i[buffer_in size_t buffer_in size_t buffer_in size_t pointer], :int
    attach_function :vpqc_open, %i[buffer_in size_t buffer_in size_t buffer_in size_t pointer], :int
    attach_function :vpqc_sign, %i[buffer_in size_t buffer_in size_t buffer_in size_t pointer], :int
    attach_function :vpqc_verify,
                    %i[buffer_in size_t buffer_in size_t buffer_in size_t buffer_in size_t], :int
    attach_function :vpqc_key_to_text, %i[int buffer_in size_t pointer], :int
    attach_function :vpqc_key_from_text, %i[int buffer_in size_t pointer], :int
    attach_function :vpqc_encrypt_file, %i[buffer_in size_t buffer_in size_t string string pointer], :int
    attach_function :vpqc_decrypt_file, %i[buffer_in size_t buffer_in size_t string string pointer], :int

    module_function

    def error_for(code)
      message = vpqc_error_message(code)
      case code
      when 8 then DecryptionError.new(message, code)
      when 9 then VerificationError.new(message, code)
      when 1, 3, 4, 5, 6, 10 then InvalidInputError.new(message, code)
      when 11 then IOError.new(message, code)
      else Error.new(message, code)
      end
    end

    def check(rc)
      raise error_for(rc) unless rc.zero?
    end

    # Copies the native buffer into a binary String, then frees (zeroizes) it.
    def take(buf)
      len = buf[:len]
      out = len.zero? ? "".b : buf[:ptr].read_bytes(len)
      vpqc_buf_free(buf.pointer)
      out
    end

    def bin(str)
      str.to_s.b
    end

    def abi_version
      vpqc_abi_version
    end

    def keygen(profile, encrypt)
      pub = Buf.new
      sec = Buf.new
      rc = encrypt ? vpqc_encryption_keygen(profile, pub, sec) : vpqc_signing_keygen(profile, pub, sec)
      check(rc)
      [take(pub), take(sec)]
    end

    def call3(fn, a, b, c)
      a, b, c = bin(a), bin(b), bin(c)
      out = Buf.new
      check(send(fn, a, a.bytesize, b, b.bytesize, c, c.bytesize, out))
      take(out)
    end

    def verify(pk, msg, ctx, sig)
      pk, msg, ctx, sig = bin(pk), bin(msg), bin(ctx), bin(sig)
      check(vpqc_verify(pk, pk.bytesize, msg, msg.bytesize, ctx, ctx.bytesize, sig, sig.bytesize))
    end

    def file(fn, key, aad, input, output)
      key, aad = bin(key), bin(aad)
      n = FFI::MemoryPointer.new(:uint64)
      check(send(fn, key, key.bytesize, aad, aad.bytesize, input.to_s, output.to_s, n))
      n.read_uint64
    end

    def key_to_text(kind, key)
      key = bin(key)
      out = Buf.new
      check(vpqc_key_to_text(kind, key, key.bytesize, out))
      take(out).force_encoding(Encoding::UTF_8)
    end

    def key_from_text(kind, text)
      text = bin(text)
      out = Buf.new
      check(vpqc_key_from_text(kind, text, text.bytesize, out))
      take(out)
    end
  end
end
