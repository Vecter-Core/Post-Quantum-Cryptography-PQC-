# frozen_string_literal: true

# Ruby driver for the interoperability suite. See interop/run.sh.
require_relative "../../bindings/ruby/lib/vpqc"

cmd, *a = ARGV
begin
  case cmd
  when "keygen" # keygen encrypt|sign PROFILE_NAME OUT_PREFIX
    kp = a[0] == "encrypt" ? Vpqc.generate_encryption_keypair(a[1]) : Vpqc.generate_signing_keypair(a[1])
    File.write("#{a[2]}.pub", kp.public.to_text)
    File.write("#{a[2]}.sec", kp.secret.to_text)
  when "seal" # seal PUBFILE AAD IN OUT
    File.binwrite(a[3], Vpqc.seal(Vpqc::PublicKey.from_text(File.read(a[0])), File.binread(a[2]), aad: a[1]))
  when "open" # open SECFILE AAD IN OUT
    File.binwrite(a[3], Vpqc.unseal(Vpqc::SecretKey.from_text(File.read(a[0])), File.binread(a[2]), aad: a[1]))
  when "sign" # sign SECFILE CTX IN OUT
    File.binwrite(a[3], Vpqc.sign(Vpqc::SecretKey.from_text(File.read(a[0])), File.binread(a[2]), context: a[1]))
  when "verify" # verify PUBFILE CTX SIG IN
    Vpqc.verify(Vpqc::PublicKey.from_text(File.read(a[0])), File.binread(a[3]), File.binread(a[2]), context: a[1])
  when "encrypt-file" # encrypt-file PUBFILE AAD IN OUT
    Vpqc.encrypt_file(Vpqc::PublicKey.from_text(File.read(a[0])), a[2], a[3], aad: a[1])
  when "encrypt-file-multi" # encrypt-file-multi AAD IN OUT PUBFILE...
    Vpqc.encrypt_file_multi(a[3..].map { |f| Vpqc::PublicKey.from_text(File.read(f)) }, a[1], a[2], aad: a[0])
  when "rewrap-file" # rewrap-file SECFILE AAD IN OUT PUBFILE...
    Vpqc.rewrap_file(Vpqc::SecretKey.from_text(File.read(a[0])), a[4..].map { |f| Vpqc::PublicKey.from_text(File.read(f)) },
                     a[2], a[3], aad: a[1])
  when "decrypt-file" # decrypt-file SECFILE AAD IN OUT
    Vpqc.decrypt_file(Vpqc::SecretKey.from_text(File.read(a[0])), a[2], a[3], aad: a[1])
  when "protect" # protect SECFILE PASSPHRASE OUT
    File.write(a[2], Vpqc::SecretKey.from_text(File.read(a[0])).to_protected_text(a[1], memory_kib: 8192))
  when "unprotect" # unprotect PROTFILE PASSPHRASE OUT
    File.write(a[2], Vpqc::SecretKey.from_protected(File.read(a[0]), a[1]).to_text)
  else
    raise ArgumentError, "unknown command #{cmd}"
  end
rescue Vpqc::Error, ArgumentError => e
  warn "ruby-driver: #{e.message}"
  exit 1
end
