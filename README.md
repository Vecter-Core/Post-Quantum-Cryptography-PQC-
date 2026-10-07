# Post-Quantum Security
Achieving quantum security while maintaining quantum resistance makes it easier to integrate into programming languages, offering a lightweight and user-friendly solution.

## Kế hoạch dự án

- Lõi duy nhất viết bằng **Rust**, bám theo chuẩn NIST (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA; theo dõi FN-DSA, HQC).
- Mỗi ngôn ngữ có một thư viện riêng, mỏng, viết theo phong cách của ngôn ngữ đó.
- Dùng **cơ chế lai** (cổ điển + hậu lượng tử) ở nơi cần chống "thu thập bây giờ, giải mã sau", và giữ thuật toán cổ điển ở nơi không cần thiết.

Xem kế hoạch đầy đủ tại [docs/ROADMAP.md](docs/ROADMAP.md) và hướng dẫn dùng nhanh tại [docs/GUIDE.md](docs/GUIDE.md).

## Trạng thái

Bản tiền phát hành (0.0.x), **chưa kiểm toán, chưa dùng cho bí mật thật**. Đã có lõi Rust
(ML-KEM, ML-DSA, X-Wing, MLKEM1024-P384, chữ ký composite; 4 profile), thư viện `vpqc` và CLI `vpqc`.

```sh
cargo run -p vpqc-cli -- keygen --purpose encrypt --out alice
echo "hello" | cargo run -q -p vpqc-cli -- seal --to alice.pub -o msg.vpqc
cargo run -q -p vpqc-cli -- open --key alice.vpqc-secret msg.vpqc
```

Tệp lớn (sao lưu, ảnh đĩa) dùng dạng streaming, bộ nhớ không đổi:

```sh
vpqc encrypt --to alice.pub -o backup.tar.vpqc backup.tar
vpqc decrypt --key alice.vpqc-secret -o backup.tar backup.tar.vpqc   # chỉ ghi tệp nếu toàn bộ hợp lệ
vpqc encrypt --to alice.pub --to recovery.pub -o backup.tar.vpqc backup.tar   # nhiều người nhận
```

## Thư viện theo ngôn ngữ

| Ngôn ngữ | Thư mục | Cách nối | Trạng thái |
|----------|---------|----------|-----------|
| Rust | `crates/vpqc` | trực tiếp | có |
| CLI | `crates/vpqc-cli` | trực tiếp | có |
| C / C++ | `crates/vpqc-ffi` | C ABI | có |
| Python | `bindings/python` | PyO3 | có |
| JavaScript / TypeScript | `bindings/js` | WebAssembly | có |
| Go | `bindings/go` | cgo + C ABI | có |
| Java | `bindings/java` | Panama FFM + C ABI | có |
| PHP | `bindings/php` | FFI + C ABI | có |
| Ruby | `bindings/ruby` | ffi gem + C ABI | có |
| .NET | `bindings/dotnet` | P/Invoke + C ABI | có |
| Dart | `bindings/dart` | dart:ffi + C ABI | có |
| Swift, Kotlin/Android | | C ABI | chưa |

Kiểm tra tương tác giữa các thư viện: `interop/run.sh` (xem `docs/ROADMAP.md`).

## Bảo vệ khoá bí mật (passphrase, KMS, TPM)

```sh
vpqc keygen --purpose encrypt --out alice --passphrase            # Argon2id + XChaCha20-Poly1305
vpqc protect app.vpqc-secret --kms aws-kms:alias/vpqc -o app.key  # hoặc gcp-kms, vault-transit, systemd-creds
vpqc decrypt --key app.key data.vpqc -o data                      # khoá được bảo vệ dùng như khoá thường
```

Khoá bí mật không còn phải nằm dạng rõ trên đĩa (ADR-0013); định dạng passphrase đã kiểm chéo
với argon2-cffi + libsodium.

## Kiểm kê mật mã (migration)

```sh
vpqc scan ./my-project                       # báo cáo, xếp theo mức ưu tiên di trú
vpqc scan ./my-project --format cbom -o cbom.json   # CycloneDX 1.6 CBOM
vpqc scan ./my-project --fail-on quantum-vulnerable # thoát mã 2 nếu còn thuật toán dễ bị lượng tử
```

Chứng chỉ X.509 và tệp khoá được phân tích chính xác; mã nguồn/cấu hình được quét theo mẫu
(chỉ tìm *lần nhắc tên*, không chứng minh việc sử dụng), nên có thể có dương tính giả. Khoá
không bao giờ được in ra.

## JWT/JWS hậu lượng tử

```sh
vpqc jwk generate --out issuer.jwk > issuer.pub.jwk
echo '{"sub":"alice"}' | vpqc jwt sign --key issuer.jwk > token
vpqc jwt verify --key issuer.pub.jwk token
```

ML-DSA-65/87 theo draft IETF (`kty: AKP`), tương thích thư viện `jose` (Node.js); crate
`vpqc-jose`.

## COSE / CWT hậu lượng tử (IoT)

```sh
vpqc cose key --out dev.key --pub dev.pub
vpqc cose sign --key dev.key --kid sensor-17 -o msg.cose reading.cbor
vpqc cwt sign --key as.key --sub sensor-17 --aud light-3 -o token.cwt
vpqc cwt verify --key as.pub --aud light-3 token.cwt
```

COSE_Sign1/CWT ký bằng ML-DSA (draft-ietf-cose-dilithium, giá trị IANA), tương thích OpenSSL
và `coset`; crate `vpqc-cose` (ADR-0012).

## Chứng chỉ X.509 hậu lượng tử

```sh
vpqc x509 key --alg ML-DSA-87 --out root.key > root.pub
vpqc x509 ca --key root.key --cn "Example Root" -o root.pem
vpqc x509 issue --ca root.pem --ca-key root.key --subject-key api.pub --cn api --dns api.example.com --purpose server -o api.pem
vpqc x509 verify --ca root.pem --dns api.example.com api.pem
```

ML-DSA theo RFC 9881, tương thích OpenSSL (đã kiểm với Python `cryptography` và Node.js); crate `vpqc-x509`.

## SSH hậu lượng tử

```sh
vpqc ssh probe git.example.com --require-pq   # máy chủ có đề xuất KEX lai (ML-KEM/sntrup761) không
vpqc scan /etc/ssh                            # KexAlgorithms nào đang tắt KEX lai
```

Dùng KEX lai sẵn có của OpenSSH (`mlkem768x25519-sha256`), không tự làm SSH; crate `vpqc-ssh`
(ADR-0011), đã kiểm với `sshd` thật.

## VPN hậu lượng tử (WireGuard, IPsec)

```sh
vpqc wg psk-seal --to bob.pub --wg-local "$A" --wg-peer "$B" --psk-out wg0.psk --sign-key alice.vpqc-secret -o for-bob
vpqc wg psk-open --key bob.vpqc-secret --from alice.pub --wg-local "$B" --wg-peer "$A" -o wg0.psk for-bob
vpqc scan /etc/wireguard /etc/swanctl      # peer thiếu PresharedKey, IKEv2 thiếu ML-KEM
```

PSK của WireGuard được chuyển bằng sealed box lai, có chữ ký người gửi; đã kiểm bằng handshake
WireGuard thật (ADR-0014).

## TLS lai và HPKE

```sh
# Đặt TLS lai (X25519MLKEM768) trước một dịch vụ không sửa được
vpqc-tls-proxy server --listen 0.0.0.0:8443 --backend 127.0.0.1:8080 --cert cert.pem --key key.pem
# Nâng cấp một client cũ: plaintext cục bộ -> TLS lai ra ngoài
vpqc-tls-proxy client --listen 127.0.0.1:9000 --connect api.example.com:443 --server-name api.example.com --ca ca.pem
# Kiểm tra máy chủ có dùng trao đổi khoá hậu lượng tử không (mã thoát 2 nếu không)
vpqc-tls-proxy probe example.com:443 --require-pq
```

Mặc định proxy **chỉ chấp nhận nhóm lai**; thêm `--allow-classical` để cho client cũ dùng
X25519 (mỗi kết nối cổ điển được ghi log). HPKE cho giao thức cần nó (MLS, ECH, OHTTP) có ở
`vpqc::hpke`.
