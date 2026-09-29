# Kế hoạch tổng thể: PQC dễ dùng, lõi Rust, thư viện theo từng ngôn ngữ

> Trạng thái: **bản nháp v0.1 – 2026-09-29**. Tên gói `vpqc-*` chỉ là tên tạm.
> Trạng thái chuẩn (FIPS 206, HQC, các bản draft IETF) thay đổi nhanh. Mục nào ghi
> **[kiểm tra lại]** phải đối chiếu nguồn chính thức (NIST CSRC, IETF datatracker) trước khi
> hiện thực hoá.

---

## Trạng thái triển khai (cập nhật 2026-09-29)

| Hạng mục | Trạng thái | Ghi chú |
|----------|-----------|---------|
| Giai đoạn 0: workspace, CI, ADR, SECURITY, `deny.toml` | Xong | 5 ADR trong `docs/adr/`; MSRV 1.85 đã build thử; `cargo deny check` sạch |
| ML-KEM-768/1024 (FIPS 203) | Xong | Backend libcrux; **khớp từng byte với RustCrypto `ml-kem`** (test vi sai) |
| ML-DSA-65/87 (FIPS 204) | Xong | Backend libcrux; khớp từng byte với RustCrypto `ml-dsa`, kể cả chữ ký xác định |
| X-Wing (X25519 + ML-KEM-768) | Xong | **Vượt 3/3 test vector chính thức** của draft CFRG (keygen, encaps, decaps) |
| Chữ ký composite Ed25519 + ML-DSA-65 | Xong | Nhãn vpqc riêng, chưa tương thích dây với draft LAMPS (xem ADR-0005) |
| Phong bì `sealed`, chữ ký tách rời, khoá dạng armor | Xong | Chống hạ cấp: header + KEM ciphertext nằm trong KDF và AAD |
| API dễ dùng `vpqc` (`seal/open`, `sign/verify`) và CLI `vpqc` | Xong | 3 profile: `standard`, `fast-auth`, `cnsa2` |
| Profile `high`: KEM lai MLKEM1024-P384 + chữ ký composite ECDSA-P384 + ML-DSA-87 | Xong | KEM **vượt 10/10 vector chính thức** của draft CFRG concrete-hybrid-kems; ECDSA low-S bắt buộc (đã kiểm bằng đột biến) |
| Profile `archive` (SLH-DSA) | **Hoãn có chủ đích** | Xem ADR-0006: chỉ có `slh-dsa` bản RC, chưa kiểm toán, không có bản thứ hai để đối chiếu |
| Profile `fips` (backend aws-lc-rs, FIPS 140-3) | **Chưa** | Cần backend aws-lc-rs |
| Backend RustCrypto làm backend chạy thật (`no_std`, WASM) | **Chưa** | Hiện chỉ dùng cho test vi sai; các crate hiện dùng `std` |
| KAT ACVP cho ML-KEM-1024 / ML-DSA, fuzzing, đo constant-time | **Chưa** | Giai đoạn 1 còn lại / giai đoạn 5 |
| C ABI (`vpqc-ffi`, header `vpqc.h`) | Xong | Panic không vượt biên; buffer xoá bộ nhớ khi giải phóng; ASan/UBSan/LSan sạch; kiểm cả C++ và liên kết tĩnh |
| Python (PyO3 + maturin, wheel `abi3` ≥ 3.9) | Xong | `bindings/python`: kiểu dữ liệu, type hints, hệ exception; 13 test |
| JavaScript/TypeScript (WASM, Node + web) | Xong | `bindings/js`: ~570 KB wasm, ngẫu nhiên từ `crypto.getRandomValues`; 7 test |
| Go (cgo, liên kết tĩnh) | Xong | `bindings/go`: `errors.Is`, `-race` sạch, khoá bí mật không in ra qua `fmt`; mới thử trên Linux |
| Java (Panama FFM, JDK 21 preview / 22+ final) | Xong | `bindings/java`: Maven, `DecryptionException`…, `SecretKey.destroy()`; 10 test. **Chưa có JCA Provider** (`KeyPairGenerator`/`Signature`) |
| PHP (FFI), Ruby (ffi gem) | Xong | `bindings/php` (29 kiểm tra), `bindings/ruby` (9 test) |
| **Test tương tác chéo ngôn ngữ** (`interop/run.sh`) | Xong | CLI Rust, Python, Node, Go, Java, PHP, Ruby: **5502 kiểm tra, 0 lỗi (4 profile)** (mọi tổ hợp sinh khoá × mã hoá × giải mã, ký × xác minh, sai context, dữ liệu bị sửa) |
| Parser: fuzz nhẹ (>600.000 đầu vào ngẫu nhiên/biến dị) | Xong | `vpqc-format/tests/robustness.rs`; fuzz theo độ phủ (`cargo-fuzz`) vẫn chưa |
| .NET, Swift, Kotlin (JCA), Dart | **Chưa** | Chưa có toolchain trong môi trường này để kiểm chứng; dùng chung C ABI |
| Phát hành gói (PyPI wheel đa nền tảng, npm, thư viện C dựng sẵn cho Go) | **Chưa** | Hiện phải build từ mã nguồn; CI đã khai báo nhưng mới chạy thử trên Linux |
| Kiểm toán bên ngoài | **Chưa** | **Chưa dùng cho bí mật thật** |

Ghi chú lệch so với sơ đồ mục 3: `vpqc-policy` hiện nằm trong `vpqc-core` (module `profile`);
`vpqc-easy` là crate `vpqc`; backend RustCrypto chưa có adapter.

---

## 0. Tầm nhìn và nguyên tắc

**Mục tiêu:** một bộ thư viện giúp mọi hệ thống chống được máy tính lượng tử mà không cần
hiểu mật mã. Dùng đúng mặc định là đã an toàn, muốn tuỳ biến vẫn có đường.

| # | Nguyên tắc | Ý nghĩa cụ thể |
|---|-----------|----------------|
| P1 | **Một lõi, nhiều vỏ** | Toàn bộ logic mật mã, định dạng dữ liệu, chính sách nằm trong lõi Rust. Mỗi ngôn ngữ chỉ có lớp vỏ mỏng, viết theo phong cách của ngôn ngữ đó. Nhờ vậy khi NIST/IETF đổi chuẩn, chỉ sửa một chỗ. |
| P2 | **Không tự phát minh mật mã** | Không viết lại phép toán ML-KEM/ML-DSA để dùng trong production. Dùng các backend đã kiểm toán hoặc kiểm chứng hình thức. Phần dự án tự làm là *lớp kết hợp lai, chính sách, định dạng, API, công cụ di trú*. |
| P3 | **Lai theo mức rủi ro, không lai tràn lan** | Chỗ nào nguy cơ "thu thập bây giờ, giải mã sau" thì lai bắt buộc. Chỗ nào không cần thì giữ thuật toán cổ điển. Xem mục 1. |
| P4 | **Chỉ theo chuẩn** | Chỉ ship thuật toán có chuẩn NIST (hoặc đã được NIST chọn). Thuật toán thử nghiệm nằm sau feature `experimental` và không nằm trong mặc định. |
| P5 | **Chống dùng sai (misuse-resistant)** | API mức cao không lộ nonce, IV, tham số. Không có cách chọn thuật toán yếu ngoài chính sách. |
| P6 | **Crypto-agility có kiểm soát** | Mọi dữ liệu mang ID thuật toán có phiên bản. Đổi thuật toán là đổi *profile*, không phải sửa mã người dùng. Có chống hạ cấp (downgrade). |
| P7 | **Dễ tích hợp** | Cài bằng một lệnh (`pip`, `npm`, `go get`, `cargo add`, ...). Có sẵn mặc định, CLI, sidecar/proxy cho hệ thống không sửa được mã. |

---

## 1. Mô hình mối đe doạ và phân tầng bảo vệ

Máy tính lượng tử đủ mạnh (CRQC) ảnh hưởng mật mã theo hai cách khác nhau:

- **Bí mật (confidentiality):** kẻ tấn công lưu lưu lượng mã hoá hôm nay, giải mã sau
  (*harvest now, decrypt later*). Đây là rủi ro **hiện hữu ngay**, ưu tiên cao nhất.
- **Tính xác thực (authenticity):** kẻ tấn công cần *có CRQC vào đúng lúc* mới giả mạo được
  chữ ký. Chữ ký sống ngắn (vài giây đến vài phút) ít rủi ro. Chữ ký sống dài (chứng chỉ gốc,
  firmware, tài liệu pháp lý) là rủi ro thật (*trust now, forge later*).
- **Đối xứng và băm:** Grover chỉ giảm một nửa độ mạnh hiệu dụng, nên khoá 256-bit là đủ.

### Bảng quyết định lai / cổ điển / thuần PQC

| Tầng | Trường hợp | Quyết định | Lý do |
|------|-----------|-----------|-------|
| **T0 – bắt buộc lai** | Thiết lập khoá / trao đổi khoá (TLS, SSH, VPN, HPKE, mã hoá tệp cho người nhận) | **X25519 + ML-KEM-768** (mặc định) | Chống HNDL. Lai để nếu ML-KEM có lỗ hổng bất ngờ thì X25519 vẫn giữ mức hiện tại. |
| **T0+ – bảo mật cao** | Dữ liệu sống >20 năm, chính phủ/quốc phòng, tuân thủ CNSA 2.0 | **ML-KEM-1024** (+ P-384 hoặc X448 ở chế độ lai) | Có profile riêng, kích thước lớn hơn nhưng dư địa an toàn cao hơn. |
| **T1 – chữ ký sống dài** | CA gốc/trung gian, firmware, code signing, tài liệu lưu trữ, chuỗi cung ứng | **Ed25519/ECDSA + ML-DSA-65** dạng composite (cả hai phải hợp lệ); gốc tin cậy siêu dài hạn dùng thêm **SLH-DSA** (chỉ dựa vào hàm băm) | Chống "trust now, forge later". SLH-DSA là lựa chọn bảo thủ nhất về giả định toán học. |
| **T1b – firmware phần cứng** | Bộ nạp khởi động, thiết bị nhúng cập nhật ít | **LMS/XMSS (SP 800-208)** hoặc ML-DSA | Có tuỳ chọn stateful nhưng chỉ khi có HSM/quản lý trạng thái chặt. Mặc định không bật. |
| **T2 – chữ ký sống ngắn** | Xác thực trong handshake, token vài phút, chữ ký request | **Cổ điển được chấp nhận** (Ed25519), cấu hình nâng lên ML-DSA bằng một cờ | Kẻ tấn công không kịp có CRQC. Tiết kiệm băng thông/CPU. Nếu cần tuân thủ thì nâng profile, không phải viết lại. |
| **T3 – không đổi** | Mã hoá đối xứng, MAC, KDF, băm | **AES-256-GCM / ChaCha20-Poly1305, HMAC-SHA-256/384, HKDF, SHA-384/SHA3-256** | Khoá ≥256-bit vẫn an toàn trước Grover. Không có lý do thêm phức tạp. |
| **T4 – di trú dần** | Hệ thống cũ chỉ nói được RSA/ECC | Bọc bằng sidecar/proxy PQC ở biên, bản ghi lại ID thuật toán để lập kế hoạch thay | Không phải hệ thống nào cũng sửa được ngay. |

> **Quy tắc kết hợp:** KEM lai dùng bộ kết hợp có chứng minh (ví dụ X-Wing cho
> X25519+ML-KEM-768; bộ kết hợp tổng quát theo hướng dẫn CFRG/IRTF cho các cặp khác) và luôn
> gắn ciphertext + khoá công khai vào KDF. Chữ ký lai dùng composite có ràng buộc (ràng buộc
> hai chữ ký vào cùng thông điệp và nhãn miền) để chống tấn công tách/thay một nửa.

---

## 2. Thuật toán và profile

| Chức năng | Chuẩn | Vai trò trong dự án |
|-----------|-------|--------------------|
| ML-KEM-512/768/1024 | FIPS 203 | KEM chính. Mặc định 768, cao cấp 1024. 512 chỉ bật khi ràng buộc tài nguyên và phải chọn rõ. |
| ML-DSA-44/65/87 | FIPS 204 | Chữ ký đa dụng. Mặc định 65, cao cấp 87. |
| SLH-DSA (SPHINCS+) | FIPS 205 | Chữ ký bảo thủ cho gốc tin cậy, dữ liệu lưu trữ dài hạn. |
| FN-DSA (Falcon) | FIPS 206 **[kiểm tra lại trạng thái]** | Chữ ký nhỏ gọn cho môi trường hạn chế băng thông. Chỉ ship sau khi chuẩn ổn định. Cẩn thận triển khai (số học dấu phẩy động, nguy cơ kênh kề). |
| HQC | NIST chọn làm KEM dự phòng (2025); bản draft/final **[kiểm tra lại]** | KEM thứ hai dựa trên *mã sửa lỗi* (khác họ lưới) để đa dạng hoá giả định toán học. Đưa vào lộ trình khi có FIPS. |
| LMS / XMSS | SP 800-208 | Chữ ký hash-based stateful cho firmware, bật thủ công. |
| Các ứng viên "on-ramp" chữ ký bổ sung (MAYO, UOV, HAWK, SQIsign, ...) | Đang đánh giá **[kiểm tra lại]** | Chỉ theo dõi. Không đưa vào mặc định. |
| Đối xứng/băm | FIPS 197/180/202, SP 800-38D... | AES-256-GCM, ChaCha20-Poly1305 (theo RFC), SHA-2/SHA-3, HKDF. |

### Các profile (người dùng chọn một tên, không chọn thuật toán)

| Profile | KEM | Chữ ký | Dùng khi |
|---------|-----|--------|----------|
| `standard` (mặc định) | X25519 + ML-KEM-768 | Ed25519 + ML-DSA-65 (composite) | Hầu hết ứng dụng |
| `fast-auth` | X25519 + ML-KEM-768 | Ed25519 (T2 cổ điển) | Xác thực ngắn hạn, thiết bị hạn chế |
| `high` | P-384 + ML-KEM-1024 | ECDSA-P384 + ML-DSA-87 | Dữ liệu sống rất lâu |
| `archive` | như `high` | thêm SLH-DSA | Chữ ký lưu trữ, gốc tin cậy |
| `cnsa2` | ML-KEM-1024 thuần | ML-DSA-87 / LMS | Tuân thủ CNSA 2.0 |
| `fips` | P-256/P-384 + ML-KEM (backend có FIPS 140-3) | ECDSA + ML-DSA | Môi trường cần chứng nhận |
| `experimental` | HQC, FN-DSA, on-ramp | ... | Nghiên cứu, không hỗ trợ SLA |

---

## 3. Kiến trúc lõi Rust

```
vpqc/                       (Cargo workspace, Apache-2.0)
├─ vpqc-core                # trait Kem/Signer/Aead, kiểu khoá, lỗi, zeroize, no_std
├─ vpqc-policy              # profile, ID thuật toán, chống hạ cấp, ngày hết hạn thuật toán
├─ vpqc-hybrid              # bộ kết hợp KEM lai, chữ ký composite, nhãn miền
├─ vpqc-backend-*           # adapter cho backend (xem bên dưới)
├─ vpqc-format              # phong bì (envelope) có phiên bản, mã hoá khoá PKCS#8/SPKI, PEM
├─ vpqc-easy                # API mức cao: seal/open, sign/verify, kx (3 lớp: Easy/Standard/Expert)
├─ vpqc-ffi                 # C ABI ổn định (cbindgen) – nền cho mọi ngôn ngữ dùng FFI
├─ vpqc-wasm                # wasm-bindgen cho web/Node/Deno/edge
├─ vpqc-cli                 # công cụ dòng lệnh: keygen, seal, sign, inspect, scan
└─ vpqc-testvec             # KAT, ACVP, Wycheproof-style, vector lai của dự án
```

### Chiến lược backend (quyết định quan trọng nhất)

Không tự viết primitive. Trừu tượng hoá qua trait và cho phép thay backend:

| Backend | Ưu điểm | Dùng cho |
|---------|---------|----------|
| **libcrux** (Cryspen, kiểm chứng hình thức) | Có chứng minh tính đúng/an toàn bộ nhớ, đa nền tảng | Mặc định cho ML-KEM/ML-DSA |
| **RustCrypto** (`ml-kem`, `ml-dsa`, `slh-dsa`) | Thuần Rust, `no_std`, dễ biên dịch sang WASM | Dự phòng, nhúng, WASM |
| **aws-lc-rs** | Có đường tới chứng nhận FIPS 140-3 | Profile `fips` |
| **liboqs** (tuỳ chọn) | Rộng nhất về thuật toán | Chỉ cho `experimental`/thử nghiệm |

Cơ chế **kiểm thử vi sai** (differential testing): chạy cùng đầu vào qua ≥2 backend và so kết
quả trong CI. Đây là lưới an toàn khi một backend có lỗi.

### Định dạng dữ liệu
- Phong bì `vpqc-envelope`: `magic | version | profile-id | alg-ids | ...`, có xác thực toàn bộ
  header (AAD) để chống hạ cấp.
- Khoá: PKCS#8 / SubjectPublicKeyInfo theo OID do IETF LAMPS/NIST quy định **[kiểm tra lại OID]**.
- Ưu tiên tương thích chuẩn có sẵn thay vì tự đặt: HPKE (RFC 9180 + KEM lai), JOSE/COSE, CMS, X.509.

---

## 4. Thư viện theo từng ngôn ngữ

Nguyên tắc: **cơ chế nối** chọn theo hệ sinh thái. **API thì mang phong cách bản địa** (lỗi kiểu
exception hay `Result`, async, kiểu dữ liệu, quy ước đặt tên). Không đẩy `unsafe` lên người dùng.

| Ưu tiên | Ngôn ngữ | Cơ chế nối với lõi | Gói phát hành | Ghi chú tích hợp |
|:-:|----------|--------------------|---------------|------------------|
| 1 | **Rust** | trực tiếp | `crates.io: vpqc` | Bản gốc, `no_std`, `serde`, async tuỳ chọn |
| 1 | **Python** | PyO3 + maturin (wheel `abi3`) | `pip install vpqc` | Type hints, tích hợp `cryptography`-style, asyncio; wheel cho manylinux/musl/macOS/Windows/arm64 |
| 1 | **JavaScript/TypeScript** | WASM (`wasm-bindgen`) cho trình duyệt/edge; `napi-rs` cho Node tốc độ cao | `npm i @vpqc/core` | Dùng WebCrypto cho phần cổ điển nếu có; type định nghĩa đầy đủ |
| 1 | **C / C++** | C ABI + header sinh bởi `cbindgen` | tarball, vcpkg, Conan, pkg-config | Nền cho các ngôn ngữ còn lại; ABI có phiên bản, cấp phát rõ ràng |
| 2 | **Go** | Mặc định cgo + tĩnh; tuỳ chọn WASM/`wazero` để không cần cgo | `go get` | Go 1.24+ đã có `crypto/mlkem`: phần đơn dùng stdlib, phần lai/chính sách/định dạng dùng lõi |
| 2 | **Java / Kotlin** | Panama FFM API (JDK 22+), JNI cho bản cũ; **JCA Provider** | Maven Central | Chạy được trong Spring/Android qua `KeyPairGenerator`, `Signature`, `KeyAgreement` |
| 2 | **C# / .NET** | P/Invoke (`LibraryImport`) | NuGet | Tương thích `System.Security.Cryptography`; .NET mới đã có ML-KEM/ML-DSA gốc, ta thêm lai/chính sách |
| 2 | **Swift / iOS/macOS** | UniFFI hoặc C ABI + XCFramework | Swift Package Manager | CryptoKit đã có PQC mới; ta bổ sung lai và định dạng thống nhất |
| 3 | **Kotlin Multiplatform / Android** | UniFFI | Maven / AAR | Dùng chung Java cho backend |
| 3 | **PHP** | FFI hoặc `ext-php-rs` | Composer | Nhu cầu WordPress/Laravel |
| 3 | **Ruby** | `magnus` | RubyGems | Rails |
| 3 | **Dart/Flutter** | `flutter_rust_bridge` | pub.dev | Ứng dụng di động |
| 3 | **Zig, Elixir, Lua, R...** | C ABI | theo yêu cầu cộng đồng | |

### Bộ kiểm thử chéo ngôn ngữ (bắt buộc)
- Mỗi binding phải vượt **cùng một bộ vector** từ `vpqc-testvec` (KAT + tương tác chéo: mã hoá
  bằng Python, giải mã bằng Go/Java/JS/...).
- Chạy CI ma trận (OS × kiến trúc × phiên bản ngôn ngữ). Không phát hành nếu một binding lệch.

### Ba lớp API (giống nhau ở mọi ngôn ngữ)

```
Lớp 1 – Easy (95% người dùng):     seal(data, recipient_pk) / open(sealed, my_sk)
                                     sign(msg, key) / verify(msg, sig, pk)
Lớp 2 – Standard (chọn profile):    Kem::new(Profile::High), Signer::new(Profile::Archive)
Lớp 3 – Expert (có cảnh báo):       chọn thuật toán riêng, tham số, chế độ, backend
```

---

## 5. Hướng tích hợp hệ thống

Xếp theo **tác động chống HNDL / độ khó tích hợp**. Mỗi mục là một hướng độc lập, có thể chia
cho người đóng góp.

### 5.1 Kênh truyền (ưu tiên cao nhất – T0)
| Hướng | Việc cần làm | Đích đến |
|-------|-------------|----------|
| **TLS 1.3** | Bổ sung nhóm lai `X25519MLKEM768` (đã là hướng chuẩn IETF); ví dụ và hướng dẫn cho rustls, OpenSSL 3.5+, BoringSSL, Go, Java, .NET. Cung cấp sidecar/reverse proxy cho dịch vụ không sửa được. | Mặc định bật lai cho dịch vụ mới |
| **SSH** | Tận dụng KEX lai sẵn có của OpenSSH (`mlkem768x25519-sha256`), cung cấp tài liệu cấu hình + công cụ kiểm tra cấu hình | Không tự tái phát minh |
| **VPN / WireGuard** | Lớp PSK sinh từ KEM (mẫu Rosenpass) dưới dạng dịch vụ đồng hành | Tunnel chống HNDL mà không sửa giao thức lõi |
| **gRPC / HTTP / QUIC** | Middleware/interceptor dùng TLS lai; nhận diện "kênh không PQC" | Dịch vụ nội bộ, microservice |
| **Nhắn tin (Signal/PQXDH, MLS)** | Không viết lại giao thức. Cung cấp primitive KEM lai cho ai xây ứng dụng | Ứng dụng chat |

### 5.2 Mã hoá dữ liệu lưu trữ (T0)
| Hướng | Việc cần làm |
|-------|-------------|
| **HPKE lai** | Cài HPKE với KEM lai, dùng làm khối xây dựng chung |
| **Mã hoá tệp/sao lưu** | Định dạng phong bì kiểu `age`, người nhận là khoá lai; công cụ CLI |
| **Envelope encryption cho KMS/DB** | Mở rộng cho AWS KMS/GCP KMS/HashiCorp Vault/Azure Key Vault: bọc DEK bằng khoá lai. Adapter cho ORM/driver (mã hoá cột) |
| **Object storage (S3...)** | SDK middleware mã hoá phía client |

### 5.3 Danh tính, PKI và chữ ký (T1)
| Hướng | Việc cần làm |
|-------|-------------|
| **X.509 / PKI** | Chứng chỉ ML-DSA và composite (theo IETF LAMPS), công cụ phát hành/kiểm tra, tích hợp `step-ca`, cert-manager (K8s) |
| **JOSE/JWT, COSE/CWT** | Thuật toán ML-DSA cho JWS; token lai; cảnh báo kích thước |
| **Ký code/firmware/OCI image** | Tích hợp Sigstore/cosign (song song), `git` commit signing, ký gói (npm/PyPI/crates), SLH-DSA/LMS cho bản phát hành |
| **Tài liệu / PDF / e-signature** | Chữ ký dài hạn + đóng dấu thời gian (kết hợp LTV) |
| **FIDO2/WebAuthn, mTLS** | Theo dõi chuẩn, cung cấp cầu nối khi chuẩn xong |

### 5.4 Công cụ di trú (yếu tố quyết định việc được dùng)
| Công cụ | Chức năng |
|---------|----------|
| `vpqc scan` | Quét mã nguồn, cấu hình, chứng chỉ, lưu lượng để lập **CBOM** (Cryptographic Bill of Materials, định dạng CycloneDX) |
| `vpqc lint` | Gợi ý chuyển đổi (RSA/ECDH → profile phù hợp), xếp theo rủi ro T0→T4 |
| `vpqc inspect` | Đọc phong bì/khoá/chứng chỉ, cho biết thuật toán, profile, hạn dùng |
| Chế độ **song song (shadow mode)** | Chạy lai ở chế độ ghi nhận để đo chi phí/độ tương thích trước khi bật thật |
| Cờ **kill-switch profile** | Đổi profile toàn hệ thống bằng cấu hình, có kiểm soát downgrade |

---

## 6. An toàn kỹ thuật và chất lượng

| Lĩnh vực | Biện pháp |
|----------|-----------|
| **Chính xác** | KAT của NIST, ACVP, vector riêng của lai, fuzzing (`cargo-fuzz`, libFuzzer) trên mọi parser |
| **Thời gian hằng (constant-time)** | Kiểm tra bằng `dudect`/`ctgrind`, không nhánh phụ thuộc bí mật; báo cáo cho từng backend |
| **Bộ nhớ** | `#![forbid(unsafe_code)]` ở mọi crate ngoại trừ `vpqc-ffi` (kiểm duyệt riêng), Miri, `zeroize`/`secrecy` cho khoá |
| **Kênh kề** | Tài liệu mô hình đe doạ, đặc biệt FN-DSA và triển khai nhúng |
| **Chuỗi cung ứng** | `cargo-deny`, `cargo-vet`, `cargo-audit`, khoá phụ thuộc, build tái lập được (reproducible), SBOM + CBOM cho mỗi bản phát hành, ký bản phát hành |
| **Hình thức** | Ưu tiên backend đã chứng minh; đề xuất chứng minh cho bộ kết hợp lai (Tamarin/ProVerif/EasyCrypt cho phần giao thức) |
| **Kiểm toán** | Kiểm toán bên ngoài trước 1.0 (mục tiêu: một đơn vị chuyên mật mã), chương trình báo lỗi (`SECURITY.md`, bug bounty khi có nguồn lực) |
| **Hiệu năng** | Benchmark công khai (`criterion`), SIMD (AVX2/NEON) qua backend, báo cáo kích thước/độ trễ mỗi profile |

---

## 7. Lộ trình theo giai đoạn

Thời gian ước tính cho một nhóm nhỏ (2–4 người), điều chỉnh khi rõ nguồn lực.

| Giai đoạn | Thời gian | Sản phẩm | Điều kiện hoàn thành (exit criteria) |
|-----------|-----------|----------|--------------------------------------|
| **0. Nền móng** | 2 tuần | Cargo workspace, CI (fmt, clippy, test, deny), `SECURITY.md`, `CONTRIBUTING.md`, ADR (Architecture Decision Records) cho các quyết định ở mục 1–3, chọn tên chính thức | CI xanh, ADR được review |
| **1. Lõi + lai** | 6–8 tuần | `core`, `policy`, `hybrid`, backend libcrux + RustCrypto, ML-KEM/ML-DSA/SLH-DSA, X25519+ML-KEM-768, Ed25519+ML-DSA-65, định dạng phong bì, `easy` API, CLI cơ bản | Vượt 100% KAT/ACVP; differential test giữa ≥2 backend; fuzz parser 24h sạch |
| **2. Vỏ ưu tiên 1** | 6 tuần | C ABI, Python, JS/TS (WASM+Node), bộ vector chéo ngôn ngữ, tài liệu + ví dụ "5 dòng mã" | Tương tác chéo Rust↔Python↔JS↔C đạt; phát hành `0.x` |
| **3. Vỏ ưu tiên 2** | 8 tuần | Go, Java/Kotlin (JCA), .NET, Swift; profile `high`, `archive`, `cnsa2`, `fips` | Ma trận CI đầy đủ; mỗi ngôn ngữ có gói cài được bằng công cụ chuẩn |
| **4. Tích hợp hệ thống** | 8–12 tuần (song song) | Sidecar TLS, HPKE lai, envelope-encryption cho KMS, X.509/JOSE, `vpqc scan/lint/inspect`, ví dụ K8s/Docker | ≥3 hướng tích hợp chạy thực tế với dự án thí điểm |
| **5. Củng cố & kiểm toán** | 8 tuần | Kiểm toán ngoài, constant-time report, SBOM/CBOM, build tái lập, ổn định API | Không còn lỗi mức cao/nghiêm trọng; phát hành **1.0** |
| **6. Liên tục** | không dừng | Theo dõi NIST/IETF: FN-DSA, HQC, on-ramp, đổi ngày ngừng dùng thuật toán; vỏ ưu tiên 3 | Có quy trình "standards watch" hằng quý |

### Mốc thời gian bên ngoài cần bám (định hướng)
- NIST IR 8547: dự kiến **ngừng dùng** RSA/ECC 112-bit vào 2030 và **cấm** vào 2035 **[kiểm tra lại]**.
- CNSA 2.0: lộ trình theo loại hệ thống, nhiều hạng mục đến 2030–2033 **[kiểm tra lại]**.
- Tức là hệ thống có vòng đời dài nên bắt đầu ngay, ưu tiên T0 trước.

---

## 8. Rủi ro và cách giảm

| Rủi ro | Cách giảm |
|--------|-----------|
| Chuẩn còn đổi (FN-DSA, HQC, OID, định dạng composite) | Định danh thuật toán có phiên bản, cách ly trong `policy`; cờ `experimental`; theo dõi hằng quý |
| Phát hiện điểm yếu trong thuật toán mới (đã xảy ra với SIKE, Rainbow) | Mặc định luôn **lai**; hỗ trợ đa dạng họ toán (lưới + hash + mã) |
| Lỗi triển khai, kênh kề | Không tự viết primitive, backend kiểm chứng, differential test, kiểm toán |
| Kích thước khoá/chữ ký lớn ảnh hưởng hiệu năng, MTU, độ trễ | Profile `fast-auth`; benchmark công khai; nén/cache; hướng dẫn cho từng giao thức |
| Phân mảnh giữa các binding | Một lõi, bộ vector chung, phát hành đồng bộ phiên bản (lockstep) |
| Nhiều người dùng dùng sai | API 3 lớp, mặc định an toàn, `vpqc lint`, tài liệu ví dụ đúng |
| Giấy phép và bằng sáng chế | Apache-2.0; rà soát giấy phép backend; theo dõi tuyên bố IPR của NIST |
| Nguồn lực hạn chế | Ưu tiên T0 (KEM lai) + Python/JS/C trước; vỏ ưu tiên 3 nhờ cộng đồng |

---

## 9. Việc cần quyết định trước khi bắt đầu giai đoạn 1

1. **Tên chính thức** cho dự án/gói (kiểm tra trùng trên crates.io, PyPI, npm, Maven).
2. **Đối tượng người dùng chính**: nhà phát triển ứng dụng, tổ chức chính phủ/tài chính, hay IoT/nhúng? (ảnh hưởng thứ tự profile và ngôn ngữ).
3. **Có cần đường FIPS 140-3 ngay không?** (nếu có thì đưa `aws-lc-rs` lên trước).
4. **Mô hình phát hành:** phiên bản đồng bộ cho mọi ngôn ngữ (đề xuất) hay độc lập.
5. **Nguồn lực kiểm toán** và thời điểm dự kiến.
6. **Chính sách đóng góp** và quản trị (DCO/CLA, mô hình bảo trì).

---

## 10. Việc làm đầu tiên (2 tuần tới)

- [ ] Tạo Cargo workspace và CI (`fmt`, `clippy -D warnings`, `test`, `cargo-deny`).
- [ ] Viết ADR-001…005: (1) một lõi Rust, (2) không tự viết primitive, (3) tầng lai/cổ điển, (4) backend & differential test, (5) định dạng phong bì + chống hạ cấp.
- [ ] Prototype `vpqc-hybrid`: X25519 + ML-KEM-768 qua backend libcrux, chạy KAT.
- [ ] Prototype binding Python (PyO3) làm "đường ống thử" cho toàn bộ quy trình phát hành đa ngôn ngữ.
- [ ] Bảng theo dõi chuẩn (standards watch) trong `docs/STANDARDS.md`.
