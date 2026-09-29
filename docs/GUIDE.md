# Hướng dẫn nhanh

> Bản tiền phát hành, **chưa kiểm toán**. Đừng dùng để bảo vệ bí mật thật.

## 1. Chọn profile (không chọn thuật toán)

| Bạn cần | Profile | Mã hoá (KEM) | Chữ ký |
|---------|---------|--------------|--------|
| Hầu hết ứng dụng | `standard` (mặc định) | X25519 + ML-KEM-768 (X-Wing) | Ed25519 + ML-DSA-65 (cả hai phải hợp lệ) |
| Xác thực ngắn hạn (token vài phút, handshake) | `fast-auth` | như `standard` | Ed25519 (cổ điển) |
| Dữ liệu/chứng chỉ sống rất lâu | `high` | P-384 + ML-KEM-1024 (MLKEM1024-P384) | ECDSA-P384 + ML-DSA-87 |
| Tuân thủ kiểu CNSA 2.0 | `cnsa2` | ML-KEM-1024 | ML-DSA-87 |

Quy tắc chọn:
- **Mã hoá và trao đổi khoá luôn nên lai** (mối đe doạ "thu thập bây giờ, giải mã sau" là có thật).
- **Chữ ký sống dài** (chứng chỉ, firmware, tài liệu lưu trữ) dùng composite. Chữ ký sống vài
  giây đến vài phút thì `fast-auth` chấp nhận được, vì kẻ tấn công không kịp có máy lượng tử.
- Mã hoá đối xứng và băm không cần đổi: ChaCha20-Poly1305 (khoá 256-bit), SHA-3/SHAKE.

## 2. Mã hoá và chữ ký trong 5 dòng

Ngữ nghĩa giống nhau ở mọi ngôn ngữ:

- `seal(khoá công khai, dữ liệu, aad)` / `open(khoá bí mật, hộp, aad)`: mã hoá cho người nhận.
  `aad` là ngữ cảnh được xác thực (sai `aad` thì mở không được).
- `sign(khoá bí mật, thông điệp, context)` / `verify(khoá công khai, thông điệp, context, chữ ký)`.
  `context` (tối đa 255 byte) **bắt buộc**, ví dụ `my-app/release-v1`: chữ ký cho mục đích này
  không dùng được cho mục đích khác.

**Rust**
```rust
use vpqc::{Profile, encryption, signing};
let keys = encryption::generate(Profile::Standard)?;
let sealed = encryption::seal(&keys.public, b"secret", b"ctx")?;
let plain = encryption::open(&keys.secret, &sealed, b"ctx")?;

let signer = signing::generate(Profile::Standard)?;
let sig = signing::sign(&signer.secret, b"release", b"my-app/v1")?;
signing::verify(&signer.public, b"release", b"my-app/v1", &sig)?;
```

**Python**
```python
import vpqc
keys = vpqc.generate_encryption_keypair()
sealed = vpqc.seal(keys.public, b"secret", aad=b"ctx")
vpqc.unseal(keys.secret, sealed, aad=b"ctx")
signer = vpqc.generate_signing_keypair()
sig = vpqc.sign(signer.secret, b"release", context=b"my-app/v1")
vpqc.verify(signer.public, b"release", sig, context=b"my-app/v1")   # ném VerificationError nếu sai
```

**JavaScript / TypeScript** (WASM)
```js
const vpqc = require("@vpqc/core");
const enc = new TextEncoder();
const keys = vpqc.generateEncryptionKeypair();
const sealed = vpqc.seal(keys.publicKey, enc.encode("secret"), enc.encode("ctx"));
vpqc.unseal(keys.secretKey, sealed, enc.encode("ctx"));
```

**Go**
```go
pk, sk, _ := vpqc.GenerateEncryptionKeypair(vpqc.ProfileStandard)
sealed, _ := vpqc.Seal(pk, []byte("secret"), []byte("ctx"))
plain, err := vpqc.Open(sk, sealed, []byte("ctx")) // errors.Is(err, vpqc.ErrDecryption)
```

**Java** (JDK 21 với `--enable-preview`, hoặc JDK 22+)
```java
KeyPair keys = Vpqc.generateEncryptionKeypair(Profile.STANDARD);
byte[] sealed = Vpqc.seal(keys.publicKey(), data, aad);
byte[] plain = Vpqc.open(keys.secretKey(), sealed, aad);
```

**PHP** (`ext-ffi`), **Ruby** (gem `ffi`), **C/C++** (`vpqc.h`): xem `bindings/php`,
`bindings/ruby`, `crates/vpqc-ffi/include/vpqc.h`.

**Dòng lệnh**
```sh
vpqc keygen --purpose encrypt --out alice
vpqc seal --to alice.pub --aad v1 -o msg.vpqc message.txt
vpqc open --key alice.vpqc-secret --aad v1 msg.vpqc
vpqc inspect msg.vpqc            # cho biết thuật toán, kích thước, cảnh báo nếu chỉ cổ điển
```

## 3. Lỗi và bảo mật khi dùng

- Giải mã/xác minh thất bại luôn báo lỗi gộp (`DecryptionFailed` / `VerificationFailed`): sai khoá,
  sai `aad`/`context` hay dữ liệu bị sửa đều cho cùng một kết quả, để không tạo "oracle".
- Khoá bí mật là hạt giống 32/64 byte, lưu **không mã hoá** trong tệp `.vpqc-secret` (quyền 0600).
  Hãy đặt trong kho khoá của hệ điều hành/KMS cho dữ liệu quan trọng.
- Python, JavaScript, Java, PHP, Ruby không thể đảm bảo xoá sạch khoá khỏi bộ nhớ; lõi Rust và
  bộ đệm của C ABI thì có xoá (`zeroize`).
- Kích thước lớn hơn RSA/ECC cổ điển: `standard` có khoá công khai 1216 byte (mã hoá) hoặc
  1984 byte (chữ ký), chữ ký 3373 byte (kích thước thô; bản mã hoá tuần tự hoá thêm 11 đến 16 byte
  tiêu đề). Với `fast-auth`, chữ ký chỉ 64 byte.

## 4. Kiểm kê và di trú

```sh
vpqc scan ./project                      # tìm thuật toán dễ bị lượng tử, xếp theo mức ưu tiên
vpqc scan ./project --format cbom -o cbom.json
vpqc scan ./project --fail-on quantum-vulnerable    # chặn trong CI
```

Thứ tự ưu tiên di trú (ADR-0003): **T0** trao đổi khoá/mã hoá khoá công khai (rủi ro hiện hữu)
→ **T1** chữ ký sống dài → **T2** chữ ký ngắn hạn → **T3** đối xứng/băm (không đổi) →
**T4** thuật toán yếu sẵn có (MD5, SHA-1, DES, RC4...).
