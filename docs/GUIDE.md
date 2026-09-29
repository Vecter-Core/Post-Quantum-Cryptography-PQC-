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

**Java qua JCA** (dùng được với code sẵn có viết theo `java.security`)
```java
Security.addProvider(new VpqcProvider());
KeyPairGenerator kpg = KeyPairGenerator.getInstance("VPQC-SIG", "VPQC");
kpg.initialize(new VpqcParameterSpec(Profile.STANDARD));
KeyPair kp = kpg.generateKeyPair();
Signature s = Signature.getInstance("VPQC-SIG", "VPQC");
s.setParameter(new VpqcSignatureParameterSpec("my-app/v1"));   // bắt buộc
s.initSign(kp.getPrivate()); s.update(data); byte[] sig = s.sign();

KEM kem = KEM.getInstance("VPQC-KEM", "VPQC");                 // javax.crypto.KEM, JDK 21+
KEM.Encapsulated e = kem.newEncapsulator(kemKeys.getPublic()).encapsulate(0, 32, "AES");
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

## 3. Tệp lớn (streaming)

`seal`/`open` dành cho thông điệp vừa bộ nhớ. Với tệp (sao lưu, ảnh đĩa, log), dùng dạng
**stream**: bộ nhớ không đổi dù tệp lớn cỡ nào (1 GiB chạy với ~10 MiB RAM).

```sh
vpqc encrypt --to alice.pub --aad backup/2026-09 -o db.dump.vpqc db.dump
vpqc decrypt --key alice.vpqc-secret --aad backup/2026-09 -o db.dump db.dump.vpqc
pg_dump mydb | vpqc encrypt --to alice.pub > db.vpqc          # stdin/stdout cũng được
```

```python
vpqc.encrypt_file(keys.public, "db.dump", "db.dump.vpqc", aad=b"backup/2026-09")
vpqc.decrypt_file(keys.secret, "db.dump.vpqc", "db.dump", aad=b"backup/2026-09")
enc = vpqc.StreamEncryptor(keys.public, aad=b"upload")    # dữ liệu đến từng phần
```

Go `EncryptFile/DecryptFile`, Java `Vpqc.encryptFile/decryptFile`, PHP `Vpqc::encryptFile`,
Ruby `Vpqc.encrypt_file`, C `vpqc_encrypt_file`, JS/trình duyệt `new StreamEncryptor(...)` /
`new StreamDecryptor(...)` (dùng với `file.stream()`).

**Nhiều người nhận** (ADR-0009): lặp lại `--to` (tối đa 32), ví dụ khoá của người dùng và một
khoá khôi phục cất ngoại tuyến. Mỗi người mở bằng khoá bí mật của chính mình; profile có thể khác nhau.

```sh
vpqc encrypt --to alice.pub --to recovery.pub --aad backup/2026-09 -o db.vpqc db.dump
```

```python
vpqc.encrypt_file([alice.public, recovery.public], "db.dump", "db.vpqc", aad=b"backup/2026-09")
```

Có ở mọi ngôn ngữ (Go `EncryptFileMulti`, Java/PHP `encryptFileMulti`, Ruby
`encrypt_file_multi`, JS `new StreamEncryptor([k1, k2], aad)`, C `vpqc_encrypt_file_multi`).
Người nhận không chứng minh được ai đã tạo tệp: nếu nguồn gốc quan trọng, hãy ký tệp.

**Xoay khoá / đổi người nhận không mã hoá lại dữ liệu** (`rewrap`, kiểu "re-wrap data key"
của KMS). Một người nhận hiện tại tạo tệp mới cho danh sách người nhận mới; thân tệp giữ nguyên:

```sh
vpqc encrypt --envelope --to key-2026.pub -o db.vpqc db.dump      # --envelope: để xoay khoá được
vpqc rewrap --key key-2026.vpqc-secret --to key-2027.pub -o db.2027.vpqc db.vpqc
```

Bỏ một người nhận chỉ ngăn họ mở **tệp mới**; họ có thể đã giữ tệp cũ hoặc khoá tệp. Muốn thu
hồi thật sự dữ liệu họ từng đọc được thì phải mã hoá lại.

**Quy tắc quan trọng:** khi giải mã ra **tệp**, tệp đích chỉ xuất hiện nếu toàn bộ luồng hợp
lệ. Khi giải mã theo kiểu luồng (stdout, `StreamDecryptor`, `Decryptor`), các phần bản rõ được
trả dần; nếu cuối cùng báo lỗi (ví dụ tệp bị cắt cụt) thì **phải bỏ toàn bộ dữ liệu đã nhận**.

## 3a. JWT / JWS hậu lượng tử (JOSE)

Token ký bằng **ML-DSA** theo draft IETF (`alg: ML-DSA-65`, khoá JWK `kty: AKP`), dùng được
với các thư viện JOSE khác (đã kiểm với `jose` trên Node.js).

```sh
vpqc jwk generate --out issuer.jwk > issuer.pub.jwk        # khoá riêng (0600) + khoá công khai
echo '{"sub":"alice","aud":"api"}' | vpqc jwt sign --key issuer.jwk --ttl 300 > token
vpqc jwt verify --key issuer.pub.jwk --aud api token       # in claims, hoặc báo lỗi
```

```rust
use vpqc_jose::{Algorithm, SigningKey, jwt};
let key = SigningKey::generate(Algorithm::MlDsa65)?;
let token = jwt::encode(&key, claims, 300)?;
let claims = jwt::decode(&token, &key.verifying_key(), &jwt::Validation {
    audience: Some("api".into()), ..Default::default()
})?;
```

- Mặc định an toàn: `alg` phải khớp khoá (chặn `none`/đổi thuật toán), bắt buộc `exp`, token
  có `aud` chỉ được chấp nhận khi bạn khai báo audience của mình.
- **Kích thước:** token ML-DSA-65 khoảng 4,5 KB. Vừa header HTTP nhưng chiếm phần lớn giới hạn
  8 KB thường gặp của proxy; kiểm tra trước khi gửi trong `Authorization`.
- Đây là ML-DSA "thuần" (chuẩn), không phải chữ ký lai: để các hệ khác xác minh được (ADR-0008).

## 3e. COSE / CWT hậu lượng tử (IoT, thiết bị, firmware)

Bản nhị phân (CBOR) của JWS/JWT, cho CoAP, thiết bị IoT, attestation, manifest firmware:

```sh
vpqc cose key --out thiet-bi.key --pub thiet-bi.pub           # COSE_Key AKP (ML-DSA-65)
vpqc cose sign --key thiet-bi.key --kid cam-bien-17 -o msg.cose du-lieu.bin
vpqc cose verify --key thiet-bi.pub msg.cose                   # in ra payload
vpqc cose sign --key fw.key --detached --aad "model-X/v2" firmware.bin > fw.sig
vpqc cose verify --key fw.pub --aad "model-X/v2" --payload firmware.bin fw.sig
vpqc cwt sign --key as.key --iss as.congtyx.vn --sub cam-bien-17 --aud den-kho-3 --ttl 3600 -o tok.cwt
vpqc cwt verify --key as.pub --aud den-kho-3 tok.cwt           # claims dạng JSON
```

- Thêm `--base64` để có văn bản base64url; khi xác minh, đầu vào base64url được nhận tự động.
- Mặc định an toàn: `alg` phải nằm trong header được bảo vệ và khớp khoá; `kid` và content
  type cũng được ký. `crit` và nhãn trùng giữa hai header bị từ chối. CWT bắt buộc `exp`;
  token có `aud` chỉ được chấp nhận khi bạn khai báo audience của mình.
- `--aad` (external AAD) gắn ngữ cảnh không truyền đi (model thiết bị, phiên bản...): chữ ký
  của thiết bị này không dùng lại được cho ngữ cảnh khác.
- **Kích thước:** thông điệp/CWT ML-DSA-65 khoảng 3,4 KB. Ổn với CoAP block-wise, BLE có phân
  mảnh; **không** vừa một khung LoRaWAN/802.15.4: hãy xác minh ở gateway (ADR-0012).
- Tương thích: ML-DSA theo draft-ietf-cose-dilithium với giá trị IANA (−49/−50, `kty` 7); đã
  kiểm hai chiều với OpenSSL + cbor2 và đối chiếu với `coset` (Google).

## 3c. Chứng chỉ X.509 hậu lượng tử (ML-DSA)

Chứng chỉ theo RFC 9881, dùng được với OpenSSL ≥ 3.5 (đã kiểm với `cryptography` và Node.js):

```sh
vpqc x509 key --alg ML-DSA-87 --out root.key > root.pub            # CA gốc sống lâu: ML-DSA-87
vpqc x509 ca --key root.key --cn "Công ty X Root CA" --days 7300 -o root.pem
vpqc x509 key --out api.key > api.pub
vpqc x509 issue --ca root.pem --ca-key root.key --subject-key api.pub \
  --cn api.congtyx.vn --dns api.congtyx.vn --purpose server --days 90 -o api.pem
vpqc x509 verify --ca root.pem --dns api.congtyx.vn api.pem
```

- Khoá riêng ở dạng PKCS#8 "seed" (54 byte, quyền 0600); đọc được khoá của OpenSSL/Node.
- `verify` là bộ kiểm tra chuỗi **tối giản** cho chuỗi toàn ML-DSA (chữ ký, hạn, CA, pathLen,
  key usage, EKU, tên DNS). Không có thu hồi (CRL/OCSP) hay name constraints; với TLS dùng
  trình duyệt/thư viện chuẩn khi chúng hỗ trợ ML-DSA.
- Chứng chỉ ML-DSA **lớn** (leaf 5,6–6,9 KB, chuỗi ~14 KB): cân nhắc cho thiết bị nhúng và TLS.

## 3d. SSH hậu lượng tử (OpenSSH)

OpenSSH đã có trao đổi khoá lai: `sntrup761x25519-sha512` (mặc định từ 9.0) và
`mlkem768x25519-sha256` (ML-KEM, từ 9.9, mặc định từ 10.0). Việc cần làm là **đừng tắt nó**
và tìm máy chủ chưa có:

```sh
vpqc ssh probe git.congtyx.vn                 # máy chủ đề xuất những KEX nào
vpqc ssh probe 10.0.0.5:2222 --require-pq     # mã thoát 2 nếu không có KEX lai (dùng trong CI)
vpqc ssh probe host --json                    # cho script quét cả dàn máy
vpqc scan /etc/ssh                            # soát KexAlgorithms trong sshd_config/ssh_config
```

- `probe` chỉ đọc gói `KEXINIT` (gửi rõ trước khi xác thực), không đăng nhập, không cần khoá.
- Cấu hình khuyên dùng: **xoá dòng `KexAlgorithms`** để dùng mặc định, hoặc đặt
  `KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256`
  (lai đứng đầu). Ở phía client, thứ tự của client quyết định: lai phải đứng **đầu**.
- **Cẩn thận:** OpenSSH < 9.9 không biết `mlkem768x25519-sha256` và `sshd` **từ chối khởi
  động** ("Unsupported KEX algorithm"). Luôn chạy `sshd -t` trước khi reload; với 9.0–9.8 bỏ
  tên `mlkem…` khỏi danh sách (vẫn còn `sntrup761x25519-sha512@openssh.com`).
- `KexAlgorithms -sntrup*,mlkem*` hay danh sách chỉ gồm `curve25519`/`ecdh-*` bị `scan`
  báo T0. `+...`/`^...` giữ nguyên các KEX lai mặc định nên không bị báo.
- Môi trường CNSA 2.0/FIPS: dùng `mlkem768x25519-sha256` (ML-KEM là chuẩn NIST; sntrup761 thì
  không). Khoá host/người dùng (chữ ký) chưa có chuẩn PQ cho SSH và ít khẩn cấp hơn (ADR-0011).

## 3b. Lỗi và bảo mật khi dùng

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
