# Post-Quantum Security
Achieving quantum security while maintaining quantum resistance makes it easier to integrate into programming languages, offering a lightweight and user-friendly solution.

## Kế hoạch dự án

- Lõi duy nhất viết bằng **Rust**, bám theo chuẩn NIST (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA; theo dõi FN-DSA, HQC).
- Mỗi ngôn ngữ có một thư viện riêng, mỏng, viết theo phong cách của ngôn ngữ đó.
- Dùng **cơ chế lai** (cổ điển + hậu lượng tử) ở nơi cần chống "thu thập bây giờ, giải mã sau", và giữ thuật toán cổ điển ở nơi không cần thiết.

Xem kế hoạch đầy đủ tại [docs/ROADMAP.md](docs/ROADMAP.md).

## Trạng thái

Bản tiền phát hành (0.0.x), **chưa kiểm toán, chưa dùng cho bí mật thật**. Đã có lõi Rust
(ML-KEM, ML-DSA, X-Wing, MLKEM1024-P384, chữ ký composite; 4 profile), thư viện `vpqc` và CLI `vpqc`.

```sh
cargo run -p vpqc-cli -- keygen --purpose encrypt --out alice
echo "hello" | cargo run -q -p vpqc-cli -- seal --to alice.pub -o msg.vpqc
cargo run -q -p vpqc-cli -- open --key alice.vpqc-secret msg.vpqc
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
| .NET, Swift, Kotlin/Android, Dart | | C ABI | chưa |

Kiểm tra tương tác giữa các thư viện: `interop/run.sh` (xem `docs/ROADMAP.md`).

## Kiểm kê mật mã (migration)

```sh
vpqc scan ./my-project                       # báo cáo, xếp theo mức ưu tiên di trú
vpqc scan ./my-project --format cbom -o cbom.json   # CycloneDX 1.6 CBOM
vpqc scan ./my-project --fail-on quantum-vulnerable # thoát mã 2 nếu còn thuật toán dễ bị lượng tử
```

Chứng chỉ X.509 và tệp khoá được phân tích chính xác; mã nguồn/cấu hình được quét theo mẫu
(chỉ tìm *lần nhắc tên*, không chứng minh việc sử dụng), nên có thể có dương tính giả. Khoá
không bao giờ được in ra.
