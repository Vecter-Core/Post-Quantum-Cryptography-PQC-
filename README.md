# Post-Quantum Security
Achieving quantum security while maintaining quantum resistance makes it easier to integrate into programming languages, offering a lightweight and user-friendly solution.

## Kế hoạch dự án

- Lõi duy nhất viết bằng **Rust**, bám theo chuẩn NIST (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA; theo dõi FN-DSA, HQC).
- Mỗi ngôn ngữ có một thư viện riêng, mỏng, viết theo phong cách của ngôn ngữ đó.
- Dùng **cơ chế lai** (cổ điển + hậu lượng tử) ở nơi cần chống "thu thập bây giờ, giải mã sau", và giữ thuật toán cổ điển ở nơi không cần thiết.

Xem kế hoạch đầy đủ tại [docs/ROADMAP.md](docs/ROADMAP.md).

## Trạng thái

Bản tiền phát hành (0.0.x), **chưa kiểm toán, chưa dùng cho bí mật thật**. Đã có lõi Rust
(ML-KEM, ML-DSA, X-Wing, chữ ký composite), thư viện `vpqc` và CLI `vpqc`.

```sh
cargo run -p vpqc-cli -- keygen --purpose encrypt --out alice
echo "hello" | cargo run -q -p vpqc-cli -- seal --to alice.pub -o msg.vpqc
cargo run -q -p vpqc-cli -- open --key alice.vpqc-secret msg.vpqc
```
