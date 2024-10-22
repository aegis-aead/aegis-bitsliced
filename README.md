# Bitsliced AEGIS

Protected implementations of the [AEGIS authenticated encryption algorithms](https://cfrg.github.io/draft-irtf-cfrg-aegis-aead/draft-irtf-cfrg-aegis-aead.html) for platforms without hardware AES support.

Side channels are mitigated using the [barrel-shiftrows](https://eprint.iacr.org/2020/1123.pdf) bitsliced representation recently introduced by Alexandre Adomnicai and Thomas Peyrin, which has proven to be a good fit for the AEGIS-128* variants.

With this representation, AEGIS-128* consistently outperforms AES128-GCM in terms of speed.

ARM Cortex A53:

| Algorithm                            | Speed (Mb/s) |
| :----------------------------------- | -----------: |
| AES-128-GCM (OpenSSL 3.3, bitsliced) |          129 |
| AEGIS-128L (bitsliced)               |          210 |
| AEGIS-128L (libaegis, unprotected)   |          427 |

Spacemit X60 RISC-V without AES extensions:

| Algorithm                              | Speed (Mb/s) |
| :------------------------------------- | -----------: |
| AES-128-GCM (OpenSSL 3.3, unprotected) |          223 |
| AEGIS-128X2 (bitsliced)                |          254 |
| AEGIS-128L (bitsliced)                 |          193 |
| AEGIS-128L (libaegis, unprotected)     |          198 |

WebAssembly (Apple M1, baseline+simd128):

| Algorithm                            | Speed (Mb/s) |
| :----------------------------------- | -----------: |
| AES-128-GCM (rust-crypto, fixsliced) |          472 |
| AES-128-GCM (zig, unprotected)       |         1040 |
| AEGIS-128L (bitsliced)               |         2215 |
| AEGIS-128L (libaegis, unprotected)   |         4232 |
