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
| AEGIS-128L (bitsliced)               |         2241 |
| AEGIS-128L (libaegis, unprotected)   |         4232 |

ARM Cortex M4 (Flipper Zero)

| Algorithm                                | Speed (Mb/s) |  CpB |
| :--------------------------------------- | -----------: | ---: |
| AES-128-GCM (fixsliced, protected GHASH) |         2.08 |  246 |
| AES-128-GCM (unprotected, 4 LUTs)        |         2.46 |  208 |
| AES-128-GCM (fixsliced, 4-bit LUT GHASH) |         2.69 |  190 |
| AEGIS-128L (bitsliced)                   |         2.77 |  185 |
| AEGIS-128L (unprotected)                 |         8.28 |   62 |
| AES-128-GCM (hardware, via AHB2 bus)     |        11.23 |   46 |
