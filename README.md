# Bitsliced AEGIS

Protected implementations of the [AEGIS authenticated encryption algorithms](https://cfrg.github.io/draft-irtf-cfrg-aegis-aead/draft-irtf-cfrg-aegis-aead.html) for platforms without hardware AES support.

Side channels are mitigated using the [barrel-shiftrows](https://eprint.iacr.org/2020/1123.pdf) bitsliced representation recently introduced by Alexandre Adomnicai and Thomas Peyrin, which has proven to be a good fit for the AEGIS-128* variants.

With this representation, AEGIS-128* consistently outperforms AES128-GCM in terms of speed.

**ARM Cortex A53:**

| Algorithm                            | Speed (Mb/s) |                 |
| :----------------------------------- | -----------: | :-------------- |
| AES-128-GCM (OpenSSL 3.3, bitsliced) |          261 | ■■■■■■■■■       |
| AEGIS-128L (bitsliced)               |          414 | ■■■■■■■■■■■■■■■ |
| AEGIS-128L (libaegis, _unprotected_) |          782 |                 |

**Spacemit X60 RISC-V without AES extensions:**

| Algorithm                                | Speed (Mb/s) |                 |
| :--------------------------------------- | -----------: | :-------------- |
| AES-128-GCM (BoringSSL, bitsliced)       |          137 | ■■■■■■          |
| AES-128-GCM (OpenSSL 3.3, _unprotected_) |          223 |                 |
| AEGIS-128X2 (bitsliced)                  |          333 | ■■■■■■■■■■■■■■■ |
| AEGIS-128L (bitsliced)                   |          193 | ■■■■■■■■■       |
| AEGIS-128L (libaegis, _unprotected_)     |          198 |                 |

**Sifive, u74-mc:**

| Algorithm                            | Speed (Mb/s) |                 |
| :----------------------------------- | -----------: | :-------------- |
| AES-128-GCM (BoringSSL, bitsliced)   |          130 | ■■■■■■          |
| AEGIS-128X2 (bitsliced)              |          311 | ■■■■■■■■■■■■■■■ |
| AEGIS-128L (bitsliced)               |          182 | ■■■■■■■■■       |
| AEGIS-128L (libaegis, _unprotected_) |          507 |                 |

**WebAssembly (Apple M1, baseline+simd128):**

| Algorithm                            | Speed (Mb/s) |                 |
| :----------------------------------- | -----------: | :-------------- |
| AES-128-GCM (boringssl, bitsliced)   |          480 | ■■              |
| AES-128-GCM (zig, _unprotected_)     |         1040 |                 |
| AEGIS-128X2 (bitsliced)              |         2912 | ■■■■■■■■■■■■■■■ |
| AEGIS-128L (bitsliced)               |         2241 | ■■■■■■■■■■■■    |
| AEGIS-128L (libaegis, _unprotected_) |         4232 |                 |

**ARM Cortex M4 (Flipper Zero):**

| Algorithm                                | Speed (Mb/s) |  CpB |
| :--------------------------------------- | -----------: | ---: |
| AES-128-GCM (fixsliced, protected GHASH) |         2.08 |  246 |
| AES-128-GCM (_unprotected_, 4 LUTs)      |         2.46 |  208 |
| AES-128-GCM (fixsliced, 4-bit LUT GHASH) |         2.69 |  190 |
| AEGIS-128L (bitsliced)                   |         2.77 |  185 |
| AEGIS-128L (libaegis, _unprotected_)     |         8.28 |   62 |
| AES-128-GCM (hardware, via AHB2 bus)     |        11.23 |   46 |

## Notes on bitslicing AEGIS

The AEGIS-128L state comprises 8 AES blocks. The AES round function is applied simultaneously to these 8 blocks, making it well-suited not only for general bitslicing but also for the barrel-shiftrows representation. AEGIS-128X2 can also be bitsliced in the same manner, using 64-bit words to update 16 blocks at once.

The state update function is defined as `S_i ← AES(in=S_{(i-1) mod 8}, round_key=S_i)` for each block, equivalent to applying a keyless AES round to a rotated state while feeding forward the original state.

In the bitsliced representation, rotating the state only requires a bit rotation across all bytes.

In the initialization, associated data absorption, and finalization functions of AEGIS-128L, the state can be maintained in the bitsliced form until the final update round.

However, the keystream is a linear combination of nearly all AES blocks. Evaluating this in bitsliced form would be slightly more costly than switching representations at each step update. Therefore, after initialization, we retain an interleaved but non-bitsliced state. We could keep the state bitsliced, unpack a copy to evaluate the linear combination, and only repack the two input blocks. However, in practice, this does not seem worthwhile.

These representation changes are costly. However, with 10 8-block AES rounds, AES-128 encrypts only 8 blocks, while AEGIS-128L encrypts 20. Additionally, AEGIS provides integrity with minimal overhead, while AES-GCM’s GMAC is costly, especially on CPUs without carryless multiplication support or lookup tables.

AEGIS-128X2 can be implemented using 64-bit words, or using two sets of 8 blocks updated alternately, offering a measurable speed advantage over AEGIS-128L on platforms such as WebAssembly and RISC-V, even with 32-bit words.

While a dedicated bitsliced representation could further improve performance, straightforward implementations using existing AES representations enable AEGIS to achieve strong performance with side-channel protection, even on CPUs lacking AES instructions.

Lastly, side-channel protection is generally unnecessary during decryption, as an adversary cannot observe individual blocks or conduct differential attacks at that stage.