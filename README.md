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
| AEGIS-128X2 (bitsliced, 64-bit words)|         2730 |
| AEGIS-128L (bitsliced)               |         2241 |
| AEGIS-128L (libaegis, unprotected)   |         4232 |

ARM Cortex M4 (Flipper Zero):

| Algorithm                                | Speed (Mb/s) |  CpB |
| :--------------------------------------- | -----------: | ---: |
| AES-128-GCM (fixsliced, protected GHASH) |         2.08 |  246 |
| AES-128-GCM (unprotected, 4 LUTs)        |         2.46 |  208 |
| AES-128-GCM (fixsliced, 4-bit LUT GHASH) |         2.69 |  190 |
| AEGIS-128L (bitsliced)                   |         2.77 |  185 |
| AEGIS-128L (libaegis, unprotected)       |         8.28 |   62 |
| AES-128-GCM (hardware, via AHB2 bus)     |        11.23 |   46 |

## Notes on bitslicing AEGIS

The AEGIS-128L state consists of 8 AES blocks. The AES round function is applied to these 8 blocks simultaneously, making it well-suited not only for bitslicing in general but also for the barrel-shiftrows representation.

The state update function is defined as `S_i ← AES(in=S_{(i-1) mod 8}, round_key=S_i)` for each block. This is equivalent to applying a keyless AES round to a rotated state and feed-forwarding the original state.

In the bitsliced representation, rotating the state only requires a bit rotation across all bytes.

In the initialization, associated data absorption and finalization functions of AEGIS-128L, the state can be maintained in the bitsliced representation until the final update round.

However, the keystream is a linear combination of nearly all the AES blocks. Evaluating it in bitsliced form would be slightly more expensive than switching between representations during each step update. Therefore, after initialization, we retain an interleaved but non-bitsliced state. These representation changes are costly. Nonetheless, in AEGIS, integrity comes almost for free. In contrast, AES-GCM’s GMAC is costly, particularly on CPUs without carryless multiplication support or lookup tables. During encryption, GMAC’s cost can surpass the cost of representation changes in AEGIS.

AEGIS-128X2 is implemented simply as two sets of 8 blocks that are updated alternately, providing a measurable speed advantage over AEGIS-128L on RISC-V.

While a dedicated bitsliced representation could further improve performance, straightforward implementations using existing AES representations still enable AEGIS to achieve strong performance with side-channel protection, even on CPUs lacking AES instructions.

Finally, side-channel protection is unlikely to be necessary during the decryption phase, where an adversary cannot observe individual blocks or perform differential attacks.
