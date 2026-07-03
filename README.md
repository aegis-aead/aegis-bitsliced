# Bitsliced AEGIS

Protected implementations of the [AEGIS authenticated encryption algorithms](https://cfrg.github.io/draft-irtf-cfrg-aegis-aead/draft-irtf-cfrg-aegis-aead.html) for platforms without hardware AES support.

Side channels are mitigated using the [barrel-shiftrows](https://eprint.iacr.org/2020/1123.pdf) bitsliced representation introduced by Alexandre Adomnicai and Thomas Peyrin, which has proven to be a good fit for AEGIS.

Implemented variants:

- AEGIS-128L - 16-byte key/nonce, 8 AES blocks state
- AEGIS-128X2 - 16-byte key/nonce, parallel variant with 16 blocks
- AEGIS-256 - 32-byte key/nonce, 6 AES blocks state
- AEGIS-256X2 - 32-byte key/nonce, parallel variant with 12 blocks

With this representation, AEGIS-128L/128X2 consistently outperform AES128-GCM in terms of speed.

**ARM Cortex A53:**

| Algorithm                            | Speed (Mb/s) |
| :----------------------------------- | -----------: |
| AES-128-GCM (OpenSSL 3.3, bitsliced) |          261 |
| AEGIS-128L (bitsliced)               |          423 |
| AEGIS-128L (libaegis, _unprotected_) |          782 |

**Spacemit X60 RISC-V without AES extensions:**

| Algorithm                                | Speed (Mb/s) |
| :--------------------------------------- | -----------: |
| AES-128-GCM (BoringSSL, bitsliced)       |          137 |
| AES-128-GCM (OpenSSL 3.3, _unprotected_) |          223 |
| AEGIS-128X2 (bitsliced)                  |          333 |
| AEGIS-128L (bitsliced)                   |          193 |
| AEGIS-128L (libaegis, _unprotected_)     |          198 |

**Sifive, u74-mc:**

| Algorithm                            | Speed (Mb/s) |
| :----------------------------------- | -----------: |
| AES-128-GCM (BoringSSL, bitsliced)   |          130 |
| AEGIS-128X2 (bitsliced)              |          311 |
| AEGIS-128L (bitsliced)               |          182 |
| AEGIS-128L (libaegis, _unprotected_) |          507 |

**WebAssembly (Apple M1, baseline+simd128):**

| Algorithm                            | Speed (Mb/s) |
| :----------------------------------- | -----------: |
| AES-128-GCM (boringssl, bitsliced)   |          480 |
| AES-128-GCM (zig, _unprotected_)     |         1040 |
| AEGIS-128X2 (bitsliced)              |         3154 |
| AEGIS-128L (bitsliced)               |         3429 |
| AEGIS-128L (libaegis, _unprotected_) |         4232 |

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

The state is kept in bitsliced form across initialization, associated data absorption, message processing, and finalization, so the update round can be applied without packing and unpacking the full state every time.

The keystream, a combination of AES blocks, is not evaluated by unpacking the full state. The implementation computes the required block expressions directly in the packed lanes, then applies a partial unpack only for the output block or blocks. Message input is packed only into the active input lanes before the next round. For a single lane, both conversions collapse into a closed form: bit-plane `k` of the byte-transposed block lands in plane word `k` at bit position 7, so injection is one mask and one shift per plane, and extraction is the mirrored OR-gather.

On targets with vector extensions, bulk associated data and message processing additionally runs in fused loops that keep the state in vector registers (or a hot local buffer, for the 64-bit doubled variants, whose working set exceeds the vector register file) instead of crossing the function-call and memory boundary once per block. For AEGIS-128L, where six of the eight blocks feed the keystream, the bulk loop works on the unpacked state — the round packs and unpacks its batch in registers — and converts from and to the packed resident state once per run.

These representation changes are costly. However, with 10 8-block AES rounds, AES-128 encrypts only 8 blocks, while AEGIS-128L encrypts 20. Additionally, AEGIS provides integrity with minimal overhead, while AES-GCM’s GMAC is costly, especially on CPUs without carryless multiplication support or lookup tables.

AEGIS-128X2 can be implemented using 64-bit words, or using two sets of 8 blocks updated alternately, offering a measurable speed advantage over AEGIS-128L on platforms such as WebAssembly and RISC-V, even with 32-bit words.

While a dedicated bitsliced representation could further improve performance, straightforward implementations using existing AES representations enable AEGIS to achieve strong performance with side-channel protection, even on CPUs lacking AES instructions.

In the barrel-shiftrows representation, the four 8-bit-plane groups go through identical, independent sbox circuits. On targets with vector extensions (SSE2, NEON, AltiVec, WebAssembly SIMD), these four groups are evaluated as the lanes of 4x32-bit vectors rather than relying on autovectorization. The state words are permuted so that the lane vectors are contiguous in memory and the AES round needs no transposes; the scalar code uses the same permuted layout.

On WebAssembly, the vector path requires the `simd128` target feature, for example `-Dcpu=lime1+simd128`.
With it, the bitsliced implementations run 2 to 3.3 times faster than the scalar code under wasmtime.
AEGIS-128L uses the packed-state bulk loop there instead of the unpacked one, since the per-block pack/unpack round-trip costs more than the closed-form lane crossings on that target.

These implementations use the SBOX circuits from [Maximov & Ekdahl](https://eprint.iacr.org/2019/802.pdf). A comparison against the circuits from [Jean, Baek, Kim G and Kim J](https://eprint.iacr.org/2024/1996.pdf) on Cortex A53 can be found below:

| Sbox circuit                     | AEGIS-128L speed (Mb/s) |
| :------------------------------- | ----------------------: |
| Maximov & Ekdahl                 |                  423.02 |
| depth16_RNBP28D_4AD_34NLs_81XORs |                  414.45 |
| jbkk2_RNBP41D_5AD_32NLs_97XORs   |                  410.53 |
| 32ANDs_BPD26D_6AD_32NLs_81XORs   |                  408.49 |
| depth16_BPD15D_4AD_34NLs_100XORs |                  405.76 |
| 32ANDs_BPD18D_6AD_32NLs_93XORs   |                  402.95 |
| jbkk2_BPD19D_5AD_32NLs_122XORs   |                  401.25 |
| jbkk3_RNBP41D_4AD_33NLs_102XORs  |                  400.72 |
| jbkk2_BPD17D_5AD_32NLs_142XORs   |                  395.75 |
| jbkk3_BPD16D_4AD_33NLs_154XORs   |                  376.64 |

Lastly, side-channel protection is generally unnecessary during decryption, as an adversary cannot observe individual blocks or conduct differential attacks at that stage.

## Building

```sh
zig build -Drelease=true
```

This builds a static `aegis` library along with its headers into `zig-out/`, as well as a `benchmark` executable. Add `-Dno-vector-sbox=true` to force the scalar sbox implementation on platforms with vector extensions. The test suite runs with `zig build test -Drelease=true`.
