# Bitsliced AEGIS

Protected implementations of the [AEGIS authenticated encryption algorithms](https://cfrg.github.io/draft-irtf-cfrg-aegis-aead/draft-irtf-cfrg-aegis-aead.html) for platforms without hardware AES support.

Side channels are mitigated by using the [barrel-shiftrows](https://eprint.iacr.org/2020/1123.pdf) bitsliced representation recently introduced by Alexandre Adomnicai and Thomas Peyrin, that turns out to be a good fit for all AEGIS-128* variants.

Using this representation, AEGIS-128L is consistently faster than AES128-GCM.

ARM Cortex A53

| Algorithm                 | Speed (Mb/s) |
| :------------------------ | -----------: |
| AES-128-GCM (OpenSSL 3.3) |          129 |
| AEGIS-128L (bitsliced)    |          210 |
| AEGIS-128L (unprotected)  |          427 |
