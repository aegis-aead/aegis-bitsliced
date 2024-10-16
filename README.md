# Bitsliced AEGIS

Protected implementations of the AEGIS authentication algorithms for platforms without hardware AES support.

Side channels are mitigated by using the [barrel-shiftrows](https://eprint.iacr.org/2020/1123.pdf) bitsliced representation recently introduced by Alexandre Adomnicai and Thomas Peyrin, that turns out to be a good fit for all AEGIS-128* variants as well as AEGIS-256X4.

Using this representation, AEGIS-128L appears to be consistently about 60% faster than fixliced AES128-GCM. With 64 bit registers, AEGIS-128X2 is expected to be twice as fast as AEGIS-128L.
