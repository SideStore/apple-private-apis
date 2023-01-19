# RustCrypto: PAKEs [![dependency status][deps-image]][deps-link]
[Password-Authenticated Key Agreement][1] protocols implementation.

## Warnings

Crates in this repository have not yet received any formal cryptographic and
security reviews.

No efforts were yet taken in regards of [blinding][3] or erasing secrets from
the memory.

**USE AT YOUR OWN RISK.**

## Supported algorithms

| Name      | Crates.io  | Documentation  |
| --------- |:----------:| :-----:|
| [SRP][2]  | [![crates.io](https://img.shields.io/crates/v/srp.svg)](https://crates.io/crates/srp) | [![Documentation](https://docs.rs/srp/badge.svg)](https://docs.rs/srp) |
| [spake2][4]  | [![crates.io](https://img.shields.io/crates/v/spake2.svg)](https://crates.io/crates/spake2) | [![Documentation](https://docs.rs/spake2/badge.svg)](https://docs.rs/spake2) |

## License

All crates are licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[deps-image]: https://deps.rs/repo/github/RustCrypto/PAKEs/status.svg
[deps-link]: https://deps.rs/repo/github/RustCrypto/PAKEs

[//]: # (footnotes)

[1]: https://en.wikipedia.org/wiki/Password-authenticated_key_agreement
[2]: https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol
[3]: https://en.wikipedia.org/wiki/Blinding_(cryptography)
[4]: https://www.di.ens.fr/~mabdalla/papers/AbPo05a-letter.pdf
