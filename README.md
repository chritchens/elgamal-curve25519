# elgamal-curve25519

[![Travis branch](https://img.shields.io/travis/chritchens/elgamal-curve25519/master.svg)](https://travis-ci.org/chritchens/elgamal-curve25519)
[![Coveralls github branch](https://img.shields.io/coveralls/github/chritchens/elgamal-curve25519/master.svg)](https://coveralls.io/github/chritchens/elgamal-curve25519?branch=master)
![License](https://img.shields.io/badge/License-MIT%2FApache--2.0-blue.svg)

ElGamal homomorphic encryption on Curve25519.


*NOTES*:

- The API may change (error management, more options on the homomorphic side, idk).
- `nightly` only to ensure some level of constant-time-ness. More info [here](https://github.com/dalek-cryptography/subtle) and [here](https://www.chosenplaintext.ca/open-source/rust-timing-shield/security).

## Install

To install the library add in your Cargo.toml:

```toml
# Cargo.toml

[dependencies]
elgamal-curve25519 = "0.1"
```

## Usage

To use the library just add in the root of your crate:

```rust
// root_file_name.rs

extern crate elgamal_curve25519; // old style
// or just use `use`, which can be used in any file of your project
use elgamal_curve25519; // new style
```

At the moment see the tests for more information on how to use it in practice.

## License

This project is license under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

## Contributing

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in elgamal-curve25519 by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
