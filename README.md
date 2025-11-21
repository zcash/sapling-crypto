# sapling-crypto

This repository contains an implementation of Zcash's "Sapling" cryptography.

## `no_std` compatibility

In order to take advantage of `no_std` builds, downstream users of this crate
must enable:

* the `spin_no_std` feature of the `lazy_static` crate; and
* the `no_std` feature of the `typenum` crate.

This is needed because the `--no-default-features` builds of these crates still
rely on `std`.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
