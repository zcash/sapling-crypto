use byteorder::{ByteOrder, LittleEndian};
use ff::{BitIterator, Field, PrimeField, PrimeFieldDecodingError, PrimeFieldRepr};

use super::ToUniform;

#[derive(PrimeField)]
#[PrimeFieldModulus = "6554484396890773809930967563523245729705921265872317281365359162392183254199"]
#[PrimeFieldGenerator = "6"]
pub struct Fs(FsRepr);

impl Fs {
    fn mul_bits<S: AsRef<[u64]>>(&self, bits: BitIterator<S>) -> Self {
        let mut res = Self::zero();
        for bit in bits {
            res.double();

            if bit {
                res.add_assign(self)
            }
        }
        res
    }
}

impl ToUniform for Fs {
    /// Convert a little endian byte string into a uniform
    /// field element. The number is reduced mod s. The caller
    /// is responsible for ensuring the input is 64 bytes of
    /// Random Oracle output.
    fn to_uniform(digest: &[u8]) -> Self {
        assert_eq!(digest.len(), 64);
        let mut repr: [u64; 8] = [0; 8];
        LittleEndian::read_u64_into(digest, &mut repr);
        Self::one().mul_bits(BitIterator::new(repr))
    }
}

// -((2**256) mod s) mod s
#[cfg(test)]
const NEGATIVE_ONE: Fs = Fs(FsRepr([
    0xaa9f02ab1d6124de,
    0xb3524a6466112932,
    0x7342261215ac260b,
    0x4d6b87b1da259e2,
]));

#[test]
fn test_neg_one() {
    let mut o = Fs::one();
    o.negate();

    assert_eq!(NEGATIVE_ONE, o);
}

#[cfg(test)]
use ff::LegendreSymbol::*;
#[cfg(test)]
use ff::SqrtField;
#[cfg(test)]
use rand::{Rand, SeedableRng, XorShiftRng};

#[test]
fn test_fs_repr_ordering() {
    fn assert_equality(a: FsRepr, b: FsRepr) {
        assert_eq!(a, b);
        assert!(a.cmp(&b) == ::std::cmp::Ordering::Equal);
    }

    fn assert_lt(a: FsRepr, b: FsRepr) {
        assert!(a < b);
        assert!(b > a);
    }

    assert_equality(
        FsRepr([9999, 9999, 9999, 9999]),
        FsRepr([9999, 9999, 9999, 9999]),
    );
    assert_equality(
        FsRepr([9999, 9998, 9999, 9999]),
        FsRepr([9999, 9998, 9999, 9999]),
    );
    assert_equality(
        FsRepr([9999, 9999, 9999, 9997]),
        FsRepr([9999, 9999, 9999, 9997]),
    );
    assert_lt(
        FsRepr([9999, 9997, 9999, 9998]),
        FsRepr([9999, 9997, 9999, 9999]),
    );
    assert_lt(
        FsRepr([9999, 9997, 9998, 9999]),
        FsRepr([9999, 9997, 9999, 9999]),
    );
    assert_lt(
        FsRepr([9, 9999, 9999, 9997]),
        FsRepr([9999, 9999, 9999, 9997]),
    );
}

#[test]
fn test_fs_repr_from() {
    assert_eq!(FsRepr::from(100), FsRepr([100, 0, 0, 0]));
}

#[test]
fn test_fs_repr_is_odd() {
    assert!(!FsRepr::from(0).is_odd());
    assert!(FsRepr::from(0).is_even());
    assert!(FsRepr::from(1).is_odd());
    assert!(!FsRepr::from(1).is_even());
    assert!(!FsRepr::from(324834872).is_odd());
    assert!(FsRepr::from(324834872).is_even());
    assert!(FsRepr::from(324834873).is_odd());
    assert!(!FsRepr::from(324834873).is_even());
}

#[test]
fn test_fs_repr_is_zero() {
    assert!(FsRepr::from(0).is_zero());
    assert!(!FsRepr::from(1).is_zero());
    assert!(!FsRepr([0, 0, 1, 0]).is_zero());
}

#[test]
fn test_fs_repr_div2() {
    let mut a = FsRepr([
        0xbd2920b19c972321,
        0x174ed0466a3be37e,
        0xd468d5e3b551f0b5,
        0xcb67c072733beefc,
    ]);
    a.div2();
    assert_eq!(
        a,
        FsRepr([
            0x5e949058ce4b9190,
            0x8ba76823351df1bf,
            0x6a346af1daa8f85a,
            0x65b3e039399df77e
        ])
    );
    for _ in 0..10 {
        a.div2();
    }
    assert_eq!(
        a,
        FsRepr([
            0x6fd7a524163392e4,
            0x16a2e9da08cd477c,
            0xdf9a8d1abc76aa3e,
            0x196cf80e4e677d
        ])
    );
    for _ in 0..200 {
        a.div2();
    }
    assert_eq!(a, FsRepr([0x196cf80e4e67, 0x0, 0x0, 0x0]));
    for _ in 0..40 {
        a.div2();
    }
    assert_eq!(a, FsRepr([0x19, 0x0, 0x0, 0x0]));
    for _ in 0..4 {
        a.div2();
    }
    assert_eq!(a, FsRepr([0x1, 0x0, 0x0, 0x0]));
    a.div2();
    assert!(a.is_zero());
}

#[test]
fn test_fs_repr_shr() {
    let mut a = FsRepr([
        0xb33fbaec482a283f,
        0x997de0d3a88cb3df,
        0x9af62d2a9a0e5525,
        0x36003ab08de70da1,
    ]);
    a.shr(0);
    assert_eq!(
        a,
        FsRepr([
            0xb33fbaec482a283f,
            0x997de0d3a88cb3df,
            0x9af62d2a9a0e5525,
            0x36003ab08de70da1
        ])
    );
    a.shr(1);
    assert_eq!(
        a,
        FsRepr([
            0xd99fdd762415141f,
            0xccbef069d44659ef,
            0xcd7b16954d072a92,
            0x1b001d5846f386d0
        ])
    );
    a.shr(50);
    assert_eq!(
        a,
        FsRepr([
            0xbc1a7511967bf667,
            0xc5a55341caa4b32f,
            0x75611bce1b4335e,
            0x6c0
        ])
    );
    a.shr(130);
    assert_eq!(a, FsRepr([0x1d5846f386d0cd7, 0x1b0, 0x0, 0x0]));
    a.shr(64);
    assert_eq!(a, FsRepr([0x1b0, 0x0, 0x0, 0x0]));
}

#[test]
fn test_fs_repr_mul2() {
    let mut a = FsRepr::from(23712937547);
    a.mul2();
    assert_eq!(a, FsRepr([0xb0acd6c96, 0x0, 0x0, 0x0]));
    for _ in 0..60 {
        a.mul2();
    }
    assert_eq!(a, FsRepr([0x6000000000000000, 0xb0acd6c9, 0x0, 0x0]));
    for _ in 0..128 {
        a.mul2();
    }
    assert_eq!(a, FsRepr([0x0, 0x0, 0x6000000000000000, 0xb0acd6c9]));
    for _ in 0..60 {
        a.mul2();
    }
    assert_eq!(a, FsRepr([0x0, 0x0, 0x0, 0x9600000000000000]));
    for _ in 0..7 {
        a.mul2();
    }
    assert!(a.is_zero());
}

#[test]
fn test_fs_repr_num_bits() {
    let mut a = FsRepr::from(0);
    assert_eq!(0, a.num_bits());
    a = FsRepr::from(1);
    for i in 1..257 {
        assert_eq!(i, a.num_bits());
        a.mul2();
    }
    assert_eq!(0, a.num_bits());
}

#[test]
fn test_fs_repr_sub_noborrow() {
    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    let mut t = FsRepr([
        0x8e62a7e85264e2c3,
        0xb23d34c1941d3ca,
        0x5976930b7502dd15,
        0x600f3fb517bf5495,
    ]);
    t.sub_noborrow(&FsRepr([
        0xd64f669809cbc6a4,
        0xfa76cb9d90cf7637,
        0xfefb0df9038d43b3,
        0x298a30c744b31acf,
    ]));
    assert!(
        t == FsRepr([
            0xb813415048991c1f,
            0x10ad07ae88725d92,
            0x5a7b851271759961,
            0x36850eedd30c39c5
        ])
    );

    for _ in 0..1000 {
        let mut a = FsRepr::rand(&mut rng);
        a.0[3] >>= 30;
        let mut b = a;
        for _ in 0..10 {
            b.mul2();
        }
        let mut c = b;
        for _ in 0..10 {
            c.mul2();
        }

        assert!(a < b);
        assert!(b < c);

        let mut csub_ba = c;
        csub_ba.sub_noborrow(&b);
        csub_ba.sub_noborrow(&a);

        let mut csub_ab = c;
        csub_ab.sub_noborrow(&a);
        csub_ab.sub_noborrow(&b);

        assert_eq!(csub_ab, csub_ba);
    }
}

#[test]
fn test_fs_legendre() {
    assert_eq!(QuadraticResidue, Fs::one().legendre());
    assert_eq!(Zero, Fs::zero().legendre());

    let e = FsRepr([
        0x8385eec23df1f88e,
        0x9a01fb412b2dba16,
        0x4c928edcdd6c22f,
        0x9f2df7ef69ecef9,
    ]);
    assert_eq!(QuadraticResidue, Fs::from_repr(e).unwrap().legendre());
    let e = FsRepr([
        0xe8ed9f299da78568,
        0x35efdebc88b2209,
        0xc82125cb1f916dbe,
        0x6813d2b38c39bd0,
    ]);
    assert_eq!(QuadraticNonResidue, Fs::from_repr(e).unwrap().legendre());
}

#[test]
fn test_fr_repr_add_nocarry() {
    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    let mut t = FsRepr([
        0xd64f669809cbc6a4,
        0xfa76cb9d90cf7637,
        0xfefb0df9038d43b3,
        0x298a30c744b31acf,
    ]);
    t.add_nocarry(&FsRepr([
        0x8e62a7e85264e2c3,
        0xb23d34c1941d3ca,
        0x5976930b7502dd15,
        0x600f3fb517bf5495,
    ]));
    assert_eq!(
        t,
        FsRepr([
            0x64b20e805c30a967,
            0x59a9ee9aa114a02,
            0x5871a104789020c9,
            0x8999707c5c726f65
        ])
    );

    // Test for the associativity of addition.
    for _ in 0..1000 {
        let mut a = FsRepr::rand(&mut rng);
        let mut b = FsRepr::rand(&mut rng);
        let mut c = FsRepr::rand(&mut rng);

        // Unset the first few bits, so that overflow won't occur.
        a.0[3] >>= 3;
        b.0[3] >>= 3;
        c.0[3] >>= 3;

        let mut abc = a;
        abc.add_nocarry(&b);
        abc.add_nocarry(&c);

        let mut acb = a;
        acb.add_nocarry(&c);
        acb.add_nocarry(&b);

        let mut bac = b;
        bac.add_nocarry(&a);
        bac.add_nocarry(&c);

        let mut bca = b;
        bca.add_nocarry(&c);
        bca.add_nocarry(&a);

        let mut cab = c;
        cab.add_nocarry(&a);
        cab.add_nocarry(&b);

        let mut cba = c;
        cba.add_nocarry(&b);
        cba.add_nocarry(&a);

        assert_eq!(abc, acb);
        assert_eq!(abc, bac);
        assert_eq!(abc, bca);
        assert_eq!(abc, cab);
        assert_eq!(abc, cba);
    }
}

#[test]
fn test_fs_is_valid() {
    let mut a = Fs(MODULUS);
    assert!(!a.is_valid());
    a.0.sub_noborrow(&FsRepr::from(1));
    assert!(a.is_valid());
    assert!(Fs(FsRepr::from(0)).is_valid());
    assert!(Fs(FsRepr([
        0xd0970e5ed6f72cb6,
        0xa6682093ccc81082,
        0x6673b0101343b00,
        0xe7db4ea6533afa9
    ]))
    .is_valid());
    assert!(!Fs(FsRepr([
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff
    ]))
    .is_valid());

    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    for _ in 0..1000 {
        let a = Fs::rand(&mut rng);
        assert!(a.is_valid());
    }
}

#[test]
fn test_fs_add_assign() {
    {
        // Random number
        let mut tmp = Fs::from_str(
            "4577408157467272683998459759522778614363623736323078995109579213719612604198",
        )
        .unwrap();
        assert!(tmp.is_valid());
        // Test that adding zero has no effect.
        tmp.add_assign(&Fs(FsRepr::from(0)));
        assert_eq!(
            tmp,
            Fs(FsRepr([
                0x8e6bfff4722d6e67,
                0x5643da5c892044f9,
                0x9465f4b281921a69,
                0x25f752d3edd7162
            ]))
        );
        // Add one and test for the result.
        tmp.add_assign(&Fs(FsRepr::from(1)));
        assert_eq!(
            tmp,
            Fs(FsRepr([
                0x8e6bfff4722d6e68,
                0x5643da5c892044f9,
                0x9465f4b281921a69,
                0x25f752d3edd7162
            ]))
        );
        // Add another random number that exercises the reduction.
        tmp.add_assign(&Fs(FsRepr([
            0xb634d07bc42d4a70,
            0xf724f0c008411f5f,
            0x456d4053d865af34,
            0x24ce814e8c63027,
        ])));
        assert_eq!(
            tmp,
            Fs(FsRepr([
                0x44a0d070365ab8d8,
                0x4d68cb1c91616459,
                0xd9d3350659f7c99e,
                0x4ac5d4227a3a189
            ]))
        );
        // Add one to (s - 1) and test for the result.
        tmp = Fs(FsRepr([
            0xd0970e5ed6f72cb6,
            0xa6682093ccc81082,
            0x6673b0101343b00,
            0xe7db4ea6533afa9,
        ]));
        tmp.add_assign(&Fs(FsRepr::from(1)));
        assert!(tmp.0.is_zero());
        // Add a random number to another one such that the result is s - 1
        tmp = Fs(FsRepr([
            0xa11fda5950ce3636,
            0x922e0dbccfe0ca0e,
            0xacebb6e215b82d4a,
            0x97ffb8cdc3aee93,
        ]));
        tmp.add_assign(&Fs(FsRepr([
            0x2f7734058628f680,
            0x143a12d6fce74674,
            0x597b841eeb7c0db6,
            0x4fdb95d88f8c115,
        ])));
        assert_eq!(
            tmp,
            Fs(FsRepr([
                0xd0970e5ed6f72cb6,
                0xa6682093ccc81082,
                0x6673b0101343b00,
                0xe7db4ea6533afa9
            ]))
        );
        // Add one to the result and test for it.
        tmp.add_assign(&Fs(FsRepr::from(1)));
        assert!(tmp.0.is_zero());
    }

    // Test associativity

    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    for _ in 0..1000 {
        // Generate a, b, c and ensure (a + b) + c == a + (b + c).
        let a = Fs::rand(&mut rng);
        let b = Fs::rand(&mut rng);
        let c = Fs::rand(&mut rng);

        let mut tmp1 = a;
        tmp1.add_assign(&b);
        tmp1.add_assign(&c);

        let mut tmp2 = b;
        tmp2.add_assign(&c);
        tmp2.add_assign(&a);

        assert!(tmp1.is_valid());
        assert!(tmp2.is_valid());
        assert_eq!(tmp1, tmp2);
    }
}

#[test]
fn test_fs_sub_assign() {
    {
        // Test arbitrary subtraction that tests reduction.
        let mut tmp = Fs(FsRepr([
            0xb384d9f6877afd99,
            0x4442513958e1a1c1,
            0x352c4b8a95eccc3f,
            0x2db62dee4b0f2,
        ]));
        tmp.sub_assign(&Fs(FsRepr([
            0xec5bd2d13ed6b05a,
            0x2adc0ab3a39b5fa,
            0x82d3360a493e637e,
            0x53ccff4a64d6679,
        ])));
        assert_eq!(
            tmp,
            Fs(FsRepr([
                0x97c015841f9b79f6,
                0xe7fcb121eb6ffc49,
                0xb8c050814de2a3c1,
                0x943c0589dcafa21
            ]))
        );

        // Test the opposite subtraction which doesn't test reduction.
        tmp = Fs(FsRepr([
            0xec5bd2d13ed6b05a,
            0x2adc0ab3a39b5fa,
            0x82d3360a493e637e,
            0x53ccff4a64d6679,
        ]));
        tmp.sub_assign(&Fs(FsRepr([
            0xb384d9f6877afd99,
            0x4442513958e1a1c1,
            0x352c4b8a95eccc3f,
            0x2db62dee4b0f2,
        ])));
        assert_eq!(
            tmp,
            Fs(FsRepr([
                0x38d6f8dab75bb2c1,
                0xbe6b6f71e1581439,
                0x4da6ea7fb351973e,
                0x539f491c768b587
            ]))
        );

        // Test for sensible results with zero
        tmp = Fs(FsRepr::from(0));
        tmp.sub_assign(&Fs(FsRepr::from(0)));
        assert!(tmp.is_zero());

        tmp = Fs(FsRepr([
            0x361e16aef5cce835,
            0x55bbde2536e274c1,
            0x4dc77a63fd15ee75,
            0x1e14bb37c14f230,
        ]));
        tmp.sub_assign(&Fs(FsRepr::from(0)));
        assert_eq!(
            tmp,
            Fs(FsRepr([
                0x361e16aef5cce835,
                0x55bbde2536e274c1,
                0x4dc77a63fd15ee75,
                0x1e14bb37c14f230
            ]))
        );
    }

    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    for _ in 0..1000 {
        // Ensure that (a - b) + (b - a) = 0.
        let a = Fs::rand(&mut rng);
        let b = Fs::rand(&mut rng);

        let mut tmp1 = a;
        tmp1.sub_assign(&b);

        let mut tmp2 = b;
        tmp2.sub_assign(&a);

        tmp1.add_assign(&tmp2);
        assert!(tmp1.is_zero());
    }
}

#[test]
fn test_fs_mul_assign() {
    let mut tmp = Fs(FsRepr([
        0xb433b01287f71744,
        0x4eafb86728c4d108,
        0xfdd52c14b9dfbe65,
        0x2ff1f3434821118,
    ]));
    tmp.mul_assign(&Fs(FsRepr([
        0xdae00fc63c9fa90f,
        0x5a5ed89b96ce21ce,
        0x913cd26101bd6f58,
        0x3f0822831697fe9,
    ])));
    assert!(
        tmp == Fs(FsRepr([
            0xb68ecb61d54d2992,
            0x5ff95874defce6a6,
            0x3590eb053894657d,
            0x53823a118515933
        ]))
    );

    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    for _ in 0..1000000 {
        // Ensure that (a * b) * c = a * (b * c)
        let a = Fs::rand(&mut rng);
        let b = Fs::rand(&mut rng);
        let c = Fs::rand(&mut rng);

        let mut tmp1 = a;
        tmp1.mul_assign(&b);
        tmp1.mul_assign(&c);

        let mut tmp2 = b;
        tmp2.mul_assign(&c);
        tmp2.mul_assign(&a);

        assert_eq!(tmp1, tmp2);
    }

    for _ in 0..1000000 {
        // Ensure that r * (a + b + c) = r*a + r*b + r*c

        let r = Fs::rand(&mut rng);
        let mut a = Fs::rand(&mut rng);
        let mut b = Fs::rand(&mut rng);
        let mut c = Fs::rand(&mut rng);

        let mut tmp1 = a;
        tmp1.add_assign(&b);
        tmp1.add_assign(&c);
        tmp1.mul_assign(&r);

        a.mul_assign(&r);
        b.mul_assign(&r);
        c.mul_assign(&r);

        a.add_assign(&b);
        a.add_assign(&c);

        assert_eq!(tmp1, a);
    }
}

#[test]
fn test_fr_squaring() {
    let mut a = Fs(FsRepr([
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xe7db4ea6533afa8,
    ]));
    assert!(a.is_valid());
    a.square();
    assert_eq!(
        a,
        Fs::from_repr(FsRepr([
            0x12c7f55cbc52fbaa,
            0xdedc98a0b5e6ce9e,
            0xad2892726a5396a,
            0x9fe82af8fee77b3
        ]))
        .unwrap()
    );

    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    for _ in 0..1000000 {
        // Ensure that (a * a) = a^2
        let a = Fs::rand(&mut rng);

        let mut tmp = a;
        tmp.square();

        let mut tmp2 = a;
        tmp2.mul_assign(&a);

        assert_eq!(tmp, tmp2);
    }
}

#[test]
fn test_fs_inverse() {
    assert!(Fs::zero().inverse().is_none());

    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    let one = Fs::one();

    for _ in 0..1000 {
        // Ensure that a * a^-1 = 1
        let mut a = Fs::rand(&mut rng);
        let ainv = a.inverse().unwrap();
        a.mul_assign(&ainv);
        assert_eq!(a, one);
    }
}

#[test]
fn test_fs_double() {
    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    for _ in 0..1000 {
        // Ensure doubling a is equivalent to adding a to itself.
        let mut a = Fs::rand(&mut rng);
        let mut b = a;
        b.add_assign(&a);
        a.double();
        assert_eq!(a, b);
    }
}

#[test]
fn test_fs_negate() {
    {
        let mut a = Fs::zero();
        a.negate();

        assert!(a.is_zero());
    }

    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    for _ in 0..1000 {
        // Ensure (a - (-a)) = 0.
        let mut a = Fs::rand(&mut rng);
        let mut b = a;
        b.negate();
        a.add_assign(&b);

        assert!(a.is_zero());
    }
}

#[test]
fn test_fs_pow() {
    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    for i in 0..1000 {
        // Exponentiate by various small numbers and ensure it consists with repeated
        // multiplication.
        let a = Fs::rand(&mut rng);
        let target = a.pow(&[i]);
        let mut c = Fs::one();
        for _ in 0..i {
            c.mul_assign(&a);
        }
        assert_eq!(c, target);
    }

    for _ in 0..1000 {
        // Exponentiating by the modulus should have no effect in a prime field.
        let a = Fs::rand(&mut rng);

        assert_eq!(a, a.pow(Fs::char()));
    }
}

#[test]
fn test_fs_sqrt() {
    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    assert_eq!(Fs::zero().sqrt().unwrap(), Fs::zero());

    for _ in 0..1000 {
        // Ensure sqrt(a^2) = a or -a
        let a = Fs::rand(&mut rng);
        let mut nega = a;
        nega.negate();
        let mut b = a;
        b.square();

        let b = b.sqrt().unwrap();

        assert!(a == b || nega == b);
    }

    for _ in 0..1000 {
        // Ensure sqrt(a)^2 = a for random a
        let a = Fs::rand(&mut rng);

        if let Some(mut tmp) = a.sqrt() {
            tmp.square();

            assert_eq!(a, tmp);
        }
    }
}

#[test]
fn test_fs_from_into_repr() {
    // r + 1 should not be in the field
    assert!(Fs::from_repr(FsRepr([
        0xd0970e5ed6f72cb8,
        0xa6682093ccc81082,
        0x6673b0101343b00,
        0xe7db4ea6533afa9
    ]))
    .is_err());

    // r should not be in the field
    assert!(Fs::from_repr(Fs::char()).is_err());

    // Multiply some arbitrary representations to see if the result is as expected.
    let a = FsRepr([
        0x5f2d0c05d0337b71,
        0xa1df2b0f8a20479,
        0xad73785e71bb863,
        0x504a00480c9acec,
    ]);
    let mut a_fs = Fs::from_repr(a).unwrap();
    let b = FsRepr([
        0x66356ff51e477562,
        0x60a92ab55cf7603,
        0x8e4273c7364dd192,
        0x36df8844a344dc5,
    ]);
    let b_fs = Fs::from_repr(b).unwrap();
    let c = FsRepr([
        0x7eef61708f4f2868,
        0x747a7e6cf52946fb,
        0x83dd75d7c9120017,
        0x762f5177f0f3df7,
    ]);
    a_fs.mul_assign(&b_fs);
    assert_eq!(a_fs.into_repr(), c);

    // Zero should be in the field.
    assert!(Fs::from_repr(FsRepr::from(0)).unwrap().is_zero());

    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    for _ in 0..1000 {
        // Try to turn Fs elements into representations and back again, and compare.
        let a = Fs::rand(&mut rng);
        let a_repr = a.into_repr();
        let b_repr = FsRepr::from(a);
        assert_eq!(a_repr, b_repr);
        let a_again = Fs::from_repr(a_repr).unwrap();

        assert_eq!(a, a_again);
    }
}

#[test]
fn test_fs_repr_display() {
    assert_eq!(
        format!(
            "{}",
            FsRepr([
                0xa296db59787359df,
                0x8d3e33077430d318,
                0xd1abf5c606102eb7,
                0xcbc33ee28108f0
            ])
        ),
        "0x00cbc33ee28108f0d1abf5c606102eb78d3e33077430d318a296db59787359df".to_string()
    );
    assert_eq!(
        format!(
            "{}",
            FsRepr([
                0x14cb03535054a620,
                0x312aa2bf2d1dff52,
                0x970fe98746ab9361,
                0xc1e18acf82711e6
            ])
        ),
        "0x0c1e18acf82711e6970fe98746ab9361312aa2bf2d1dff5214cb03535054a620".to_string()
    );
    assert_eq!(
        format!(
            "{}",
            FsRepr([
                0xffffffffffffffff,
                0xffffffffffffffff,
                0xffffffffffffffff,
                0xffffffffffffffff
            ])
        ),
        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string()
    );
    assert_eq!(
        format!("{}", FsRepr([0, 0, 0, 0])),
        "0x0000000000000000000000000000000000000000000000000000000000000000".to_string()
    );
}

#[test]
fn test_fs_display() {
    assert_eq!(
        format!(
            "{}",
            Fs::from_repr(FsRepr([
                0x5528efb9998a01a3,
                0x5bd2add5cb357089,
                0xc061fa6adb491f98,
                0x70db9d143db03d9
            ]))
            .unwrap()
        ),
        "Fs(0x070db9d143db03d9c061fa6adb491f985bd2add5cb3570895528efb9998a01a3)".to_string()
    );
    assert_eq!(
        format!(
            "{}",
            Fs::from_repr(FsRepr([
                0xd674745e2717999e,
                0xbeb1f52d3e96f338,
                0x9c7ae147549482b9,
                0x999706024530d22
            ]))
            .unwrap()
        ),
        "Fs(0x0999706024530d229c7ae147549482b9beb1f52d3e96f338d674745e2717999e)".to_string()
    );
}

#[test]
fn test_fs_num_bits() {
    assert_eq!(Fs::NUM_BITS, 252);
    assert_eq!(Fs::CAPACITY, 251);
}

#[test]
fn test_fs_root_of_unity() {
    assert_eq!(Fs::S, 1);
    assert_eq!(
        Fs::multiplicative_generator(),
        Fs::from_repr(FsRepr::from(6)).unwrap()
    );
    assert_eq!(
        Fs::multiplicative_generator().pow([
            0x684b872f6b7b965b,
            0x53341049e6640841,
            0x83339d80809a1d80,
            0x73eda753299d7d4
        ]),
        Fs::root_of_unity()
    );
    assert_eq!(Fs::root_of_unity().pow([1 << Fs::S]), Fs::one());
    assert!(Fs::multiplicative_generator().sqrt().is_none());
}
