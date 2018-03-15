use pairing::{
    Engine,
    Field,
    PrimeField
};

use bellman::{
    SynthesisError,
    ConstraintSystem,
    LinearCombination,
    Variable
};

use super::boolean::{
    Boolean,
    AllocatedBit
};

/// Represents an interpretation of 32 `Boolean` objects as an
/// unsigned integer.
#[derive(Clone)]
pub struct UInt32 {
    // Least significant bit first
    bits: Vec<Boolean>,
    value: Option<u32>
}

impl UInt32 {
    /// Construct a constant `UInt32` from a `u32`
    pub fn constant(value: u32) -> Self
    {
        let mut bits = Vec::with_capacity(32);

        let mut tmp = value;
        for _ in 0..32 {
            if tmp & 1 == 1 {
                bits.push(Boolean::constant(true))
            } else {
                bits.push(Boolean::constant(false))
            }

            tmp >>= 1;
        }

        UInt32 {
            bits: bits,
            value: Some(value)
        }
    }

    /// Allocate a `UInt32` in the constraint system
    pub fn alloc<E, CS>(
        mut cs: CS,
        value: Option<u32>
    ) -> Result<Self, SynthesisError>
        where E: Engine,
              CS: ConstraintSystem<E>
    {
        let values = match value {
            Some(mut val) => {
                let mut v = Vec::with_capacity(32);

                for _ in 0..32 {
                    v.push(Some(val & 1 == 1));
                    val >>= 1;
                }

                v
            },
            None => vec![None; 32]
        };

        let bits = values.into_iter()
                         .enumerate()
                         .map(|(i, v)| {
                            Ok(Boolean::from(AllocatedBit::alloc(
                                cs.namespace(|| format!("allocated bit {}", i)),
                                v
                            )?))
                         })
                         .collect::<Result<Vec<_>, SynthesisError>>()?;

        Ok(UInt32 {
            bits: bits,
            value: value
        })
    }

    pub fn into_bits_be(&self) -> Vec<Boolean> {
        self.bits.iter().rev().cloned().collect()
    }

    pub fn from_bits_be(bits: &[Boolean]) -> Self {
        assert_eq!(bits.len(), 32);

        let mut value = Some(0u32);
        for b in bits {
            value.as_mut().map(|v| *v <<= 1);

            match b.get_value() {
                Some(true) => { value.as_mut().map(|v| *v |= 1); },
                Some(false) => {},
                None => { value = None; }
            }
        }

        UInt32 {
            value: value,
            bits: bits.iter().rev().cloned().collect()
        }
    }

    /// Turns this `UInt32` into its little-endian byte order representation.
    pub fn into_bits(&self) -> Vec<Boolean> {
        self.bits.chunks(8)
                 .flat_map(|v| v.iter().rev())
                 .cloned()
                 .collect()
    }

    /// Converts a little-endian byte order representation of bits into a
    /// `UInt32`.
    pub fn from_bits(bits: &[Boolean]) -> Self
    {
        assert_eq!(bits.len(), 32);

        let new_bits = bits.chunks(8)
                           .flat_map(|v| v.iter().rev())
                           .cloned()
                           .collect::<Vec<_>>();

        let mut value = Some(0u32);
        for b in new_bits.iter().rev() {
            value.as_mut().map(|v| *v <<= 1);

            match b {
                &Boolean::Constant(b) => {
                    if b {
                        value.as_mut().map(|v| *v |= 1);
                    }
                },
                &Boolean::Is(ref b) => {
                    match b.get_value() {
                        Some(true) => { value.as_mut().map(|v| *v |= 1); },
                        Some(false) => {},
                        None => { value = None }
                    }
                },
                &Boolean::Not(ref b) => {
                    match b.get_value() {
                        Some(false) => { value.as_mut().map(|v| *v |= 1); },
                        Some(true) => {},
                        None => { value = None }
                    }
                }
            }
        }

        UInt32 {
            value: value,
            bits: new_bits
        }
    }

    pub fn shr(&self, by: usize) -> Self {
        let by = by % 32;

        let fill = Boolean::constant(false);

        let new_bits = self.bits
                           .iter() // The bits are least significant first
                           .skip(by) // Skip the bits that will be lost during the shift
                           .chain(Some(&fill).into_iter().cycle()) // Rest will be zeros
                           .take(32) // Only 32 bits needed!
                           .cloned()
                           .collect();

        UInt32 {
            bits: new_bits,
            value: self.value.map(|v| v >> by as u32)
        }
    }

    pub fn rotr(&self, by: usize) -> Self {
        let by = by % 32;

        let new_bits = self.bits.iter()
                                .skip(by)
                                .chain(self.bits.iter())
                                .take(32)
                                .cloned()
                                .collect();

        UInt32 {
            bits: new_bits,
            value: self.value.map(|v| v.rotate_right(by as u32))
        }
    }

    /// Compute the `maj` value (a and b) xor (a and c) xor (b and c)
    /// during SHA256.
    pub fn sha256_maj<E, CS>(
        cs: CS,
        a: &Self,
        b: &Self,
        c: &Self
    ) -> Result<Self, SynthesisError>
        where E: Engine,
              CS: ConstraintSystem<E>
    {
        Self::triop(cs, a, b, c, |a, b, c| (a & b) ^ (a & c) ^ (b & c),
            |cs, i, a, b, c| {
                Boolean::sha256_maj(
                    cs.namespace(|| format!("maj {}", i)),
                    a,
                    b,
                    c
                )
            }
        )
    }

    /// Compute the `ch` value `(a and b) xor ((not a) and c)`
    /// during SHA256.
    pub fn sha256_ch<E, CS>(
        cs: CS,
        a: &Self,
        b: &Self,
        c: &Self
    ) -> Result<Self, SynthesisError>
        where E: Engine,
              CS: ConstraintSystem<E>
    {
        Self::triop(cs, a, b, c, |a, b, c| (a & b) ^ ((!a) & c),
            |cs, i, a, b, c| {
                Boolean::sha256_ch(
                    cs.namespace(|| format!("ch {}", i)),
                    a,
                    b,
                    c
                )
            }
        )
    }

    fn triop<E, CS, F, U>(
        mut cs: CS,
        a: &Self,
        b: &Self,
        c: &Self,
        tri_fn: F,
        circuit_fn: U
    ) -> Result<Self, SynthesisError>
        where E: Engine,
              CS: ConstraintSystem<E>,
              F: Fn(u32, u32, u32) -> u32,
              U: Fn(&mut CS, usize, &Boolean, &Boolean, &Boolean) -> Result<Boolean, SynthesisError>
    {
        let new_value = match (a.value, b.value, c.value) {
            (Some(a), Some(b), Some(c)) => {
                Some(tri_fn(a, b, c))
            },
            _ => None
        };

        let bits = a.bits.iter()
                            .zip(b.bits.iter())
                            .zip(c.bits.iter())
                            .enumerate()
                            .map(|(i, ((a, b), c))| circuit_fn(&mut cs, i, a, b, c))
                            .collect::<Result<_, _>>()?;

        Ok(UInt32 {
            bits: bits,
            value: new_value
        })
    }

    fn binop<E, CS, F, U>(
        &self,
        mut cs: CS,
        other: &Self,
        bin_fn: F,
        circuit_fn: U
    ) -> Result<Self, SynthesisError>
        where E: Engine,
              CS: ConstraintSystem<E>,
              F: Fn(u32, u32) -> u32,
              U: Fn(&mut CS, usize, &Boolean, &Boolean) -> Result<Boolean, SynthesisError>
    {
        let new_value = match (self.value, other.value) {
            (Some(a), Some(b)) => {
                Some(bin_fn(a, b))
            },
            _ => None
        };

        let bits = self.bits.iter()
                            .zip(other.bits.iter())
                            .enumerate()
                            .map(|(i, (a, b))| circuit_fn(&mut cs, i, a, b))
                            .collect::<Result<_, _>>()?;

        Ok(UInt32 {
            bits: bits,
            value: new_value
        })
    }

    /// AND this `UInt32` with the NOT of another `UInt32`
    pub fn and_not<E, CS>(
        &self,
        cs: CS,
        other: &Self
    ) -> Result<Self, SynthesisError>
        where E: Engine,
              CS: ConstraintSystem<E>
    {
        self.binop(cs, other, |a, b| a & (!b), |cs, i, a, b| {
            Boolean::and(
                cs.namespace(|| format!("and not of bit {}", i)),
                a,
                &b.not()
            )
        })
    }

    /// AND this `UInt32` with another `UInt32`
    pub fn and<E, CS>(
        &self,
        cs: CS,
        other: &Self
    ) -> Result<Self, SynthesisError>
        where E: Engine,
              CS: ConstraintSystem<E>
    {
        self.binop(cs, other, |a, b| a & b, |cs, i, a, b| {
            Boolean::and(
                cs.namespace(|| format!("and of bit {}", i)),
                a,
                b
            )
        })
    }

    /// XOR this `UInt32` with another `UInt32`
    pub fn xor<E, CS>(
        &self,
        cs: CS,
        other: &Self
    ) -> Result<Self, SynthesisError>
        where E: Engine,
              CS: ConstraintSystem<E>
    {
        self.binop(cs, other, |a, b| a ^ b, |cs, i, a, b| {
            Boolean::xor(
                cs.namespace(|| format!("xor of bit {}", i)),
                a,
                b
            )
        })
    }

    /// Perform modular addition of several `UInt32` objects.
    pub fn addmany<E, CS>(
        cs: CS,
        operands: &[Self]
    ) -> Result<Self, SynthesisError>
        where E: Engine,
              CS: ConstraintSystem<E>
    {
        Self::addmany_multiadder(MultiAdder::new(cs), operands)
    }

    /// Perform modular addition of several `UInt32` objects.
    pub fn addmany_multiadder<E, CS, M>(
        mut cs: M,
        operands: &[Self]
    ) -> Result<Self, SynthesisError>
        where E: Engine,
              CS: ConstraintSystem<E>,
              M: ConstraintSystem<E, Root=MultiAdder<E, CS>>
    {
        // Make some arbitrary bounds for ourselves to avoid overflows
        // in the scalar field
        assert!(E::Fr::NUM_BITS >= 64);
        assert!(operands.len() >= 2); // Weird trivial cases that should never happen
        assert!(operands.len() <= 10);

        // Compute the maximum value of the sum so we allocate enough bits for
        // the result
        let mut max_value = (operands.len() as u64) * (u32::max_value() as u64);

        // Keep track of the resulting value
        let mut result_value = Some(0u64);

        // This is a linear combination that we will enforce to equal the
        // output
        let mut lc = LinearCombination::zero();

        let mut all_constants = true;

        // Iterate over the operands
        for op in operands {
            // Accumulate the value
            match op.value {
                Some(val) => {
                    result_value.as_mut().map(|v| *v += val as u64);
                },
                None => {
                    // If any of our operands have unknown value, we won't
                    // know the value of the result
                    result_value = None;
                }
            }

            // Iterate over each bit of the operand and add the operand to
            // the linear combination
            let mut coeff = E::Fr::one();
            for bit in &op.bits {
                lc = lc + &bit.lc(CS::one(), coeff);

                all_constants &= bit.is_constant();

                coeff.double();
            }
        }

        // The value of the actual result is modulo 2^32
        let modular_value = result_value.map(|v| v as u32);

        if all_constants && modular_value.is_some() {
            // We can just return a constant, rather than
            // unpacking the result into allocated bits.

            return Ok(UInt32::constant(modular_value.unwrap()));
        }

        // Storage area for the resulting bits
        let mut result_bits = vec![];

        // Linear combination representing the output,
        // for comparison with the sum of the operands
        let mut result_lc = LinearCombination::zero();

        // Allocate each bit of the result
        let mut coeff = E::Fr::one();
        let mut i = 0;
        while max_value != 0 {
            // Allocate the bit
            let b = AllocatedBit::alloc(
                cs.namespace(|| format!("result bit {}", i)),
                result_value.map(|v| (v >> i) & 1 == 1)
            )?;

            // Add this bit to the result combination
            result_lc = result_lc + (coeff, b.get_variable());

            result_bits.push(b.into());

            max_value >>= 1;
            i += 1;
            coeff.double();
        }

        // Enforce equality between the sum and result
        cs.get_root().enforce_equal(i, &lc, &result_lc);

        // Discard carry bits that we don't care about
        result_bits.truncate(32);

        Ok(UInt32 {
            bits: result_bits,
            value: modular_value
        })
    }
}

pub struct MultiAdder<E: Engine, CS: ConstraintSystem<E>>{
    cs: CS,
    ops: usize,
    bits_used: usize,
    lhs: LinearCombination<E>,
    rhs: LinearCombination<E>,
}

impl<E: Engine, CS: ConstraintSystem<E>> MultiAdder<E, CS> {
    pub fn new(cs: CS) -> Self {
        MultiAdder {
            cs: cs,
            ops: 0,
            bits_used: 0,
            lhs: LinearCombination::zero(),
            rhs: LinearCombination::zero()
        }
    }

    fn accumulate(&mut self)
    {
        let ops = self.ops;
        let lhs = self.lhs.clone();
        let rhs = self.rhs.clone();
        self.cs.enforce(
            || format!("multiadd {}", ops),
            |_| lhs,
            |lc| lc + CS::one(),
            |_| rhs
        );
        self.lhs = LinearCombination::zero();
        self.rhs = LinearCombination::zero();
        self.bits_used = 0;
        self.ops += 1;
    }

    pub fn enforce_equal(
        &mut self,
        num_bits: usize,
        lhs: &LinearCombination<E>,
        rhs: &LinearCombination<E>
    )
    {
        // Check if we will exceed the capacity
        if (E::Fr::CAPACITY as usize) <= (self.bits_used + num_bits) {
            self.accumulate();
        }

        assert!((E::Fr::CAPACITY as usize) > (self.bits_used + num_bits));

        let coeff = E::Fr::from_str("2").unwrap().pow(&[self.bits_used as u64]);
        self.lhs = self.lhs.clone() + (coeff, lhs);
        self.rhs = self.rhs.clone() + (coeff, rhs);
        self.bits_used += num_bits;
    }
}

impl<E: Engine, CS: ConstraintSystem<E>> Drop for MultiAdder<E, CS> {
    fn drop(&mut self) {
        if self.bits_used > 0 {
           self.accumulate();
        }
    }
}

impl<E: Engine, CS: ConstraintSystem<E>> ConstraintSystem<E> for MultiAdder<E, CS>
{
    type Root = Self;

    fn one() -> Variable {
        CS::one()
    }

    fn alloc<F, A, AR>(
        &mut self,
        annotation: A,
        f: F
    ) -> Result<Variable, SynthesisError>
        where F: FnOnce() -> Result<E::Fr, SynthesisError>, A: FnOnce() -> AR, AR: Into<String>
    {
        self.cs.alloc(annotation, f)
    }

    fn alloc_input<F, A, AR>(
        &mut self,
        annotation: A,
        f: F
    ) -> Result<Variable, SynthesisError>
        where F: FnOnce() -> Result<E::Fr, SynthesisError>, A: FnOnce() -> AR, AR: Into<String>
    {
        self.cs.alloc_input(annotation, f)
    }

    fn enforce<A, AR, LA, LB, LC>(
        &mut self,
        annotation: A,
        a: LA,
        b: LB,
        c: LC
    )
        where A: FnOnce() -> AR, AR: Into<String>,
              LA: FnOnce(LinearCombination<E>) -> LinearCombination<E>,
              LB: FnOnce(LinearCombination<E>) -> LinearCombination<E>,
              LC: FnOnce(LinearCombination<E>) -> LinearCombination<E>
    {
        self.cs.enforce(annotation, a, b, c)
    }

    fn push_namespace<NR, N>(&mut self, name_fn: N)
        where NR: Into<String>, N: FnOnce() -> NR
    {
        self.cs.get_root().push_namespace(name_fn)
    }

    fn pop_namespace(&mut self)
    {
        self.cs.get_root().pop_namespace()
    }

    fn get_root(&mut self) -> &mut Self::Root
    {
        self
    }
}

#[cfg(test)]
mod test {
    use rand::{XorShiftRng, SeedableRng, Rng};
    use ::circuit::boolean::{Boolean};
    use super::{UInt32};
    use pairing::bls12_381::{Bls12};
    use pairing::{Field};
    use ::circuit::test::*;
    use bellman::{ConstraintSystem};

    #[test]
    fn test_uint32_from_bits_be() {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0653]);

        for _ in 0..1000 {
            let mut v = (0..32).map(|_| Boolean::constant(rng.gen())).collect::<Vec<_>>();

            let b = UInt32::from_bits_be(&v);

            for (i, bit) in b.bits.iter().enumerate() {
                match bit {
                    &Boolean::Constant(bit) => {
                        assert!(bit == ((b.value.unwrap() >> i) & 1 == 1));
                    },
                    _ => unreachable!()
                }
            }

            let expected_to_be_same = b.into_bits_be();

            for x in v.iter().zip(expected_to_be_same.iter())
            {
                match x {
                    (&Boolean::Constant(true), &Boolean::Constant(true)) => {},
                    (&Boolean::Constant(false), &Boolean::Constant(false)) => {},
                    _ => unreachable!()
                }
            }
        }
    }

    #[test]
    fn test_uint32_from_bits() {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0653]);

        for _ in 0..1000 {
            let mut v = (0..32).map(|_| Boolean::constant(rng.gen())).collect::<Vec<_>>();

            let b = UInt32::from_bits(&v);

            for (i, bit) in b.bits.iter().enumerate() {
                match bit {
                    &Boolean::Constant(bit) => {
                        assert!(bit == ((b.value.unwrap() >> i) & 1 == 1));
                    },
                    _ => unreachable!()
                }
            }

            let expected_to_be_same = b.into_bits();

            for x in v.iter().zip(expected_to_be_same.iter())
            {
                match x {
                    (&Boolean::Constant(true), &Boolean::Constant(true)) => {},
                    (&Boolean::Constant(false), &Boolean::Constant(false)) => {},
                    _ => unreachable!()
                }
            }
        }
    }

    #[test]
    fn test_uint32_xor() {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0653]);

        for _ in 0..1000 {
            let mut cs = TestConstraintSystem::<Bls12>::new();

            let a: u32 = rng.gen();
            let b: u32 = rng.gen();
            let c: u32 = rng.gen();

            let mut expected = a ^ b ^ c;

            let a_bit = UInt32::alloc(cs.namespace(|| "a_bit"), Some(a)).unwrap();
            let b_bit = UInt32::constant(b);
            let c_bit = UInt32::alloc(cs.namespace(|| "c_bit"), Some(c)).unwrap();

            let r = a_bit.xor(cs.namespace(|| "first xor"), &b_bit).unwrap();
            let r = r.xor(cs.namespace(|| "second xor"), &c_bit).unwrap();

            assert!(cs.is_satisfied());

            assert!(r.value == Some(expected));

            for b in r.bits.iter() {
                match b {
                    &Boolean::Is(ref b) => {
                        assert!(b.get_value().unwrap() == (expected & 1 == 1));
                    },
                    &Boolean::Not(ref b) => {
                        assert!(!b.get_value().unwrap() == (expected & 1 == 1));
                    },
                    &Boolean::Constant(b) => {
                        assert!(b == (expected & 1 == 1));
                    }
                }

                expected >>= 1;
            }
        }
    }

    #[test]
    fn test_uint32_and() {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0653]);

        for _ in 0..1000 {
            let mut cs = TestConstraintSystem::<Bls12>::new();

            let a: u32 = rng.gen();
            let b: u32 = rng.gen();
            let c: u32 = rng.gen();

            let mut expected = a & b & c;

            let a_bit = UInt32::alloc(cs.namespace(|| "a_bit"), Some(a)).unwrap();
            let b_bit = UInt32::constant(b);
            let c_bit = UInt32::alloc(cs.namespace(|| "c_bit"), Some(c)).unwrap();

            let r = a_bit.and(cs.namespace(|| "first and"), &b_bit).unwrap();
            let r = r.and(cs.namespace(|| "second and"), &c_bit).unwrap();

            assert!(cs.is_satisfied());

            assert!(r.value == Some(expected));

            for b in r.bits.iter() {
                match b {
                    &Boolean::Is(ref b) => {
                        assert!(b.get_value().unwrap() == (expected & 1 == 1));
                    },
                    &Boolean::Not(ref b) => {
                        assert!(!b.get_value().unwrap() == (expected & 1 == 1));
                    },
                    &Boolean::Constant(b) => {
                        assert!(b == (expected & 1 == 1));
                    }
                }

                expected >>= 1;
            }
        }
    }

    #[test]
    fn test_uint32_and_not() {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0653]);

        for _ in 0..1000 {
            let mut cs = TestConstraintSystem::<Bls12>::new();

            let a: u32 = rng.gen();
            let b: u32 = rng.gen();
            let c: u32 = rng.gen();

            let mut expected = (a & (!b)) & (!c);

            let a_bit = UInt32::alloc(cs.namespace(|| "a_bit"), Some(a)).unwrap();
            let b_bit = UInt32::constant(b);
            let c_bit = UInt32::alloc(cs.namespace(|| "c_bit"), Some(c)).unwrap();

            let r = a_bit.and_not(cs.namespace(|| "first and not"), &b_bit).unwrap();
            let r = r.and_not(cs.namespace(|| "second and not"), &c_bit).unwrap();

            assert!(cs.is_satisfied());

            assert!(r.value == Some(expected));

            for b in r.bits.iter() {
                match b {
                    &Boolean::Is(ref b) => {
                        assert!(b.get_value().unwrap() == (expected & 1 == 1));
                    },
                    &Boolean::Not(ref b) => {
                        assert!(!b.get_value().unwrap() == (expected & 1 == 1));
                    },
                    &Boolean::Constant(b) => {
                        assert!(b == (expected & 1 == 1));
                    }
                }

                expected >>= 1;
            }
        }
    }

    #[test]
    fn test_uint32_sha256_maj() {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0653]);

        for _ in 0..1000 {
            let mut cs = TestConstraintSystem::<Bls12>::new();

            let a: u32 = rng.gen();
            let b: u32 = rng.gen();
            let c: u32 = rng.gen();

            let mut expected = (a & b) ^ (a & c) ^ (b & c);

            let a_bit = UInt32::alloc(cs.namespace(|| "a_bit"), Some(a)).unwrap();
            let b_bit = UInt32::constant(b);
            let c_bit = UInt32::alloc(cs.namespace(|| "c_bit"), Some(c)).unwrap();

            let r = UInt32::sha256_maj(&mut cs, &a_bit, &b_bit, &c_bit).unwrap();

            assert!(cs.is_satisfied());

            assert!(r.value == Some(expected));

            for b in r.bits.iter() {
                match b {
                    &Boolean::Is(ref b) => {
                        assert!(b.get_value().unwrap() == (expected & 1 == 1));
                    },
                    &Boolean::Not(ref b) => {
                        assert!(!b.get_value().unwrap() == (expected & 1 == 1));
                    },
                    &Boolean::Constant(b) => {
                        assert!(b == (expected & 1 == 1));
                    }
                }

                expected >>= 1;
            }
        }
    }

    #[test]
    fn test_uint32_sha256_ch() {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0653]);

        for _ in 0..1000 {
            let mut cs = TestConstraintSystem::<Bls12>::new();

            let a: u32 = rng.gen();
            let b: u32 = rng.gen();
            let c: u32 = rng.gen();

            let mut expected = (a & b) ^ ((!a) & c);

            let a_bit = UInt32::alloc(cs.namespace(|| "a_bit"), Some(a)).unwrap();
            let b_bit = UInt32::constant(b);
            let c_bit = UInt32::alloc(cs.namespace(|| "c_bit"), Some(c)).unwrap();

            let r = UInt32::sha256_ch(&mut cs, &a_bit, &b_bit, &c_bit).unwrap();

            assert!(cs.is_satisfied());

            assert!(r.value == Some(expected));

            for b in r.bits.iter() {
                match b {
                    &Boolean::Is(ref b) => {
                        assert!(b.get_value().unwrap() == (expected & 1 == 1));
                    },
                    &Boolean::Not(ref b) => {
                        assert!(!b.get_value().unwrap() == (expected & 1 == 1));
                    },
                    &Boolean::Constant(b) => {
                        assert!(b == (expected & 1 == 1));
                    }
                }

                expected >>= 1;
            }
        }
    }

    #[test]
    fn test_uint32_addmany_constants() {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for _ in 0..1000 {
            let mut cs = TestConstraintSystem::<Bls12>::new();

            let a: u32 = rng.gen();
            let b: u32 = rng.gen();
            let c: u32 = rng.gen();

            let a_bit = UInt32::constant(a);
            let b_bit = UInt32::constant(b);
            let c_bit = UInt32::constant(c);

            let mut expected = a.wrapping_add(b).wrapping_add(c);

            let r = UInt32::addmany(cs.namespace(|| "addition"), &[a_bit, b_bit, c_bit]).unwrap();

            assert!(r.value == Some(expected));

            for b in r.bits.iter() {
                match b {
                    &Boolean::Is(_) => panic!(),
                    &Boolean::Not(_) => panic!(),
                    &Boolean::Constant(b) => {
                        assert!(b == (expected & 1 == 1));
                    }
                }

                expected >>= 1;
            }
        }
    }

    #[test]
    fn test_uint32_addmany() {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for _ in 0..1000 {
            let mut cs = TestConstraintSystem::<Bls12>::new();

            let a: u32 = rng.gen();
            let b: u32 = rng.gen();
            let c: u32 = rng.gen();
            let d: u32 = rng.gen();

            let mut expected = (a ^ b).wrapping_add(c).wrapping_add(d);

            let a_bit = UInt32::alloc(cs.namespace(|| "a_bit"), Some(a)).unwrap();
            let b_bit = UInt32::constant(b);
            let c_bit = UInt32::constant(c);
            let d_bit = UInt32::alloc(cs.namespace(|| "d_bit"), Some(d)).unwrap();

            let r = a_bit.xor(cs.namespace(|| "xor"), &b_bit).unwrap();
            let r = UInt32::addmany(cs.namespace(|| "addition"), &[r, c_bit, d_bit]).unwrap();

            assert!(cs.is_satisfied());

            assert!(r.value == Some(expected));

            for b in r.bits.iter() {
                match b {
                    &Boolean::Is(ref b) => {
                        assert!(b.get_value().unwrap() == (expected & 1 == 1));
                    },
                    &Boolean::Not(ref b) => {
                        assert!(!b.get_value().unwrap() == (expected & 1 == 1));
                    },
                    &Boolean::Constant(_) => {
                        unreachable!()
                    }
                }

                expected >>= 1;
            }

            // Flip a bit and see if the addition constraint still works
            if cs.get("addition/result bit 0/boolean").is_zero() {
                cs.set("addition/result bit 0/boolean", Field::one());
            } else {
                cs.set("addition/result bit 0/boolean", Field::zero());
            }

            assert!(!cs.is_satisfied());
        }
    }

    #[test]
    fn test_uint32_shr() {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for _ in 0..50 {
            for i in 0..60 {
                let num = rng.gen();
                let a = UInt32::constant(num).shr(i);
                let b = UInt32::constant(num >> i);

                assert_eq!(a.value.unwrap(), num >> i);

                assert_eq!(a.bits.len(), b.bits.len());
                for (a, b) in a.bits.iter().zip(b.bits.iter()) {
                    assert_eq!(a.get_value().unwrap(), b.get_value().unwrap());
                }
            }
        }
    }

    #[test]
    fn test_uint32_rotr() {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let mut num = rng.gen();

        let a = UInt32::constant(num);

        for i in 0..32 {
            let b = a.rotr(i);
            assert_eq!(a.bits.len(), b.bits.len());

            assert!(b.value.unwrap() == num);

            let mut tmp = num;
            for b in &b.bits {
                match b {
                    &Boolean::Constant(b) => {
                        assert_eq!(b, tmp & 1 == 1);
                    },
                    _ => unreachable!()
                }

                tmp >>= 1;
            }

            num = num.rotate_right(1);
        }
    }
}
