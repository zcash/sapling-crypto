use jubjub::{JubjubEngine, ToUniform};

pub fn hash_to_scalar<E: JubjubEngine>(persona: &[u8], a: &[u8], b: &[u8]) -> E::Fs {
    let mut params = blake2b_simd::Params::new();
    params.salt(&[]);
    params.key(&[]);
    params.personal(persona);
    params.hash_length(64);

    let mut hasher = params.to_state();
    hasher.update(a);
    hasher.update(b);
    let ret = hasher.finalize();
    E::Fs::to_uniform(ret.as_ref())
}
