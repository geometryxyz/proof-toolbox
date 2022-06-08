use super::{proof::Proof, Parameters, Statement, Witness};

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{to_bytes, PrimeField};
use ark_marlin::rng::FiatShamirRng;
use ark_std::rand::Rng;
use ark_std::UniformRand;
use digest::Digest;

use std::marker::PhantomData;

pub struct Prover<C>
where
    C: ProjectiveCurve,
{
    phantom: PhantomData<C>,
}

impl<C> Prover<C>
where
    C: ProjectiveCurve,
{
    pub fn create_proof<R: Rng, D: Digest>(
        rng: &mut R,
        pp: &Parameters<C>,
        statement: &Statement<C>,
        witness: &Witness<C>,
        fs_rng: &mut FiatShamirRng<D>,
    ) -> Proof<C> {
        let random = C::ScalarField::rand(rng);

        let random_commit = pp.mul(random.into_repr());

        fs_rng.absorb(&to_bytes![b"schnorr_identity", pp, statement, random_commit].unwrap());

        let c = C::ScalarField::rand(fs_rng);

        let opening = random - c * witness;

        Proof {
            random_commit,
            opening,
        }
    }
}
