use super::proof::Proof;
use super::{Parameters, Statement, Witness};

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{PrimeField, to_bytes};
use ark_std::{rand::Rng, UniformRand};
use digest::Digest;
use ark_marlin::rng::FiatShamirRng;

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
        parameters: &Parameters<C>,
        statement: &Statement<C>,
        witness: &Witness<C>,
        fs_rng: &mut FiatShamirRng<D>
    ) -> Proof<C> {
        fs_rng.absorb(&to_bytes![b"chaum_pedersen", parameters.g, parameters.h, statement.0, statement.1].unwrap());

        let omega = C::ScalarField::rand(rng);
        let a = parameters.g.mul(omega.into_repr());
        let b = parameters.h.mul(omega.into_repr());

        fs_rng.absorb(&to_bytes![a, b].unwrap());


        let c = C::ScalarField::rand(fs_rng);

        let r = omega + c * *witness;

        Proof { a, b, r }
    }
}
