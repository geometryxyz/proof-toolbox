use crate::error::CryptoError;
use crate::vector_commitment::HomomorphicCommitmentScheme;

use ark_ec::{msm::VariableBaseMSM, ProjectiveCurve};
use ark_ff::{PrimeField, ToBytes};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    io::{Read, Write},
    marker::PhantomData,
};
use rand::Rng;

pub mod arithmetic_definitions;
mod tests;

pub struct PedersenCommitment<C: ProjectiveCurve> {
    _curve: PhantomData<C>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize, Debug)]
pub struct CommitKey<C: ProjectiveCurve> {
    g: Vec<C::Affine>,
    h: C::Affine,
}

impl<C: ProjectiveCurve> CommitKey<C> {
    pub fn new(g: Vec<C::Affine>, h: C::Affine) -> Self {
        Self { g, h }
    }
}

impl<C: ProjectiveCurve> ToBytes for CommitKey<C> {
    fn write<W: Write>(&self, mut w: W) -> ark_std::io::Result<()> {
        self.g.write(&mut w)?;
        self.h.write(&mut w)?;

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Commitment<C: ProjectiveCurve>(pub C::Affine);

impl<C: ProjectiveCurve> ToBytes for Commitment<C> {
    fn write<W: Write>(&self, mut w: W) -> ark_std::io::Result<()> {
        self.0.write(&mut w)?;

        Ok(())
    }
}

impl<C: ProjectiveCurve> HomomorphicCommitmentScheme<C::ScalarField> for PedersenCommitment<C> {
    type CommitKey = CommitKey<C>;
    type Commitment = Commitment<C>;

    fn setup<R: Rng>(public_randomess: &mut R, len: usize) -> CommitKey<C> {
        let mut g = Vec::with_capacity(len);
        for _ in 0..len {
            g.push(C::rand(public_randomess).into_affine());
        }
        let h = C::rand(public_randomess).into_affine();
        CommitKey::<C> { g, h }
    }

    fn commit(
        commit_key: &CommitKey<C>,
        x: &Vec<C::ScalarField>,
        r: C::ScalarField,
    ) -> Result<Self::Commitment, CryptoError> {
        if x.len() > commit_key.g.len() {
            return Err(CryptoError::CommitmentLengthError(
                String::from("Pedersen"),
                x.len(),
                commit_key.g.len(),
            ));
        }

        let scalars = [&[r], x.as_slice()]
            .concat()
            .iter()
            .map(|x| x.into_repr())
            .collect::<Vec<_>>();

        let bases = [&[commit_key.h], &commit_key.g[..]].concat();

        Ok(Commitment(
            VariableBaseMSM::multi_scalar_mul(&bases, &scalars[..]).into_affine(),
        ))
    }
}
