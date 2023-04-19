use super::{Parameters, Statement};
use crate::error::CryptoError;

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{to_bytes, PrimeField};
use ark_marlin::rng::FiatShamirRng;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::io::{Read, Write};
use ark_std::UniformRand;
use digest::Digest;

#[derive(Copy, Clone, CanonicalDeserialize, CanonicalSerialize, Debug, PartialEq, Eq)]
pub struct Proof<C>
where
    C: ProjectiveCurve,
{
    pub(crate) random_commit: C,
    pub(crate) opening: C::ScalarField,
}

impl<C: ProjectiveCurve> Proof<C> {
    pub fn verify<D: Digest>(
        &self,
        pp: &Parameters<C>,
        statement: &Statement<C>,
        fs_rng: &mut FiatShamirRng<D>,
    ) -> Result<(), CryptoError> {
        fs_rng.absorb(&to_bytes![
            b"schnorr_identity",
            pp,
            statement,
            &self.random_commit
        ]?);

        let c = C::ScalarField::rand(fs_rng);

        if pp.mul(self.opening.into_repr()) + statement.mul(c.into_repr()) != self.random_commit {
            return Err(CryptoError::ProofVerificationError(String::from(
                "Schnorr Identification",
            )));
        }

        Ok(())
    }
}
