pub mod proof;
pub mod prover;
mod test;

use crate::error::CryptoError;
use crate::zkp::ArgumentOfKnowledge;
use ark_ec::ProjectiveCurve;
use ark_marlin::rng::FiatShamirRng;
use ark_std::marker::PhantomData;
use ark_std::rand::Rng;
use digest::Digest;

pub struct SchnorrIdentification<C: ProjectiveCurve> {
    _group: PhantomData<C>,
}

pub type Parameters<C> = <C as ProjectiveCurve>::Affine;

pub type Statement<C> = <C as ProjectiveCurve>::Affine;

pub type Witness<C> = <C as ProjectiveCurve>::ScalarField;

impl<C: ProjectiveCurve> ArgumentOfKnowledge for SchnorrIdentification<C> {
    type CommonReferenceString = Parameters<C>;
    type Statement = Statement<C>;
    type Witness = Witness<C>;
    type Proof = proof::Proof<C>;

    fn prove<R: Rng, D: Digest>(
        rng: &mut R,
        common_reference_string: &Self::CommonReferenceString,
        statement: &Self::Statement,
        witness: &Self::Witness,
        fs_rng: &mut FiatShamirRng<D>,
    ) -> Result<Self::Proof, CryptoError> {
        prover::Prover::create_proof(rng, common_reference_string, statement, witness, fs_rng)
    }

    fn verify<D: Digest>(
        common_reference_string: &Self::CommonReferenceString,
        statement: &Self::Statement,
        proof: &Self::Proof,
        fs_rng: &mut FiatShamirRng<D>,
    ) -> Result<(), CryptoError> {
        proof.verify(common_reference_string, statement, fs_rng)
    }
}

impl<C: ProjectiveCurve> SchnorrIdentification<C> {
    pub const PROTOCOL_NAME: &'static [u8] = b"Schnorr Identification Scheme";
}
