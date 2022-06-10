mod test;

use crate::{
    error::CryptoError,
    vuf::VerifiableUnpredictableFunction,
    zkp::{
        proofs::chaum_pedersen_dl_equality::{
            proof::Proof, DLEquality, Parameters as ChaumPedersenParameters, Statement,
        },
        ArgumentOfKnowledge,
    },
};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::UniformRand;
use ark_marlin::rng::FiatShamirRng;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    io::{Read, Write},
    marker::PhantomData,
    rand::Rng,
};
use blake2::Blake2s;
use tiny_keccak::{Hasher, Shake, Xof};

const FS_RNG_SEED: &'static [u8] = b"FEDL";

/// Unique signature scheme based on [EDL](with a change to fix the randmoness), with fixed randomness, henced Fixed EDL
pub struct FEDL<'a, C: ProjectiveCurve> {
    _group: PhantomData<C>,
    _message_lifetime: PhantomData<&'a ()>,
}

#[derive(Copy, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Parameters<C: ProjectiveCurve> {
    pub g: C::Affine,
}

fn try_and_increment<C: ProjectiveCurve>(msg: &[u8]) -> Result<C::Affine, CryptoError> {
    for nonce in 0u8..=255 {
        let mut h = Shake::v128();
        h.update(&[nonce]);
        h.update(msg.as_ref());
        let output_size = C::zero().serialized_size();
        let mut output = vec![0u8; output_size];
        h.squeeze(&mut output);

        if let Some(p) = C::Affine::from_random_bytes(&output) {
            return Ok(p);
        }
    }

    Err(CryptoError::CannotHashToCurve)
}

#[derive(Copy, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Signature<C: ProjectiveCurve> {
    pub proof: Proof<C>,
    pub b: C::Affine,
}

impl<'a, C: ProjectiveCurve> VerifiableUnpredictableFunction for FEDL<'a, C> {
    type Message = &'a [u8];
    type Parameters = Parameters<C>;
    type PublicKey = <C as ProjectiveCurve>::Affine;
    type SecretKey = <C as ProjectiveCurve>::ScalarField;
    type Signature = Signature<C>;
    type UniqueToken = <C as ProjectiveCurve>::Affine;

    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), CryptoError> {
        let secret_key = Self::SecretKey::rand(rng).into();
        let public_key = pp.g.mul(secret_key).into();
        Ok((public_key, secret_key))
    }

    fn sign<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
        keypair: (&Self::PublicKey, &Self::SecretKey),
        message: Self::Message,
    ) -> Result<Self::Signature, CryptoError> {
        let hash_of_message: C::Affine = try_and_increment::<C>(message)?;
        let chaum_pedersen_parameters = ChaumPedersenParameters {
            g: &pp.g,
            h: &hash_of_message,
        };
        let b = hash_of_message.mul(*keypair.1).into();
        let statement = Statement::new(keypair.0, &b);

        let mut fs_rng = FiatShamirRng::<Blake2s>::from_seed(&FS_RNG_SEED);
        let proof = DLEquality::prove(
            rng,
            &chaum_pedersen_parameters,
            &statement,
            keypair.1,
            &mut fs_rng,
        )?;
        Ok(Signature { proof, b })
    }

    fn extract_token(signature: &Self::Signature) -> Result<Self::UniqueToken, CryptoError> {
        Ok(signature.b)
    }

    fn verify(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: Self::Message,
        signature: &Self::Signature,
    ) -> Result<(), CryptoError> {
        let hash_of_message: C::Affine = try_and_increment::<C>(message)?;
        let chaum_pedersen_parameters = ChaumPedersenParameters {
            g: &pp.g,
            h: &hash_of_message,
        };

        let statement = Statement::new(pk, &signature.b);
        let mut fs_rng = FiatShamirRng::<Blake2s>::from_seed(&FS_RNG_SEED);
        DLEquality::verify(
            &chaum_pedersen_parameters,
            &statement,
            &signature.proof,
            &mut fs_rng,
        )
    }
}
