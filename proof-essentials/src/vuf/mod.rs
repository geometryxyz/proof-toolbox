use crate::error::CryptoError;
use ark_ff::ToBytes;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;

pub mod fedl;

pub trait VerifiableUnpredictableFunction {
    type Parameters: CanonicalSerialize + CanonicalDeserialize;
    type PublicKey: CanonicalSerialize + CanonicalDeserialize;
    type SecretKey: CanonicalSerialize + CanonicalDeserialize;
    type Signature: CanonicalSerialize + CanonicalDeserialize;
    type UniqueToken: CanonicalSerialize + CanonicalDeserialize;
    type Message: ToBytes;

    /// Generate a public key and a private key.
    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), CryptoError>;

    /// Sign a message.
    fn sign<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
        keypair: (&Self::PublicKey, &Self::SecretKey),
        message: Self::Message,
    ) -> Result<Self::Signature, CryptoError>;

    /// Extract a unique token from a signature.
    fn extract_token(signature: &Self::Signature) -> Result<Self::UniqueToken, CryptoError>;

    /// Verify a signature.
    fn verify(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: Self::Message,
        signature: &Self::Signature,
    ) -> Result<(), CryptoError>;
}
