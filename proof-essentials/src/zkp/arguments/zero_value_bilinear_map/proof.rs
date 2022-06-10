use super::{BilinearMap, Parameters, Statement};

use crate::error::CryptoError;
use crate::utils::vector_arithmetic::dot_product;
use crate::vector_commitment::HomomorphicCommitmentScheme;
use crate::zkp::arguments::scalar_powers;

use ark_ff::{to_bytes, Field};
use ark_marlin::rng::FiatShamirRng;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::io::{Read, Write};
use digest::Digest;

#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct Proof<Scalar, Comm>
where
    Scalar: Field,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    // Round 1
    pub a_0_commit: Comm::Commitment,
    pub b_m_commit: Comm::Commitment,
    pub vector_of_committed_diagonals: Vec<Comm::Commitment>,

    // Round 2
    pub a_blinded: Vec<Scalar>,
    pub b_blinded: Vec<Scalar>,
    pub r_blinded: Scalar,
    pub s_blinded: Scalar,
    pub t_blinded: Scalar,
}

impl<Scalar, Comm> Proof<Scalar, Comm>
where
    Scalar: Field,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    pub fn verify<D: Digest>(
        &self,
        proof_parameters: &Parameters<Scalar, Comm>,
        statement: &Statement<Scalar, Comm>,
        fs_rng: &mut FiatShamirRng<D>,
    ) -> Result<(), CryptoError> {
        if self.vector_of_committed_diagonals[proof_parameters.m + 1]
            != Comm::commit(
                proof_parameters.commit_key,
                &vec![Scalar::zero()],
                Scalar::zero(),
            )?
        {
            return Err(CryptoError::ProofVerificationError(String::from(
                "Zero Argument (5.2)",
            )));
        }

        fs_rng.absorb(&to_bytes![b"zero_argument"]?);

        // Public parameters
        fs_rng.absorb(&to_bytes![
            proof_parameters.commit_key,
            proof_parameters.m as u32,
            proof_parameters.n as u32
        ]?);

        // Random values
        fs_rng.absorb(&to_bytes![self.a_0_commit, self.b_m_commit]?);

        // Commitments
        fs_rng.absorb(
            &to_bytes![
                statement.commitment_to_a,
                statement.commitment_to_b,
                self.vector_of_committed_diagonals
            ]
            .unwrap(),
        );

        let x = Scalar::rand(fs_rng);

        // Precompute all powers of the challenge from 0 to number_of_diagonals
        let challenge_powers = scalar_powers(x, 2 * proof_parameters.m);

        let first_m_powers = challenge_powers[0..proof_parameters.m].to_vec();
        let mut first_m_powers_reversed = first_m_powers[..].to_vec();
        first_m_powers_reversed.reverse();

        let first_m_non_zero_powers = challenge_powers[1..proof_parameters.m + 1].to_vec();
        let mut first_m_non_zero_powers_reversed = first_m_non_zero_powers[..].to_vec();
        first_m_non_zero_powers_reversed.reverse();

        // Verify commitment to A against a commitment on blinded a with blinded random r
        let left: Comm::Commitment =
            self.a_0_commit + dot_product(&first_m_non_zero_powers, statement.commitment_to_a)?;
        let right = Comm::commit(
            &proof_parameters.commit_key,
            &self.a_blinded,
            self.r_blinded,
        )?;
        if left != right {
            return Err(CryptoError::ProofVerificationError(String::from(
                "Zero Argument (5.2)",
            )));
        }

        // Verify commitment to B against a commitment on blinded b with blinded random s
        let left = self.b_m_commit
            + dot_product(&first_m_non_zero_powers_reversed, statement.commitment_to_b)?;
        let right = Comm::commit(
            &proof_parameters.commit_key,
            &self.b_blinded,
            self.s_blinded,
        )?;
        if left != right {
            return Err(CryptoError::ProofVerificationError(String::from(
                "Zero Argument (5.2)",
            )));
        }

        // Verify commitments to the diagonals against a commitment on bilinear_map(blinded a, blinded a) with blinded random t
        let left = dot_product(&challenge_powers, &self.vector_of_committed_diagonals)?;
        let a_star_b = statement
            .bilinear_map
            .compute_mapping(&self.a_blinded, &self.b_blinded)?;
        let right = Comm::commit(proof_parameters.commit_key, &vec![a_star_b], self.t_blinded)?;
        if left != right {
            return Err(CryptoError::ProofVerificationError(String::from(
                "Zero Argument (5.2)",
            )));
        }

        Ok(())
    }
}
