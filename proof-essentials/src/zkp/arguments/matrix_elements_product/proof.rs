use super::{Parameters, Statement};

use crate::error::CryptoError;
use crate::vector_commitment::HomomorphicCommitmentScheme;
use crate::zkp::arguments::{hadamard_product, single_value_product};

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
    pub b_commit: Comm::Commitment,
    pub hadamard_product_proof: hadamard_product::proof::Proof<Scalar, Comm>,
    pub single_value_proof: single_value_product::proof::Proof<Scalar, Comm>,
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
        statement.is_valid(proof_parameters)?;
        fs_rng.absorb(&to_bytes![b"matrix_elements_product"]?);

        // Verifiy hadamrd product argument
        let hadamard_product_parameters = hadamard_product::Parameters::new(
            proof_parameters.m,
            proof_parameters.n,
            proof_parameters.commit_key,
        );

        let hadamard_product_statement =
            hadamard_product::Statement::new(statement.commitments_to_a, self.b_commit);

        self.hadamard_product_proof.verify(
            &hadamard_product_parameters,
            &hadamard_product_statement,
            fs_rng,
        )?;
        // verify single value product argument
        let single_value_product_parameters =
            single_value_product::Parameters::new(proof_parameters.n, proof_parameters.commit_key);

        let single_value_product_statement =
            single_value_product::Statement::new(&self.b_commit, statement.b);

        self.single_value_proof.verify(
            &single_value_product_parameters,
            &single_value_product_statement,
            fs_rng,
        )?;

        Ok(())
    }
}
