use super::{Parameters, Statement};

use crate::error::CryptoError;
use crate::homomorphic_encryption::HomomorphicEncryptionScheme;
use crate::utils::vector_arithmetic::dot_product;
use crate::vector_commitment::HomomorphicCommitmentScheme;
use crate::zkp::arguments::scalar_powers;
use crate::zkp::arguments::{matrix_elements_product as product_argument, multi_exponentiation};

use ark_ff::{to_bytes, Field};
use ark_marlin::rng::FiatShamirRng;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::io::{Read, Write};
use digest::Digest;

#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct Proof<Scalar, Enc, Comm>
where
    Scalar: Field,
    Enc: HomomorphicEncryptionScheme<Scalar>,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    pub a_commits: Vec<Comm::Commitment>,
    pub b_commits: Vec<Comm::Commitment>,
    pub product_argument_proof: product_argument::proof::Proof<Scalar, Comm>,
    pub multi_exp_proof: multi_exponentiation::proof::Proof<Scalar, Enc, Comm>,
}

impl<Scalar, Enc, Comm> Proof<Scalar, Enc, Comm>
where
    Scalar: Field,
    Enc: HomomorphicEncryptionScheme<Scalar>,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    pub fn verify<D: Digest>(
        &self,
        proof_parameters: &Parameters<Scalar, Enc, Comm>,
        statement: &Statement<Scalar, Enc>,
        fs_rng: &mut FiatShamirRng<D>,
    ) -> Result<(), CryptoError> {
        statement.is_valid()?;

        fs_rng.absorb(&to_bytes![b"shuffle_argument"]?);

        // Public data
        fs_rng.absorb(&to_bytes![
            proof_parameters.public_key,
            proof_parameters.commit_key
        ]?);

        // statement
        fs_rng.absorb(
            &to_bytes![
                statement.input_ciphers,
                statement.shuffled_ciphers,
                statement.m as u32,
                statement.n as u32
            ]
            .unwrap(),
        );

        // round 1
        fs_rng.absorb(&to_bytes![self.a_commits]?);
        let x = Scalar::rand(fs_rng);

        let challenge_powers = scalar_powers(x, statement.m * statement.n)[1..].to_vec();

        // round 2
        fs_rng.absorb(&to_bytes![self.b_commits]?);
        let y = Scalar::rand(fs_rng);
        let z = Scalar::rand(fs_rng);

        // PRODUCT ARGUMENT -------------------------------------------------------------
        let z_vec = vec![-z; statement.n];
        let zero = Scalar::zero();
        let single_neg_z_commit = Comm::commit(proof_parameters.commit_key, &z_vec, zero)?;
        let neg_z_commit = vec![single_neg_z_commit; statement.m];

        let c_d = self
            .a_commits
            .iter()
            .zip(self.b_commits.iter())
            .map(|(&a, &b)| a * y + b)
            .collect::<Vec<_>>();

        let verifier_side_expected_product = (1..=statement.n * statement.m)
            .zip(challenge_powers.iter())
            .map(|(i, x_pow_i)| y * Scalar::from(i as u64) + x_pow_i - z)
            .product();

        let product_argument_parameters = product_argument::Parameters::new(
            statement.m,
            statement.n,
            proof_parameters.commit_key,
        );

        let commitments_to_a = c_d
            .iter()
            .zip(neg_z_commit.iter())
            .map(|(&d_commit, &z_commit)| d_commit + z_commit)
            .collect::<Vec<_>>();
        let product_argument_statement =
            product_argument::Statement::new(&commitments_to_a, verifier_side_expected_product);

        self.product_argument_proof.verify(
            &product_argument_parameters,
            &product_argument_statement,
            fs_rng,
        )?;

        // MULTI-EXPONENTIATION ARGUMENT -------------------------------------------------------
        let multi_exp_parameters = multi_exponentiation::Parameters::new(
            proof_parameters.encrypt_parameters,
            proof_parameters.public_key,
            proof_parameters.commit_key,
            proof_parameters.generator,
        );

        let shuffled_chunks = statement
            .shuffled_ciphers
            .chunks(statement.n)
            .map(|c| c.to_vec())
            .collect::<Vec<_>>();

        let product = dot_product(&challenge_powers, statement.input_ciphers).unwrap();

        let multi_exp_statement =
            multi_exponentiation::Statement::new(&shuffled_chunks, product, &self.b_commits);

        self.multi_exp_proof
            .verify(&multi_exp_parameters, &multi_exp_statement, fs_rng)?;

        Ok(())
    }
}
