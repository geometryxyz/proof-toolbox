#[cfg(test)]

mod test {
    use crate::error::CryptoError;
    use crate::utils::rand::sample_vector;
    use crate::vector_commitment::{pedersen, HomomorphicCommitmentScheme};
    use crate::zkp::{arguments::single_value_product, ArgumentOfKnowledge};

    use ark_marlin::rng::FiatShamirRng;
    use ark_std::{rand::thread_rng, UniformRand};
    use blake2::Blake2s;
    use starknet_curve;
    use std::iter::Iterator;

    // Choose ellitptic curve setting
    type Curve = starknet_curve::Projective;
    type Scalar = starknet_curve::Fr;

    // Type aliases for concrete instances using the chosen EC.
    type Comm = pedersen::PedersenCommitment<Curve>;
    type Witness<'a> = single_value_product::Witness<'a, Scalar>;
    type Statement<'a> = single_value_product::Statement<'a, Scalar, Comm>;
    type SingleValueProd<'a> = single_value_product::SingleValueProductArgument<'a, Scalar, Comm>;
    type Parameters<'a> = single_value_product::Parameters<'a, Scalar, Comm>;

    type FS = FiatShamirRng<Blake2s>;

    #[test]
    fn test_single_product_argument() {
        let n = 13;
        let rng = &mut thread_rng();
        let commit_key = Comm::setup(rng, n);

        let mut a: Vec<Scalar> = sample_vector(rng, n);
        let b: Scalar = a.iter().product();

        let r = Scalar::rand(rng);
        let a_commit = Comm::commit(&commit_key, &a, r).unwrap();

        let parameters = Parameters::new(n, &commit_key);
        let witness = Witness::new(&a, &r);
        let statement = Statement::new(&a_commit, b);

        let mut fs_rng = FS::from_seed(b"Initialised with some input");
        let valid_proof =
            SingleValueProd::prove(rng, &parameters, &statement, &witness, &mut fs_rng).unwrap();

        let mut fs_rng = FS::from_seed(b"Initialised with some input");
        assert_eq!(
            Ok(()),
            valid_proof.verify(&parameters, &statement, &mut fs_rng)
        );

        a[0] = a[0] + a[0];
        let bad_witness = Witness::new(&a, &r);

        let mut fs_rng = FS::from_seed(b"Initialised with some input");
        let invalid_proof =
            SingleValueProd::prove(rng, &parameters, &statement, &bad_witness, &mut fs_rng)
                .unwrap();

        let mut fs_rng = FS::from_seed(b"Initialised with some input");
        assert_eq!(
            Err(CryptoError::ProofVerificationError(String::from(
                "Single Value Product Argument (5.3)",
            ))),
            SingleValueProd::verify(&parameters, &statement, &invalid_proof, &mut fs_rng)
        );
    }
}
