#[cfg(test)]
mod test {

    use crate::error::CryptoError;
    use crate::zkp::{proofs::schnorr_identification, ArgumentOfKnowledge};
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_marlin::rng::FiatShamirRng;
    use ark_std::rand::thread_rng;
    use ark_std::UniformRand;
    use blake2::Blake2s;
    use rand::{prelude::ThreadRng, Rng};
    use starknet_curve;

    type Curve = starknet_curve::Projective;
    type Point = starknet_curve::Affine;
    type Schnorr<'a> = schnorr_identification::SchnorrIdentification<Curve>;
    type Scalar = starknet_curve::Fr;
    type Parameters = schnorr_identification::Parameters<Curve>;
    type FS = FiatShamirRng<Blake2s>;

    fn setup<R: Rng>(rng: &mut R) -> Result<Parameters, CryptoError> {
        Ok(Curve::rand(rng).into_affine())
    }

    fn test_template() -> (ThreadRng, Parameters, Scalar, Point) {
        let mut rng = thread_rng();

        let crs = setup(&mut rng).unwrap();

        let sk = Scalar::rand(&mut rng);
        let pk = crs.mul(sk).into_affine();

        (rng, crs, sk, pk)
    }

    #[test]
    fn test_honest_prover() {
        let (mut rng, crs, sk, pk) = test_template();

        let mut fs_rng = FS::from_seed(b"Initialised with some input");
        let proof = Schnorr::prove(&mut rng, &crs, &pk, &sk, &mut fs_rng).unwrap();

        let mut fs_rng = FS::from_seed(b"Initialised with some input");
        assert_eq!(Schnorr::verify(&crs, &pk, &proof, &mut fs_rng), Ok(()));
    }

    #[test]
    fn test_malicious_prover() {
        let (mut rng, crs, _, pk) = test_template();

        let another_scalar = Scalar::rand(&mut rng);
        let mut fs_rng = FS::from_seed(b"Initialised with some input");

        let invalid_proof =
            Schnorr::prove(&mut rng, &crs, &pk, &another_scalar, &mut fs_rng).unwrap();
        let mut fs_rng = FS::from_seed(b"Initialised with some input");

        assert_eq!(
            Schnorr::verify(&crs, &pk, &invalid_proof, &mut fs_rng),
            Err(CryptoError::ProofVerificationError(String::from(
                "Schnorr Identification"
            )))
        );
    }
}
