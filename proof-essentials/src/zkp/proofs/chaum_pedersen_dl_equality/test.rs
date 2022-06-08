#[cfg(test)]
mod test {

    use crate::error::CryptoError;
    use crate::zkp::proofs::chaum_pedersen_dl_equality;
    use crate::zkp::proofs::chaum_pedersen_dl_equality::DLEquality;
    use crate::zkp::ArgumentOfKnowledge;
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_marlin::rng::FiatShamirRng;
    use ark_std::{rand::thread_rng, UniformRand};
    use blake2::Blake2s;
    use rand::{prelude::ThreadRng, Rng};
    use starknet_curve;

    type AffinePoint = starknet_curve::Affine;
    type Curve = starknet_curve::Projective;
    type Scalar = starknet_curve::Fr;
    type Parameters<'a> = chaum_pedersen_dl_equality::Parameters<'a, Curve>;
    type FS = FiatShamirRng<Blake2s>;

    fn setup<R: Rng>(rng: &mut R) -> (AffinePoint, AffinePoint) {
        (
            Curve::rand(rng).into_affine(),
            Curve::rand(rng).into_affine(),
        )
    }

    fn test_template() -> (ThreadRng, AffinePoint, AffinePoint, Scalar) {
        let mut rng = thread_rng();
        let (g, h) = setup(&mut rng);
        let secret = Scalar::rand(&mut rng);

        (rng, g, h, secret)
    }

    #[test]
    fn test_honest_prover() {
        let (mut rng, g, h, secret) = test_template();

        let point_a = g.mul(secret).into_affine();
        let point_b = h.mul(secret).into_affine();

        let crs = Parameters::new(&g, &h);
        let statement = chaum_pedersen_dl_equality::Statement::<starknet_curve::Projective>::new(
            &point_a, &point_b,
        );
        let witness = &secret;

        let mut fs_rng = FS::from_seed(b"Initialised with some input");
        let proof = DLEquality::<starknet_curve::Projective>::prove(
            &mut rng,
            &crs,
            &statement,
            &witness,
            &mut fs_rng,
        )
        .unwrap();

        let mut fs_rng = FS::from_seed(b"Initialised with some input");
        assert_eq!(
            DLEquality::<starknet_curve::Projective>::verify(&crs, &statement, &proof, &mut fs_rng),
            Ok(())
        );

        assert_ne! {point_a, point_b};
    }

    #[test]
    fn test_malicious_prover() {
        let (mut rng, g, h, secret) = test_template();

        let point_a = g.mul(secret).into_affine();
        let point_b = h.mul(secret).into_affine();

        let another_scalar = Scalar::rand(&mut rng);

        let crs = Parameters::new(&g, &h);
        let statement = chaum_pedersen_dl_equality::Statement::<starknet_curve::Projective>::new(
            &point_a, &point_b,
        );

        let wrong_witness = &another_scalar;

        let mut fs_rng = FS::from_seed(b"Initialised with some input");
        let invalid_proof = DLEquality::<starknet_curve::Projective>::prove(
            &mut rng,
            &crs,
            &statement,
            &wrong_witness,
            &mut fs_rng,
        )
        .unwrap();

        let mut fs_rng = FS::from_seed(b"Initialised with some input");
        assert_eq!(
            DLEquality::<starknet_curve::Projective>::verify(
                &crs,
                &statement,
                &invalid_proof,
                &mut fs_rng
            ),
            Err(CryptoError::ProofVerificationError(String::from(
                "Chaum-Pedersen"
            )))
        );
    }
}
