#[cfg(test)]
mod test {

    use crate::vuf::{
        fedl::{self, FEDL},
        VerifiableUnpredictableFunction,
    };
    use ark_ec::ProjectiveCurve;
    use ark_std::{rand::thread_rng, UniformRand};
    use rand::{prelude::ThreadRng, Rng};
    use starknet_curve;

    type AffinePoint = starknet_curve::Affine;
    type Curve = starknet_curve::Projective;
    type Parameters = fedl::Parameters<Curve>;

    fn setup<R: Rng>(rng: &mut R) -> AffinePoint {
        Curve::rand(rng).into_affine()
    }

    fn test_template() -> (ThreadRng, AffinePoint) {
        let mut rng = thread_rng();
        let g = setup(&mut rng);

        (rng, g)
    }

    #[test]
    fn test_signing_and_uniqueness() {
        let (mut rng, g) = test_template();

        let pp = Parameters { g };

        let keypair = FEDL::keygen(&pp, &mut rng).unwrap();

        let message = b"MESSAGE!!!";

        let signature =
            FEDL::sign(&pp, &mut rng, (&keypair.0, &keypair.1), message.as_slice()).unwrap();
        FEDL::verify(&pp, &keypair.0, message.as_slice(), &signature).unwrap();
        let signature2 =
            FEDL::sign(&pp, &mut rng, (&keypair.0, &keypair.1), message.as_slice()).unwrap();
        FEDL::verify(&pp, &keypair.0, message.as_slice(), &signature2).unwrap();
        assert_eq!(
            FEDL::extract_token(&signature),
            FEDL::extract_token(&signature2),
        );
    }

    #[test]
    #[should_panic]
    fn test_bad_signing() {
        let (mut rng, g) = test_template();

        let pp = Parameters { g };

        let keypair = FEDL::keygen(&pp, &mut rng).unwrap();
        let keypair2 = FEDL::keygen(&pp, &mut rng).unwrap();

        let message = b"MESSAGE!!!";

        let signature =
            FEDL::sign(&pp, &mut rng, (&keypair.0, &keypair.1), message.as_slice()).unwrap();
        FEDL::verify(&pp, &keypair2.0, message.as_slice(), &signature).unwrap();
    }
}
