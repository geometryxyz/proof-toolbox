use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

use proof_essentials::homomorphic_encryption::{el_gamal, HomomorphicEncryptionScheme};
use proof_essentials::utils::rand::sample_vector;
use proof_essentials::vector_commitment::{pedersen, HomomorphicCommitmentScheme};
use proof_essentials::zkp::{arguments::shuffle, ArgumentOfKnowledge};

use ark_ff::Zero;
use ark_marlin::rng::FiatShamirRng;
use ark_std::UniformRand;
use blake2::Blake2s;
use proof_essentials::utils::permutation::Permutation;
use rand::rngs::OsRng;
use starknet_curve;
use std::iter::Iterator;

// Choose ellitptic curve setting
type Curve = starknet_curve::Projective;
type Scalar = starknet_curve::Fr;

// Type aliases for concrete instances using the chosen EC.
type Enc = el_gamal::ElGamal<Curve>;
type Comm = pedersen::PedersenCommitment<Curve>;
type Plaintext = el_gamal::Plaintext<Curve>;
type Generator = el_gamal::Generator<Curve>;
type Ciphertext = el_gamal::Ciphertext<Curve>;
type Witness<'a> = shuffle::Witness<'a, Scalar>;
type Statement<'a> = shuffle::Statement<'a, Scalar, Enc>;
type ShuffleArgument<'a> = shuffle::ShuffleArgument<'a, Scalar, Enc, Comm>;
type Parameters<'a> = shuffle::Parameters<'a, Scalar, Enc, Comm>;

type FS = FiatShamirRng<Blake2s>;

fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = OsRng;

    let encrypt_parameters = Enc::setup(&mut rng).unwrap();
    let (pk, _) = Enc::keygen(&encrypt_parameters, &mut rng).unwrap();

    let generator = Generator::rand(&mut rng);

    let prepare_proof_parameters = |m, n| {
        let mut rng = OsRng;
        let number_of_ciphers = n * m;

        let commit_key = Comm::setup(&mut rng, n);

        let ciphers: Vec<Ciphertext> = sample_vector(&mut rng, number_of_ciphers);
        let masking_factors: Vec<Scalar> = sample_vector(&mut rng, number_of_ciphers);

        let permutation = Permutation::new(&mut rng, number_of_ciphers);

        let permuted_ciphers = permutation.permute_array(&ciphers);

        let shuffled_ciphers = permuted_ciphers
            .iter()
            .zip(masking_factors.iter())
            .map(|(&cipher, masking_factor)| {
                let zero_cipher = Plaintext::zero();
                let masking_cipher =
                    Enc::encrypt(&encrypt_parameters, &pk, &zero_cipher, masking_factor).unwrap();

                cipher + masking_cipher
            })
            .collect::<Vec<_>>();

        (
            commit_key,
            ciphers,
            masking_factors,
            permutation,
            shuffled_ciphers,
        )
    };

    // test for pairs (m, n) such that m = number_of_chunks, n = len_of_chunk and m*n is the number of ciphertexts
    // since proof runs in O(m^2) we expect (2, 26) to be the fastest one
    let num_of_chunks_x_chunk_length = vec![(4, 13), (13, 4), (2, 26), (26, 2)];

    {
        let mut group = c.benchmark_group("PROVING");
        group.sample_size(10);
        for (m, n) in num_of_chunks_x_chunk_length.clone() {
            let (commit_key, ciphers, masking_factors, permutation, shuffled_ciphers) =
                prepare_proof_parameters(m, n);
            let parameters = Parameters::new(&encrypt_parameters, &pk, &commit_key, &generator);
            let statement = Statement::new(&ciphers, &shuffled_ciphers, m, n);
            let witness = Witness::new(&permutation, &masking_factors);
            let mut fs_rng = FS::from_seed(b"Initialised with some input");
            let bench_id =
                BenchmarkId::new("number_of_ciphers:", format!("({} * {} = {})", m, n, m * n));
            group.bench_function(bench_id, |b| {
                b.iter(|| {
                    ShuffleArgument::prove(
                        &mut rng,
                        &parameters,
                        &statement,
                        &witness,
                        &mut fs_rng,
                    )
                    .unwrap();
                })
            });
        }
    }

    {
        let mut group = c.benchmark_group("VERIFYING");
        group.sample_size(10);
        for (m, n) in num_of_chunks_x_chunk_length.clone() {
            let (commit_key, ciphers, masking_factors, permutation, shuffled_ciphers) =
                prepare_proof_parameters(m, n);
            let parameters = Parameters::new(&encrypt_parameters, &pk, &commit_key, &generator);
            let statement = Statement::new(&ciphers, &shuffled_ciphers, m, n);
            let witness = Witness::new(&permutation, &masking_factors);
            let mut fs_rng = FS::from_seed(b"Initialised with some input");
            let proof =
                ShuffleArgument::prove(&mut rng, &parameters, &statement, &witness, &mut fs_rng)
                    .unwrap();
            let mut fs_rng = FS::from_seed(b"Initialised with some input");
            assert_eq!(
                Ok(()),
                ShuffleArgument::verify(&parameters, &statement, &proof, &mut fs_rng)
            );
            let bench_id =
                BenchmarkId::new("number_of_ciphers:", format!("({} * {} = {})", m, n, m * n));
            let mut fs_rng = FS::from_seed(b"Initialised with some input");
            group.bench_function(bench_id, |b| {
                b.iter(|| ShuffleArgument::verify(&parameters, &statement, &proof, &mut fs_rng))
            });
        }
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
