use base64::prelude::{Engine as _, BASE64_STANDARD};
use cfdkim::*;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fancy_regex::Regex;
use halo2_base::halo2_proofs;
use halo2_base::halo2_proofs::circuit::SimpleFloorPlanner;
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_base::halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ConstraintSystem};
use halo2_base::halo2_proofs::poly::kzg::commitment::KZGCommitmentScheme;
use halo2_base::halo2_proofs::poly::kzg::multiopen::{ProverGWC, VerifierGWC};
use halo2_base::halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_base::halo2_proofs::poly::{
    commitment::{Params, ParamsProver, ParamsVerifier},
    kzg::commitment::ParamsKZG,
};
use halo2_base::halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer};
use halo2_base::halo2_proofs::{circuit::Layouter, plonk::Error, SerdeFormat};
use halo2_base::halo2_proofs::{
    circuit::{floor_planner::V1, Cell, Value},
    dev::{CircuitCost, FailureLocation, MockProver, VerifyFailure},
    plonk::{Any, Column, Instance, ProvingKey, VerifyingKey},
};
use halo2_base::{gates::range::RangeConfig, utils::PrimeField, Context};
use halo2_base::{gates::range::RangeStrategy::Vertical, SKIP_FIRST_PASS};
use halo2_regex::defs::{AllstrRegexDef, SubstrRegexDef};
use halo2_regex::vrm::DecomposedRegexConfig;
use halo2_rsa::{RSAPubE, RSAPublicKey, RSASignature};
use halo2_zk_email::{default_config_params, DefaultCommitVerifyCircuit, COMMIT_VERIFY_CONFIG_ENV};
use itertools::Itertools;
use mailparse::parse_mail;
use num_bigint::BigUint;
use rand::rngs::OsRng;
use rand::thread_rng;
use rand::Rng;
use rsa::{PublicKeyParts, RsaPrivateKey};
use sha2::{self, Digest, Sha256};
use snark_verifier_sdk::halo2::{gen_proof, gen_proof_shplonk};
use snark_verifier_sdk::CircuitExt;
use std::env::set_var;
use std::{
    fs::File,
    io::{prelude::*, BufReader, BufWriter},
    path::Path,
};
use tokio::runtime::Runtime;

fn gen_or_get_params(k: usize) -> ParamsKZG<Bn256> {
    let path = format!("params_{}.bin", k);
    match File::open(&path) {
        Ok(f) => {
            let mut reader = BufReader::new(f);
            ParamsKZG::read(&mut reader).unwrap()
        }
        Err(_) => {
            let params = ParamsKZG::<Bn256>::setup(k as u32, OsRng);
            params.write(&mut BufWriter::new(File::create(&path).unwrap())).unwrap();
            params
        }
    }
}

fn bench_email_verify1(c: &mut Criterion) {
    let mut group = c.benchmark_group("email bench1 without recursion");
    group.sample_size(10);
    set_var(COMMIT_VERIFY_CONFIG_ENV, "./configs/app_bench.config");
    let config_params = default_config_params();
    let params = gen_or_get_params(config_params.degree as usize);
    println!("gen_params");
    let regex_bodyhash_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/bodyhash_defs.json").unwrap()).unwrap();
    regex_bodyhash_decomposed
        .gen_regex_files(
            &Path::new("./test_data/bodyhash_allstr.txt").to_path_buf(),
            &[Path::new("./test_data/bodyhash_substr_0.txt").to_path_buf()],
        )
        .unwrap();
    let regex_from_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/from_defs.json").unwrap()).unwrap();
    regex_from_decomposed
        .gen_regex_files(
            &Path::new("./test_data/from_allstr.txt").to_path_buf(),
            &[Path::new("./test_data/from_substr_0.txt").to_path_buf()],
        )
        .unwrap();
    let regex_to_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/to_defs.json").unwrap()).unwrap();
    regex_to_decomposed
        .gen_regex_files(
            &Path::new("./test_data/to_allstr.txt").to_path_buf(),
            &[Path::new("./test_data/to_substr_0.txt").to_path_buf()],
        )
        .unwrap();
    let regex_subject_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/subject_defs.json").unwrap()).unwrap();
    regex_subject_decomposed
        .gen_regex_files(
            &Path::new("./test_data/subject_allstr.txt").to_path_buf(),
            &[
                Path::new("./test_data/subject_substr_0.txt").to_path_buf(),
                Path::new("./test_data/subject_substr_1.txt").to_path_buf(),
                Path::new("./test_data/subject_substr_2.txt").to_path_buf(),
            ],
        )
        .unwrap();
    let regex_body_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/test_ex1_email_body_defs.json").unwrap()).unwrap();
    regex_body_decomposed
        .gen_regex_files(
            &Path::new("./test_data/test_ex1_email_body_allstr.txt").to_path_buf(),
            &[
                Path::new("./test_data/test_ex1_email_body_substr_0.txt").to_path_buf(),
                Path::new("./test_data/test_ex1_email_body_substr_1.txt").to_path_buf(),
                Path::new("./test_data/test_ex1_email_body_substr_2.txt").to_path_buf(),
            ],
        )
        .unwrap();
    let email_bytes = {
        let mut f = File::open("./test_data/test_email1.eml").unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        buf
    };
    let logger = slog::Logger::root(slog::Discard, slog::o!());
    let runtime = Runtime::new().unwrap();
    let public_key = runtime.block_on(async { resolve_public_key(&logger, &email_bytes).await }).unwrap();
    let public_key = match public_key {
        cfdkim::DkimPublicKey::Rsa(pk) => pk,
        _ => panic!("not supportted public key type."),
    };
    let public_key_n = BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
    let circuit = DefaultCommitVerifyCircuit::new(email_bytes, public_key_n);

    MockProver::run(params.k(), &circuit, circuit.instances()).unwrap().assert_satisfied();
    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk.clone(), &circuit).unwrap();
    group.bench_function("bench 1", |b| {
        b.iter(|| gen_proof_shplonk(&params, &pk, circuit.clone(), circuit.instances(), &mut OsRng, None))
    });
    group.finish();
}

criterion_group!(benches, bench_email_verify1,);
criterion_main!(benches);
