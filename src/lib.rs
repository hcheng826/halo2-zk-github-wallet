//! Email verification circuit compatible with the [halo2 library developed by privacy-scaling-explorations team](https://github.com/privacy-scaling-explorations/halo2).
//!
//! Our email verification circuit [`DefaultCommitVerifyCircuit`] enables you to prove that
//! - your email is authenticated by a domain server with an RSA digital signature according to the DKIM protocol.
//! - the string in your email satisfies regular expressions (regexes) specified in the circuit.
//! - the string in the public input of the circuit is a correct substring in your email.
//!
//! You can specify the configuration of that circuit with two kinds of json files:
//! 1. Decomposed regex json: defining a regex that the string in the email header/body must satisfy and which kinds of substring will be exposed in the public input.
//! 2. Email configuration json: defining some parameters of the email, e.g., the max size of the email header and body, the RSA public key size, pathes to text files to describe the regex definitions.
//!
//! With these files, you can call our CLI commands or helper functions to generate proving and verifying keys, proofs, and verifier Solidity contracts that conform to your configuration.
//!
//! Our circuit consists of three chips: [`RegexSha2Config`], [`RegexSha2Base64Config`], [`SignVerifyConfig`].
//! - The [`RegexSha2Config`] verifies that the input string satisfies the specified regex, extracts its substrings, and computes its SHA256 hash.
//! - The [`RegexSha2Base64Config`] additionally computes the base64 encoding of the SHA256 hash.
//! - The [`SignVerifyConfig`] verifies the RSA signature with the given SHA256 hash and RSA public key.
//!
//! The [`RegexSha2Config`], [`RegexSha2Base64Config`], [`SignVerifyConfig`] are used for the email header, email body, and RSA signature, respectively.
//! If you want to omit some verification in our circuit, you can build your own circuit with these chips.  

pub mod chars_shift;
pub mod config_params;
#[cfg(not(target_arch = "wasm32"))]
pub mod eth;
#[cfg(not(target_arch = "wasm32"))]
pub mod helpers;
/// Regex verification + SHA256 computation.
pub mod regex_sha2;
/// Regex verification + SHA256 computation + base64 encoding.
pub mod regex_sha2_base64;
/// RSA signature verification.
pub mod sign_verify;
/// Util functions.
pub mod utils;
#[cfg(target_arch = "wasm32")]
pub mod wasm;
pub mod wtns_commit;
use std::fs::File;
use std::marker::PhantomData;

use crate::chars_shift::CharsShiftConfig;
#[cfg(not(target_arch = "wasm32"))]
pub use crate::helpers::*;
use crate::regex_sha2::RegexSha2Config;
use crate::sign_verify::*;
use crate::utils::*;
use crate::wtns_commit::poseidon_circuit::*;
use crate::wtns_commit::*;
use cfdkim::canonicalize_signed_email;
#[cfg(not(target_arch = "wasm32"))]
use cfdkim::resolve_public_key;
pub use config_params::*;
use halo2_base::halo2_proofs::circuit;
use halo2_base::halo2_proofs::circuit::{SimpleFloorPlanner, Value};
use halo2_base::halo2_proofs::plonk::{Circuit, Column, ConstraintSystem, Instance};
use halo2_base::halo2_proofs::{circuit::Layouter, plonk::Error};
use halo2_base::utils::fe_to_biguint;
use halo2_base::utils::{decompose_fe_to_u64_limbs, value_to_option};
use halo2_base::QuantumCell;
use halo2_base::{gates::range::RangeStrategy::Vertical, SKIP_FIRST_PASS};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions, RangeInstructions},
    utils::PrimeField,
};
/// Re-export [halo2_base64](https://github.com/zkemail/halo2-base64).
pub use halo2_base64;
/// Re-export [halo2_dynamic_sha256](https://github.com/zkemail/halo2-dynamic-sha256/tree/feat/lookup)
pub use halo2_dynamic_sha256;
use halo2_dynamic_sha256::*;
/// Re-export [halo2_regex](https://github.com/zkemail/halo2-regex/tree/feat/multi_path)
pub use halo2_regex;
use halo2_regex::defs::{AllstrRegexDef, RegexDefs, SubstrRegexDef};
use halo2_regex::*;
/// Re-export [halo2_rsa](https://github.com/zkemail/halo2-rsa)
pub use halo2_rsa;
use halo2_rsa::*;
use itertools::Itertools;
use num_bigint::BigUint;
use regex_sha2_base64::RegexSha2Base64Config;
use rsa::traits::PublicKeyParts;
use rsa::{pkcs1::DecodeRsaPublicKey, RsaPublicKey};
use sha2::{Digest, Sha256};
#[cfg(not(target_arch = "wasm32"))]
use snark_verifier::loader::LoadedScalar;
use snark_verifier_sdk::CircuitExt;
use ssh_key::SshSig;
use std::io::{Read, Write};

/// The name of env variable for the path to the email configuration json.
pub const EMAIL_VERIFY_CONFIG_ENV: &'static str = "EMAIL_VERIFY_CONFIG";

/// Public input definition of [`DefaultCommitVerifyCircuit`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DefaultCommitVerifyPublicInput {
    /// A decimal string of a commitment of the signature defined as poseidon(rsaSign).
    pub sign_commit: String,
    /// A decimal string of the poseidon hash of the `n` parameter in the RSA public key. (The e parameter is fixed to 65537.)
    pub public_key_hash: String,
    /// The start positions of substrings in the commit payload.
    pub payload_starts: Vec<usize>,
    /// The substrings in the commit payload.
    pub payload_substrs: Vec<String>,
}

#[derive(serde::Deserialize)]
struct CommitFile {
    commit: Commit,
}

#[derive(serde::Deserialize)]
struct Commit {
    verification: Verification,
}

#[derive(serde::Deserialize)]
struct Verification {
    signature: String,
    payload: String,
}

impl DefaultCommitVerifyPublicInput {
    /// Create a public input for [`DefaultCommitVerifyCircuit`].
    ///
    /// # Arguments
    /// * `sign_commit` - a decimal string of a commitment of the signature defined as poseidon(rsaSign).
    /// * `public_key_hash` - a decimal string of the poseidon hash of the `n` parameter in the RSA public key.
    /// * `payload_substrs` - a vector of (the start position, the bytes) of the substrings in the email body.
    /// # Return values
    /// Return a new [`DefaultCommitVerifyPublicInput`].
    pub fn new<F: PrimeField>(sign_commit: F, public_key_hash: F, payload_substrs: Vec<Option<(usize, String)>>) -> Self {
        let mut payload_starts_vec = vec![];
        let mut payload_substrs_vec = vec![];
        for s in payload_substrs.into_iter() {
            if let Some(s) = s {
                payload_starts_vec.push(s.0);
                payload_substrs_vec.push(s.1);
            } else {
                payload_starts_vec.push(0);
                payload_substrs_vec.push("".to_string());
            }
        }
        let field2string = |val: &F| {
            let big = fe_to_biguint(val);
            big.to_str_radix(10)
        };
        DefaultCommitVerifyPublicInput {
            sign_commit: field2string(&sign_commit),
            public_key_hash: field2string(&public_key_hash),
            payload_starts: payload_starts_vec,
            payload_substrs: payload_substrs_vec,
        }
    }

    /// Output [`DefaultCommitVerifyPublicInput`] to a json file.
    ///
    /// # Arguments
    /// * `public_input_path` - a file path of the output json file.
    pub fn write_file(&self, public_input_path: &str) {
        let public_input_str = serde_json::to_string(&self).unwrap();
        let mut file = File::create(public_input_path).expect("public_input_path creation failed");
        write!(file, "{}", public_input_str).unwrap();
        file.flush().unwrap();
    }

    /// Output a vector of field values in the instance column.
    pub fn instances<F: PrimeField>(&self) -> Vec<F> {
        let sign_commit = F::from_str_vartime(&self.sign_commit).unwrap();
        let public_key_hash = F::from_str_vartime(&self.public_key_hash).unwrap();
        let mut rlc_inputs = vec![];
        let config_params = default_config_params();
        {
            let max_byte_size = config_params.header_config.as_ref().unwrap().max_variable_byte_size;
            let mut expected_masked_chars = vec![0u8; max_byte_size];
            let mut expected_substr_ids = vec![0u8; max_byte_size];
            // for (idx, (substr, start_idx)) in self.header_substrs.iter().zip(self.header_starts.iter()).enumerate() {
            //     for (j, byte) in substr.as_bytes().iter().enumerate() {
            //         expected_masked_chars[*start_idx + j] = *byte;
            //         expected_substr_ids[*start_idx + j] = idx as u8 + 1;
            //     }
            // }
            rlc_inputs.append(&mut expected_masked_chars);
            rlc_inputs.append(&mut expected_substr_ids);
        }
        {
            let max_byte_size = config_params.body_config.as_ref().unwrap().max_variable_byte_size;
            let mut expected_masked_chars = vec![0u8; max_byte_size];
            let mut expected_substr_ids = vec![0u8; max_byte_size];
            // for (idx, (substr, start_idx)) in self.body_substrs.iter().zip(self.body_starts.iter()).enumerate() {
            //     for (j, byte) in substr.as_bytes().iter().enumerate() {
            //         expected_masked_chars[*start_idx + j] = *byte;
            //         expected_substr_ids[*start_idx + j] = idx as u8 + 1;
            //     }
            // }
            rlc_inputs.append(&mut expected_masked_chars);
            rlc_inputs.append(&mut expected_substr_ids);
        }
        let mut rlc = F::zero();
        let mut coeff = sign_commit.clone();
        for input in rlc_inputs.into_iter() {
            rlc += coeff * F::from(input as u64);
            coeff *= sign_commit.clone();
        }
        println!("rlc instance {:?}", rlc);
        vec![sign_commit, public_key_hash, rlc]
    }
}

/// Configuration for [`DefaultCommitVerifyCircuit`].
#[derive(Debug, Clone)]
pub struct DefaultCommitVerifyConfig<F: PrimeField> {
    pub sha256_config: Sha256DynamicConfig<F>,
    pub sign_verify_config: SignVerifyConfig<F>,
    pub header_config: RegexSha2Config<F>,
    pub body_config: RegexSha2Base64Config<F>,
    pub chars_shift_config: CharsShiftConfig<F>,
    /// An instance column that contains a commitment of the email header, a hash of the public key `n` parameter, and a random linear combination of the masked characters and their substring ids in the email header and body.
    pub instances: Column<Instance>,
}

/// Default email verification circuit.
#[derive(Debug, Clone)]
pub struct DefaultCommitVerifyCircuit<F: PrimeField> {
    /// commit payload bytes.
    pub payload_bytes: Vec<u8>,
    /// commit signature bytes.
    pub signature_bytes: Vec<u8>,

    /// A `n` parameter of the RSA public key.
    pub public_key_n: BigUint, // pub public_key: RSAPublicKey<F>,
    _f: PhantomData<F>,
}

impl<F: PrimeField> Circuit<F> for DefaultCommitVerifyCircuit<F> {
    type Config = DefaultCommitVerifyConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            signature_bytes: vec![],
            payload_bytes: vec![],
            public_key_n: self.public_key_n.clone(),
            _f: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        #[cfg(not(target_arch = "wasm32"))]
        let config = Self::configure_native(meta);
        #[cfg(target_arch = "wasm32")]
        let config = wasm::configure_wasm(meta);
        config
    }

    fn synthesize(&self, mut config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        config.sha256_config.range().load_lookup_table(&mut layouter)?;
        config.sha256_config.load(&mut layouter)?;
        config.body_config.load(&mut layouter)?;
        // let mut first_pass = SKIP_FIRST_PASS;
        let mut public_hash_cell = vec![];
        let params = default_config_params();
        if let Some(sign_config) = params.sign_verify_config.as_ref() {
            assert_eq!(self.public_key_n.bits() as usize, sign_config.public_key_bits);
        }
        // let (header_bytes, body_bytes, signature_bytes) = canonicalize_signed_email(&self.email_bytes).unwrap();
        // println!("canonicalized_header:\n{}", String::from_utf8(header_bytes.clone()).unwrap());
        // println!("canonicalized_body:\n{}", String::from_utf8(body_bytes.clone()).unwrap());

        layouter.assign_region(
            || "zkcommit",
            |region| {
                let ctx = &mut config.sha256_config.new_context(region);
                let range = config.sha256_config.range().clone();
                let gate = range.gate.clone();

                // 1. Compute the SHA-256 hash of the payload
                let payload_hash_result = config.sha256_config.digest(ctx, &self.payload_bytes, Some(self.payload_bytes.len()))?;
                // Extract the assigned values from the hash result
                let payload_hash_values: Vec<halo2_base::AssignedValue<F>> = payload_hash_result.output_bytes.to_vec();

                // 2. Verify the RSA signature
                let e = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
                let public_key = RSAPublicKey::<F>::new(Value::known(self.public_key_n.clone()), e);
                let signature = RSASignature::<F>::new(Value::known(BigUint::from_bytes_be(&self.signature_bytes)));
                let (assigned_public_key, assigned_signature) = config.sign_verify_config.verify_signature(ctx, &payload_hash_values, public_key, signature.clone())?;

                // 3. Compute public input values
                let poseidon = PoseidonChipBn254_8_58::new(ctx, &gate);
                let sign_commit = poseidon.hash_elements(ctx, &gate, &assigned_signature.c.limbs()).unwrap().0[0].clone();
                let public_key_n_hash = poseidon.hash_elements(ctx, &gate, &assigned_public_key.n.limbs()).unwrap().0[0].clone();

                public_hash_cell.push(sign_commit.cell());
                public_hash_cell.push(public_key_n_hash.cell());

                // 4. Compute RLC of payload bytes
                let mut rlc = gate.load_zero(ctx);
                let mut coeff = sign_commit.clone();
                for byte in self.payload_bytes.iter() {
                    let byte_cell = gate.load_constant(ctx, F::from(*byte as u64));
                    rlc = gate.mul_add(ctx, QuantumCell::Existing(&byte_cell), QuantumCell::Existing(&coeff), QuantumCell::Existing(&rlc));
                    coeff = gate.mul(ctx, QuantumCell::Existing(&sign_commit), QuantumCell::Existing(&coeff));
                }
                public_hash_cell.push(rlc.cell());

                range.finalize(ctx);
                Ok(())
            },
        )?;
        for (idx, cell) in public_hash_cell.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.instances, idx)?;
        }
        Ok(())
    }
}

impl<F: PrimeField> CircuitExt<F> for DefaultCommitVerifyCircuit<F> {
    fn num_instance(&self) -> Vec<usize> {
        vec![3]
    }

    fn instances(&self) -> Vec<Vec<F>> {
        let public_input = self.gen_default_public_input();
        vec![public_input.instances()]
    }
}

impl<F: PrimeField> DefaultCommitVerifyCircuit<F> {
    pub const DEFAULT_E: u128 = 65537;

    /// Create a new [`DefaultCommitVerifyCircuit`].
    /// # Arguments
    /// * `email_bytes` - email bytes.
    /// * `public_key_n` - `n` parameter of the RSA public key.
    ///
    /// # Return values
    /// Return a new [`DefaultCommitVerifyCircuit`].
    pub fn new(payload_bytes: Vec<u8>, signature_bytes: Vec<u8>, public_key_n: BigUint) -> Self {
        Self {
            payload_bytes,
            signature_bytes,
            public_key_n,
            _f: PhantomData,
        }
    }

    /// Generate a new circuit from the given commit file.
    ///
    /// # Arguments
    /// * `commit_path` - a file path of the commit file.
    /// * `public_key_path` - a file path of the public key file.
    ///
    /// # Return values
    /// Return a new [`DefaultCommitVerifyCircuit`].
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn gen_circuit_from_commit_path(commit_path: &str, public_key_path: &str) -> Self {
        // Read and parse the commit file
        let mut commit_file = File::open(commit_path).unwrap();
        let mut commit_contents = String::new();
        commit_file.read_to_string(&mut commit_contents).unwrap();
        let commit: CommitFile = serde_json::from_str(&commit_contents).unwrap();

        // Extract signature and payload from the commit
        let signature_pem = commit.commit.verification.signature;
        let payload = commit.commit.verification.payload;

        let ssh_sig = SshSig::from_pem(signature_pem).unwrap();
        let signature_bytes = ssh_sig.signature_bytes().to_vec();

        // Convert payload to bytes
        let payload_bytes = payload.into_bytes();

        let mut public_key_file = File::open(public_key_path).unwrap();
        let mut public_key_contents = String::new();
        public_key_file.read_to_string(&mut public_key_contents).unwrap();

        let public_key = RsaPublicKey::from_pkcs1_pem(&public_key_contents).unwrap();
        let public_key_n = BigUint::from_bytes_be(&public_key.n().clone().to_bytes_be());

        let circuit = Self::new(payload_bytes, signature_bytes, public_key_n);
        circuit
    }

    /// Compute public input values as [`DefaultCommitVerifyPublicInput`] from the circuit.
    pub fn gen_default_public_input(&self) -> DefaultCommitVerifyPublicInput {
        let signature = BigUint::from_bytes_be(&self.signature_bytes);
        let config_params = default_config_params();
        let num_limbs = config_params.sign_verify_config.as_ref().unwrap().public_key_bits / LIMB_BITS;
        let sign_commit: F = {
            let limbs = decompose_biguint(&signature, num_limbs, LIMB_BITS);
            poseidon_hash_fields(&limbs)
        };
        let public_key_hash = {
            let limbs = decompose_biguint(&self.public_key_n, num_limbs, LIMB_BITS);
            poseidon_hash_fields(&limbs)
        };
        let payload_params = config_params.body_config.as_ref().unwrap();
        let payload_str = String::from_utf8(self.payload_bytes.clone()).unwrap();
        println!("payload_params {:?}", payload_params);
        println!("payload_str {:?}", payload_str);

        let payload_substrs = get_payload_substrs(&payload_str, &payload_params.substr_regexes);
        println!("payload_substrs {:?}", payload_substrs);

        DefaultCommitVerifyPublicInput::new(sign_commit, public_key_hash, payload_substrs)
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn configure_native(meta: &mut ConstraintSystem<F>) -> DefaultCommitVerifyConfig<F> {
        let params = default_config_params();
        let range_config = RangeConfig::configure(
            meta,
            Vertical,
            &[params.num_flex_advice],
            &[params.num_range_lookup_advice],
            params.num_flex_advice,
            params.range_lookup_bits,
            0,
            params.degree as usize,
        );
        let header_params = params.header_config.as_ref().expect("header_config is required");
        let body_params = params.body_config.as_ref().expect("body_config is required");
        let sign_verify_params = params.sign_verify_config.as_ref().expect("sign_verify_config is required");
        let sha256_params = params.sha256_config.as_ref().expect("sha256_config is required");
        assert_eq!(header_params.allstr_filepathes.len(), header_params.substr_filepathes.len());
        assert_eq!(body_params.allstr_filepathes.len(), body_params.substr_filepathes.len());

        let sha256_config = Sha256DynamicConfig::configure(
            meta,
            vec![body_params.max_variable_byte_size, header_params.max_variable_byte_size],
            range_config.clone(),
            sha256_params.num_bits_lookup,
            sha256_params.num_advice_columns,
            false,
        );

        let sign_verify_config = SignVerifyConfig::configure(range_config.clone(), sign_verify_params.public_key_bits);

        let bodyhash_allstr_def = AllstrRegexDef::read_from_text(&header_params.bodyhash_allstr_filepath);
        let bodyhash_substr_def = SubstrRegexDef::read_from_text(&header_params.bodyhash_substr_filepath);
        let bodyhash_defs = RegexDefs {
            allstr: bodyhash_allstr_def,
            substrs: vec![bodyhash_substr_def],
        };
        let mut bodyhash_substr_id = 1;
        let header_regex_defs = header_params
            .allstr_filepathes
            .iter()
            .zip(header_params.substr_filepathes.iter())
            .map(|(allstr_path, substr_pathes)| {
                let allstr = AllstrRegexDef::read_from_text(&allstr_path);
                let substrs = substr_pathes.into_iter().map(|path| SubstrRegexDef::read_from_text(&path)).collect_vec();
                bodyhash_substr_id += substrs.len();
                RegexDefs { allstr, substrs }
            })
            .collect_vec();
        let header_config = RegexSha2Config::configure(
            meta,
            header_params.max_variable_byte_size,
            header_params.skip_prefix_bytes_size.unwrap_or(0),
            range_config.clone(),
            vec![header_regex_defs, vec![bodyhash_defs]].concat(),
        );

        let body_regex_defs = body_params
            .allstr_filepathes
            .iter()
            .zip(body_params.substr_filepathes.iter())
            .map(|(allstr_path, substr_pathes)| {
                let allstr = AllstrRegexDef::read_from_text(&allstr_path);
                let substrs = substr_pathes.into_iter().map(|path| SubstrRegexDef::read_from_text(&path)).collect_vec();
                RegexDefs { allstr, substrs }
            })
            .collect_vec();
        let body_config = RegexSha2Base64Config::configure(
            meta,
            body_params.max_variable_byte_size,
            body_params.skip_prefix_bytes_size.unwrap_or(0),
            range_config,
            body_regex_defs,
        );
        let chars_shift_config = CharsShiftConfig::configure(header_params.max_variable_byte_size, 44, bodyhash_substr_id as u64);

        let instances = meta.instance_column();
        meta.enable_equality(instances);
        DefaultCommitVerifyConfig {
            sha256_config,
            sign_verify_config,
            header_config,
            body_config,
            chars_shift_config,
            instances,
        }
    }
}
/*
#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod test {
    use super::*;
    use cfdkim::{resolve_public_key, SignerBuilder};
    use halo2_base::halo2_proofs::{
        circuit::Value,
        dev::{CircuitCost, FailureLocation, MockProver, VerifyFailure},
        halo2curves::bn256::{Fr, G1},
    };
    use halo2_regex::vrm::DecomposedRegexConfig;
    use halo2_rsa::RSAPubE;
    use mailparse::parse_mail;
    use num_bigint::BigUint;
    use rand::thread_rng;
    use rsa::{traits::PublicKeyParts, RsaPrivateKey};
    use snark_verifier_sdk::CircuitExt;
    use std::{fs::File, io::Read, path::Path};
    use temp_env;

    #[test]
    fn test_generated_email1() {
        temp_env::with_var(EMAIL_VERIFY_CONFIG_ENV, Some("./configs/test1_email_verify.config"), || {
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
            let regex_body_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/test1_email_body_defs.json").unwrap()).unwrap();
            regex_body_decomposed
                .gen_regex_files(
                    &Path::new("./test_data/test1_email_body_allstr.txt").to_path_buf(),
                    &[Path::new("./test_data/test1_email_body_substr_0.txt").to_path_buf()],
                )
                .unwrap();
            let params = default_config_params();
            let sign_verify_config = params.sign_verify_config.as_ref().expect("sign_verify_config is required");
            let mut rng = thread_rng();
            let _private_key = RsaPrivateKey::new(&mut rng, sign_verify_config.public_key_bits).expect("failed to generate a key");
            let public_key = rsa::RsaPublicKey::from(&_private_key);
            let private_key = cfdkim::DkimPrivateKey::Rsa(_private_key);
            let message = concat!("From: alice@zkemail.com\r\n", "\r\n", "email was meant for @zkemailverify.",).as_bytes();
            let email = parse_mail(message).unwrap();
            let logger = slog::Logger::root(slog::Discard, slog::o!());
            let signer = SignerBuilder::new()
                .with_signed_headers(&["From"])
                .unwrap()
                .with_private_key(private_key)
                .with_selector("default")
                .with_signing_domain("zkemail.com")
                .with_logger(&logger)
                .with_header_canonicalization(cfdkim::canonicalization::Type::Relaxed)
                .with_body_canonicalization(cfdkim::canonicalization::Type::Relaxed)
                .build()
                .unwrap();
            let signature = signer.sign(&email).unwrap();
            let email_bytes = vec![signature.as_bytes(), b"\r\n", message].concat();
            println!("email: {}", String::from_utf8(email_bytes.clone()).unwrap());
            let public_key_n = BigUint::from_bytes_be(&public_key.n().clone().to_bytes_be());
            let circuit = DefaultCommitVerifyCircuit::<Fr>::new(email_bytes, public_key_n);
            let instances = circuit.instances();
            let prover = MockProver::run(params.degree, &circuit, instances).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        });
    }

    #[test]
    fn test_generated_email2() {
        temp_env::with_var(EMAIL_VERIFY_CONFIG_ENV, Some("./configs/test2_email_verify.config"), || {
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
            let regex_body_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/test2_email_body_defs.json").unwrap()).unwrap();
            regex_body_decomposed
                .gen_regex_files(
                    &Path::new("./test_data/test2_email_body_allstr.txt").to_path_buf(),
                    &[
                        Path::new("./test_data/test2_email_body_substr_0.txt").to_path_buf(),
                        Path::new("./test_data/test2_email_body_substr_1.txt").to_path_buf(),
                    ],
                )
                .unwrap();
            let params = default_config_params();
            let sign_verify_config = params.sign_verify_config.as_ref().expect("sign_verify_config is required");
            let mut rng = thread_rng();
            let _private_key = RsaPrivateKey::new(&mut rng, sign_verify_config.public_key_bits).expect("failed to generate a key");
            let public_key = rsa::RsaPublicKey::from(&_private_key);
            let private_key = cfdkim::DkimPrivateKey::Rsa(_private_key);
            let message = concat!(
                "From: alice@zkemail.com\r\n",
                "To: bob@example.com\r\n",
                "\r\n",
                "email was meant for @zkemailverify and halo.",
            )
            .as_bytes();
            let email = parse_mail(message).unwrap();
            let logger = slog::Logger::root(slog::Discard, slog::o!());
            let signer = SignerBuilder::new()
                .with_signed_headers(&["To", "From"])
                .unwrap()
                .with_private_key(private_key)
                .with_selector("default")
                .with_signing_domain("zkemail.com")
                .with_logger(&logger)
                .with_header_canonicalization(cfdkim::canonicalization::Type::Relaxed)
                .with_body_canonicalization(cfdkim::canonicalization::Type::Relaxed)
                .build()
                .unwrap();
            let signature = signer.sign(&email).unwrap();
            println!("signature {}", signature);
            let email_bytes = vec![signature.as_bytes(), b"\r\n", message].concat();
            let public_key_n = BigUint::from_bytes_be(&public_key.n().clone().to_bytes_be());
            let circuit = DefaultCommitVerifyCircuit::<Fr>::new(email_bytes, public_key_n);

            let instances = circuit.instances();
            let prover = MockProver::run(params.degree, &circuit, instances).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        });
    }

    #[tokio::test]
    async fn test_existing_email1() {
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
        println!("email {}", String::from_utf8(email_bytes.clone()).unwrap());
        println!("email bytes {:?}", email_bytes.clone());
        let logger = slog::Logger::root(slog::Discard, slog::o!());
        let public_key = resolve_public_key(&logger, &email_bytes).await.unwrap();
        let public_key = match public_key {
            cfdkim::DkimPublicKey::Rsa(pk) => pk,
            _ => panic!("not supportted public key type."),
        };
        temp_env::with_var(EMAIL_VERIFY_CONFIG_ENV, Some("./configs/test_ex1_email_verify.config"), move || {
            let params = default_config_params();
            let public_key_n = BigUint::from_bytes_be(&public_key.n().clone().to_bytes_be());
            let circuit = DefaultCommitVerifyCircuit::<Fr>::new(email_bytes.clone(), public_key_n);

            let instances = circuit.instances();
            let prover = MockProver::run(params.degree, &circuit, instances).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        });
    }

    #[tokio::test]
    async fn test_existing_email2() {
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
        let regex_body_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/test_ex2_email_body_defs.json").unwrap()).unwrap();
        regex_body_decomposed
            .gen_regex_files(
                &Path::new("./test_data/test_ex2_email_body_allstr.txt").to_path_buf(),
                &[
                    Path::new("./test_data/test_ex2_email_body_substr_0.txt").to_path_buf(),
                    Path::new("./test_data/test_ex2_email_body_substr_1.txt").to_path_buf(),
                    Path::new("./test_data/test_ex2_email_body_substr_2.txt").to_path_buf(),
                ],
            )
            .unwrap();
        let email_bytes = {
            let mut f = File::open("./test_data/test_email2.eml").unwrap();
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).unwrap();
            buf
        };

        let logger = slog::Logger::root(slog::Discard, slog::o!());
        let public_key = resolve_public_key(&logger, &email_bytes).await.unwrap();
        let public_key = match public_key {
            cfdkim::DkimPublicKey::Rsa(pk) => pk,
            _ => panic!("not supportted public key type."),
        };
        temp_env::with_var(EMAIL_VERIFY_CONFIG_ENV, Some("./configs/test_ex2_email_verify.config"), move || {
            let params = default_config_params();
            let public_key_n = BigUint::from_bytes_be(&public_key.n().clone().to_bytes_be());
            let circuit = DefaultCommitVerifyCircuit::<Fr>::new(email_bytes.clone(), public_key_n);

            let instances = circuit.instances();
            let prover = MockProver::run(params.degree, &circuit, instances).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        });
    }

    #[ignore]
    #[tokio::test]
    async fn test_existing_email3() {
        let regex_bodyhash_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/bodyhash_defs.json").unwrap()).unwrap();
        regex_bodyhash_decomposed
            .gen_regex_files(
                &Path::new("./test_data/bodyhash_allstr.txt").to_path_buf(),
                &[Path::new("./test_data/bodyhash_substr_0.txt").to_path_buf()],
            )
            .unwrap();
        let regex_timestamp_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/timestamp_defs.json").unwrap()).unwrap();
        regex_timestamp_decomposed
            .gen_regex_files(
                &Path::new("./test_data/timestamp_allstr.txt").to_path_buf(),
                &[Path::new("./test_data/timestamp_substr_0.txt").to_path_buf()],
            )
            .unwrap();
        let regex_body_decomposed: DecomposedRegexConfig = serde_json::from_reader(File::open("./test_data/test_ex3_email_body_defs.json").unwrap()).unwrap();
        regex_body_decomposed
            .gen_regex_files(
                &Path::new("./test_data/test_ex3_email_body_allstr.txt").to_path_buf(),
                &[Path::new("./test_data/test_ex3_email_body_substr_0.txt").to_path_buf()],
            )
            .unwrap();
        let email_bytes = {
            let mut f = File::open("./test_data/test_email3.eml").unwrap();
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).unwrap();
            buf
        };

        let logger = slog::Logger::root(slog::Discard, slog::o!());
        let public_key = resolve_public_key(&logger, &email_bytes).await.unwrap();
        let public_key = match public_key {
            cfdkim::DkimPublicKey::Rsa(pk) => pk,
            _ => panic!("not supportted public key type."),
        };
        temp_env::with_var(EMAIL_VERIFY_CONFIG_ENV, Some("./configs/test_ex3_email_verify.config"), move || {
            let params = default_config_params();
            let public_key_n = BigUint::from_bytes_be(&public_key.n().clone().to_bytes_be());
            let circuit = DefaultCommitVerifyCircuit::<Fr>::new(email_bytes.clone(), public_key_n);

            let instances = circuit.instances();
            let prover = MockProver::run(params.degree, &circuit, instances).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        });
    }

    #[tokio::test]
    async fn test_existing_email_invalid1() {
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
        let public_key = resolve_public_key(&logger, &email_bytes).await.unwrap();
        let public_key = match public_key {
            cfdkim::DkimPublicKey::Rsa(pk) => pk,
            _ => panic!("not supportted public key type."),
        };
        temp_env::with_var(EMAIL_VERIFY_CONFIG_ENV, Some("./configs/test_ex1_email_verify.config"), move || {
            let params = default_config_params();
            let mut public_key_n_bytes = public_key.n().clone().to_bytes_be();
            for i in 0..256 {
                public_key_n_bytes[i] = 255;
            }
            let public_key_n = BigUint::from_bytes_be(&public_key_n_bytes);
            let circuit = DefaultCommitVerifyCircuit::<Fr>::new(email_bytes.clone(), public_key_n);

            let instances = circuit.instances();
            let prover = MockProver::run(params.degree, &circuit, instances).unwrap();
            assert!(prover.verify().is_err());
        });
    }

    #[tokio::test]
    async fn test_existing_email_invalid2() {
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
            let mut f = File::open("./test_data/invalid_test_email1.eml").unwrap();
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).unwrap();
            buf
        };

        let logger = slog::Logger::root(slog::Discard, slog::o!());
        let public_key = resolve_public_key(&logger, &email_bytes).await.unwrap();
        let public_key = match public_key {
            cfdkim::DkimPublicKey::Rsa(pk) => pk,
            _ => panic!("not supportted public key type."),
        };
        temp_env::with_var(EMAIL_VERIFY_CONFIG_ENV, Some("./configs/test_ex1_email_verify.config"), move || {
            let params = default_config_params();
            let public_key_n = BigUint::from_bytes_be(&public_key.n().clone().to_bytes_be());
            let circuit = DefaultCommitVerifyCircuit::<Fr>::new(email_bytes.clone(), public_key_n);

            let instances = circuit.instances();
            let prover = MockProver::run(params.degree, &circuit, instances).unwrap();
            assert!(prover.verify().is_err());
        });
    }
}
 */
