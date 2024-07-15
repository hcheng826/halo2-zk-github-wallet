use halo2_base::gates::{flex_gate::FlexGateConfig, range::RangeConfig};
use halo2_dynamic_sha256::*;
use halo2_regex::defs::{AllstrRegexDef, RegexDefs, SubstrRegexDef};
use std::fs::File;
// use regex_sha2_base64::RegexSha2Base64Config;
use crate::{DefaultCommitVerifyCircuit, RegexSha2Base64Config, RegexSha2Config, SignVerifyConfig};
use once_cell::sync::OnceCell;

#[cfg(not(test))]
pub fn default_config_params() -> CommitVerifyConfigParams {
    #[cfg(not(target_arch = "wasm32"))]
    {
        if GLOBAL_CONFIG_PARAMS.get().is_none() {
            CommitVerifyConfigParams::set_from_env();
        }
        CommitVerifyConfigParams::global().clone()
    }
    #[cfg(target_arch = "wasm32")]
    {
        // wasm::get_config_params_wasm()
        CommitVerifyConfigParams::global().clone()
    }
}

#[cfg(test)]
pub fn default_config_params() -> &'static CommitVerifyConfigParams {
    let params = CommitVerifyConfigParams::get_from_env();
    let params = Box::new(params);
    let static_ref: &'static mut CommitVerifyConfigParams = Box::leak(params);
    static_ref
}

pub static GLOBAL_CONFIG_PARAMS: OnceCell<CommitVerifyConfigParams> = OnceCell::new();
#[cfg(target_arch = "wasm32")]
pub static GLOBAL_BODYHASH_DEFS_AND_ID: OnceCell<(RegexDefs, usize)> = OnceCell::new();
#[cfg(target_arch = "wasm32")]
pub static GLOBAL_HEADER_DEFS: OnceCell<Vec<RegexDefs>> = OnceCell::new();
#[cfg(target_arch = "wasm32")]
pub static GLOBAL_BODY_DEFS: OnceCell<Vec<RegexDefs>> = OnceCell::new();

/// The name of env variable for the path to the commit configuration json.
pub const COMMIT_VERIFY_CONFIG_ENV: &'static str = "COMMIT_VERIFY_CONFIG";

/// Configuration parameters for [`Sha256DynamicConfig`]
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct Sha256ConfigParams {
    /// The bits of lookup table. It must be a divisor of 16, i.e., 1, 2, 4, 8, and 16.
    pub num_bits_lookup: usize,
    /// The number of advice columns used to assign values in [`Sha256DynamicConfig`].
    /// Specifying a larger number of columns increases the verification cost and decreases the proving cost.
    pub num_advice_columns: usize,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct PayloadConfigParams {
    // pub bodyhash_allstr_filepath: String,
    // pub bodyhash_substr_filepath: String,
    pub allstr_filepathes: Vec<String>,
    pub substr_filepathes: Vec<Vec<String>>,
    pub max_variable_byte_size: usize,
    pub substr_regexes: Vec<Vec<String>>,
    /// The bytes of the skipped email header that do not satisfy the regexes.
    /// It must be multiple of 64 and less than `max_variable_byte_size`.
    pub skip_prefix_bytes_size: Option<usize>,
    // pub expose_substrs: Option<bool>,
}

/// Configuration parameters for [`SignVerifyConfig`].
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct SignVerifyConfigParams {
    /// The bits of RSA public key.
    pub public_key_bits: usize,
    /// A flag whether the public key is hidden.
    pub hide_public_key: Option<bool>,
}

/// Configuration parameters for the commit verification circuits.
///
/// Although the types of some parameters are defined as [`Option`], you will get an error if they are omitted for [`DefaultCommitVerifyCircuit`].
/// You can build a circuit that accepts the same format configuration file except that some parameters are omitted.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct CommitVerifyConfigParams {
    /// The degree of the number of rows, i.e., 2^(`degree`) rows are set.
    pub degree: u32,
    /// The number of advice columns in [`FlexGateConfig`].
    pub num_flex_advice: usize,
    /// The number of advice columns for lookup constraints in [`RangeConfig`].
    pub num_range_lookup_advice: usize,
    /// The number of fix columns in [`FlexGateConfig`].
    pub num_flex_fixed: usize,
    /// The bits of lookup table in [`RangeConfig`], which must be less than `degree`.
    pub range_lookup_bits: usize,
    /// Configuration parameters for [`Sha256DynamicConfig`].
    pub sha256_config: Option<Sha256ConfigParams>,
    /// Configuration parameters for [`SignVerifyConfig`].
    pub sign_verify_config: Option<SignVerifyConfigParams>,
    /// Configuration parameters for [`RegexSha2Config`].
    pub payload_config: Option<PayloadConfigParams>,
}

impl CommitVerifyConfigParams {
    /// Return the [`CommitVerifyConfigParams`] stored in [`GLOBAL_CONFIG_PARAMS`].
    pub fn global() -> &'static Self {
        GLOBAL_CONFIG_PARAMS.get().expect("GLOBAL_CONFIG_PARAMS is not set.")
    }

    /// Set the [`CommitVerifyConfigParams`] in the path of [`COMMIT_VERIFY_CONFIG_ENV`]  to [`GLOBAL_CONFIG_PARAMS`].
    pub fn set_from_env() {
        let params: Self = Self::get_from_env();
        GLOBAL_CONFIG_PARAMS.set(params).unwrap();
    }

    /// Get the [`CommitVerifyConfigParams`] from the path of [`COMMIT_VERIFY_CONFIG_ENV`].
    pub fn get_from_env() -> Self {
        let path = std::env::var(COMMIT_VERIFY_CONFIG_ENV).expect("You must set the configure file path to COMMIT_VERIFY_CONFIG.");
        serde_json::from_reader(File::open(path.as_str()).expect(&format!("{} does not exist.", path))).expect("File is found but invalid.")
    }
}
