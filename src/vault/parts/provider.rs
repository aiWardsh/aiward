fn derive_key(passphrase: &str, salt: &[u8], kdf: &KdfEnvelope) -> Result<[u8; KEY_LEN]> {
    let params = Params::new(
        kdf.memory_cost,
        kdf.time_cost,
        kdf.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|error| anyhow!("invalid Argon2 parameters: {error}"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0_u8; KEY_LEN];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|error| anyhow!("failed to derive vault key: {error}"))?;
    Ok(key)
}

fn derive_api_vault_key(
    passphrase: &str,
    salt: &[u8],
    kdf: &KdfEnvelope,
    api: &ApiDerivedEnvelope,
) -> Result<[u8; KEY_LEN]> {
    validate_api_metadata(api)?;
    let mut client_factor = derive_key(passphrase, salt, kdf)?;
    let server_material =
        default_key_provider().derive_server_material(api, &client_factor, kdf)?;
    let mut input = Vec::with_capacity(client_factor.len() + server_material.len());
    input.extend_from_slice(&client_factor);
    input.extend_from_slice(&server_material);
    client_factor.zeroize();

    let hk = Hkdf::<Sha256>::new(Some(API_HKDF_SALT), &input);
    input.zeroize();
    let mut key = [0_u8; KEY_LEN];
    hk.expand(API_HKDF_INFO, &mut key)
        .map_err(|_| anyhow!("failed to derive api-derived vault key"))?;
    Ok(key)
}

fn validate_api_metadata(api: &ApiDerivedEnvelope) -> Result<()> {
    anyhow::ensure!(
        !api.vault_id.trim().is_empty(),
        "api-derived vault is missing vaultId"
    );
    anyhow::ensure!(
        !api.key_derivation_nonce.trim().is_empty(),
        "api-derived vault is missing keyDerivationNonce"
    );
    anyhow::ensure!(
        !api.server_key_id.trim().is_empty(),
        "api-derived vault is missing serverKeyId"
    );
    Ok(())
}

#[cfg(not(test))]
fn derive_api_server_material_http(
    api: &ApiDerivedEnvelope,
    client_factor: &[u8; KEY_LEN],
    kdf: &KdfEnvelope,
) -> Result<[u8; KEY_LEN]> {
    let request = ApiDeriveRequest {
        version: 1,
        vault_id: api.vault_id.clone(),
        key_derivation_nonce: api.key_derivation_nonce.clone(),
        server_key_id: api.server_key_id.clone(),
        client_kdf: ApiClientKdf {
            name: kdf.name.clone(),
            memory_cost: kdf.memory_cost,
            time_cost: kdf.time_cost,
            parallelism: kdf.parallelism,
        },
        client_factor: STANDARD.encode(client_factor),
    };
    let endpoint = key_api_url();
    let response = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("failed to initialize Ward key API client")?
        .post(&endpoint)
        .json(&request)
        .send()
        .with_context(|| format!("failed to call Ward key API at {endpoint}"))?;
    if response.status().as_u16() == 429 {
        anyhow::bail!("Ward key API rate limit exceeded; wait before trying this PIN again");
    }
    if !response.status().is_success() {
        anyhow::bail!("Ward key API derive failed with HTTP {}", response.status());
    }
    let body: ApiDeriveResponse = response
        .json()
        .context("failed to parse Ward key API derive response")?;
    validate_api_response(body, &api.server_key_id)
}

fn validate_api_response(
    body: ApiDeriveResponse,
    expected_server_key_id: &str,
) -> Result<[u8; KEY_LEN]> {
    anyhow::ensure!(
        body.version == 1,
        "unsupported Ward key API response version {}",
        body.version
    );
    anyhow::ensure!(
        body.server_key_id == expected_server_key_id,
        "Ward key API responded with server key id {}; expected {}",
        body.server_key_id,
        expected_server_key_id
    );
    let decoded = STANDARD
        .decode(body.key_material)
        .context("Ward key API returned invalid key material")?;
    decoded.try_into().map_err(|value: Vec<u8>| {
        anyhow!(
            "Ward key API returned {} bytes of key material; expected {KEY_LEN}",
            value.len()
        )
    })
}

#[cfg(not(test))]
fn key_api_url() -> String {
    env::var("WARD_KEY_API_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_KEY_API_URL.to_string())
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(not(test))]
struct ApiDeriveRequest {
    version: u32,
    vault_id: String,
    key_derivation_nonce: String,
    server_key_id: String,
    client_kdf: ApiClientKdf,
    client_factor: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(not(test))]
struct ApiClientKdf {
    name: String,
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiDeriveResponse {
    version: u32,
    server_key_id: String,
    key_material: String,
}
