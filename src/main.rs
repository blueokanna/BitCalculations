mod utils;

use anyhow::{anyhow, Result};
use bip39::{Language, Mnemonic, Seed};
use bitcoin::secp256k1::{All, PublicKey, Secp256k1};
use bitcoin::{Address, CompressedPublicKey, Network, PubkeyHash};
use std::str::FromStr;

use crate::utils::{base58check_encode, remove_prefix, ripple_base58check_encode};
use bitcoin::bip32::{DerivationPath, ExtendedPrivKey};
use bitcoin::hashes::{ripemd160, sha256, Hash};
use chrono::Local;
use futures::future::join_all;
use hex::encode;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tiny_keccak::{Hasher, Keccak};
use tokio::fs::{self, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tokio::time::sleep;

// 数据结构：存储私钥、地址和余额
#[derive(Serialize, Deserialize, Debug)]
struct WalletInfo {
    private_key: String,
    address: String,
    balance: f64,
    currency: String,
}

async fn save_wallet_info(wallet: &WalletInfo, file_path: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(file_path)
        .await?;

    let data = serde_json::to_string(wallet)? + "\n";
    file.write_all(data.as_bytes()).await?;
    Ok(())
}

async fn load_wallet_info(file_path: &str) -> Result<Vec<WalletInfo>> {
    if let Ok(data) = fs::read_to_string(file_path).await {
        let wallets: Vec<WalletInfo> = data
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        Ok(wallets)
    } else {
        Ok(vec![])
    }
}

async fn generate_address_for_network(
    extended_priv_key: &ExtendedPrivKey,
    secp: &Secp256k1<All>,
    network: &str,
    index: usize,
) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
    // 根据不同网络选择对应的派生路径和前缀
    let (derivation_path_str, prefix) = match network {
        "ETH" => (format!("m/44'/60'/0'/0/{}", index), 0x00), //ETH (无)前缀
        "DOGE" => (format!("m/44'/3'/0'/0/{}", index), 0x1E), // DOGE 前缀
        "DASH" => (format!("m/44'/5'/0'/0/{}", index), 0x4C), // DASH 前缀
        "LTC" => (format!("m/44'/2'/0'/0/{}", index), 0x30),  // LTC 前缀
        "RVN" => (format!("m/44'/175'/0'/0/{}", index), 0x3C), //RVN 前缀
        "XRP" => (format!("m/44'/144'/0'/0/{}", index), 0x00), //XRP 前缀
        _ => return Err("Unsupported network".into()),        // 其它网络不支持
    };

    // 创建派生路径
    let derivation_path = DerivationPath::from_str(derivation_path_str.as_str())?;
    let derived_priv_key = extended_priv_key.derive_priv(secp, &derivation_path)?;
    let secret_key = derived_priv_key.private_key;
    let public_key = PublicKey::from_secret_key(secp, &secret_key);
    let compressed_public_key = CompressedPublicKey::from_slice(&public_key.clone().serialize())?;
    let uncompressed_public_key =
        CompressedPublicKey::from_slice(&public_key.clone().serialize_uncompressed())?;

    //let mut no_profix = uncompressed_public_key.0.serialize_uncompressed();
    let mut no_profix = remove_prefix(&mut uncompressed_public_key.0.serialize_uncompressed());
    //let mut temp_no_profix = &no_profix[1..65];
    let mut temp_keccak = Keccak::v256();
    let mut temp_address = [0u8; 32];
    temp_keccak.update(&mut no_profix);
    temp_keccak.finalize(&mut temp_address);
    let ethereum_address = &temp_address[12..32];

    // 生成地址：通过公钥计算 SHA256 -> RIPEMD160
    let pub_key_sha256 = sha256::Hash::hash(&compressed_public_key.to_bytes());
    let pub_key_ripemd160 = ripemd160::Hash::hash(pub_key_sha256.as_ref());

    // 拼接前缀和公钥哈希
    let mut versioned_payload = Vec::new();
    versioned_payload.push(prefix);
    versioned_payload.extend_from_slice((&pub_key_ripemd160).as_ref());

    // Base58Check 编码生成地址
    let address: String = match network {
        "ETH" => format!("0x{}", encode(ethereum_address)),
        "XRP" => ripple_base58check_encode(&versioned_payload)?,
        _ => base58check_encode(&versioned_payload)?,
    };
    //let address = base58check_encode(&versioned_payload)?;

    let private_key = encode(secret_key.secret_bytes());
    Ok((private_key, address))
}

// 助记词转换为私钥和地址
async fn mnemonic_to_private_key_and_address(
    mnemonic: &str,
    language: Language,
    password: &str,
    network: &str,
) -> Result<Vec<(String, String)>> {
    let mnemonic = Mnemonic::from_phrase(mnemonic, language)?;
    let seed = Seed::new(&mnemonic, password);

    let secp = Secp256k1::new();
    let extended_priv_key = ExtendedPrivKey::new_master(Network::Bitcoin, &seed.as_bytes())?;

    let mut addresses = Vec::new();

    match network {
        "BTC" => {
            let bip141_semantics = {
                let mut semantics = Vec::new();
                if BTC_SCAN_BIP141_P2SH_P2WPKH {
                    semantics.push("p2shwpkh");
                }
                if BTC_SCAN_BIP141_P2WPKH {
                    semantics.push("p2wpkh");
                }
                if semantics.is_empty() {
                    return Err(anyhow!(
                        "BIP141 semantics are all disabled, enable at least one of P2SH-P2WPKH/P2WPKH"
                    )
                    .into());
                }
                semantics
            };

            let btc_specs = vec![
                (
                    "BIP44",
                    vec!["p2pkh"],
                    "m/44'/0'/0'/0/{}",
                    "m/44'/0'/0'/0'/{}'",
                ),
                (
                    "BIP49",
                    vec!["p2shwpkh"],
                    "m/49'/0'/0'/0/{}",
                    "m/49'/0'/0'/0'/{}'",
                ),
                (
                    "BIP84",
                    vec!["p2wpkh"],
                    "m/84'/0'/0'/0/{}",
                    "m/84'/0'/0'/0'/{}'",
                ),
                ("BIP141", bip141_semantics, "m/0/{}", "m/0'/{}'"),
            ];

            for (spec_name, script_semantics_list, standard_tpl, hardened_tpl) in btc_specs {
                for i in 0..BTC_ADDRESS_INDEX_END_EXCLUSIVE {
                    let mut derivation_variants = Vec::new();
                    if BTC_SCAN_STANDARD_PATHS {
                        derivation_variants
                            .push(("standard", standard_tpl.replace("{}", &i.to_string())));
                    }
                    if BTC_SCAN_HARDENED_PATHS {
                        derivation_variants
                            .push(("hardened", hardened_tpl.replace("{}", &i.to_string())));
                    }
                    if derivation_variants.is_empty() {
                        return Err(anyhow!(
                            "BTC derivation variants are all disabled, enable standard/hardened"
                        )
                        .into());
                    }

                    for script_semantics in &script_semantics_list {
                        for (variant_name, derivation_path_str) in &derivation_variants {
                            let derivation_path = DerivationPath::from_str(derivation_path_str)?;
                            let derived_priv_key =
                                extended_priv_key.derive_priv(&secp, &derivation_path)?;
                            let secret_key = derived_priv_key.private_key;
                            let public_key = PublicKey::from_secret_key(&secp, &secret_key);
                            let compressed_public_key =
                                CompressedPublicKey::from_slice(&public_key.clone().serialize())?;

                            let address = match *script_semantics {
                                "p2pkh" => {
                                    let pub_key_sha256 =
                                        sha256::Hash::hash(&compressed_public_key.to_bytes());
                                    let pub_key_ripemd160 =
                                        ripemd160::Hash::hash(pub_key_sha256.as_ref());
                                    let pubkey_hash =
                                        PubkeyHash::from_slice(pub_key_ripemd160.as_ref())?;
                                    Address::p2pkh(pubkey_hash, Network::Bitcoin).to_string()
                                }
                                "p2shwpkh" => {
                                    Address::p2shwpkh(&compressed_public_key, Network::Bitcoin)
                                        .to_string()
                                }
                                "p2wpkh" => {
                                    Address::p2wpkh(&compressed_public_key, Network::Bitcoin)
                                        .to_string()
                                }
                                _ => {
                                    return Err(anyhow!(
                                        "Unsupported BTC script semantics: {}",
                                        script_semantics
                                    )
                                    .into())
                                }
                            };

                            println!(
                                "BTC Derivation [{} - {} - {}]: {} -> {}",
                                spec_name,
                                script_semantics,
                                variant_name,
                                derivation_path_str,
                                address
                            );

                            let private_key = hex::encode(secret_key.secret_bytes());
                            addresses.push((private_key, address));
                        }
                    }
                }
            }
        }
        "ETH" | "DOGE" | "DASH" | "LTC" | "RVN" | "XRP" => {
            for i in 0..1 {
                match generate_address_for_network(&extended_priv_key, &secp, network, i).await {
                    Ok((private_key, address)) => addresses.push((private_key, address)),
                    Err(e) => return Err(anyhow!("Error generating address: {}", e).into()),
                }
            }
        }
        _ => return Err(anyhow!("Unsupported network: {}", network).into()),
    }

    Ok(addresses)
}

// 查询地址余额（支持 BTC 和 DOGE）
async fn get_balance(address: &str, network: &str) -> Result<f64> {
    let client = build_http_client()?;
    match network {
        "BTC" => get_btc_balance_with_failover(&client, address).await,
        "ETH" => get_eth_balance_with_failover(&client, address).await,
        "DOGE" => get_doge_balance_with_failover(&client, address).await,
        "DASH" => get_dash_balance_with_failover(&client, address).await,
        "LTC" => get_ltc_balance_with_failover(&client, address).await,
        "XRP" => get_xrp_balance_with_failover(&client, address).await,
        "RVN" => get_rvn_balance_with_failover(&client, address).await,
        _ => Err(anyhow!("Unsupported network: {}", network).into()),
    }
}

const CHECK_INTERVAL_SECS: u64 = 3;
const REQUEST_TIMEOUT_SECS: u64 = 15;
const MAX_PROVIDER_RETRIES: usize = 2;
const BTC_ADDRESS_INDEX_END_EXCLUSIVE: usize = 1;
const BTC_SCAN_STANDARD_PATHS: bool = true;
const BTC_SCAN_HARDENED_PATHS: bool = true;
const BTC_SCAN_BIP141_P2SH_P2WPKH: bool = true;
const BTC_SCAN_BIP141_P2WPKH: bool = true;

static RATE_LIMITER: OnceLock<Mutex<Option<Instant>>> = OnceLock::new();

fn global_rate_limiter() -> &'static Mutex<Option<Instant>> {
    RATE_LIMITER.get_or_init(|| Mutex::new(None))
}

async fn throttle_requests() {
    let mut guard = global_rate_limiter().lock().await;
    if let Some(last_request) = *guard {
        let elapsed = last_request.elapsed();
        if elapsed < Duration::from_secs(CHECK_INTERVAL_SECS) {
            sleep(Duration::from_secs(CHECK_INTERVAL_SECS) - elapsed).await;
        }
    }
    *guard = Some(Instant::now());
}

fn build_http_client() -> Result<Client> {
    Ok(Client::builder()
        .user_agent("BitCalculations/1.0 (production balance checker)")
        .connect_timeout(Duration::from_secs(8))
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .pool_max_idle_per_host(8)
        .build()?)
}

async fn request_json_with_retries(
    client: &Client,
    provider: &str,
    url: &str,
) -> Result<serde_json::Value> {
    let mut errors = Vec::new();

    for attempt in 0..=MAX_PROVIDER_RETRIES {
        throttle_requests().await;

        let response = match client.get(url).send().await {
            Ok(resp) => resp,
            Err(e) => {
                errors.push(format!("attempt {} request failed: {}", attempt + 1, e));
                if attempt < MAX_PROVIDER_RETRIES {
                    sleep(Duration::from_millis(700 * (attempt as u64 + 1))).await;
                    continue;
                }
                break;
            }
        };

        if !response.status().is_success() {
            let status = response.status();
            errors.push(format!(
                "attempt {} returned status {}",
                attempt + 1,
                status
            ));
            if (status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error())
                && attempt < MAX_PROVIDER_RETRIES
            {
                sleep(Duration::from_millis(1200 * (attempt as u64 + 1))).await;
                continue;
            }
            break;
        }

        match response.json::<serde_json::Value>().await {
            Ok(parsed) => return Ok(parsed),
            Err(e) => {
                errors.push(format!("attempt {} json parse failed: {}", attempt + 1, e));
                if attempt < MAX_PROVIDER_RETRIES {
                    sleep(Duration::from_millis(500 * (attempt as u64 + 1))).await;
                    continue;
                }
                break;
            }
        }
    }

    Err(anyhow!(
        "provider {} failed for {}: {}",
        provider,
        url,
        errors.join(" | ")
    ))
}

async fn request_text_with_retries(client: &Client, provider: &str, url: &str) -> Result<String> {
    let mut errors = Vec::new();

    for attempt in 0..=MAX_PROVIDER_RETRIES {
        throttle_requests().await;

        let response = match client.get(url).send().await {
            Ok(resp) => resp,
            Err(e) => {
                errors.push(format!("attempt {} request failed: {}", attempt + 1, e));
                if attempt < MAX_PROVIDER_RETRIES {
                    sleep(Duration::from_millis(700 * (attempt as u64 + 1))).await;
                    continue;
                }
                break;
            }
        };

        if !response.status().is_success() {
            let status = response.status();
            errors.push(format!(
                "attempt {} returned status {}",
                attempt + 1,
                status
            ));
            if (status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error())
                && attempt < MAX_PROVIDER_RETRIES
            {
                sleep(Duration::from_millis(1200 * (attempt as u64 + 1))).await;
                continue;
            }
            break;
        }

        match response.text().await {
            Ok(text) => return Ok(text),
            Err(e) => {
                errors.push(format!("attempt {} text parse failed: {}", attempt + 1, e));
                if attempt < MAX_PROVIDER_RETRIES {
                    sleep(Duration::from_millis(500 * (attempt as u64 + 1))).await;
                    continue;
                }
                break;
            }
        }
    }

    Err(anyhow!(
        "provider {} failed for {}: {}",
        provider,
        url,
        errors.join(" | ")
    ))
}

async fn request_json_post_with_retries(
    client: &Client,
    provider: &str,
    url: &str,
    body: &serde_json::Value,
) -> Result<serde_json::Value> {
    let mut errors = Vec::new();

    for attempt in 0..=MAX_PROVIDER_RETRIES {
        throttle_requests().await;

        let response = match client.post(url).json(body).send().await {
            Ok(resp) => resp,
            Err(e) => {
                errors.push(format!("attempt {} request failed: {}", attempt + 1, e));
                if attempt < MAX_PROVIDER_RETRIES {
                    sleep(Duration::from_millis(700 * (attempt as u64 + 1))).await;
                    continue;
                }
                break;
            }
        };

        if !response.status().is_success() {
            let status = response.status();
            errors.push(format!("attempt {} returned status {}", attempt + 1, status));
            if (status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error())
                && attempt < MAX_PROVIDER_RETRIES
            {
                sleep(Duration::from_millis(1200 * (attempt as u64 + 1))).await;
                continue;
            }
            break;
        }

        match response.json::<serde_json::Value>().await {
            Ok(parsed) => return Ok(parsed),
            Err(e) => {
                errors.push(format!("attempt {} json parse failed: {}", attempt + 1, e));
                if attempt < MAX_PROVIDER_RETRIES {
                    sleep(Duration::from_millis(500 * (attempt as u64 + 1))).await;
                    continue;
                }
                break;
            }
        }
    }

    Err(anyhow!(
        "provider {} failed for {}: {}",
        provider,
        url,
        errors.join(" | ")
    ))
}

fn json_value_to_f64(value: &serde_json::Value) -> Option<f64> {
    value
        .as_f64()
        .or_else(|| value.as_i64().map(|v| v as f64))
        .or_else(|| value.as_u64().map(|v| v as f64))
        .or_else(|| value.as_str().and_then(|v| v.parse::<f64>().ok()))
}

fn parse_btc_balance_haskoin(parsed: &serde_json::Value) -> Result<f64> {
    let confirmed = json_value_to_f64(&parsed["confirmed"])
        .ok_or_else(|| anyhow!("missing 'confirmed' in haskoin response"))?;
    let unconfirmed = json_value_to_f64(&parsed["unconfirmed"])
        .ok_or_else(|| anyhow!("missing 'unconfirmed' in haskoin response"))?;
    Ok((confirmed + unconfirmed) * 1e-8)
}

fn parse_btc_balance_blockstream(parsed: &serde_json::Value) -> Result<f64> {
    let chain_funded = json_value_to_f64(&parsed["chain_stats"]["funded_txo_sum"])
        .ok_or_else(|| anyhow!("missing chain_stats.funded_txo_sum"))?;
    let chain_spent = json_value_to_f64(&parsed["chain_stats"]["spent_txo_sum"])
        .ok_or_else(|| anyhow!("missing chain_stats.spent_txo_sum"))?;
    let mempool_funded = json_value_to_f64(&parsed["mempool_stats"]["funded_txo_sum"])
        .ok_or_else(|| anyhow!("missing mempool_stats.funded_txo_sum"))?;
    let mempool_spent = json_value_to_f64(&parsed["mempool_stats"]["spent_txo_sum"])
        .ok_or_else(|| anyhow!("missing mempool_stats.spent_txo_sum"))?;

    let sats = (chain_funded - chain_spent) + (mempool_funded - mempool_spent);
    Ok(sats * 1e-8)
}

fn parse_btc_balance_blockcypher(parsed: &serde_json::Value) -> Result<f64> {
    let sats = json_value_to_f64(&parsed["final_balance"])
        .ok_or_else(|| anyhow!("missing final_balance in blockcypher response"))?;
    Ok(sats * 1e-8)
}

fn parse_blockchair_balance_sats(parsed: &serde_json::Value, address: &str) -> Result<f64> {
    let sats = json_value_to_f64(&parsed["data"][address]["address"]["balance"])
        .ok_or_else(|| anyhow!("missing blockchair data.{address}.address.balance"))?;
    Ok(sats * 1e-8)
}

fn parse_blockchair_balance_wei(parsed: &serde_json::Value, address: &str) -> Result<f64> {
    let wei = json_value_to_f64(&parsed["data"][address]["address"]["balance"])
        .ok_or_else(|| anyhow!("missing blockchair data.{address}.address.balance"))?;
    Ok(wei * 1e-18)
}

fn parse_trezor_blockbook_balance_sats(parsed: &serde_json::Value) -> Result<f64> {
    let sats = json_value_to_f64(&parsed["balance"])
        .ok_or_else(|| anyhow!("missing balance in trezor blockbook response"))?;
    Ok(sats * 1e-8)
}

fn parse_cryptoid_balance_text(text: &str) -> Result<f64> {
    let cleaned = text.trim();
    let balance = cleaned
        .parse::<f64>()
        .map_err(|e| anyhow!("invalid cryptoid response '{}': {}", cleaned, e))?;
    Ok(balance)
}

fn parse_eth_rpc_hex_balance(parsed: &serde_json::Value) -> Result<f64> {
    let hex = parsed["result"]
        .as_str()
        .ok_or_else(|| anyhow!("missing result in rpc response"))?;
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let wei = u128::from_str_radix(hex, 16)
        .map_err(|e| anyhow!("invalid hex balance '{}': {}", hex, e))?;
    Ok((wei as f64) * 1e-18)
}

async fn get_btc_balance_with_failover(client: &Client, address: &str) -> Result<f64> {
    let sources = vec![
        (
            "haskoin",
            format!(
                "https://api.blockchain.info/haskoin-store/btc/address/{}/balance",
                address
            ),
        ),
        (
            "blockstream",
            format!("https://blockstream.info/api/address/{}", address),
        ),
        (
            "blockcypher",
            format!(
                "https://api.blockcypher.com/v1/btc/main/addrs/{}/balance",
                address
            ),
        ),
        (
            "sochain",
            format!(
                "https://sochain.com/api/v2/get_address_balance/BTC/{}",
                address
            ),
        ),
        (
            "mempool_space",
            format!("https://mempool.space/api/address/{}", address),
        ),
        (
            "blockchair",
            format!("https://api.blockchair.com/bitcoin/dashboards/address/{}", address),
        ),
        (
            "cryptoid",
            format!(
                "https://chainz.cryptoid.info/btc/api.dws?q=getbalance&a={}",
                address
            ),
        ),
        (
            "trezor_blockbook",
            format!("https://btc1.trezor.io/api/v2/address/{}", address),
        ),
    ];

    let mut errors = Vec::new();

    for (source_name, url) in sources {
        let balance_result = match source_name {
            "cryptoid" => {
                let text = match request_text_with_retries(client, source_name, &url).await {
                    Ok(v) => v,
                    Err(e) => {
                        errors.push(format!("{} failed: {}", source_name, e));
                        continue;
                    }
                };
                parse_cryptoid_balance_text(&text)
            }
            _ => {
                let parsed = match request_json_with_retries(client, source_name, &url).await {
                    Ok(v) => v,
                    Err(e) => {
                        errors.push(format!("{} failed: {}", source_name, e));
                        continue;
                    }
                };
                match source_name {
                    "haskoin" => parse_btc_balance_haskoin(&parsed),
                    "blockstream" | "mempool_space" => parse_btc_balance_blockstream(&parsed),
                    "blockcypher" => parse_btc_balance_blockcypher(&parsed),
                    "sochain" => {
                        let confirmed = json_value_to_f64(&parsed["data"]["confirmed_balance"])
                            .ok_or_else(|| {
                                anyhow!("missing data.confirmed_balance in sochain response")
                            })?;
                        let unconfirmed = json_value_to_f64(&parsed["data"]["unconfirmed_balance"])
                            .unwrap_or(0.0);
                        Ok(confirmed + unconfirmed)
                    }
                    "blockchair" => parse_blockchair_balance_sats(&parsed, address),
                    "trezor_blockbook" => parse_trezor_blockbook_balance_sats(&parsed),
                    _ => Err(anyhow!("unknown BTC source: {}", source_name)),
                }
            }
        };

        match balance_result {
            Ok(balance) => return Ok(balance),
            Err(e) => {
                errors.push(format!("{} failed: {}", source_name, e));
            }
        }
    }

    Err(anyhow!(
        "all BTC providers failed for {}: {}",
        address,
        errors.join(" | ")
    ))
}

async fn get_eth_balance_with_failover(client: &Client, address: &str) -> Result<f64> {
    let sources = vec![
        (
            "blockchain_info",
            format!(
                "https://api.blockchain.info/v2/eth/data/account/{}/wallet?page=0&size=5",
                address
            ),
        ),
        (
            "blockcypher",
            format!(
                "https://api.blockcypher.com/v1/eth/main/addrs/{}/balance",
                address
            ),
        ),
        (
            "blockchair",
            format!(
                "https://api.blockchair.com/ethereum/dashboards/address/{}",
                address
            ),
        ),
        (
            "ethplorer",
            format!(
                "https://api.ethplorer.io/getAddressInfo/{}?apiKey=freekey",
                address
            ),
        ),
        (
            "blockscout",
            format!(
                "https://eth.blockscout.com/api?module=account&action=balance&address={}",
                address
            ),
        ),
        ("cloudflare_rpc", "https://cloudflare-eth.com".to_string()),
        ("ankr_rpc", "https://rpc.ankr.com/eth".to_string()),
        ("flashbots_rpc", "https://rpc.flashbots.net".to_string()),
    ];

    let mut errors = Vec::new();
    for (source_name, url) in sources {
        let balance_result = match source_name {
            "cloudflare_rpc" | "ankr_rpc" | "flashbots_rpc" => {
                let rpc_body = serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "eth_getBalance",
                    "params": [address, "latest"],
                    "id": 1
                });
                let parsed =
                    match request_json_post_with_retries(client, source_name, &url, &rpc_body)
                        .await
                    {
                        Ok(v) => v,
                        Err(e) => {
                            errors.push(format!("{} failed: {}", source_name, e));
                            continue;
                        }
                    };
                parse_eth_rpc_hex_balance(&parsed)
            }
            _ => {
                let parsed = match request_json_with_retries(client, source_name, &url).await {
                    Ok(v) => v,
                    Err(e) => {
                        errors.push(format!("{} failed: {}", source_name, e));
                        continue;
                    }
                };
                match source_name {
                    "blockchain_info" => {
                        let wei = json_value_to_f64(&parsed["balance"]).ok_or_else(|| {
                            anyhow!("missing balance in blockchain_info ETH response")
                        })?;
                        Ok(wei * 1e-18)
                    }
                    "blockcypher" => {
                        let wei = json_value_to_f64(&parsed["final_balance"])
                            .or_else(|| json_value_to_f64(&parsed["balance"]))
                            .ok_or_else(|| {
                                anyhow!("missing final_balance/balance in blockcypher ETH response")
                            })?;
                        Ok(wei * 1e-18)
                    }
                    "blockchair" => parse_blockchair_balance_wei(&parsed, address),
                    "ethplorer" => {
                        let balance = json_value_to_f64(&parsed["ETH"]["balance"])
                            .ok_or_else(|| anyhow!("missing ETH.balance in ethplorer response"))?;
                        Ok(balance)
                    }
                    "blockscout" => {
                        let wei = json_value_to_f64(&parsed["result"])
                            .ok_or_else(|| anyhow!("missing result in blockscout response"))?;
                        Ok(wei * 1e-18)
                    }
                    _ => Err(anyhow!("unknown ETH source: {}", source_name)),
                }
            }
        };

        match balance_result {
            Ok(balance) => return Ok(balance),
            Err(e) => errors.push(format!("{} failed: {}", source_name, e)),
        }
    }

    Err(anyhow!(
        "all ETH providers failed for {}: {}",
        address,
        errors.join(" | ")
    ))
}

fn parse_coinspace_array_balance(parsed: &serde_json::Value) -> Result<f64> {
    let balance = json_value_to_f64(&parsed[0]["balance"])
        .ok_or_else(|| anyhow!("missing [0].balance in coin.space response"))?;
    Ok(balance)
}

fn parse_sochain_coin_balance(parsed: &serde_json::Value) -> Result<f64> {
    let confirmed = json_value_to_f64(&parsed["data"]["confirmed_balance"])
        .ok_or_else(|| anyhow!("missing data.confirmed_balance in sochain response"))?;
    let unconfirmed = json_value_to_f64(&parsed["data"]["unconfirmed_balance"]).unwrap_or(0.0);
    Ok(confirmed + unconfirmed)
}

async fn get_doge_balance_with_failover(client: &Client, address: &str) -> Result<f64> {
    let sources = vec![
        (
            "coinspace",
            format!("https://doge.coin.space/api/v1/addrs/{}", address),
        ),
        (
            "blockcypher",
            format!(
                "https://api.blockcypher.com/v1/doge/main/addrs/{}/balance",
                address
            ),
        ),
        (
            "sochain",
            format!(
                "https://sochain.com/api/v2/get_address_balance/DOGE/{}",
                address
            ),
        ),
        (
            "chain_so",
            format!("https://chain.so/api/v2/get_address_balance/DOGE/{}", address),
        ),
        (
            "blockchair",
            format!("https://api.blockchair.com/dogecoin/dashboards/address/{}", address),
        ),
        (
            "cryptoid",
            format!(
                "https://chainz.cryptoid.info/doge/api.dws?q=getbalance&a={}",
                address
            ),
        ),
        (
            "trezor_blockbook",
            format!("https://doge1.trezor.io/api/v2/address/{}", address),
        ),
    ];

    let mut errors = Vec::new();
    for (source_name, url) in sources {
        let balance_result = match source_name {
            "cryptoid" => {
                let text = match request_text_with_retries(client, source_name, &url).await {
                    Ok(v) => v,
                    Err(e) => {
                        errors.push(format!("{} failed: {}", source_name, e));
                        continue;
                    }
                };
                parse_cryptoid_balance_text(&text)
            }
            _ => {
                let parsed = match request_json_with_retries(client, source_name, &url).await {
                    Ok(v) => v,
                    Err(e) => {
                        errors.push(format!("{} failed: {}", source_name, e));
                        continue;
                    }
                };
                match source_name {
                    "coinspace" => parse_coinspace_array_balance(&parsed),
                    "blockcypher" => {
                        let sats = json_value_to_f64(&parsed["final_balance"]).ok_or_else(|| {
                            anyhow!("missing final_balance in blockcypher DOGE response")
                        })?;
                        Ok(sats * 1e-8)
                    }
                    "sochain" | "chain_so" => parse_sochain_coin_balance(&parsed),
                    "blockchair" => parse_blockchair_balance_sats(&parsed, address),
                    "trezor_blockbook" => parse_trezor_blockbook_balance_sats(&parsed),
                    _ => Err(anyhow!("unknown DOGE source: {}", source_name)),
                }
            }
        };

        match balance_result {
            Ok(balance) => return Ok(balance),
            Err(e) => errors.push(format!("{} failed: {}", source_name, e)),
        }
    }

    Err(anyhow!(
        "all DOGE providers failed for {}: {}",
        address,
        errors.join(" | ")
    ))
}

async fn get_dash_balance_with_failover(client: &Client, address: &str) -> Result<f64> {
    let sources = vec![
        (
            "coinspace",
            format!("https://dash.coin.space/api/v1/addrs/{}", address),
        ),
        (
            "blockcypher",
            format!(
                "https://api.blockcypher.com/v1/dash/main/addrs/{}/balance",
                address
            ),
        ),
        (
            "sochain",
            format!(
                "https://sochain.com/api/v2/get_address_balance/DASH/{}",
                address
            ),
        ),
        (
            "chain_so",
            format!("https://chain.so/api/v2/get_address_balance/DASH/{}", address),
        ),
        (
            "blockchair",
            format!("https://api.blockchair.com/dash/dashboards/address/{}", address),
        ),
        (
            "cryptoid",
            format!(
                "https://chainz.cryptoid.info/dash/api.dws?q=getbalance&a={}",
                address
            ),
        ),
        (
            "trezor_blockbook",
            format!("https://dash1.trezor.io/api/v2/address/{}", address),
        ),
    ];

    let mut errors = Vec::new();
    for (source_name, url) in sources {
        let balance_result = match source_name {
            "cryptoid" => {
                let text = match request_text_with_retries(client, source_name, &url).await {
                    Ok(v) => v,
                    Err(e) => {
                        errors.push(format!("{} failed: {}", source_name, e));
                        continue;
                    }
                };
                parse_cryptoid_balance_text(&text)
            }
            _ => {
                let parsed = match request_json_with_retries(client, source_name, &url).await {
                    Ok(v) => v,
                    Err(e) => {
                        errors.push(format!("{} failed: {}", source_name, e));
                        continue;
                    }
                };
                match source_name {
                    "coinspace" => parse_coinspace_array_balance(&parsed),
                    "blockcypher" => {
                        let sats = json_value_to_f64(&parsed["final_balance"]).ok_or_else(|| {
                            anyhow!("missing final_balance in blockcypher DASH response")
                        })?;
                        Ok(sats * 1e-8)
                    }
                    "sochain" | "chain_so" => parse_sochain_coin_balance(&parsed),
                    "blockchair" => parse_blockchair_balance_sats(&parsed, address),
                    "trezor_blockbook" => parse_trezor_blockbook_balance_sats(&parsed),
                    _ => Err(anyhow!("unknown DASH source: {}", source_name)),
                }
            }
        };

        match balance_result {
            Ok(balance) => return Ok(balance),
            Err(e) => errors.push(format!("{} failed: {}", source_name, e)),
        }
    }

    Err(anyhow!(
        "all DASH providers failed for {}: {}",
        address,
        errors.join(" | ")
    ))
}

async fn get_ltc_balance_with_failover(client: &Client, address: &str) -> Result<f64> {
    let sources = vec![
        (
            "coinspace",
            format!("https://ltc.coin.space/api/v1/addrs/{}", address),
        ),
        (
            "blockcypher",
            format!(
                "https://api.blockcypher.com/v1/ltc/main/addrs/{}/balance",
                address
            ),
        ),
        (
            "sochain",
            format!(
                "https://sochain.com/api/v2/get_address_balance/LTC/{}",
                address
            ),
        ),
        (
            "chain_so",
            format!("https://chain.so/api/v2/get_address_balance/LTC/{}", address),
        ),
        (
            "blockchair",
            format!("https://api.blockchair.com/litecoin/dashboards/address/{}", address),
        ),
        (
            "cryptoid",
            format!(
                "https://chainz.cryptoid.info/ltc/api.dws?q=getbalance&a={}",
                address
            ),
        ),
        (
            "trezor_blockbook",
            format!("https://ltc1.trezor.io/api/v2/address/{}", address),
        ),
    ];

    let mut errors = Vec::new();
    for (source_name, url) in sources {
        let balance_result = match source_name {
            "cryptoid" => {
                let text = match request_text_with_retries(client, source_name, &url).await {
                    Ok(v) => v,
                    Err(e) => {
                        errors.push(format!("{} failed: {}", source_name, e));
                        continue;
                    }
                };
                parse_cryptoid_balance_text(&text)
            }
            _ => {
                let parsed = match request_json_with_retries(client, source_name, &url).await {
                    Ok(v) => v,
                    Err(e) => {
                        errors.push(format!("{} failed: {}", source_name, e));
                        continue;
                    }
                };
                match source_name {
                    "coinspace" => parse_coinspace_array_balance(&parsed),
                    "blockcypher" => {
                        let sats = json_value_to_f64(&parsed["final_balance"]).ok_or_else(|| {
                            anyhow!("missing final_balance in blockcypher LTC response")
                        })?;
                        Ok(sats * 1e-8)
                    }
                    "sochain" | "chain_so" => parse_sochain_coin_balance(&parsed),
                    "blockchair" => parse_blockchair_balance_sats(&parsed, address),
                    "trezor_blockbook" => parse_trezor_blockbook_balance_sats(&parsed),
                    _ => Err(anyhow!("unknown LTC source: {}", source_name)),
                }
            }
        };

        match balance_result {
            Ok(balance) => return Ok(balance),
            Err(e) => errors.push(format!("{} failed: {}", source_name, e)),
        }
    }

    Err(anyhow!(
        "all LTC providers failed for {}: {}",
        address,
        errors.join(" | ")
    ))
}

async fn get_xrp_balance_with_failover(client: &Client, address: &str) -> Result<f64> {
    let sources = vec![
        (
            "coinspace",
            format!("https://xrp.coin.space/api/v1/account/{}", address),
        ),
        (
            "xrpscan",
            format!("https://api.xrpscan.com/api/v1/account/{}", address),
        ),
    ];

    let mut errors = Vec::new();
    for (source_name, url) in sources {
        let parsed = match request_json_with_retries(client, source_name, &url).await {
            Ok(v) => v,
            Err(e) => {
                errors.push(e.to_string());
                continue;
            }
        };

        let balance_result = match source_name {
            "coinspace" => {
                let balance = json_value_to_f64(&parsed["balance"])
                    .ok_or_else(|| anyhow!("missing balance in XRP coinspace response"))?;
                Ok(balance)
            }
            "xrpscan" => {
                if let Some(balance) = json_value_to_f64(&parsed["xrpBalance"]) {
                    Ok(balance)
                } else {
                    let drops =
                        json_value_to_f64(&parsed["account_data"]["Balance"]).ok_or_else(|| {
                            anyhow!("missing xrpBalance/account_data.Balance in xrpscan response")
                        })?;
                    Ok(drops * 1e-6)
                }
            }
            _ => Err(anyhow!("unknown XRP source: {}", source_name)),
        };

        match balance_result {
            Ok(balance) => return Ok(balance),
            Err(e) => errors.push(format!("{} schema parse failed: {}", source_name, e)),
        }
    }

    Err(anyhow!(
        "all XRP providers failed for {}: {}",
        address,
        errors.join(" | ")
    ))
}

async fn get_rvn_balance_with_failover(client: &Client, address: &str) -> Result<f64> {
    let mut errors = Vec::new();

    let tokenview_url = format!(
        "https://rvn.tokenview.io/api/address/balancetrend/rvn/{}",
        address
    );
    match request_json_with_retries(client, "tokenview", &tokenview_url).await {
        Ok(parsed) => {
            let today = Local::now().format("%Y-%m-%d").to_string();
            if let Some(balance_str) = parsed["data"][0].get(&today).and_then(|v| v.as_str()) {
                if let Ok(balance) = balance_str.parse::<f64>() {
                    return Ok(balance);
                }
            }

            if let Some(obj) = parsed["data"][0].as_object() {
                for value in obj.values() {
                    if let Some(balance) = json_value_to_f64(value) {
                        return Ok(balance);
                    }
                }
            }
            errors.push("tokenview schema parse failed".to_string());
        }
        Err(e) => errors.push(e.to_string()),
    }

    let cryptoid_url = format!(
        "https://chainz.cryptoid.info/rvn/api.dws?q=getbalance&a={}",
        address
    );
    match request_text_with_retries(client, "cryptoid", &cryptoid_url).await {
        Ok(text) => {
            let cleaned = text.trim();
            if let Ok(balance) = cleaned.parse::<f64>() {
                return Ok(balance);
            }
            errors.push(format!("cryptoid schema parse failed: {}", cleaned));
        }
        Err(e) => errors.push(e.to_string()),
    }

    Err(anyhow!(
        "all RVN providers failed for {}: {}",
        address,
        errors.join(" | ")
    ))
}

// 生成助记词
fn generate_mnemonic(word_count: usize) -> String {
    let mnemonic_type = match word_count {
        12 => bip39::MnemonicType::Words12,
        15 => bip39::MnemonicType::Words15,
        18 => bip39::MnemonicType::Words18,
        21 => bip39::MnemonicType::Words21,
        24 => bip39::MnemonicType::Words24,
        _ => panic!("Only below Mnemonic words are supported!"),
    };
    let mnemonic = Mnemonic::new(mnemonic_type, Language::English);
    mnemonic.phrase().to_string()
}

// 连续生成助记词并查询余额（支持 BTC 和 DOGE）
async fn generate_and_check_keys(
    file_path: &str,
    language: Language,
    password: String,        // 改为拥有所有权的 String
    networks: Vec<String>,   // 修改为拥有所有权的 Vec<String>
    word_counts: Vec<usize>, // 支持的多个助记词长度
) -> Result<()> {
    loop {
        // 对每个助记词长度进行并行处理
        let tasks: Vec<_> = word_counts
            .iter()
            .map(|&word_count| {
                let file_path_clone = file_path.to_string();
                let password_clone = password.clone(); // 克隆密码
                let networks_clone = networks.clone(); // 克隆网络列表
                tokio::spawn(async move {
                    let mnemonic = generate_mnemonic(word_count);
                    println!("Generated {}-word mnemonic: {}", word_count, mnemonic);

                    let inner_tasks: Vec<_> = networks_clone
                        .iter()
                        .map(|network| {
                            let mnemonic_clone = mnemonic.clone();
                            let network_str = network.clone(); // 克隆字符串
                            let password_clone = password_clone.clone(); // 克隆密码
                            tokio::spawn({
                                let value = file_path_clone.clone();
                                async move {
                                    match mnemonic_to_private_key_and_address(
                                        &mnemonic_clone,
                                        language,
                                        &password_clone,
                                        &network_str,
                                    )
                                    .await
                                    {
                                        Ok(addresses) => {
                                            for (private_key, address) in addresses {
                                                println!(
                                                    "Generated {} address: {}\n",
                                                    network_str.clone(),
                                                    address
                                                );
                                                let balance = match get_balance(
                                                    &address,
                                                    &network_str,
                                                )
                                                .await
                                                {
                                                    Ok(value) => value,
                                                    Err(e) => {
                                                        println!(
                                                            "{} Address: {} -> balance query failed: {}",
                                                            network_str, address, e
                                                        );
                                                        0.0
                                                    }
                                                };
                                                println!(
                                                    "{} Address: {} -> Balance: {}\n",
                                                    network_str, address, balance
                                                );

                                                if balance > 0.00000000 {
                                                    println!(
                                                        "Found address with balance: {}\n",
                                                        address
                                                    );
                                                    let wallet = WalletInfo {
                                                        private_key,
                                                        address,
                                                        balance,
                                                        currency: network_str.clone(),
                                                    };
                                                    save_wallet_info(&wallet, &value)
                                                        .await
                                                        .unwrap();
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            println!(
                                                "Failed to process mnemonic: {}. Error: {}\n",
                                                value, e
                                            );
                                        }
                                    }
                                }
                            })
                        })
                        .collect();

                    join_all(inner_tasks).await;
                })
            })
            .collect();

        join_all(tasks).await;

        sleep(Duration::from_secs(3)).await;
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let file_path = "wallets.json";

    let existing_wallets = load_wallet_info(file_path).await?;
    if !existing_wallets.is_empty() {
        println!("Loaded {} wallets from history:", existing_wallets.len());
        for wallet in &existing_wallets {
            println!("{:?}", wallet);
        }
    }

    let start_time = Instant::now();

    generate_and_check_keys(
        file_path,
        Language::English,
        "".to_string(),
        vec![
            "BTC".to_string(),
            "ETH".to_string(),
            "DOGE".to_string(),
            "DASH".to_string(),
            "LTC".to_string(),
            "RVN".to_string(),
        ],
        vec![12, 18, 24],
    )
    .await?;

    println!("程序运行时间: {:?}", start_time.elapsed());
    Ok(())
}
