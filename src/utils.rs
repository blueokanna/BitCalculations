use anyhow::anyhow;
use bitcoin::hashes::{sha256, Hash};
use regex::Regex;
use sha2::{Digest, Sha256};

const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const RIPPLE_B58_DIGITS: &[u8] = b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

pub fn extract_doge_balance(html: &str) -> Option<f64> {
    // 正则表达式匹配 "Balance" 行之后的 DOGE 余额
    let re = Regex::new(r#"<td>Balance</td>\s*<td><span class="currency">([0-9]+\.[0-9]+)</span> DOGE</td>"#).unwrap();

    // 查找匹配项
    if let Some(caps) = re.captures(html) {
        // 提取余额字符串
        let balance_str = &caps[1];
        // 尝试将字符串转换为 f64
        balance_str.parse::<f64>().ok()
    } else {
        None
    }
}


pub fn remove_prefix(public_key: &[u8]) -> [u8; 64] {
    let mut public_key_no_prefix = [0u8; 64]; // 创建一个长度为 64 的数组
    public_key_no_prefix.copy_from_slice(&public_key[1..65]); // 从索引1开始复制64字节
    public_key_no_prefix
}

fn double_sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(Sha256::digest(data).as_slice()).to_vec()
}

// Ripple Base58Check encoding
pub fn ripple_base58check_encode(payload: &[u8]) -> anyhow::Result<String> {
    let checksum = &double_sha256(payload)[..4]; // Get the first 4 bytes of the checksum

    // Combine the payload and checksum
    let mut payload_with_checksum = Vec::with_capacity(payload.len() + checksum.len());
    payload_with_checksum.extend_from_slice(payload);
    payload_with_checksum.extend_from_slice(checksum);

    ripple_b58enc(&payload_with_checksum)
}

// Base58 encoding function
pub fn ripple_b58enc(bin: &[u8]) -> anyhow::Result<String> {
    let mut zcount = 0;
    let mut i = 0;
    let mut j = 0;
    let mut carry = 0;

    // Prefix the data with 0x00 (Ripple address prefix)
    let mut prefixed_data = Vec::with_capacity(bin.len() + 1);
    prefixed_data.push(0x00);
    prefixed_data.extend_from_slice(bin);

    let binsz = prefixed_data.len();

    // Count leading zeros
    while zcount < binsz && prefixed_data[zcount] == 0 {
        zcount += 1;
    }

    // Allocate a buffer to store the Base58 encoded result
    let size = (binsz - zcount) * 138 / 100 + 1;
    let mut buf = vec![0; size];

    // Base58 encoding loop
    let high = size - 1;
    i = zcount;
    while i < binsz {
        carry = prefixed_data[i] as usize;
        j = size - 1;

        // Process the carry value and update the buffer
        while j > high || carry > 0 {
            carry += 256 * buf[j];
            buf[j] = carry % 58;
            carry /= 58;
            if j == 0 {
                break;
            }
            j -= 1;
        }
        i += 1;
    }

    // Find the actual encoded length
    j = 0;
    while j < size && buf[j] == 0 {
        j += 1;
    }

    // Build the final Base58 encoded result
    let mut result = Vec::new();
    for _ in 0..zcount {
        result.push(b'r');
    }

    while j < size {
        result.push(RIPPLE_B58_DIGITS[buf[j]]);
        j += 1;
    }

    // Return the result as a string
    String::from_utf8(result).map_err(|e| anyhow!("Base58 encoding failed: {}", e))
}
fn base58_encode(input: &[u8], alphabet: &[u8]) -> anyhow::Result<String> {
    let mut x = input.to_vec();
    let mut result = Vec::new();

    // 计算 Base58 编码
    while !x.is_empty() {
        let mut carry = 0;
        let mut idx = 0;

        // 处理每个字节
        while idx < x.len() {
            let temp = (x[idx] as usize) + (carry << 8);
            x[idx] = (temp / 58) as u8;
            carry = temp % 58;
            idx += 1;
        }

        // 删除多余的前导零
        while x.len() > 0 && x[0] == 0 {
            x.remove(0);
        }

        result.push(alphabet[carry]);
    }

    // 反转结果数组
    result.reverse();

    String::from_utf8(result).map_err(|e| anyhow!("Base58 encoding failed: {}", e))
}

pub fn base58check_encode(payload: &[u8]) -> anyhow::Result<String> {
    let checksum = &sha256::Hash::hash(&sha256::Hash::hash(payload)[..])[..4];
    let mut payload_with_checksum = payload.to_vec();

    payload_with_checksum.extend_from_slice(checksum);

    Ok(base58_encode(&payload_with_checksum, BASE58_ALPHABET)
        .map_err(|e| anyhow!("Base58 encoding failed: {}", e))?)
}
