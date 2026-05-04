use clap::{Parser, Subcommand};
use std::io::{self, BufRead, Write};

use abir_guard::{Ciphertext, McpServer, VERSION};
use abir_guard::persistent_vault;
use abir_guard::shamir;
use abir_guard::ml_dsa;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

const DEFAULT_PASSPHRASE: &str = "";  // Empty = use env var ABIR_GUARD_KEY

#[derive(Parser)]
#[command(name = "abir-guard")]
#[command(about = "Abir-Guard: Quantum-Resilient Agentic Vault", long_about = None)]
struct Cli {
    /// Vault passphrase (or set ABIR_GUARD_KEY env var)
    #[arg(short, long, env = "ABIR_GUARD_KEY")]
    key: Option<String>,
    
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new keypair for an agent
    Init { key_id: String },
    /// Encrypt data with a key
    Encrypt { key_id: String, data: String },
    /// Decrypt data with a key
    Decrypt { key_id: String, ciphertext: String, nonce: String },
    /// List all stored keys
    ListKeys,
    /// Delete a key
    DeleteKey { key_id: String },
    /// Clear all cached data
    ClearCache,
    /// Start MCP server (stdio mode)
    McpServer { mode: String },
    /// Split a secret into N shares (require T to recover)
    ShamirSplit {
        /// The secret to split
        secret: String,
        /// Number of shares required to reconstruct
        #[arg(short, long, default_value_t = 2)]
        threshold: usize,
        /// Total number of shares to create
        #[arg(short, long, default_value_t = 3)]
        shares: usize,
    },
    /// Reconstruct a secret from shares (one share per argument)
    ShamirJoin {
        /// Share strings (base64 encoded, format: "index:data")
        shares: Vec<String>,
    },
    /// Generate ML-DSA-65 signing/verifying keypair
    MldsaInit {
        /// Key ID to store in vault
        #[arg(short, long)]
        key_id: Option<String>,
    },
    /// Sign data with ML-DSA using vault-stored key
    MldsaSign {
        /// Key ID to use for signing
        key_id: String,
        /// Data to sign (or read from stdin if empty)
        data: Option<String>,
    },
    /// Verify ML-DSA signature using vault-stored key
    MldsaVerify {
        /// Key ID to use for verification
        key_id: String,
        /// Data that was signed
        data: String,
        /// Base64 encoded signature
        signature: String,
    },
    /// List stored ML-DSA keys
    MldsaList,
    /// Show version info
    Info,
}

fn get_passphrase(cli: &Cli) -> String {
    cli.key.clone().unwrap_or_else(|| DEFAULT_PASSPHRASE.to_string())
}

/// Validate key_id: alphanumeric, hyphens, underscores only, max 64 chars
fn validate_key_id(key_id: &str) -> Result<(), String> {
    if key_id.is_empty() {
        return Err("key_id cannot be empty".to_string());
    }
    if key_id.len() > 64 {
        return Err(format!("key_id too long (max 64 chars, got {})", key_id.len()));
    }
    if key_id.contains(|c: char| !c.is_alphanumeric() && c != '-' && c != '_') {
        return Err("key_id must be alphanumeric, hyphens, or underscores only".to_string());
    }
    if key_id.starts_with("__") {
        return Err("key_id cannot start with __ (reserved for system)".to_string());
    }
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    let passphrase = get_passphrase(&cli);
    
    match cli.command {
        Some(Commands::Init { key_id }) => {
            if let Err(e) = validate_key_id(&key_id) {
                eprintln!("Invalid key_id: {}", e);
                std::process::exit(1);
            }
            let vault = persistent_vault::get_vault(&passphrase);
            let (pub_key, sec_key) = vault.generate_keypair(&key_id);
            persistent_vault::persist(&vault, &passphrase);
            println!("Generated keypair: {}", key_id);
            println!("Public key: {}", pub_key);
            let _ = sec_key;
        }
        
        Some(Commands::Encrypt { key_id, data }) => {
            if let Err(e) = validate_key_id(&key_id) {
                eprintln!("Invalid key_id: {}", e);
                std::process::exit(1);
            }
            if data.len() > 1024 * 1024 {
                eprintln!("Data too large (max 1MB)");
                std::process::exit(1);
            }
            let vault = persistent_vault::get_vault(&passphrase);
            let ct = persistent_vault::store_encrypted(&vault, &key_id, data.as_bytes(), &passphrase)
                .expect("Encryption failed (key may not exist - run 'init' first)");
            println!("Ciphertext: {}", ct.ciphertext);
            println!("Nonce: {}", ct.nonce);
        }
        
        Some(Commands::Decrypt { key_id, ciphertext, nonce }) => {
            if let Err(e) = validate_key_id(&key_id) {
                eprintln!("Invalid key_id: {}", e);
                std::process::exit(1);
            }
            let vault = persistent_vault::get_vault(&passphrase);
            let ct = Ciphertext {
                ciphertext,
                nonce,
                key_id: key_id.clone(),
            };
            let plain = match persistent_vault::retrieve_decrypted(&vault, &key_id, &ct, &passphrase) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Decryption failed: {}", e);
                    std::process::exit(1);
                }
            };
            println!("{}", String::from_utf8_lossy(&plain));
        }
        
        Some(Commands::ListKeys) => {
            let vault = persistent_vault::get_vault(&passphrase);
            let keys = vault.list_keypairs();
            let user_keys: Vec<_> = keys.iter()
                .filter(|k| !k.starts_with("__"))
                .collect();
            if user_keys.is_empty() {
                println!("No keys stored");
            } else {
                println!("Stored keys:");
                for key in user_keys {
                    println!("  - {}", key);
                }
            }
        }
        
        Some(Commands::DeleteKey { key_id }) => {
            if let Err(e) = validate_key_id(&key_id) {
                eprintln!("Invalid key_id: {}", e);
                std::process::exit(1);
            }
            let vault = persistent_vault::get_vault(&passphrase);
            vault.remove_keypair(&key_id);
            persistent_vault::persist(&vault, &passphrase);
            println!("Deleted key: {}", key_id);
        }
        
        Some(Commands::ClearCache) => {
            if let Some(home) = dirs::home_dir() {
                let vault_dir = home.join(".abir_guard");
                if vault_dir.exists() {
                    std::fs::remove_dir_all(&vault_dir).ok();
                }
            }
            println!("Vault cleared (all keys removed)");
        }
        
        Some(Commands::McpServer { mode }) => {
            eprintln!("Starting MCP server in {} mode", mode);
            if mode == "stdio" {
                run_stdio_server();
            }
        }
        
        Some(Commands::ShamirSplit { secret, threshold, shares }) => {
            if threshold < 2 {
                eprintln!("Threshold must be >= 2");
                std::process::exit(1);
            }
            if shares < threshold {
                eprintln!("Shares ({}) must be >= threshold ({})", shares, threshold);
                std::process::exit(1);
            }
            if shares > 255 {
                eprintln!("Shares must be <= 255");
                std::process::exit(1);
            }
            
            let shares_result = shamir::split(secret.as_bytes(), threshold, shares);
            let encoded = shamir::encode_shares(&shares_result);
            
            println!("SHAMIR Secret Sharing ({}, {})", threshold, shares);
            println!("Secret length: {} bytes", secret.len());
            println!();
            println!("Store each share separately. Any {} shares can recover the secret.", threshold);
            println!();
            for (i, share_str) in encoded.iter().enumerate() {
                println!("Share {}: {}", i + 1, share_str);
            }
        }
        
        Some(Commands::ShamirJoin { shares: share_strings }) => {
            if share_strings.len() < 2 {
                eprintln!("Need at least 2 shares to reconstruct");
                std::process::exit(1);
            }
            
            let refs: Vec<&str> = share_strings.iter().map(|s| s.as_str()).collect();
            let shares_result = match shamir::decode_shares(&refs) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Invalid share format: {}", e);
                    std::process::exit(1);
                }
            };
            
            let recovered = shamir::reconstruct(&shares_result);
            match String::from_utf8(recovered.clone()) {
                Ok(s) => println!("{}", s),
                Err(_) => {
                    println!("{}", BASE64.encode(&recovered));
                }
            }
        }
        
        Some(Commands::Info) => {
            println!("Abir-Guard v{}", VERSION);
            println!("PQC Agent Memory Vault");
            println!("ML-KEM + AES-256-GCM");
            println!("ML-DSA-65 Signatures");
            println!("Argon2id Key Derivation");
            println!("SHAMIR Secret Sharing");
            println!("Security Watchdog: 200ms");
            println!("Memory Zeroization: enabled");
            println!("Disk Encryption: AES-256-GCM");
        }
        
        Some(Commands::MldsaInit { ref key_id }) => {
            let keypair = ml_dsa::generate_keypair().expect("Key generation failed");
            let json = ml_dsa::serialize_keypair(&keypair);
            
            println!("ML-DSA-65 Keypair Generated");
            println!("Security Category: 3 (equivalent to AES-192)");
            println!("Signing Key Size: {} bytes", keypair.signing_key.len());
            println!("Verifying Key Size: {} bytes", keypair.verifying_key.len());
            println!();
            
            if let Some(id) = key_id {
                if let Err(e) = validate_key_id(id) {
                    eprintln!("Invalid key_id: {}", e);
                    std::process::exit(1);
                }
                
                let passphrase = get_passphrase(&cli);
                match persistent_vault::persist_mldsa_keys(&[(id.clone(), keypair.clone())], &passphrase) {
                    Ok(()) => {
                        println!("Stored in vault with key_id: {}", id);
                        println!("Verify Key: {}", BASE64.encode(&keypair.verifying_key));
                    }
                    Err(e) => {
                        eprintln!("Failed to store in vault: {}", e);
                        println!("Exported as JSON for manual storage:");
                        println!("{}", json);
                    }
                }
            } else {
                println!("Sign Key: {}", BASE64.encode(&keypair.signing_key));
                println!();
                println!("Verify Key: {}", BASE64.encode(&keypair.verifying_key));
                println!();
                println!("Store both keys securely. Never share the signing key.");
                println!("Exported as JSON for vault storage:");
                println!("{}", json);
                println!();
                println!("To store in vault, run with --key-id <id>");
            }
        }
        
        Some(Commands::MldsaSign { ref key_id, ref data }) => {
            if let Err(e) = validate_key_id(key_id) {
                eprintln!("Invalid key_id: {}", e);
                std::process::exit(1);
            }
            
            let data_bytes = match data {
                Some(d) => d.clone().into_bytes(),
                None => {
                    let mut input = String::new();
                    io::stdin().read_line(&mut input).expect("Failed to read stdin");
                    input.into_bytes()
                }
            };
            
            let hash = ml_dsa::hash_data(&data_bytes);
            let passphrase = get_passphrase(&cli);
            
            match persistent_vault::sign_with_vault(key_id, &data_bytes, &passphrase) {
                Ok(signature) => {
                    println!("Data Hash (SHA3-512): {}", BASE64.encode(&hash));
                    println!("Signature: {}", BASE64.encode(&signature));
                }
                Err(e) => {
                    eprintln!("Signing failed: {}", e);
                    eprintln!("Ensure key '{}' exists in vault (run 'mldsa-init --key-id {}' first)", key_id, key_id);
                    std::process::exit(1);
                }
            }
        }
        
        Some(Commands::MldsaVerify { ref key_id, ref data, ref signature }) => {
            if let Err(e) = validate_key_id(key_id) {
                eprintln!("Invalid key_id: {}", e);
                std::process::exit(1);
            }
            
            let data_bytes = data.clone().into_bytes();
            let sig_bytes = BASE64.decode(signature).expect("Invalid base64 signature");
            let passphrase = get_passphrase(&cli);
            
            match persistent_vault::verify_with_vault(&key_id, &data_bytes, &sig_bytes, &passphrase) {
                Ok(valid) => {
                    if valid {
                        println!("Signature VALID");
                    } else {
                        println!("Signature INVALID");
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("Verification error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        
        Some(Commands::MldsaList) => {
            let passphrase = get_passphrase(&cli);
            match persistent_vault::list_mldsa_keys(&passphrase) {
                Ok(keys) => {
                    if keys.is_empty() {
                        println!("No ML-DSA keys stored");
                    } else {
                        println!("Stored ML-DSA keys:");
                        for key in keys {
                            println!("  - {}", key);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to load keys: {}", e);
                }
            }
        }
        
        None => {
            println!("Abir-Guard v{}", VERSION);
            println!("Usage: abir-guard [OPTIONS] <command>");
            println!();
            println!("Options:");
            println!("  -k, --key <PASSPHRASE>  Vault passphrase (or ABIR_GUARD_KEY env)");
            println!();
            println!("Commands:");
            println!("  init         Generate a new keypair");
            println!("  encrypt      Encrypt data");
            println!("  decrypt      Decrypt data");
            println!("  list-keys    List stored keys");
            println!("  delete-key   Delete a key");
            println!("  clear-cache  Clear all vault data");
            println!("  mcp-server   Start MCP server (stdio)");
            println!("  shamir-split Split a secret into N shares");
            println!("  shamir-join  Reconstruct a secret from shares");
            println!("  mldsa-init   Generate ML-DSA signing keypair");
            println!("  mldsa-sign   Sign data with ML-DSA");
            println!("  mldsa-verify Verify ML-DSA signature");
            println!("  mldsa-list   List stored ML-DSA keys");
            println!("  info         Show version info");
        }
    }
}

fn run_stdio_server() {
    let server = McpServer::new();
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    
    eprintln!("MCP server ready on stdio");
    
    for line in stdin.lock().lines() {
        match line {
            Ok(line) => {
                if line.trim().is_empty() {
                    continue;
                }
                
                match abir_guard::mcp_gateway::parse_request(&line) {
                    Ok(request) => {
                        let response = server.handle(request);
                        match serde_json::to_string(&response) {
                            Ok(resp_json) => {
                                println!("{}", resp_json);
                                stdout.flush().ok();
                            }
                            Err(e) => {
                                eprintln!("Error: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Parse error: {}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("Read error: {}", e);
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }
    
    #[test]
    fn test_validate_key_id() {
        assert!(validate_key_id("agent-1").is_ok());
        assert!(validate_key_id("my_agent_123").is_ok());
        assert!(validate_key_id("").is_err());
        assert!(validate_key_id(&"a".repeat(65)).is_err());
        assert!(validate_key_id("bad key!").is_err());
        assert!(validate_key_id("__system").is_err());
    }
}
