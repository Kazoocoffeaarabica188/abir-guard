use clap::{Parser, Subcommand};
use std::io::{self, BufRead, Write};

use abir_guard::{Ciphertext, McpServer, VERSION};
use abir_guard::persistent_vault;

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
        
        Some(Commands::Info) => {
            println!("Abir-Guard v{}", VERSION);
            println!("PQC Agent Memory Vault");
            println!("ML-KEM + AES-256-GCM");
            println!("Security Watchdog: 200ms");
            println!("Memory Zeroization: enabled");
            println!("Disk Encryption: AES-256-GCM");
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
