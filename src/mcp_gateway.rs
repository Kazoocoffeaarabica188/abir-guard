use serde::{Deserialize, Serialize};
use std::sync::Mutex;

use crate::quantum_kernel::Vault;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpRequest {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpResponse {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<McpError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl std::fmt::Display for McpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (code {})", self.message, self.code)
    }
}

impl McpError {
    pub fn invalid_request(msg: &str) -> Self {
        Self { code: -32600, message: msg.to_string(), data: None }
    }
    
    pub fn method_not_found(method: &str) -> Self {
        Self { code: -32601, message: format!("Method not found: {}", method), data: None }
    }
    
    pub fn invalid_params(msg: &str) -> Self {
        Self { code: -32602, message: msg.to_string(), data: None }
    }
    
    pub fn internal_error(msg: &str) -> Self {
        Self { code: -32603, message: msg.to_string(), data: None }
    }
}

pub struct McpServer {
    vault: Vault,
    request_count: Mutex<u64>,
}

impl McpServer {
    pub fn new() -> Self {
        Self {
            vault: Vault::new(),
            request_count: Mutex::new(0),
        }
    }
    
    pub fn handle(&self, request: McpRequest) -> McpResponse {
        *self.request_count.lock().unwrap() += 1;
        
        let result = match request.method.as_str() {
            "generate_key" => self.handle_generate_key(&request),
            "encrypt" => self.handle_encrypt(&request),
            "decrypt" => self.handle_decrypt(&request),
            "list_keys" => self.handle_list_keys(&request),
            "delete_key" => self.handle_delete_key(&request),
            "clear_cache" => self.handle_clear_cache(&request),
            "info" => self.handle_info(&request),
            _ => Err(McpError::method_not_found(&request.method)),
        };
        
        match result {
            Ok(value) => McpResponse {
                jsonrpc: "2.0".to_string(),
                id: request.id,
                result: Some(value),
                error: None,
            },
            Err(e) => McpResponse {
                jsonrpc: "2.0".to_string(),
                id: request.id,
                result: None,
                error: Some(e),
            },
        }
    }
    
    fn handle_generate_key(&self, req: &McpRequest) -> Result<serde_json::Value, McpError> {
        let key_id = req.params.get("key_id")
            .and_then(|v| v.as_str())
            .ok_or(McpError::invalid_params("key_id required"))?;
        
        let pub_key = self.vault.generate_keypair(key_id);
        
        Ok(serde_json::json!({
            "key_id": key_id,
            "public_key": pub_key,
            "generated": true
        }))
    }
    
    fn handle_encrypt(&self, req: &McpRequest) -> Result<serde_json::Value, McpError> {
        let key_id = req.params.get("key_id")
            .and_then(|v| v.as_str())
            .ok_or(McpError::invalid_params("key_id required"))?;
        
        let data = req.params.get("data")
            .and_then(|v| v.as_str())
            .ok_or(McpError::invalid_params("data required"))?;
        
        let ct = self.vault.store(key_id.as_bytes(), data.as_bytes())
            .map_err(|e| McpError::internal_error(&e))?;
        
        Ok(serde_json::json!({
            "nonce": ct.nonce,
            "ciphertext": ct.ciphertext,
            "key_id": ct.key_id
        }))
    }
    
    fn handle_decrypt(&self, req: &McpRequest) -> Result<serde_json::Value, McpError> {
        let key_id = req.params.get("key_id")
            .and_then(|v| v.as_str())
            .ok_or(McpError::invalid_params("key_id required"))?;
        
        let ciphertext = req.params.get("ciphertext")
            .and_then(|v| v.as_str())
            .map(|s| crate::quantum_kernel::Ciphertext {
                nonce: req.params.get("nonce")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                ciphertext: s.to_string(),
                key_id: key_id.to_string(),
            })
            .ok_or(McpError::invalid_params("ciphertext required"))?;
        
        let plain = self.vault.retrieve(key_id.as_bytes(), &ciphertext)
            .map_err(|e| McpError::internal_error(&e))?;
        
        Ok(serde_json::json!({
            "plaintext": String::from_utf8_lossy(&plain)
        }))
    }
    
    fn handle_list_keys(&self, _req: &McpRequest) -> Result<serde_json::Value, McpError> {
        Ok(serde_json::json!({
            "keys": self.vault.list_keypairs()
        }))
    }
    
    fn handle_delete_key(&self, req: &McpRequest) -> Result<serde_json::Value, McpError> {
        let key_id = req.params.get("key_id")
            .and_then(|v| v.as_str())
            .ok_or(McpError::invalid_params("key_id required"))?;
        
        self.vault.remove_keypair(key_id);
        
        Ok(serde_json::json!({
            "deleted": true,
            "key_id": key_id
        }))
    }
    
    fn handle_clear_cache(&self, _req: &McpRequest) -> Result<serde_json::Value, McpError> {
        Ok(serde_json::json!({ "cleared": true }))
    }
    
    fn handle_info(&self, _req: &McpRequest) -> Result<serde_json::Value, McpError> {
        Ok(serde_json::json!({
            "name": "Abir-Guard",
            "version": "1.0.0",
            "mcp_version": "1.0"
        }))
    }
}

impl Default for McpServer {
    fn default() -> Self {
        Self::new()
    }
}

pub fn parse_request(line: &str) -> Result<McpRequest, McpError> {
    serde_json::from_str(line)
        .map_err(|e| McpError::invalid_request(&e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mcp() {
        let server = McpServer::new();
        
        let req = McpRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::json!(1)),
            method: "generate_key".to_string(),
            params: serde_json::json!({"key_id": "test"}),
        };
        
        let resp = server.handle(req);
        assert!(resp.error.is_none());
    }
}