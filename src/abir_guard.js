/**
 * Abir-Guard: Quantum-Resilient Agentic Vault
 * JavaScript/TypeScript SDK
 * 
 * Usage:
 *   const { AbirGuard, AbirGuardMCP } = require('./abir_guard');
 *   
 *   const vault = new AbirGuard();
 *   const { ciphertext } = await vault.encrypt('agent-1', 'secret data');
 */

const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;
const NONCE_LENGTH = 12;

/**
 * Abir-Guard Vault
 */
class AbirGuard {
  constructor() {
    this.keys = new Map();
    this.cache = new Map();
  }
  
  /**
   * Generate a new keypair for an agent
   */
  async generateKeyPair(keyId) {
    const secret = crypto.randomBytes(KEY_LENGTH);
    const publicKey = crypto.createHash('sha256').update(secret).digest();
    
    this.keys.set(keyId, { publicKey, secret });
    
    return {
      keyId,
      publicKey: publicKey.toString('base64'),
      secret: secret.toString('base64')
    };
  }
  
  /**
   * Encrypt data
   */
  async encrypt(keyId, data) {
    let keyData = this.keys.get(keyId);
    if (!keyData) {
      await this.generateKeyPair(keyId);
      keyData = this.keys.get(keyId);
    }
    
    const nonce = crypto.randomBytes(NONCE_LENGTH);
    
    // Derive AES key
    const hash = crypto.createHash('sha256');
    hash.update(Buffer.concat([keyData.secret, Buffer.from('Abir-Guard-PQC-2026')]));
    const aesKey = hash.digest();
    
    const cipher = crypto.createCipheriv(ALGORITHM, aesKey, nonce);
    const ciphertext = Buffer.concat([
      cipher.update(Buffer.from(data)),
      cipher.final()
    ]);
    
    const authTag = cipher.getAuthTag();
    
    const result = {
      keyId,
      nonce: nonce.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      authTag: authTag.toString('base64')
    };
    
    this.cache.set(keyId, result);
    return result;
  }
  
  /**
   * Decrypt data
   */
  async decrypt(keyId, encrypted) {
    const keyData = this.keys.get(keyId);
    if (!keyData) {
      throw new Error(`No key found for ${keyId}`);
    }
    
    const nonce = Buffer.from(encrypted.nonce, 'base64');
    const ciphertext = Buffer.from(encrypted.ciphertext, 'base64');
    const authTag = Buffer.from(encrypted.authTag, 'base64');
    
    // Derive AES key
    const hash = crypto.createHash('sha256');
    hash.update(Buffer.concat([keyData.secret, Buffer.from('Abir-Guard-PQC-2026')]));
    const aesKey = hash.digest();
    
    const decipher = crypto.createDecipheriv(ALGORITHM, aesKey, nonce);
    decipher.setAuthTag(authTag);
    
    const plaintext = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final()
    ]);
    
    return plaintext.toString('utf8');
  }
  
  /**
   * Rotate key (kill switch)
   */
  async rotateKey(keyId) {
    this.keys.delete(keyId);
    this.cache.delete(keyId);
    return this.generateKeyPair(keyId);
  }
  
  /**
   * List all keys
   */
  listKeys() {
    return Array.from(this.keys.keys());
  }
  
  /**
   * Delete key
   */
  async deleteKey(keyId) {
    this.keys.delete(keyId);
    this.cache.delete(keyId);
  }
}

/**
 * MCP Server Client
 */
class AbirGuardMCP {
  constructor(port = 9090) {
    this.port = port;
    this.url = `http://localhost:${port}`;
  }
  
  async request(method, params) {
    const response = await fetch(this.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method,
        params
      })
    });
    
    return response.json();
  }
  
  async generateKeyPair(keyId) {
    return this.request('generate_key', { key_id: keyId });
  }
  
  async encrypt(keyId, data) {
    return this.request('encrypt', { key_id: keyId, data });
  }
  
  async decrypt(keyId, ciphertext) {
    return this.request('decrypt', { key_id: keyId, ciphertext });
  }
}

// ES Module exports
module.exports = { AbirGuard, AbirGuardMCP };
module.exports.default = AbirGuard;