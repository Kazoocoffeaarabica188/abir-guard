"""
Abir-Guard: Pytest Test Suite
"""
import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from abir_guard import Vault, McpServer, VERSION, Ciphertext
from abir_guard.ml_kem import MLKEM1024, HybridKem
from abir_guard.abir_hsm import HSMKeyStore


class TestVault:
    """Test Core Vault"""
    
    def test_generate_keypair(self):
        vault = Vault()
        pub, sec = vault.generate_keypair("test-agent")
        assert pub
        assert sec
        assert len(pub) > 0
    
    def test_encrypt_decrypt(self):
        vault = Vault()
        vault.generate_keypair("test-agent")
        
        secret = b"API_KEY=sk-abc123xyz"
        ct = vault.store("test-agent", secret)
        plain = vault.retrieve("test-agent", ct)
        
        assert plain == secret
    
    def test_list_keypairs(self):
        vault = Vault()
        vault.generate_keypair("agent-1")
        vault.generate_keypair("agent-2")
        
        keys = vault.list_keypairs()
        assert "agent-1" in keys
        assert "agent-2" in keys
    
    def test_remove_keypair(self):
        vault = Vault()
        vault.generate_keypair("temp-key")
        vault.remove_keypair("temp-key")
        
        assert "temp-key" not in vault.list_keypairs()
    
    def test_clear_cache(self):
        vault = Vault()
        vault.clear_cache()
        assert len(vault.cache) == 0


class TestMcpServer:
    """Test MCP Server"""
    
    def test_info(self):
        server = McpServer()
        req = {"jsonrpc": "2.0", "id": 1, "method": "info", "params": {}}
        resp = server.handle(req)
        
        assert resp["result"]["name"] == "Abir-Guard"
        assert resp["result"]["version"] == VERSION
    
    def test_generate_key(self):
        server = McpServer()
        req = {"jsonrpc": "2.0", "id": 1, "method": "generate_key", "params": {"key_id": "test"}}
        resp = server.handle(req)
        
        assert resp["result"]["generated"] is True
    
    def test_encrypt_decrypt_roundtrip(self):
        server = McpServer()
        
        # Generate key
        req = {"jsonrpc": "2.0", "id": 1, "method": "generate_key", "params": {"key_id": "test"}}
        server.handle(req)
        
        # Encrypt
        req = {"jsonrpc": "2.0", "id": 2, "method": "encrypt", "params": {"key_id": "test", "data": "secret"}}
        resp = server.handle(req)
        assert "ciphertext" in resp["result"]
        
        # Decrypt
        req = {"jsonrpc": "2.0", "id": 3, "method": "decrypt", "params": {"key_id": "test", "ciphertext": resp["result"]}}
        resp = server.handle(req)
        assert resp["result"]["plaintext"] == "secret"
    
    def test_list_keys(self):
        server = McpServer()
        req = {"jsonrpc": "2.0", "id": 1, "method": "generate_key", "params": {"key_id": "test"}}
        server.handle(req)
        
        req = {"jsonrpc": "2.0", "id": 2, "method": "list_keys", "params": {}}
        resp = server.handle(req)
        
        assert "test" in resp["result"]["keys"]
    
    def test_unknown_method(self):
        server = McpServer()
        req = {"jsonrpc": "2.0", "id": 1, "method": "unknown", "params": {}}
        resp = server.handle(req)
        
        assert "error" in resp


class TestMLKEM:
    """Test ML-KEM Key Encapsulation"""
    
    def test_availability(self):
        kem = MLKEM1024()
        assert isinstance(kem.is_available(), bool)
    
    def test_keygen(self):
        kem = MLKEM1024()
        pk, sk = kem.keygen()
        assert len(pk) > 0
        assert len(sk) > 0
    
    def test_encapsulate_decapsulate(self):
        kem = MLKEM1024()
        pk, sk = kem.keygen()
        
        ct, ss = kem.encapsulate(pk)
        ss2 = kem.decapsulate(ct, sk)
        
        assert ss == ss2
    
    def test_hybrid(self):
        hybrid = HybridKem()
        hpk, hsk = hybrid.keygen()
        
        hct, hss = hybrid.encapsulate(hpk)
        hss2 = hybrid.decapsulate(hct, hsk)
        
        assert hss == hss2


class TestHSM:
    """Test HSM Integration"""
    
    def test_backend_detection(self):
        hsm = HSMKeyStore("auto")
        assert hsm.backend in ["keychain", "credential_manager", "secret_service", "file"]
    
    def test_store_retrieve(self):
        hsm = HSMKeyStore("file")
        hsm.store_secret("test-key", b"my-secret-data")
        secret = hsm.retrieve_secret("test-key")
        assert secret == b"my-secret-data"
    
    def test_delete(self):
        hsm = HSMKeyStore("file")
        hsm.store_secret("temp-key", b"data")
        hsm.delete_secret("temp-key")
        assert hsm.retrieve_secret("temp-key") is None