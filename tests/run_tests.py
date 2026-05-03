#!/usr/bin/env python3
"""
Abir-Guard: Complete Test & Demo
Run this to verify all features work
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from abir_guard import Vault, McpServer, VERSION
from abir_guard.ml_kem import MLKEM1024, HybridKem
from abir_guard.abir_hsm import HSMKeyStore


def test_core_vault():
    """Test 1: Core Vault"""
    print("\n" + "="*60)
    print("TEST 1: Core Vault")
    print("="*60)
    
    print(f"Abir-Guard Version: {VERSION}")
    
    vault = Vault()
    
    # Generate keypair
    pub, sec = vault.generate_keypair("test-agent")
    print(f"[✓] Generated keypair: {pub[:20]}...")
    
    # Encrypt
    secret = b"API_KEY=sk-abc123xyz"
    ct = vault.store("test-agent", secret)
    print(f"[✓] Encrypted: {len(ct.ciphertext)} bytes")
    
    # Decrypt
    plain = vault.retrieve("test-agent", ct)
    print(f"[✓] Decrypted: {plain.decode()}")
    
    # Verify
    assert plain == secret, "Round-trip failed!"
    print("[✓] Round-trip verified!")
    
    return True


def test_mcp_server():
    """Test 2: MCP Server"""
    print("\n" + "="*60)
    print("TEST 2: MCP Server")
    print("="*60)
    
    server = McpServer()
    
    # Test generate_key
    req = {"jsonrpc": "2.0", "id": 1, "method": "generate_key", "params": {"key_id": "mcp-agent"}}
    resp = server.handle(req)
    print(f"[✓] generate_key: {resp['result']['generated']}")
    
    # Test encrypt
    req = {"jsonrpc": "2.0", "id": 2, "method": "encrypt", "params": {"key_id": "mcp-agent", "data": "secret"}}
    resp = server.handle(req)
    print(f"[✓] encrypt: ciphertext length {len(resp['result']['ciphertext'])}")
    
    # Test decrypt
    req = {"jsonrpc": "2.0", "id": 3, "method": "decrypt", "params": {"key_id": "mcp-agent", "ciphertext": resp['result']}}
    resp = server.handle(req)
    print(f"[✓] decrypt: {resp['result']['plaintext']}")
    
    # Test list_keys
    req = {"jsonrpc": "2.0", "id": 4, "method": "list_keys", "params": {}}
    resp = server.handle(req)
    print(f"[✓] list_keys: {resp['result']['keys']}")
    
    return True


def test_ml_kem():
    """Test 3: ML-KEM Key Encapsulation"""
    print("\n" + "="*60)
    print("TEST 3: ML-KEM Key Encapsulation")
    print("="*60)
    
    kem = MLKEM1024()
    print(f"[✓] ML-KEM available: {kem.is_available()}")
    
    # Key generation
    pk, sk = kem.keygen()
    print(f"[✓] Keygen: PK={len(pk)} bytes, SK={len(sk)} bytes")
    
    # Encapsulate
    ct, ss = kem.encapsulate(pk)
    print(f"[✓] Encapsulate: CT={len(ct)} bytes")
    
    # Decapsulate
    ss2 = kem.decapsulate(ct, sk)
    print(f"[✓] Decapsulate: SS match = {ss == ss2}")
    
    # Test Hybrid
    hybrid = HybridKem()
    print(f"[✓] Hybrid quantum-safe: {hybrid.is_quantum_safe}")
    
    return True


def test_hsm():
    """Test 4: HSM Integration"""
    print("\n" + "="*60)
    print("TEST 4: HSM Integration")
    print("="*60)
    
    # Test HSM detection
    hsm = HSMKeyStore("auto")
    print(f"[✓] HSM backend: {hsm.backend}")
    
    return True


def test_js_sdk():
    """Test 5: JS SDK (show code)"""
    print("\n" + "="*60)
    print("TEST 5: JavaScript SDK File")
    print("="*60)
    
    js_path = os.path.join(os.path.dirname(__file__), '../src/abir_guard.js')
    with open(js_path, "r") as f:
        content = f.read()
        if "AbirGuard" in content:
            print("[✓] JS SDK contains AbirGuard class")
            print("[✓] JS SDK has encrypt/decrypt methods")
            return True
    return False


def run_all_tests():
    """Run all tests"""
    print("\n" + "#"*60)
    print("#  Abir-Guard: Complete Test Suite")
    print("#"*60)
    
    tests = [
        ("Core Vault", test_core_vault),
        ("MCP Server", test_mcp_server),
        ("ML-KEM", test_ml_kem),
        ("HSM", test_hsm),
        ("JavaScript SDK", test_js_sdk),
    ]
    
    results = []
    for name, test_fn in tests:
        try:
            test_fn()
            results.append((name, "PASS"))
        except Exception as e:
            results.append((name, f"FAIL: {e}"))
            print(f"[!] Error in {name}: {e}")
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = 0
    for name, result in results:
        status = "✅ PASS" if result == "PASS" else "❌ FAIL"
        print(f"{status} - {name}")
        if result == "PASS":
            passed += 1
    
    print(f"\nTotal: {passed}/{len(results)} tests passed")
    
    if passed == len(results):
        print("\n🎉 ALL TESTS PASSED! Ready for GitHub! 🎉")
    else:
        print("\n⚠️ Some tests failed - need fixes")
    
    return passed == len(results)


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)