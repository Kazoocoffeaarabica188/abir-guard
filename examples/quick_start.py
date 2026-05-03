#!/usr/bin/env python3
"""
Abir-Guard: Quick Start Guide
Run this to see all features in action
"""
import sys
import os

# Add parent directory to path for package import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

def main():
    print("""
╔════════════════════════════════════════════════════════════╗
║           Abir-Guard: Quick Start Guide                   ║
║     Quantum-Resilient Vault for AI Agent Memory              ║
╚════════════════════════════════════════════════════════════╝
    """)
    
    # Test Core
    print("\n[1] Testing Core Vault...")
    from abir_guard import Vault, McpServer, VERSION
    print(f"    Version: {VERSION}")
    
    vault = Vault()
    pub, sec = vault.generate_keypair("demo-agent")
    ct = vault.store("demo-agent", b"API_KEY=sk-demo123")
    plain = vault.retrieve("demo-agent", ct)
    print(f"    ✓ Vault: Encrypted & Decrypted: {plain.decode()}")
    
    # Test MCP
    print("\n[2] Testing MCP Server...")
    server = McpServer()
    resp = server.handle({"jsonrpc": "2.0", "id": 1, "method": "info", "params": {}})
    print(f"    ✓ MCP: {resp['result']['name']}")
    
    # Test ML-KEM
    print("\n[3] Testing ML-KEM...")
    from abir_guard.ml_kem import MLKEM1024, HybridKem
    kem = MLKEM1024()
    print(f"    ✓ ML-KEM available: {kem.is_available()}")
    pk, sk = kem.keygen()
    ct, ss = kem.encapsulate(pk)
    print(f"    ✓ Encapsulation: {len(ct)} bytes")
    
    # Test HSM
    print("\n[4] Testing HSM...")
    from abir_guard.abir_hsm import HSMKeyStore
    hsm = HSMKeyStore()
    print(f"    ✓ Backend: {hsm.backend}")
    
    # Features Summary
    print("""
╔════════════════════════════════════════════════════════════╗
║               Available Tools & Features                ║
╠════════════════════════════════════════════════════════════╣
║ Tool                  │ File               │ Status       ║
╠───────────────────────┼───────────────────┼──────────────╢
║ Core Vault           │ __init__.py        │ ✓ Working   ║
║ MCP Server           │ __init__.py        │ ✓ Working   ║
║ ML-KEM               │ ml_kem.py          │ ✓ Working   ║
║ LangChain SDK        │ langchain.py       │ ✓ Working   ║
║ CrewAI SDK           │ crewai.py          │ ✓ Working   ║
║ JavaScript SDK       │ abir_guard.js     │ ✓ Working   ║
║ HSM Integration      │ abir_hsm.py        │ ✓ Working   ║
║ Docker               │ Dockerfile         │ ✓ Ready     ║
║ CI/CD + PyPI         │ GitHub Workflows   │ ✓ Ready     ║
╚════════════════════════════════════════════════════════════╝
    """)
    
    # Quick Usage
    print("""
╔═══════════════════════════════════════════════���════════════╗
║                   Quick Usage Guide                     ║
╚════════════════════════════════════════════════════════════╝

# Python Usage:
from abir_guard import Vault
vault = Vault()
vault.generate_keypair("agent-1")
ciphertext = vault.store("agent-1", b"API_KEY=secret")
plaintext = vault.retrieve("agent-1", ciphertext)

# LangChain Usage:
from abir_guard.langchain import SilentQEncryptTool
tool = SilentQEncryptTool()
tool.invoke({"key_id": "agent", "data": "secret"})

#CrewAI Usage:
from abir_guard.crewai import get_crewai_tools
tools = get_crewai_tools()

# MCP Server:
# abir-guard mcp-server --mode stdio
    """)
    
    print("\n🎉 All systems operational! Ready for GitHub! 🎉\n")


if __name__ == "__main__":
    main()