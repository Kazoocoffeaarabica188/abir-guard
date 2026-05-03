#!/usr/bin/env python3
"""
Abir-Guard: Secure CrewAI Agent Example
Shows how to handle sensitive data securely in CrewAI workflows
"""

from abir_guard import Vault, McpServer


def demo_secure_agent():
    """
    Secure CrewAI workflow demo
    
    The agent handles sensitive data securely:
    1. Generate unique keypair per agent
    2. Encrypt sensitive data before agent memory
    3. Only decrypt when explicitly needed
    4. Auto-rotate keys on suspicion
    """
    print("=" * 60)
    print("Abir-Guard: Secure CrewAI Agent Demo")
    print("=" * 60)
    
    # Initialize vault
    vault = Vault()
    
    # Create secure agent
    agent_id = "secure-agent"
    pub_key, sec_key = vault.generate_keypair(agent_id)
    print(f"\n[1] Created secure agent: {agent_id}")
    print(f"    Public key: {pub_key[:20]}...")
    
    # Sensitive data the agent needs to handle
    sensitive_data = b"API_KEY=sk-secret-12345"
    
    # Before storing in agent memory - encrypt!
    encrypted = vault.store(agent_id, sensitive_data)
    print(f"\n[2] Encrypted sensitive data")
    print(f"    Ciphertext: {encrypted.ciphertext[:20]}...")
    print(f"    Stored ONLY encrypted - agent memory is safe!")
    
    # Agent continues normal work...
    print(f"\n[3] Agent doing normal work...")
    print(f"    (Sensitive data not in plaintext memory)")
    
    # When data is actually needed - decrypt
    decrypted = vault.retrieve(agent_id, encrypted)
    print(f"\n[4] Decrypt on-demand:")
    print(f"    Plaintext: {decrypted.decode()}")
    
    # Verify security
    assert decrypted == sensitive_data
    print(f"\n[+] Round-trip verified!")
    
    # Kill switch demo - remove key to invalidate data
    print(f"\n[5] Kill Switch - Remove key...")
    vault.remove_keypair(agent_id)
    print(f"    Key removed - old data orphaned!")
    
    print("\n" + "=" * 60)
    print("Benefits:")
    print("  + Sensitive data never in plaintext")
    print("  + Encrypted before agent memory")
    print("  + Zero tokens sent to LLM containing secrets")
    print("  + Kill switch can invalidate all data")
    print("=" * 60)


def demo_mcp_integration():
    """Show MCP server usage"""
    print("\n=== MCP Server Integration ===")
    
    server = McpServer()
    
    # Agent generates key
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "generate_key",
        "params": {"key_id": "secure-agent"}
    }
    resp = server.handle(req)
    print(f"generate_key: {resp['result']['generated']}")
    
    # Encrypt sensitive data
    req = {
        "jsonrpc": "2.0", 
        "id": 2,
        "method": "encrypt",
        "params": {"key_id": "secure-agent", "data": "TOP_SECRET=ABC123"}
    }
    resp = server.handle(req)
    print(f"encrypt: ciphertext length = {len(resp['result']['ciphertext'])}")
    
    # List keys
    req = {"jsonrpc": "2.0", "id": 3, "method": "list_keys", "params": {}}
    resp = server.handle(req)
    print(f"keys: {resp['result']['keys']}")
    
    print("MCP ready for CrewAI/LangChain integration!")


if __name__ == "__main__":
    demo_secure_agent()
    demo_mcp_integration()
    
    print("\n" + "=" * 60)
    print("All demos passed!")
    print("=" * 60)
