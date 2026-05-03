"""
Abir-Guard LangChain Integration
Use Abir-Guard as a LangChain tool
"""

from typing import Type, Optional
from pydantic import BaseModel, Field
from . import Vault, Ciphertext


class EncryptInput(BaseModel):
    """Input for encrypt tool"""
    key_id: str = Field(description="Unique identifier for the encryption key")
    data: str = Field(description="Sensitive data to encrypt")


class DecryptInput(BaseModel):
    """Input for decrypt tool"""
    key_id: str = Field(description="Key identifier used during encryption")
    ciphertext: dict = Field(description="Ciphertext from encrypt response")


class SilentQEncryptTool:
    """
    Abir-Guard Encryption Tool for LangChain
    
    Usage:
        from abir_guard.langchain import SilentQEncryptTool, SilentQDecryptTool
        
        encrypt_tool = SilentQEncryptTool()
        result = encrypt_tool.invoke({"key_id": "agent-1", "data": "secret"})
    """
    
    name = "abir_guard_encrypt"
    description = "Encrypts sensitive data using quantum-resistant encryption. Use this to protect API keys, passwords, or other secrets before storing or passing to AI models."
    
    def __init__(self, vault: Optional[Vault] = None):
        if vault is None:
            from . import Vault as V
            vault = V()
        self.vault = vault
    
    def invoke(self, input_data: dict) -> dict:
        """Encrypt data"""
        key_id = input_data["key_id"]
        data = input_data["data"].encode()
        
        ct = self.vault.store(key_id, data)
        
        return {
            "success": True,
            "key_id": key_id,
            "ciphertext": {
                "nonce": ct.nonce,
                "ciphertext": ct.ciphertext
            },
            "message": "Data encrypted successfully"
        }
    
    def __call__(self, input_data: dict) -> dict:
        return self.invoke(input_data)


class SilentQDecryptTool:
    """
    Abir-Guard Decryption Tool for LangChain
    """
    
    name = "abir_guard_decrypt"
    description = "Decrypts data that was encrypted with Abir-Guard. Requires the same key_id used for encryption."
    
    def __init__(self, vault: Optional[Vault] = None):
        self.vault = vault or Vault()
    
    def invoke(self, input_data: dict) -> dict:
        """Decrypt data"""
        key_id = input_data["key_id"]
        ct = Ciphertext(**input_data["ciphertext"])
        
        plaintext = self.vault.retrieve(key_id, ct)
        
        return {
            "success": True,
            "key_id": key_id,
            "plaintext": plaintext.decode(),
            "message": "Data decrypted successfully"
        }
    
    def __call__(self, input_data: dict) -> dict:
        return self.invoke(input_data)


class SilentQKeyGenTool:
    """
    Abir-Guard Key Generation Tool for LangChain
    """
    
    name = "abir_guard_keygen"
    description = "Generates a new quantum-resistant keypair for an AI agent. Each agent should have its own unique key_id."
    
    def __init__(self, vault: Optional[Vault] = None):
        self.vault = vault or Vault()
    
    def invoke(self, input_data: dict) -> dict:
        """Generate keypair"""
        key_id = input_data["key_id"]
        
        pub, sec = self.vault.generate_keypair(key_id)
        
        return {
            "success": True,
            "key_id": key_id,
            "public_key": pub[:32] + "...",
            "message": "Keypair generated. Keep secret_key secure!"
        }
    
    def __call__(self, input_data: dict) -> dict:
        return self.invoke(input_data)


def get_langchain_tools(vault: Optional[Vault] = None):
    """
    Get all Abir-Guard tools for LangChain
    
    Usage:
        from abir_guard.langchain import get_langchain_tools
        
        tools = get_langchain_tools()
        agent = Agent(tools=tools)
    """
    return [
        SilentQKeyGenTool(vault),
        SilentQEncryptTool(vault),
        SilentQDecryptTool(vault),
    ]


def demo():
    """Demo LangChain integration"""
    print("=" * 50)
    print("Abir-Guard: LangChain Integration")
    print("=" * 50)
    
    vault = Vault()
    
    print("\n[1] KeyGen Tool...")
    gen_tool = SilentQKeyGenTool(vault)
    result = gen_tool.invoke({"key_id": "agent-1"})
    print(f"    {result}")
    
    print("\n[2] Encrypt Tool...")
    enc_tool = SilentQEncryptTool(vault)
    result = enc_tool.invoke({
        "key_id": "agent-1",
        "data": "API_KEY=sk-abc123"
    })
    print(f"    Encrypted: {result['ciphertext']['ciphertext'][:24]}...")
    
    print("\n[3] Decrypt Tool...")
    dec_tool = SilentQDecryptTool(vault)
    result = dec_tool.invoke({
        "key_id": "agent-1",
        "ciphertext": result['ciphertext']
    })
    print(f"    Decrypted: {result['plaintext']}")
    
    print("\n[4] Get all tools...")
    tools = get_langchain_tools(vault)
    print(f"    Tools: {len(tools)}")
    for t in tools:
        print(f"    - {t.name}")
    
    print("\n" + "=" * 50)


if __name__ == "__main__":
    demo()