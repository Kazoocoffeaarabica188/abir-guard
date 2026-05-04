"""
Abir-Guard LangChain Integration
Use Abir-Guard as a LangChain tool
"""

from typing import Type, Optional
from pydantic import BaseModel, Field
from langchain.tools import BaseTool
from . import Vault, Ciphertext


class EncryptInput(BaseModel):
    """Input for encrypt tool"""
    key_id: str = Field(description="Unique identifier for the encryption key")
    data: str = Field(description="Sensitive data to encrypt")


class DecryptInput(BaseModel):
    """Input for decrypt tool"""
    key_id: str = Field(description="Key identifier used during encryption")
    ciphertext: dict = Field(description="Ciphertext from encrypt response")


class KeyGenInput(BaseModel):
    """Input for key generation tool"""
    key_id: str = Field(description="Unique identifier for the new keypair")


class SilentQEncryptTool(BaseTool):
    """Abir-Guard Encryption Tool for LangChain"""

    name = "abir_guard_encrypt"
    description = "Encrypts sensitive data using quantum-resistant encryption. Use this to protect API keys, passwords, or other secrets before storing or passing to AI models."
    args_schema: Type[BaseModel] = EncryptInput

    def __init__(self, vault: Optional[Vault] = None):
        super().__init__()
        if vault is None:
            from . import Vault as V
            vault = V()
        self.vault = vault

    def _run(self, key_id: str, data: str) -> dict:
        """Encrypt data"""
        ct = self.vault.store(key_id, data.encode())

        return {
            "success": True,
            "key_id": key_id,
            "ciphertext": {
                "nonce": ct.nonce,
                "ciphertext": ct.ciphertext
            },
            "message": "Data encrypted successfully"
        }

    async def _arun(self, key_id: str, data: str) -> dict:
        return self._run(key_id, data)


class SilentQDecryptTool(BaseTool):
    """Abir-Guard Decryption Tool for LangChain"""

    name = "abir_guard_decrypt"
    description = "Decrypts data that was encrypted with Abir-Guard. Requires the same key_id used for encryption."
    args_schema: Type[BaseModel] = DecryptInput

    def __init__(self, vault: Optional[Vault] = None):
        super().__init__()
        self.vault = vault or Vault()

    def _run(self, key_id: str, ciphertext: dict) -> dict:
        """Decrypt data"""
        ct = Ciphertext(**ciphertext)
        plaintext = self.vault.retrieve(key_id, ct)

        return {
            "success": True,
            "key_id": key_id,
            "plaintext": plaintext.decode(),
            "message": "Data decrypted successfully"
        }

    async def _arun(self, key_id: str, ciphertext: dict) -> dict:
        return self._run(key_id, ciphertext)


class SilentQKeyGenTool(BaseTool):
    """Abir-Guard Key Generation Tool for LangChain"""

    name = "abir_guard_keygen"
    description = "Generates a new quantum-resistant keypair for an AI agent. Each agent should have its own unique key_id."
    args_schema: Type[BaseModel] = KeyGenInput

    def __init__(self, vault: Optional[Vault] = None):
        super().__init__()
        self.vault = vault or Vault()

    def _run(self, key_id: str) -> dict:
        """Generate keypair"""
        pub, sec = self.vault.generate_keypair(key_id)

        return {
            "success": True,
            "key_id": key_id,
            "public_key": pub[:32] + "...",
            "message": "Keypair generated. Keep secret_key secure!"
        }

    async def _arun(self, key_id: str) -> dict:
        return self._run(key_id)


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