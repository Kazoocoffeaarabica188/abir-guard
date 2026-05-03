"""
Abir-Guard CrewAI Integration
Use Abir-Guard as a CrewAI tool
"""

from typing import Optional, Any
from pydantic import Field
from . import Vault, Ciphertext


def _get_base_tool_class():
    """Lazily import CrewAI BaseTool to handle version differences"""
    try:
        from crewai.tools import BaseTool
        return BaseTool
    except ImportError:
        try:
            from crewai_tools import BaseTool
            return BaseTool
        except ImportError:
            raise ImportError(
                "crewai or crewai-tools is required. "
                "Install with: pip install crewai"
            )


class EncryptCrewTool(_get_base_tool_class()):
    """CrewAI Encrypt Tool"""
    
    name: str = "abir_guard_encrypt"
    description: str = "Encrypts sensitive data using quantum-resistant encryption. Input: key_id (str), data (str). Output: encrypted ciphertext."
    
    def __init__(self, vault: Optional[Vault] = None, **kwargs):
        # Don't call super().__init__() with vault - it's not a CrewAI kwarg
        super().__init__(**kwargs)
        if vault is None:
            from . import Vault as V
            vault = V()
        self.vault = vault
    
    def _run(self, key_id: str, data: str) -> str:
        """Encrypt data"""
        key_id = key_id.strip()
        if not key_id:
            return "Error: key_id is required"
        ct = self.vault.store(key_id, data.encode())
        return f"Encrypted successfully. Ciphertext: {ct.ciphertext[:32]}... Nonce: {ct.nonce}"


class DecryptCrewTool(_get_base_tool_class()):
    """CrewAI Decrypt Tool"""
    
    name: str = "abir_guard_decrypt"
    description: str = "Decrypts Abir-Guard encrypted data. Input: key_id (str), ciphertext (dict). Output: plaintext."
    
    def __init__(self, vault: Optional[Vault] = None, **kwargs):
        super().__init__(**kwargs)
        if vault is None:
            from . import Vault as V
            vault = V()
        self.vault = vault
    
    def _run(self, key_id: str, ciphertext: dict) -> str:
        """Decrypt data"""
        try:
            ct = Ciphertext(**ciphertext)
            plaintext = self.vault.retrieve(key_id, ct)
            return f"Decrypted: {plaintext.decode()}"
        except Exception as e:
            return f"Decryption failed: {e}"


class KeyGenCrewTool(_get_base_tool_class()):
    """CrewAI KeyGen Tool"""
    
    name: str = "abir_guard_keygen"
    description: str = "Generate a new Abir-Guard encryption key. Input: key_id (str). Output: success message."
    
    def __init__(self, vault: Optional[Vault] = None, **kwargs):
        super().__init__(**kwargs)
        if vault is None:
            from . import Vault as V
            vault = V()
        self.vault = vault
    
    def _run(self, key_id: str) -> str:
        """Generate keypair"""
        try:
            pub, sec = self.vault.generate_keypair(key_id)
            return f"Keypair generated for {key_id}. Public key: {pub[:20]}..."
        except Exception as e:
            return f"Key generation failed: {e}"


def get_crewai_tools(vault: Optional[Vault] = None):
    """
    Get all Abir-Guard tools for CrewAI
    
    Usage:
        from abir_guard.crewai import get_crewai_tools
        
        tools = get_crewai_tools()
        agent = Agent(tools=tools)
    """
    return [
        KeyGenCrewTool(vault),
        EncryptCrewTool(vault),
        DecryptCrewTool(vault),
    ]


def demo():
    """Demo CrewAI integration"""
    print("=" * 50)
    print("Abir-Guard: CrewAI Integration")
    print("=" * 50)
    
    vault = Vault()
    
    print("\n[1] KeyGen Tool...")
    tool = KeyGenCrewTool(vault)
    result = tool._run("agent-1")
    print(f"    {result}")
    
    print("\n[2] Encrypt Tool...")
    enc_tool = EncryptCrewTool(vault)
    result = enc_tool._run("agent-1", "API_KEY=sk-abc123")
    print(f"    {result}")
    
    print("\n[3] Get all tools...")
    tools = get_crewai_tools(vault)
    print(f"    Tools: {len(tools)}")
    for t in tools:
        print(f"    - {t.name}")
    
    print("\n" + "=" * 50)


if __name__ == "__main__":
    demo()
