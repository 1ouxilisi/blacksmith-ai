"""
Pentest Knowledge Base - RAG-powered knowledge base for penetration testing methodology,
CVE references, and attack techniques.
"""
import os
from typing import List, Dict, Any, Optional
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_openai import OpenAIEmbeddings
from utils.vectors import storage_manager
from agents.base import init_embedding_model


# Default knowledge base content - MITRE ATT&CK style techniques
DEFAULT_KNOWLEDGE = """
# Reconnaissance Techniques

## Passive OSINT
- WHOIS lookup: Registrant info, nameservers, creation date
- DNS enumeration: A, MX, NS, TXT, CNAME records
- Certificate Transparency: Subdomain discovery via crt.sh
- Search engine recon: Google dorks, GitHub code search
- Social media: Employee enumeration, tech stack hints

## Active Recon
- Port scanning: TCP connect, SYN, UDP scans
- Service version detection: Banner grabbing, nmap -sV
- OS fingerprinting: nmap -O, TTL analysis
- Virtual host discovery: vhost fuzzing
- Web technology fingerprinting: Wappalyzer, whatweb

# Scanning & Enumeration

## Web Enumeration
- Directory bruteforcing: gobuster, ffuf, feroxbuster
- File extension discovery
- Parameter discovery
- API endpoint enumeration
- GraphQL introspection
- WordPress enumeration: wpscan

## Service Enumeration
- SMB: enum4linux, smbclient, share enumeration
- SSH: Version detection, user enumeration
- FTP: Anonymous login, file listing
- Database: Default credentials, version detection
- LDAP: User enumeration, anonymous bind

# Vulnerability Mapping

## Common Web Vulnerabilities
- SQL Injection: Union-based, blind, time-based
- XSS: Reflected, stored, DOM-based
- CSRF: Token validation issues
- SSRF: Server-side request forgery
- XXE: XML external entity
- File upload: Unrestricted upload
- LFI/RFI: Local/remote file inclusion
- Command injection: OS command injection
- Deserialization: Insecure deserialization

## Network Vulnerabilities
- SMB Relay, SMB signing disabled
- Kerberoasting, AS-REP roasting
- EternalBlue (MS17-010)
- BlueKeep (CVE-2019-0708)
- RDP vulnerabilities

# Exploitation Methodology

## Exploit Selection
1. Identify service version precisely
2. Map to CVE database
3. Check exploit-db for public exploits
4. Verify exploit safety and impact
5. Test in lab environment first
6. Execute carefully with rate limiting

## Post-Exploitation
- Privilege escalation: Enumerate misconfigs, kernel exploits, service misconfigs
- Credential access: Dump hashes, keyloggers, password spraying
- Lateral movement: Pass-the-hash, pass-the-ticket, SSH keys
- Persistence: Scheduled tasks, services, registry keys, startup folders
- Data exfiltration: Compressed archives, encoded channels
- Covering tracks: Clear logs, remove artifacts

# Reporting Structure
1. Executive Summary
2. Methodology
3. Findings (with severity ratings)
4. Evidence (screenshots, command outputs)
5. Remediation Recommendations
6. Appendix (technical details, tools used)

# Severity Ratings
- Critical: Direct system compromise, sensitive data exposure
- High: Significant vulnerability with known exploit path
- Medium: Config issue, limited impact, requires specific conditions
- Low: Informational, hardening recommendation
- Info: Observations, no direct security impact
"""


class PentestKnowledgeBase:
    """RAG-powered knowledge base for penetration testing."""

    def __init__(self, persist_dir: str = "./store/knowledge_db"):
        self.persist_dir = persist_dir
        os.makedirs(persist_dir, exist_ok=True)

        # Initialize vector store
        embedding_model = init_embedding_model().get_model()
        self.vector_store = storage_manager(
            collection_name="pentest_knowledge",
            persist_directory=persist_dir,
            embedding_function=embedding_model,
        )

        # Load default knowledge if empty
        self._ensure_default_knowledge()

    def _ensure_default_knowledge(self):
        """Load default knowledge base content if the store is empty."""
        try:
            # Check if store has documents
            results = self.vector_store.query("reconnaissance", n_results=1)
            if not results:
                self.add_knowledge(
                    content=DEFAULT_KNOWLEDGE,
                    metadata={"source": "builtin", "category": "methodology"},
                )
        except Exception:
            # If query fails (empty store), add default
            try:
                self.add_knowledge(
                    content=DEFAULT_KNOWLEDGE,
                    metadata={"source": "builtin", "category": "methodology"},
                )
            except Exception:
                pass  # Vector store not ready yet

    def add_knowledge(self, content: str, metadata: Dict[str, Any]):
        """Add a document to the knowledge base."""
        splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,
            chunk_overlap=200,
        )
        chunks = splitter.split_text(content)

        metadatas = [metadata.copy() for _ in chunks]
        for i, m in enumerate(metadatas):
            m["chunk_index"] = i

        self.vector_store.add_texts(chunks, metadatas=metadatas)

    def query(
        self,
        question: str,
        n_results: int = 5,
        category: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Query the knowledge base."""
        where = {"category": category} if category else None
        results = self.vector_store.query(
            query_texts=[question],
            n_results=n_results,
            where=where,
        )

        documents = []
        for i, doc in enumerate(results.get("documents", [[]])[0]):
            metadata = results.get("metadatas", [[]])[0][i] if results.get("metadatas") else {}
            documents.append({
                "content": doc,
                "metadata": metadata,
                "relevance_score": results.get("distances", [[]])[0][i] if results.get("distances") else None,
            })
        return documents

    def get_relevant_guidance(self, phase: str, target_info: str) -> str:
        """Get relevant guidance for a given phase and target info."""
        query = f"{phase}: {target_info}"
        results = self.query(query, n_results=3)

        if not results:
            return "No specific guidance found. Use standard methodology."

        guidance = "=== Relevant Guidance ===\n\n"
        for r in results:
            guidance += r["content"] + "\n\n"
        return guidance


# Global instance
knowledge_base = PentestKnowledgeBase()
