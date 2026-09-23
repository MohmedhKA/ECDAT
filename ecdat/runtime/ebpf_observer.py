import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from ecdat.models import CryptoAsset, PrimitiveType, XTier, EvidenceLevel, IntentClass, AgilityLevel

# Standard BPF trace script for OpenSSL EVP and SSL operations
BPFTRACE_CRYPTO_SCRIPT = """
uprobe:/lib/x86_64-linux-gnu/libcrypto.so.3:EVP_EncryptInit_ex
{
    printf("EVP_ENCRYPT_INIT: pid=%d comm=%s\\n", pid, comm);
}

uprobe:/lib/x86_64-linux-gnu/libcrypto.so.3:EVP_DigestInit_ex
{
    printf("EVP_DIGEST_INIT: pid=%d comm=%s\\n", pid, comm);
}

uprobe:/lib/x86_64-linux-gnu/libssl.so.3:SSL_set_cipher_list
{
    printf("SSL_CIPHER_LIST: pid=%d comm=%s str=%s\\n", pid, comm, str(arg1));
}
"""

class EBPFObserver:
    """
    Dynamic cryptographic observer using eBPF uprobes on OpenSSL shared libraries.
    Captures live user-space cryptographic invocations across unparsed runtimes
    with PID and process image correlation.
    """

    def __init__(self, libcrypto_path: Optional[str] = None):
        self.libcrypto_path = libcrypto_path or self._locate_libcrypto()

    def _locate_libcrypto(self) -> Optional[str]:
        candidates = [
            "/lib/x86_64-linux-gnu/libcrypto.so.3",
            "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
            "/usr/lib64/libcrypto.so.3",
            "/usr/lib/libcrypto.so",
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
        return None

    def is_available(self) -> bool:
        """Checks whether eBPF tracing tools (bpftrace) and root privileges are available."""
        has_tool = shutil.which("bpftrace") is not None
        has_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
        return has_tool and has_root and (self.libcrypto_path is not None)

    def generate_tracer_script(self, output_file: Path) -> Path:
        """Writes a ready-to-run standalone bpftrace script for runtime crypto monitoring."""
        script_content = BPFTRACE_CRYPTO_SCRIPT.replace(
            "/lib/x86_64-linux-gnu/libcrypto.so.3",
            self.libcrypto_path or "/lib/x86_64-linux-gnu/libcrypto.so.3"
        )
        output_file.write_text(script_content, encoding="utf-8")
        return output_file

    def execute_live_trace(self, duration_seconds: int = 5, output_file: Optional[Path] = None) -> List[CryptoAsset]:
        """
        Executes a live bpftrace session for the given duration, captures logs,
        and parses observed cryptographic operations into CryptoAsset records.
        """
        if not self.is_available():
            missing = []
            if shutil.which("bpftrace") is None:
                missing.append("bpftrace utility not installed")
            if not (hasattr(os, "geteuid") and os.geteuid() == 0):
                missing.append("root privileges (CAP_BPF/CAP_SYS_ADMIN) required")
            if self.libcrypto_path is None:
                missing.append("libcrypto.so shared library not located")
            raise RuntimeError(f"eBPF runtime observation unavailable: {', '.join(missing)}")

        with tempfile.NamedTemporaryFile("w", suffix=".bt", delete=False) as script_tmp:
            script_path = Path(script_tmp.name)
            self.generate_tracer_script(script_path)

        out_log_path = output_file or Path(tempfile.NamedTemporaryFile(suffix=".log", delete=False).name)

        try:
            # Run bpftrace with timeout
            proc = subprocess.run(
                ["bpftrace", str(script_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=duration_seconds,
            )
            out_log_path.write_text(proc.stdout, encoding="utf-8")
        except subprocess.TimeoutExpired as e:
            # Timeout is expected when duration expires
            captured = e.stdout or ""
            if isinstance(captured, bytes):
                captured = captured.decode("utf-8", errors="replace")
            out_log_path.write_text(captured, encoding="utf-8")
        finally:
            if script_path.exists():
                try:
                    script_path.unlink()
                except OSError:
                    pass

        return self.parse_trace_log(out_log_path)

    def parse_trace_log(self, log_path: Path) -> List[CryptoAsset]:
        """
        Parses an eBPF trace log into E4_RUNTIME_OBSERVED CryptoAsset models.
        Strictly avoids fabricating algorithm names; reports explicit captured algorithms
        or flags as unmodeled EVP runtime invocations.
        """
        if not log_path.exists():
            return []

        assets: List[CryptoAsset] = []
        try:
            lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return []

        for idx, line in enumerate(lines, start=1):
            # Parse pid and comm if present
            pid = "unknown"
            comm = "runtime"
            for part in line.split():
                if part.startswith("pid="):
                    pid = part.split("=")[-1]
                elif part.startswith("comm="):
                    comm = part.split("=")[-1]

            if "EVP_ENCRYPT_INIT" in line:
                # Check if specific cipher was captured in trace line
                alg = "OPENSSL-EVP-CIPHER"
                key_size = None
                for token in line.split():
                    if token.startswith("cipher=") or token.startswith("alg="):
                        alg = token.split("=")[-1].upper()
                        if "AES" in alg:
                            key_size = 256
                        elif "DES" in alg:
                            key_size = 64

                assets.append(CryptoAsset(
                    asset_id=f"EBPF-ENCRYPT-{idx:03d}",
                    component_name=f"{comm}:{pid}:evp_encrypt",
                    algorithm=alg,
                    key_size=key_size,
                    primitive_type=PrimitiveType.ENCRYPTION,
                    file_path=str(self.libcrypto_path or "libcrypto.so"),
                    line_number=0,
                    x_tier=XTier.SHORT_TERM,
                    x_confidence="MEDIUM" if alg == "OPENSSL-EVP-CIPHER" else "VERIFIED",
                    has_crypto_shredding=False,
                    intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
                    evidence_level=EvidenceLevel.E4_RUNTIME_OBSERVED,
                    evidence_sources=["ebpf:EVP_EncryptInit_ex"],
                    agility_level=AgilityLevel.PROVIDER,
                    raw_properties={"source": "ebpf_observer", "pid": pid, "comm": comm, "trace_line": line}
                ))
            elif "EVP_DIGEST_INIT" in line:
                alg = "OPENSSL-EVP-DIGEST"
                key_size = None
                for token in line.split():
                    if token.startswith("digest=") or token.startswith("md="):
                        alg = token.split("=")[-1].upper()

                assets.append(CryptoAsset(
                    asset_id=f"EBPF-DIGEST-{idx:03d}",
                    component_name=f"{comm}:{pid}:evp_digest",
                    algorithm=alg,
                    key_size=key_size,
                    primitive_type=PrimitiveType.HASH,
                    file_path=str(self.libcrypto_path or "libcrypto.so"),
                    line_number=0,
                    x_tier=XTier.OPERATIONAL,
                    x_confidence="MEDIUM" if alg == "OPENSSL-EVP-DIGEST" else "VERIFIED",
                    has_crypto_shredding=False,
                    intent_class=IntentClass.INTEGRITY_CHECKSUM,
                    evidence_level=EvidenceLevel.E4_RUNTIME_OBSERVED,
                    evidence_sources=["ebpf:EVP_DigestInit_ex"],
                    agility_level=AgilityLevel.PROVIDER,
                    raw_properties={"source": "ebpf_observer", "pid": pid, "comm": comm, "trace_line": line}
                ))
            elif "SSL_CIPHER_LIST" in line:
                cipher_str = line.split("str=")[-1].strip() if "str=" in line else "TLS-CIPHERS"
                first_cipher = cipher_str.split(":")[0] if ":" in cipher_str else cipher_str
                assets.append(CryptoAsset(
                    asset_id=f"EBPF-SSL-{idx:03d}",
                    component_name=f"{comm}:{pid}:cipher_list",
                    algorithm=first_cipher,
                    key_size=None,
                    primitive_type=PrimitiveType.KEY_EXCHANGE,
                    file_path="libssl.so",
                    line_number=0,
                    x_tier=XTier.OPERATIONAL,
                    x_confidence="VERIFIED",
                    has_crypto_shredding=False,
                    intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
                    evidence_level=EvidenceLevel.E4_RUNTIME_OBSERVED,
                    evidence_sources=["ebpf:SSL_set_cipher_list"],
                    agility_level=AgilityLevel.CONFIGURABLE,
                    raw_properties={"source": "ebpf_observer", "pid": pid, "comm": comm, "trace_line": line, "ciphers": cipher_str}
                ))

        return assets

def get_ebpf_observer() -> EBPFObserver:
    return EBPFObserver()
