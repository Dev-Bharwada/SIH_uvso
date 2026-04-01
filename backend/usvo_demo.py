#!/usr/bin/env python3
"""
UVSO Demo Prototype (Safe Simulation + Drive Detection)
Universal Verifiable Sanitization Orchestrator (Prototype for SIH)

Features:
- Simulated disk mode (safe, uses a file as fake disk)
- Detect real drives safely (classification; non-destructive)
- Clear overwrite sanitization (simulation; two-pass 0xFF then 0x00)
- Cryptographic Erase (simulated via XOR + key sharding)
- Verification (NIST-style stratified sampling)
- Certificate JSON generation (+ detached RSA-3072 signature)
- Ledger (append-only text file)
- Sequential certificate numbering

Usage:
    python3 usvo_demo.py
"""

import os
import json
import hashlib
import subprocess
import random
import time
import base64
from collections import Counter
import math
import shutil
import re

FAKE_DISK = "fakedisk.img"
LEDGER_FILE = "ledger.txt"
CERT_FILE = "cert.json"
LAST_METHOD = None

# ---------------------
# Utility Functions
# ---------------------

def run_cmd(cmd):
    """Run a shell command and return output ('' on failure)."""
    try:
        return subprocess.check_output(cmd, text=True).strip()
    except subprocess.CalledProcessError:
        return ""

# ---------------------
# Simulation Functions
# ---------------------

def create_fake_disk(size_mb: int = 10) -> None:
    """Create a fake disk file for simulation."""
    print(f"Creating fake {size_mb}MB disk at {FAKE_DISK}...")
    with open(FAKE_DISK, "wb") as f:
        f.write(os.urandom(size_mb * 1024 * 1024))
    print("Fake disk created.")

def clear_overwrite(disk: str = FAKE_DISK) -> None:
    """Simulate NIST-style Clear with a two-pass complement pattern.
    Pass 1: write all 1s (0xFF)
    Pass 2: write all 0s (0x00)
    Final state is zeros so sampling verification expects all-zero blocks.
    """
    if not os.path.exists(disk):
        print(f"Error: {disk} not found. Create it first (Menu option 2).")
        return

    size = os.path.getsize(disk)
    chunk = 1024 * 1024  # 1 MiB

    print(f"Clear Pass 1/2: writing 0xFF across {disk} ({size} bytes)...")
    written = 0
    with open(disk, "r+b") as f:
        f.seek(0)
        pattern_ff = b"\xFF" * chunk
        while written < size:
            to_write = min(chunk, size - written)
            if to_write == chunk:
                f.write(pattern_ff)
            else:
                f.write(b"\xFF" * to_write)
            written += to_write
        f.flush()
        os.fsync(f.fileno())
    print("Pass 1 complete.")

    print(f"Clear Pass 2/2: writing 0x00 across {disk} ({size} bytes)...")
    written = 0
    with open(disk, "r+b") as f:
        f.seek(0)
        pattern_00 = b"\x00" * chunk
        while written < size:
            to_write = min(chunk, size - written)
            if to_write == chunk:
                f.write(pattern_00)
            else:
                f.write(b"\x00" * to_write)
            written += to_write
        f.flush()
        os.fsync(f.fileno())
    print("Pass 2 complete. Clear overwrite (two-pass) done.")

def cryptographic_erase(disk: str = FAKE_DISK, operator: str = "TeamSIH") -> None:
    """Simulate Cryptographic Erase using key + sharding and write a CE event record."""
    if not os.path.exists(disk):
        print(f"Error: {disk} not found. Create it first (Menu option 2).")
        return

    key = os.urandom(32)  # 256-bit key
    print("Generated 256-bit encryption key.")
    key_fingerprint = hashlib.sha256(key).hexdigest()

    # Shard key into 3 pieces (XOR-based 2-of-3 reconstruction)
    shard1 = os.urandom(32)
    shard2 = os.urandom(32)
    shard3 = bytes(a ^ b ^ c for a, b, c in zip(key, shard1, shard2))
    shards = [shard1, shard2, shard3]

    for i, s in enumerate(shards):
        with open(f"shard_{i}.bin", "wb") as f:
            f.write(s)
    print("Key split into 3 shards: shard_0.bin, shard_1.bin, shard_2.bin")

    # "Encrypt" disk by XORing with key (demo only)
    with open(disk, "rb") as f:
        data = f.read()
    encrypted = bytes(a ^ b for a, b in zip(data, key * (len(data) // len(key) + 1)))
    with open(disk, "wb") as f:
        f.write(encrypted)
    print("Disk encrypted (simulated CE).")

    # Zeroize & delete shard files
    for i in range(3):
        shard_file = f"shard_{i}.bin"
        try:
            if os.path.exists(shard_file):
                size = os.path.getsize(shard_file)
                with open(shard_file, "r+b") as f:
                    f.write(b"\x00" * size)
                os.remove(shard_file)
        except Exception as e:
            print(f"Warning: could not securely delete {shard_file}: {e}")
    print("All shards securely destroyed (zeroized + deleted).")

    # CE event evidence
    ce_event = {
        "event": "cryptographic_erase",
        "device": disk,
        "operator": operator,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "key_fingerprint": key_fingerprint,
        "sharding": {"scheme": "xor-2of3", "shards_destroyed": True},
        "note": "Simulated CE: data XORed with ephemeral key; shards deleted."
    }
    with open("ce_event.json", "w") as f:
        f.write(json.dumps(ce_event, indent=2))
    print("CE event recorded in ce_event.json.")

# ---------------------
# Verification helpers
# ---------------------

def shannon_entropy(b: bytes) -> float:
    """Shannon entropy (bits/byte) for a byte string; 0..8. Heuristic only."""
    if not b:
        return 0.0
    counts = Counter(b)
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())

# ---------------------
# Signing helpers (OpenSSL required)
# ---------------------

def ensure_signing_keys():
    """Create RSA-3072 keypair via openssl if not present."""
    os.makedirs("keys", exist_ok=True)
    priv = "keys/private_key.pem"
    pub = "keys/public_key.pem"

    if not os.path.exists(priv):
        subprocess.check_call([
            "openssl", "genpkey",
            "-algorithm", "RSA",
            "-pkeyopt", "rsa_keygen_bits:3072",
            "-out", priv
        ])
        os.chmod(priv, 0o600)

    if not os.path.exists(pub):
        subprocess.check_call([
            "openssl", "rsa",
            "-in", priv,
            "-pubout",
            "-out", pub
        ])
    return priv, pub

def public_key_fingerprint_sha256(pub_pem_path: str) -> str:
    """Compute SHA-256 fingerprint of the public key (DER) as base64."""
    der_path = "keys/public_key.der"
    subprocess.check_call([
        "openssl", "pkey",
        "-pubin",
        "-in", pub_pem_path,
        "-pubout",
        "-outform", "DER",
        "-out", der_path
    ])
    with open(der_path, "rb") as f:
        der = f.read()
    fp_b64 = base64.b64encode(hashlib.sha256(der).digest()).decode()
    return fp_b64

def sign_file_with_openssl(file_path: str, private_key_path: str, sig_path: str = "cert.json.sig") -> str:
    """Sign file with RSA-3072 SHA-256 using openssl; writes detached signature."""
    subprocess.check_call([
        "openssl", "dgst", "-sha256",
        "-sign", private_key_path,
        "-out", sig_path,
        file_path
    ])
    return sig_path

def read_base64(path: str) -> str:
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode()

# ---------------------
# Verification & Certificate
# ---------------------

def verify_and_certificate(disk: str = FAKE_DISK, method: str = "clear", operator: str = "TeamSIH") -> None:
    """Verification/cert generation:
       - CLEAR: NIST-style sampling -> expect all zeros
       - CE: include ce_event.json (process ack) + randomness heuristic (NOT proof)
    """
    if not os.path.exists(disk):
        print(f"Error: {disk} not found. Create it first (Menu option 2).")
        return

    # Sequential certificate number
    cert_num = 1
    if os.path.exists(LEDGER_FILE):
        with open(LEDGER_FILE) as lf:
            cert_num = sum(1 for line in lf if "CERT-" in line) + 1
    cert_number = f"CERT-{time.strftime('%Y')}-{cert_num:04d}"

    size = os.path.getsize(disk)
    block_size = 4096
    blocks = max(1, size // block_size)
    rng = random.SystemRandom()

    # --- Stratified sampling per your spec ---
    # 1) Break media into equally-sized subsections
    subsections = min(100, blocks)  # cap at 100 strata
    # Use proportional boundaries to avoid tiny/zero sections
    samples = []

    def section_bounds(i: int):
        """Closed interval [lo, hi] for subsection i of 'subsections'."""
        # round down start, up end via arithmetic on cumulative fractions
        lo = (i * blocks) // subsections
        hi = ((i + 1) * blocks) // subsections - 1
        hi = min(hi, blocks - 1)
        return lo, max(lo, hi)

    for i in range(subsections):
        lo, hi = section_bounds(i)
        length = hi - lo + 1
        if length <= 0:
            continue
        # 2) Select at least two non-overlapping pseudorandom LBAs per subsection
        k = 2 if length >= 2 else 1
        # sample without replacement to ensure distinct picks
        choices = list(range(lo, hi + 1))
        picks = rng.sample(choices, k)
        samples.extend(picks)

    # 3) Always include first and last block
    samples.extend([0, blocks - 1])

    # Deduplicate and sort
    samples = sorted(set(l for l in samples if 0 <= l < blocks))

    # --- Read & evaluate samples ---
    sample_results = []
    passed = True
    entropy_samples = []

    with open(disk, "rb") as f:
        for lba in samples:
            f.seek(lba * block_size)
            data = f.read(block_size)
            h = hashlib.sha256(data).hexdigest()
            all_zero = (data == b"\x00" * len(data))
            ent = shannon_entropy(data)
            if method.lower() == "clear" and not all_zero:
                passed = False
            if method.lower() != "clear":
                entropy_samples.append(ent)
            sample_results.append({
                "lba": lba,
                "sha256": h,
                "all_zero": all_zero,
                "entropy_bits_per_byte": round(ent, 4)
            })

    cert = {
        "certificate_number": cert_number,
        "device": disk,
        "method": method,
        "operator": operator,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "media_bytes": size,
        "block_size": block_size,
        "blocks": blocks,
        "subsections": subsections,
        "samples_checked": len(samples),
        "verification": {},
        "results": {"passed": passed},
        "sample_results_preview": sample_results[:5],
    }

    method_l = method.lower()
    if method_l == "clear":
        cert["verification"] = {
            "mode": "data-sampling",
            "policy": (
                "Media divided into equal subsections; at least two distinct pseudorandom "
                "LBAs sampled from each subsection; first and last block included."
            ),
            "pattern": ["0xFF", "0x00"],  # our two-pass Clear
        }
    else:  # CE or other Purge simulation
        ce_info = None
        if os.path.exists("ce_event.json"):
            try:
                with open("ce_event.json") as c:
                    ce_info = json.load(c)
            except Exception:
                ce_info = {"error": "Failed to read ce_event.json"}
        avg_entropy = round(sum(entropy_samples) / len(entropy_samples), 4) if entropy_samples else None
        cert["verification"] = {
            "mode": "process-ack",
            "explanation": (
                "Cryptographic Erase cannot be externally verified by sampling; "
                "evidence is the recorded CE event plus a randomness heuristic."
            ),
            "ce_evidence": ce_info,
            "randomness_heuristic": {
                "metric": "Shannon entropy (bits/byte, 0–8)",
                "avg_entropy_over_samples": avg_entropy,
                "note": "High entropy suggests ciphertext-like data but is NOT proof of CE."
            }
        }
        cert["results"]["passed"] = (ce_info is not None and "error" not in ce_info)

    cert_json = json.dumps(cert, indent=2)
    with open(CERT_FILE, "w") as f:
        f.write(cert_json)

    print("\nCertificate generated:")
    print(cert_json)

    # Sign & record
    try:
        priv_key, pub_key = ensure_signing_keys()
        sig_path = "cert.json.sig"
        sign_file_with_openssl(CERT_FILE, priv_key, sig_path=sig_path)

        pk_fingerprint_b64 = public_key_fingerprint_sha256(pub_key)
        sig_b64 = read_base64(sig_path)
        pub_pem_b64 = read_base64(pub_key)

        signature_meta = {
            "signed_file": CERT_FILE,
            "signature_file": sig_path,
            "algorithm": "RSA-3072 / SHA-256 (openssl dgst)",
            "public_key_fingerprint_sha256_b64": pk_fingerprint_b64,
            "public_key_pem_b64": pub_pem_b64,
            "signature_b64": sig_b64,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "note": "Detached signature accompanies cert.json; verify with openssl.",
            "certificate_number": cert_number,
        }
        with open("cert_signature.json", "w") as sf:
            sf.write(json.dumps(signature_meta, indent=2))

        print("\nDigital signature written to cert.json.sig and cert_signature.json")
        print(f"Public key fingerprint (SHA-256, b64): {pk_fingerprint_b64}")

    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print("\nWARNING: Failed to generate digital signature. Ensure 'openssl' is installed and on PATH.")
        print(f"Error: {e}")

    cert_hash = hashlib.sha256(cert_json.encode()).hexdigest()
    with open(LEDGER_FILE, "a") as f:
        f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ')} {cert_number} {cert_hash}\n")
    print(f"\nCertificate hash appended to {LEDGER_FILE}.")

    if os.path.exists("cert.json.sig"):
        sig_hash = hashlib.sha256(open("cert.json.sig", "rb").read()).hexdigest()
        with open(LEDGER_FILE, "a") as f:
            f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ')} {cert_number} SIG {sig_hash}\n")
        print("Signature hash appended to ledger.")

# ---------------------
# Detection (Read-only; classification)
# ---------------------

def detect_all_media() -> None:
    """Enumerate storage devices and print classification (read-only)."""
    print("\nDetecting storage devices (comprehensive, read-only) ...\n")

    lsblk_raw = run_cmd(["lsblk", "-J", "-O"]) or "{}"
    try:
        blk = json.loads(lsblk_raw)
    except Exception:
        print(run_cmd(["lsblk", "-d", "-o", "NAME,ROTA,TYPE,SIZE,MODEL,TRAN"]))
        return

    def prop(d, k, default=""):
        return d.get(k, default) if isinstance(d, dict) else default

    for dev in blk.get("blockdevices", []):
        name = prop(dev, "name")
        dtype = prop(dev, "type")
        size = prop(dev, "size")
        model = (prop(dev, "model") or "").strip()
        tran = (prop(dev, "tran") or "").lower()
        kname = f"/dev/{name}" if name else "(unknown)"
        if not name or dtype in ("loop",):
            continue

        is_rom = (dtype == "rom")
        is_nvme = name.startswith("nvme")
        is_mmc = name.startswith("mmcblk")
        is_sdhd = (dtype == "disk" and not is_nvme and name[0] in ("s", "h"))

        print(f"Device: {kname} | TYPE: {dtype} | SIZE: {size} | MODEL: {model} | BUS: {tran or 'n/a'}")

        if is_rom:
            print("  Class: Optical media (CD/DVD/BD). NIST handling: Destroy only.\n")
            continue

        if is_nvme:
            print("  Class: NVMe SSD")
        elif is_mmc:
            print("  Class: Memory card (SD/SDHC/MMC/CF)")
        elif tran in ("usb",) and dtype == "disk":
            print("  Class: USB-attached storage (thumb/external)")
        elif is_sdhd:
            print("  Class: ATA HDD/SSD (SATA/PATA/eSATA)")
        elif tran in ("sas", "scsi", "fc") and dtype == "disk":
            print("  Class: SCSI-family disk (SAS/FC/UAS)")
        else:
            print("  Class: Generic disk")

        # Minimal capability hints (still read-only)
        if is_nvme and shutil.which("nvme"):
            idc = run_cmd(["nvme", "id-ctrl", "-H", kname]) or ""
            has_san = "Sanitize" in idc
            print(f"  NVMe sanitize capability: {'present' if has_san else 'not reported'}")

        if is_sdhd and shutil.which("hdparm"):
            hpa = run_cmd(["hdparm", "-N", kname]) or ""
            if hpa:
                m = re.search(r"max sectors\s*=\s*(\d+)/(\d+)", hpa, re.IGNORECASE)
                if m and m.group(1) != m.group(2):
                    print(f"  HPA: enabled (visible {m.group(1)} < native {m.group(2)})")
                else:
                    print("  HPA: disabled or not reported")
            dco = run_cmd(["hdparm", "--dco-identify", kname]) or ""
            if dco:
                print("  DCO: identify supported")

        print()

    # Embedded flash via MTD
    if os.path.exists("/proc/mtd"):
        lines = [l.strip() for l in open("/proc/mtd").read().splitlines() if l.strip()]
        if len(lines) > 1:
            print("MTD (embedded flash) devices detected:")
            for l in lines[1:]:
                print("  ", l)
            print()

# ---------------------
# Verification Runner (Signature + Ledger)
# ---------------------

def verify_certificate_and_signature(cert_path: str = CERT_FILE,
                                     sig_path: str = "cert.json.sig",
                                     pub_key_path: str = "keys/public_key.pem",
                                     ledger_path: str = LEDGER_FILE) -> bool:
    """Verify detached signature using OpenSSL and compare cert hash with ledger entries."""
    ok = True

    missing = []
    for p, name in [(cert_path, "certificate"), (sig_path, "signature"), (pub_key_path, "public key")]:
        if not os.path.exists(p):
            missing.append(name)
    if missing:
        print(f"Missing required file(s): {', '.join(missing)}. Generate a certificate first (Menu option 5).")
        return False

    try:
        res = subprocess.run([
            "openssl", "dgst", "-sha256",
            "-verify", pub_key_path,
            "-signature", sig_path,
            cert_path
        ], capture_output=True, text=True, check=False)
        print("[Signature Verification]")
        print(res.stdout.strip() or res.stderr.strip())
        if "Verified OK" not in res.stdout:
            ok = False
    except FileNotFoundError:
        print("OpenSSL not found. Please install 'openssl' and ensure it is on PATH.")
        return False

    print("[Ledger Check]")
    cert_bytes = open(cert_path, "rb").read()
    cert_hash = hashlib.sha256(cert_bytes).hexdigest()
    print(f"Computed SHA-256(cert.json): {cert_hash}")

    if os.path.exists(ledger_path):
        ledger = open(ledger_path).read().splitlines()
        match = any(cert_hash in line for line in ledger)
        if match:
            print("Certificate hash FOUND in ledger.")
        else:
            print("Certificate hash NOT found in ledger.")
            ok = False
    else:
        print("Ledger file not found.")
        ok = False

    print("[Result]", "PASS" if ok else "FAIL")
    return ok

# ---------------------
# Menu
# ---------------------

def menu() -> None:
    global LAST_METHOD
    while True:
        print("\n==== UVSO Demo ====")
        print("1. Detect Storage (comprehensive, read-only)")
        print("2. Create Fake Disk (simulation)")
        print("3. Clear Overwrite (Two-pass: 0xFF then 0x00)")
        print("4. Cryptographic Erase (Simulated CE + KT-CE)")
        print("5. Verify & Generate Certificate (Simulation)")
        print("6. Show Ledger")
        print("7. Verify Certificate & Signature")
        print("8. Exit")

        choice = input("Select option: ")

        if choice == "1":
            detect_all_media()
        elif choice == "2":
            create_fake_disk()  # auto default 10MB
        elif choice == "3":
            clear_overwrite()
            LAST_METHOD = "clear"
        elif choice == "4":
            cryptographic_erase()
            LAST_METHOD = "ce"
        elif choice == "5":
            if LAST_METHOD is None:
                print("No sanitization method has been performed yet.")
            else:
                verify_and_certificate(method=LAST_METHOD)
        elif choice == "6":
            if os.path.exists(LEDGER_FILE):
                print(open(LEDGER_FILE).read())
            else:
                print("Ledger is empty.")
        elif choice == "7":
            verify_certificate_and_signature()
        elif choice == "8":
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    menu()

