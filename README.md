# TPM 2.0 VBS-style Secret Delivery — PoC (TSS.CPP / TSS.MSR)

Proof-of-concept demonstrating how Windows Virtualization-Based Security (VBS) can receive a
`SECRET` from a remote Server across an **untrusted transport (VTL0)** — the layer between the
guest OS and the TPM — without the plaintext ever appearing on the wire.

The mechanism is transport-layer parameter encryption using a **salted HMAC session**: VBS and
the TPM jointly derive an ephemeral symmetric key (`channelKey`) that VTL0 cannot compute, then
the TPM encrypts the `RSA_Decrypt` response with that key before the bytes cross VTL0.

---

## Terminology

| Name | Role |
|------|------|
| `SECRET` | Payload to be delivered confidentially. |
| `wrapKey` / `tpm-pub` / `tpm-priv` | RSA-2048 decrypt key created **inside** the TPM. Server encrypts `SECRET` to `tpm-pub`; only `tpm-priv` (never leaves the chip) can open it. |
| `EK` | Endorsement Key — RSA-2048 restricted decrypt key. Used **only** to bootstrap the encrypted channel (salted session salt key). Different role from `wrapKey`. |
| `channelKey` | Ephemeral AES-128 key that VBS and the TPM both derive from the salted session. Protects the response parameter on the wire. VTL0 cannot see it. |

---

## Flow

```
A. Prepare
   1. TPM creates wrapKey (RSA-2048 decrypt). Exports tpm-pub.
   2. TPM creates EK (RSA-2048 restricted decrypt). Exports EK pub.

B. Server encrypts
   3. Server: C = RSA-OAEP(tpm-pub, SECRET)  →  hands C to VBS.

C. VBS establishes encrypted channel
   4. VBS picks a random salt, OAEP-encrypts it to EK pub (→ encryptedSalt).
      VBS calls TPM2_StartAuthSession(tpmKey=EK, encryptedSalt, AES-128-CFB).
      TPM decrypts salt with EK priv, both sides derive channelKey.
      VBS sets TPMA_SESSION::encrypt on the session → response parameters will be
      AES-128-CFB encrypted with channelKey before leaving the chip.

D. VBS recovers SECRET
   5. VBS calls TPM2_RSA_Decrypt(wrapKey, C) OVER the session.
      Inside TPM: tpm-priv opens C → SECRET; TPM encrypts the response parameter
      with channelKey → crosses VTL0 as ciphertext.
      TSS.CPP transparently decrypts with channelKey → VBS sees SECRET.
```

What VTL0 (step 5 wire):

| Encryption | What VTL0 sees |
|-----------|----------------|
| OFF | `SECRET` plaintext bytes inside the TPM response |
| ON  | AES-128-CFB ciphertext — `SECRET` not recoverable without `channelKey` |

---

## Expected output

```
Connected to TPM simulator. Transport VTL0 tap is active.

[A] wrapKey (tpm-pub) and EK (salt key) created inside the TPM.
[B] Server: SECRET = "VBS-TOP-SECRET-2026!!"
    Server: C = tpm-pub(SECRET) = 256 bytes of RSA-OAEP ciphertext, handed to VBS.

================  Delivery: RESPONSE ENCRYPTION OFF  ================
  channel: salted HMAC session, tpmKey = EK, 20-byte salt, AES-128-CFB
  RSA_Decrypt RESPONSE on VTL0 wire (82 bytes):
    800200000052000000000000001700155642532d544f502d5345435245542d323032362121...
  SECRET plaintext visible on the wire? : YES   <-- LEAKED to VTL0
  VBS recovered SECRET                  : "VBS-TOP-SECRET-2026!!"
  recovered == original SECRET?         : yes

================  Delivery: RESPONSE ENCRYPTION ON   ================
  channel: salted HMAC session, tpmKey = EK, 20-byte salt, AES-128-CFB
  RSA_Decrypt RESPONSE on VTL0 wire (82 bytes):
    8002000000520000000000000017001532214caed12c0fec0f255174b60cc539e7e18561...
  SECRET plaintext visible on the wire? : no    <-- protected from VTL0
  VBS recovered SECRET                  : "VBS-TOP-SECRET-2026!!"
  recovered == original SECRET?         : yes

Done. With response encryption ON, VTL0 saw only ciphertext, yet VBS
recovered the SECRET -- plaintext never crossed the transport in the clear.
```

In the OFF run you can verify by eye: `5642532d544f502d5345435245542d323032362121` in the hex
dump is ASCII for `VBS-TOP-SECRET-2026!!`. In the ON run that sequence is absent.

---

## Prerequisites

- **Windows** with Visual Studio 2022 (Community is fine) — the `cl.exe` toolchain.
- **Microsoft TSS.MSR** (TSS.CPP) — already cloned and built in `../tpm-work/TSS.MSR`.
- **Microsoft TPM 2.0 simulator** (`ms-tpm-20-ref`) — already built in
  `../tpm-work/sim-build2/Simulator/Simulator.exe`.

> **Which simulator?** TSS.CPP's `TpmTcpDevice` speaks the Microsoft simulator TCP protocol
> (command port **2321**, platform port **2322**). This is **not** compatible with `swtpm`.
> Use `ms-tpm-20-ref` or the legacy `Simulator.exe`.

---

## Building from source

### 1. Get and build TSS.CPP

TSS.CPP is the C++ library that provides the TPM API (`tpm.CreatePrimary()`,
`tpm.StartAuthSession()`, `tpm.RSA_Decrypt()`, …). Without it you would have to hand-craft
binary TPM command packets. Building it produces `TSS.CPP.lib` (linked into the exe) and
`TSS.CPP.dll` (needed at runtime).

```bat
git clone https://github.com/microsoft/TSS.MSR.git
```

Open `TSS.MSR\TSS.CPP\TSS.CPP.sln` in Visual Studio 2019 or 2022, select
**Release / x64**, and build the `TSS.CPP` project.

Output: `TSS.MSR\TSS.CPP\bin\x64\Release\TSS.CPP.lib` and `TSS.CPP.dll`.

### 2. Get and build the TPM simulator

The TPM is normally a chip soldered onto the motherboard. The simulator is a software replica
that listens on TCP 2321/2322 and behaves exactly like real hardware — so the PoC works
without a physical TPM chip.

```bat
git clone https://github.com/microsoft/ms-tpm-20-ref.git
cd ms-tpm-20-ref\TPMCmd
cmake -B build -A x64
cmake --build build --config Release
```

Output: `ms-tpm-20-ref\TPMCmd\build\Simulator\Release\Simulator.exe`.

> **Note:** building the simulator requires OpenSSL. The easiest way on Windows is to install
> it via `winget install ShiningLight.OpenSSL` or use a pre-built binary from
> https://slproweb.com/products/Win32OpenSSL.html, then add its `lib` and `include` to the
> CMake prefix path if the configure step complains.

### 3. Build this PoC

```bat
git clone https://github.com/tuananh-jos/tpm-vbs-poc.git
cd tpm-vbs-poc
build.bat C:\path\to\TSS.MSR\TSS.CPP
```

`build.bat` auto-detects Visual Studio, compiles `vbs_poc.cpp`, and copies `TSS.CPP.dll`
next to the executable (the DLL must be in the same directory at runtime).

---

## Running

### Mode 1 — Simulator (default, full wire tap)

**Step 1** — start the simulator in a separate window (or minimized):

```bat
"C:\Users\Tai Khoan\Documents\tpm-work\sim-build2\Simulator\Simulator.exe"
```

Leave it running. It listens on TCP ports 2321 and 2322.

**Step 2** — run the PoC:

```bat
vbs_poc.exe
```

> **Rerunning:** if the PoC exits abnormally, the simulator may still hold loaded key handles.
> Restart the simulator before running again (the normal exit path flushes all handles, but a
> crash skips that). The error `TPM_RC::OBJECT_MEMORY` is the symptom.

### Mode 2 — Real hardware TPM (no wire tap)

No simulator needed. Run as Administrator:

```bat
vbs_poc.exe --real-tpm
```

Expected output:

```
Connected to REAL TPM via Windows TBS. (No VTL0 wire tap available.)

[A.1] TPM2_CreatePrimary: creating wrapKey (RSA-2048 decrypt) in OWNER hierarchy...
       -> handle 0x80000000  tpm-pub = 256-byte RSA modulus
       -> tpm-priv NEVER leaves the chip.
[A.2] TPM2_CreatePrimary: creating EK (RSA-2048 restricted decrypt) in ENDORSEMENT hierarchy...
       -> handle 0x80000001  (used only as salt key for salted session)

[B]   Server: SECRET = "VBS-TOP-SECRET-2026!!" (21 bytes)
      Server: RSA-OAEP encrypting SECRET to tpm-pub...
      Server: C = tpm-pub(SECRET) = 256 bytes ciphertext  -> handed to VBS.

================  Delivery: RESPONSE ENCRYPTION OFF  ================
  channel: salted HMAC session, tpmKey = EK, 20-byte salt, AES-128-CFB
  Wire tap: N/A (real TPM uses physical SPI/LPC bus -- needs logic analyzer).
  Expected: OFF leaks plaintext on bus; ON protects with AES-128-CFB.
  VBS recovered SECRET                  : "VBS-TOP-SECRET-2026!!"
  recovered == original SECRET?         : yes

================  Delivery: RESPONSE ENCRYPTION ON   ================
  channel: salted HMAC session, tpmKey = EK, 20-byte salt, AES-128-CFB
  Wire tap: N/A (real TPM uses physical SPI/LPC bus -- needs logic analyzer).
  Expected: OFF leaks plaintext on bus; ON protects with AES-128-CFB.
  VBS recovered SECRET                  : "VBS-TOP-SECRET-2026!!"
  recovered == original SECRET?         : yes

[Cleanup] TPM2_FlushContext: releasing wrapKey and EK handles.
```

The wire tap is unavailable because the real TPM communicates over a physical SPI or LPC bus.
To observe the OFF vs ON difference on real hardware you would need a logic analyzer attached
to that bus. Functionally, both modes decrypt correctly and the step-by-step log confirms each
TPM command issued.

---

## Security notes

### What this PoC demonstrates
Response parameter encryption via a salted HMAC session prevents a **passive** observer on VTL0
from reading `SECRET`. The raw wire bytes in the ON run are indistinguishable from random.

### What this PoC does NOT defend against
**Active MITM at session setup.** If VTL0 swaps the EK public key during `StartAuthSession`, it
can choose its own salt, know `channelKey`, and decrypt everything. The `TODO(SECURITY)` in
`vbs_poc.cpp` marks the fix: read the EK certificate from TPM NV and verify its chain to a
trusted TPM-vendor root CA **before** using the EK public area as the session salt key.
See TCG *CPU to TPM Bus Protection Guidance — Passive Attack Mitigations* (2023), §4–5.

### SHA-1 note
This version of TSS.CPP (TSS.MSR) ignores the `hashAlg` argument in its internal `RsaEncrypt`
and always performs OAEP with **SHA-1** (OpenSSL `RSA_PKCS1_OAEP_PADDING` default). Key
templates therefore use SHA-1 to match. This is a library limitation, not a fundamental
constraint of the protocol; a real deployment would use SHA-256 throughout.

### Other omissions (intentional for a PoC)
- Auth values on keys are empty.
- No PCR policy binding.
- `wrapKey` and EK are primary keys created fresh each run rather than provisioned NV keys.
- EK is created in the ENDORSEMENT hierarchy but its certificate is not validated.

---

## References

- TCG, *CPU to TPM Bus Protection Guidance — Passive Attack Mitigations* (2023), §4–5.
- TPM 2.0 Library, Part 1: Architecture — *Session-based encryption* / salted sessions.
- Microsoft TSS.MSR — <https://github.com/microsoft/TSS.MSR>
  (`TSS.CPP/Samples/Samples.cpp`: `SeededSession`, `SessionEncryption`, `RsaEncryptDecrypt`)
- Microsoft reference TPM simulator — <https://github.com/microsoft/ms-tpm-20-ref>
