# TPM 2.0 Secret Delivery via Salted Session — PoC (TSS.CPP / TSS.MSR)

Proof-of-concept demonstrating **salted HMAC session + response parameter encryption** on
TPM 2.0: the session's symmetric key (`channelKey`) never appears in plaintext on the VTL0
transport, so a passive observer on VTL0 cannot decrypt the TPM response even if it captures
every byte on the wire.

**Core mechanism:** VBS OAEP-encrypts a random salt to the EK public key and passes only
`encryptedSalt` to the TPM via VTL0. The TPM decrypts the salt with EK private (which never
leaves the chip), both sides independently derive `channelKey`, and the TPM encrypts the
`RSA_Decrypt` response with `channelKey` before the bytes cross VTL0. VTL0 sees only
`encryptedSalt` and AES-128-CFB ciphertext — it has no path to `channelKey` and therefore
cannot recover `SECRET`.

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

What VTL0 sees on the wire (step 5):

| Mode | VTL0 sees | Can recover SECRET? |
|------|-----------|---------------------|
| OFF  | `SECRET` plaintext in TPM response | YES — leaked |
| ON   | AES-128-CFB ciphertext; `channelKey` never crossed VTL0 in plaintext | NO — protected |

The protection comes from `channelKey` being invisible to VTL0, not merely from the response
being encrypted — without the key, the ciphertext is unrecoverable.

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

## Do you have a real TPM?

First, check whether your machine has a hardware TPM 2.0 chip:

```powershell
Get-Tpm
```

| Result | What to use |
|--------|-------------|
| `TpmPresent: True`, `TpmReady: True` | Run with `--real-tpm` (no simulator needed) |
| `TpmPresent: False` or TPM disabled in BIOS | Run with simulator (default mode) |

Both modes produce the same PoC result. The difference is:
- **Simulator** — software replica of the TPM chip, runs on TCP 2321/2322. Lets you see raw command/response bytes on the wire (full wire tap).
- **`--real-tpm`** — uses the actual TPM chip via Windows TBS. No wire tap (chip communicates over physical SPI/LPC bus), but proves the mechanism works on real hardware.

---

## Quick start

### Step 1 — check if you have a real TPM

```powershell
Get-Tpm
```

- `TpmPresent: True` + `TpmReady: True` → go to **Path A** (real TPM, no simulator needed)
- Otherwise → go to **Path B** (simulator)

---

## Path A — Real hardware TPM

### Build

You need TSS.CPP (the TPM API library) and this PoC. No simulator required.

**1. Clone and build TSS.CPP:**

```bat
git clone https://github.com/microsoft/TSS.MSR.git
```

Open `TSS.MSR\TSS.CPP\TSS.CPP.sln` in Visual Studio 2019/2022, select **Release / x64**,
build the `TSS.CPP` project. Output: `TSS.MSR\TSS.CPP\bin\x64\Release\TSS.CPP.lib` + `TSS.CPP.dll`.

**2. Clone and build this PoC:**

```bat
git clone https://github.com/tuananh-jos/tpm-vbs-poc.git
cd tpm-vbs-poc
build.bat C:\path\to\TSS.MSR\TSS.CPP
```

### Run

Run as Administrator:

```bat
vbs_poc.exe --real-tpm
```

Expected output:

```
Connected to REAL TPM via Windows TBS. (No VTL0 wire tap available.)

[A.1] TPM2_CreatePrimary: creating wrapKey (RSA-2048 decrypt) in OWNER hierarchy...
       -> handle 0x80xxxxxx  tpm-pub = 258-byte RSA modulus
       -> tpm-priv NEVER leaves the chip.
[A.2] TPM2_CreatePrimary: creating EK (RSA-2048 restricted decrypt) in ENDORSEMENT hierarchy...
       -> handle 0x80xxxxxx  (used only as salt key for salted session)

[B]   Server: SECRET = "VBS-TOP-SECRET-2026!!" (21 bytes)
      Server: RSA-OAEP encrypting SECRET to tpm-pub...
      Server: C = tpm-pub(SECRET) = 256 bytes ciphertext  -> handed to VBS.

================  Delivery: RESPONSE ENCRYPTION OFF  ================
  Wire tap: N/A (real TPM uses physical SPI/LPC bus -- needs logic analyzer).
  Expected: OFF leaks plaintext on bus; ON protects with AES-128-CFB.
  VBS recovered SECRET                  : "VBS-TOP-SECRET-2026!!"
  recovered == original SECRET?         : yes

================  Delivery: RESPONSE ENCRYPTION ON   ================
  Wire tap: N/A (real TPM uses physical SPI/LPC bus -- needs logic analyzer).
  Expected: OFF leaks plaintext on bus; ON protects with AES-128-CFB.
  VBS recovered SECRET                  : "VBS-TOP-SECRET-2026!!"
  recovered == original SECRET?         : yes

[Cleanup] TPM2_FlushContext: releasing wrapKey and EK handles.
```

> Handles (`0x80xxxxxx`) are assigned dynamically by the real TPM and vary between runs.
> Wire tap is unavailable on real hardware — to observe OFF vs ON on the physical bus you
> need a logic analyzer on the SPI/LPC pins.

---

## Path B — Simulator (no real TPM)

The simulator is a software replica of the TPM chip that listens on TCP 2321/2322.
Use this if your machine has no TPM or TPM is disabled. You get a full wire tap as a bonus.

### Build

Same steps as Path A, plus build the simulator:

**1 + 2.** Follow Path A build steps above.

**3. Clone and build the simulator:**

```bat
git clone https://github.com/microsoft/ms-tpm-20-ref.git
cd ms-tpm-20-ref\TPMCmd
cmake -B build -A x64
cmake --build build --config Release
```

Output: `ms-tpm-20-ref\TPMCmd\build\Simulator\Release\Simulator.exe`.

> Requires OpenSSL. Install via `winget install ShiningLight.OpenSSL` if the CMake configure
> step complains about missing OpenSSL headers/libs.

> **Which simulator?** TSS.CPP speaks the Microsoft simulator TCP protocol (ports 2321/2322).
> This is **not** compatible with `swtpm` — use `ms-tpm-20-ref` only.

### Run

**Step 1** — start the simulator in a separate window:

```bat
Simulator.exe
```

Leave it running (listens on ports 2321 and 2322).

**Step 2** — run the PoC:

```bat
vbs_poc.exe
```

> **Rerunning:** if the PoC crashes, restart the simulator before running again — it may still
> hold loaded key handles. Symptom: `TPM_RC::OBJECT_MEMORY`.

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
