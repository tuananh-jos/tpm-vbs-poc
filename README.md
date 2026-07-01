# TPM 2.0 Secret Delivery via Salted Session — PoC (TSS.CPP / TSS.MSR)

Proof-of-concept demonstrating **salted HMAC session + response parameter encryption** on
TPM 2.0: the session's symmetric key (`channelKey`) never appears in plaintext on the
transport, so a passive observer cannot decrypt the TPM response even if it captures every
byte on the wire.

**Core mechanism:** The client OAEP-encrypts a random salt to the EK public key and passes
only `encryptedSalt` to the TPM. The TPM decrypts the salt with EK private (which never
leaves the chip), both sides independently derive `channelKey`, and the TPM encrypts the
`RSA_Decrypt` response with `channelKey` before the bytes leave the chip. The transport sees
only `encryptedSalt` and AES-128-CFB ciphertext — it has no path to `channelKey`.

---

## Terminology

| Name | Role |
|------|------|
| `SECRET` | Payload to be delivered confidentially. |
| `wrapKey` / `tpm-pub` / `tpm-priv` | RSA-2048 decrypt key created **inside** the TPM. External encrypts `SECRET` to `tpm-pub`; only `tpm-priv` (never leaves the chip) can open it. |
| `EK` | Endorsement Key — RSA-2048 restricted decrypt key. Used **only** to bootstrap the salted session (salt key). |
| `channelKey` | Ephemeral AES-128 key derived from the salted session. Protects the response parameter on the wire. The transport cannot see it. |

---

## Flow

```
A. Prepare
   1. TPM creates wrapKey (RSA-2048 decrypt). Exports tpm-pub.
   2. TPM creates EK (RSA-2048 restricted decrypt). Exports EK pub.

B. External encrypts
   3. External: C = RSA-OAEP(tpm-pub, SECRET)  ->  hands C to client.

C. Client establishes encrypted channel
   4. Client picks a random salt, OAEP-encrypts it to EK pub (-> encryptedSalt).
      Calls TPM2_StartAuthSession(tpmKey=EK, encryptedSalt, AES-128-CFB).
      TPM decrypts salt with EK priv; both sides derive channelKey independently.
      Client sets TPMA_SESSION::encrypt -> response parameters encrypted before leaving chip.

D. Client recovers SECRET
   5. Client calls TPM2_RSA_Decrypt(wrapKey, C) over the session.
      Inside TPM: tpm-priv opens C -> SECRET; response encrypted with channelKey.
      TSS.CPP decrypts response with channelKey -> client sees SECRET.
```

| Mode | Transport sees | Can recover SECRET? |
|------|----------------|---------------------|
| OFF  | SECRET plaintext in response | YES — leaked |
| ON   | AES-128-CFB ciphertext; channelKey never crossed the transport | NO — protected |

---

## Prerequisites

- Windows with Visual Studio 2019 or 2022 (`cl.exe` toolchain)
- Hardware TPM 2.0 chip (check: `Get-Tpm` → `TpmPresent: True`, `TpmReady: True`)
- Microsoft TSS.MSR (TSS.CPP) — cloned and built

---

## Build

**1. Clone and build TSS.CPP:**

```bat
git clone https://github.com/microsoft/TSS.MSR.git
```

Open `TSS.MSR\TSS.CPP\TSS.CPP.sln` in Visual Studio, select **Release / x64**, build the
`TSS.CPP` project. Output: `bin\x64\Release\TSS.CPP.lib` + `TSS.CPP.dll`.

**2. Clone and build this PoC:**

```bat
git clone https://github.com/tuananh-jos/tpm-vbs-poc.git
cd tpm-vbs-poc
build.bat C:\path\to\TSS.MSR\TSS.CPP
```

---

## Run

Run as Administrator:

```bat
tpm_poc.exe
```

Expected output:

```
Connected to real TPM via Windows TBS.

[A.1] CreatePrimary: wrapKey (RSA-2048, OWNER)...
       handle 0x80xxxxxx  (tpm-priv never leaves chip)
[A.2] CreatePrimary: EK (RSA-2048, ENDORSEMENT)...
       handle 0x80xxxxxx

[B] External: SECRET="TOP-SECRET-2026!!"
    C = RSA-OAEP(tpm-pub, SECRET) = 256 bytes

================  Delivery: RESPONSE ENCRYPTION OFF  ================
  channel : salted HMAC, tpmKey=EK, 20-byte salt, AES-128-CFB
  wire    : N/A (SPI/LPC bus -- needs logic analyzer to observe OFF vs ON)
  SECRET  : "TOP-SECRET-2026!!"
  correct : yes

================  Delivery: RESPONSE ENCRYPTION ON   ================
  channel : salted HMAC, tpmKey=EK, 20-byte salt, AES-128-CFB
  wire    : N/A (SPI/LPC bus -- needs logic analyzer to observe OFF vs ON)
  SECRET  : "TOP-SECRET-2026!!"
  correct : yes

Done.
```

> Handles (`0x80xxxxxx`) are assigned dynamically by the TPM and vary between runs.

---

## Security notes

### What this PoC demonstrates
`channelKey` never appears in plaintext on the transport — the transport sees only
`encryptedSalt` (which it cannot decrypt without EK private) and AES-128-CFB ciphertext.

### What this PoC does NOT defend against
**Active MITM at session setup.** If the transport swaps the EK public key during
`StartAuthSession`, it can choose its own salt, derive `channelKey`, and decrypt everything.
Fix: read the EK certificate from TPM NV and verify its chain to a trusted TPM-vendor root CA
before using EK pub as the session salt key.
See TCG *CPU to TPM Bus Protection Guidance — Passive Attack Mitigations* (2023), §4–5.

### SHA-1 note
TSS.CPP (TSS.MSR) ignores the `hashAlg` argument in its internal `RsaEncrypt` and always
uses SHA-1 OAEP. Key templates use SHA-1 to match. This is a library limitation — a real
deployment would use SHA-256 throughout.

### Intentional omissions
- Auth values on keys are empty.
- No PCR policy binding.
- Keys are primary keys created fresh each run, not provisioned NV keys.
- EK certificate is not validated.

---

## References

- TCG, *CPU to TPM Bus Protection Guidance — Passive Attack Mitigations* (2023), §4–5.
- TPM 2.0 Library, Part 1: Architecture — *Session-based encryption* / salted sessions.
- Microsoft TSS.MSR — <https://github.com/microsoft/TSS.MSR>
