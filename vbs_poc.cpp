/*
 *  vbs_poc.cpp  --  TPM 2.0 "VBS-style" secret delivery PoC (TSS.CPP / Microsoft TSS.MSR)
 *
 *  GOAL (simulating Windows VBS):
 *    Deliver a SECRET from a "Server" to "VBS" (the receiver, like VTL1) across an
 *    UNTRUSTED transport ("VTL0") that sits between VBS and the TPM. Hard requirement:
 *    the plaintext of SECRET MUST NEVER appear in the clear on the wire between the
 *    caller and the TPM. The transport may only ever see ciphertext.
 *
 *  TERMINOLOGY (kept identical in code + comments to avoid confusion):
 *    SECRET      payload to be delivered.
 *    wrapKey     RSA *decrypt* key created INSIDE the TPM; its public is "tpm-pub".
 *                The Server encrypts SECRET to tpm-pub; only the TPM can open it with
 *                the private "tpm-priv". (Non-restricted -> usable with TPM2_RSA_Decrypt.)
 *    EK          Endorsement Key of the TPM. Used ONLY to bootstrap the encrypted channel
 *                (as the salt/tpmKey of a salted session). Distinct role from wrapKey.
 *    channelKey  Ephemeral SYMMETRIC key that VBS and the TPM both derive via the salted
 *                session; protects the response on the wire. This is the TPM session key
 *                used for parameter encryption (named channelKey to avoid the word "session").
 *
 *  FLOW:
 *    A. Prepare : create wrapKey in TPM (export tpm-pub); create EK (salt key).
 *    B. Server  : C = tpm-pub(SECRET) using RSA-OAEP. Hand C to VBS.
 *    C. Channel : VBS opens a SALTED HMAC session with tpmKey = EK (salt OAEP-encrypted
 *                 to EK pub). Turn on RESPONSE parameter encryption (AES-128-CFB).
 *                 After this VBS and the TPM share channelKey; VTL0 does not.
 *    D. Deliver : VBS calls TPM2_RSA_Decrypt(wrapKey, C) OVER that session. Inside the TPM
 *                 tpm-priv opens C -> SECRET, then the first response parameter is encrypted
 *                 with channelKey before leaving the chip. On VTL0: ciphertext only.
 *                 TSS.CPP transparently decrypts the response with channelKey -> SECRET.
 *
 *  WE DELIBERATELY DO NOT:
 *    - create a VBS keypair for the TPM to "re-wrap with vbs-pub": the TPM has no command to
 *      re-encrypt an internal value under an external public key. The return trip is protected
 *      by the SYMMETRIC channelKey (parameter encryption), not by a VBS public key.
 *    - use TPM2_Duplicate / TPM2_Rewrap.
 *    - call TPM2_RSA_Decrypt with no session and re-encrypt caller-side: that would expose the
 *      plaintext on the wire.
 *
 *  VERIFY: the delivery is run twice -- response encryption OFF then ON -- and the raw response
 *  buffer that VTL0 sees is printed both times: OFF leaks the plaintext SECRET, ON shows only
 *  ciphertext, yet VBS still recovers SECRET in both cases.
 *
 *  References:
 *    - TCG "CPU to TPM Bus Protection Guidance - Passive Attack Mitigations" (2023), sec. 4-5.
 *    - TPM 2.0 Library, Part 1: Architecture, "Session-based encryption".
 *    - Microsoft TSS.MSR / TSS.CPP (StartAuthSession with a salt key, AUTH_SESSION).
 */

// Standard headers MUST precede Tpm2.h: the TSS.CPP headers use std::runtime_error,
// std::string, etc. but expect the consumer (normally via stdafx.h) to have included
// these first. Including Tpm2.h before them yields C2039 'runtime_error' is not in std.
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <string>
#include <stdexcept>
#include <vector>
#include <windows.h>
#include <enclaveapi.h>

#include "Tpm2.h"
#include "enclave/tpm_enclave_shared.h"

using namespace TpmCpp;
using namespace std;

// TSS.CPP's sample convention: `null` is a macro for an empty initializer `{}`, used as a
// default/empty value for ByteVec, TPMS_SENSITIVE_CREATE, policy digests, symmetric defs, etc.
// It lives in the samples' Samples.h, not the library headers, so we define it here.
#define null {}

// AES-128-CFB symmetric def for object parameters (TSS.CPP does not export this constant).
static const TPMT_SYM_DEF_OBJECT Aes128Cfb { TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB };

// ---------------------------------------------------------------------------
// Vtl0LoggingDevice: a transparent tap on the transport between TSS.CPP and the
// TPM. It models the untrusted VTL0: every byte that crosses it is exactly what
// an attacker controlling VTL0 would observe. We override the two transfer
// methods only to stash the raw command/response of the call we are auditing.
// ---------------------------------------------------------------------------
class Vtl0LoggingDevice : public TpmTcpDevice
{
public:
    Vtl0LoggingDevice(string host = "127.0.0.1", int port = 2321)
        : TpmTcpDevice(host, port) {}

    bool    Capture = false;   // when true, record the next command/response pair
    ByteVec LastCommand;
    ByteVec LastResponse;

    void DispatchCommand(const ByteVec& outBytes) override {
        if (Capture) LastCommand = outBytes;
        TpmTcpDevice::DispatchCommand(outBytes);
    }
    ByteVec GetResponse() override {
        ByteVec r = TpmTcpDevice::GetResponse();
        if (Capture) LastResponse = r;
        return r;
    }
};

static string toHex(const ByteVec& v)
{
    static const char* h = "0123456789abcdef";
    string s;
    s.reserve(v.size() * 2);
    for (BYTE b : v) { s += h[b >> 4]; s += h[b & 0x0f]; }
    return s;
}

// Does the raw wire buffer contain the SECRET plaintext as a contiguous byte run?
static bool wireContains(const ByteVec& hay, const ByteVec& needle)
{
    if (needle.empty() || hay.size() < needle.size()) return false;
    return search(hay.begin(), hay.end(), needle.begin(), needle.end()) != hay.end();
}

static string asAscii(const ByteVec& v) { return string(v.begin(), v.end()); }

// ---------------------------------------------------------------------------
// One secret-delivery run. encryptResponse toggles ONLY the response parameter
// encryption attribute on the channel; everything else is identical so the
// difference on the wire is purely the effect of channelKey protection.
// ---------------------------------------------------------------------------
static void runDelivery(Tpm2& tpm, Vtl0LoggingDevice& vtl0,
                        TPM_HANDLE ekHandle, TPMT_PUBLIC& ekPub,
                        TPM_HANDLE wrapKey, const ByteVec& C,
                        const ByteVec& SECRET, bool encryptResponse)
{
    cout << "================  Delivery: RESPONSE ENCRYPTION "
         << (encryptResponse ? "ON " : "OFF") << "  ================\n";

    // --- C. VBS establishes the encrypted channel (salted HMAC session) ---------
    // A fresh random salt is OAEP-encrypted to EK pub; only the TPM (EK priv) can
    // recover it, so VTL0 cannot derive channelKey from what it sees on the wire.
    ByteVec salt          = Helpers::RandomBytes(Crypto::HashLength(TPM_ALG_ID::SHA1));
    ByteVec encryptedSalt = ekPub.EncryptSessionSalt(salt);   // OAEP to EK pub, label "SECRET"

    TPMA_SESSION attrs = TPMA_SESSION::continueSession;
    if (encryptResponse)
        attrs = attrs | TPMA_SESSION::encrypt;                // encrypt RESPONSE parameters

    // tpmKey = EK -> salted session. symmetric = AES-128-CFB -> channelKey for param enc.
    // Session hash SHA-1 matches the EK nameAlg (TSS.CPP SHA-1 OAEP constraint).
    AUTH_SESSION channel = tpm.StartAuthSession(
        ekHandle, TPM_RH_NULL, TPM_SE::HMAC, TPM_ALG_ID::SHA1,
        attrs, TPMT_SYM_DEF(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
        salt, encryptedSalt);

    // --- D. VBS asks the TPM to unwrap SECRET, over the channel -----------------
    vtl0.LastResponse.clear();
    vtl0.Capture = true;                                      // begin watching the VTL0 wire
    ByteVec recovered = tpm[channel].RSA_Decrypt(wrapKey, C, TPMS_NULL_ASYM_SCHEME(), null);
    vtl0.Capture = false;

    // --- E. What did VTL0 actually see? -----------------------------------------
    const ByteVec& wireCmd  = vtl0.LastCommand;
    const ByteVec& wireResp = vtl0.LastResponse;
    bool leaked = wireContains(wireResp, SECRET);

    cout << "  channel: salted HMAC session, tpmKey = EK, " << salt.size()
         << "-byte salt, AES-128-CFB\n";
    cout << "  RSA_Decrypt COMMAND  on VTL0 wire (" << wireCmd.size() << " bytes):\n";
    cout << "    " << toHex(wireCmd) << "\n";
    cout << "  RSA_Decrypt RESPONSE on VTL0 wire (" << wireResp.size() << " bytes):\n";
    cout << "    " << toHex(wireResp) << "\n";
    cout << "  SECRET plaintext visible on the wire? : "
         << (leaked ? "YES   <-- LEAKED to VTL0" : "no    <-- protected from VTL0") << "\n";
    cout << "  VBS recovered SECRET                  : \"" << asAscii(recovered) << "\"\n";
    cout << "  recovered == original SECRET?         : "
         << ((recovered == SECRET) ? "yes" : "NO") << "\n\n";

    tpm.FlushContext(channel);
}

int main(int argc, char* argv[])
{
    bool useRealTpm   = false;
    bool useVbsEnclave = false;
    for (int i = 1; i < argc; i++) {
        if (string(argv[i]) == "--real-tpm")    useRealTpm    = true;
        if (string(argv[i]) == "--vbs-enclave") useVbsEnclave = true;
    }

    try {

        // ======================== VBS ENCLAVE PATH ==============================
        if (useVbsEnclave) {
            cout << "=== VBS Enclave mode ===\n"
                 << "Host (VTL0) creates enclave, passes C to it; SECRET stays in VTL1.\n\n";

            // Load the enclave DLL into a VBS enclave (VTL1).
            ENCLAVE_CREATE_INFO_VBS cfg = { IMAGE_ENCLAVE_POLICY_DEBUGGABLE };
            HANDLE hEnc = CreateEnclave(GetCurrentProcess(), NULL,
                                        0x10000000 /*256MB*/, 0,
                                        ENCLAVE_TYPE_VBS,
                                        &cfg, sizeof(cfg), NULL);
            if (!hEnc || hEnc == INVALID_HANDLE_VALUE) {
                cerr << "CreateEnclave failed: " << GetLastError()
                     << "\n(Hyper-V / VBS must be enabled. Run as Administrator.)\n";
                return 1;
            }

            if (!LoadEnclaveImage(hEnc, L"tpm_enclave.dll")) {
                cerr << "LoadEnclaveImage failed: " << GetLastError() << "\n";
                return 1;
            }
            if (!InitializeEnclave(GetCurrentProcess(), hEnc, NULL, 0, NULL)) {
                cerr << "InitializeEnclave failed: " << GetLastError() << "\n";
                return 1;
            }
            cout << "[Enclave] VBS enclave loaded into VTL1.\n";

            // Phase 1: enclave creates wrapKey + EK in TPM, returns tpm-pub.
            EnclavePhase1Out p1out = {};
            LPVOID ret1 = NULL;
            if (!CallEnclave((LPENCLAVE_ROUTINE)EnclaveCreateWrapKey,
                             &p1out, TRUE, &ret1) || !p1out.success) {
                cerr << "EnclaveCreateWrapKey failed: " << p1out.error << "\n";
                return 1;
            }
            cout << "[VTL1 -> VTL0] tpm-pub exported (" << p1out.tpmPubSize
                 << " bytes). Server can now encrypt SECRET.\n";

            // Phase 1.5 (Server, runs in VTL0): deserialize tpm-pub, encrypt SECRET.
            // In production the Server is a remote machine; here it's in-process.
            ByteVec pubBytes(p1out.tpmPub, p1out.tpmPub + p1out.tpmPubSize);
            TPMT_PUBLIC tpmPub;
            tpmPub.fromBytes(pubBytes);

            string secretStr = "VBS-TOP-SECRET-2026!!";
            ByteVec SECRET(secretStr.begin(), secretStr.end());
            ByteVec C = tpmPub.Encrypt(SECRET, null);
            cout << "[VTL0 / Server] C = tpm-pub(SECRET) = " << C.size()
                 << " bytes. Handing C to enclave.\n\n";

            // Phase 2: pass C into enclave; enclave decrypts via salted session;
            // SECRET stays in VTL1 -- only byte count comes back to VTL0.
            EnclavePhase2In  p2in  = {};
            EnclavePhase2Out p2out = {};
            p2in.ciphertextSize = (DWORD)C.size();
            memcpy(p2in.ciphertext, C.data(), C.size());

            struct { EnclavePhase2In* in; EnclavePhase2Out* out; } p2ctx = { &p2in, &p2out };
            LPVOID ret2 = NULL;
            if (!CallEnclave((LPENCLAVE_ROUTINE)EnclaveDecryptSecret,
                             &p2ctx, TRUE, &ret2) || !p2out.success) {
                cerr << "EnclaveDecryptSecret failed: " << p2out.error << "\n";
                return 1;
            }

            cout << "[VTL1] " << p2out.message << "\n";
            cout << "[VTL0] Host received status only -- SECRET never left VTL1.\n";
            return 0;
        }

        Tpm2 tpm;

        // --- Transport (VTL0) + TPM connection ----------------------------------
        // Default: Microsoft TPM simulator over TCP (ms-tpm-20-ref, port 2321).
        // Pass --real-tpm to use the hardware TPM via Windows TBS instead.
        if (useRealTpm) {
            TpmTbsDevice* tbs = new TpmTbsDevice();
            if (!tbs->Connect()) {
                cerr << "Could not connect to the real TPM via Windows TBS.\n"
                     << "Make sure you are running as Administrator and TPM is enabled.\n";
                return 1;
            }
            tpm._SetDevice(*tbs);
            cout << "Connected to REAL TPM via Windows TBS. (No VTL0 wire tap available.)\n\n";

            // Run the PoC without the logging tap (real TPM path).
            // Re-use runDelivery with a dummy vtl0 that never captures.
            Vtl0LoggingDevice dummy;

            TPMT_PUBLIC wrapTemplate(
                TPM_ALG_ID::SHA1,
                TPMA_OBJECT::decrypt | TPMA_OBJECT::userWithAuth | TPMA_OBJECT::sensitiveDataOrigin
                    | TPMA_OBJECT::fixedTPM | TPMA_OBJECT::fixedParent,
                null,
                TPMS_RSA_PARMS(null, TPMS_SCHEME_OAEP(TPM_ALG_ID::SHA1), 2048, 65537),
                TPM2B_PUBLIC_KEY_RSA());
            auto wrapKey = tpm.CreatePrimary(TPM_RH::OWNER, null, wrapTemplate, null, null);
            TPMT_PUBLIC tpmPub = wrapKey.outPublic;

            TPMT_PUBLIC ekTemplate(
                TPM_ALG_ID::SHA1,
                TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted | TPMA_OBJECT::fixedTPM
                    | TPMA_OBJECT::fixedParent | TPMA_OBJECT::sensitiveDataOrigin
                    | TPMA_OBJECT::userWithAuth,
                null,
                TPMS_RSA_PARMS(Aes128Cfb, TPMS_NULL_ASYM_SCHEME(), 2048, 65537),
                TPM2B_PUBLIC_KEY_RSA());
            auto ek = tpm.CreatePrimary(TPM_RH::ENDORSEMENT, null, ekTemplate, null, null);
            TPMT_PUBLIC ekPub = ek.outPublic;

            cout << "[A] wrapKey and EK created inside the REAL TPM.\n";

            string secretStr = "VBS-TOP-SECRET-2026!!";
            ByteVec SECRET(secretStr.begin(), secretStr.end());
            ByteVec C = tpmPub.Encrypt(SECRET, null);
            cout << "[B] Server: SECRET = \"" << secretStr << "\"\n";
            cout << "    C = tpm-pub(SECRET) = " << C.size() << " bytes.\n\n";

            runDelivery(tpm, dummy, ek.handle, ekPub, wrapKey.handle, C, SECRET, false);
            runDelivery(tpm, dummy, ek.handle, ekPub, wrapKey.handle, C, SECRET, true);

            tpm.FlushContext(wrapKey.handle);
            tpm.FlushContext(ek.handle);
            return 0;
        }

        // --- Simulator path (default) -------------------------------------------
        Vtl0LoggingDevice vtl0("127.0.0.1", 2321);
        if (!vtl0.Connect()) {
            cerr << "Could not connect to the TPM simulator at 127.0.0.1:2321.\n"
                 << "Start the Microsoft TPM simulator (ms-tpm-20-ref) first. See README.\n";
            return 1;
        }
        tpm._SetDevice(vtl0);
        vtl0.PowerOn();                                  // BIOS would normally do this
        tpm._AllowErrors().Startup(TPM_SU::CLEAR);       // tolerate an already-started TPM

        cout << "Connected to TPM simulator. Transport VTL0 tap is active.\n\n";

        // ======================== A. PREPARE ====================================
        // A.1 wrapKey: a NON-restricted RSA decrypt key created in the TPM. tpm-priv
        //     never leaves the chip. Its public area "tpm-pub" is handed to the Server.
        //
        // NOTE: TSS.CPP's Crypto::Encrypt / RsaEncrypt ignores the hashAlg parameter and
        //   always performs OAEP with SHA-1 (OpenSSL RSA_PKCS1_OAEP_PADDING default).
        //   The key nameAlg and OAEP hash must therefore both be SHA-1 so that what
        //   TSS.CPP encrypts client-side matches what the TPM decrypts inside the chip.
        TPMT_PUBLIC wrapTemplate(
            TPM_ALG_ID::SHA1,
            TPMA_OBJECT::decrypt | TPMA_OBJECT::userWithAuth | TPMA_OBJECT::sensitiveDataOrigin
                | TPMA_OBJECT::fixedTPM | TPMA_OBJECT::fixedParent,
            null,                                                       // no policy
            TPMS_RSA_PARMS(null, TPMS_SCHEME_OAEP(TPM_ALG_ID::SHA1), 2048, 65537),
            TPM2B_PUBLIC_KEY_RSA());
        auto      wrapKey = tpm.CreatePrimary(TPM_RH::OWNER, null, wrapTemplate, null, null);
        TPMT_PUBLIC tpmPub = wrapKey.outPublic;                        // "tpm-pub"

        // A.2 EK: a RESTRICTED RSA decrypt key in the endorsement hierarchy, used ONLY
        //     as the salt key of the channel below.
        //
        // TODO(SECURITY): A salted session only stops PASSIVE snooping. To stop an ACTIVE
        //   MITM on VTL0 that swaps EK pub at channel-setup time (and would then know
        //   channelKey), the EK CERTIFICATE must be read (from TPM NV / manufacturer) and
        //   its chain verified to a trusted TPM-vendor root BEFORE ekPub is used as the salt
        //   key. This PoC skips that check -- DO NOT ship without it.
        //
        // NOTE: nameAlg SHA-1 matches the SHA-1 OAEP that EncryptSessionSalt actually uses
        //   (same TSS.CPP limitation as wrapKey above).
        TPMT_PUBLIC ekTemplate(
            TPM_ALG_ID::SHA1,
            TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted | TPMA_OBJECT::fixedTPM
                | TPMA_OBJECT::fixedParent | TPMA_OBJECT::sensitiveDataOrigin
                | TPMA_OBJECT::userWithAuth,
            null,                                                       // no policy
            TPMS_RSA_PARMS(Aes128Cfb, TPMS_NULL_ASYM_SCHEME(), 2048, 65537),
            TPM2B_PUBLIC_KEY_RSA());
        auto       ek    = tpm.CreatePrimary(TPM_RH::ENDORSEMENT, null, ekTemplate, null, null);
        TPMT_PUBLIC ekPub = ek.outPublic;

        cout << "[A] wrapKey (tpm-pub) and EK (salt key) created inside the TPM.\n";

        // ======================== B. SERVER sends SECRET ========================
        // The "Server" runs in software and only possesses tpm-pub. Here we use the
        // TSS.CPP software crypto to perform the RSA-OAEP(SHA256) encryption.
        string  secretStr = "VBS-TOP-SECRET-2026!!";
        ByteVec SECRET(secretStr.begin(), secretStr.end());
        ByteVec C = tpmPub.Encrypt(SECRET, null);                     // C = tpm-pub(SECRET)

        cout << "[B] Server: SECRET = \"" << secretStr << "\"\n";
        cout << "    Server: C = tpm-pub(SECRET) = " << C.size()
             << " bytes of RSA-OAEP ciphertext, handed to VBS.\n\n";

        // ======================== C + D. Deliver twice ==========================
        runDelivery(tpm, vtl0, ek.handle, ekPub, wrapKey.handle, C, SECRET, /*encrypt*/ false);
        runDelivery(tpm, vtl0, ek.handle, ekPub, wrapKey.handle, C, SECRET, /*encrypt*/ true);

        cout << "Done. With response encryption ON, VTL0 saw only ciphertext, yet VBS\n"
             << "recovered the SECRET -- plaintext never crossed the transport in the clear.\n";

        tpm.FlushContext(wrapKey.handle);
        tpm.FlushContext(ek.handle);
    }
    catch (const exception& e) {
        cerr << "ERROR: " << e.what() << endl;
        return 1;
    }
    return 0;
}
