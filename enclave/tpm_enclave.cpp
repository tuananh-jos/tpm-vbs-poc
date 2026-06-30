/*
 * tpm_enclave.cpp  --  VBS Enclave DLL (runs in VTL1)
 *
 * This DLL is loaded by the host (VTL0) via CreateEnclave() + LoadEnclaveImage().
 * All code here executes inside the VBS Enclave (VTL1). The host calls individual
 * functions via CallEnclave().
 *
 * KEY INVARIANT: SECRET (the decrypted plaintext) is computed and used entirely
 * within VTL1. It is NEVER copied into the EnclavePhase2Out struct returned to
 * the host -- only a proof (byte count + status message) crosses back to VTL0.
 *
 * BUILD NOTE: this DLL must be linked with /ENCLAVE and the VBS enclave config
 * section below. For development, ENCLAVE_POLICY_DEBUGGABLE relaxes signing.
 * Production enclaves require an Authenticode certificate trusted by VBS.
 *
 * VBS ENCLAVE CONFIG (required -- informs the loader this is an enclave image):
 */
#define WIN32_LEAN_AND_MEAN   // prevents windows.h from pulling in winsock.h (conflicts with TSS.CPP's winsock2.h)
#include <windows.h>
#include <enclaveapi.h>

// Enclave configuration section -- required for Windows to recognise this as a
// VBS enclave image. The linker places this in the .rdata section.
// Flags: IMAGE_ENCLAVE_POLICY_DEBUGGABLE allows unsigned debug enclaves on Dev builds.
// Remove that flag and add a valid certificate for production.
volatile const IMAGE_ENCLAVE_CONFIG64 __enclave_config = {
    sizeof(IMAGE_ENCLAVE_CONFIG64),          // Size
    IMAGE_ENCLAVE_MINIMUM_CONFIG_SIZE,       // MinimumRequiredConfigSize
    IMAGE_ENCLAVE_POLICY_DEBUGGABLE,         // PolicyFlags (dev only -- see note above)
    0,                                       // NumberOfImports
    0, 0,                                    // ImportList / ImportEntrySize
    { 0 },                                   // FamilyID  (set per-product in production)
    { 0 },                                   // ImageID   (set per-product in production)
    0,                                       // ImageVersion
    0,                                       // SecurityVersion
    0x10000000,                              // EnclaveSize (256 MB virtual)
    16,                                      // NumberOfThreads
    IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE         // EnclaveFlags
};

#include <iostream>
#include <string>
#include <stdexcept>
#include <vector>
#include <algorithm>

#include "Tpm2.h"
#include "tpm_enclave_shared.h"

using namespace TpmCpp;
using namespace std;

#define null {}
static const TPMT_SYM_DEF_OBJECT Aes128Cfb { TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB };

// ---------------------------------------------------------------------------
// EnclaveCreateWrapKey  (Phase 1)
//
// Called by host via CallEnclave(EnclaveCreateWrapKey, out, ...).
// Creates wrapKey and EK inside the real TPM (accessed from VTL1 via TBS),
// then serialises tpm-pub back to the host so the Server can encrypt SECRET.
//
// The EK handle is stored in a global so Phase 2 can reuse it without
// recreating it (saves one expensive CreatePrimary round-trip).
// ---------------------------------------------------------------------------
static TPM_HANDLE g_wrapKeyHandle { 0 };
static TPM_HANDLE g_ekHandle      { 0 };
static TPMT_PUBLIC g_ekPub;

extern "C" __declspec(dllexport)
DWORD WINAPI EnclaveCreateWrapKey(LPVOID lpParam)
{
    auto* out = reinterpret_cast<EnclavePhase1Out*>(lpParam);
    memset(out, 0, sizeof(*out));

    try {
        // Connect to the REAL TPM from inside VTL1 via Windows TBS.
        // TBS is a kernel service; syscalls work from VTL1 user mode.
        //
        // TODO(SECURITY): verify EK certificate chain before using EK pub as
        // salt key -- same active-MITM caveat as the simulator PoC.
        TpmTbsDevice tbs;
        if (!tbs.Connect())
            throw runtime_error("TBS connect failed -- run as Administrator");

        Tpm2 tpm;
        tpm._SetDevice(tbs);

        // A.1 wrapKey: non-restricted RSA decrypt key, born inside TPM.
        //     SHA-1 constraint: see vbs_poc.cpp header for explanation.
        TPMT_PUBLIC wrapTemplate(
            TPM_ALG_ID::SHA1,
            TPMA_OBJECT::decrypt | TPMA_OBJECT::userWithAuth
                | TPMA_OBJECT::sensitiveDataOrigin
                | TPMA_OBJECT::fixedTPM | TPMA_OBJECT::fixedParent,
            null,
            TPMS_RSA_PARMS(null, TPMS_SCHEME_OAEP(TPM_ALG_ID::SHA1), 2048, 65537),
            TPM2B_PUBLIC_KEY_RSA());

        auto wrapKey = tpm.CreatePrimary(TPM_RH::OWNER, null, wrapTemplate, null, null);
        g_wrapKeyHandle = wrapKey.handle;

        // Serialise tpm-pub so the host can hand it to the Server for encryption.
        // The private key (tpm-priv) never leaves the chip.
        ByteVec pubBytes = wrapKey.outPublic.toBytes();
        if (pubBytes.size() > sizeof(out->tpmPub))
            throw runtime_error("tpm-pub too large for shared buffer");
        memcpy(out->tpmPub, pubBytes.data(), pubBytes.size());
        out->tpmPubSize = (DWORD)pubBytes.size();

        // A.2 EK: restricted decrypt key used ONLY as salt key for the channel.
        TPMT_PUBLIC ekTemplate(
            TPM_ALG_ID::SHA1,
            TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted
                | TPMA_OBJECT::fixedTPM | TPMA_OBJECT::fixedParent
                | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth,
            null,
            TPMS_RSA_PARMS(Aes128Cfb, TPMS_NULL_ASYM_SCHEME(), 2048, 65537),
            TPM2B_PUBLIC_KEY_RSA());

        auto ek = tpm.CreatePrimary(TPM_RH::ENDORSEMENT, null, ekTemplate, null, null);
        g_ekHandle = ek.handle;
        g_ekPub    = ek.outPublic;

        out->success = TRUE;
    }
    catch (const exception& e) {
        strncpy_s(out->error, e.what(), sizeof(out->error) - 1);
        out->success = FALSE;
    }
    return out->success ? 0 : 1;
}

// ---------------------------------------------------------------------------
// EnclaveDecryptSecret  (Phase 2)
//
// Called by host via CallEnclave(EnclaveDecryptSecret, &{in, out}, ...).
// Receives C = tpm-pub(SECRET) from the host (VTL0), decrypts it inside the
// TPM over a salted session, and KEEPS SECRET IN VTL1.
// Only a status message (byte count, no content) is returned to VTL0.
// ---------------------------------------------------------------------------
struct Phase2Ctx { EnclavePhase2In* in; EnclavePhase2Out* out; };

extern "C" __declspec(dllexport)
DWORD WINAPI EnclaveDecryptSecret(LPVOID lpParam)
{
    auto* ctx = reinterpret_cast<Phase2Ctx*>(lpParam);
    EnclavePhase2In*  in  = ctx->in;
    EnclavePhase2Out* out = ctx->out;
    memset(out, 0, sizeof(*out));

    try {
        TpmTbsDevice tbs;
        if (!tbs.Connect())
            throw runtime_error("TBS connect failed");

        Tpm2 tpm;
        tpm._SetDevice(tbs);

        // C. Open salted HMAC session with RESPONSE parameter encryption.
        //    Salt OAEP-encrypted to EK pub -- VTL0 cannot derive channelKey.
        ByteVec salt         = Helpers::RandomBytes(Crypto::HashLength(TPM_ALG_ID::SHA1));
        ByteVec encryptedSalt = g_ekPub.EncryptSessionSalt(salt);

        AUTH_SESSION channel = tpm.StartAuthSession(
            g_ekHandle, TPM_RH_NULL, TPM_SE::HMAC, TPM_ALG_ID::SHA1,
            TPMA_SESSION::continueSession | TPMA_SESSION::encrypt,
            TPMT_SYM_DEF(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
            salt, encryptedSalt);

        // D. Decrypt C inside the TPM. Response comes back AES-CFB encrypted
        //    over the physical bus; TSS.CPP decrypts it here in VTL1.
        //    SECRET is now in VTL1 memory -- it NEVER touches VTL0.
        ByteVec C(in->ciphertext, in->ciphertext + in->ciphertextSize);
        ByteVec SECRET = tpm[channel].RSA_Decrypt(
            g_wrapKeyHandle, C, TPMS_NULL_ASYM_SCHEME(), null);

        // *** SECRET IS HERE, INSIDE VTL1 ***
        // Process it (decrypt a payload, verify a token, store to secure NV, etc.).
        // We deliberately do NOT copy it into out->message.

        string msg = "VTL1: SECRET received and processed (" +
                     to_string(SECRET.size()) + " bytes). Not returned to VTL0.";
        strncpy_s(out->message, msg.c_str(), sizeof(out->message) - 1);
        out->secretSize = (DWORD)SECRET.size();
        out->success    = TRUE;

        // Zero SECRET before it can be paged/inspected by VTL0
        SecureZeroMemory(SECRET.data(), SECRET.size());

        tpm.FlushContext(channel);
    }
    catch (const exception& e) {
        strncpy_s(out->error, e.what(), sizeof(out->error) - 1);
        out->success = FALSE;
    }
    return out->success ? 0 : 1;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }
