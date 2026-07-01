#include <iostream>
#include <string>
#include <vector>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "Tpm2.h"

using namespace TpmCpp;
using namespace std;
typedef vector<uint8_t> ByteVec;
#define null {}
static const TPMT_SYM_DEF_OBJECT Aes128Cfb { TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB };

static string toHex(const ByteVec& v)
{
    string s;
    for (auto b : v) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", b);
        s += buf;
    }
    return s;
}

int main()
{
    try {
        // ── Connect ──────────────────────────────────────────────────────────
        cout << "[1] Connecting to real TPM via Windows TBS...\n";
        TpmTbsDevice tbs;
        if (!tbs.Connect()) {
            cerr << "    FAILED. Run as Administrator.\n";
            return 1;
        }
        Tpm2 tpm;
        tpm._SetDevice(tbs);
        cout << "    OK\n\n";

        // ── wrapKey ───────────────────────────────────────────────────────────
        cout << "[2] TPM2_CreatePrimary: wrapKey (RSA-2048, non-restricted, OWNER hierarchy)\n";
        cout << "    tpm-priv will never leave the chip.\n";
        TPMT_PUBLIC wrapTemplate(
            TPM_ALG_ID::SHA1,
            TPMA_OBJECT::decrypt | TPMA_OBJECT::userWithAuth | TPMA_OBJECT::sensitiveDataOrigin
                | TPMA_OBJECT::fixedTPM | TPMA_OBJECT::fixedParent,
            null,
            TPMS_RSA_PARMS(null, TPMS_SCHEME_OAEP(TPM_ALG_ID::SHA1), 2048, 65537),
            TPM2B_PUBLIC_KEY_RSA());
        auto wrapKey = tpm.CreatePrimary(TPM_RH::OWNER, null, wrapTemplate, null, null);
        ByteVec tpmPub = wrapKey.outPublic.unique->toBytes();
        cout << "    handle  : 0x" << hex << wrapKey.handle.handle << dec << "\n";
        cout << "    tpm-pub : " << tpmPub.size() << " bytes  "
             << toHex(ByteVec(tpmPub.begin(), tpmPub.begin() + 8)) << "...\n\n";

        // ── EK ───────────────────────────────────────────────────────────────
        cout << "[3] TPM2_CreatePrimary: EK (RSA-2048, restricted, ENDORSEMENT hierarchy)\n";
        cout << "    EK-priv will never leave the chip.\n";
        cout << "    Role: salt key only — used to bootstrap secret, not to decrypt sessionKey.\n";
        TPMT_PUBLIC ekTemplate(
            TPM_ALG_ID::SHA1,
            TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted | TPMA_OBJECT::fixedTPM
                | TPMA_OBJECT::fixedParent | TPMA_OBJECT::sensitiveDataOrigin
                | TPMA_OBJECT::userWithAuth,
            null,
            TPMS_RSA_PARMS(Aes128Cfb, TPMS_NULL_ASYM_SCHEME(), 2048, 65537),
            TPM2B_PUBLIC_KEY_RSA());
        auto ek = tpm.CreatePrimary(TPM_RH::ENDORSEMENT, null, ekTemplate, null, null);
        ByteVec ekPubBytes = ek.outPublic.unique->toBytes();
        cout << "    handle  : 0x" << hex << ek.handle.handle << dec << "\n";
        cout << "    EK-pub  : " << ekPubBytes.size() << " bytes  "
             << toHex(ByteVec(ekPubBytes.begin(), ekPubBytes.begin() + 8)) << "...\n\n";

        // ── External encrypts sessionKey ──────────────────────────────────────
        string sessionKeyStr = "TOP-SECRET-2026!!";
        ByteVec sessionKey(sessionKeyStr.begin(), sessionKeyStr.end());
        cout << "[4] External: sessionKey = \"" << sessionKeyStr << "\"\n";
        cout << "    Encrypting sessionKey with tpm-pub (RSA-OAEP)...\n";
        ByteVec C = wrapKey.outPublic.Encrypt(sessionKey, null);
        cout << "    C (" << C.size() << " bytes) : " << toHex(C) << "\n";
        cout << "    sessionKey is now opaque — only the TPM can open C.\n\n";

        // ── Salt + session ────────────────────────────────────────────────────
        cout << "[5] External: generating salt (random bytes)...\n";
        ByteVec salt = Helpers::RandomBytes(Crypto::HashLength(TPM_ALG_ID::SHA1));
        cout << "    salt (" << salt.size() << " bytes) : " << toHex(salt) << "\n";

        cout << "    Encrypting salt to EK-pub (RSA-OAEP) -> encryptedSalt...\n";
        ByteVec encryptedSalt = ek.outPublic.EncryptSessionSalt(salt);
        cout << "    encryptedSalt (" << encryptedSalt.size() << " bytes) : "
             << toHex(ByteVec(encryptedSalt.begin(), encryptedSalt.begin() + 16)) << "...\n";
        cout << "    Transport only ever sees encryptedSalt — salt itself is hidden.\n\n";

        cout << "[6] TPM2_StartAuthSession (salted HMAC, AES-128-CFB, encrypt ON)...\n";
        cout << "    TPM decrypts encryptedSalt with EK-priv -> recovers salt\n";
        cout << "    Both sides: secret = KDF(salt)  [neither side transmits secret]\n";
        AUTH_SESSION session = tpm.StartAuthSession(
            ek.handle, TPM_RH_NULL, TPM_SE::HMAC, TPM_ALG_ID::SHA1,
            TPMA_SESSION::continueSession | TPMA_SESSION::encrypt,
            TPMT_SYM_DEF(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
            salt, encryptedSalt);
        cout << "    Session established. secret shared between external and TPM.\n\n";

        // ── RSA_Decrypt over session ──────────────────────────────────────────
        cout << "[7] TPM2_RSA_Decrypt(wrapKey, C) over session...\n";
        cout << "    Inside TPM : wrapKey-priv decrypts C -> sessionKey\n";
        cout << "    Inside TPM : sessionKey encrypted with secret -> sent over transport\n";
        cout << "    TSS.CPP    : decrypts response with secret -> sessionKey in memory\n";
        ByteVec recovered = tpm[session].RSA_Decrypt(
            wrapKey.handle, C, TPMS_NULL_ASYM_SCHEME(), null);
        cout << "    recovered  : \"" << string(recovered.begin(), recovered.end()) << "\"\n";
        cout << "    correct    : " << (recovered == sessionKey ? "yes" : "NO -- MISMATCH") << "\n\n";

        // ── Cleanup ───────────────────────────────────────────────────────────
        cout << "[8] TPM2_FlushContext: releasing session, wrapKey, EK handles.\n";
        tpm.FlushContext(session);
        tpm.FlushContext(wrapKey.handle);
        tpm.FlushContext(ek.handle);
        cout << "    Done.\n";
    }
    catch (const exception& e) {
        cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
