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
        // -- Connect --
        cout << "[1] Connecting to real TPM via Windows TBS...\n";
        TpmTbsDevice tbs;
        if (!tbs.Connect()) {
            cerr << "    FAILED. Run as Administrator.\n";
            return 1;
        }
        Tpm2 tpm;
        tpm._SetDevice(tbs);
        cout << "    OK\n\n";

        // ----------------------------------------------------------------
        // [2] Certification chain: EK -> AIK -> SPCK
        //     Goal: prove SPCK lives in a genuine TPM, so external can
        //     trust SPCK-pub and use SPCK as salt key instead of EK.
        // ----------------------------------------------------------------
        cout << "[2] Building certification chain: EK -> AIK -> SPCK\n\n";

        // -- [2a] EK: derive pre-existing key (manufacturer-provisioned) --
        TPMT_PUBLIC ekTemplate(
            TPM_ALG_ID::SHA1,
            TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted | TPMA_OBJECT::fixedTPM
                | TPMA_OBJECT::fixedParent | TPMA_OBJECT::sensitiveDataOrigin
                | TPMA_OBJECT::userWithAuth,
            null,
            TPMS_RSA_PARMS(Aes128Cfb, TPMS_NULL_ASYM_SCHEME(), 2048, 65537),
            TPM2B_PUBLIC_KEY_RSA());

        cout << "  [2a] EK: deriving pre-existing key (ENDORSEMENT hierarchy).\n";
        auto ek = tpm.CreatePrimary(TPM_RH::ENDORSEMENT, null, ekTemplate, null, null);
        cout << "       handle : 0x" << hex << ek.handle.handle << dec << "\n";
        cout << "       EK-pub : " << toHex(ek.outPublic.unique->toBytes()) << "\n\n";

        // -- [2b] AIK: restricted signing key, certified by EK --
        TPMT_PUBLIC aikTemplate(
            TPM_ALG_ID::SHA1,
            TPMA_OBJECT::restricted | TPMA_OBJECT::sign | TPMA_OBJECT::fixedTPM
                | TPMA_OBJECT::fixedParent | TPMA_OBJECT::sensitiveDataOrigin
                | TPMA_OBJECT::userWithAuth,
            null,
            TPMS_RSA_PARMS(null, TPMS_SCHEME_RSASSA(TPM_ALG_ID::SHA1), 2048, 65537),
            TPM2B_PUBLIC_KEY_RSA());

        cout << "  [2b] AIK: creating restricted signing key (OWNER hierarchy).\n";
        auto aik = tpm.CreatePrimary(TPM_RH::OWNER, null, aikTemplate, null, null);
        cout << "       handle : 0x" << hex << aik.handle.handle << dec << "\n";
        cout << "       AIK-pub: " << toHex(aik.outPublic.unique->toBytes()) << "\n\n";

        // -- [2c] SPCK: non-restricted decrypt key, certified by AIK --
        TPMT_PUBLIC spckTemplate(
            TPM_ALG_ID::SHA1,
            TPMA_OBJECT::decrypt | TPMA_OBJECT::userWithAuth | TPMA_OBJECT::sensitiveDataOrigin
                | TPMA_OBJECT::fixedTPM | TPMA_OBJECT::fixedParent,
            null,
            TPMS_RSA_PARMS(null, TPMS_SCHEME_OAEP(TPM_ALG_ID::SHA1), 2048, 65537),
            TPM2B_PUBLIC_KEY_RSA());

        cout << "  [2c] SPCK: creating non-restricted decrypt key (OWNER hierarchy).\n";
        auto spck = tpm.CreatePrimary(TPM_RH::OWNER, null, spckTemplate, null, null);
        cout << "       handle   : 0x" << hex << spck.handle.handle << dec << "\n";

        // Certify: AIK signs SPCK's public area -> proves SPCK lives in same TPM as AIK.
        auto cert = tpm.Certify(spck.handle, aik.handle, ByteVec{}, TPMS_NULL_SIG_SCHEME());
        cout << "       Certify  : OK -- SPCK certified by AIK\n";
        cout << "       signer   : " << toHex(cert.certifyInfo.qualifiedSigner) << "\n";
        cout << "       SPCK-pub : " << toHex(spck.outPublic.unique->toBytes()) << "\n\n";

        // Release EK and AIK -- no longer needed
        tpm.FlushContext(ek.handle);
        tpm.FlushContext(aik.handle);
        cout << "  EK and AIK handles released.\n";
        cout << "  Chain: EK -> AIK -> SPCK established.\n";
        cout << "  External can now trust SPCK-pub via cert chain.\n";
        cout << "  SPCK replaces EK as salt key: only real TPM can recover salt.\n\n";

        // ----------------------------------------------------------------
        // [3] External encrypts sessionKey with SPCK-pub
        // ----------------------------------------------------------------
        string sessionKeyStr = "TOP-SECRET-2026!!";
        ByteVec sessionKey(sessionKeyStr.begin(), sessionKeyStr.end());
        cout << "[3] External: sessionKey = \"" << sessionKeyStr << "\"\n";
        ByteVec C = spck.outPublic.Encrypt(sessionKey, null);
        cout << "    C = SPCK-pub(sessionKey)\n";
        cout << "    C : " << toHex(C) << "\n";
        cout << "    Only SPCK-priv (inside chip) can open C.\n\n";

        // ----------------------------------------------------------------
        // [4] Salt encrypted with SPCK-pub (not EK-pub)
        // ----------------------------------------------------------------
        cout << "[4] External generates salt.\n";
        ByteVec salt = Helpers::RandomBytes(Crypto::HashLength(TPM_ALG_ID::SHA1));
        cout << "    salt          : " << toHex(salt) << "\n";
        ByteVec encryptedSalt = spck.outPublic.EncryptSessionSalt(salt);
        cout << "    encryptedSalt = SPCK-pub(salt)  <- SPCK instead of EK\n";
        cout << "    encryptedSalt : " << toHex(encryptedSalt) << "\n";
        cout << "    Transport only sees encryptedSalt, not salt.\n\n";

        // ----------------------------------------------------------------
        // [5] StartAuthSession with SPCK as salt key
        // ----------------------------------------------------------------
        cout << "[5] StartAuthSession: SPCK-priv decrypts encryptedSalt -> salt.\n";
        cout << "    Both sides derive channelKey = KDF(salt). channelKey never transmitted.\n";
        AUTH_SESSION session = tpm.StartAuthSession(
            spck.handle,
            TPM_RH_NULL, TPM_SE::HMAC, TPM_ALG_ID::SHA1,
            TPMA_SESSION::continueSession | TPMA_SESSION::encrypt,
            TPMT_SYM_DEF(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
            salt, encryptedSalt);
        cout << "    Session established.\n\n";

        // ----------------------------------------------------------------
        // [6] RSA_Decrypt over session
        // ----------------------------------------------------------------
        cout << "[6] RSA_Decrypt(SPCK-priv, C) over session.\n";
        cout << "    SPCK-priv decrypts C -> sessionKey (inside chip, never on transport).\n";
        cout << "    TPM sends channelKey(sessionKey) over transport.\n";
        cout << "    External uses channelKey to decrypt -> sessionKey plaintext in RAM.\n";
        ByteVec recovered = tpm[session].RSA_Decrypt(
            spck.handle, C, TPMS_NULL_ASYM_SCHEME(), null);
        cout << "    recovered : \"" << string(recovered.begin(), recovered.end()) << "\"\n";
        cout << "    correct   : " << (recovered == sessionKey ? "yes" : "NO -- MISMATCH") << "\n\n";

        // ----------------------------------------------------------------
        // [7] Cleanup
        // ----------------------------------------------------------------
        cout << "[7] FlushContext: releasing session and SPCK.\n";
        tpm.FlushContext(session);
        tpm.FlushContext(spck.handle);
        cout << "    Done.\n";
    }
    catch (const exception& e) {
        cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
