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

int main()
{
    try {
        TpmTbsDevice tbs;
        if (!tbs.Connect()) {
            cerr << "Cannot connect to TPM. Run as Administrator.\n";
            return 1;
        }
        Tpm2 tpm;
        tpm._SetDevice(tbs);

        // wrapKey: RSA-2048 decrypt key born inside the TPM. tpm-priv never leaves the chip.
        TPMT_PUBLIC wrapTemplate(
            TPM_ALG_ID::SHA1,
            TPMA_OBJECT::decrypt | TPMA_OBJECT::userWithAuth | TPMA_OBJECT::sensitiveDataOrigin
                | TPMA_OBJECT::fixedTPM | TPMA_OBJECT::fixedParent,
            null,
            TPMS_RSA_PARMS(null, TPMS_SCHEME_OAEP(TPM_ALG_ID::SHA1), 2048, 65537),
            TPM2B_PUBLIC_KEY_RSA());
        auto wrapKey = tpm.CreatePrimary(TPM_RH::OWNER, null, wrapTemplate, null, null);

        // EK: restricted decrypt key used only as salt key to bootstrap secret.
        TPMT_PUBLIC ekTemplate(
            TPM_ALG_ID::SHA1,
            TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted | TPMA_OBJECT::fixedTPM
                | TPMA_OBJECT::fixedParent | TPMA_OBJECT::sensitiveDataOrigin
                | TPMA_OBJECT::userWithAuth,
            null,
            TPMS_RSA_PARMS(Aes128Cfb, TPMS_NULL_ASYM_SCHEME(), 2048, 65537),
            TPM2B_PUBLIC_KEY_RSA());
        auto ek = tpm.CreatePrimary(TPM_RH::ENDORSEMENT, null, ekTemplate, null, null);

        // External encrypts sessionKey to tpm-pub.
        string sessionKeyStr = "TOP-SECRET-2026!!";
        ByteVec sessionKey(sessionKeyStr.begin(), sessionKeyStr.end());
        ByteVec C = wrapKey.outPublic.Encrypt(sessionKey, null);

        // Salted HMAC session: salt OAEP-encrypted to EK-pub so transport never sees secret.
        // Both sides derive secret from salt independently.
        // Response encryption ON: TPM re-encrypts sessionKey with secret before wire.
        ByteVec salt          = Helpers::RandomBytes(Crypto::HashLength(TPM_ALG_ID::SHA1));
        ByteVec encryptedSalt = ek.outPublic.EncryptSessionSalt(salt);
        AUTH_SESSION session   = tpm.StartAuthSession(
            ek.handle, TPM_RH_NULL, TPM_SE::HMAC, TPM_ALG_ID::SHA1,
            TPMA_SESSION::continueSession | TPMA_SESSION::encrypt,
            TPMT_SYM_DEF(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
            salt, encryptedSalt);

        // TPM decrypts C with wrapKey-priv, returns sessionKey encrypted with secret.
        ByteVec recovered = tpm[session].RSA_Decrypt(
            wrapKey.handle, C, TPMS_NULL_ASYM_SCHEME(), null);

        cout << "recovered : \"" << string(recovered.begin(), recovered.end()) << "\"\n";
        cout << "correct   : " << (recovered == sessionKey ? "yes" : "NO -- MISMATCH") << "\n";

        tpm.FlushContext(session);
        tpm.FlushContext(wrapKey.handle);
        tpm.FlushContext(ek.handle);
    }
    catch (const exception& e) {
        cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
