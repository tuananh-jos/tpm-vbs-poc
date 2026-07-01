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

        // -- key pair (tpm-pub / tpm-priv) --
        cout << "[2] TPM creates key pair inside chip (tpm-priv never leaves).\n";
        TPMT_PUBLIC keyPairTemplate(
            TPM_ALG_ID::SHA1,
            TPMA_OBJECT::decrypt | TPMA_OBJECT::userWithAuth | TPMA_OBJECT::sensitiveDataOrigin
                | TPMA_OBJECT::fixedTPM | TPMA_OBJECT::fixedParent,
            null,
            TPMS_RSA_PARMS(null, TPMS_SCHEME_OAEP(TPM_ALG_ID::SHA1), 2048, 65537),
            TPM2B_PUBLIC_KEY_RSA());
        auto keyPair = tpm.CreatePrimary(TPM_RH::OWNER, null, keyPairTemplate, null, null);
        ByteVec tpmPub = keyPair.outPublic.unique->toBytes();
        cout << "    handle  : 0x" << hex << keyPair.handle.handle << dec << "\n";
        cout << "    tpm-pub : " << toHex(tpmPub) << "\n\n";

        // -- EK --
        cout << "[3] TPM creates EK inside chip (EK-priv never leaves).\n";
        cout << "    Role: used only to hide salt from transport.\n";
        TPMT_PUBLIC ekTemplate(
            TPM_ALG_ID::SHA1,
            TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted | TPMA_OBJECT::fixedTPM
                | TPMA_OBJECT::fixedParent | TPMA_OBJECT::sensitiveDataOrigin
                | TPMA_OBJECT::userWithAuth,
            null,
            TPMS_RSA_PARMS(Aes128Cfb, TPMS_NULL_ASYM_SCHEME(), 2048, 65537),
            TPM2B_PUBLIC_KEY_RSA());
        auto ek = tpm.CreatePrimary(TPM_RH::ENDORSEMENT, null, ekTemplate, null, null);
        ByteVec ekPub = ek.outPublic.unique->toBytes();
        cout << "    handle  : 0x" << hex << ek.handle.handle << dec << "\n";
        cout << "    EK-pub  : " << toHex(ekPub) << "\n\n";

        // -- External encrypts sessionKey --
        string sessionKeyStr = "TOP-SECRET-2026!!";
        ByteVec sessionKey(sessionKeyStr.begin(), sessionKeyStr.end());
        cout << "[4] External: sessionKey = \"" << sessionKeyStr << "\"\n";
        ByteVec C = keyPair.outPublic.Encrypt(sessionKey, null);
        cout << "    C = tpm-pub(sessionKey)\n";
        cout << "    C : " << toHex(C) << "\n";
        cout << "    Only tpm-priv (inside chip) can open C.\n\n";

        // -- Salt --
        cout << "[5] External generates salt.\n";
        ByteVec salt = Helpers::RandomBytes(Crypto::HashLength(TPM_ALG_ID::SHA1));
        cout << "    salt          : " << toHex(salt) << "\n";
        ByteVec encryptedSalt = ek.outPublic.EncryptSessionSalt(salt);
        cout << "    encryptedSalt = EK-pub(salt)\n";
        cout << "    encryptedSalt : " << toHex(encryptedSalt) << "\n";
        cout << "    Transport only sees encryptedSalt, not salt.\n\n";

        // -- Session --
        cout << "[6] StartAuthSession: TPM decrypts encryptedSalt with EK-priv -> salt.\n";
        cout << "    Both sides derive secret = KDF(salt). Secret never transmitted.\n";
        AUTH_SESSION session = tpm.StartAuthSession(
            ek.handle, TPM_RH_NULL, TPM_SE::HMAC, TPM_ALG_ID::SHA1,
            TPMA_SESSION::continueSession | TPMA_SESSION::encrypt,
            TPMT_SYM_DEF(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
            salt, encryptedSalt);
        cout << "    Session established.\n\n";

        // -- Decrypt --
        cout << "[7] RSA_Decrypt(tpm-priv, C) over session.\n";
        cout << "    tpm-priv decrypts C -> sessionKey (inside chip).\n";
        cout << "    TPM sends secret(sessionKey) over transport.\n";
        cout << "    TSS.CPP decrypts -> sessionKey in memory.\n";
        ByteVec recovered = tpm[session].RSA_Decrypt(
            keyPair.handle, C, TPMS_NULL_ASYM_SCHEME(), null);
        cout << "    recovered : \"" << string(recovered.begin(), recovered.end()) << "\"\n";
        cout << "    correct   : " << (recovered == sessionKey ? "yes" : "NO -- MISMATCH") << "\n\n";

        // -- Cleanup --
        cout << "[8] FlushContext: releasing session, key pair, EK.\n";
        tpm.FlushContext(session);
        tpm.FlushContext(keyPair.handle);
        tpm.FlushContext(ek.handle);
        cout << "    Done.\n";
    }
    catch (const exception& e) {
        cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
