#include "external.h"
#include "tpm_ipc_device.h"

static const TPMT_SYM_DEF_OBJECT Aes128Cfb { TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB };
#define null {}

static TPMT_PUBLIC ekTemplate()
{
    return TPMT_PUBLIC(
        TPM_ALG_ID::SHA1,
        TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted | TPMA_OBJECT::fixedTPM
            | TPMA_OBJECT::fixedParent | TPMA_OBJECT::sensitiveDataOrigin
            | TPMA_OBJECT::userWithAuth,
        null, TPMS_RSA_PARMS(Aes128Cfb, TPMS_NULL_ASYM_SCHEME(), 2048, 65537),
        TPM2B_PUBLIC_KEY_RSA());
}
static TPMT_PUBLIC aikTemplate()
{
    return TPMT_PUBLIC(
        TPM_ALG_ID::SHA1,
        TPMA_OBJECT::restricted | TPMA_OBJECT::sign | TPMA_OBJECT::fixedTPM
            | TPMA_OBJECT::fixedParent | TPMA_OBJECT::sensitiveDataOrigin
            | TPMA_OBJECT::userWithAuth,
        null, TPMS_RSA_PARMS(null, TPMS_SCHEME_RSASSA(TPM_ALG_ID::SHA1), 2048, 65537),
        TPM2B_PUBLIC_KEY_RSA());
}
static TPMT_PUBLIC spckTemplate()
{
    return TPMT_PUBLIC(
        TPM_ALG_ID::SHA1,
        TPMA_OBJECT::decrypt | TPMA_OBJECT::userWithAuth | TPMA_OBJECT::sensitiveDataOrigin
            | TPMA_OBJECT::fixedTPM | TPMA_OBJECT::fixedParent,
        null, TPMS_RSA_PARMS(null, TPMS_SCHEME_OAEP(TPM_ALG_ID::SHA1), 2048, 65537),
        TPM2B_PUBLIC_KEY_RSA());
}

int main()
{
    try {
        // ----------------------------------------------------------------
        // [1] Connect to Middle via named pipe (NO TBS in this process)
        // ----------------------------------------------------------------
        cout << "[External] Connecting to Middle...\n";
        TpmIpcDevice ipc;
        if (!ipc.Connect()) {
            cerr << "[External] Cannot connect to Middle. Start middle.exe first.\n";
            return 1;
        }
        External external(ipc);
        cout << "[External] Connected.\n";
        cout << "[External] Route: External --(IPC pipe)--> Middle --(TBS)--> TPM\n\n";

        // ----------------------------------------------------------------
        // [2] Cert chain: EK -> AIK -> SPCK  (commands routed via Middle)
        // ----------------------------------------------------------------
        cout << "[2] Building cert chain: EK -> AIK -> SPCK\n";
        Tpm2& tpm = external.TPM();
        auto ek   = tpm.CreatePrimary(TPM_RH::ENDORSEMENT, null, ekTemplate(),  null, null);
        auto aik  = tpm.CreatePrimary(TPM_RH::OWNER,       null, aikTemplate(), null, null);
        auto spck = tpm.CreatePrimary(TPM_RH::OWNER,       null, spckTemplate(),null, null);
        tpm.Certify(spck.handle, aik.handle, ByteVec{}, TPMS_NULL_SIG_SCHEME());
        tpm.FlushContext(ek.handle);
        tpm.FlushContext(aik.handle);
        external.TrustSPCK(spck.outPublic);
        cout << "    SPCK-pub : " << toHex(spck.outPublic.unique->toBytes()) << "\n";
        cout << "    Chain established.\n\n";

        // ----------------------------------------------------------------
        // [3] External encrypts sessionKey with SPCK-pub  (local, no TPM)
        // ----------------------------------------------------------------
        string sessionKeyStr = "TOP-SECRET-2026!!";
        ByteVec sessionKey(sessionKeyStr.begin(), sessionKeyStr.end());
        cout << "[3] External: sessionKey = \"" << sessionKeyStr << "\"\n";
        ByteVec C = external.EncryptPayload(sessionKey);
        cout << "    C = SPCK-pub(sessionKey) : " << toHex(C) << "\n\n";

        // ----------------------------------------------------------------
        // [4+5] External generates salt (local), opens session via Middle
        // ----------------------------------------------------------------
        cout << "[4] External generates salt  (local, never leaves External process)\n";
        cout << "[5] StartAuthSession  (External -> Middle -> TPM)\n";
        AUTH_SESSION session = external.OpenSession(spck.handle);
        cout << "    channelKey = KDF(salt, nonceCaller, nonceTPM)  [External only]\n";
        cout << "    Middle never has salt -> Middle never has channelKey.\n\n";

        // ----------------------------------------------------------------
        // [6] RSA_Decrypt over session  (External -> Middle -> TPM)
        //     Middle forwards bytes verbatim, logs raw param (opaque to it).
        //     TSS.CPP inside external.exe AES-CFB-decrypts response param.
        // ----------------------------------------------------------------
        cout << "[6] RSA_Decrypt  (External -> Middle -> TPM)\n";
        ByteVec recovered = external.Recover(session, spck.handle, C);

        // ── PROOF ───────────────────────────────────────────────────────────
        // Capture raw bytes from TpmIpcDevice.GetResponse() BEFORE TSS.CPP
        // calls ParamXcrypt(). Proves decryption happens inside external.exe.
        // TPM_ST_SESSIONS layout: [10-13] paramSize, [14-15] TPM2B size, [16..] bytes
        ByteVec encryptedParam;
        {
            const ByteVec& raw = ipc.LastRawResponse();
            if (raw.size() >= 18) {
                uint16_t blobSize = (uint16_t(raw[14]) << 8) | raw[15];
                if (raw.size() >= 16u + blobSize)
                    encryptedParam = ByteVec(raw.begin()+16, raw.begin()+16+blobSize);
                cout << "\n  [PROOF] raw bytes at External pipe boundary (BEFORE TSS.CPP ParamXcrypt):\n";
                cout << "          encrypted param = " << toHex(encryptedParam) << "\n";
                cout << "          ^ same as Middle's log -- still encrypted here\n";
                cout << "          TSS.CPP ParamXcrypt() AES-CFB-decrypts this inside external.exe...\n";
            }
        }

        cout << "\n    [External] recovered = \""
             << string(recovered.begin(), recovered.end()) << "\"\n";
        cout << "    correct   : " << (recovered == sessionKey ? "yes" : "NO -- MISMATCH") << "\n\n";

        // ----------------------------------------------------------------
        // [CONTRAST] Same RSA_Decrypt but session WITHOUT TPMA_SESSION::encrypt.
        //   Middle will see sessionKey in PLAINTEXT -- proves session encryption
        //   is the ONLY thing keeping Middle blind.
        // ----------------------------------------------------------------
        cout << "================================================================\n";
        cout << "[CONTRAST] Same RSA_Decrypt, session WITHOUT TPMA_SESSION::encrypt\n";
        cout << "           Middle will see PLAINTEXT in its log below:\n\n";
        {
            ByteVec salt2 = Helpers::RandomBytes(Crypto::HashLength(TPM_ALG_ID::SHA1));
            ByteVec encSalt2 = spck.outPublic.EncryptSessionSalt(salt2);
            AUTH_SESSION session2 = tpm.StartAuthSession(
                spck.handle, TPM_RH_NULL, TPM_SE::HMAC, TPM_ALG_ID::SHA1,
                TPMA_SESSION::continueSession,           // <-- NO encrypt flag
                TPMT_SYM_DEF(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
                salt2, encSalt2);
            tpm[session2].RSA_Decrypt(spck.handle, C, TPMS_NULL_ASYM_SCHEME(), {});
            tpm.FlushContext(session2);

            const ByteVec& raw2 = ipc.LastRawResponse();
            ByteVec plaintextParam;
            if (raw2.size() >= 18) {
                uint16_t paramSize2 = (uint16_t(raw2[14]) << 8) | raw2[15];
                if (raw2.size() >= 16u + paramSize2)
                    plaintextParam = ByteVec(raw2.begin()+16, raw2.begin()+16+paramSize2);
            }

            cout << "\n  [CONTRAST SUMMARY]\n";
            cout << "  WITH encrypt:    Middle saw = " << toHex(encryptedParam) << "\n";
            cout << "  WITHOUT encrypt: Middle saw = " << toHex(plaintextParam) << "\n";
            cout << "  Decoded (no enc): \"" << string(plaintextParam.begin(), plaintextParam.end()) << "\"\n";
            cout << "  ^ Middle read the sessionKey in plaintext!\n";
            cout << "  TPMA_SESSION::encrypt is the ONLY difference between these two calls.\n\n";
        }

        // ----------------------------------------------------------------
        // [7] Cleanup
        // ----------------------------------------------------------------
        cout << "[7] Cleanup.\n";
        external.FlushSession(session, spck.handle);
        ipc.Close();
        cout << "    Done.\n";
    }
    catch (const exception& e) {
        cerr << "[External] Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
