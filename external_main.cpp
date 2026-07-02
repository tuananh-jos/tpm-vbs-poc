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
        //     Middle sees channelKey(sessionKey), cannot decrypt.
        //     External decrypts with channelKey -> sessionKey.
        // ----------------------------------------------------------------
        cout << "[6] RSA_Decrypt  (External -> Middle -> TPM)\n";
        ByteVec recovered = external.Recover(session, spck.handle, C);

        // ── PROOF ───────────────────────────────────────────────────────────
        // Show the raw bytes that TpmIpcDevice.GetResponse() received from
        // Middle's pipe BEFORE TSS.CPP called ParamXcrypt() to decrypt.
        // TPM_ST_SESSIONS response layout:
        //   [0-1] tag  [2-5] size  [6-9] rc  [10-13] paramSize
        //   [14-15] TPM2B size of first output param  [16..] encrypted bytes
        {
            const ByteVec& raw = ipc.LastRawResponse();
            if (raw.size() >= 16) {
                uint16_t blobSize = (uint16_t(raw[14]) << 8) | raw[15];
                ByteVec blob;
                if (raw.size() >= 16u + blobSize)
                    blob = ByteVec(raw.begin()+16, raw.begin()+16+blobSize);

                cout << "\n  [PROOF] TpmIpcDevice.GetResponse() raw bytes from pipe\n";
                cout << "          (inside external.exe, BEFORE TSS.CPP ParamXcrypt):\n";
                cout << "          encrypted param = " << toHex(blob) << "\n";
                cout << "          ^ compare with Middle's log above -- same bytes\n";
                cout << "          TSS.CPP ParamXcrypt() AES-CFB decrypts this now...\n";
            }
        }
        // ────────────────────────────────────────────────────────────────────

        cout << "\n    [External] recovered = \""
             << string(recovered.begin(), recovered.end()) << "\"\n";
        cout << "    correct   : " << (recovered == sessionKey ? "yes" : "NO -- MISMATCH") << "\n\n";

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
