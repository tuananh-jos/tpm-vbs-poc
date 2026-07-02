#include "middle.h"
#include "external.h"

// Key templates for cert chain (used in main, not owned by External/Middle)
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
        // [1] Connect
        //     Middle owns the TBS connection.
        //     External routes all TPM calls through Middle.
        // ----------------------------------------------------------------
        cout << "[1] Connecting...\n";
        Middle    middle;
        if (!middle.Connect()) { cerr << "Middle: FAILED to connect TBS. Run as Admin.\n"; return 1; }
        MiddleDevice adapter(middle);
        External  external(adapter);
        cout << "    OK.  Route: External -> Middle -> TBS -> TPM\n\n";

        // ----------------------------------------------------------------
        // [2] Certification chain: EK -> AIK -> SPCK
        //     TPM creates keys; External gets SPCK-pub to trust.
        //     Middle relays silently here.
        // ----------------------------------------------------------------
        cout << "[2] Building certification chain: EK -> AIK -> SPCK\n";
        Tpm2& tpm = external.TPM();
        auto ek   = tpm.CreatePrimary(TPM_RH::ENDORSEMENT, null, ekTemplate(),  null, null);
        auto aik  = tpm.CreatePrimary(TPM_RH::OWNER,       null, aikTemplate(), null, null);
        auto spck = tpm.CreatePrimary(TPM_RH::OWNER,       null, spckTemplate(),null, null);
        tpm.Certify(spck.handle, aik.handle, ByteVec{}, TPMS_NULL_SIG_SCHEME());
        tpm.FlushContext(ek.handle);
        tpm.FlushContext(aik.handle);

        external.TrustSPCK(spck.outPublic);
        cout << "    SPCK-pub : " << toHex(spck.outPublic.unique->toBytes()) << "\n";
        cout << "    Chain established. External trusts SPCK-pub via AIK cert.\n\n";

        // ----------------------------------------------------------------
        // [3] External encrypts sessionKey  (local, no TPM call)
        // ----------------------------------------------------------------
        string sessionKeyStr = "TOP-SECRET-2026!!";
        ByteVec sessionKey(sessionKeyStr.begin(), sessionKeyStr.end());
        cout << "[3] External: sessionKey = \"" << sessionKeyStr << "\"\n";
        ByteVec C = external.EncryptPayload(sessionKey);
        cout << "    C = SPCK-pub(sessionKey) : " << toHex(C) << "\n\n";

        // ----------------------------------------------------------------
        // [4] + [5] External opens salted HMAC session via Middle
        // ----------------------------------------------------------------
        cout << "[4] External generates salt  (local, no TPM call)\n";
        cout << "[5] StartAuthSession  (External -> Middle -> TPM)\n";
        middle.SetLogging(true);
        AUTH_SESSION session = external.OpenSession(spck.handle);
        middle.SetLogging(false);
        cout << "    [External] channelKey = KDF(salt, nonceCaller, nonceTPM)  [computed locally]\n";
        cout << "    [TPM]      channelKey = KDF(salt, nonceCaller, nonceTPM)  [computed in chip]\n";
        cout << "    [Middle]   channelKey = ???  [Middle never has salt]\n";
        cout << "    Session established.\n\n";

        // ----------------------------------------------------------------
        // [6] RSA_Decrypt over session  (External -> Middle -> TPM)
        //     Middle sees channelKey(sessionKey) -- cannot decrypt.
        //     External recovers plaintext sessionKey via channelKey.
        // ----------------------------------------------------------------
        cout << "[6] RSA_Decrypt  (External -> Middle -> TPM)\n";
        middle.SetLogging(true);
        ByteVec recovered = external.Recover(session, spck.handle, C);
        middle.SetLogging(false);

        cout << "\n";
        cout << "    [External] decrypts channelKey(sessionKey) with channelKey:\n";
        cout << "    recovered : \"" << string(recovered.begin(), recovered.end()) << "\"\n";
        cout << "    correct   : " << (recovered == sessionKey ? "yes" : "NO -- MISMATCH") << "\n\n";

        // ----------------------------------------------------------------
        // [7] Cleanup
        // ----------------------------------------------------------------
        cout << "[7] FlushContext.\n";
        external.FlushSession(session, spck.handle);
        cout << "    Done.\n";
    }
    catch (const exception& e) {
        cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
