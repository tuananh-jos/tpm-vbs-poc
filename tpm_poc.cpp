#include <iostream>
#include <string>
#include <vector>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "Tpm2.h"
#include "TpmDevice.h"

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

// ----------------------------------------------------------------
// Middle: relay between External and TPM.
// Forwards every byte verbatim. Logs what it sees at command level.
// Middle never has channelKey -> cannot decrypt session responses.
// ----------------------------------------------------------------
class MiddleDevice : public TpmDevice
{
    TpmTbsDevice& inner;
    ByteVec       lastResp;
    bool          logging = false;
    uint32_t      lastCmdCode = 0;
    ByteVec       encryptedBlob; // channelKey(sessionKey) extracted from RSA_Decrypt response

    static uint32_t parseCmdCode(const ByteVec& req)
    {
        if (req.size() < 10) return 0;
        return (uint32_t(req[6]) << 24) | (uint32_t(req[7]) << 16)
             | (uint32_t(req[8]) <<  8) |  uint32_t(req[9]);
    }

    static const char* cmdName(uint32_t cc)
    {
        switch (cc) {
            case 0x00000131: return "CreatePrimary";
            case 0x00000176: return "StartAuthSession";
            case 0x00000159: return "RSA_Decrypt";
            case 0x00000148: return "Certify";
            case 0x00000165: return "FlushContext";
            default:         return "TPM command";
        }
    }

public:
    MiddleDevice(TpmTbsDevice& d) : inner(d) {}

    bool    Connect()                          override { return inner.Connect(); }
    void    Close()                            override { inner.Close(); }
    bool    ResponseIsReady()            const override { return inner.ResponseIsReady(); }
    void    SetLogging(bool on)                        { logging = on; }
    const ByteVec& EncryptedBlob()       const         { return encryptedBlob; }

    void DispatchCommand(const ByteVec& req) override
    {
        lastCmdCode = parseCmdCode(req);
        if (logging)
            cout << "  [Middle] -> TPM  " << cmdName(lastCmdCode)
                 << "  (" << req.size() << " bytes, forwarded verbatim)\n";
        inner.DispatchCommand(req);
    }

    ByteVec GetResponse() override
    {
        lastResp = inner.GetResponse();
        if (!logging) return lastResp;

        if (lastCmdCode == 0x00000159 && lastResp.size() >= 16) {
            // TPM_ST_SESSIONS response layout:
            //   [0-1]  tag
            //   [2-5]  totalSize
            //   [6-9]  responseCode
            //   [10-13] parameterSize
            //   [14-15] TPM2B size of outData  <- first output param
            //   [16..] outData bytes            <- channelKey(sessionKey)
            uint16_t blobSize = (uint16_t(lastResp[14]) << 8) | lastResp[15];
            if (lastResp.size() >= 16u + blobSize)
                encryptedBlob = ByteVec(lastResp.begin() + 16,
                                        lastResp.begin() + 16 + blobSize);

            cout << "  [Middle] <- TPM  RSA_Decrypt response  ("
                 << lastResp.size() << " bytes)\n";
            cout << "  [Middle]         channelKey(sessionKey) = "
                 << toHex(encryptedBlob) << "\n";
            cout << "  [Middle]         no channelKey -> cannot decrypt\n";
        } else {
            cout << "  [Middle] <- TPM  " << cmdName(lastCmdCode)
                 << " response  (" << lastResp.size() << " bytes)\n";
        }
        return lastResp;
    }
};

int main()
{
    try {
        // ----------------------------------------------------------------
        // [1] Connect  (External -> Middle -> TBS -> TPM)
        // ----------------------------------------------------------------
        cout << "[1] Connecting...\n";
        TpmTbsDevice tbs;
        if (!tbs.Connect()) { cerr << "FAILED. Run as Administrator.\n"; return 1; }
        MiddleDevice middle(tbs);
        Tpm2 tpm;
        tpm._SetDevice(middle);
        cout << "    OK.  Route: External -> Middle -> TBS -> TPM\n\n";

        // ----------------------------------------------------------------
        // [2] Certification chain: EK -> AIK -> SPCK
        //     Middle relays silently (not the focus of this demo)
        // ----------------------------------------------------------------
        cout << "[2] Building certification chain: EK -> AIK -> SPCK\n";

        TPMT_PUBLIC ekTemplate(
            TPM_ALG_ID::SHA1,
            TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted | TPMA_OBJECT::fixedTPM
                | TPMA_OBJECT::fixedParent | TPMA_OBJECT::sensitiveDataOrigin
                | TPMA_OBJECT::userWithAuth,
            null, TPMS_RSA_PARMS(Aes128Cfb, TPMS_NULL_ASYM_SCHEME(), 2048, 65537),
            TPM2B_PUBLIC_KEY_RSA());

        TPMT_PUBLIC aikTemplate(
            TPM_ALG_ID::SHA1,
            TPMA_OBJECT::restricted | TPMA_OBJECT::sign | TPMA_OBJECT::fixedTPM
                | TPMA_OBJECT::fixedParent | TPMA_OBJECT::sensitiveDataOrigin
                | TPMA_OBJECT::userWithAuth,
            null, TPMS_RSA_PARMS(null, TPMS_SCHEME_RSASSA(TPM_ALG_ID::SHA1), 2048, 65537),
            TPM2B_PUBLIC_KEY_RSA());

        TPMT_PUBLIC spckTemplate(
            TPM_ALG_ID::SHA1,
            TPMA_OBJECT::decrypt | TPMA_OBJECT::userWithAuth | TPMA_OBJECT::sensitiveDataOrigin
                | TPMA_OBJECT::fixedTPM | TPMA_OBJECT::fixedParent,
            null, TPMS_RSA_PARMS(null, TPMS_SCHEME_OAEP(TPM_ALG_ID::SHA1), 2048, 65537),
            TPM2B_PUBLIC_KEY_RSA());

        auto ek   = tpm.CreatePrimary(TPM_RH::ENDORSEMENT, null, ekTemplate,   null, null);
        auto aik  = tpm.CreatePrimary(TPM_RH::OWNER,       null, aikTemplate,  null, null);
        auto spck = tpm.CreatePrimary(TPM_RH::OWNER,       null, spckTemplate, null, null);
        tpm.Certify(spck.handle, aik.handle, ByteVec{}, TPMS_NULL_SIG_SCHEME());
        tpm.FlushContext(ek.handle);
        tpm.FlushContext(aik.handle);

        cout << "    SPCK-pub : " << toHex(spck.outPublic.unique->toBytes()) << "\n";
        cout << "    Chain established. External trusts SPCK-pub via AIK cert.\n\n";

        // ----------------------------------------------------------------
        // [3] External encrypts sessionKey with SPCK-pub
        //     (local operation, no TPM call)
        // ----------------------------------------------------------------
        string sessionKeyStr = "TOP-SECRET-2026!!";
        ByteVec sessionKey(sessionKeyStr.begin(), sessionKeyStr.end());
        cout << "[3] External: sessionKey = \"" << sessionKeyStr << "\"\n";
        ByteVec C = spck.outPublic.Encrypt(sessionKey, null);
        cout << "    C = SPCK-pub(sessionKey)\n";
        cout << "    C : " << toHex(C) << "\n\n";

        // ----------------------------------------------------------------
        // [4] External generates salt, encrypts with SPCK-pub
        //     (local operation, no TPM call)
        //     salt stays with External only -- Middle never sees it
        // ----------------------------------------------------------------
        cout << "[4] External generates salt (stays with External only).\n";
        ByteVec salt = Helpers::RandomBytes(Crypto::HashLength(TPM_ALG_ID::SHA1));
        cout << "    salt          : " << toHex(salt) << "  [External only]\n";
        ByteVec encryptedSalt = spck.outPublic.EncryptSessionSalt(salt);
        cout << "    encryptedSalt : " << toHex(encryptedSalt) << "\n\n";

        // ----------------------------------------------------------------
        // [5] StartAuthSession  (External -> Middle -> TPM)
        //     External sends encryptedSalt (not salt) -- Middle relays.
        //     Both External and TPM independently derive channelKey.
        //     Middle sees the bytes but has no channelKey.
        // ----------------------------------------------------------------
        cout << "[5] StartAuthSession  (External -> Middle -> TPM)\n";
        middle.SetLogging(true);
        AUTH_SESSION session = tpm.StartAuthSession(
            spck.handle, TPM_RH_NULL, TPM_SE::HMAC, TPM_ALG_ID::SHA1,
            TPMA_SESSION::continueSession | TPMA_SESSION::encrypt,
            TPMT_SYM_DEF(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
            salt, encryptedSalt);
        middle.SetLogging(false);
        cout << "    [External] channelKey = KDF(salt, nonceCaller, nonceTPM)  [computed locally]\n";
        cout << "    [TPM]      channelKey = KDF(salt, nonceCaller, nonceTPM)  [computed in chip]\n";
        cout << "    [Middle]   channelKey = ???  [Middle never has this]\n";
        cout << "    Session established.\n\n";

        // ----------------------------------------------------------------
        // [6] RSA_Decrypt over session  (External -> Middle -> TPM)
        //     Middle forwards C to TPM.
        //     TPM decrypts C -> sessionKey, re-encrypts: channelKey(sessionKey).
        //     Middle sees channelKey(sessionKey) -- cannot decrypt.
        //     External decrypts with channelKey -> sessionKey.
        // ----------------------------------------------------------------
        cout << "[6] RSA_Decrypt  (External -> Middle -> TPM)\n";
        middle.SetLogging(true);
        ByteVec recovered = tpm[session].RSA_Decrypt(
            spck.handle, C, TPMS_NULL_ASYM_SCHEME(), null);
        middle.SetLogging(false);

        cout << "\n";
        cout << "    [External] decrypts channelKey(sessionKey) with channelKey:\n";
        cout << "    recovered : \"" << string(recovered.begin(), recovered.end()) << "\"\n";
        cout << "    correct   : " << (recovered == sessionKey ? "yes" : "NO -- MISMATCH") << "\n\n";

        // ----------------------------------------------------------------
        // [7] Cleanup
        // ----------------------------------------------------------------
        cout << "[7] FlushContext.\n";
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
