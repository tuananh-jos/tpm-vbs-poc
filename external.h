#pragma once
#include "middle.h"

// ================================================================
// External: session owner. Knows salt -> derives channelKey.
//   - Routes all TPM commands through a TpmDevice (Middle).
//   - Never shares salt with Middle.
//   - Encrypts sessionKey with SPCK-pub, opens a salted HMAC
//     session, recovers sessionKey from the session-encrypted
//     response.
// ================================================================
class External
{
    Tpm2         tpm;        // TSS.CPP object, routed through Middle
    TPMT_PUBLIC  spckPub;    // trusted SPCK public key

public:
    explicit External(TpmDevice& relay) { tpm._SetDevice(relay); }

    // Raw access for cert chain setup in main.
    Tpm2& TPM() { return tpm; }

    // Called after cert chain is built -- External trusts this key.
    void TrustSPCK(const TPMT_PUBLIC& pub) { spckPub = pub; }

    // C = SPCK-pub(sessionKey) -- only SPCK-priv (in chip) can open.
    ByteVec EncryptPayload(const ByteVec& sessionKey)
    {
        return spckPub.Encrypt(sessionKey, {});
    }

    // Generate salt, wrap it, open salted HMAC session via Middle.
    // salt stays here; only encryptedSalt goes on the wire.
    AUTH_SESSION OpenSession(TPM_HANDLE saltKeyHandle)
    {
        ByteVec salt = Helpers::RandomBytes(Crypto::HashLength(TPM_ALG_ID::SHA1));
        cout << "    salt          : " << toHex(salt) << "  [External only]\n";
        ByteVec encSalt = spckPub.EncryptSessionSalt(salt);
        cout << "    encryptedSalt : " << toHex(encSalt) << "\n";

        return tpm.StartAuthSession(
            saltKeyHandle, TPM_RH_NULL, TPM_SE::HMAC, TPM_ALG_ID::SHA1,
            TPMA_SESSION::continueSession | TPMA_SESSION::encrypt,
            TPMT_SYM_DEF(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
            salt, encSalt);
    }

    // Decrypt C inside TPM over session.
    // TPM returns channelKey(sessionKey); TSS.CPP decrypts -> plaintext.
    ByteVec Recover(AUTH_SESSION& session, TPM_HANDLE spckHandle, const ByteVec& C)
    {
        return tpm[session].RSA_Decrypt(spckHandle, C, TPMS_NULL_ASYM_SCHEME(), {});
    }

    void FlushSession(AUTH_SESSION& session, TPM_HANDLE spckHandle)
    {
        tpm.FlushContext(session);
        tpm.FlushContext(spckHandle);
    }
};

