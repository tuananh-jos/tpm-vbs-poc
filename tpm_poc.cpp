/*
 *  tpm_poc.cpp  --  TPM 2.0 secret delivery via salted session (TSS.CPP / TSS.MSR)
 *
 *  Demonstrates that channelKey never appears in plaintext on the transport:
 *    - salt is OAEP-encrypted to EK pub; only the TPM can recover it with EK priv
 *    - both sides derive channelKey independently; the transport never sees it
 *    - TPM encrypts RSA_Decrypt response with channelKey before bytes leave the chip
 *
 *  Run as Administrator (requires Windows TBS access to the real TPM chip).
 */

#include <iostream>
#include <string>
#include <stdexcept>
#include <vector>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "Tpm2.h"

using namespace TpmCpp;
using namespace std;
typedef vector<uint8_t> ByteVec;
#define null {}
static const TPMT_SYM_DEF_OBJECT Aes128Cfb { TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB };

static string asAscii(const ByteVec& v) { return string(v.begin(), v.end()); }

static void runDelivery(Tpm2& tpm, TPM_HANDLE ekHandle, TPMT_PUBLIC& ekPub,
                        TPM_HANDLE wrapKey, const ByteVec& C,
                        const ByteVec& SECRET, bool encryptResponse)
{
    cout << "================  Delivery: RESPONSE ENCRYPTION "
         << (encryptResponse ? "ON " : "OFF") << "  ================\n";

    ByteVec salt          = Helpers::RandomBytes(Crypto::HashLength(TPM_ALG_ID::SHA1));
    ByteVec encryptedSalt = ekPub.EncryptSessionSalt(salt);

    TPMA_SESSION attrs = TPMA_SESSION::continueSession;
    if (encryptResponse)
        attrs = attrs | TPMA_SESSION::encrypt;

    AUTH_SESSION channel = tpm.StartAuthSession(
        ekHandle, TPM_RH_NULL, TPM_SE::HMAC, TPM_ALG_ID::SHA1,
        attrs, TPMT_SYM_DEF(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
        salt, encryptedSalt);

    ByteVec recovered = tpm[channel].RSA_Decrypt(wrapKey, C, TPMS_NULL_ASYM_SCHEME(), null);

    cout << "  channel : salted HMAC, tpmKey=EK, " << salt.size() << "-byte salt, AES-128-CFB\n";
    cout << "  wire    : N/A (SPI/LPC bus -- needs logic analyzer to observe OFF vs ON)\n";
    cout << "  SECRET  : \"" << asAscii(recovered) << "\"\n";
    cout << "  correct : " << ((recovered == SECRET) ? "yes" : "NO -- MISMATCH") << "\n\n";

    tpm.FlushContext(channel);
}

int main()
{
    try {
        TpmTbsDevice* tbs = new TpmTbsDevice();
        if (!tbs->Connect()) {
            cerr << "Cannot connect to TPM via Windows TBS. Run as Administrator.\n";
            return 1;
        }
        Tpm2 tpm;
        tpm._SetDevice(*tbs);
        cout << "Connected to real TPM via Windows TBS.\n\n";

        // A.1 wrapKey: non-restricted RSA decrypt key. Server encrypts SECRET to tpm-pub.
        //     tpm-priv never leaves the chip.
        cout << "[A.1] CreatePrimary: wrapKey (RSA-2048, OWNER)...\n";
        TPMT_PUBLIC wrapTemplate(
            TPM_ALG_ID::SHA1,
            TPMA_OBJECT::decrypt | TPMA_OBJECT::userWithAuth | TPMA_OBJECT::sensitiveDataOrigin
                | TPMA_OBJECT::fixedTPM | TPMA_OBJECT::fixedParent,
            null,
            TPMS_RSA_PARMS(null, TPMS_SCHEME_OAEP(TPM_ALG_ID::SHA1), 2048, 65537),
            TPM2B_PUBLIC_KEY_RSA());
        auto wrapKey = tpm.CreatePrimary(TPM_RH::OWNER, null, wrapTemplate, null, null);
        cout << "       handle 0x" << hex << wrapKey.handle.handle << dec
             << "  (tpm-priv never leaves chip)\n";

        // A.2 EK: restricted decrypt key used only as salt key for the salted session.
        cout << "[A.2] CreatePrimary: EK (RSA-2048, ENDORSEMENT)...\n";
        TPMT_PUBLIC ekTemplate(
            TPM_ALG_ID::SHA1,
            TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted | TPMA_OBJECT::fixedTPM
                | TPMA_OBJECT::fixedParent | TPMA_OBJECT::sensitiveDataOrigin
                | TPMA_OBJECT::userWithAuth,
            null,
            TPMS_RSA_PARMS(Aes128Cfb, TPMS_NULL_ASYM_SCHEME(), 2048, 65537),
            TPM2B_PUBLIC_KEY_RSA());
        auto ek = tpm.CreatePrimary(TPM_RH::ENDORSEMENT, null, ekTemplate, null, null);
        TPMT_PUBLIC ekPub = ek.outPublic;
        cout << "       handle 0x" << hex << ek.handle.handle << dec << "\n\n";

        // B. External encrypts SECRET to tpm-pub (RSA-OAEP). Hands ciphertext C to TPM.
        string secretStr = "TOP-SECRET-2026!!";
        ByteVec SECRET(secretStr.begin(), secretStr.end());
        ByteVec C = wrapKey.outPublic.Encrypt(SECRET, null);
        cout << "[B] External: SECRET=\"" << secretStr << "\"\n"
             << "    C = RSA-OAEP(tpm-pub, SECRET) = " << C.size() << " bytes\n\n";

        // C+D. External opens salted session, calls RSA_Decrypt over it. Run twice: OFF then ON.
        runDelivery(tpm, ek.handle, ekPub, wrapKey.handle, C, SECRET, false);
        runDelivery(tpm, ek.handle, ekPub, wrapKey.handle, C, SECRET, true);

        tpm.FlushContext(wrapKey.handle);
        tpm.FlushContext(ek.handle);
        cout << "Done.\n";
    }
    catch (const exception& e) {
        cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
