#pragma once
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

static string toHex(const ByteVec& v)
{
    string s;
    for (auto b : v) { char buf[3]; snprintf(buf, 3, "%02x", b); s += buf; }
    return s;
}

// ================================================================
// Middle: standalone proxy class.
//   - Owns its own TBS connection to the TPM.
//   - Relay() forwards every byte verbatim, logs what it observes.
//   - Middle never receives salt or channelKey -> cannot decrypt.
// ================================================================
class Middle
{
    TpmTbsDevice inner;
    bool         logging = false;

    static uint32_t parseCmdCode(const ByteVec& req)
    {
        if (req.size() < 10) return 0;
        return (uint32_t(req[6])<<24)|(uint32_t(req[7])<<16)
              |(uint32_t(req[8])<<8 )| uint32_t(req[9]);
    }
    static const char* cmdName(uint32_t cc)
    {
        switch (cc) {
            case 0x131: return "CreatePrimary";
            case 0x176: return "StartAuthSession";
            case 0x159: return "RSA_Decrypt";
            case 0x148: return "Certify";
            case 0x165: return "FlushContext";
            default:    return "TPM cmd";
        }
    }

public:
    bool Connect() { return inner.Connect(); }

    // Forward req to TPM verbatim, return response verbatim.
    ByteVec Relay(const ByteVec& req)
    {
        uint32_t cc = parseCmdCode(req);
        if (logging)
            cout << "  [Middle] -> TPM  " << cmdName(cc)
                 << "  (" << req.size() << " bytes, forwarded verbatim)\n";

        inner.DispatchCommand(req);
        ByteVec resp = inner.GetResponse();

        if (logging) {
            if (cc == 0x159 && resp.size() >= 18) {
                // TPM_ST_SESSIONS response layout (both encrypted and plaintext cases):
                //   [0-1] tag=0x8002  [2-5] size  [6-9] rc  [10-13] paramSize
                //   [14-15] TPM2B size of first output param  [16..] bytes
                // If session had TPMA_SESSION::encrypt: bytes = channelKey(sessionKey) -- opaque
                // If session had no encrypt flag:        bytes = sessionKey -- PLAINTEXT
                // Middle cannot tell which -- it just sees bytes.
                uint16_t paramSize = (uint16_t(resp[14]) << 8) | resp[15];
                ByteVec param;
                if (resp.size() >= 16u + paramSize)
                    param = ByteVec(resp.begin()+16, resp.begin()+16+paramSize);
                cout << "  [Middle] <- TPM  RSA_Decrypt response  (" << resp.size() << " bytes)\n";
                cout << "  [Middle]         first output param = " << toHex(param) << "\n";
                cout << "  [Middle]         (no channelKey -> cannot interpret -> forward as-is)\n";
            } else {
                cout << "  [Middle] <- TPM  " << cmdName(cc)
                     << " response  (" << resp.size() << " bytes)\n";
            }
        }
        return resp;
    }

    void SetLogging(bool on) { logging = on; }
};

// ================================================================
// MiddleDevice: thin adapter between TSS.CPP's TpmDevice interface
// and the Middle class. External's Tpm2 object routes all commands
// here, which delegates to Middle::Relay().
// ================================================================
class MiddleDevice : public TpmDevice
{
    Middle& middle;
    ByteVec lastResp;
public:
    explicit MiddleDevice(Middle& m) : middle(m) {}
    bool    Connect()                           override { return true; }
    void    Close()                             override {}
    bool    ResponseIsReady()             const override { return true; }
    void    DispatchCommand(const ByteVec& req) override { lastResp = middle.Relay(req); }
    ByteVec GetResponse()                       override { return lastResp; }
};
