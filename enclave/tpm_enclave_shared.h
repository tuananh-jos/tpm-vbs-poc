#pragma once
#include <windows.h>

// Shared structs between host (VTL0) and enclave (VTL1).
// Passed via CallEnclave() -- must be plain C structs, no pointers to VTL0 memory.

#pragma pack(push, 1)

// Phase 1: host asks enclave to create wrapKey, return tpm-pub so Server can encrypt.
struct EnclavePhase1Out {
    DWORD tpmPubSize;
    BYTE  tpmPub[512];      // serialized TPMT_PUBLIC of wrapKey
    BOOL  success;
    char  error[256];
};

// Phase 2: host passes C (RSA-OAEP ciphertext from Server), enclave decrypts inside VTL1.
struct EnclavePhase2In {
    DWORD ciphertextSize;
    BYTE  ciphertext[256];  // C = tpm-pub(SECRET), 256 bytes for RSA-2048
};
struct EnclavePhase2Out {
    BOOL  success;
    DWORD secretSize;       // proof: how many bytes recovered (SECRET itself NOT returned)
    char  message[256];     // e.g. "SECRET processed in VTL1: 21 bytes"
    char  error[256];
};

#pragma pack(pop)
