#pragma once
#include "middle.h"

#define TPM_PIPE_NAME "\\\\.\\pipe\\tpm-middle"

// TpmDevice implementation for External process.
// Sends raw TPM command bytes to Middle via named pipe.
// External never touches TBS -- Middle owns it.
class TpmIpcDevice : public TpmDevice
{
    HANDLE  pipe = INVALID_HANDLE_VALUE;
    ByteVec lastResp;

    static void writeAll(HANDLE h, const void* buf, DWORD n)
    {
        const BYTE* p = (const BYTE*)buf;
        while (n > 0) {
            DWORD w;
            if (!WriteFile(h, p, n, &w, NULL) || w == 0)
                throw runtime_error("pipe write failed");
            p += w; n -= w;
        }
    }
    static void readAll(HANDLE h, void* buf, DWORD n)
    {
        BYTE* p = (BYTE*)buf;
        while (n > 0) {
            DWORD r;
            if (!ReadFile(h, p, n, &r, NULL) || r == 0)
                throw runtime_error("pipe read failed");
            p += r; n -= r;
        }
    }

public:
    // Retry until Middle is ready (Middle must start first).
    bool Connect() override
    {
        for (int i = 0; i < 50; ++i) {
            pipe = CreateFileA(TPM_PIPE_NAME,
                GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
            if (pipe != INVALID_HANDLE_VALUE) return true;
            if (GetLastError() == ERROR_PIPE_BUSY)
                WaitNamedPipeA(TPM_PIPE_NAME, 5000);
            else
                Sleep(200);
        }
        return false;
    }

    void Close() override
    {
        if (pipe != INVALID_HANDLE_VALUE) { CloseHandle(pipe); pipe = INVALID_HANDLE_VALUE; }
    }

    bool ResponseIsReady() const override { return true; }

    // Protocol: send [uint32 size][bytes], receive [uint32 size][bytes].
    // DispatchCommand sends AND receives -- GetResponse just returns cached result.
    void DispatchCommand(const ByteVec& req) override
    {
        uint32_t size = (uint32_t)req.size();
        writeAll(pipe, &size, 4);
        writeAll(pipe, req.data(), size);

        uint32_t respSize;
        readAll(pipe, &respSize, 4);
        lastResp.resize(respSize);
        readAll(pipe, lastResp.data(), respSize);
    }

    ByteVec GetResponse() override { return lastResp; }

    // Expose raw response bytes for proof logging.
    const ByteVec& LastRawResponse() const { return lastResp; }
};
