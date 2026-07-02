#include "middle.h"

#define TPM_PIPE_NAME "\\\\.\\pipe\\tpm-middle"

static bool pipeReadAll(HANDLE h, void* buf, DWORD n)
{
    BYTE* p = (BYTE*)buf;
    while (n > 0) {
        DWORD r;
        if (!ReadFile(h, p, n, &r, NULL) || r == 0) return false;
        p += r; n -= r;
    }
    return true;
}
static void pipeWriteAll(HANDLE h, const void* buf, DWORD n)
{
    const BYTE* p = (const BYTE*)buf;
    while (n > 0) {
        DWORD w;
        if (!WriteFile(h, p, n, &w, NULL) || w == 0)
            throw runtime_error("pipe write failed");
        p += w; n -= w;
    }
}

int main()
{
    try {
        // Connect to TPM via TBS (Middle owns this, External never touches it)
        Middle middle;
        if (!middle.Connect()) {
            cerr << "[Middle] FAILED to connect TBS. Run as Admin.\n";
            return 1;
        }
        middle.SetLogging(true);
        cout << "[Middle] TBS connected.\n";

        // Create named pipe -- External connects here
        HANDLE pipe = CreateNamedPipeA(
            TPM_PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1, 65536, 65536, 0, NULL);
        if (pipe == INVALID_HANDLE_VALUE) {
            cerr << "[Middle] Failed to create named pipe. Error: " << GetLastError() << "\n";
            return 1;
        }
        cout << "[Middle] Pipe ready. Waiting for External...\n\n";

        ConnectNamedPipe(pipe, NULL);
        cout << "[Middle] External connected.\n\n";

        // Relay loop: read command from External, forward to TPM, return response
        while (true) {
            uint32_t cmdSize;
            if (!pipeReadAll(pipe, &cmdSize, 4)) break;  // External disconnected

            ByteVec cmd(cmdSize);
            if (!pipeReadAll(pipe, cmd.data(), cmdSize)) break;

            cout << "[Middle] <- External  " << cmdSize << " bytes\n";

            // Middle.Relay() forwards to TBS and logs what it sees
            ByteVec resp = middle.Relay(cmd);

            uint32_t respSize = (uint32_t)resp.size();
            pipeWriteAll(pipe, &respSize, 4);
            pipeWriteAll(pipe, resp.data(), respSize);

            cout << "[Middle] -> External  " << respSize << " bytes\n\n";
        }

        cout << "[Middle] External disconnected. Done.\n";
        CloseHandle(pipe);
    }
    catch (const exception& e) {
        cerr << "[Middle] Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
