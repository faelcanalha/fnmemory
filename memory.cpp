// created by: https://github.com/faelcanalha
#include "./bypass.h"

extern "C" NTSTATUS ZwReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);
extern "C" NTSTATUS ZwWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, LPCVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);

int get_pid(const char* processName) {

    if (processName == NULL)
        return 0;
    DWORD pid = 0;
    DWORD threadCount = 0;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;

    pe.dwSize = sizeof(PROCESSENTRY32);
    Process32First(hSnap, &pe);
    while (Process32Next(hSnap, &pe)) {
        if (_tcsicmp(pe.szExeFile, processName) == 0) {
            if ((int)pe.cntThreads > threadCount) {
                threadCount = pe.cntThreads;

                pid = pe.th32ProcessID;

            }
        }
    }
    return pid;
}

BOOL c_fn_memory::set_privilege(HANDLE processhandle, std::string perm)
{
    const char* permchar = perm.c_str();
    HANDLE tokenhandle;
    LUID permissionidentifier;
    TOKEN_PRIVILEGES tokenpriv;
    if (OpenProcessToken(processhandle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenhandle))
    {
        if (LookupPrivilegeValue(NULL, permchar, &permissionidentifier))
        {
            tokenpriv.PrivilegeCount = 1;
            tokenpriv.Privileges[0].Luid = permissionidentifier;
            tokenpriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            if (AdjustTokenPrivileges(tokenhandle, false, &tokenpriv, sizeof(tokenpriv), NULL, NULL)) { return true; }
            else { return false; }
        }
        else { return false; }
    }
    else { return false; }
    CloseHandle(tokenhandle);
}
BOOL c_fn_memory::attack_process(const char* processName) {
    DWORD process_id = get_pid(processName);
    if (process_id == 0)
        return false;

    processId = process_id;
    processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
    return processHandle != nullptr;
}

std::vector<BYTE> c_fn_memory::hex_string_to_byte(const std::string& hex_string) {
    std::vector<BYTE> byte_vector;

    for (std::size_t i = 0; i < hex_string.size(); i += 3) {
        std::string byte_string = hex_string.substr(i, 2);
        BYTE byte = static_cast<BYTE>(std::strtol(byte_string.c_str(), nullptr, 16));
        byte_vector.push_back(byte);
    }

    return byte_vector;
}

std::vector<LPVOID> c_fn_memory::find_byte(const std::string& hex_sequence) {
    std::vector<BYTE> byte_sequence = hex_string_to_byte(hex_sequence);
    return find_byte(byte_sequence);
}
std::vector<LPVOID> c_fn_memory::find_byte(const std::vector<BYTE>& findPattern) {
    std::vector<LPVOID> addresses;
    
    if (processId == 0 || processHandle == NULL) return addresses;

    LPVOID baseAddress = nullptr;

    while (true) {
        MEMORY_BASIC_INFORMATION memoryInfo;
        if (VirtualQueryEx(processHandle, baseAddress, &memoryInfo, sizeof(memoryInfo)) == 0) {
            break;
        }

        if (memoryInfo.State == MEM_COMMIT &&
            (memoryInfo.Protect & PAGE_READONLY ||
                memoryInfo.Protect & PAGE_READWRITE ||
                memoryInfo.Protect & PAGE_WRITECOPY ||
                memoryInfo.Protect & PAGE_EXECUTE_READ ||
                memoryInfo.Protect & PAGE_EXECUTE_READWRITE ||
                memoryInfo.Protect & PAGE_EXECUTE_WRITECOPY)) {
            const size_t bufferSize = memoryInfo.RegionSize;
            std::vector<BYTE> buffer(bufferSize);
            ULONG bytesRead;
            if (ZwReadVirtualMemory(processHandle, memoryInfo.BaseAddress, &buffer[0], bufferSize, &bytesRead) == 0) {
                auto foundIter = std::search(buffer.begin(), buffer.end(), findPattern.begin(), findPattern.end());

                while (foundIter != buffer.end()) {
                    LPVOID byteAddress = reinterpret_cast<LPVOID>(reinterpret_cast<DWORD_PTR>(memoryInfo.BaseAddress) + std::distance(buffer.begin(), foundIter));
                    addresses.push_back(byteAddress);
                    foundIter = std::search(foundIter + 1, buffer.end(), findPattern.begin(), findPattern.end());
                }
            }
        }

        baseAddress = reinterpret_cast<LPVOID>(reinterpret_cast<DWORD_PTR>(baseAddress) + memoryInfo.RegionSize);
    }
    return addresses;
}

BOOL c_fn_memory::replace_byte(const std::string& findPattern, const std::string& replacePattern) {
    std::vector<BYTE> byte_findPattern = hex_string_to_byte(findPattern);
    std::vector<BYTE> byte_replacePattern = hex_string_to_byte(replacePattern);
    return replace_byte(byte_findPattern, byte_replacePattern);
}
BOOL c_fn_memory::replace_byte(const std::vector<BYTE>& findPattern, const std::vector<BYTE>& replacePattern) {

    size_t RepByteSize = replacePattern.size();
    if (RepByteSize <= 0) return false;

    std::vector<LPVOID> addresses = c_fn_memory::find_byte(findPattern);
    if (addresses.empty()) return false;

    for (const auto& address : addresses)
    {
        SIZE_T bytesWritten;
        ZwWriteVirtualMemory(processHandle, address, replacePattern.data(), RepByteSize, &bytesWritten);
    }
    return true;
}