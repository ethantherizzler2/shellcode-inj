#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <cstring>
DWORD FindProcessId(const char* notepad)
{
    PROCESSENTRY32 entry{};
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(snapshot, &entry))
    {
        do
        {
            if (!_stricmp(entry.szExeFile, notepad))
            {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return 0;
}

int main()
{
    const char* dll = "Module.dll"; // our dll we will load
    DWORD pid = FindProcessId("Notepad.exe");

    if (!pid)
    {
        std::cout << "Notepad.exe not found\n";
        return 0;
    }

    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    void* string = VirtualAllocEx(
        process,
        nullptr,
        100,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    WriteProcessMemory(
        process,
        string,
        dll,
        strlen(dll) + 1,
        nullptr
    );

    FARPROC loadLib = GetProcAddress(
        GetModuleHandleA("kernel32.dll"),
        "LoadLibraryA"
    );

    unsigned char shellcode[] = // our shellcode that will call LoadLibraryA
    {
        0x48,0x83,0xEC,0x28,
        0x48,0xB9,0,0,0,0,0,0,0,0,
        0x48,0xB8,0,0,0,0,0,0,0,0,
        0xFF,0xD0,
        0x48,0x83,0xC4,0x28,
        0xC3
    };

    *(void**)(shellcode + 6) = string;
    // Here we patch the shellcode so RCX points to our dll

    *(void**)(shellcode + 16) = loadLib;
     // Here we patch the shellcode with the address of LoadLibraryA

    void* shell = VirtualAllocEx(
        process,
        nullptr,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    WriteProcessMemory(
        process,
        shell,
        shellcode,
        sizeof(shellcode),
        nullptr
    );

    CreateRemoteThread(
        process,
        nullptr,
        0,
        (LPTHREAD_START_ROUTINE)shell,
        nullptr,
        0,
        nullptr
    );
    CloseHandle(process);
    std::cout << "Injected\n";
}
