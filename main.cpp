#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>
#include <conio.h>
#include <random>
#include <iomanip>
#include <chrono>
#include <memory>
#include <thread>
#include <mutex>
#include <atomic>

DWORD processId;
HANDLE handle;

std::string signature = "00 66 C7 41 2F 00 00 C6 41 2E 00";

HANDLE GetProcessByName(const PCSTR name)
{
    DWORD pid = 0;

    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process;
    ZeroMemory(&process, sizeof(process));
    process.dwSize = sizeof(process);

    // Walkthrough all processes.
    if (Process32First(snapshot, &process))
    {
        do
        {
            // Compare process.szExeFile based on format of name, i.e., trim file path
            // trim .exe if necessary, etc.
            if (std::string(process.szExeFile) == std::string(name))
            {
                pid = process.th32ProcessID;
                processId = pid;
                break;
            }
        } while (Process32Next(snapshot, &process));
    }

    CloseHandle(snapshot);

    if (pid != 0)
    {
        return OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
    }

    return nullptr;
}

void patchBytes(void* dst, void* src, unsigned int size) {
    DWORD oldprotect;
    VirtualProtectEx(handle, dst, size, PAGE_EXECUTE_READWRITE, &oldprotect);
    WriteProcessMemory(handle, dst, src, size, 0);
    VirtualProtectEx(handle, dst, size, oldprotect, &oldprotect);
};

struct Pattern {
    std::vector<BYTE> bytes;
    std::string mask;
};

std::mutex resultsMutex;

bool compareBytes(const BYTE* data, const BYTE* mask, const char* pattern) {
    for (; *pattern; ++pattern, ++data, ++mask) {
        if (*pattern == 'x' && *data != *mask) {
            return false;
        }
    }
    return true;
}

Pattern createPattern(const std::string& sig) {
    Pattern pattern;
    const char* str = sig.c_str();
    while (*str) {
        if (*str == ' ') {
            ++str;
            continue;
        }
        if (*str == '?') {
            pattern.bytes.push_back(0);
            pattern.mask.push_back('?');
            ++str;
            if (*str == '?') {
                ++str;
            }
        } else {
            pattern.bytes.push_back(static_cast<BYTE>(std::strtoul(str, nullptr, 16)));
            pattern.mask.push_back('x');
            while (*str && *str != ' ') {
                ++str;
            }
        }
    }
    return pattern;
}

void scanMemory(HANDLE handle, void* startAddress, SIZE_T regionSize, Pattern pattern, std::atomic<void*>& foundAddress) {
    std::unique_ptr<BYTE[]> pageData(new BYTE[regionSize]);
    SIZE_T bytesRead;
    if (ReadProcessMemory(handle, startAddress, pageData.get(), regionSize, &bytesRead)) {
        const BYTE* patBytes = pattern.bytes.data();
        const char* patMask = pattern.mask.c_str();

        for (size_t i = 0; i <= bytesRead - pattern.bytes.size(); ++i) {
            if (compareBytes(pageData.get() + i, patBytes, patMask)) {
                std::lock_guard<std::mutex> lock(resultsMutex);
                foundAddress = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(startAddress) + i);
                return;
            }
        }
    }
}

void* scanSig(const std::string& sig) {
    Pattern pattern = createPattern(sig);
    std::atomic<void*> foundAddress(nullptr);

    MEMORY_BASIC_INFORMATION memInfo;
    void* currentAddress = nullptr;

    std::vector<std::thread> threads;

    while (VirtualQueryEx(handle, currentAddress, &memInfo, sizeof(memInfo)) != 0) {
        if (memInfo.State == MEM_COMMIT && memInfo.Protect != PAGE_NOACCESS) {
            threads.emplace_back(scanMemory, handle, currentAddress, memInfo.RegionSize, std::ref(pattern), std::ref(foundAddress));
            if (foundAddress) break;
        }
        currentAddress = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(currentAddress) + memInfo.RegionSize);
    }

    for (auto& thread : threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }

    return foundAddress;
}

int main() {
    handle = GetProcessByName("Minecraft.Windows.exe");
    if(handle == nullptr) {
        std::cout << "Failed to find Minecraft.Windows.exe" << std::endl;
        Sleep(30000);
        return 0;
    }

    handle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, processId);

    auto st = std::chrono::high_resolution_clock::now();
    void* sig = scanSig(signature);
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - st;
    std::cout << "Scan took " << duration.count() << " seconds." << std::endl;

    if(sig == nullptr) {
        std::cout << "Impossible to find the signature: " + signature << std::endl;
        Sleep(30000);
        return 0;
    }

    BYTE bytes1[] = {0x1};
    patchBytes(sig, bytes1, sizeof(bytes1));

    std::cout << "Successful injection to " << signature << " (" << sig << ")" << std::endl;
    Sleep(15000);
    return 0;
}