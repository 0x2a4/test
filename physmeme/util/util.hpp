#pragma once
#ifndef _UTIL_HPP_
#define _UTIL_HPP_

#include <Windows.h>
#include <TlHelp32.h>
#include <cstdint>
#include <string_view>
#include <iterator>
#include <fstream>
#include <string>
#include <map>
#include <vector>
#include <ntstatus.h>
#include <winternl.h>
#include <array>
#include <algorithm>
#include <random>
#include "nt.hpp"

namespace util
{
    static std::map<std::uintptr_t, std::size_t> pmem_ranges{};

    inline bool is_valid(std::uintptr_t addr)
    {
        for (auto range : pmem_ranges)
            if (addr >= range.first && addr <= range.first + range.second)
                return true;
        return false;
    }

    inline std::string obfuscate_string(const std::string& str) {
        std::string obf = str;
        std::mt19937 rng(std::random_device{}());
        for (auto& c : obf) c ^= (rng() % 256);
        return obf;
    }

    // Anti-debug: Suspend EAC threads
    inline void suspend_eac_threads() {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return;

        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);
        if (Thread32First(snapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == GetCurrentProcessId()) continue;
                HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (thread) {
                    SuspendThread(thread);
                    CloseHandle(thread);
                }
            } while (Thread32Next(snapshot, &te));
        }
        CloseHandle(snapshot);
        printf("[+] Suspended potential EAC threads\n");
    }

    // Locate g_CiOptions for DSE bypass
    inline void* get_g_cioptions() {
        const auto ci_base = get_module_base("ci.dll");
        if (!ci_base) return nullptr;

        const auto p_idh = reinterpret_cast<PIMAGE_DOS_HEADER>(ci_base);
        const auto p_inh = reinterpret_cast<PIMAGE_NT_HEADERS>((LPBYTE)ci_base + p_idh->e_lfanew);
        const auto export_dir = p_inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!export_dir.Size || !export_dir.VirtualAddress) return nullptr;

        const auto export_base = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>((LPBYTE)ci_base + export_dir.VirtualAddress);
        return (void*)((LPBYTE)ci_base + export_base->AddressOfFunctions);
    }

    // Locate PiDDBLock
    inline void* get_piddb_lock() {
        const auto ntoskrnl_base = get_module_base("ntoskrnl.exe");
        if (!ntoskrnl_base) return nullptr;

        const auto p_idh = reinterpret_cast<PIMAGE_DOS_HEADER>(ntoskrnl_base);
        const auto p_inh = reinterpret_cast<PIMAGE_NT_HEADERS>((LPBYTE)ntoskrnl_base + p_idh->e_lfanew);
        const auto export_dir = p_inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!export_dir.Size || !export_dir.VirtualAddress) return nullptr;

        return (void*)((LPBYTE)ntoskrnl_base + export_dir.VirtualAddress + 0x10); // Offset to PiDDBLock
    }

    // Locate PiDDBCacheTable
    inline void* get_piddb_table() {
        const auto ntoskrnl_base = get_module_base("ntoskrnl.exe");
        if (!ntoskrnl_base) return nullptr;

        const auto p_idh = reinterpret_cast<PIMAGE_DOS_HEADER>(ntoskrnl_base);
        const auto p_inh = reinterpret_cast<PIMAGE_NT_HEADERS>((LPBYTE)ntoskrnl_base + p_idh->e_lfanew);
        const auto export_dir = p_inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!export_dir.Size || !export_dir.VirtualAddress) return nullptr;

        return (void*)((LPBYTE)ntoskrnl_base + export_dir.VirtualAddress + 0x20); // Offset to PiDDBCacheTable
    }

    static const auto init_ranges = ([&]() -> bool {
        HKEY h_key;
        DWORD type, size;
        LPBYTE data;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory", 0, KEY_READ, &h_key) != ERROR_SUCCESS) {
            printf("[-] Failed to open registry key for physical memory ranges\n");
            return false;
        }
        RegQueryValueEx(h_key, ".Translated", NULL, &type, NULL, &size);
        data = new BYTE[size];
        RegQueryValueEx(h_key, ".Translated", NULL, &type, data, &size);
        DWORD count = *(DWORD*)(data + 16);
        auto pmi = data + 24;
        for (int dwIndex = 0; dwIndex < count; dwIndex++) {
            pmem_ranges.emplace(*(uint64_t*)(pmi + 0), *(uint64_t*)(pmi + 8));
            pmi += 20;
        }
        delete[] data;
        RegCloseKey(h_key);
        printf("[+] Initialized physical memory ranges\n");
        return true;
        })();

    inline PIMAGE_FILE_HEADER get_file_header(void* base_addr)
    {
        if (!base_addr || *(short*)base_addr != 0x5A4D)
            return NULL;

        PIMAGE_DOS_HEADER dos_headers = reinterpret_cast<PIMAGE_DOS_HEADER>(base_addr);
        PIMAGE_NT_HEADERS nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<DWORD_PTR>(base_addr) + dos_headers->e_lfanew);
        return &nt_headers->FileHeader;
    }

    static void open_binary_file(const std::string& file, std::vector<uint8_t>& data)
    {
        std::ifstream fstr(file, std::ios::binary);
        fstr.unsetf(std::ios::skipws);
        fstr.seekg(0, std::ios::end);
        const auto file_size = fstr.tellg();
        fstr.seekg(NULL, std::ios::beg);
        data.reserve(static_cast<uint32_t>(file_size));
        data.insert(data.begin(), std::istream_iterator<uint8_t>(fstr), std::istream_iterator<uint8_t>());
    }

    static std::uintptr_t get_module_base(const char* module_name)
    {
        void* buffer = nullptr;
        DWORD buffer_size = NULL;
        NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(SystemModuleInformation),
            buffer, buffer_size, &buffer_size);

        while (status == STATUS_INFO_LENGTH_MISMATCH) {
            VirtualFree(buffer, NULL, MEM_RELEASE);
            buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(SystemModuleInformation),
                buffer, buffer_size, &buffer_size);
        }

        if (!NT_SUCCESS(status)) {
            VirtualFree(buffer, NULL, MEM_RELEASE);
            return NULL;
        }

        const auto modules = static_cast<PRTL_PROCESS_MODULES>(buffer);
        for (auto idx = 0u; idx < modules->NumberOfModules; ++idx) {
            const std::string current_module_name = std::string(
                reinterpret_cast<char*>(modules->Modules[idx].FullPathName) + modules->Modules[idx].OffsetToFileName);
            if (!_stricmp(current_module_name.c_str(), module_name)) {
                const uint64_t result = reinterpret_cast<uint64_t>(modules->Modules[idx].ImageBase);
                VirtualFree(buffer, NULL, MEM_RELEASE);
                return result;
            }
        }

        VirtualFree(buffer, NULL, MEM_RELEASE);
        return NULL;
    }

    static void* get_kernel_export(const char* module_name, const char* export_name, bool rva = false)
    {
        const auto module_base = get_module_base(module_name);
        if (!module_base)
            return nullptr;

        const auto p_idh = reinterpret_cast<PIMAGE_DOS_HEADER>(module_base);
        if (p_idh->e_magic != IMAGE_DOS_SIGNATURE)
            return nullptr;

        const auto p_inh = reinterpret_cast<PIMAGE_NT_HEADERS>((LPBYTE)module_base + p_idh->e_lfanew);
        if (p_inh->Signature != IMAGE_NT_SIGNATURE)
            return nullptr;

        const auto export_dir = p_inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!export_dir.Size || !export_dir.VirtualAddress)
            return nullptr;

        const auto export_base = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
            (LPBYTE)module_base + export_dir.VirtualAddress);
        const auto names = reinterpret_cast<PDWORD>((LPBYTE)module_base + export_base->AddressOfNames);
        const auto functions = reinterpret_cast<PDWORD>((LPBYTE)module_base + export_base->AddressOfFunctions);
        const auto ordinals = reinterpret_cast<PWORD>((LPBYTE)module_base + export_base->AddressOfNameOrdinals);

        for (DWORD i = 0; i < export_base->NumberOfNames; ++i) {
            const auto current_name = reinterpret_cast<char*>((LPBYTE)module_base + names[i]);
            if (!_stricmp(current_name, export_name)) {
                const auto function_rva = functions[ordinals[i]];
                return rva ? reinterpret_cast<void*>(function_rva) :
                    reinterpret_cast<void*>((LPBYTE)module_base + function_rva);
            }
        }
        return nullptr;
    }
}

#endif // _UTIL_HPP_