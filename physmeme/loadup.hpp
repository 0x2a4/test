#pragma once
#include <Windows.h>
#include <winternl.h>
#include <string>
#include <fstream>
#include <filesystem>
#include <random>

#pragma comment(lib, "ntdll.lib")
using nt_load_driver_t = NTSTATUS(__fastcall*)(PUNICODE_STRING);
using nt_unload_driver_t = NTSTATUS(__fastcall*)(PUNICODE_STRING);

namespace driver
{
    namespace util
    {
        inline std::string generate_random_name(std::size_t length) {
            static const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            std::string str(length, 0);
            std::mt19937 rng(std::random_device{}());
            std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);
            for (auto& c : str) c = charset[dist(rng)];
            return str;
        }

        inline bool delete_service_entry(const std::string& service_name)
        {
            HKEY reg_handle;
            static const std::string reg_key("System\\CurrentControlSet\\Services\\");

            auto result = RegOpenKeyA(HKEY_LOCAL_MACHINE, reg_key.c_str(), &reg_handle);
            bool success = ERROR_SUCCESS == RegDeleteKeyA(reg_handle, service_name.data()) &&
                ERROR_SUCCESS == RegCloseKey(reg_handle);
            if (success) printf("[+] Cleaned registry entry for %s\n", service_name.c_str());
            return success;
        }

        inline bool create_service_entry(const std::string& drv_path, const std::string& service_name)
        {
            HKEY reg_handle;
            std::string reg_key("System\\CurrentControlSet\\Services\\");
            reg_key += service_name;

            auto result = RegCreateKeyA(HKEY_LOCAL_MACHINE, reg_key.c_str(), &reg_handle);
            if (result != ERROR_SUCCESS) {
                printf("[-] Failed to create registry key\n");
                return false;
            }

            constexpr std::uint8_t type_value = 1;
            result = RegSetValueExA(reg_handle, "Type", NULL, REG_DWORD, &type_value, 4u);
            if (result != ERROR_SUCCESS) return false;

            constexpr std::uint8_t error_control_value = 3;
            result = RegSetValueExA(reg_handle, "ErrorControl", NULL, REG_DWORD, &error_control_value, 4u);
            if (result != ERROR_SUCCESS) return false;

            constexpr std::uint8_t start_value = 3;
            result = RegSetValueExA(reg_handle, "Start", NULL, REG_DWORD, &start_value, 4u);
            if (result != ERROR_SUCCESS) return false;

            std::string masquerade_path = "\\SystemRoot\\system32\\drivers\\AMDRyzenMasterDriverV" +
                generate_random_name(2) + ".sys";
            result = RegSetValueExA(reg_handle, "ImagePath", NULL, REG_SZ,
                (std::uint8_t*)masquerade_path.c_str(), masquerade_path.size());
            if (result != ERROR_SUCCESS) return false;

            printf("[+] Created service entry for %s\n", service_name.c_str());
            return ERROR_SUCCESS == RegCloseKey(reg_handle);
        }