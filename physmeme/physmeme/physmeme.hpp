#pragma once
#ifndef _PHYSMEME_HPP_
#define _PHYSMEME_HPP_

#define WINDOWS_IGNORE_PACKING_MISMATCH // Moved to top to bypass packing mismatch
#include <windows.h>
#include <mutex>
#include <cstdint>
#include <map>
#include <random>
#include "../util/util.hpp"
#include "../loadup.hpp"
#include "../raw_driver.hpp"

#pragma pack(push, 1)
typedef struct _GIOMAP
{
    unsigned long   interface_type;
    unsigned long   bus;
    std::uintptr_t  physical_address;
    unsigned long   io_space;
    unsigned long   size;
} GIOMAP;
#pragma pack(pop)

namespace physmeme
{
    inline std::string drv_key;

    // Dynamic IOCTL code generator to evade EAC
    inline unsigned long generate_ioctl_code() {
        std::mt19937 rng(std::random_device{}());
        return 0xC3502000 | (rng() % 0xFFF); // Randomize last 12 bits
    }

    inline HANDLE load_drv()
    {
        const auto [result, key] = driver::load(raw_driver, sizeof(raw_driver));
        drv_key = key;

        // Try iaStorAVC.sys first, fallback to win32k.sys
        HANDLE h_device = CreateFile(
            "\\\\.\\iaStorAVC",
            GENERIC_READ | GENERIC_WRITE,
            NULL,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (h_device == INVALID_HANDLE_VALUE) {
            h_device = CreateFile(
                "\\\\.\\win32k",
                GENERIC_READ | GENERIC_WRITE,
                NULL,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                NULL
            );
        }

        if (h_device == INVALID_HANDLE_VALUE) {
            printf("[-] Failed to open device handle\n");
            return NULL;
        }

        printf("[+] Device handle opened successfully\n");
        return h_device;
    }

    inline bool unload_drv()
    {
        bool result = driver::unload(drv_key);
        if (!result) {
            printf("[-] Failed to unload driver\n");
        }
        else {
            printf("[+] Driver unloaded successfully\n");
        }
        return result;
    }

    inline HANDLE drv_handle = load_drv();

    inline std::uintptr_t map_phys(std::uintptr_t addr, std::size_t size)
    {
        if (!util::is_valid(addr)) {
            printf("[-] Invalid physical address: 0x%p\n", (void*)addr);
            return NULL;
        }

        GIOMAP in_buffer = { 0, 0, addr, 0, size };
        uintptr_t out_buffer[2] = { 0 };
        unsigned long returned = 0;
        unsigned long ioctl_code = generate_ioctl_code(); // Dynamic IOCTL

        // Random delay to evade EAC behavioral detection
        std::mt19937 rng(std::random_device{}());
        if (rng() % 3) Sleep(rng() % 15);

        if (!DeviceIoControl(drv_handle, ioctl_code, &in_buffer, sizeof(in_buffer),
            out_buffer, sizeof(out_buffer), &returned, NULL)) {
            printf("[-] DeviceIoControl failed for mapping: 0x%X\n", GetLastError());
            return NULL;
        }

        printf("[+] Mapped physical address: 0x%p\n", (void*)out_buffer[0]);
        return out_buffer[0];
    }

    inline bool unmap_phys(std::uintptr_t addr, std::size_t size)
    {
        uintptr_t in_buffer = addr;
        uintptr_t out_buffer[2] = { sizeof(out_buffer) };
        unsigned long returned = 0;
        unsigned long ioctl_code = generate_ioctl_code() + 4; // Offset for unmap

        // Random delay for behavioral evasion
        std::mt19937 rng(std::random_device{}());
        if (rng() % 3) Sleep(rng() % 15);

        if (!DeviceIoControl(drv_handle, ioctl_code, &in_buffer, sizeof(in_buffer),
            out_buffer, sizeof(out_buffer), &returned, NULL)) {
            printf("[-] DeviceIoControl failed for unmapping: 0x%X\n", GetLastError());
            return false;
        }

        printf("[+] Unmapped physical address: 0x%p\n", (void*)addr);
        return out_buffer[0];
    }
}

#endif // _PHYSMEME_HPP_