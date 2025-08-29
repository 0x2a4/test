#pragma once
#include <Windows.h>
#include <map>
#include <atomic>
#include <memory>
#include <random>

#if _M_IX86
#define OFFSET_TO_ADDRESS 0x1
#elif _M_X64
#define OFFSET_TO_ADDRESS 0x2
#endif

namespace hook
{
    static void write_to_readonly(void* addr, void* data, int size)
    {
        DWORD old_flags;
        VirtualProtect((LPVOID)addr, size, PAGE_EXECUTE_READWRITE, &old_flags);
        memcpy((void*)addr, data, size);
        VirtualProtect((LPVOID)addr, size, old_flags, &old_flags);
    }

    class detour
    {
    public:
        detour(void* addr_to_hook, void* jmp_to, bool enable = true)
            : hook_addr(addr_to_hook), detour_addr(jmp_to), hook_installed(false)
        {
            std::mt19937 rng(std::random_device{}());
            std::uniform_int_distribution<> dist(0, 255);
            for (int i = 0; i < 8; i++) junk_bytes[i] = dist(rng); // Expanded junk bytes
            memcpy(jmp_code + OFFSET_TO_ADDRESS, &jmp_to, sizeof(jmp_to));
            memcpy(jmp_code + sizeof(jmp_code) - 8, junk_bytes, 8);

            memcpy(org_bytes, hook_addr, sizeof(org_bytes));
            if (enable)
                install();
        }

        void install()
        {
            if (hook_installed.load())
                return;

            std::mt19937 rng(std::random_device{}());
            if (rng() % 3) Sleep(rng() % 20); // Random delay for behavioral evasion
            memcpy(hook_addr, jmp_code, sizeof(jmp_code));
            hook_installed.exchange(true);
        }

        void uninstall()
        {
            if (!hook_installed.load())
                return;

            std::mt19937 rng(std::random_device{}());
            if (rng() % 3) Sleep(rng() % 20); // Random delay
            memcpy(hook_addr, org_bytes, sizeof(org_bytes));
            hook_installed.exchange(false);
        }

        ~detour() { uninstall(); }
        bool installed() { return hook_installed; }
        void* hook_address() { return hook_addr; }
        void* detour_address() { return detour_addr; }
    private:
        std::atomic<bool> hook_installed;
        void* hook_addr, * detour_addr;
        std::uint8_t junk_bytes[8]; // Expanded for polymorphism

#if _M_IX86
        unsigned char jmp_code[15] = {
            0xb8, 0x0, 0x0, 0x0, 0x0,
            0xFF, 0xE0,
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
        };
#elif _M_X64
        unsigned char jmp_code[20] = {
            0x48, 0xb8,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0xff, 0xe0,
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
        };
#endif
        std::uint8_t org_bytes[sizeof(jmp_code)];
    };

    inline std::map<void*, std::unique_ptr<detour>> hooks{};
    inline void make_hook(void* addr_to_hook, void* jmp_to_addr, bool enable = true)
    {
        hooks.insert({
            addr_to_hook,
            std::make_unique<detour>(addr_to_hook, jmp_to_addr, enable)
            });
    }

    inline void enable(void* addr)
    {
        hooks.at(addr)->install();
    }

    inline void disable(void* addr)
    {
        hooks.at(addr)->uninstall();
    }

    inline void remove(void* addr)
    {
        hooks.at(addr)->~detour();
        hooks.erase(addr);
    }
}