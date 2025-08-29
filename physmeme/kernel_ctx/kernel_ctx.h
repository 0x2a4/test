#pragma once
#ifndef _KERNEL_CTX_H_
#define _KERNEL_CTX_H_

#include <atomic>
#include <vector>
#include <thread>
#include "physmeme.hpp"

namespace physmeme
{
    inline std::pair<const char*, unsigned long> syscall_hook = { "NtTraceControl", 0 };
    inline std::atomic<void*> psyscall_func = nullptr;
    inline std::atomic<bool> is_page_found = false;
    inline unsigned long nt_page_offset = 0x1000;

    class kernel_ctx
    {
    private:
        std::uint8_t* ntoskrnl_buffer;
        std::uint32_t nt_rva;
        void map_syscall(std::uintptr_t, std::uintptr_t) const;

    public:
        kernel_ctx();
        void disable_dse();
        void spoof_hwid();
        bool clear_piddb_cache(const std::string&, const std::uint32_t);

        template<typename t>
        void read_kernel(void* addr, void* buffer, std::size_t size)
        {
            read_kernel(addr, buffer, size);
        }

        template<typename t>
        t read_kernel(void* addr)
        {
            t buffer;
            read_kernel(addr, &buffer, sizeof(t));
            return buffer;
        }

        template<typename t>
        void write_kernel(void* addr, const t& value)
        {
            write_kernel(addr, (void*)&value, sizeof(t));
        }

        void read_kernel(void* addr, void* buffer, std::size_t size);
        void write_kernel(void* addr, void* buffer, std::size_t size);
        void zero_kernel_memory(void* addr, std::size_t size);

        template<typename t, typename... args>
        t syscall(void* addr, args... arg_list)
        {
            return reinterpret_cast<t(*)(args...)>(psyscall_func.load())(std::forward<args>(arg_list)...);
        }

        void* allocate_pool(std::size_t size, POOL_TYPE pool_type);
        void* allocate_pool(std::size_t size, ULONG pool_tag, POOL_TYPE pool_type);
        PEPROCESS get_peprocess(unsigned pid) const;
        void* get_proc_base(unsigned pid) const;
    };
}

#endif // _KERNEL_CTX_H_