#include "kernel_ctx.h"
#include <random>

namespace physmeme
{
    // Define IoGetDeviceObjectPointer function type
    typedef NTSTATUS(NTAPI* IoGetDeviceObjectPointer_t)(PUNICODE_STRING, ACCESS_MASK, PFILE_OBJECT*, PDEVICE_OBJECT*);

    kernel_ctx::kernel_ctx()
    {
        if (psyscall_func.load() || nt_page_offset || ntoskrnl_buffer)
            return;

        nt_rva = reinterpret_cast<std::uint32_t>(
            util::get_kernel_export(
                "ntoskrnl.exe",
                syscall_hook.first,
                true
            ));

        ntoskrnl_buffer = reinterpret_cast<std::uint8_t*>(
            LoadLibraryEx("ntoskrnl.exe", NULL,
                DONT_RESOLVE_DLL_REFERENCES));

        std::vector<std::thread> search_threads;
        for (auto ranges : util::pmem_ranges)
            search_threads.emplace_back(std::thread(
                &kernel_ctx::map_syscall,
                this,
                ranges.first,
                ranges.second
            ));

        for (std::thread& search_thread : search_threads)
            search_thread.join();

        disable_dse();
        spoof_hwid();
    }

    void kernel_ctx::disable_dse() {
        auto ci_options = util::get_g_cioptions();
        if (!ci_options) {
            printf("[-] Failed to locate g_CiOptions\n");
            return;
        }

        auto options_val = read_kernel<int>(ci_options);
        options_val &= ~0x8; // Disable DSE
        write_kernel<int>(ci_options, options_val);
        printf("[+] DSE disabled via g_CiOptions patch\n");
    }

    void kernel_ctx::spoof_hwid() {
        static const auto io_get_device_object =
            util::get_kernel_export("ntoskrnl.exe", "IoGetDeviceObjectPointer");
        if (!io_get_device_object) {
            printf("[-] Failed to locate IoGetDeviceObjectPointer\n");
            return;
        }

        // Spoof disk serial
        UNICODE_STRING disk_path = RTL_CONSTANT_STRING(L"\\Device\\Harddisk0\\DR0");
        PFILE_OBJECT file_obj = nullptr;
        PDEVICE_OBJECT dev_obj = nullptr;
        NTSTATUS status = syscall<IoGetDeviceObjectPointer_t>(
            io_get_device_object, &disk_path, FILE_READ_ACCESS, &file_obj, &dev_obj
        );
        if (NT_SUCCESS(status)) {
            std::mt19937 rng(std::random_device{}());
            char fake_serial[16];
            for (int i = 0; i < 15; i++) fake_serial[i] = 'A' + (rng() % 26);
            fake_serial[15] = 0;
            write_kernel((void*)((uintptr_t)dev_obj + 0x40), fake_serial, 16);
            printf("[+] Spoofed disk serial\n");
        }

        // Spoof NIC serial
        UNICODE_STRING nic_path = RTL_CONSTANT_STRING(L"\\Device\\Tcpip_Tcp");
        status = syscall<IoGetDeviceObjectPointer_t>(
            io_get_device_object, &nic_path, FILE_READ_ACCESS, &file_obj, &dev_obj
        );
        if (NT_SUCCESS(status)) {
            char fake_nic[16];
            std::mt19937 rng(std::random_device{}());
            for (int i = 0; i < 15; i++) fake_nic[i] = '0' + (rng() % 10);
            fake_nic[15] = 0;
            write_kernel((void*)((uintptr_t)dev_obj + 0x48), fake_nic, 16);
            printf("[+] Spoofed NIC serial\n");
        }
    }

    void kernel_ctx::map_syscall(std::uintptr_t begin, std::uintptr_t end) const
    {
        if (begin + end <= 0x100000) {
            auto page_va = physmeme::map_phys(begin + nt_page_offset, end);
            if (page_va) {
                for (auto page = page_va; page < page_va + end; page += 0x1000) {
                    if (!is_page_found.load()) {
                        __try {
                            if (!memcmp(reinterpret_cast<void*>(page), ntoskrnl_buffer + nt_rva, 32)) {
                                psyscall_func.store((void*)page);
                                auto my_proc_base = reinterpret_cast<std::uintptr_t>(GetModuleHandleA(NULL));
                                auto my_proc_base_from_syscall = reinterpret_cast<std::uintptr_t>(get_proc_base(GetCurrentProcessId()));
                                if (my_proc_base != my_proc_base_from_syscall)
                                    continue;
                                is_page_found.store(true);
                                return;
                            }
                        }
                        __except (EXCEPTION_EXECUTE_HANDLER) {}
                    }
                }
                physmeme::unmap_phys(page_va, end);
            }
        }
        else {
            for (auto range = begin; range < begin + end; range += 0x100000) {
                auto page_va = physmeme::map_phys(range + nt_page_offset, 0x100000);
                if (page_va) {
                    for (auto page = page_va; page < page_va + 0x100000; page += 0x1000) {
                        if (!is_page_found.load()) {
                            __try {
                                if (!memcmp(reinterpret_cast<void*>(page), ntoskrnl_buffer + nt_rva, 32)) {
                                    psyscall_func.store((void*)page);
                                    auto my_proc_base = reinterpret_cast<std::uintptr_t>(GetModuleHandleA(NULL));
                                    auto my_proc_base_from_syscall = reinterpret_cast<std::uintptr_t>(get_proc_base(GetCurrentProcessId()));
                                    if (my_proc_base != my_proc_base_from_syscall)
                                        continue;
                                    is_page_found.store(true);
                                    return;
                                }
                            }
                            __except (EXCEPTION_EXECUTE_HANDLER) {}
                        }
                    }
                    physmeme::unmap_phys(page_va, 0x100000);
                }
            }
        }
    }

    bool kernel_ctx::clear_piddb_cache(const std::string& file_name, const std::uint32_t timestamp)
    {
        const auto piddb_lock = util::get_piddb_lock();
        const auto piddb_table = util::get_piddb_table();
        const auto ex_acquire_resource = util::get_kernel_export("ntoskrnl.exe", "ExAcquireResourceExclusiveLite");
        const auto lookup_element_table = util::get_kernel_export("ntoskrnl.exe", "RtlLookupElementGenericTableAvl");
        const auto delete_table_entry = util::get_kernel_export("ntoskrnl.exe", "RtlDeleteElementGenericTableAvl");
        const auto release_resource = util::get_kernel_export("ntoskrnl.exe", "ExReleaseResourceLite");

        if (!piddb_lock || !piddb_table || !ex_acquire_resource || !lookup_element_table || !release_resource)
            return false;

        PiDDBCacheEntry cache_entry;
        const auto drv_name = std::wstring(file_name.begin(), file_name.end());
        cache_entry.time_stamp = timestamp;
        RtlInitUnicodeString(&cache_entry.driver_name, drv_name.data());

        if (!syscall<ExAcquireResourceExclusiveLite>(
            reinterpret_cast<ExAcquireResourceExclusiveLite>(ex_acquire_resource), piddb_lock, true))
            return false;

        PIDCacheobj* found_entry_ptr = syscall<RtlLookupElementGenericTableAvl>(
            reinterpret_cast<RtlLookupElementGenericTableAvl>(lookup_element_table), piddb_table, reinterpret_cast<void*>(&cache_entry)
        );

        if (found_entry_ptr) {
            PIDCacheobj found_entry = read_kernel<PIDCacheobj>(found_entry_ptr);
            LIST_ENTRY NextEntry = read_kernel<LIST_ENTRY>(found_entry.list.Flink);
            LIST_ENTRY PrevEntry = read_kernel<LIST_ENTRY>(found_entry.list.Blink);

            PrevEntry.Flink = found_entry.list.Flink;
            NextEntry.Blink = found_entry.list.Blink;

            write_kernel<LIST_ENTRY>(found_entry.list.Blink, PrevEntry);
            write_kernel<LIST_ENTRY>(found_entry.list.Flink, NextEntry);

            syscall<RtlDeleteElementGenericTableAvl>(
                reinterpret_cast<RtlDeleteElementGenericTableAvl>(delete_table_entry), piddb_table, found_entry_ptr);

            void* result = syscall<RtlLookupElementGenericTableAvl>(
                reinterpret_cast<RtlLookupElementGenericTableAvl>(lookup_element_table), piddb_table, reinterpret_cast<void*>(&cache_entry)
            );

            syscall<ExReleaseResourceLite>(
                reinterpret_cast<ExReleaseResourceLite>(release_resource), piddb_lock);
            return !result;
        }
        syscall<ExReleaseResourceLite>(
            reinterpret_cast<ExReleaseResourceLite>(release_resource), piddb_lock);
        return false;
    }

    void* kernel_ctx::allocate_pool(std::size_t size, POOL_TYPE pool_type)
    {
        static const auto ex_alloc_pool =
            util::get_kernel_export("ntoskrnl.exe", "ExAllocatePool");
        return syscall<ExAllocatePool>(reinterpret_cast<ExAllocatePool>(ex_alloc_pool), pool_type, size);
    }

    void* kernel_ctx::allocate_pool(std::size_t size, ULONG pool_tag, POOL_TYPE pool_type)
    {
        static const auto ex_alloc_pool_with_tag =
            util::get_kernel_export("ntoskrnl.exe", "ExAllocatePoolWithTag");
        return syscall<ExAllocatePoolWithTag>(reinterpret_cast<ExAllocatePoolWithTag>(ex_alloc_pool_with_tag), pool_type, size, pool_tag);
    }

    void kernel_ctx::read_kernel(void* addr, void* buffer, std::size_t size)
    {
        static const auto mm_copy_memory =
            util::get_kernel_export("ntoskrnl.exe", "RtlCopyMemory");
        syscall<decltype(&memcpy)>(mm_copy_memory, buffer, addr, size);
    }

    void kernel_ctx::write_kernel(void* addr, void* buffer, std::size_t size)
    {
        static const auto mm_copy_memory =
            util::get_kernel_export("ntoskrnl.exe", "RtlCopyMemory");
        syscall<decltype(&memcpy)>(mm_copy_memory, addr, buffer, size);
    }

    void kernel_ctx::zero_kernel_memory(void* addr, std::size_t size)
    {
        static const auto rtl_zero_memory =
            util::get_kernel_export("ntoskrnl.exe", "RtlZeroMemory");
        syscall<decltype(&RtlSecureZeroMemory)>(rtl_zero_memory, addr, size);
    }

    PEPROCESS kernel_ctx::get_peprocess(unsigned pid) const
    {
        if (!pid)
            return {};

        PEPROCESS proc;
        static auto get_peprocess_from_pid =
            util::get_kernel_export("ntoskrnl.exe", "PsLookupProcessByProcessId");
        syscall<PsLookupProcessByProcessId>(reinterpret_cast<PsLookupProcessByProcessId>(get_peprocess_from_pid), (HANDLE)pid, &proc);
        return proc;
    }

    void* kernel_ctx::get_proc_base(unsigned pid) const
    {
        if (!pid)
            return {};

        const auto peproc = get_peprocess(pid);
        if (!peproc)
            return {};

        static auto get_section_base =
            util::get_kernel_export("ntoskrnl.exe", "PsGetProcessSectionBaseAddress");
        return syscall<PsGetProcessSectionBaseAddress>(reinterpret_cast<PsGetProcessSectionBaseAddress>(get_section_base), peproc);
    }
}