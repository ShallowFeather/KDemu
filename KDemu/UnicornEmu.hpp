#pragma once
#include <unicorn/unicorn.h>
#include <unicorn/x86.h>
#include <cstdint>
#include <vector>
#include <memory>
#include <cstdarg>
#include <malloc.h>
#include <optional>
#include "LoadPE.hpp"

class UnicornEmu {
private:
    uc_engine* uc_;

public:
    explicit UnicornEmu(uc_engine* uc) : uc_(uc) {}

    UnicornEmu& rip(uint64_t value) {
        uc_reg_write(uc_, UC_X86_REG_RIP, &value);
        return *this;
    }
    
    uint64_t rip() const {
        uint64_t value;
        uc_reg_read(uc_, UC_X86_REG_RIP, &value);
        return value;
    }

    UnicornEmu& rax(uint64_t value) {
        uc_reg_write(uc_, UC_X86_REG_RAX, &value);
        return *this;
    }
    
    uint64_t rax() const {
        uint64_t value;
        uc_reg_read(uc_, UC_X86_REG_RAX, &value);
        return value;
    }

    UnicornEmu& rbx(uint64_t value) {
        uc_reg_write(uc_, UC_X86_REG_RBX, &value);
        return *this;
    }
    
    uint64_t rbx() const {
        uint64_t value;
        uc_reg_read(uc_, UC_X86_REG_RBX, &value);
        return value;
    }

    UnicornEmu& rcx(uint64_t value) {
        uc_reg_write(uc_, UC_X86_REG_RCX, &value);
        return *this;
    }
    
    uint64_t rcx() const {
        uint64_t value;
        uc_reg_read(uc_, UC_X86_REG_RCX, &value);
        return value;
    }

    UnicornEmu& rdx(uint64_t value) {
        uc_reg_write(uc_, UC_X86_REG_RDX, &value);
        return *this;
    }
    
    uint64_t rdx() const {
        uint64_t value;
        uc_reg_read(uc_, UC_X86_REG_RDX, &value);
        return value;
    }

    UnicornEmu& rsi(uint64_t value) {
        uc_reg_write(uc_, UC_X86_REG_RSI, &value);
        return *this;
    }
    
    uint64_t rsi() const {
        uint64_t value;
        uc_reg_read(uc_, UC_X86_REG_RSI, &value);
        return value;
    }

    UnicornEmu& rdi(uint64_t value) {
        uc_reg_write(uc_, UC_X86_REG_RDI, &value);
        return *this;
    }
    
    uint64_t rdi() const {
        uint64_t value;
        uc_reg_read(uc_, UC_X86_REG_RDI, &value);
        return value;
    }

    UnicornEmu& rsp(uint64_t value) {
        uc_reg_write(uc_, UC_X86_REG_RSP, &value);
        return *this;
    }
    
    uint64_t rsp() const {
        uint64_t value;
        uc_reg_read(uc_, UC_X86_REG_RSP, &value);
        return value;
    }

    UnicornEmu& rbp(uint64_t value) {
        uc_reg_write(uc_, UC_X86_REG_RBP, &value);
        return *this;
    }
    
    uint64_t rbp() const {
        uint64_t value;
        uc_reg_read(uc_, UC_X86_REG_RBP, &value);
        return value;
    }

    UnicornEmu& r8(uint64_t value) {
        uc_reg_write(uc_, UC_X86_REG_R8, &value);
        return *this;
    }
    
    uint64_t r8() const {
        uint64_t value;
        uc_reg_read(uc_, UC_X86_REG_R8, &value);
        return value;
    }

    UnicornEmu& r9(uint64_t value) {
        uc_reg_write(uc_, UC_X86_REG_R9, &value);
        return *this;
    }
    
    uint64_t r9() const {
        uint64_t value;
        uc_reg_read(uc_, UC_X86_REG_R9, &value);
        return value;
    }

    UnicornEmu& r10(uint64_t value) {
        uc_reg_write(uc_, UC_X86_REG_R10, &value);
        return *this;
    }
    
    uint64_t r10() const {
        uint64_t value;
        uc_reg_read(uc_, UC_X86_REG_R10, &value);
        return value;
    }

    UnicornEmu& r11(uint64_t value) {
        uc_reg_write(uc_, UC_X86_REG_R11, &value);
        return *this;
    }
    
    uint64_t r11() const {
        uint64_t value;
        uc_reg_read(uc_, UC_X86_REG_R11, &value);
        return value;
    }

    UnicornEmu& r12(uint64_t value) {
        uc_reg_write(uc_, UC_X86_REG_R12, &value);
        return *this;
    }
    
    uint64_t r12() const {
        uint64_t value;
        uc_reg_read(uc_, UC_X86_REG_R12, &value);
        return value;
    }

    UnicornEmu& r13(uint64_t value) {
        uc_reg_write(uc_, UC_X86_REG_R13, &value);
        return *this;
    }
    
    uint64_t r13() const {
        uint64_t value;
        uc_reg_read(uc_, UC_X86_REG_R13, &value);
        return value;
    }

    UnicornEmu& r14(uint64_t value) {
        uc_reg_write(uc_, UC_X86_REG_R14, &value);
        return *this;
    }
    
    uint64_t r14() const {
        uint64_t value;
        uc_reg_read(uc_, UC_X86_REG_R14, &value);
        return value;
    }

    UnicornEmu& r15(uint64_t value) {
        uc_reg_write(uc_, UC_X86_REG_R15, &value);
        return *this;
    }
    
    uint64_t r15() const {
        uint64_t value;
        uc_reg_read(uc_, UC_X86_REG_R15, &value);
        return value;
    }

    UnicornEmu& cr0(uint64_t value) {
        uc_reg_write(uc_, UC_X86_REG_CR0, &value);
        return *this;
    }
    
    uint64_t cr0() const {
        uint64_t value;
        uc_reg_read(uc_, UC_X86_REG_CR0, &value);
        return value;
    }

    UnicornEmu& cr2(uint64_t value) {
        uc_reg_write(uc_, UC_X86_REG_CR2, &value);
        return *this;
    }
    
    uint64_t cr2() const {
        uint64_t value;
        uc_reg_read(uc_, UC_X86_REG_CR2, &value);
        return value;
    }

    UnicornEmu& cr3(uint64_t value) {
        uc_reg_write(uc_, UC_X86_REG_CR3, &value);
        return *this;
    }
    
    uint64_t cr3() const {
        uint64_t value;
        uc_reg_read(uc_, UC_X86_REG_CR3, &value);
        return value;
    }

    UnicornEmu& cr4(uint64_t value) {
        uc_reg_write(uc_, UC_X86_REG_CR4, &value);
        return *this;
    }
    
    uint64_t cr4() const {
        uint64_t value;
        uc_reg_read(uc_, UC_X86_REG_CR4, &value);
        return value;
    }

    UnicornEmu& cr8(uint64_t value) {
        uc_reg_write(uc_, UC_X86_REG_CR8, &value);
        return *this;
    }
    
    uint64_t cr8() const {
        uint64_t value;
        uc_reg_read(uc_, UC_X86_REG_CR8, &value);
        return value;
    }

    UnicornEmu& cs(uint64_t value) {
        uc_reg_write(uc_, UC_X86_REG_CS, &value);
        return *this;
    }
    
    uint64_t cs() const {
        uint64_t value;
        uc_reg_read(uc_, UC_X86_REG_CS, &value);
        return value;
    }

    UnicornEmu& ds(uint64_t value) {
        uc_reg_write(uc_, UC_X86_REG_DS, &value);
        return *this;
    }
    
    uint64_t ds() const {
        uint64_t value;
        uc_reg_read(uc_, UC_X86_REG_DS, &value);
        return value;
    }

    UnicornEmu& es(uint64_t value) {
        uc_reg_write(uc_, UC_X86_REG_ES, &value);
        return *this;
    }
    
    uint64_t es() const {
        uint64_t value;
        uc_reg_read(uc_, UC_X86_REG_ES, &value);
        return value;
    }

    UnicornEmu& fs(uint64_t value) {
        uc_reg_write(uc_, UC_X86_REG_FS, &value);
        return *this;
    }
    
    uint64_t fs() const {
        uint64_t value;
        uc_reg_read(uc_, UC_X86_REG_FS, &value);
        return value;
    }

    UnicornEmu& gs(uint64_t value) {
        uc_reg_write(uc_, UC_X86_REG_GS, &value);
        return *this;
    }
    
    uint64_t gs() const {
        uint64_t value;
        uc_reg_read(uc_, UC_X86_REG_GS, &value);
        return value;
    }

    UnicornEmu& ss(uint64_t value) {
        uc_reg_write(uc_, UC_X86_REG_SS, &value);
        return *this;
    }
    
    uint64_t ss() const {
        uint64_t value;
        uc_reg_read(uc_, UC_X86_REG_SS, &value);
        return value;
    }

    UnicornEmu& gs_base(uint64_t value) {
        uc_reg_write(uc_, UC_X86_REG_GS_BASE, &value);
        return *this;
    }
    
    uint64_t gs_base() const {
        uint64_t value;
        uc_reg_read(uc_, UC_X86_REG_GS_BASE, &value);
        return value;
    }

    UnicornEmu& eflags(uint64_t value) {
        uc_reg_write(uc_, UC_X86_REG_EFLAGS, &value);
        return *this;
    }
    
    uint64_t eflags() const {
        uint64_t value;
        uc_reg_read(uc_, UC_X86_REG_EFLAGS, &value);
        return value;
    }

    template<typename T>
    T read(uint64_t addr) const {
        T value;
        uc_mem_read(uc_, addr, &value, sizeof(T));
        return value;
    }

    std::vector<uint8_t> read(uint64_t addr, size_t size) const {
        std::vector<uint8_t> data(size);
        uc_mem_read(uc_, addr, data.data(), size);
        return data;
    }

    bool try_read(uint64_t addr, void* buffer, size_t size) const {
        return uc_mem_read(uc_, addr, buffer, size) == UC_ERR_OK;
    }

    template<typename T>
    std::optional<T> try_read(uint64_t addr) const {
        T value;
        if (try_read(addr, &value, sizeof(T))) {
            return value;
        }
        return std::nullopt;
    }

    template<typename T>
    UnicornEmu& write(uint64_t addr, const T& value) {
        uc_mem_write(uc_, addr, &value, sizeof(T));
        return *this;
    }

    UnicornEmu& write(uint64_t addr, const void* data, size_t size) {
        uc_err err = uc_mem_write(uc_, addr, data, size);
        return *this;
    }

    bool try_write(uint64_t addr, const void* data, size_t size) const {
        return uc_mem_write(uc_, addr, data, size) == UC_ERR_OK;
    }

    UnicornEmu& write_page(uint64_t addr, const void* data) {
        write(addr, data, 0x1000);
        return *this;
    }

    uint64_t qword(uint64_t addr) const {
        return read<uint64_t>(addr);
    }

    uint32_t dword(uint64_t addr) const {
        return read<uint32_t>(addr);
    }

    uint16_t word(uint64_t addr) const {
        return read<uint16_t>(addr);
    }

    uint8_t byte(uint64_t addr) const {
        return read<uint8_t>(addr);
    }

    UnicornEmu& qword(uint64_t addr, uint64_t value) {
        return write(addr, value);
    }

    UnicornEmu& dword(uint64_t addr, uint32_t value) {
        return write(addr, value);
    }

    UnicornEmu& word(uint64_t addr, uint16_t value) {
        return write(addr, value);
    }

    UnicornEmu& byte(uint64_t addr, uint8_t value) {
        return write(addr, value);
    }

    uint64_t alloc(size_t size, uint64_t address = 0) {
        return alloc_impl(size, address, MUC_PROT_ALL, true);
    }

    uint64_t alloc(size_t size, uint64_t address, bool show) {
        return alloc_impl(size, address, MUC_PROT_ALL, show);
    }

    uint64_t alloc(size_t size, uint64_t address, my_uc_prot prot) {
        return alloc_impl(size, address, prot, true);
    }

    uint64_t alloc(size_t size, uint64_t address, my_uc_prot prot, bool show) {
        return alloc_impl(size, address, prot, show);
    }

    uint64_t alloc_impl(size_t size, uint64_t address, my_uc_prot prot, bool show) {
        PEloader* loader = &PEloader::GetInstance();
        EnterCriticalSection(&loader->cs);

        if (show) {
            Logger::Log(true, ConsoleColor::RED, "Alloc\n");
        }

        size_t allocSize = static_cast<size_t>(PAGE_ALIGN(size));
        if (allocSize == 0) {
            LeaveCriticalSection(&loader->cs);
            return 0;
        }

        if (address == 0) {
            if (loader->lastAlloc == 0) {
                loader->lastAlloc = PEloader::AllocBase;
            }
            address = loader->lastAlloc;
            loader->lastAlloc += allocSize;
        }

        void* real_addr = _aligned_malloc(allocSize, 0x1000);
        if (!real_addr) {
            Logger::Log(true, ConsoleColor::RED, "Alloc error: _aligned_malloc failed size: %llx\n", static_cast<uint64_t>(allocSize));
            LeaveCriticalSection(&loader->cs);
            return 0;
        }

        loader->real_mem_map[address] = { real_addr, static_cast<uint64_t>(allocSize) };

        switch (prot) {
        case MUC_PROT_ALL:
            loader->real_mem_map_type_all[address] = { real_addr, prot };
            break;
        case MUC_PROT_READ:
            loader->real_mem_map_type_read[address] = { real_addr, prot };
            break;
        case MUC_PORT_READ_WRITE:
            loader->real_mem_map_type_read_write[address] = { real_addr, prot };
            break;
        default:
            break;
        }

        uc_err err = uc_mem_map_ptr(uc_, address, allocSize, prot, real_addr);
        if (err != UC_ERR_OK) {
            Logger::Log(true, ConsoleColor::RED, "Alloc error: %d\n", err);
            loader->real_mem_map.erase(address);
            loader->real_mem_map_type_all.erase(address);
            loader->real_mem_map_type_read.erase(address);
            loader->real_mem_map_type_read_write.erase(address);
            _aligned_free(real_addr);
            LeaveCriticalSection(&loader->cs);
            return 0;
        }

        if (show) {
            Logger::Log(true, ConsoleColor::DARK_YELLOW, "Memory address: %llx size: %llx\n", address, static_cast<uint64_t>(allocSize));
        }

        LeaveCriticalSection(&loader->cs);
        return address;
    }

    uint64_t HeapAlloc(uint64_t size) {
        return HeapAlloc(size, true);
    }

    uint64_t HeapAlloc(uint64_t size, bool show) {
        PEloader* loader = &PEloader::GetInstance();
        while (loader->g_running) {
            if (InterlockedCompareExchange(&loader->g_flag, 1, 0) == 0) {

                DWORD tid = GetCurrentThreadId();
                for (auto& ti : loader->Threads) {
                    if (ti->threadId != tid) {
                        ResetEvent(ti->Event);
                    }
                    else if (ti->threadId == tid) {
                        loader->errorevent = ti->Event;
                        Sleep(100);
                    }
                }

                if (show) {
                    Logger::Log(true, ConsoleColor::RED, "HeapAlloc\n");
                }
                if (loader->lastAlloc == 0) {
                    loader->lastAlloc = PEloader::AllocBase;
                }

                size_t allocSize = static_cast<size_t>(PAGE_ALIGN(size));
                uc_engine* engine = uc_;
                uc_mem_region* region = nullptr;
                uint32_t count = 0;
                uc_mem_regions(engine, &region, &count);
                bool found_gap = false;
                uint64_t alloc_addr = 0;
                if (count > 1) {
                    int start = 0;
                    for (uint32_t i = 0; i < count; i++) {
                        if (region[i].begin == PEloader::AllocBase) {
                            start = static_cast<int>(i);
                            break;
                        }
                    }
                    for (int i = start; i < static_cast<int>(count) - 1; i++) {
                        if (region[i + 1].begin - region[i].end >= allocSize) {
                            alloc_addr = PAGE_ALIGN(region[i].end);
                            found_gap = true;
                            break;
                        }
                    }
                }

                if (!found_gap) {
                    alloc_addr = loader->lastAlloc;
                }

                if (allocSize == 0) {
                    for (auto& ti : loader->Threads) {
                        SetEvent(ti->Event);
                        loader->errorevent = nullptr;
                    }
                    InterlockedExchange(&loader->g_flag, 0);
                    if (region) {
                        uc_free(region);
                    }
                    return 0;
                }

                Logger::Log(true, ConsoleColor::DARK_YELLOW, "Memory address: %llx size: %llx\n", alloc_addr, static_cast<uint64_t>(allocSize));
                bool success = false;
                void* real_addr = _aligned_malloc(allocSize, 0x1000);
                if (!real_addr) {
                    Logger::Log(true, ConsoleColor::RED, "HeapAlloc error: _aligned_malloc failed size: %llx\n", static_cast<uint64_t>(allocSize));
                }
                else {
                    loader->real_mem_map[alloc_addr] = { real_addr, static_cast<uint64_t>(allocSize) };
                    loader->real_mem_map_type_read[alloc_addr] = { real_addr, MUC_PROT_READ };
                    uc_err err = uc_mem_map_ptr(engine, alloc_addr, allocSize, UC_PROT_READ, real_addr);
                    if (err != UC_ERR_OK) {
                        Logger::Log(true, ConsoleColor::RED, "uc_mem_map_ptr failed: %d\n", err);
                        uc_mem_unmap(engine, alloc_addr, allocSize);
                        loader->real_mem_map.erase(alloc_addr);
                        loader->real_mem_map_type_read.erase(alloc_addr);
                        _aligned_free(real_addr);
                        uc_emu_stop(engine);
                    }
                    else {
                        success = true;
                    }
                }

                if (success && !found_gap) {
                    loader->lastAlloc += allocSize;
                }

                for (auto& ti : loader->Threads) {
                    SetEvent(ti->Event);
                    loader->errorevent = nullptr;
                }
                InterlockedExchange(&loader->g_flag, 0);

                if (region) {
                    uc_free(region);
                }
                return success ? alloc_addr : 0;
            }
            Sleep(100);
        }
        return 0;
    }

    void HeapFree(uint64_t addr) {
        PEloader* loader = &PEloader::GetInstance();
        uc_engine* engine = uc_;
        Logger::Log(true, ConsoleColor::RED, "HeapFree: %llx\n", addr);

        auto it = loader->real_mem_map.find(addr);
        if (it != loader->real_mem_map.end()) {
            uc_mem_unmap(engine, it->first, it->second.second);
            _aligned_free(it->second.first);
            loader->real_mem_map.erase(it);
            loader->real_mem_map_type_all.erase(addr);
            loader->real_mem_map_type_read.erase(addr);
            loader->real_mem_map_type_read_write.erase(addr);
        }
    }

    uint64_t AllocVirtPhysPage(uint64_t virtAddr) {
        PEloader* loader = &PEloader::GetInstance();
        EnterCriticalSection(&loader->cs);
        size_t pageSize = 0x1000;
        void* real_addr = _aligned_malloc(pageSize, 0x1000);
        if (!real_addr) {
            LeaveCriticalSection(&loader->cs);
            return 0;
        }

        auto physOpt = loader->kdmp.VirtTranslate(virtAddr);
        if (!physOpt.has_value()) {
            _aligned_free(real_addr);
            LeaveCriticalSection(&loader->cs);
            return 0;
        }
        uint64_t physAddr = physOpt.value();

        loader->real_mem_map[virtAddr] = { real_addr, pageSize };
        loader->real_mem_map[physAddr] = { real_addr, pageSize };

        uc_mem_map_ptr(uc_, virtAddr, pageSize, UC_PROT_ALL, real_addr);
        uc_mem_map_ptr(uc_, physAddr, pageSize, UC_PROT_ALL, real_addr);

        uc_mem_write(uc_, virtAddr, loader->kdmp.GetVirtualPage(virtAddr), pageSize);
        Logger::Log(true, ConsoleColor::DARK_YELLOW, "VirtAddr: %llx PhysAddr: %llx\n", virtAddr, physAddr);

        LeaveCriticalSection(&loader->cs);
        return virtAddr;
    }

    static uint64_t StackAlloc(ULONG AllocBytes) {
        PEloader* loader = &PEloader::GetInstance();
        uint64_t rsp = 0;
        uc_reg_read(loader->uc, UC_X86_REG_RSP, &rsp);
        rsp -= AllocBytes;
        uc_reg_write(loader->uc, UC_X86_REG_RSP, &rsp);
        return rsp;
    }

    static void StackFree(ULONG AllocBytes) {
        PEloader* loader = &PEloader::GetInstance();
        uint64_t rsp = 0;
        uc_reg_read(loader->uc, UC_X86_REG_RSP, &rsp);
        rsp += AllocBytes;
        uc_reg_write(loader->uc, UC_X86_REG_RSP, &rsp);
    }

    uc_err map(uint64_t address, size_t size, int prot = 7) {
        return uc_mem_map(uc_, address, size, prot);
    }

    uc_err unmap(uint64_t address, size_t size) {
        return uc_mem_unmap(uc_, address, size);
    }

    uc_err protect(uint64_t address, size_t size, int prot) {
        return uc_mem_protect(uc_, address, size, prot);
    }

    uc_engine* engine() const {
        return uc_;
    }



    uc_err start(uint64_t begin, uint64_t until, uint64_t timeout = 0, size_t count = 0) {
        return uc_emu_start(uc_, begin, until, timeout, count);
    }

    uc_err stop() {
        return uc_emu_stop(uc_);
    }

    uc_err hook_code(uc_hook* hh, void* callback, void* user_data = nullptr, 
                     uint64_t begin = 1, uint64_t end = 0) {
        return uc_hook_add(uc_, hh, UC_HOOK_CODE, callback, user_data, begin, end);
    }

    uc_err hook_block(uc_hook* hh, void* callback, void* user_data = nullptr, 
                      uint64_t begin = 1, uint64_t end = 0) {
        return uc_hook_add(uc_, hh, UC_HOOK_BLOCK, callback, user_data, begin, end);
    }

    uc_err hook_intr(uc_hook* hh, void* callback, void* user_data = nullptr) {
        return uc_hook_add(uc_, hh, UC_HOOK_INTR, callback, user_data, 1, 0);
    }

    uc_err hook_mem_read(uc_hook* hh, void* callback, void* user_data = nullptr, 
                         uint64_t begin = 1, uint64_t end = 0) {
        return uc_hook_add(uc_, hh, UC_HOOK_MEM_READ, callback, user_data, begin, end);
    }

    uc_err hook_mem_write(uc_hook* hh, void* callback, void* user_data = nullptr, 
                          uint64_t begin = 1, uint64_t end = 0) {
        return uc_hook_add(uc_, hh, UC_HOOK_MEM_WRITE, callback, user_data, begin, end);
    }

    uc_err hook_mem_access(uc_hook* hh, void* callback, void* user_data = nullptr, 
                           uint64_t begin = 1, uint64_t end = 0) {
        return uc_hook_add(uc_, hh, UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, callback, user_data, begin, end);
    }

    uc_err hook_mem_fetch(uc_hook* hh, void* callback, void* user_data = nullptr, 
                          uint64_t begin = 1, uint64_t end = 0) {
        return uc_hook_add(uc_, hh, UC_HOOK_MEM_FETCH, callback, user_data, begin, end);
    }

    uc_err hook_mem_invalid(uc_hook* hh, void* callback, void* user_data = nullptr) {
        return uc_hook_add(uc_, hh, UC_HOOK_MEM_UNMAPPED, callback, user_data, 1, 0);
    }

    uc_err hook_mem_read_unmapped(uc_hook* hh, void* callback, void* user_data = nullptr) {
        return uc_hook_add(uc_, hh, UC_HOOK_MEM_READ_UNMAPPED, callback, user_data, 1, 0);
    }

    uc_err hook_mem_write_unmapped(uc_hook* hh, void* callback, void* user_data = nullptr) {
        return uc_hook_add(uc_, hh, UC_HOOK_MEM_WRITE_UNMAPPED, callback, user_data, 1, 0);
    }

    uc_err hook_mem_fetch_unmapped(uc_hook* hh, void* callback, void* user_data = nullptr) {
        return uc_hook_add(uc_, hh, UC_HOOK_MEM_FETCH_UNMAPPED, callback, user_data, 1, 0);
    }

    uc_err hook_mem_prot(uc_hook* hh, void* callback, void* user_data = nullptr) {
        return uc_hook_add(uc_, hh, UC_HOOK_MEM_PROT, callback, user_data, 1, 0);
    }

    uc_err hook_mem_read_prot(uc_hook* hh, void* callback, void* user_data = nullptr) {
        return uc_hook_add(uc_, hh, UC_HOOK_MEM_READ_PROT, callback, user_data, 1, 0);
    }

    uc_err hook_mem_write_prot(uc_hook* hh, void* callback, void* user_data = nullptr) {
        return uc_hook_add(uc_, hh, UC_HOOK_MEM_WRITE_PROT, callback, user_data, 1, 0);
    }

    uc_err hook_mem_fetch_prot(uc_hook* hh, void* callback, void* user_data = nullptr) {
        return uc_hook_add(uc_, hh, UC_HOOK_MEM_FETCH_PROT, callback, user_data, 1, 0);
    }

    uc_err hook_insn_invalid(uc_hook* hh, void* callback, void* user_data = nullptr) {
        return uc_hook_add(uc_, hh, UC_HOOK_INSN_INVALID, callback, user_data, 1, 0);
    }

    uc_err hook_edge_generated(uc_hook* hh, void* callback, void* user_data = nullptr) {
        return uc_hook_add(uc_, hh, UC_HOOK_EDGE_GENERATED, callback, user_data, 1, 0);
    }

    uc_err hook_tcg_opcode(uc_hook* hh, void* callback, void* user_data = nullptr, int opcode = 0) {
        return uc_hook_add(uc_, hh, UC_HOOK_TCG_OPCODE, callback, user_data, 1, 0, opcode);
    }

    uc_err hook_add(uc_hook* hh, int type, void* callback, void* user_data = nullptr, 
                    uint64_t begin = 1, uint64_t end = 0) {
        return uc_hook_add(uc_, hh, type, callback, user_data, begin, end);
    }

    uc_err hook_del(uc_hook hh) {
        return uc_hook_del(uc_, hh);
    }

    uc_err context_alloc(uc_context** context) {
        return uc_context_alloc(uc_, context);
    }

    uc_err context_save(uc_context* context) {
        return uc_context_save(uc_, context);
    }

    uc_err context_restore(uc_context* context) {
        return uc_context_restore(uc_, context);
    }

    uc_err context_free(uc_context* context) {
        return uc_context_free(context);
    }

    uc_err ctl(uc_control_type control, ...) {
        va_list args;
        va_start(args, control);
        uc_err result = uc_ctl(uc_, control, args);
        va_end(args);
        return result;
    }

    uc_err tlb_flush() {
        return uc_ctl(uc_, UC_CTL_TLB_FLUSH, NULL);
    }

    uc_err set_cpu_model(int model) {
        return uc_ctl_set_cpu_model(uc_, model);
    }

    uc_err set_tlb_mode(int mode) {
        return uc_ctl_tlb_mode(uc_, mode);
    }

    uc_err set_page_size(uint32_t page_size) {
        return uc_ctl(uc_, UC_CTL_UC_PAGE_SIZE, page_size);
    }

    uc_err mem_regions(uc_mem_region** regions, uint32_t* count) {
        return uc_mem_regions(uc_, regions, count);
    }

    static uint32_t version(uint32_t* major = nullptr, uint32_t* minor = nullptr) {
        return uc_version(major, minor);
    }

    static bool arch_supported(uc_arch arch) {
        return uc_arch_supported(arch);
    }

    static const char* strerror(uc_err code) {
        return uc_strerror(code);
    }

    uc_err errno_func() {
        return uc_errno(uc_);
    }

    UnicornEmu& msr_write(uint32_t msr_id, uint64_t value) {
        uc_x86_msr msr = { msr_id, value };
        uc_reg_write(uc_, UC_X86_REG_MSR, &msr);
        return *this;
    }

    uint64_t msr_read(uint32_t msr_id) {
        uc_x86_msr msr = { msr_id, 0 };
        uc_reg_read(uc_, UC_X86_REG_MSR, &msr);
        return msr.value;
    }

    uc_err reg_write_batch(int* regs, void** vals, int count) {
        return uc_reg_write_batch(uc_, regs, vals, count);
    }

    uc_err reg_read_batch(int* regs, void** vals, int count) {
        return uc_reg_read_batch(uc_, regs, vals, count);
    }

    uc_err mem_map_ptr(uint64_t address, size_t size, int prot, void* ptr) {
        return uc_mem_map_ptr(uc_, address, size, prot, ptr);
    }

    uc_err free(void* mem) {
        return uc_free(mem);
    }

    UnicornEmu& eax(uint32_t value) {
        uc_reg_write(uc_, UC_X86_REG_EAX, &value);
        return *this;
    }
    
    uint32_t eax() const {
        uint32_t value;
        uc_reg_read(uc_, UC_X86_REG_EAX, &value);
        return value;
    }

    UnicornEmu& ebx(uint32_t value) {
        uc_reg_write(uc_, UC_X86_REG_EBX, &value);
        return *this;
    }
    
    uint32_t ebx() const {
        uint32_t value;
        uc_reg_read(uc_, UC_X86_REG_EBX, &value);
        return value;
    }

    UnicornEmu& ecx(uint32_t value) {
        uc_reg_write(uc_, UC_X86_REG_ECX, &value);
        return *this;
    }
    
    uint32_t ecx() const {
        uint32_t value;
        uc_reg_read(uc_, UC_X86_REG_ECX, &value);
        return value;
    }

    UnicornEmu& edx(uint32_t value) {
        uc_reg_write(uc_, UC_X86_REG_EDX, &value);
        return *this;
    }
    
    uint32_t edx() const {
        uint32_t value;
        uc_reg_read(uc_, UC_X86_REG_EDX, &value);
        return value;
    }

    UnicornEmu& esp(uint32_t value) {
        uc_reg_write(uc_, UC_X86_REG_ESP, &value);
        return *this;
    }
    
    uint32_t esp() const {
        uint32_t value;
        uc_reg_read(uc_, UC_X86_REG_ESP, &value);
        return value;
    }

    UnicornEmu& ebp(uint32_t value) {
        uc_reg_write(uc_, UC_X86_REG_EBP, &value);
        return *this;
    }
    
    uint32_t ebp() const {
        uint32_t value;
        uc_reg_read(uc_, UC_X86_REG_EBP, &value);
        return value;
    }

    UnicornEmu& esi(uint32_t value) {
        uc_reg_write(uc_, UC_X86_REG_ESI, &value);
        return *this;
    }
    
    uint32_t esi() const {
        uint32_t value;
        uc_reg_read(uc_, UC_X86_REG_ESI, &value);
        return value;
    }

    UnicornEmu& edi(uint32_t value) {
        uc_reg_write(uc_, UC_X86_REG_EDI, &value);
        return *this;
    }
    
    uint32_t edi() const {
        uint32_t value;
        uc_reg_read(uc_, UC_X86_REG_EDI, &value);
        return value;
    }

    UnicornEmu& xmm(int reg_num, const uint8_t value[16]) {
        int reg_id = UC_X86_REG_XMM0 + reg_num;
        uc_reg_write(uc_, reg_id, value);
        return *this;
    }

    void xmm(int reg_num, uint8_t value[16]) const {
        int reg_id = UC_X86_REG_XMM0 + reg_num;
        uc_reg_read(uc_, reg_id, value);
    }

    UnicornEmu& dr(int reg_num, uint64_t value) {
        int reg_id = UC_X86_REG_DR0 + reg_num;
        uc_reg_write(uc_, reg_id, &value);
        return *this;
    }

    uint64_t dr(int reg_num) const {
        uint64_t value;
        int reg_id = UC_X86_REG_DR0 + reg_num;
        uc_reg_read(uc_, reg_id, &value);
        return value;
    }

    UnicornEmu& gdtr(uint64_t base, uint32_t limit) {
        uc_x86_mmr mmr = { base, limit, 0, 0 };
        uc_reg_write(uc_, UC_X86_REG_GDTR, &mmr);
        return *this;
    }

    void gdtr(uint64_t* base, uint32_t* limit) const {
        uc_x86_mmr mmr;
        uc_reg_read(uc_, UC_X86_REG_GDTR, &mmr);
        if (base) *base = mmr.base;
        if (limit) *limit = mmr.limit;
    }

    UnicornEmu& idtr(uint64_t base, uint32_t limit) {
        uc_x86_mmr mmr = { base, limit, 0, 0 };
        uc_reg_write(uc_, UC_X86_REG_IDTR, &mmr);
        return *this;
    }

    void idtr(uint64_t* base, uint32_t* limit) const {
        uc_x86_mmr mmr;
        uc_reg_read(uc_, UC_X86_REG_IDTR, &mmr);
        if (base) *base = mmr.base;
        if (limit) *limit = mmr.limit;
    }

    UnicornEmu& tr(uint64_t value) {
        uc_reg_write(uc_, UC_X86_REG_TR, &value);
        return *this;
    }
    
    uint64_t tr() const {
        uint64_t value;
        uc_reg_read(uc_, UC_X86_REG_TR, &value);
        return value;
    }

    UnicornEmu& ldtr(uint64_t value) {
        uc_reg_write(uc_, UC_X86_REG_LDTR, &value);
        return *this;
    }
    
    uint64_t ldtr() const {
        uint64_t value;
        uc_reg_read(uc_, UC_X86_REG_LDTR, &value);
        return value;
    }

    static uc_err open(uc_engine** uc) {
        return uc_open(UC_ARCH_X86, UC_MODE_64, uc);
    }

    static uc_err close(uc_engine* uc) {
        return uc_close(uc);
    }
};

class EmuWrapper {
private:
    UnicornEmu emu;

public:
    explicit EmuWrapper(uc_engine* uc) : emu(uc) {}
    
    UnicornEmu* operator->() {
        return &emu;
    }
    
    const UnicornEmu* operator->() const {
        return &emu;
    }
};

inline EmuWrapper Emu(uc_engine* uc) {
    return EmuWrapper(uc);
}