#include "Emulate.hpp"
#include <fstream>
#include <conio.h>
#include "LoadPE.hpp"
#include "UnicornEmu.hpp"
#include "NtType.hpp"
#define MAX_INSTRUCTION_SIZE 16

PEloader* Unicorn::loader = &PEloader::GetInstance();
uint64_t Previous_address = 0;


namespace {
	constexpr size_t kPageSize = 0x1000;
	inline bool match(const uint8_t* buf, uint32_t size, std::initializer_list<uint8_t> pattern) {
		if (size < pattern.size()) return false;
		size_t i = 0;
		for (auto b : pattern) {
			if (buf[i++] != b) return false;
		}
		return true;
	}

	inline int32_t read_disp32_at(const uint8_t* buf, uint32_t size, uint32_t offset) {
		if (size < offset + 4) return 0;
		return static_cast<int32_t>(
			(uint32_t)buf[offset + 0] |
			((uint32_t)buf[offset + 1] << 8) |
			((uint32_t)buf[offset + 2] << 16) |
			((uint32_t)buf[offset + 3] << 24)
			);
	}

	inline void log_addr(const char* msg, uint64_t addr) {
		Logger::Log(true, ConsoleColor::DARK_GREEN, "%s 0x%llx \n", msg, addr);
	}
}


Unicorn::Unicorn() {

}

void Unicorn::seh_Handle(uc_engine* uc)
{
	auto emu = Emu(uc);
	uint64_t rsp = emu->rsp();
	uint64_t rip = emu->rip();
	uint64_t error = 0xC0000094;
	rsp -= 8;
	emu->qword(rsp, rip);
	emu->rcx(error);
	emu->rsp(rsp);
	emu->rip(loader->RtlRaiseStatusBase);
	Sleep(10);
}

void Unicorn::register_hook(uc_engine* uc, uint64_t address, const byte size, void* user_data)
{
	PEloader* loader = &PEloader::GetInstance();
	auto emu = Emu(uc);
	if (loader->errorevent != nullptr)
	{
		for (auto& ti : loader->Threads) {
			if (ti->threadId == GetCurrentThreadId() && loader->errorevent != ti->Event)
			{
				WaitForSingleObject(loader->errorevent, INFINITE);
				Sleep(100);
			}
		}
	}

	std::vector<uint8_t> code = emu->read(address, size);
	if (size >= 1) {
		if (match(code.data(), size, { 0xFA })) {
			Logger::Log(true, 12, "Clearing Interrupts %llx\n", address);
		}
		if (match(code.data(), size, { 0xFB })) {
			Logger::Log(true, 12, "Restoring Interrupts %llx\n", address);
		}
	}
	if (size >= 2) {
		if (match(code.data(), size, { 0x48, 0xCF })) {
			Logger::Log(true, 13, "IRET %llx\n", address);

			uint64_t old_rsp = emu->rsp();
			uint64_t old_cs = emu->cs();

			uint64_t new_rip = qword_load(uc, old_rsp + 0x00);
			uint64_t new_cs = qword_load(uc, old_rsp + 0x08);
			uint64_t new_fl = qword_load(uc, old_rsp + 0x10);
			uint64_t new_rsp = qword_load(uc, old_rsp + 0x18);
			uint64_t new_ss = qword_load(uc, old_rsp + 0x20);
			emu->eflags(new_fl);
			emu->cs(new_cs);
			emu->rsp(new_rsp);
			emu->rip(new_rip);
		}
		if (match(code.data(), size, { 0x0f, 0x05 })) {
			Logger::Log(true, 13, "SYSCALL  address: %llx \n", address);
			ShowRegister(uc);
		}
		if (match(code.data(), size, { 0x0F, 0x20 })) {
			Logger::Log(true, 13, "Read CR0 register address: %llx \n", address);
			/*return;
			uint64_t cr0 = emu->cr0();
			cr0 = 0x000000080050033;
			emu->rax(cr0);
			address += 2;
			emu->rip(address);
			ShowRegister(uc);*/
		}
		if (match(code.data(), size, { 0x0F, 0x30 })) {
			uint64_t rip = emu->rip();
			uint64_t rcx = emu->rcx();
			uint32_t edx = emu->edx();
			uint32_t eax = emu->eax();
			auto value = static_cast<uint64_t>(static_cast<uint64_t>(edx) << 32) | static_cast<uint64_t>(eax);
			if (!loader->MSRList[rcx].second.empty()) {
				Logger::Log(true, 10, "%s\n", loader->MSRList[rcx].second.c_str());
				loader->MSRList[rcx] = { value, loader->MSRList[rcx].second };
				if (loader->MSRList[rcx].second == "MSR_LSTAR") {
					uint64_t h = emu->read<uint64_t>(0xfffff30000010000);
					Logger::Log(true, 12, "Value: %llx\n", h);
				}
				Logger::Log(true, 12, "WRITE MSR: %llx Addr: %llx, value : 0x%llx \n", loader->MSRList[rcx].first, rip, value);
				emu->rax(value);
				uint64_t addr = address + 2;
				emu->rip(addr);
				return;
			}
		}
		if (match(code.data(), size, { 0x0f, 0x32 })) {
			uint64_t rcx = emu->rcx();
			Logger::Log(true, 12, "RDMSR %llx\n", rcx);
			Logger::Log(true, 10, "Addr: %llx\n", address);
			if (!loader->MSRList[rcx].second.empty()) {

				Logger::Log(true, 10, "%s\n", loader->MSRList[rcx].second.c_str());
				auto value1 = loader->MSRList[rcx].first & 0xFFFFFFFF;
				auto value2 = (loader->MSRList[rcx].first >> 32) & 0xFFFFFFFF;
				emu->eax(static_cast<uint32_t>(value1));
				emu->edx(static_cast<uint32_t>(value2));
				uint64_t addr = address + 2;
				emu->rip(addr);
				Logger::Log(true, 12, "READ MSR: %llx\n", loader->MSRList[rcx].first);
				Sleep(1000);
			}
			else {
				seh_Handle(uc);
			}

		}
		if (match(code.data(), size, { 0xCD, 0x20 }))
		{
			Logger::Log(true, 12, "INT 20\n");
			uint64_t rip = emu->rip();
			rip += 2;
			emu->rip(rip);
		}
	}

	if (size >= 3) {
		if (match(code.data(), size, { 0x0F, 0x23 })) {
			if (size >= 3) {
				uint8_t modrm = code[2];
				uint8_t reg = (modrm >> 3) & 0x7;
				if (reg <= 7) {
					int dr_reg_id = UC_X86_REG_DR0 + reg;
					uint64_t value;
					uc_reg_read(uc, dr_reg_id, &value);
					Logger::Log(true, ConsoleColor::DARK_GREEN, "DR%d  modified at 0x%llx with value 0x%llx \n", int(reg), address, value);
				}
			}
		}
		if (match(code.data(), size, { 0x0f, 0x01, 0xF8 })) {
			Logger::Log(true, ConsoleColor::RED, "SWAPGS\n");
		}
		if (match(code.data(), size, { 0x0F, 0x01, 0xF9 }))
		{
			uint64_t fake_tsc = (uint64_t)__rdtsc();
			emu->rax(fake_tsc);
			Logger::Log(true, 13, "rdtscp!!!!!!!!!!! address: %llx code: %x\n", address, code[2]);
			address += 3;
			emu->rip(address);
		}
		if (match(code.data(), size, { 0x0F, 0x20, 0xD8 }))
		{
			uint64_t rcx = emu->rcx();
			Logger::Log(true, 13, "Suck my CR3 DICK~~~~~~~~~~~~~~~~~~~~~~~~~~!!!!!!!!!!! address: %llx code: %x\n", address, code[2]);
		}

		if (match(code.data(), size, { 0x0F, 0x20 })) {
			Logger::Log(true, 13, "Read CR register address: %llx code: %x\n", address, code[2]);
		}
		if (size >= 4 && match(code.data(), size, { 0xF0, 0x0F, 0xB1 }))
		{
			uint64_t rcx = emu->rcx();
			if (code[3] == 0x0D)
			{
				int32_t disp32_alt = static_cast<int32_t>(
					(uint32_t)code[size - 4] |
					((uint32_t)code[size - 3] << 8) |
					((uint32_t)code[size - 2] << 16) |
					((uint32_t)code[size - 1] << 24)
					);
				uint64_t temp = address + size + disp32_alt;
				uint32_t temp_value = emu->read<uint32_t>(temp);
				if (temp_value != 0)
				{
					/*int o = 0;
					do {
						temp_value = emu->read<uint32_t>(temp);
						if (temp_value == 0)
							break;
					} while (true);*/
				}
			}
		}
	}

	if (size >= 4) {
		if (match(code.data(), size, { 0x41, 0x0f, 0x01 })) {
			Logger::Log(true, 13, "Read CR0 register address: %llx \n", address);
		}
	}

	Previous_address = address;
	for (auto& ti : loader->Threads) {
		if (ti->threadId == GetCurrentThreadId())
		{
			ti->paddress = address;
		}
	}
}

void Unicorn::catch_error(uc_engine* uc, int exception, void* user_data) {
	PEloader* loader = &PEloader::GetInstance();
	uint64_t rip;
	uc_reg_read(uc, UC_X86_REG_RIP, &rip);
	if (loader->peFiles[1]->Base < rip && loader->peFiles[1]->End > rip)
	{
		uc_hook t;
		uc_hook_add(uc, &t, UC_HOOK_CODE, Unicorn::register_hook, NULL, rip, rip + 10);
		return;
	}
	Logger::Log(true, ConsoleColor::DARK_GREEN, "exception # 0x%x \n", exception);
	seh_Handle(uc);
	return;
	ShowRegister(uc);
	uint64_t rsp;
	uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
	dump_stack(uc, rsp, 12);
	uint64_t ExceptionRecord, EstablisherFrame, ContextRecord, DispatcherContext;
	uc_reg_read(uc, UC_X86_REG_RCX, &ExceptionRecord);
	uc_reg_read(uc, UC_X86_REG_RDX, &EstablisherFrame);
	uc_reg_read(uc, UC_X86_REG_R8, &ContextRecord);
	uc_reg_read(uc, UC_X86_REG_R9, &DispatcherContext);
	EXCEPTION_RECORD exp;
	uc_mem_read(uc, ExceptionRecord, &exp, sizeof(exp));
	switch (exception) {
	case EXCP00_DIVZ:
	case EXCP08_DBLE:
		loader->LastException = EXCEPTION_INT_DIVIDE_BY_ZERO;
		break;
	case EXCP01_DB:
		loader->LastException = STATUS_SINGLE_STEP;
		break;
	case EXCP03_INT3:
	case 0x2d:
		loader->LastException = 0x80000003;
		break;
	case 0x20:
		return;
	case 0x29:
		loader->LastException = 0xC0000409;
		break;
	default:
		loader->LastException = STATUS_SUCCESS;
		break;
	}
	seh_Handle(uc);
}


bool Unicorn::check_is_ntFunc(uint64_t _register)
{
	for (auto& peFile : loader->peFiles) {

		if (peFile->FileName == "ntoskrnl.exe")
		{
			if (peFile->Base < _register && _register < peFile->End)
			{
				auto Ntstr = peFile->FuncRVA[_register - peFile->Base];
				Unicorn _uc{};
				if (Ntstr != "" && (
					Ntstr != "_stricmp" &&
					Ntstr != "DbgPrompt" &&
					Ntstr != "KeInitializeGuardedMutex" &&
					Ntstr != "qsort" &&
					Ntstr != "KeReadStateTimer" &&
					Ntstr != "ExAcquireSpinLockShared" &&
					Ntstr != "ExReleaseSpinLockShared" &&
					Ntstr != "memset" &&
					Ntstr != "RtlRaiseStatus" &&
					Ntstr != "__chkstk" &&
					Ntstr != "RtlUnwindEx" &&
					Ntstr != "NtQuerySystemInformation" &&
					Ntstr != "RtlUnicodeToMultiByteSize" &&
					Ntstr != "RtlUnicodeToMultiByteN")) {
					if (_uc.NtfuncMap.find(Ntstr) == _uc.NtfuncMap.end())
					{
						Logger::Log(true, ConsoleColor::DARK_GREEN, "Previous_address : 0x%llx\n", Previous_address);
						Logger::Log(true, 5, "NT Function %s \n", Ntstr.c_str());
						return true;
					}
				}
			}
		}
		else if (peFile->FileName == "cng.sys")
		{
			if (peFile->Base < _register && _register < peFile->End)
			{
				auto str = peFile->FuncRVA[_register - peFile->Base];
				if (str != "") {
					Logger::Log(true, 5, "Cng Function %s \n", str.c_str());
					return true;
				}
			}
		}
		else if (peFile->FileName == "CI.dll")
		{
			if (peFile->Base < _register && _register < peFile->End)
			{
				auto str = peFile->FuncRVA[_register - peFile->Base];
				if (str != "" && (str != "CiFreePolicyInfo" && str != "CiCheckSignedFile" && str != "KeInitializeGuardedMutex"))
				{
					Logger::Log(true, 5, "Ci Function %s \n", str.c_str());

					return true;
				}
			}
		}
		else
		{

			if (peFile->Base < _register && _register < peFile->End)
			{
				Logger::Log(true, ConsoleColor::DARK_GREEN, "next RIP : %llx \n", _register);
				return true;
			}
		}

	}
	return false;
}

bool Unicorn::hook_mem_invalid(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data) {
	DWORD tid = GetCurrentThreadId();

	for (auto& ti : loader->Threads) {
		ResetEvent(ti->Event);
		if (ti->threadId == tid) {
			if (loader->errorevent != nullptr && loader->errorevent != ti->Event)
			{
				WaitForSingleObject(loader->errorevent, INFINITE);
				Sleep(10);
			}
			loader->errorevent = ti->Event;
			Previous_address = ti->paddress;
			Sleep(10);
		}
	}

	uint32_t count;
	uint64_t msize, rip, rsp;
	my_uc_prot my_ucport;
	void* real_addr = nullptr;
	uc_hook trace;
	size_t page_size = 0x1000;
	uint64_t aligned_address = address & ~0xFFF;

	std::vector<uint8_t> memory_data;
	uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
	uc_reg_read(uc, UC_X86_REG_RIP, &rip);

	uc_err err, check;
	switch (type) {
	case UC_MEM_WRITE_PROT:
		for (auto& map : loader->real_mem_map_type_read)
		{
			aligned_address = map.first;
			msize = loader->real_mem_map[aligned_address].second;
			real_addr = map.second.first;
			if (aligned_address <= address && address <= aligned_address + msize - 1)
			{
				break;
			}
		}
		if (real_addr != nullptr)
		{
			uc_err err = uc_mem_protect(uc, aligned_address, msize, MUC_PORT_READ_WRITE);
			if (err != UC_ERR_OK) {
				Logger::Log(true, ConsoleColor::YELLOW, "uc_mem_protect failed at %llx err : %llx\n", aligned_address, err);
				return false;
			}
			loader->real_mem_map_type_read_write[aligned_address] = { real_addr, MUC_PORT_READ_WRITE };
			loader->real_mem_map_type_all.erase(aligned_address);
			loader->real_mem_map_type_read.erase(aligned_address);

			Logger::Log(true, ConsoleColor::YELLOW, "UC_MEM_WRITE_PROT memory AT %llx  msize : %llx\n", address, msize);
		}

		break;
	case UC_MEM_FETCH_PROT:
		for (auto& map : loader->real_mem_map_type_read)
		{
			aligned_address = map.first;
			msize = loader->real_mem_map[aligned_address].second;
			real_addr = map.second.first;
			if (aligned_address <= address && address <= aligned_address + msize - 1)
			{
				break;
			}
		}
		if (real_addr != nullptr)
		{
			check = uc_mem_protect(uc, aligned_address, msize, MUC_PROT_ALL);
			Logger::Log(true, ConsoleColor::RED, "EXECUTE on non-executable memory at 0x%llx\n", address);
			loader->real_mem_map_type_all[aligned_address] = { real_addr ,MUC_PROT_ALL };
			loader->real_mem_map_type_read_write.erase(aligned_address);
			loader->real_mem_map_type_read.erase(aligned_address);
			return true;
		}
		break;
	case UC_MEM_READ_UNMAPPED:

		for (auto& map : loader->real_mem_map)
		{
			aligned_address = map.first;
			msize = map.second.second;
			real_addr = map.second.first;
			my_ucport = loader->real_mem_map_type_read[aligned_address].second;
			if (my_ucport == 0)
			{
				my_ucport = loader->real_mem_map_type_read_write[aligned_address].second;
				loader->real_mem_map_type_read.erase(aligned_address);
			}

			if (my_ucport == 0)
			{
				my_ucport = loader->real_mem_map_type_all[aligned_address].second;
				loader->real_mem_map_type_read_write.erase(aligned_address);
			}

			if (aligned_address <= address && address <= aligned_address + msize - 1)
			{
				Logger::Log(true, ConsoleColor::RED, "UC_MEM_READ_UNMAPPED Remap Region AT %llx, %llx size : %llx\n",
					aligned_address,
					real_addr,
					msize);
				err = uc_mem_map_ptr(uc, aligned_address, msize, my_ucport, real_addr);
				if (err != UC_ERR_OK) {
					Logger::Log(true, ConsoleColor::YELLOW, "UC_MEM_READ_UNMAPPED failed at %llx err : %d\n", aligned_address, err);
					return false;
				}
				for (auto& ti : loader->Threads) {
					SetEvent(ti->Event);
					loader->errorevent = nullptr;
				}
				return true;
			}
		}
		aligned_address = address & ~0xFFF;

		if (aligned_address > 0)
		{
			auto page1 = loader->kdmp.GetVirtualPage(aligned_address);
			if (page1 != 0)
			{
				Emu(uc)->alloc(kPageSize, aligned_address, false);
				err = uc_mem_write(uc, aligned_address, loader->kdmp.GetVirtualPage(aligned_address), 0x1000);
				if (err != UC_ERR_OK)
				{
					Logger::Log(true, ConsoleColor::RED, "READ from unmapped memory Address error: %d\n", err);
				}
				break;
			}
			else {
				Logger::Log(true, ConsoleColor::RED, "KDMP not found address: 0x%llx\n", address);
				Emu(uc)->alloc(kPageSize, aligned_address, MUC_PROT_READ);
			}
		}

		Logger::Log(true, ConsoleColor::RED, "------------------------------\n");
		Logger::Log(true, ConsoleColor::RED, "READ from unmapped memory Address : 0x%llx\n", address);
		Logger::Log(true, ConsoleColor::RED, "------------------------------\n");
		Logger::Log(true, ConsoleColor::DARK_GREEN, "Previous_address : %llx\n", Previous_address);
		Logger::Log(true, ConsoleColor::RED, "------------------------------\n");
		break;
	case UC_MEM_WRITE_UNMAPPED:

		for (auto& map : loader->real_mem_map)
		{
			aligned_address = map.first;
			msize = map.second.second;
			real_addr = map.second.first;
			my_ucport = loader->real_mem_map_type_read[aligned_address].second;
			if (my_ucport == 0)
			{
				my_ucport = loader->real_mem_map_type_read_write[aligned_address].second;
				loader->real_mem_map_type_read.erase(aligned_address);
			}

			if (my_ucport == 0)
			{
				my_ucport = loader->real_mem_map_type_all[aligned_address].second;
				loader->real_mem_map_type_read_write.erase(aligned_address);
			}

			if (aligned_address <= address && address <= aligned_address + msize - 1)
			{
				Logger::Log(true, ConsoleColor::RED, "UC_MEM_WRITE_UNMAPPED Remap Region AT %llx, %llx size : %llx\n",
					aligned_address,
					real_addr,
					msize);
				err = uc_mem_map_ptr(uc, aligned_address, msize, my_ucport, real_addr);

				if (err != UC_ERR_OK) {
					Logger::Log(true, ConsoleColor::YELLOW, "UC_MEM_WRITE_UNMAPPED failed at %llx err : %d\n", aligned_address, err);
					return false;
				}
				for (auto& ti : loader->Threads) {
					SetEvent(ti->Event);
					loader->errorevent = nullptr;
				}
				return true;
			}
		}
		aligned_address = address & ~0xFFF;

		if (aligned_address > 0)
		{
			auto page1 = loader->kdmp.GetVirtualPage(aligned_address);
			if (page1 != 0)
			{
				Emu(uc)->alloc(kPageSize, aligned_address, false);
				uc_mem_write(uc, aligned_address, loader->kdmp.GetVirtualPage(aligned_address), 0x1000);
				break;
			}
			else {
				Logger::Log(true, ConsoleColor::RED, "KDMP not found address: 0x%llx\n", address);
				Emu(uc)->alloc(kPageSize, aligned_address, MUC_PROT_ALL);
			}
		}
		ShowRegister(uc);
		dump_stack(uc, rsp, 10);
		break;
	case UC_MEM_FETCH_UNMAPPED:
		for (auto& map : loader->real_mem_map)
		{
			aligned_address = map.first;
			msize = map.second.second;
			real_addr = map.second.first;
			my_ucport = loader->real_mem_map_type_read[aligned_address].second;
			if (my_ucport == 0)
			{
				my_ucport = loader->real_mem_map_type_read_write[aligned_address].second;
				loader->real_mem_map_type_read.erase(aligned_address);
			}

			if (my_ucport == 0)
			{
				my_ucport = loader->real_mem_map_type_all[aligned_address].second;
				loader->real_mem_map_type_read_write.erase(aligned_address);
			}
			if (aligned_address <= address && address <= aligned_address + msize - 1)
			{
				Logger::Log(true, ConsoleColor::RED, "UC_MEM_FETCH_UNMAPPED Remap Region AT %llx, %llx size : %llx\n",
					aligned_address,
					real_addr,
					msize);
				err = uc_mem_map_ptr(uc, aligned_address, msize, my_ucport, real_addr);

				if (err != UC_ERR_OK) {
					Logger::Log(true, ConsoleColor::YELLOW, "UC_MEM_FETCH_UNMAPPED failed at %llx err : %d\n", aligned_address, err);
					return false;
				}
				for (auto& ti : loader->Threads) {
					SetEvent(ti->Event);
					loader->errorevent = nullptr;
				}
				return true;
			}
		}
		for (auto& map : loader->real_mem_map)
		{
			aligned_address = map.first;
			msize = loader->real_mem_map[aligned_address].second;
			real_addr = map.second.first;
			if (my_ucport == 0)
				my_ucport = loader->real_mem_map_type_read[aligned_address].second;
			if (my_ucport == 0)
				my_ucport = loader->real_mem_map_type_read_write[aligned_address].second;
			if (my_ucport == 0)
				my_ucport = loader->real_mem_map_type_all[aligned_address].second;
			if (aligned_address <= address && address <= aligned_address + msize - 1)
			{
				Logger::Log(true, ConsoleColor::RED, "UC_MEM_FETCH_UNMAPPED Remap Region AT %llx, %llx size : %llx\n",
					aligned_address,
					real_addr,
					msize);
				err = uc_mem_map_ptr(uc, aligned_address, msize, my_ucport, real_addr);

				if (err != UC_ERR_OK) {
					Logger::Log(true, ConsoleColor::YELLOW, "UC_MEM_FETCH_UNMAPPED failed at %llx err : %d\n", aligned_address, err);
					return false;
				}
				for (auto& ti : loader->Threads) {
					SetEvent(ti->Event);
					loader->errorevent = nullptr;
				}
				return true;
			}
		}
		aligned_address = address & ~0xFFF;
		if (aligned_address > 0)
		{

			auto page2 = loader->kdmp.GetVirtualPage(aligned_address);
			if (page2 != 0)
			{
				Emu(uc)->alloc(kPageSize, aligned_address, false);
				uc_mem_write(uc, aligned_address, page2, 0x1000);
			}
			else {
				Logger::Log(true, ConsoleColor::RED, "KDMP not found address: 0x%llx\n", address);
				Emu(uc)->alloc(kPageSize, aligned_address, MUC_PROT_ALL);
			}
		}

		Logger::Log(true, ConsoleColor::RED, "------------------------------\n");
		Logger::Log(true, ConsoleColor::RED, "EXECUTE from unmapped memory Address : 0x%llx\n", address);
		Logger::Log(true, ConsoleColor::RED, "------------------------------\n");
		Logger::Log(true, ConsoleColor::DARK_GREEN, "Previous_address : %llx\n", Previous_address);
		break;

	default:
		Logger::Log(true, ConsoleColor::RED, "------------------------------\n");
		Logger::Log(true, ConsoleColor::RED, "Unknown memory error Address : 0x%llx\n", address);
		Logger::Log(true, ConsoleColor::RED, "------------------------------\n");
		Logger::Log(true, ConsoleColor::DARK_GREEN, "Previous_address : %llx\n", Previous_address);
		ShowRegister(uc);
		dump_stack(uc, rsp, 10);
		uc_emu_stop(uc);
		break;
	}

	for (auto& ti : loader->Threads) {
		SetEvent(ti->Event);
		loader->errorevent = nullptr;
	}
	return true;
}

void Unicorn::hook_access_object(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data) {
	Object* obj = (Object*)user_data;
	uint64_t rip;
	uc_reg_read(uc, UC_X86_REG_RIP, &rip);
	switch (type) {
	case UC_MEM_READ:
		uc_mem_read(uc, address, &value, sizeof(value));
		Logger::Log(true, ConsoleColor::BLUE, "Read %s + 0x%llx at address: 0x%llx Value: %llx\n", obj->name.c_str(), address - obj->address, rip, value);
		break;
	case UC_MEM_WRITE:
		Logger::Log(true, ConsoleColor::BLUE, "Write %s + 0x%llx at address: 0x%llx Value: %llx\n", obj->name.c_str(), address - obj->address, rip, value);
		break;
	}
}

void Unicorn::hook_mem_access(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data)
{
	uint64_t addr;
	uc_reg_read(uc, UC_X86_REG_RIP, &addr);
	_LDR_DATA_TABLE_ENTRY val;
	uint64_t useraddress;
	switch (type) {
	case UC_MEM_READ:
		uc_mem_read(uc, address, &useraddress, sizeof(useraddress));
		Logger::Log(true, 14, "[RIP address : 0x%llx ]  Read at address: 0x%llx Value: %llx\n", addr, address, useraddress);

		break;
	case UC_MEM_WRITE:
		Logger::Log(true, 11, "[RIP address : 0x%llx ]  Write in address: 0x%llx Value: %llx\n", addr, address, value);
		break;
	default:
		Logger::Log(true, ConsoleColor::DARK_GREEN, "[RIP address : 0x%llx ] Unknown memory access type at address: 0x%llx \n", address);
		break;
	}
}

void Unicorn::hook_mem_write(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data)
{
	uint64_t addr;
	uc_reg_read(uc, UC_X86_REG_RIP, &addr);
	Logger::Log(true, 11, "RIP : 0x%llx Write in address: 0x%llx Value: %llx\n", addr, address, value);
}

void Unicorn::hook_File_func(uc_engine* uc, std::string fileName, std::string funcName, void(*func)(uc_engine*, uint64_t, uint32_t, void*)) {
	for (auto& peFile : loader->peFiles) {
		uint64_t Base = peFile->Base;
		uint64_t RVA = peFile->FuncAddr[funcName];
		uc_hook trace;
		if (RVA != 0) {
			uc_hook_add(uc, &trace, UC_HOOK_CODE, (void*)func, NULL, Base + RVA, Base + RVA + sizeof(uint8_t));
		}
	}
}

crt_buffer_t::crt_buffer_t() : m_cbSize(0), m_pBuffer(NULL)
{
}

crt_buffer_t::crt_buffer_t(size_t size) : m_cbSize(size), m_pBuffer(malloc(size))
{
}

crt_buffer_t::~crt_buffer_t()
{
	if (m_pBuffer)
		free(m_pBuffer);
}

void* crt_buffer_t::GetSpace(size_t needSize)
{
	if (m_cbSize < needSize)
	{
		if (m_pBuffer)
			m_pBuffer = realloc(m_pBuffer, needSize);
		else
			m_pBuffer = malloc(needSize);
		m_cbSize = needSize;
	}
	return m_pBuffer;
}

