#include "Emulate.hpp"
#include "UnicornEmu.hpp"
#include "NtType.hpp"
#include <bcrypt.h>
#include <windows.h>

#include <fstream>
#include <conio.h>
#include <iostream>
#include <algorithm>
#include <cstdlib>
#include <cwchar>
#include <emmintrin.h>
#include <xmmintrin.h>
#include <cstring>
#include <unordered_set>
#include <thread>
#include <tlhelp32.h>
#include <mutex>
#pragma comment(lib, "bcrypt.lib")
int checknumh = 0;

PEloader* Emulate::loader = &PEloader::GetInstance();


uint64_t ramAddr;


Emulate::Emulate(uc_engine* uc)
{
	struct RamRange {
		uint64_t base;
		uint64_t size;
	};

	RamRange myRam[9] = { { 0x1000, 0x57000 }, { 0x59000, 0x46000 }, { 0x100000, 0xb81b9000 }, { 0xb82f1000, 0x3b0000 }, { 0xb86a3000, 0xcc58000 },
		{ 0xc6b99000, 0xfd000 }, { 0xc7ba2000, 0x5e000 }, { 0x100000000, 0x337000000 }, { 0, 0 } };
	ramAddr = HeapAlloc(uc, sizeof(myRam));
}

ULONG64 Emulate::StackAlloc(ULONG AllocBytes)
{
	return UnicornEmu::StackAlloc(AllocBytes);
}

VOID Emulate::StackFree(ULONG AllocBytes)
{
	UnicornEmu::StackFree(AllocBytes);
}
uint64_t Emulate::Alloc(uc_engine* uc, uint64_t size, uint64_t myaddr) {
	return Emu(uc)->alloc(size, myaddr);
}
uint64_t Emulate::Alloc(uc_engine* uc, uint64_t size, uint64_t myaddr, bool show) {
	return Emu(uc)->alloc(size, myaddr, show);
}
uint64_t Emulate::Alloc(uc_engine* uc, uint64_t size, uint64_t myaddr, my_uc_prot m) {
	return Emu(uc)->alloc(size, myaddr, m);
}

uint64_t Emulate::AllocVirtPhysPage(uint64_t virtAddr) {
	return Emu(loader->uc)->AllocVirtPhysPage(virtAddr);
}

uint64_t Emulate::HeapAlloc(uc_engine* uc, uint64_t size) {
	return Emu(uc)->HeapAlloc(size);
}
uint64_t Emulate::HeapAlloc(uc_engine* uc, uint64_t size, bool show) {

	auto emuc = Emu(uc);
	return emuc->HeapAlloc(size, show);
}
void Emulate::HeapFree(uint64_t addr) {
	Emu(loader->uc)->HeapFree(addr);
}

void Emulate::RtlInitUnicodeString(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "RtlInitUnicodeString \n");
	auto emu = Emu(uc);
	uint64_t rcx = emu->rcx();
	uint64_t rdx = emu->rdx();
	std::wstring wstr;
	read_null_unicode_string(uc, rdx, wstr);
	std::string str;
	UnicodeToANSI(wstr, str);
	UNICODE_STRING ustr;
	ustr.Buffer = (PWCH)rdx;
	ustr.Length = (USHORT)wstr.length() * sizeof(WCHAR);
	ustr.MaximumLength = (USHORT)(wstr.length() + 1) * sizeof(WCHAR);
	emu->write(rcx, &ustr, sizeof(ustr));
	Logger::Log(true, ConsoleColor::RED, "DestString 0x%llx SourceString: %s\n", rcx, str.c_str());
	RetHook(uc);
}

void Emulate::RtlAnsiStringToUnicodeString(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "RtlAnsiStringToUnicodeString\n");
	auto emu = Emu(uc);
	uint64_t unicode_str_ptr = emu->rcx();
	uint64_t ansi_str_ptr = emu->rdx();
	uint64_t should_alloc = emu->r8();
	std::string ansi_str = read_ansi_string(uc, ansi_str_ptr);
	Logger::Log(true, ConsoleColor::RED, "ANSI String:: %s\n", ansi_str.c_str());
	std::wstring wstr;
	ANSIToUnicode(ansi_str, wstr);
	UNICODE_STRING ustr;

	ustr.Length = (USHORT)wstr.length() * sizeof(WCHAR);
	ustr.MaximumLength = (USHORT)(wstr.length() + 1) * sizeof(WCHAR);
	uint64_t buffer_addr = Emulate::HeapAlloc(uc, 0x1000);
	if (buffer_addr)
		emu->write(buffer_addr, wstr.data(), ustr.Length);

	emu->write(unicode_str_ptr, &ustr, sizeof(ustr));
	uint64_t status = 0;
    emu->rax(status);
	RetHook(uc);
}

void Emulate::RtlInitString(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "RtlInitString\n");
	auto emu = Emu(uc);
	uint64_t ansi_string_ptr = emu->rcx();
    uint64_t source_ptr = emu->rdx();
	std::string str;
	char ch;
	int offset = 0;
	do {
		ch = emu->read<char>(source_ptr + offset);
		if (ch != '\0') str += ch;
		offset++;
	} while (ch != '\0');

	uint16_t length = static_cast<uint16_t>(str.size());
	uint16_t maxLength = length + 1;

	struct {
		uint16_t Length;
		uint16_t MaximumLength;
		uint64_t Buffer;
	} ansi;

	ansi.Length = length;
	ansi.MaximumLength = maxLength;
	ansi.Buffer = source_ptr;

	emu->write(ansi_string_ptr, &ansi, sizeof(ansi));
	Logger::Log(true, ConsoleColor::RED, "RtlInitString : %s Length : %llx MaxLength : %llx at 0x%llx\n", str.c_str(), length, maxLength, ansi_string_ptr);
	RetHook(uc);
}

void Emulate::ExSystemTimeToLocalTime(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "ExSystemTimeToLocalTime\n");
	auto emu = Emu(uc);
	uint64_t lpSystemTime = emu->rcx();
	uint64_t lpLocalTime = emu->rdx();
	emu->write(lpLocalTime, &lpSystemTime, sizeof(LARGE_INTEGER));

	RetHook(uc);
}

void Emulate::RtlTimeFieldsToTime(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "RtlTimeFieldsToTime\n");
	auto emu = Emu(uc);
	uint64_t tf_ptr = emu->rcx();
    uint64_t time_ptr = emu->rdx();
	TIME_FIELDS tf = emu->read<TIME_FIELDS>(tf_ptr);

	SYSTEMTIME st = {
		(WORD)tf.Year,
		(WORD)tf.Month,
		(WORD)(tf.Weekday + 1),
		(WORD)tf.Day,
		(WORD)tf.Hour,
		(WORD)tf.Minute,
		(WORD)tf.Second,
		(WORD)tf.Milliseconds
	};

	FILETIME ft = { 0 };
	LARGE_INTEGER result = { 0 };
	BOOLEAN success = FALSE;

	if (::SystemTimeToFileTime(&st, &ft)) {
		result.LowPart = ft.dwLowDateTime;
		result.HighPart = ft.dwHighDateTime;
		success = TRUE;

		emu->write(time_ptr, &result, sizeof(result));
	}

	Logger::Log(true, ConsoleColor::RED, "via SystemTimeToFileTime : %s, Result = 0x%llx",
		(success ? "✓ OK" : "✗ Failed")
		, result.QuadPart);

	emu->rax(success);
    RetHook(uc);
}


void Emulate::RtlTimeToTimeFields(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	Logger::Log(true, ConsoleColor::RED, "RtlTimeToTimeFields\n");

	auto emu = Emu(uc);
	uint64_t time_ptr = emu->rcx();
    uint64_t timefields_ptr = emu->rdx();
	LARGE_INTEGER time = emu->read<LARGE_INTEGER>(time_ptr);

	FILETIME ft;
	ft.dwLowDateTime = time.LowPart;
	ft.dwHighDateTime = time.HighPart;

	SYSTEMTIME st;
	FileTimeToSystemTime(&ft, &st);
	TIME_FIELDS tf;
	tf.Year = st.wYear;
	tf.Month = st.wMonth;
	tf.Day = st.wDay;
	tf.Hour = st.wHour;
	tf.Minute = st.wMinute;
	tf.Second = st.wSecond;
	tf.Milliseconds = st.wMilliseconds;
	tf.Weekday = st.wDayOfWeek;

	emu->write(timefields_ptr, &tf, sizeof(TIME_FIELDS));
	RetHook(uc);
}

void Emulate::RtlDuplicateUnicodeString(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "RtlDuplicateUnicodeString\n");
	auto emu = Emu(uc);
	uint64_t flags = emu->rcx();
    uint64_t string_ptr = emu->rdx();
    uint64_t dest_ptr = emu->r8();
	UNICODE_STRING string = emu->read<UNICODE_STRING>(string_ptr);
	if (string.Buffer != NULL && string.Length > 0) {
		std::wstring unicode_str = read_unicode_string(uc, string_ptr);

		std::string utf8_str;
		for (wchar_t wc : unicode_str) {
			if (wc < 128) {
				utf8_str += static_cast<char>(wc);
			}
			else {
				utf8_str += '?';
    		}
		}
		Logger::Log(true, ConsoleColor::RED, "Unicode String: %s\n", utf8_str.c_str());
	}
	else {
		Logger::Log(true, ConsoleColor::RED, "Unicode String is empty or null.\n");
	}

	UNICODE_STRING dest_string;
	dest_string.Length = string.Length;
	dest_string.MaximumLength = string.MaximumLength;
	dest_string.Buffer = string.Buffer;
    emu->write(dest_ptr, &dest_string, sizeof(UNICODE_STRING));

	uint64_t status = 0;
    emu->rax(status);
	RetHook(uc);
}

void Emulate::RtlCompareMemory(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "RtlCompareMemory\n");
	auto emu = Emu(uc);
	uint64_t source1 = emu->rcx();
    uint64_t source2 = emu->rdx();
    uint64_t length = emu->r8();
	std::vector<uint8_t> buf1 = emu->read(source1, static_cast<size_t>(length));
	std::vector<uint8_t> buf2 = emu->read(source2, static_cast<size_t>(length));

	size_t match_len = 0;
	for (size_t i = 0; i < length; ++i) {
		if (buf1[i] != buf2[i])
			break;
		++match_len;
	}

	Logger::Log(true, ConsoleColor::RED, " %d/%d bytes match\n", match_len, length);
	emu->rax(match_len);
	RetHook(uc);
}
void Emulate::IsDigit(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "IsDigit\n");
	auto emu = Emu(uc);
	uint64_t ch = emu->rcx();
	int result = (ch >= '0' && ch <= '9') ? 1 : 0;

	Logger::Log(true, ConsoleColor::RED, "(%c) => %c", (char)ch, result);
	emu->rax(result);
	RetHook(uc);
}
void Emulate::atol(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "atol\n");
	auto emu = Emu(uc);
	uint64_t str_ptr = emu->rcx();
	char raw_str[64] = { 0 };
	auto data = emu->read(str_ptr, sizeof(raw_str) - 1);
	size_t copy_len = min(data.size(), sizeof(raw_str) - 1);
	std::memcpy(raw_str, data.data(), copy_len);
	raw_str[copy_len] = '\0';

	int result = std::atoi(raw_str);

	Logger::Log(true, ConsoleColor::RED, "( %s ) = %d\n", raw_str, result);
	emu->rax(result);
	RetHook(uc);
}
void Emulate::ExAllocatePoolWithTag(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {


	auto emu = Emu(uc);
	uint64_t rcx_value = emu->rcx();
	int a1 = static_cast<int>(rcx_value & 0xFFFFFFFF);
    uint64_t a2 = emu->rdx();
    uint64_t a3 = emu->r8();
    uint64_t allocated_address;
	Logger::Log(true, ConsoleColor::RED, "ExAllocatePoolWithTag : called with PoolType: %d , NumberOfBytes: %lld,  Tag: %llx\n", a1, a2, a3);
	allocated_address = HeapAlloc(uc, a2, false);
	emu->rax(allocated_address);
	RetHook(uc);
}
void Emulate::ExFreePoolWithTag(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "ExFreePoolWithTag\n");
	auto emu = Emu(uc);
	uint64_t free_address = emu->rcx();
    uint64_t tag = emu->rdx();
	Logger::Log(true, ConsoleColor::DARK_GREEN, "called for address: 0x%llx , Tag : 0x%llx \n", free_address, tag);










	emu->rax(0);
	uint64_t rsp = emu->rsp();
	dump_stack(uc, rsp - 8, 10);
	RetHook(uc);
}
void Emulate::ExFreeHeapPool(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	Logger::Log(true, ConsoleColor::RED, "ExFreeHeapPool \n");
	RetHook(uc);

}
void Emulate::ExFreePool(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
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
			Sleep(10);
		}
	}
	auto emu = Emu(uc);
	uint64_t allocated_address = emu->rcx();
    Logger::Log(true, ConsoleColor::RED, "ExFreePool : allocated_address = %llx \n", allocated_address);

	auto it = loader->real_mem_map.find(allocated_address);
	if (it == loader->real_mem_map.end()) {
		Logger::Log(true, ConsoleColor::RED, "Error: Attempted to free unallocated or invalid address: 0x%llx \n", allocated_address);
		return;
	}
	emu->rax(0);
	uint64_t rsp = emu->rsp();
	if (loader->sysinfo_addr == allocated_address)
		loader->sysinfo_addr = 0;
	RetHook(uc);
	for (auto& ti : loader->Threads) {
		SetEvent(ti->Event);
		loader->errorevent = nullptr;
	}
}
void Emulate::IoCreateDevice(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "IoCreateDevice\n");
	DRIVER_OBJECT driverObj;
	uint64_t rax, rcx, rdx, r8, r9, r10, r11, rsp;
	auto emu = Emu(uc);
	rax = emu->rax();
    rcx = emu->rcx();
    rdx = emu->rdx();
    r8 = emu->r8();
    r9 = emu->r9();

	rsp = emu->rsp();
	std::wstring var_name = read_unicode_string(uc, r8);
    rsp = rsp + 8;
	r10 = emu->read<uint64_t>(rsp + 0x20);
    r11 = emu->read<uint64_t>(rsp + 0x28);
    uint64_t deviceObjPtr = emu->read<uint64_t>(rsp + 0x30);
    driverObj = emu->read<DRIVER_OBJECT>(rcx);

	std::string Device_name;
	std::wstring device_name = read_unicode_string(uc, r8);
    UnicodeToANSI(device_name, Device_name);

	uint64_t device_obj_addr = Emulate::HeapAlloc(uc, sizeof(_DEVICE_OBJECT));

	_DEVICE_OBJECT dev = {};
	dev.DriverObject = (DRIVER_OBJECT*)rcx;
	dev.DeviceType = static_cast<DEVICE_TYPE>(r9);
	dev.Type = 3;
	dev.Size = sizeof(_DEVICE_OBJECT);
	dev.ReferenceCount = 1;
	dev.NextDevice = 0;

	if (rdx > 0) {
		uint64_t extAddr = Emulate::HeapAlloc(uc, rdx);
		dev.DeviceExtension = (PVOID)extAddr;
	}
	driverObj.DeviceObject = (_DEVICE_OBJECT*)device_obj_addr;
	emu->write(rcx, &driverObj, sizeof(DRIVER_OBJECT));
	emu->write(device_obj_addr, &dev, sizeof(dev));
	emu->write(deviceObjPtr, &device_obj_addr, sizeof(device_obj_addr));
	uint64_t t;
	emu->rax(STATUS_SUCCESS);
	Logger::Log(true, 12, "IoCreateDevice: %s\n", Device_name.c_str());
	RetHook(uc);
}

void Emulate::IoRegisterShutdownNotification(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "IoRegisterShutdownNotification\n");
	auto emu = Emu(uc);
	uint64_t device_object_addr = emu->rcx();

	Logger::Log(true, ConsoleColor::RED, "Called : DEVICE_OBJECT @ 0x%llx\n", device_object_addr);


	RetHook(uc);
}

void Emulate::IoCreateSymbolicLink(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "IoCreateSymbolicLink\n");
	auto emu = Emu(uc);
	uint64_t symbolic_link_str_ptr = emu->rcx();
    uint64_t device_name_str_ptr = emu->rdx();
	std::wstring symbolic_link = read_unicode_string(uc, symbolic_link_str_ptr);
	std::string ssymbolic_link;
	UnicodeToANSI(symbolic_link, ssymbolic_link);
	uint64_t rsp = emu->rsp();
    std::wstring device_name = read_unicode_string(uc, device_name_str_ptr);
	std::string sdevice_name;
	UnicodeToANSI(device_name, sdevice_name);
	Logger::Log(true, ConsoleColor::RED, "  called  SymbolicLink: %s DeviceName: %s \n", ssymbolic_link, sdevice_name.c_str());

	uint64_t t;
	emu->rax(0);
    RetHook(uc);
}

void Emulate::ZwFlushKey(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "ZwFlushKey \n");
	auto emu = Emu(uc);
	uint64_t keyHandle = emu->rcx();
    Logger::Log(true, ConsoleColor::DARK_GREEN, "Flushing key : 0x%llx \n", keyHandle);

	emu->rax(0);
    RetHook(uc);
}
std::map<uint64_t, HANDLE> r3SectionMap;uint64_t nextFakeHandle = 0x10000;
void Emulate::ZwCreateSection(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t SectionHandlePtr = emu->rcx();
    uint64_t DesiredAccess = emu->rdx();
	uint64_t ObjectAttributes = emu->r8();
	uint64_t MaximumSizePtr = emu->r9();

	uint64_t rsp = emu->rsp();
	uint64_t Protection = emu->read<uint64_t>(rsp + 0x28);
    uint64_t AllocationAttributes = emu->read<uint64_t>(rsp + 0x30);
    uint64_t FileHandle = emu->read<uint64_t>(rsp + 0x38);
	uint64_t maxSize = 0x1000;
	if (MaximumSizePtr)
		maxSize = emu->read<uint64_t>(MaximumSizePtr);

	DWORD protect = PAGE_READWRITE;
	if (Protection == PAGE_EXECUTE_READWRITE) protect = PAGE_EXECUTE_READWRITE;

	DWORD secAttrib = (AllocationAttributes & 0x1000000) ? SEC_COMMIT : SEC_RESERVE;



	HANDLE hSection = CreateFileMappingW(
		(HANDLE)FileHandle, nullptr,
		protect | secAttrib,
		(DWORD)(maxSize >> 32),
		(DWORD)(maxSize & 0xFFFFFFFF),
		nullptr
	);

	if (!hSection) {
		emu->rax(0xC0000001);
		RetHook(uc);
		return;
	}
	emu->write(SectionHandlePtr, &FileHandle, sizeof(FileHandle));

	std::cout << "[+] ZwCreateSection simulation completed, FakeHandle = 0x" << std::hex << FileHandle
		<< ", Size = 0x" << maxSize << "\n";

	emu->rax(0);
	RetHook(uc);
}

void Emulate::ZwClose(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {


	Logger::Log(true, ConsoleColor::RED, "ZwClose\n");
	auto emu = Emu(uc);
	uint64_t handle = emu->rcx();

	Logger::Log(true, ConsoleColor::DARK_GREEN, "Closed handle 0x%llx \n", handle);
	if (handle > 0xcafebabe)
		return;
	if (handle != 0xcafebabe)
		try
	{
		CloseHandle((HANDLE)handle);
	}
	catch (const std::exception&)
	{

	}

	emu->rax(0);
    RetHook(uc);
}
void Emulate::PsGetCurrentProcess(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "PsGetCurrentProcess\n");

	auto emu = Emu(uc);
	uint64_t gsBase = emu->gs_base();

	uint64_t kthreadPtr = emu->read<uint64_t>(gsBase + 0x188);

	uint64_t eprocess_ptr, t;
	eprocess_ptr = emu->read<uint64_t>(kthreadPtr + 0x220);
	Logger::Log(true, ConsoleColor::DARK_GREEN, "EPROCESS = 0x%llx\n", eprocess_ptr);
	emu->rax(eprocess_ptr);

	PEloader* loader = &PEloader::GetInstance();

	RetHook(uc);}
void Emulate::KeStackAttachProcess(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "KeStackAttachProcess\n");
	auto emu = Emu(uc);
	uint64_t eprocess = emu->rcx();
    uint64_t apc_state_ptr = emu->rdx();
    uint64_t gsBase = emu->gs_base();
	uint64_t kthread = emu->read<uint64_t>(gsBase + 0x188);

	uint64_t apcStateOffset = 0x98;
    uint64_t currentApcState = emu->read<uint64_t>(kthread + apcStateOffset);
	uint64_t old_process = emu->read<uint64_t>(currentApcState);

	if (eprocess != 0)
	{

		emu->write(apc_state_ptr, &old_process, sizeof(old_process));

		emu->write(currentApcState, &eprocess, sizeof(eprocess));
	}
	else {
		uint64_t PsInitialSystemProcess;
		PEloader* loader = &PEloader::GetInstance();
		PsInitialSystemProcess = emu->read<uint64_t>(loader->peFiles[1]->Base + loader->peFiles[1]->FuncAddr["PsInitialSystemProcess"]);
		eprocess = PsInitialSystemProcess;
		emu->write(apc_state_ptr, &old_process, sizeof(old_process));

		emu->write(currentApcState, &eprocess, sizeof(eprocess));

	}
	Logger::Log(true, ConsoleColor::DARK_GREEN, "Attached to EPROCESS = 0x%llx\n", eprocess);
	emu->rax(0);
    RetHook(uc);
}

void Emulate::KeUnstackDetachProcess(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "KeUnstackDetachProcess\n");
	uint64_t t;

	RetHook(uc);
}

void Emulate::ExGetFirmwareEnvironmentVariable(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "ExGetFirmwareEnvironmentVariable\n");
	auto emu = Emu(uc);
	uint64_t var_name_ptr = emu->rcx();
	uint64_t guid_ptr = emu->rdx();
	uint64_t value_ptr = emu->r8();
	uint64_t value_len = emu->r9();

	uint64_t rsp = emu->rsp();
	uint64_t return_len_ptr = emu->read<uint64_t>(rsp + 0x20);

	uint32_t value_len_temp = emu->read<uint32_t>(value_len);



	std::wstring var_name = read_unicode_string(uc, var_name_ptr);
    int var_name_len = WideCharToMultiByte(CP_UTF8, 0, var_name.c_str(), -1, nullptr, 0, nullptr, nullptr);
	char* var_name_mb = new char[var_name_len];
	WideCharToMultiByte(CP_UTF8, 0, var_name.c_str(), -1, var_name_mb, var_name_len, nullptr, nullptr);
	Logger::Log(true, ConsoleColor::DARK_GREEN, "var_name: %s\n", var_name_mb);
	delete[] var_name_mb;

	GUID guid = emu->read<GUID>(guid_ptr);
	wchar_t guid_str[64];
	StringFromGUID2(guid, guid_str, 64);
	int guid_len = WideCharToMultiByte(CP_UTF8, 0, guid_str, -1, nullptr, 0, nullptr, nullptr);
	char* guid_mb = new char[guid_len];
	WideCharToMultiByte(CP_UTF8, 0, guid_str, -1, guid_mb, guid_len, nullptr, nullptr);
	Logger::Log(true, ConsoleColor::DARK_GREEN, "guid_str: %s\n", guid_mb);
	delete[] guid_mb;

	auto status = STATUS_SUCCESS;
	RetHook(uc);}



void Emulate::MmGetPhysicalMemoryRanges(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "MmGetPhysicalMemoryRanges\n");
}

void Emulate::ObfDereferenceObject(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	Logger::Log(true, ConsoleColor::RED, "ObfDereferenceObject\n");
	return;
}

void Emulate::MmBuildMdlForNonPagedPool(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "MmBuildMdlForNonPagedPool\n");
	auto emu = Emu(uc);
	uint64_t mdl_addr = emu->rcx();
	uint16_t MdlFlags = emu->read<uint16_t>(mdl_addr + offsetof(FAKE_MDL, MdlFlags));

	MdlFlags |= 0x0002;
    emu->write(mdl_addr + offsetof(FAKE_MDL, MdlFlags), &MdlFlags, sizeof(MdlFlags));

	Logger::Log(true, ConsoleColor::DARK_GREEN, "Setting MDL @ 0x%llx MdlFlags = 0x%llx\n", mdl_addr, MdlFlags);

	RetHook(uc);
}

void Emulate::IoAllocateMdl(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "IoAllocateMdl\n");
	auto emu = Emu(uc);
	uint64_t VirtualAddress = emu->rcx();
	uint64_t Length = emu->rdx();
	uint64_t SecondaryBuffer = emu->r8();
	uint64_t ChargeQuota = emu->r9();

	uint64_t rsp = emu->rsp();
	uint64_t Irp = emu->read<uint64_t>(rsp + 0x28);
	uint64_t mdl_addr = Emulate::HeapAlloc(uc, sizeof(FAKE_MDL));
	FAKE_MDL mdl = {};
	mdl.Size = sizeof(FAKE_MDL);
	mdl.StartVa = VirtualAddress;
	mdl.ByteCount = Length;
	mdl.MappedSystemVa = VirtualAddress;
    emu->write(mdl_addr, &mdl, sizeof(mdl));

	Logger::Log(true, ConsoleColor::DARK_GREEN, "Alloc MDL  0x%llx VA: 0x%llx, Len= %lld\n", mdl_addr, VirtualAddress, Length);

	emu->rax(mdl_addr);
	RetHook(uc);
}

void Emulate::MmAllocateContiguousMemorySpecifyCache(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "MmAllocateContiguousMemorySpecifyCache\n");
	auto emu = Emu(uc);
	SIZE_T NumberOfBytes = static_cast<SIZE_T>(emu->rcx());
    uint64_t LowestAcceptableAddress = emu->rdx();
    uint64_t HighestAcceptableAddress = emu->r8();
    uint64_t BoundaryAddressMultiple = emu->r9();
    uint64_t rsp = emu->rsp();
	Logger::Log(true, ConsoleColor::DARK_GREEN, "\tLowest : %llx - Highest : %llx - Boundary : %llx - Size : %08x\n", LowestAcceptableAddress, HighestAcceptableAddress, BoundaryAddressMultiple, NumberOfBytes);
	loader->AllocatedContiguous = (uint64_t)HeapAlloc(uc, NumberOfBytes);
	emu->rax(loader->AllocatedContiguous);
	RetHook(uc);
}

void Emulate::PsRemoveLoadImageNotifyRoutine(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	Logger::Log(true, ConsoleColor::RED, "PsRemoveLoadImageNotifyRoutine\n");

}

void Emulate::PsSetCreateProcessNotifyRoutineEx(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	Logger::Log(true, ConsoleColor::RED, "PsSetCreateProcessNotifyRoutineEx\n");
	auto emu = Emu(uc);
	uint64_t NotifyRoutine = emu->rcx();
	uint64_t Remove = emu->rdx();

	uint64_t ret;
	if (Remove) {
		ret = STATUS_INVALID_PARAMETER;
	}
	else {
		ret = STATUS_SUCCESS;
	}
}

void Emulate::ObRegisterCallbacks(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "ObRegisterCallback\n");
	auto emu = Emu(uc);
	uint64_t registration_addr = emu->rcx();
	uint64_t handle_ptr = emu->rdx();

	uint16_t count;
	uint64_t op_array;
	uint64_t context;

	count = emu->read<uint16_t>(registration_addr + 4);
    context = emu->read<uint64_t>(registration_addr + 0x10);
    op_array = emu->read<uint64_t>(registration_addr + 0x18);
	uint64_t fake_handle = 0xDEADBEEF00000001;
	emu->write(handle_ptr, &fake_handle, sizeof(fake_handle));

	uint64_t status = 0;
    emu->rax(status);
	Logger::Log(true, ConsoleColor::DARK_GREEN, " %llx\n", count);
	RetHook(uc);
}
uint64_t g_CmCookieSeed = 0xCB00000000000000;
void Emulate::CmRegisterCallbackEx(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "CmRegisterCallbackEx\n");
	auto emu = Emu(uc);
	uint64_t fn = emu->rcx();
	uint64_t ctx = emu->rdx();
	uint64_t alt_str_ptr = emu->r8();
	uint64_t driver = emu->r9();

	uint64_t rsp = emu->rsp();
	uint64_t cookie_ptr = emu->read<uint64_t>(rsp + 0x20);

	std::wstring altitude;
	if (alt_str_ptr != 0) {
		altitude = read_unicode_string(uc, alt_str_ptr);
	}
	g_CmCookieSeed++;
	emu->write(cookie_ptr, &g_CmCookieSeed, sizeof(g_CmCookieSeed));

	Logger::Log(true, ConsoleColor::DARK_GREEN, " Registered Callback: 0x%llx , Altitude: %s\n", fn, altitude.c_str());

	uint64_t status = 0;
    emu->rax(status);
	RetHook(uc);
}
void Emulate::ObUnRegisterCallbacks(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "ObUnRegisterCallbacks\n");
	auto emu = Emu(uc);
	uint64_t regHandle = emu->rcx();

	Logger::Log(true, ConsoleColor::DARK_GREEN, "Removed \n");

	NTSTATUS status = 0;



	emu->rax(status);
	RetHook(uc);
}
void Emulate::ZwWaitForSingleObject(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "ZwWaitForSingleObject\n");
	auto emu = Emu(uc);
	uint64_t status = 0;
    emu->rax(status);
	RetHook(uc);
}
void Emulate::InitializeSListHead(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "InitializeSListHead\n");
	auto emu = Emu(uc);
	uint64_t listHeadAddr = emu->rcx();
	uint8_t zero[16] = {};

	Logger::Log(true, ConsoleColor::DARK_GREEN, " Clear SLIST_HEADER  0x%llx\n", listHeadAddr);

}
void Emulate::KeInitializeSpinLock(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "KeInitializeSpinLock \n");
	auto emu = Emu(uc);
	uint64_t spinlock_addr = emu->rcx();

	Logger::Log(true, ConsoleColor::DARK_GREEN, "SpinLock @ 0x%llx Set to Zero\n", spinlock_addr);

}

void Emulate::KeAcquireSpinLockRaiseToDpc(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	Logger::Log(true, ConsoleColor::RED, "KeAcquireSpinLockRaiseToDpc\n");

	auto emu = Emu(uc);
	uint64_t ret = 0;
	emu->rax(ret);
	RetHook(uc);
}

void Emulate::KeReleaseSpinLock(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	Logger::Log(true, ConsoleColor::RED, "KeReleaseSpinLock\n");
	RetHook(uc);
}

void Emulate::ExpInterlockedPopEntrySList(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	Logger::Log(true, ConsoleColor::RED, "ExpInterlockedPopEntrySList\n");
	auto emu = Emu(uc);
	uint64_t ret = 0;
	emu->rax(ret);
	RetHook(uc);
}

void Emulate::ExWaitForRundownProtectionRelease(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	Logger::Log(true, ConsoleColor::RED, "ExWaitForRundownProtectionRelease\n");
	RetHook(uc);
}

void Emulate::KeCancelTimer(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	Logger::Log(true, ConsoleColor::RED, "KeCancelTimer\n");

	auto emu = Emu(uc);
	uint64_t ret = 1;
	emu->rax(ret);
	RetHook(uc);
}


void Emulate::RtlFreeUnicodeString(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	Logger::Log(true, ConsoleColor::RED, "RtlFreeUnicodeString\n");
	RetHook(uc);
}

void Emulate::PsSetCreateThreadNotifyRoutine(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	Logger::Log(true, ConsoleColor::RED, "PsSetCreateThreadNotifyRoutine\n");
	auto emu = Emu(uc);
	emu->rax(STATUS_SUCCESS);
	RetHook(uc);
}

void Emulate::PsSetLoadImageNotifyRoutine(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	Logger::Log(true, ConsoleColor::RED, "PsSetLoadImageNotifyRoutine\n");
	auto emu = Emu(uc);
	emu->rax(STATUS_SUCCESS);
	RetHook(uc);
}

void Emulate::ExRegisterCallback(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "ExRegisterCallback\n");
	auto emu = Emu(uc);
	uint64_t callback_object = emu->rcx();
	uint64_t callback_fn = emu->rdx();
	uint64_t callback_ctx = emu->r8();

	Logger::Log(true, ConsoleColor::DARK_GREEN, "object = 0x%llx, fn=0x%llx, ctx=0x%llx\n", callback_object, callback_fn, callback_ctx);

	uint64_t reg_handle = callback_fn;
    emu->rax(reg_handle);
	RetHook(uc);
}
void Emulate::ExUnregisterCallback(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "ExUnregisterCallback\n");
	auto emu = Emu(uc);
	uint64_t handle = emu->rcx();
	Logger::Log(true, ConsoleColor::DARK_GREEN, " Remove Callback handle: %llx\n", handle);

	RetHook(uc);
}


void Emulate::_CiCheckSignedFile(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	Logger::Log(true, ConsoleColor::RED, "CiCheckSignedFile\n");
	auto emu = Emu(uc);
	uint64_t digestBuffer = emu->rcx();
	uint64_t digestSize = emu->rdx();
	uint64_t digestIdentifier = emu->r8();
	uint64_t winCert = emu->r9();

	uint64_t rsp = emu->rsp();
	rsp = rsp + 8;
	int sizeOfSecurityDirectory;
	uint64_t policyInfoForSigner;
	uint64_t signingTime;
	uint64_t policyInfoForTimestampingAuthority;
	sizeOfSecurityDirectory = emu->read<int>(rsp + 0x20);
	policyInfoForSigner = emu->qword(rsp + 0x28);
	signingTime = emu->qword(rsp + 0x30);
	policyInfoForTimestampingAuthority = emu->qword(rsp + 0x38);
	std::vector<uint8_t> copiedDigestBufferData;
	if (digestSize != 0) {
		copiedDigestBufferData = emu->read(digestBuffer, static_cast<size_t>(digestSize));
	}
	const uint64_t WIN_CERTIFICATE_SIZE = 8;
    std::vector<uint8_t> copiedWinCertData;
	if (winCert != 0) {
		copiedWinCertData = emu->read(winCert, static_cast<size_t>(WIN_CERTIFICATE_SIZE));
	}
	auto ret = 0;


	emu->rax(ret);
	RetHook(uc);
}

void Emulate::CiFreePolicyInfo(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{

	Logger::Log(true, ConsoleColor::RED, "CiFreePolicyInfo\n");
	auto emu = Emu(uc);
	uint64_t ptr = emu->rcx();

	Logger::Log(true, ConsoleColor::RED, "CiFreePolicyInfo: Free PolicyInfo @ 0x%llx\n", ptr);



	RetHook(uc);
}

void Emulate::KeWaitForMultipleObjects(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t Count = emu->rcx();
	uint64_t ObjectArrayAddr = emu->rdx();
	uint64_t WaitType = emu->r8();
	uint64_t WaitReason = emu->r9();

	uint64_t rsp = emu->rsp();
	uint64_t WaitMode = emu->read<uint64_t>(rsp + 0x28);
	uint64_t Alertable = emu->read<uint64_t>(rsp + 0x30);
	uint64_t TimeoutAddr = emu->read<uint64_t>(rsp + 0x38);



	DWORD timeout_ms = INFINITE;
	if (TimeoutAddr != 0) {
		LARGE_INTEGER timeoutVal;
		timeoutVal = emu->read<LARGE_INTEGER>(TimeoutAddr);
		timeout_ms = (DWORD)(-timeoutVal.QuadPart / 10000);
	}

	DWORD result = 0;
	WaitForMultipleObjects(
		static_cast<DWORD>(loader->waitHandles.size()),
		loader->waitHandles.data(),
		WaitType,
		timeout_ms
	);

	uint64_t status = 0;
	switch (result) {
	case WAIT_OBJECT_0:
		std::cout << "Both events are signaled!\n";
		break;
	case WAIT_TIMEOUT:
		std::cout << "Timeout waiting for events.\n";
		break;
	case WAIT_FAILED:
		std::cout << "Wait failed: " << GetLastError() << "\n";
		break;
	default:
		std::cout << "Unknown result: " << result << "\n";
		break;
	}

	std::cout << "[+] KeWaitForMultipleObjects completed, return status: 0x" << std::hex << status << std::endl;
	emu->rax(status);
	RetHook(uc);
}


void Emulate::HalAcpiGetTableEx(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	Logger::Log(true, ConsoleColor::RED, "HalAcpiGetTableEx\n");
	auto emu = Emu(uc);
	uint64_t rcx = emu->rcx();
	uint64_t rdx = emu->rdx();
	uint64_t r8 = emu->r8();
	std::wstring wstr;
	read_null_unicode_string(uc, rcx, wstr);

	RetHook(uc);
}

void Emulate::IoQueryFileInformation(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	ZwQueryInformationFile(uc, address, size, user_data);
}

void Emulate::DbgPrint(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	Logger::Log(true, ConsoleColor::RED, "DbgPrint\n");

	auto emu = Emu(uc);
	uint64_t format_ptr = emu->rcx();
	uint64_t arg1 = emu->rdx();
	uint64_t arg2 = emu->r8();
	uint64_t arg3 = emu->r9();

	std::vector<char> format;
	char ch;
	do {
		ch = static_cast<char>(emu->read<uint8_t>(format_ptr++));
		format.push_back(ch);
	} while (ch != '\0');
	std::string fmt(format.begin(), format.end());

	char str_arg1[256] = {};
	if (arg1 != 0) {
		auto arg1Data = emu->read(arg1, sizeof(str_arg1) - 1);
		memcpy(str_arg1, arg1Data.data(), arg1Data.size());
	}

	char buffer[512];
	snprintf(buffer, sizeof(buffer), fmt.c_str(), arg1, (unsigned int)arg2, (unsigned int)arg3);

	Logger::Log(true, ConsoleColor::GREEN, "%s", buffer);

	RetHook(uc);
}

void Emulate::RtlVirtualUnwind(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	Logger::Log(true, ConsoleColor::RED, "RtlVirtualUnwind \n");
	uint64_t rsp;
}

void Emulate::SeSinglePrivilegeCheck(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	auto emu = Emu(uc);
	emu->rax(STATUS_SUCCESS);
	RetHook(uc);
}

void Emulate::ExAcquireResourceExclusiveLite(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	auto emu = Emu(uc);
	emu->rax(STATUS_SUCCESS);
	RetHook(uc);
}
int test = 0;

void Emulate::RtlRaiseStatus(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::DARK_GREEN, "RtlRaiseStatus\n");
}
void Emulate::PsGetCurrentServerSilo(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	Logger::Log(true, ConsoleColor::RED, "PsGetCurrentServerSilo\n");
	auto emu = Emu(uc);
	uint64_t PsIdleProcess = emu->qword(0xfffff80508b134d0);

	emu->rax(0);
	RetHook(uc);


}
void Emulate::RtlLookupFunctionEntry(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	Logger::Log(true, ConsoleColor::RED, "RtlLookupFunctionEntry\n");
	/*auto emu = Emu(uc);
	uint64_t rcx = emu->rcx();
	uint64_t rdx = emu->rdx();
	uint64_t r8 = emu->r8();
	uint64_t rcxtemp, rdxtemp;
	UNWIND_HISTORY_TABLE historyTable = {};
	rcxtemp = emu->qword(rcx);
	rdxtemp = emu->qword(rdx);
	historyTable = emu->read<UNWIND_HISTORY_TABLE>(r8);
	uint64_t rsp;*/


}

void Emulate::MmGetPhysicalAddress(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	Logger::Log(true, ConsoleColor::RED, "MmGetPhysicalAddress\n");
	auto emu = Emu(uc);
	uint64_t baseAddress = emu->rcx();
	uint64_t ret = baseAddress >> 12;

	if (baseAddress == loader->AllocatedContiguous) {
		Logger::Log(true, DARK_GREEN, "\tGetting physical for last Contiguous Allocated Memory.\n");
	}
	if (baseAddress == 0xf0f87c3e1000) {
		ret = 0x1ad000;
	}
	else if (baseAddress == 0xfb7dbedf6000) {
		ret = 0x200000;
	}
	else if (baseAddress == 0xfbfdfeff7000) {
		ret = 0x200000;
	}
	else if (baseAddress == 0xfc7e3f1f8000) {
		ret = 0x200000;
	}
	else if (baseAddress == 0xfcfe7f3f9000) {
		ret = 0x200000;
	}
	Logger::Log(true, DARK_GREEN, "%llx Return: %llx\n", baseAddress, ret);
	emu->rax(ret);
	RetHook(uc);

	return;
}

void Emulate::ZwOpenSection(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "ZwOpenSection \n");
	auto emu = Emu(uc);
	uint64_t sectionHandlePtr = emu->rcx();
    uint64_t desiredAccess = emu->rdx();
	uint64_t objectAttrAddr = emu->r8();

	OBJECT_ATTRIBUTES ObjectAttributes = {};
	ObjectAttributes = emu->read<OBJECT_ATTRIBUTES>(objectAttrAddr);

	std::wstring sectionName = read_unicode_string(uc, ObjectAttributes.ObjectName);
	UNICODE_STRING KeyPath;
	ConvertToUnicodeString(KeyPath, sectionName);
	OBJECT_ATTRIBUTES objAttr;
	std::string unstring;
	UnicodeToANSI(sectionName, unstring);
	InitializeObjectAttributes(&objAttr, (uint64_t)&KeyPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
	Logger::Log(true, DARK_GREEN, "Attempting to open Section: %s\n", unstring.c_str());

	uint64_t fakeHandle = 0xBAD00001;
	auto ret = __NtRoutine("NtOpenSection", &sectionHandlePtr, desiredAccess, &objAttr);

	uint64_t status = 0;
    emu->rax(ret);

	RetHook(uc);
}

static std::vector<uint8_t> get_system_module_information() {
	ULONG size = 0;
	HINSTANCE hNtDLL = LoadLibraryA("ntdll.dll");
	if (!hNtDLL) {
		std::cerr << "Failed to load ntdll.dll" << std::endl;
		return {};
	}

	_NtQuerySystemInformation NtQuerySystemInformation = _NtQuerySystemInformation(GetProcAddress(hNtDLL, "NtQuerySystemInformation"));
	if (!NtQuerySystemInformation) {
		std::cerr << "Failed to find NtQuerySystemInformation" << std::endl;
		FreeLibrary(hNtDLL);
		return {};
	}
	NTSTATUS status = NtQuerySystemInformation(11, nullptr, 0, &size);

	std::vector<uint8_t> buffer(size);
	status = NtQuerySystemInformation(11, buffer.data(), size, &size);
	PSYSTEM_MODULE_INFORMATION moduleInfo = (PSYSTEM_MODULE_INFORMATION)buffer.data();
	printf("Module count: %lu\n", moduleInfo->ModuleCount);
	return buffer;
}


void Emulate::ZwQuerySystemInformation(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {

	Logger::Log(true, ConsoleColor::RED, "ZwQuerySystemInformation\n");
	auto emu = Emu(uc);
	uint64_t SystemInformationClass = emu->rcx();
    uint64_t SystemInformation = emu->rdx();
    uint64_t SystemInformationLength = emu->r8();
    uint64_t ReturnLength = emu->r9();
    uint64_t rsp;

	Logger::Log(true, ConsoleColor::YELLOW, "SystemInformationClass : 0x%llx SystemInformation: 0x%llx \n", SystemInformationClass, SystemInformation);

	if (SystemInformationClass == 0x67) {

		SYSTEM_CODEINTEGRITY_INFORMATION Integrity = { sizeof(Integrity),0 };
		uint32_t retLen;
		uint32_t status = __NtRoutine("NtQuerySystemInformation", SystemInformationClass, &Integrity,
			sizeof(Integrity), &retLen);
		Logger::Log(true, ConsoleColor::RED, "returned : 0x%llx Integrity: %x\n", status, Integrity.CodeIntegrityOptions);
		Integrity.CodeIntegrityOptions = 0x2001;
		emu->write(SystemInformation, Integrity);
		if (ReturnLength != 0) {
			emu->write(ReturnLength, retLen);
			RetHook(uc);
			return;
		}
		emu->rax(status);
		RetHook(uc);
		return;
	}

	if (SystemInformationClass == 0x4d)
	{
		loader->sysinfo_addr = SystemInformation;
	}
}

void Emulate::_vswprintf_s(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	DWORD tid = GetCurrentThreadId();
	for (auto& ti : loader->Threads) {
		if (ti->threadId != tid) {
			ResetEvent(ti->Event);
		}
		else if (ti->threadId == tid) {
			loader->errorevent = ti->Event;
		}
	}

	auto restore_threads = [&]() {
		for (auto& ti : loader->Threads) {
			SetEvent(ti->Event);
		}
		loader->errorevent = nullptr;
		};

	Logger::Log(true, ConsoleColor::RED, L"_vswprintf_s\n");

	auto emu = Emu(uc);
	uint64_t buffer_ptr = emu->rcx();
	uint64_t sizeInWords = emu->rdx();
	uint64_t format_ptr = emu->r8();
	uint64_t va_args_ptr = emu->r9();

	if (sizeInWords == 0 || sizeInWords > 0x100000) {
		wchar_t zero = L'\0';
		emu->write(buffer_ptr, &zero, sizeof(wchar_t));
		emu->rax(static_cast<uint64_t>(-1));
		RetHook(uc);
		restore_threads();
		return;
	}

	std::wstring format;
	for (uint64_t addr = format_ptr;; addr += sizeof(wchar_t)) {
		wchar_t ch = 0;
		if (!emu->try_read(addr, &ch, sizeof(ch))) {
			break;
		}
		format.push_back(ch);
		if (ch == L'\0') {
			break;
		}
	}
	if (format.empty() || format.back() != L'\0') {
		format.push_back(L'\0');
	}

	std::vector<uint64_t> guest_args;
	guest_args.reserve(32);
	for (int i = 0; i < 64; ++i) {
		uint64_t offset = va_args_ptr + static_cast<uint64_t>(i) * sizeof(uint64_t);
		if (auto value = emu->try_read<uint64_t>(offset)) {
			guest_args.push_back(*value);
		}
		else {
			break;
		}
	}

	std::wstringstream ws;
	size_t arg_idx = 0;

	for (size_t i = 0; i < format.size(); ++i) {
		if (format[i] == L'%' && i + 1 < format.size()) {
			size_t j = i + 1;
			int zero_pad = 0;

			if (j < format.size() && format[j] == L'0' && j + 1 < format.size() && iswdigit(format[j + 1])) {
				j++;
				while (j < format.size() && iswdigit(format[j])) {
					zero_pad = zero_pad * 10 + (format[j] - L'0');
					j++;
				}
			}

			if (j + 1 < format.size() && format[j] == L'h' && format[j + 1] == L'u') {
				if (arg_idx < guest_args.size()) {
					uint16_t val = static_cast<uint16_t>(guest_args[arg_idx++]);
					ws << std::setfill(L'0') << std::setw(zero_pad) << val;
				}
				i = j + 1;
			}
			else if (format[j] == L'u' && arg_idx < guest_args.size()) {
				uint32_t val = static_cast<uint32_t>(guest_args[arg_idx++]);
				ws << std::setfill(L'0') << std::setw(zero_pad) << val;
				i = j;
			}
			else if (format[j] == L'X' && arg_idx < guest_args.size()) {
				uint32_t val = static_cast<uint32_t>(guest_args[arg_idx++]);
				ws << std::uppercase << std::hex << std::setfill(L'0') << std::setw(zero_pad) << val << std::dec;
				i = j;
			}
			else if (format[j] == L'S' && arg_idx < guest_args.size()) {
				char tmp[512] = {};
				if (emu->try_read(guest_args[arg_idx++], tmp, sizeof(tmp))) {
					std::string ansi_tmp(tmp);
					std::wstring wide_tmp;
					ANSIToUnicode(ansi_tmp, wide_tmp);
					ws << wide_tmp.c_str();
				}
				i = j;
			}
			else if (format[j] == L's' && arg_idx < guest_args.size()) {
				wchar_t tmp[512] = {};
				if (emu->try_read(guest_args[arg_idx++], tmp, sizeof(tmp))) {
					ws << tmp;
				}
				i = j;
			}
			else if ((format[j] == L'd' || format[j] == L'i') && arg_idx < guest_args.size()) {
				int64_t val = static_cast<int64_t>(guest_args[arg_idx++]);
				ws << std::setfill(L'0') << std::setw(zero_pad) << val;
				i = j;
			}
			else if (format[j] == L'x' && arg_idx < guest_args.size()) {
				int64_t val = static_cast<int64_t>(guest_args[arg_idx++]);
				ws << std::hex << std::setfill(L'0') << std::setw(zero_pad) << val << std::dec;
				i = j;
			}
			else {
				ws << format[i];
			}
		}
		else {
			ws << format[i];
		}
	}

	std::wstring result = ws.str();
	size_t required = result.size() + 1;
	if (required > sizeInWords) {
		wchar_t zero = L'\0';
		emu->write(buffer_ptr, &zero, sizeof(wchar_t));
		emu->rax(static_cast<uint64_t>(-1));
		RetHook(uc);
		restore_threads();
		return;
	}

	Logger::Log(true, ConsoleColor::RED, L"%ls\n", result.c_str());
	emu->write(buffer_ptr, result.c_str(), required * sizeof(wchar_t));
	emu->rax(static_cast<uint64_t>(result.size()));
	RetHook(uc);
	restore_threads();
}

void Emulate::_swprintf_s(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	DWORD tid = GetCurrentThreadId();
	for (auto& ti : loader->Threads) {
		if (ti->threadId != tid) {
			ResetEvent(ti->Event);
		}
		else {
			loader->errorevent = ti->Event;
		}
	}

	auto restore_threads = [&]() {
		for (auto& ti : loader->Threads) {
			SetEvent(ti->Event);
		}
		loader->errorevent = nullptr;
		};

	Logger::Log(true, ConsoleColor::RED, L"_swprintf_s\n");

	auto emu_sw = Emu(uc);
	uint64_t buffer_ptr = emu_sw->rcx();
	uint64_t sizeInWords = emu_sw->rdx();
	uint64_t format_ptr = emu_sw->r8();

	if (sizeInWords == 0 || sizeInWords > 0x100000) {
		wchar_t zero = L'\0';
		emu_sw->write(buffer_ptr, &zero, sizeof(wchar_t));
		emu_sw->rax(static_cast<uint64_t>(-1));
		RetHook(uc);
		restore_threads();
		return;
	}

	std::wstring format;
	for (uint64_t addr = format_ptr;; addr += sizeof(wchar_t)) {
		wchar_t ch = 0;
		if (!emu_sw->try_read(addr, &ch, sizeof(ch))) {
			break;
		}
		format.push_back(ch);
		if (ch == L'\0') {
			break;
		}
	}
	if (format.empty() || format.back() != L'\0') {
		format.push_back(L'\0');
	}

	std::vector<uint64_t> guest_args;
	guest_args.reserve(16);
	guest_args.push_back(emu_sw->r9());

	uint64_t rsp = emu_sw->rsp();
	for (int i = 0; i < 32; ++i) {
		uint64_t val = 0;
		if (!emu_sw->try_read(rsp + 0x28 + static_cast<uint64_t>(i) * 8, &val, sizeof(val))) {
			break;
		}
		guest_args.push_back(val);
	}

	size_t arg_idx = 0;
	auto next_arg = [&]() -> uint64_t {
		if (arg_idx < guest_args.size()) {
			return guest_args[arg_idx++];
		}
		return 0;
		};

	auto read_guest_cstring = [&](uint64_t addr) {
		std::string str;
		if (addr == 0) {
			return str;
		}
		for (size_t offset = 0; offset < 0x2000; ++offset) {
			char c = 0;
			if (!emu_sw->try_read(addr + offset, &c, sizeof(c))) {
				break;
			}
			if (c == '\0') {
				break;
			}
			str.push_back(c);
		}
		return str;
		};

	std::wstring result;
	result.reserve(format.size());

	size_t i = 0;
	while (i < format.size()) {
		wchar_t ch = format[i];
		if (ch == L'\0') {
			break;
		}
		if (ch != L'%') {
			result.push_back(ch);
			++i;
			continue;
		}
		if (i + 1 < format.size() && format[i + 1] == L'%') {
			result.push_back(L'%');
			i += 2;
			continue;
		}

		size_t j = i + 1;
		while (j < format.size()) {
			wchar_t flagChar = format[j];
			if (flagChar == L'-' || flagChar == L'+' || flagChar == L' ' || flagChar == L'#' || flagChar == L'0') {
				++j;
			}
			else {
				break;
			}
		}

		while (j < format.size() && iswdigit(format[j])) {
			++j;
		}

		if (j < format.size() && format[j] == L'.') {
			++j;
			while (j < format.size() && iswdigit(format[j])) {
				++j;
			}
		}

		size_t length_start = j;
		if (j < format.size()) {
			switch (format[j]) {
			case L'h':
				++j;
				if (j < format.size() && format[j] == L'h') {
					++j;
				}
				break;
			case L'l':
				++j;
				if (j < format.size() && format[j] == L'l') {
					++j;
				}
				break;
			case L'L':
			case L'w':
			case L'j':
			case L'z':
			case L't':
				++j;
				break;
			case L'I':
				++j;
				if (j + 1 < format.size() && format[j] == L'6' && format[j + 1] == L'4') {
					j += 2;
				}
				else if (j + 1 < format.size() && format[j] == L'3' && format[j + 1] == L'2') {
					j += 2;
				}
				break;
			default:
				break;
			}
		}

		if (j >= format.size()) {
			break;
		}

		wchar_t spec = format[j];
		size_t spec_pos = j;
		++j;
		std::wstring token = format.substr(i, j - i);
		std::wstring length_mod = format.substr(length_start, spec_pos - length_start);

		auto append_with_token = [&](auto value) -> bool {
			int needed = _scwprintf(token.c_str(), value);
			if (needed < 0) {
				return false;
			}
			std::vector<wchar_t> temp(static_cast<size_t>(needed) + 1, L'\0');
			if (_snwprintf_s(temp.data(), temp.size(), _TRUNCATE, token.c_str(), value) < 0) {
				return false;
			}
			result.append(temp.data());
			return true;
			};

		auto length_equals = [&](const wchar_t* mod) -> bool {
			return length_mod == mod;
			};

		bool handled = true;
		switch (spec) {
		case L'd':
		case L'i': {
			int64_t raw = static_cast<int64_t>(next_arg());
			if (length_equals(L"ll") || length_equals(L"I64")) {
				handled = append_with_token(static_cast<long long>(raw));
			}
			else if (length_equals(L"l")) {
				handled = append_with_token(static_cast<long>(raw));
			}
			else if (length_equals(L"hh")) {
				handled = append_with_token(static_cast<signed char>(raw));
			}
			else if (length_equals(L"h")) {
				handled = append_with_token(static_cast<short>(raw));
			}
			else {
				handled = append_with_token(static_cast<int>(raw));
			}
			break;
		}
		case L'u':
		case L'o':
		case L'x':
		case L'X': {
			uint64_t raw = next_arg();
			if (length_equals(L"ll") || length_equals(L"I64")) {
				handled = append_with_token(static_cast<unsigned long long>(raw));
			}
			else if (length_equals(L"l")) {
				handled = append_with_token(static_cast<unsigned long>(raw));
			}
			else if (length_equals(L"hh")) {
				handled = append_with_token(static_cast<unsigned char>(raw));
			}
			else if (length_equals(L"h")) {
				handled = append_with_token(static_cast<unsigned short>(raw));
			}
			else {
				handled = append_with_token(static_cast<unsigned int>(raw));
			}
			break;
		}
		case L'p': {
			uint64_t raw = next_arg();
			void* ptr_value = reinterpret_cast<void*>(raw);
			handled = append_with_token(ptr_value);
			break;
		}
		case L's': {
			uint64_t ptr = next_arg();
			const wchar_t* str_ptr = L"(null)";
			std::wstring tmp;
			if (ptr != 0) {
				std::wstring guest;
				read_null_unicode_string(uc, ptr, guest);
				tmp = std::move(guest);
				str_ptr = tmp.c_str();
			}
			handled = append_with_token(str_ptr);
			break;
		}
		case L'S': {
			uint64_t ptr = next_arg();
			const char* str_ptr = "(null)";
			std::string tmp;
			if (ptr != 0) {
				tmp = read_guest_cstring(ptr);
				str_ptr = tmp.c_str();
			}
			handled = append_with_token(str_ptr);
			break;
		}
		case L'c': {
			uint64_t raw = next_arg();
			wint_t ch_value = static_cast<wint_t>(raw);
			handled = append_with_token(ch_value);
			break;
		}
		case L'C': {
			uint64_t raw = next_arg();
			int ch_value = static_cast<int>(static_cast<unsigned char>(raw));
			handled = append_with_token(ch_value);
			break;
		}
		case L'f':
		case L'F':
		case L'e':
		case L'E':
		case L'g':
		case L'G':
		case L'a':
		case L'A': {
			uint64_t raw = next_arg();
			double value = 0.0;
			std::memcpy(&value, &raw, sizeof(value));
			handled = append_with_token(value);
			break;
		}
		case L'n': {
			uint64_t dest = next_arg();
			if (dest != 0) {
				int64_t count = static_cast<int64_t>(result.size());
				if (length_equals(L"ll") || length_equals(L"I64")) {
					long long value = static_cast<long long>(count);
					emu_sw->write(dest, &value, sizeof(value));
				}
				else if (length_equals(L"l")) {
					long value = static_cast<long>(count);
					emu_sw->write(dest, &value, sizeof(value));
				}
				else if (length_equals(L"hh")) {
					signed char value = static_cast<signed char>(count);
					emu_sw->write(dest, &value, sizeof(value));
				}
				else if (length_equals(L"h")) {
					short value = static_cast<short>(count);
					emu_sw->write(dest, &value, sizeof(value));
				}
				else {
					int value = static_cast<int>(count);
					emu_sw->write(dest, &value, sizeof(value));
				}
			}
			handled = true;
			break;
		}
		default:
			handled = false;
			break;
		}

		if (!handled) {
			result.append(token);
		}

		i = j;
	}

	size_t required = result.size() + 1;
	if (required > sizeInWords) {
		wchar_t zero = L'\0';
		emu_sw->write(buffer_ptr, &zero, sizeof(wchar_t));
		emu_sw->rax(static_cast<uint64_t>(-1));
		RetHook(uc);
		restore_threads();
		return;
	}

	emu_sw->write(buffer_ptr, result.c_str(), required * sizeof(wchar_t));
	Logger::Log(true, ConsoleColor::RED, L"%ls\n", result.c_str());
	emu_sw->rax(static_cast<uint64_t>(result.size()));
	RetHook(uc);
	restore_threads();
}


void Emulate::KeInsertQueueApc(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "KeInsertQueueApc\n");
	auto emu = Emu(uc);
	uint64_t status = 0;
	emu->rax(status);
	RetHook(uc);
}
void Emulate::KeInitializeApc(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "KeInitializeApc\n");
	auto emu = Emu(uc);
	uint64_t apc = emu->rcx();
	uint64_t inserted = 0;
	emu->try_write(apc + 0x52, &inserted, sizeof(inserted));

	RetHook(uc);
}


void Emulate::_vsnwprintf(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	DWORD tid = GetCurrentThreadId();
	for (auto& ti : loader->Threads) {
		if (ti->threadId != tid) {
			ResetEvent(ti->Event);
		}
		else if (ti->threadId == tid) {
			loader->errorevent = ti->Event;
		}
	}
	auto emu_vsnw = Emu(uc);
	uint64_t buffer_ptr = emu_vsnw->rcx();
	uint64_t sizeInWords = emu_vsnw->rdx();
	uint64_t format_ptr = emu_vsnw->r8();
	uint64_t va_args_ptr = emu_vsnw->r9();

	std::vector<uint64_t> guest_args;
	for (int i = 0; i < 8; ++i) {
		uint64_t val = 0;
		val = emu_vsnw->read<uint64_t>(va_args_ptr + i * 8);
		guest_args.push_back(val);
	}

	std::wstring format;
	for (uint64_t addr = format_ptr;; addr += sizeof(wchar_t)) {
		wchar_t ch;
		ch = emu_vsnw->read<wchar_t>(addr);
		format.push_back(ch);
		if (ch == L'\0') break;
	}

	std::wstringstream ws;
	size_t arg_idx = 0;

	for (size_t i = 0; i < format.size(); ++i) {
		if (format[i] == L'%' && i + 1 < format.size()) {
			size_t j = i + 1;
			int zero_pad = 0;

			if (format[j] == L'0' && iswdigit(format[j + 1])) {
				j++;
				while (j < format.size() && iswdigit(format[j])) {
					zero_pad = zero_pad * 10 + (format[j] - L'0');
					j++;
				}
			}

			if (j + 1 < format.size() && format[j] == L'h' && format[j + 1] == L'u') {
				if (arg_idx < guest_args.size()) {
					uint16_t val = static_cast<uint16_t>(guest_args[arg_idx++]);
					ws << std::setfill(L'0') << std::setw(zero_pad) << val;
				}
				i = j + 1;
			}
			else if (format[j] == L'u' && arg_idx < guest_args.size()) {
				uint32_t val = static_cast<uint32_t>(guest_args[arg_idx++]);
				ws << std::setfill(L'0') << std::setw(zero_pad) << val;
				i = j;
			}
			else if (format[j] == L'X' && arg_idx < guest_args.size()) {
				uint32_t val = static_cast<uint32_t>(guest_args[arg_idx++]);
				ws << std::uppercase << std::hex << std::setfill(L'0') << std::setw(zero_pad) << val << std::dec;
				i = j;
			}
			else if (format[j] == L'S' && arg_idx < guest_args.size()) {
				char tmp[512] = {};
				auto tmpData = emu_vsnw->read(guest_args[arg_idx++], sizeof(tmp));
				memcpy(tmp, tmpData.data(), tmpData.size());
				ws << tmp;
				i = j;
			}
			else if (format[j] == L's' && arg_idx < guest_args.size()) {
				wchar_t tmp[512] = {};
				auto tmpData = emu_vsnw->read(guest_args[arg_idx++], sizeof(tmp));
				memcpy(tmp, tmpData.data(), tmpData.size());
				ws << tmp;
				i = j;
			}
			else if ((format[j] == L'd' || format[j] == L'i') && arg_idx < guest_args.size()) {
				int64_t val = static_cast<int64_t>(guest_args[arg_idx++]);
				ws << std::setfill(L'0') << std::setw(zero_pad) << val;
				i = j;
			}
			else if (format[j] == L'x' && arg_idx < guest_args.size()) {
				int64_t val = static_cast<int64_t>(guest_args[arg_idx++]);
				ws << std::hex << std::setfill(L'0') << std::setw(zero_pad) << val << std::dec;
				i = j;
			}
			else {
				ws << format[i];
			}
		}
		else {
			ws << format[i];
		}
	}
	std::wstring result = ws.str();
	std::string results;
	UnicodeToANSI(result, results);
	if (strcmp(results.c_str(), "\n") != 0) {
		std::string s = results + " \n";
		Logger::Log(true, ConsoleColor::RED, "_vsnwprintf\n");
		Logger::Log(true, ConsoleColor::RED, s.c_str());
	}

	size_t write_len = sizeInWords;
	emu_vsnw->write(buffer_ptr, result.c_str(), result.size());

	int ret = ws.str().size();
	emu_vsnw->rax(static_cast<uint64_t>(ret));


	RetHook(uc);
	for (auto& ti : loader->Threads) {
		SetEvent(ti->Event);
		loader->errorevent = nullptr;
	}
}
void Emulate::KeInitializeTimer(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "KeInitializeTimer\n");

	auto emu = Emu(uc);
	uint64_t timer_ptr = emu->rcx();
	Logger::Log(true, ConsoleColor::RED, "called with timer ptr : 0x%llx\n", timer_ptr);

	struct FAKE_KTIMER {
		uint8_t Header[0x18];
    	uint64_t DueTime;
    	uint64_t TimerListEntry[2];
    	void* Dpc;
    	uint32_t Period;
    };

	FAKE_KTIMER fake_timer = {};
	fake_timer.Header[0] = 0x08;
	emu->write(timer_ptr, &fake_timer, sizeof(fake_timer));

	Logger::Log(true, ConsoleColor::RED, "KTIMER initialized(fake)\n");

	uint64_t status = 0;
    emu->rax(status);
	RetHook(uc);
}
void Emulate::KeSetTimer(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "KeSetTimer\n");

	auto emu = Emu(uc);
	uint64_t timer_ptr = emu->rcx();
    uint64_t due_time_ptr = emu->rdx();
    uint64_t dpc_ptr = emu->r8();
	Logger::Log(true, ConsoleColor::DARK_GREEN, "called\n    Timer Ptr:     0x%llx\n    DueTime Ptr:   0x%llx\n    DPC Ptr:       0x%llx", timer_ptr, due_time_ptr, dpc_ptr);


	const size_t offset_DueTime = 0x18;
    const size_t offset_Dpc = 0x28;
	int64_t due_time_value = emu->read<int64_t>(due_time_ptr);
	Logger::Log(true, ConsoleColor::DARK_GREEN, "DueTime value: %d (100ns units)\n", due_time_value);

	emu->write(timer_ptr + offset_DueTime, due_time_value);
	emu->write(timer_ptr + offset_Dpc, dpc_ptr);
	uint32_t signal = 1;
	emu->write(timer_ptr + 0x0C, signal);
	uint64_t result = 0;
	emu->rax(result);

	Logger::Log(true, ConsoleColor::DARK_GREEN, "KTIMER Set\n");
	RetHook(uc);
}

void Emulate::KeReadStateTimer(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "KeReadStateTimer\n");
	return;
	auto emu = Emu(uc);
	uint64_t Timer = emu->rcx();
    int32_t SignalState = 0;
	emu->try_read(Timer + 0x4, &SignalState, sizeof(SignalState));

	Logger::Log(true, ConsoleColor::DARK_GREEN,
		"KeReadStateTimer\n"
		"  Timer: 0x%llx\n"
		"  SignalState: %d\n",
		Timer, SignalState);
	emu->rax(SignalState);

	RetHook(uc);
}
void Emulate::ExCreateCallback(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "ExCreateCallback\n");
	auto emu = Emu(uc);
	uint64_t callbackObjectPtr = emu->rcx();
    uint64_t ObjectAttributesAddr = emu->rdx();
    uint64_t create = emu->r8();
    uint64_t allowMultiple = emu->r9();
	OBJECT_ATTRIBUTES ObjectAttributes;
	ObjectAttributes = emu->read<OBJECT_ATTRIBUTES>(ObjectAttributesAddr);
	std::wstring file_name_str = read_unicode_string(uc, (uint64_t)ObjectAttributes.ObjectName);
	std::string str;
	UnicodeToANSI(file_name_str, str);
	Logger::Log(true, 8, "%s \n", str.c_str());

	uint64_t fake_callback_object = Emulate::HeapAlloc(uc, 0x1000);
	emu->write(callbackObjectPtr, fake_callback_object);

	uint64_t status = 0;
	emu->rax(status);

	Logger::Log(true, ConsoleColor::RED, "CallbackObject 0x%llx\n", fake_callback_object);
	RetHook(uc);
}
void Emulate::DebugPrompt(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "DebugPrompt\n");
	RetHook(uc);
}
void Emulate::DbgPrompt(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "DbgPrompt\n");
	auto emu = Emu(uc);
	uint64_t promptPtr = emu->rcx();
    uint64_t responsePtr = emu->rdx();
    uint64_t maxLen = emu->r8();
	std::vector<uint8_t> promptBuf = emu->read(promptPtr, 255);
	promptBuf.push_back(0);
	std::string prompt(reinterpret_cast<char*>(promptBuf.data()));
	uint64_t rsp = emu->rsp();
	auto lastExceptData = emu->read(rsp, sizeof(loader->lastExcept));
	memcpy(&loader->lastExcept, lastExceptData.data(), lastExceptData.size());
	Logger::Log(true, 12, "%s\n", prompt.c_str());
	Unicorn::seh_Handle(uc);

}


void Emulate::ExAcquireRundownProtection(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "ExAcquireRundownProtection\n");
	auto emu = Emu(uc);
	uint64_t rundownRefPtr = emu->rcx();

	uint64_t count = emu->qword(rundownRefPtr);

	Logger::Log(true, ConsoleColor::RED, "called, Count = %d\n", count);

	bool success = false;

	if (count != 0 && count < 0xFFFFFFF0) {
		count++;
    	emu->write(rundownRefPtr, count);
		success = true;
	}

	uint64_t result = 1;
	emu->rax(result);

	Logger::Log(true, ConsoleColor::RED, "Result = %s\n", (success ? "TRUE" : "FALSE"));
	RetHook(uc);
}



void Emulate::_wcscpy_s(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "_wcscpy_s\n");
	auto emu = Emu(uc);
	uint64_t dest_addr = emu->rcx();

	rsize_t destsz = static_cast<rsize_t>(emu->rdx());

	uint64_t src_addr = emu->r8();
	std::wstring src_str;
	read_null_unicode_string(uc, src_addr, src_str);
	uint64_t rbp = emu->rbp();
	uint64_t rbpValue;

	rbpValue = emu->read<uint64_t>(rbp - 0x49);
	size_t total_length = src_str.length() + 1;

	if (total_length * sizeof(wchar_t) > destsz) {
		Logger::Log(true, ConsoleColor::RED, "wcscpy_s: Buffer too small need %zu bytes; Got %zu bytes\n", total_length * sizeof(wchar_t), destsz);


		uint64_t error_code = 22;
    	emu->rax(error_code);
		RetHook(uc);
		return;
	}

	emu->write(dest_addr, src_str.c_str(), total_length * sizeof(wchar_t));

	Logger::Log(true, ConsoleColor::RED, "wcscpy_s: Copied string = %s\n", std::string(src_str.begin(), src_str.end()));

	uint64_t success_code = 0;
	emu->rax(success_code);

	RetHook(uc);
}
void Emulate::KeIpiGenericCall(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	Logger::Log(true, ConsoleColor::RED, "KeIpiGenericCall\n");
	auto emu = Emu(uc);
	uint64_t routine = emu->rcx();
    uint64_t context = emu->rdx();
	emu->rip(routine);
	Logger::Log(true, 12, " jmp to %llx\n", routine);


}
void Emulate::KdChangeOption(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "KdChangeOption\n");
	auto emu = Emu(uc);
	emu->rax(0xC0000354);
    RetHook(uc);
}

void Emulate::MmIsAddressValid(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "MmIsAddressValid\n");
	auto emu = Emu(uc);
	uint64_t virtAddr = emu->rcx();

	bool isValid = false;
	uint64_t tmp = 0;
	if (emu->try_read(virtAddr, &tmp, sizeof(tmp))) {
		isValid = true;
	}
	emu->rax(isValid);
	Logger::Log(true, 12, "Address 0x%llx is %s\n", virtAddr, isValid ? "valid" : "invalid");

	RetHook(uc);
}
void Emulate::RtlInitializeBitMap(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "RtlInitializeBitMap\n");
	auto emu = Emu(uc);
	uint64_t bitmap_struct_addr = emu->rcx();
	uint64_t bitmap_buffer_addr = emu->rdx();
	uint64_t bit_size = emu->r8();

	struct {
		uint32_t SizeOfBitMap;
		uint64_t Buffer;
	} RTL_BITMAP_STRUCT;

	RTL_BITMAP_STRUCT.SizeOfBitMap = (uint32_t)bit_size;
	RTL_BITMAP_STRUCT.Buffer = bitmap_buffer_addr;

	emu->write(bitmap_struct_addr, &RTL_BITMAP_STRUCT, sizeof(RTL_BITMAP_STRUCT));
	Logger::Log(true, ConsoleColor::RED, "Bitmap initialized at 0x%llx Buffer address %llx\n", bitmap_struct_addr, bitmap_buffer_addr);

	RetHook(uc);}

void Emulate::RtlSetBits(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "RtlSetBits\n");
	auto emu = Emu(uc);
	uint64_t bitmap_addr = emu->rcx();
    uint64_t start_index = emu->rdx();
    uint64_t bit_count = emu->r8();
	if (bitmap_addr == 0 || bit_count == 0) {
		std::cerr << "[-] RtlSetBits: Invalid parameters (null or zero count)" << std::endl;
		RetHook(uc);
		return;
	}

	struct {
		ULONG  SizeOfBitMap;
		uint64_t Buffer;
	} bitmap;

	bitmap = emu->read<decltype(bitmap)>(bitmap_addr);


	if (bitmap.Buffer == 0 || bitmap.SizeOfBitMap == 0 || start_index + bit_count > bitmap.SizeOfBitMap) {
		std::cerr << "[-] RtlSetBits: Invalid bitmap range or buffer" << std::endl;
		RetHook(uc);
		return;
	}
	Logger::Log(true, ConsoleColor::RED, "RtlSetBits: Set %d bits at pos 0x%llx (Total bits: 0x%llx) Buffer=0x%llx\n", bit_count, start_index, bitmap.SizeOfBitMap, bitmap.Buffer);

	/*for (uint32_t i = 0; i < bit_count; ++i) {
		uint32_t bit_index = (uint32_t)(start_index + i);
		uint64_t byte_offset = bit_index / 8;
		uint8_t  bit_mask = 1 << (bit_index % 8);

		uint8_t byte_value = 0;
		uc_mem_read(uc, bitmap_addr + byte_offset, &byte_value, 1);
		byte_value |= bit_mask;
		uc_mem_write(uc, bitmap_addr + byte_offset, &byte_value, 1);
	}*/



	Logger::Log(true, 12, "RtlSetBits: Set %llx bits at pos %llx (Total bits : %llx ) Address: %llx\n", bit_count, start_index, bitmap.SizeOfBitMap, bitmap_addr);

	PEloader* loader = &PEloader::GetInstance();
	uint64_t t;

}

bool EnableDebugPrivilege() {
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return false;

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
		CloseHandle(hToken);
		return false;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
	CloseHandle(hToken);

	return result && GetLastError() == ERROR_SUCCESS;
}
void Emulate::PsLookupProcessByProcessId(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "PsLookupProcessByProcessId\n");
	auto emu = Emu(uc);
	uint64_t pid = emu->rcx();
	uint64_t outEprocessPtr = emu->rdx();
	Logger::Log(true, ConsoleColor::RED, "PsLookupProcessByProcessId Search PID: %llx\n", pid);
	if (pid == 4) {
		uint64_t base = 0;
		emu->rdx(base);
		Logger::Log(true, 12, "PsLookupProcessByProcessId System 4\n");
		uint64_t status = STATUS_SUCCESS;
    	emu->rax(status);
		RetHook(uc);
		return;
	}
	uint64_t status = 0xC000000D;
    emu->rax(status);
	RetHook(uc);
}

void Emulate::PsGetProcessImageFileName(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "PsGetProcessImageFileName\n");
	return;
	auto emu = Emu(uc);
	uint64_t eprocess = emu->rcx();
	if (eprocess == 0) {
		Logger::Log(true, ConsoleColor::DARK_GREEN, "PsGetProcessImageFileName: Invalid EPROCESS pointer \n ");
		uint64_t null = 0;
		emu->rax(null);
		RetHook(uc);
		return;
	}

	uint64_t image_name_addr = emu->read<uint64_t>(eprocess + 0x5a8);
    char image_name[16] = { 0 };
    emu->try_read(image_name_addr, image_name, sizeof(image_name));
    emu->rax(image_name_addr);

	Logger::Log(true, ConsoleColor::DARK_GREEN, "ImageFileName: %s\n", image_name);

	RetHook(uc);
}

void Emulate::PsGetProcessSectionBaseAddress(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "PsGetProcessSectionBaseAddress\n");
	auto emu = Emu(uc);
	uint64_t eprocess = emu->rcx();

	if (eprocess == 0) {
		Logger::Log(true, ConsoleColor::GREEN, "PsGetProcessSectionBaseAddress: Invalid EPROCESS\n");
		Logger::Log(true, ConsoleColor::DARK_GREEN, "PsGetProcessSectionBaseAddress: Invalid EPROCESS pointer \n");
		uint64_t null = 0;
		emu->rax(null);
		RetHook(uc);
		return;
	}

	uint64_t image_base = emu->read<uint64_t>(eprocess + 0x520);
	Logger::Log(true, ConsoleColor::DARK_GREEN, "PsGetProcessSectionBaseAddress: ImageBase = 0x%llx\n", image_base);

	emu->rax(image_base);
	RetHook(uc);
}

void Emulate::PsGetSessionId(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "PsGetSessionId\n");
	auto emu = Emu(uc);
	uint64_t eprocess = emu->rcx();

	if (eprocess == 0) {
		Logger::Log(true, ConsoleColor::DARK_GREEN, "PsGetSessionId: Invalid EPROCESS pointer \n");
		uint64_t zero = 0;
		emu->rax(zero);
		RetHook(uc);
		return;
	}

	uint32_t sessionId = emu->read<uint32_t>(eprocess + 0x448);
	Logger::Log(true, ConsoleColor::DARK_GREEN, "PsGetSessionId : Session ID = %d\n", sessionId);

	emu->rax(static_cast<uint64_t>(sessionId));
	RetHook(uc);
}

typedef enum _FILE_INFORMATION_CLASS {
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation,
	FileBothDirectoryInformation,
	FileBasicInformation = 4,
	FileStandardInformation = 5,
} FILE_INFORMATION_CLASS;

void Emulate::IoCreateFileEx(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "IoCreateFileEx\n");
	auto emu = Emu(uc);
	uint64_t FileHandle, DesiredAccess, ObjectAttributesAddr, IoStatusBlock, AllocationSize, DriverContext, InternalParameters;
	uint32_t FileAttributes, ShareAccess, Disposition, CreateOptions, CreateFileType, EaBuffer, EaLength;
	FileHandle = emu->rcx();

	DesiredAccess = emu->rdx();
	uint32_t DesiredAccess32 = static_cast<uint32_t>(DesiredAccess);
    ObjectAttributesAddr = emu->r8();
	OBJECT_ATTRIBUTES ObjectAttributes;
	emu->try_read(ObjectAttributesAddr, &ObjectAttributes, sizeof(ObjectAttributes));
	std::wstring file_name_str = read_unicode_string(uc, (uint64_t)ObjectAttributes.ObjectName);
	std::string str;
	UnicodeToANSI(file_name_str, str);
	Logger::Log(true, 12, "IoCreateFileEx Path: %s\n", str.c_str());
	IoStatusBlock = emu->r9();

	uint64_t rsp = emu->rsp();
	rsp = rsp + 8;
	emu->try_read(rsp + 0x20, &AllocationSize, sizeof(AllocationSize));
	emu->try_read(rsp + 0x28, &FileAttributes, sizeof(FileAttributes));
	emu->try_read(rsp + 0x30, &ShareAccess, sizeof(ShareAccess));
	emu->try_read(rsp + 0x38, &Disposition, sizeof(Disposition));
	emu->try_read(rsp + 0x40, &CreateOptions, sizeof(CreateOptions));
	emu->try_read(rsp + 0x48, &EaBuffer, sizeof(EaBuffer));
	emu->try_read(rsp + 0x50, &EaLength, sizeof(EaLength));
	emu->try_read(rsp + 0x58, &CreateFileType, sizeof(CreateFileType));
	emu->try_read(rsp + 0x70, &DriverContext, sizeof(DriverContext));
	emu->try_read(rsp + 0x80, &InternalParameters, sizeof(InternalParameters));
	UNICODE_STRING KeyPath;
	ConvertToUnicodeString(KeyPath, file_name_str);
	OBJECT_ATTRIBUTES objAttr = { 0 };
	InitializeObjectAttributes(&objAttr, (uint64_t)&KeyPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
	IO_STATUS_BLOCK io_status = { 0 };
	LARGE_INTEGER allocationSize;
	allocationSize.QuadPart = 0;
    HANDLE real_file_handle = nullptr;

	std::wstring prefix = L"\\??\\";
	std::wstring system32prefix = L"system32";
	std::wstring System32prefix = L"System32";
	std::wstring vgkbootstatusprefix = L"vgkbootstatus";
#define FILE_OPEN                       0x00000001
	if (file_name_str.find(system32prefix, 0) != std::wstring::npos ||
		file_name_str.find(System32prefix, 0) != std::wstring::npos ||
		file_name_str.find(vgkbootstatusprefix, 0) != std::wstring::npos)
	{
		auto ret = __NtRoutine("NtCreateFile", &real_file_handle,
			DesiredAccess,
			&objAttr,
			&io_status,
			nullptr,
			FileAttributes,
			ShareAccess,
			Disposition,
			CreateOptions,
			nullptr,
			0
		);
		emu->write(IoStatusBlock, &io_status, sizeof(io_status));

		Logger::Log(true, 10, "NtCreateFile Handle %llx    status : %lx \n", real_file_handle, ret);

		emu->write(FileHandle, &real_file_handle, sizeof(real_file_handle));
		emu->rax(ret);
		RetHook(uc);
		return;
	}
	else
	{
		if (file_name_str.rfind(prefix, 0) == 0) {
			file_name_str = file_name_str.substr(prefix.length());
    	}
		real_file_handle = CreateFile(
			file_name_str.c_str(),			FILE_APPEND_DATA,			FILE_SHARE_READ | FILE_SHARE_WRITE,			NULL,			OPEN_ALWAYS,			FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,			NULL		);

		if (real_file_handle == INVALID_HANDLE_VALUE) {
			DWORD errorCode = GetLastError();
			std::cerr << "CreateFile failed, error code: " << errorCode << std::endl;
			auto ret = 0xC000000D;
			emu->rax(ret);
			RetHook(uc);
			return;
		}
		else
		{
			auto ret = 0;
			Logger::Log(true, 10, "CreateFile Handle %llx    status : %lx \n", real_file_handle, ret);
			emu->write(FileHandle, &real_file_handle, sizeof(real_file_handle));
			emu->rax(ret);
			RetHook(uc);
			return;
		}

	}
}

void Emulate::wcscat_s(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "wcscat_s\n");
	auto emu = Emu(uc);
	uint64_t dest_addr = emu->rcx();

	rsize_t destsz = static_cast<rsize_t>(emu->rdx());

	uint64_t src_addr = emu->r8();

	std::wstring dest_str;
	read_null_unicode_string(uc, dest_addr, dest_str);
	std::wstring src_str;
	read_null_unicode_string(uc, src_addr, src_str);
	size_t total_length = dest_str.length() + src_str.length() + 1;

	if (total_length * sizeof(wchar_t) > destsz) {
		Logger::Log(true, ConsoleColor::DARK_GREEN, " wcscat_s: Target buffer too small! Need %d bytes, but only %d \n", total_length * sizeof(wchar_t), destsz);
		uint64_t error_code = 22;
    	emu->rax(error_code);
		return;
	}

	dest_str += src_str;

	emu->write(dest_addr, dest_str.c_str(), total_length * sizeof(wchar_t));

	Logger::Log(true, ConsoleColor::RED, "wcscat_s: Concat = %s\n", std::string(dest_str.begin(), dest_str.end()).c_str());
	uint64_t success_code = 0;
	emu->rax(success_code);

	RetHook(uc);
}

void Emulate::RtlMultiByteToUnicodeN(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "RtlMultiByteToUnicodeN\n");
	auto emu = Emu(uc);
	uint64_t unicode_str_ptr = emu->rcx();
    uint64_t unicode_size = emu->rdx();
    uint64_t result_size_ptr = emu->r8();
    uint64_t multi_byte_str_ptr = emu->r9();
    uint64_t rsp_value = emu->rsp();
	uint64_t multi_byte_size_addr = rsp_value + 0x28;
	uint32_t multi_byte_size = 0;
	emu->try_read(multi_byte_size_addr, &multi_byte_size, sizeof(multi_byte_size));


	std::vector<char> multi_byte_str(multi_byte_size + 1, 0);
	emu->try_read(multi_byte_str_ptr, multi_byte_str.data(), multi_byte_size);

	int wide_char_size = MultiByteToWideChar(CP_ACP, 0, multi_byte_str.data(), -1, NULL, 0);
	std::vector<wchar_t> unicode_str(wide_char_size, 0);
	MultiByteToWideChar(CP_ACP, 0, multi_byte_str.data(), -1, unicode_str.data(), wide_char_size);

	uint64_t unicode_length = unicode_str.size() + 1 * sizeof(wchar_t);

	uint64_t status = 0;
    if (unicode_length > unicode_size) {
		unicode_length = unicode_size;
		status = 0xC0000023;
    }

	Logger::Log(true, ConsoleColor::DARK_GREEN, "Before conversion (MultiByte): %s After conversion (Unicode): %s \n", multi_byte_str.data(), unicode_str.data());

	emu->write(unicode_str_ptr, unicode_str.data(), unicode_size);

	if (result_size_ptr) {
		emu->write(result_size_ptr, &unicode_size, sizeof(uint32_t));
	}

	emu->rax(status);
	RetHook(uc);
}


std::map<std::string, std::map<std::string, std::vector<uint8_t>>> Emulate::registry;
void Emulate::RtlWriteRegistryValue(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "RtlWriteRegistryValue\n");
	auto emu = Emu(uc);
	uint64_t relativeTo = emu->rcx();
    uint64_t pathAddr = emu->rdx();
    uint64_t valueNameAddr = emu->r8();
    uint64_t valueType = emu->r9();
	uint64_t stackPointer = emu->rsp();

	uint64_t valueDataAddr = 0;
	emu->try_read(stackPointer + 0x28, &valueDataAddr, sizeof(valueDataAddr));
    uint64_t valueLength = 0;
	emu->try_read(stackPointer + 0x30, &valueLength, sizeof(valueLength));
	std::wstring wstr = read_unicode_string(uc, pathAddr);
	std::string str;
	UnicodeToANSI(wstr, str);

	std::wstring wstr_valueNameAddr = read_unicode_string(uc, valueNameAddr);
	std::string str_valueNameAddr;
	UnicodeToANSI(wstr_valueNameAddr, str_valueNameAddr);

	std::vector<uint8_t> valueData(static_cast<size_t>(valueLength));
	emu->try_read(valueDataAddr, valueData.data(), static_cast<size_t>(valueLength));

	std::string pathStr(str);
	std::string valueNameStr(str_valueNameAddr);
	registry[pathStr][valueNameStr] = valueData;

	Logger::Log(true, ConsoleColor::DARK_GREEN, " Path: %s ValueName : %s ValueType : %d ValueLength: %d \n", pathStr, valueNameStr, valueType, valueLength);

	uint64_t status = 0;
    emu->rax(status);
    RetHook(uc);
}

void Emulate::RtlDeleteRegistryValue(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "RtlDeleteRegistryValue\n");
	auto emu = Emu(uc);
	uint64_t relativeTo = emu->rcx();
    uint64_t pathAddr = emu->rdx();
    uint64_t valueNameAddr = emu->r8();
	std::wstring wstr = read_unicode_string(uc, pathAddr);
	std::string str;
	UnicodeToANSI(wstr, str);


	std::wstring wstr_valueNameAddr = read_unicode_string(uc, valueNameAddr);
	std::string str_valueNameAddr;
	UnicodeToANSI(wstr_valueNameAddr, str_valueNameAddr);



	Logger::Log(true, ConsoleColor::DARK_GREEN, " Value :%llx not found in path \n ", str_valueNameAddr);
	uint64_t status = 0xC0000034;
    emu->rax(status);
	RetHook(uc);
}

void Emulate::ZwOpenKey(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "ZwOpenKey\n");
	auto emu = Emu(uc);
	uint64_t keyHandleAddr = emu->rcx();
    uint64_t desiredAccess = emu->rdx();
    uint64_t objectAttributesAddr = emu->r8();
    uint64_t rsp = emu->rsp();

	OBJECT_ATTRIBUTES ObjectAttributes;
	emu->try_read(objectAttributesAddr, &ObjectAttributes, sizeof(ObjectAttributes));
    std::wstring file_name_str = read_unicode_string(uc, ObjectAttributes.ObjectName);
	std::string str;
	UnicodeToANSI(file_name_str, str);

	HANDLE realHandle = nullptr;
	UNICODE_STRING KeyPath;
	ConvertToUnicodeString(KeyPath, file_name_str);
	OBJECT_ATTRIBUTES objAttr = { 0 };
	InitializeObjectAttributes(&objAttr, (uint64_t)&KeyPath, objAttr.Attributes, nullptr, nullptr);

	NTSTATUS ret = __NtRoutine("NtOpenKey", &realHandle, (ACCESS_MASK)desiredAccess, &objAttr);
	Logger::Log(true, 12, "Directory name: %s status : %lx\n", str.c_str(), ret);
	if (ret == 0) {
		uint64_t t;
		emu->write(keyHandleAddr, &realHandle, sizeof(realHandle));
	}

	emu->rax(ret);
	RetHook(uc);
}
void Emulate::ZwQueryValueKey(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "ZwQueryValueKey\n");
	auto emu = Emu(uc);
	uint64_t rcx = emu->rcx();
    uint64_t rdx = emu->rdx();
    uint64_t r8 = emu->r8();
    uint64_t outBufPtr = emu->r9();
    uint32_t bufLen = 0;
	uint64_t rsp = emu->rsp();
    emu->try_read(rsp + 0x28, &bufLen, sizeof(bufLen));
	uint64_t resultLenPtr = 0;
	emu->try_read(rsp + 0x30, &resultLenPtr, sizeof(resultLenPtr));
	if (rcx == 0 || resultLenPtr == 0) {
		Logger::Log(true, 12, "ZwQueryValueKey: Invalid KeyHandle \n");
		uint64_t status = STATUS_INVALID_HANDLE;
		emu->rax(status);
		RetHook(uc);
		return;
	}

	std::wstring valueNameW = read_unicode_string(uc, rdx);
	std::string svalueNameW;
	UnicodeToANSI(valueNameW, svalueNameW);
	UNICODE_STRING valueName;
	ConvertToUnicodeString(valueName, valueNameW);
	std::vector<uint8_t> buffer(bufLen);
	ULONG resultLength = 0;
	NTSTATUS status = __NtRoutine("NtQueryValueKey",
		reinterpret_cast<HANDLE>(rcx),
		&valueName,
		r8,
		buffer.data(),
		(ULONG)bufLen,
		&resultLength);

	buffer.resize(resultLength);

	status = __NtRoutine("NtQueryValueKey",
		reinterpret_cast<HANDLE>(rcx),
		&valueName,
		r8,
		buffer.data(),
		(ULONG)resultLength,
		&resultLength);
	Logger::Log(true, 12, "ZwQueryValueKey KeyHandle: %llx  Value=:%s \n", rcx, svalueNameW.c_str());

	if (status == 0) {

		uint64_t buffer_temp = Emulate::HeapAlloc(uc, 0x1000);
		emu->write(buffer_temp, buffer.data(), buffer.size());
		emu->r9(buffer_temp);
    	emu->write(resultLenPtr, &resultLength, sizeof(ULONG));
	}

	emu->rax(status);
	RetHook(uc);
}
void Emulate::ZwCreateKey(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "ZwCreateKey\n");
	auto emu = Emu(uc);
	uint64_t rcx = emu->rcx();
    uint64_t rdx = emu->rdx();
    uint64_t r8 = emu->r8();
    uint64_t r9 = emu->r9();
    uint64_t r10 = emu->r10();
    uint64_t r11 = emu->r11();
	if (r8 == 0) {
		Logger::Log(true, ConsoleColor::DARK_GREEN, "Invalid ObjectAttributes \n");
		NTSTATUS status = STATUS_INVALID_PARAMETER;
		emu->rax(status);
		RetHook(uc);
		return;
	}

	OBJECT_ATTRIBUTES ObjectAttributes;
	emu->try_read(r8, &ObjectAttributes, sizeof(ObjectAttributes));
    std::wstring file_name_str = read_unicode_string(uc, (uint64_t)ObjectAttributes.ObjectName);

	std::string str;
	UnicodeToANSI(file_name_str, str);
	Logger::Log(true, ConsoleColor::DARK_GREEN, "Path: %s\n", str.c_str());
	static std::unordered_set<std::wstring> fake_registry_keys;
	uint64_t disposition = REG_CREATED_NEW_KEY;
	NTSTATUS status = STATUS_SUCCESS;

	if (fake_registry_keys.count(file_name_str)) {
		Logger::Log(true, ConsoleColor::DARK_GREEN, "Key Exist\n");
		disposition = REG_OPENED_EXISTING_KEY;
	}
	else {
		Logger::Log(true, ConsoleColor::GREEN, "Key does not exist, create new key\n");
		fake_registry_keys.insert(file_name_str);
	}

	uint64_t fake_handle = 0xaa;
	emu->write(rcx, &fake_handle, sizeof(fake_handle));

	emu->write(r11, &disposition, sizeof(disposition));

	emu->rax(status);
	RetHook(uc);
}


void Emulate::ZwSetValueKey(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "ZwSetValueKey\n");
	auto emu = Emu(uc);
	uint64_t hKey = emu->rcx();
	uint64_t valueNameAddr = emu->rdx();
	uint64_t titleIndex = emu->r8();
	uint64_t type = emu->r9();

	uint64_t rsp = emu->rsp();
	uint64_t dataAddr = 0;
	emu->try_read(rsp + 0x28, &dataAddr, sizeof(uint64_t));
	uint32_t dataSize = 0;
	emu->try_read(rsp + 0x30, &dataSize, sizeof(uint32_t));
	std::wstring file_name_str = read_unicode_string(uc, valueNameAddr);

	UNICODE_STRING realStr;
	ConvertToUnicodeString(realStr, file_name_str);
	std::string st;
	UnicodeToANSI(file_name_str, st);
	std::vector<uint8_t> buffer(dataSize);
	emu->try_read(dataAddr, buffer.data(), buffer.size());
	Logger::Log(true, DARK_GREEN, "KeyHandle: %llx  Value=:%s \n", hKey, st);
	auto ret = __NtRoutine("NtSetValueKey",
		reinterpret_cast<HANDLE>(hKey),
		&realStr,
		static_cast<ULONG>(titleIndex),
		static_cast<ULONG>(type),
		buffer.data(),
		static_cast<ULONG>(dataSize)
	);
	uint64_t status = ret;
    emu->rax(status);
	RetHook(uc);
}
void Emulate::ZwDeleteValueKey(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "ZwDeleteValueKey\n");
	auto emu = Emu(uc);
	uint64_t KeyHandle = emu->rcx();
    uint64_t ValueNamePtr = emu->rdx();
	std::wstring value_name = read_unicode_string(uc, ValueNamePtr);


	std::string found_key;

	for (const auto& entry : registryHandles) {
		if (entry.second == KeyHandle) {
			found_key = entry.first;
			break;
    	}
	}
	std::wstring key_name;
	ANSIToUnicode(found_key, key_name);
	std::wstring key_path = key_name;



	RetHook(uc);
}

void Emulate::RtlRandomEx(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t seed_ptr;
    uint64_t rip;
    uint32_t seed_value;
    uint32_t random_value;
	seed_ptr = emu->rcx();
    rip = emu->rip();
    emu->try_read(seed_ptr, &seed_value, sizeof(seed_value));

	seed_value = seed_value * 214013 + 2531011;
	random_value = (seed_value >> 16) & 0x7FFFFFFF;

	emu->write(seed_ptr, &seed_value, sizeof(seed_value));

	emu->rax(random_value);
	RetHook(uc);
}

void Emulate::KeAreAllApcsDisabled(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	Logger::Log(true, ConsoleColor::RED, "KeAreAllApcsDisabled\n");
	return;
	uint64_t status = 0;
    auto emu = Emu(uc);
	emu->rax(status);
	RetHook(uc);
}
void Emulate::KeInitializeGuardedMutex(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "KeInitializeGuardedMutex\n");
	auto emu = Emu(uc);
	uint64_t mutexPtr = emu->rcx();
	Logger::Log(true, ConsoleColor::RED, "Initialize @ 0x%llx\n", mutexPtr);

	RetHook(uc);

}

void Emulate::ZwDeviceIoControlFile(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t fileHandle = emu->rcx();
	uint64_t event = emu->rdx();
	uint64_t ioStatusBlock = emu->r8();
	uint64_t apcRoutine = emu->r9();
	uint64_t apcContext = 0;
	uint64_t ioControlCode = 0;
	uint64_t inputBuffer = 0;
	uint32_t inputBufferLength = 0;
	uint64_t outputBuffer = 0;
	uint32_t outputBufferLength = 0;

	uint64_t rsp = emu->rsp();
	emu->try_read(rsp + 0x8, &ioStatusBlock, sizeof(uint64_t));
	emu->try_read(rsp + 0x28, &apcContext, sizeof(uint64_t));
	emu->try_read(rsp + 0x30, &ioControlCode, sizeof(uint64_t));
	emu->try_read(rsp + 0x38, &inputBuffer, sizeof(inputBuffer));
	emu->try_read(rsp + 0x40, &inputBufferLength, sizeof(inputBufferLength));
	emu->try_read(rsp + 0x48, &outputBuffer, sizeof(outputBuffer));
	emu->try_read(rsp + 0x50, &outputBufferLength, sizeof(outputBufferLength));
	Logger::Log(true, ConsoleColor::RED, "ZwDeviceIoControlFile\n");
	Logger::Log(true, ConsoleColor::RED, "IOCTL = 0x%llx \n", ioControlCode);
	std::vector<uint8_t> input(inputBufferLength);
	emu->try_read(inputBuffer, input.data(), inputBufferLength);

	std::vector<uint8_t> output(outputBufferLength, 0);
	DWORD bytesReturned = 0;


	BOOL result = ::DeviceIoControl(
		(HANDLE)fileHandle,
		static_cast<DWORD>(ioControlCode),
		input.data(), static_cast<DWORD>(input.size()),
		output.data(), static_cast<DWORD>(output.size()),
		&bytesReturned,
		nullptr
	);

	NTSTATUS status = result ? 0 : HRESULT_FROM_WIN32(GetLastError());

	if (result) {
		emu->write(outputBuffer, output.data(), bytesReturned);
	}

	struct IO_STATUS_BLOCK {
		NTSTATUS Status;
		ULONG_PTR Information;
	} iosb = { status, bytesReturned };

	emu->write(ioStatusBlock, &iosb, sizeof(iosb));
	emu->rax(status);
	RetHook(uc);
}


void Emulate::ZwCreateFile(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "ZwCreateFile\n");
	auto emu = Emu(uc);
	uint64_t FileHandle, DesiredAccess, ObjectAttributesAddr, IoStatusBlock, AllocationSize, DriverContext, InternalParameters;
	uint32_t FileAttributes, ShareAccess, Disposition, CreateOptions, CreateFileType, EaBuffer, EaLength;
	FileHandle = emu->rcx();

	DesiredAccess = emu->rdx();
	uint32_t DesiredAccess32 = static_cast<uint32_t>(DesiredAccess);
    ObjectAttributesAddr = emu->r8();
	OBJECT_ATTRIBUTES ObjectAttributes;
	emu->try_read(ObjectAttributesAddr, &ObjectAttributes, sizeof(ObjectAttributes));
	std::wstring file_name_str = read_unicode_string(uc, (uint64_t)ObjectAttributes.ObjectName);
	std::string str;
	UnicodeToANSI(file_name_str, str);
	Logger::Log(true, ConsoleColor::RED, "Path: %s\n", str.c_str());
	IoStatusBlock = emu->r9();

	uint64_t rsp = emu->rsp();
	rsp = rsp + 8;
	emu->try_read(rsp + 0x20, &AllocationSize, sizeof(AllocationSize));
	emu->try_read(rsp + 0x28, &FileAttributes, sizeof(FileAttributes));
	emu->try_read(rsp + 0x30, &ShareAccess, sizeof(ShareAccess));
	emu->try_read(rsp + 0x38, &Disposition, sizeof(Disposition));
	emu->try_read(rsp + 0x40, &CreateOptions, sizeof(CreateOptions));
	emu->try_read(rsp + 0x48, &EaBuffer, sizeof(EaBuffer));
	emu->try_read(rsp + 0x50, &EaLength, sizeof(EaLength));
	emu->try_read(rsp + 0x58, &CreateFileType, sizeof(CreateFileType));
	emu->try_read(rsp + 0x70, &DriverContext, sizeof(DriverContext));
	emu->try_read(rsp + 0x80, &InternalParameters, sizeof(InternalParameters));
	UNICODE_STRING KeyPath;
	ConvertToUnicodeString(KeyPath, file_name_str);
	OBJECT_ATTRIBUTES objAttr = { 0 };
	InitializeObjectAttributes(&objAttr, (uint64_t)&KeyPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
	IO_STATUS_BLOCK io_status = { 0 };
	LARGE_INTEGER allocationSize;
	allocationSize.QuadPart = 0;
    uint32_t ret = 0;
	HANDLE real_file_handle = nullptr;


#define FILE_OPEN                       0x00000001

	ret = __NtRoutine("NtCreateFile", &real_file_handle,
		DesiredAccess,
		&objAttr,
		&io_status,
		nullptr,
		FileAttributes,
		ShareAccess,
		Disposition,
		CreateOptions,
		nullptr,
		0
	);
	emu->write(IoStatusBlock, &io_status, sizeof(io_status));

	Logger::Log(true, 10, "NtCreateFile Handle %llx    status : %llx \n", real_file_handle, ret);

	emu->write(FileHandle, &real_file_handle, sizeof(real_file_handle));
	emu->rax(ret);
	RetHook(uc);
	return;


}
void Emulate::ZwWriteFile(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "ZwWriteFile\n");
	auto emu = Emu(uc);
	uint64_t file_handle = emu->rcx();
	uint64_t event = emu->rdx();
	uint64_t apc_routine = emu->r8();
	uint64_t apc_context = emu->r9();
	uint64_t io_status_block = 0;
	uint64_t buffer_addr = 0;
	uint64_t byte_offset = 0;
	uint32_t key = 0;
	uint32_t length = 0;
	uint64_t rsp = emu->rsp();
	emu->try_read(rsp + 0x28, &io_status_block, sizeof(uint64_t));
	emu->try_read(rsp + 0x30, &buffer_addr, sizeof(uint64_t));
	emu->try_read(rsp + 0x38, &length, sizeof(uint32_t));
	emu->try_read(rsp + 0x40, &byte_offset, sizeof(uint64_t));
	emu->try_read(rsp + 0x48, &key, sizeof(uint32_t));

	if (file_handle == 0) {
		Logger::Log(true, ConsoleColor::DARK_GREEN, "Invalid file handle\n");
		uint64_t status_invalid = 0xC0000008;
    	emu->rax(status_invalid);
		RetHook(uc);
		return;
	}

	if (length == 0) {
		Logger::Log(true, ConsoleColor::DARK_GREEN, "Write length is 0, no operation\n");
		uint64_t status_success = 0x0;
    	emu->rax(status_success);
		RetHook(uc);
		return;
	}

	std::vector<uint8_t> buffer(length);
	if (!emu->try_read(buffer_addr, buffer.data(), length)) {
		Logger::Log(true, ConsoleColor::DARK_GREEN, "Unable to read buffer\n");
		uint64_t status_access_violation = 0xC0000005;
    	emu->rax(status_access_violation);
		RetHook(uc);
		return;
	}


	DWORD bytesWritten;
	uint64_t status = 0;
	BOOL writeSuccess = WriteFile(
		(HANDLE)file_handle,
		buffer.data(),
		buffer.size(),
		&bytesWritten,
		NULL	);

	if (!writeSuccess) {
		std::cerr << "WriteFile failed, error code: " << GetLastError() << std::endl;
		status = GetLastError();
	}
	else {
		Logger::Log(true, ConsoleColor::DARK_GREEN, "Write successful, bytes written: %d \n", bytesWritten);
	}


	Logger::Log(true, 10, "NtWriteFile Handle: %llx\nLength: %d\nContent: ", file_handle, length);
	for (size_t i = 0; i < length; i++) {
		Logger::Log(false, ConsoleColor::DARK_GREEN, "%llx", (int)buffer[i]);
	}
	Logger::Log(false, ConsoleColor::DARK_GREEN, "\n");




	emu->rax(status);
	RetHook(uc);
}
void Emulate::ZwFlushBuffersFile(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {

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
			Sleep(10);
		}
	}
	Logger::Log(true, ConsoleColor::RED, "ZwFlushBuffersFile\n");
	auto emu = Emu(uc);
	uint64_t status = 0;
	uint64_t file_handle_raw = emu->rcx();
	uint64_t io_status_block_raw = emu->rdx();
	HANDLE file_handle = reinterpret_cast<HANDLE>(file_handle_raw);
	PIO_STATUS_BLOCK io_status_block = reinterpret_cast<PIO_STATUS_BLOCK>(io_status_block_raw);

	Logger::Log(true, ConsoleColor::DARK_GREEN, "Flush file buffers, file handle: %llx\n", file_handle);
	if (!FlushFileBuffers(file_handle)) {

		status = GetLastError();
		std::cerr << "FlushFileBuffers failed, error code: " << status << std::endl;
	}
	else {
		Logger::Log(true, ConsoleColor::DARK_GREEN, "Data successfully written to disk!\n");
	}
	emu->write(io_status_block_raw, &io_status_block, sizeof(IO_STATUS_BLOCK));

	emu->rax(status);
	RetHook(uc);
	for (auto& ti : loader->Threads) {
		SetEvent(ti->Event);
		loader->errorevent = nullptr;
	}
}
void Emulate::KeGetCurrentIrql(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "KeGetCurrentIrql\n");
	auto emu = Emu(uc);
	uint64_t irql = emu->cr8();


	emu->rax(irql);
	RetHook(uc);
}
void Emulate::ZwQueryInformationFile(uc_engine* uc) {
	Logger::Log(true, ConsoleColor::RED, "ZwQueryInformationFile\n");
	auto emu = Emu(uc);
	uint64_t FileHandle = emu->rcx();
	uint64_t IoStatusBlock = emu->rdx();
	uint64_t FileInformation = emu->r8();
	uint64_t Length = emu->r9();

	uint64_t rsp = emu->rsp();
	uint64_t FileInformationClass = 0;
	emu->try_read(rsp + 0x20, &FileInformationClass, sizeof(uint64_t));
	IO_STATUS_BLOCK _IoStatusBlock = { 0 };

	Logger::Log(true, ConsoleColor::RED, " Handle: %llx, InfoClass: %d\n", FileHandle, FileInformationClass);
	uint32_t status = 0xc0000003;
	PEloader* loader = &PEloader::GetInstance();
	auto it = loader->handle_table.find(FileHandle);

	if (FileInformationClass == 5) {		FILE_STANDARD_INFORMATION _FileInformation = { sizeof(FILE_STANDARD_INFORMATION),0 };
		auto ret = __NtRoutine("NtQueryInformationFile", FileHandle, &_IoStatusBlock, &_FileInformation, sizeof(_FileInformation), FileInformationClass);
		if (Length >= sizeof(FILE_STANDARD_INFORMATION)) {
			emu->write(FileInformation, &_FileInformation, sizeof(_FileInformation));
		}
		status = ret;
	}
	else if (FileInformationClass == 0) {
		FILE_DIRECTORY_INFORMATION _FILE_DIRECTORY_INFORMATION = { sizeof(FILE_DIRECTORY_INFORMATION),0 };
		auto ret = __NtRoutine("NtQueryInformationFile", FileHandle, &_IoStatusBlock, &_FILE_DIRECTORY_INFORMATION, sizeof(_FILE_DIRECTORY_INFORMATION), FileInformationClass);
		if (Length >= sizeof(FILE_DIRECTORY_INFORMATION)) {
			emu->write(FileInformation, &_FILE_DIRECTORY_INFORMATION, sizeof(FILE_DIRECTORY_INFORMATION));
		}
		status = ret;
	}
	status = 0;
	emu->rax(status);
}

void Emulate::ZwQueryInformationFile(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "ZwQueryInformationFile\n");
	auto emu = Emu(uc);
	uint64_t FileHandle = emu->rcx();
	uint64_t IoStatusBlock = emu->rdx();
	uint64_t FileInformation = emu->r8();
	uint64_t Length = emu->r9();

	uint64_t rsp = emu->rsp();
	uint64_t FileInformationClass = 0;
	emu->try_read(rsp + 0x28, &FileInformationClass, sizeof(uint64_t));
	uint64_t _FileInformationClass = 0;
	emu->try_read(FileInformationClass, &_FileInformationClass, sizeof(_FileInformationClass));
	IO_STATUS_BLOCK _IoStatusBlock = { 0 };
	FILE_STANDARD_INFORMATION _FileInformation = { sizeof(FILE_STANDARD_INFORMATION),0 };
	auto ret = __NtRoutine("NtQueryInformationFile", FileHandle, &_IoStatusBlock, &_FileInformation, sizeof(_FileInformation), FileInformationClass);

	Logger::Log(true, ConsoleColor::RED, " Handle: %llx, InfoClass: %d\n", FileHandle, FileInformationClass);
	uint32_t status = ret;
	PEloader* loader = &PEloader::GetInstance();
	auto it = loader->handle_table.find(FileHandle);

	if (FileInformationClass == 5) {		/*FILE_STANDARD_INFORMATION info{};
		info.AllocationSize = file.size;
		info.EndOfFile = file.size;
		info.NumberOfLinks = 1;
		info.DeletePending = 0;
		info.Directory = 0;*/

		if (Length >= sizeof(FILE_STANDARD_INFORMATION)) {
			emu->write(FileInformation, &_FileInformation, sizeof(_FileInformation));
		}
	}


	emu->rax(status);
	RetHook(uc);
}

void Emulate::ZwReadFile(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	Logger::Log(true, ConsoleColor::RED, "ZwReadFile\n");
	auto emu = Emu(uc);
	HANDLE FileHandle = reinterpret_cast<HANDLE>(emu->rcx());
	uint64_t Event = emu->rdx();
	uint64_t ApcRoutine = emu->r8();
	uint64_t ApcContext = emu->r9();
	uint64_t r15 = emu->r15();

	uint64_t rsp = emu->rsp();

	rsp = rsp + 8;
	uint64_t IoStatusBlock = 0;
	uint64_t BufferAddr = 0;
	uint32_t Length = 0;
	uint64_t ByteOffsetAddr = 0;
	uint64_t Key = 0;
	emu->try_read(rsp + 0x20, &IoStatusBlock, sizeof(uint64_t));
	emu->try_read(rsp + 0x28, &BufferAddr, sizeof(uint64_t));
	emu->try_read(rsp + 0x30, &Length, sizeof(uint32_t));
	emu->try_read(rsp + 0x38, &ByteOffsetAddr, sizeof(uint64_t));
	emu->try_read(rsp + 0x40, &Key, sizeof(uint64_t));
    LARGE_INTEGER ByteOffset = {};
	emu->try_read(ByteOffsetAddr, &ByteOffset, sizeof(LARGE_INTEGER));
	if (Length < 1)
		Length = static_cast<uint32_t>(emu->r13());


	LARGE_INTEGER liBytes = { 0 };
	std::vector<uint8_t> readBuffer(Length);
	IO_STATUS_BLOCK iosb = { 0 };
	ULONG fileSize = GetFileSize((HANDLE)FileHandle, NULL);
	IO_STATUS_BLOCK ioStatus = { 0 };
	LARGE_INTEGER offset = {};
	char buffer[1024] = {};
	auto status = __NtRoutine("NtReadFile",
		FileHandle,
		nullptr,
		nullptr,
		nullptr,
		&iosb,
		readBuffer.data(),
		readBuffer.size(),
		&offset,
		nullptr
	);
	if (status < 0xc0000000) {
		emu->write(BufferAddr, readBuffer.data(), readBuffer.size());
		status = 0;
	}

	emu->write(IoStatusBlock, &iosb, sizeof(ioStatus));

	emu->rax(status);
	Logger::Log(true, 10, "ZwReadFile simulation completed, Status: %d    Handle  0x%llx\n", status, reinterpret_cast<uint64_t>(FileHandle));
	RetHook(uc);
}

void Emulate::NtQuerySystemInformation(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t SystemInformationClass = emu->rcx();
	uint64_t SystemInformation = emu->rdx();
	uint64_t SystemInformationLength = emu->r8();
	uint64_t ReturnLength = emu->r9();
	Logger::Log(true, ConsoleColor::RED, "NtQuerySystemInformation\n");

	Logger::Log(true, ConsoleColor::YELLOW, "SystemInformationClass: %llx Output Buffer Addr: 0x%llx\n", SystemInformationClass, SystemInformation);












}

void Emulate::IoWMIOpenBlock(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t rcx = emu->rcx();
    uint64_t rdx = emu->rdx();
    uint64_t r8 = emu->r8();
    (void)rdx;

	uint8_t read_guid[16] = {};
	emu->try_read(rcx, read_guid, sizeof(read_guid));
	uint8_t TARGET_GUID[16] = { 0x50, 0x08, 0x68, 0x8f, 0x84, 0xa5, 0xd1, 0x11,
						   0xbf, 0x38, 0x00, 0xa0, 0xc9, 0x06, 0x29, 0x10 };
	uint64_t status = STATUS_WMI_GUID_NOT_FOUND;
	if (memcmp(read_guid, TARGET_GUID, 16) == 0) {
		Logger::Log(true, ConsoleColor::RED, "IoWMIOpenBlock Success\n");
		status = STATUS_SUCCESS;

		uint32_t fake_wmi_obj = 0xDEADBEEF;
    	emu->write(r8, &fake_wmi_obj, sizeof(fake_wmi_obj));
	}
	else {
		Logger::Log(true, ConsoleColor::GREEN, "IoWMIOpenBlock Failed\n");
	}

	emu->rax(status);
	RetHook(uc);
}
void Emulate::IoWMIQueryAllData(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t rcx = emu->rcx();
    uint64_t rdx = emu->rdx();
    uint64_t r8 = emu->r8();
    (void)rdx;

	uint32_t handle_value = 0;
	emu->try_read(rcx, &handle_value, sizeof(handle_value));

	Logger::Log(true, ConsoleColor::RED, "IoWMIQueryAllData, Handle: 0x%llx\n", handle_value);
	uint64_t status = STATUS_INVALID_HANDLE;
	if (rcx == 0xDEADBEEF) {
		Logger::Log(true, ConsoleColor::DARK_GREEN, "Valid WMI Handle, Return Fake WMI Data\n");

		uint8_t fake_wmi_data[0x100] = { 0 };
		*(uint32_t*)&fake_wmi_data[0] = 0x100;
    	*(uint32_t*)&fake_wmi_data[4] = 0xDEADBEEF;
		emu->write(r8, fake_wmi_data, sizeof(fake_wmi_data));

		status = STATUS_SUCCESS;
	}
	else {
		Logger::Log(true, ConsoleColor::DARK_GREEN, "Invalid WMI Handle, return STATUS_INVALID_HANDLE");
	}

	emu->rax(status);
	RetHook(uc);
}
void Emulate::PsDereferenceSiloContext(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	uint64_t status = STATUS_SUCCESS;
	Logger::Log(true, ConsoleColor::RED, "PsDereferenceSiloContext\n");
	auto emu = Emu(uc);
	emu->rax(status);
	RetHook(uc);
}
void Emulate::__C_specific_handler(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	Logger::Log(true, ConsoleColor::RED, "C_specific_handler\n");
	auto emu = Emu(uc);
	uint64_t ExceptionRecord = emu->rcx();
	uint64_t EstablisherFrame = emu->rdx();
	uint64_t ContextRecord = emu->r8();
	uint64_t DispatcherContext = emu->r9();

	Logger::Log(true, ConsoleColor::DARK_GREEN, "  ExceptionRecord:    0x%llx \n", ExceptionRecord);
	Logger::Log(true, ConsoleColor::DARK_GREEN, "  EstablisherFrame:   0x%llx\n", EstablisherFrame);
	CONTEXT mContextRecord;
	DISPATCHER_CONTEXT mDispatcherContext;
	emu->try_read(ContextRecord, &mContextRecord, sizeof(mContextRecord));
	emu->try_read(DispatcherContext, &mDispatcherContext, sizeof(mDispatcherContext));
	uint32_t exceptionCode = 0;
	emu->try_read(ExceptionRecord, &exceptionCode, sizeof(exceptionCode));







	Logger::Log(true, ConsoleColor::DARK_GREEN, "  ExceptionCode:    0x%llx \n", exceptionCode);




	loader->ExecuteExceptionHandler = 1;
	loader->LastException = exceptionCode;
}
void Emulate::KeInitializeEvent(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t event_ptr = emu->rcx();
	uint64_t type = emu->rdx();
	uint64_t state = emu->r8();
	Logger::Log(true, ConsoleColor::RED, "KeInitializeEvent\n");
	Logger::Log(true, 8, "Event Address: 0x%llx\n", event_ptr);
	Logger::Log(true, 8, "Type: %s\n", (type == 0 ? "NotificationEvent" : "SynchronizationEvent"));
	Logger::Log(true, 8, "Initial State: %s\n", (state ? "Signaled" : "Non-Signaled"));
	HANDLE event = CreateEvent(NULL, type == 0, state != 0, NULL);


	if (event_ptr == 0) return;

	struct {
		uint8_t Type;
		uint8_t Absolute;
		uint8_t Size;
		uint8_t Inserted;
		int32_t SignalState;
	} header = { 0 };

	header.Type = (uint8_t)type;
    header.Absolute = 0;
	header.Size = sizeof(header) / sizeof(ULONG_PTR);
	header.Inserted = 0;
	header.SignalState = (state ? 1 : 0);
	uint64_t ptr = HeapAlloc(uc, 0x1000);
	emu->write(event_ptr, &event, sizeof(event));

	RetHook(uc);
}
int iws = 0;
void Emulate::TrampolineThread(ThreadInfo_t* ti) {
	ti->threadId = GetCurrentThreadId();
	for (auto& tii : loader->Threads) {
		if (tii->threadId != ti->threadId) {
			ResetEvent(tii->Event);
		}
		else if (tii->threadId == ti->threadId) {
			loader->errorevent = tii->Event;
		}

	}
	uc_engine* uc = loader->uc;
	
	uc_open(UC_ARCH_X86, UC_MODE_64, &ti->tuc);
	uc_mem_region* regions;
	uint32_t count;
	uc_ctl_set_cpu_model(ti->tuc, UC_CPU_X86_QEMU64);
	uc_ctl(ti->tuc, UC_CTL_UC_PAGE_SIZE, 0x100000000);
	uc_ctl_tlb_mode(ti->tuc, UC_TLB_VIRTUAL);
	auto emu = Emu(uc);
	auto threadEmu = Emu(ti->tuc);
	uc_hook trace, traces, trace_mem, trace_nt, t;
	bool KdDebuggerNotPresent = 1;
	bool KdDebuggerEnabled = 0;
	for (auto& peFile : loader->peFiles)
	{

		if (peFile->FileName == "ntoskrnl.exe")
		{
			uint64_t size = loader->real_mem_map[peFile->Base].second;
			uc_err err = uc_mem_map_ptr(ti->tuc, peFile->Base, peFile->End - peFile->Base, UC_PROT_ALL, loader->real_mem_map[peFile->Base].first);
			uint64_t KdDebuggerNotPresentaddress = peFile->Base + peFile->FuncAddr["KdDebuggerNotPresent"];
			uint64_t KdDebuggerEnabledaddress = peFile->Base + peFile->FuncAddr["KdDebuggerEnabled"];
			loader->RtlRaiseStatusBase = peFile->Base + peFile->FuncAddr["RtlRaiseStatus"];
			threadEmu->write(KdDebuggerNotPresentaddress, &KdDebuggerNotPresent, sizeof(KdDebuggerNotPresent));
			threadEmu->write(KdDebuggerEnabledaddress, &KdDebuggerEnabled, sizeof(KdDebuggerEnabled));
		}

	}


	uc_err errU = uc_hook_add(ti->tuc, &trace_mem, UC_HOOK_MEM_INVALID, (void*)Unicorn::hook_mem_invalid, NULL, 1, 0);
	errU = uc_hook_add(ti->tuc, &trace_mem, UC_HOOK_INSN_INVALID, (void*)Unicorn::hook_mem_invalid, NULL, 1, 0);
	errU = uc_hook_add(ti->tuc, &intr_hook, UC_HOOK_INTR, (void*)Unicorn::catch_error, nullptr, 1, 0);
	Unicorn _uc{};
	for (const auto& pair : _uc.NtfuncMap) {
		_uc.hook_File_func(ti->tuc, "t", pair.first, pair.second);
	}
	for (const auto& pair : _uc.CngFuncMap) {
		_uc.hook_File_func(ti->tuc, "t", pair.first, pair.second);
	}
	for (const auto& pair : _uc.CiFuncMap) {
		_uc.hook_File_func(ti->tuc, "t", pair.first, pair.second);
	}
	for (auto object : loader->objectList) {
		uc_hook_add(ti->tuc, &t, UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, (void*)Unicorn::hook_access_object, (void*)object, object->address, object->address + object->size);
	}

	uc_hook_add(ti->tuc, &t, UC_HOOK_CODE, Unicorn::register_hook, NULL, 1, 0);


	uc_context_restore(ti->tuc, ti->uc_ctx);

	threadEmu->rip(ti->routineStart);
	threadEmu->rcx(ti->routineContext);

	uint64_t rsp_MapBase = 0xffff890a9a3c1000;
	uint64_t rsp = 0xffff890a9a3c72b8;
	std::vector<uint8_t> buffer(0x7000);
	uc_mem_map(ti->tuc, rsp_MapBase, 0x7000, UC_PROT_ALL);
	emu->try_read(rsp_MapBase, buffer.data(), buffer.size());
	threadEmu->write(rsp_MapBase, buffer.data(), buffer.size());
	threadEmu->rsp(rsp);


	Logger::Log(true, ConsoleColor::RED, "TI routineStart: %llx\n", ti->routineStart);
	for (auto& ti : loader->Threads) {
		SetEvent(ti->Event);
		loader->errorevent = nullptr;
	}
	uc_err uc_check = uc_emu_start(ti->tuc, ti->routineStart, loader->peFiles[0]->End, 0, 0);
	if (uc_check != UC_ERR_OK)
	{
		ShowRegister(ti->tuc);
		Logger::Log(true, ConsoleColor::RED, "uc_emu_start error: %d\n", uc_check);
	}
	DWORD tid = GetCurrentThreadId();


	Logger::Log(true, ConsoleColor::YELLOW, "Thread is about to terminate \n");
	for (auto& ti : loader->Threads) {
		SetEvent(ti->Event);
	}
	uc_engine* uc_t = ti->tuc;
	/*loader->Threads.erase(std::remove_if(loader->Threads.begin(), loader->Threads.end(), [uc_t](ThreadInfo_t* ti) {
		return ti->tuc == ti->tuc;
		}), loader->Threads.end());*/
	uc_close(ti->tuc);
	ti->tuc = nullptr;


	return;
}



void Emulate::PsCreateSystemThread(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t threadHandlePtr = emu->rcx();
	uint64_t desiredAccess = emu->rdx();
	uint64_t objectAttr = emu->r8();
	uint64_t processHandle = emu->r9();
	UNREFERENCED_PARAMETER(desiredAccess);
	UNREFERENCED_PARAMETER(objectAttr);
	UNREFERENCED_PARAMETER(processHandle);

	uint64_t rsp = emu->rsp();
	uint64_t clientId = 0;
	uint64_t startRoutine = 0;
	uint64_t startContext =0;
	emu->try_read(rsp + 0x28, &clientId, sizeof(clientId));
	emu->try_read(rsp + 0x30, &startRoutine, sizeof(startRoutine));
	emu->try_read(rsp + 0x38, &startContext, sizeof(startContext));
	uint64_t checkstartContext = 0;
	emu->try_read(startContext, &checkstartContext, sizeof(checkstartContext));

	Logger::Log(true, ConsoleColor::RED, "PsCreateSystemThread: threadHandlePtr: 0x%llx StartContext: 0x%llx startRoutine : 0x%llx\n", threadHandlePtr, startContext, startRoutine);

	ThreadInfo_t* ti = (ThreadInfo_t*)malloc(sizeof(ThreadInfo_t));
	ti->routineContext = startContext;
	ti->routineStart = startRoutine;
	ti->uc_ctx = nullptr;


	ti->Event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
	ti->id = loader->Threads.size();

	uc_context_alloc(uc, &ti->uc_ctx);
	uc_context_save(uc, ti->uc_ctx);

	HANDLE thread = CreateThread(nullptr, 8192, (LPTHREAD_START_ROUTINE)TrampolineThread, ti, 0, nullptr);
	
	ti->handle = thread;

	loader->Threads.push_back(ti);
	loader->waitHandles.push_back(ti->Event);



	WaitForSingleObject(ti->Event, INFINITE);
	uint64_t status = 0;
	emu->rax(status);
	RetHook(uc);

}

void Emulate::KeSetEvent(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t rcx = emu->rcx();
    uint64_t rdx = emu->rdx();
    uint64_t r8 = emu->r8();
    UNREFERENCED_PARAMETER(rdx);
	UNREFERENCED_PARAMETER(r8);
	Logger::Log(true, ConsoleColor::RED, "KeSetEvent\n");
	HANDLE handle = nullptr;
	emu->try_read(rcx, &handle, sizeof(handle));
	SetEvent(handle);

	RetHook(uc);
}
void Emulate::KeResetEvent(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t rcx = emu->rcx();
	int32_t previous_state = 0;
	Logger::Log(true, ConsoleColor::RED, "KeResetEvent\n");
	emu->try_read(rcx + 0x08, &previous_state, sizeof(int32_t));
	Logger::Log(true, ConsoleColor::RED, "KeResetEvent: Original SignalState = %d \n", previous_state);

	int32_t new_state = 0;
	emu->write(rcx + 0x08, &new_state, sizeof(int32_t));
	Logger::Log(true, ConsoleColor::BLUE, "KeResetEvent: Set SignalState = 0\n");

	uint64_t result = static_cast<uint64_t>(previous_state);
	emu->rax(result);

	RetHook(uc);}

void Emulate::KeCapturePersistentThreadState(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t context_ptr = emu->rcx();
	uint64_t kthread_ptr = emu->rdx();
	uint64_t kprocess_ptr = emu->r8();
	Logger::Log(true, ConsoleColor::RED, "KeCapturePersistentThreadState\n");
	return;
}
void Emulate::ZwOpenDirectoryObject(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t rcx = emu->rcx();
    uint64_t rdx = emu->rdx();
    uint64_t r8 = emu->r8();
    
	Logger::Log(true, ConsoleColor::RED, "ZwOpenDirectoryObject\n");

	Logger::Log(true, ConsoleColor::RED, "DirectoryHandle: 0x%llx\n    DirectoryHandle address: %llx\n    DesiredAccess: %d    ObjectAttributes pointer: %llx\n", rcx, rdx, r8);
	OBJECT_ATTRIBUTES ObjectAttributes;
	emu->try_read(r8, &ObjectAttributes, sizeof(ObjectAttributes));
    
	std::wstring file_name_str = read_unicode_string(uc, ObjectAttributes.ObjectName);
	std::wcout << "Directory name: " << file_name_str << std::endl;

	uint64_t status = STATUS_OBJECT_NAME_NOT_FOUND;
	uint32_t fake_handle = 0xBADF00D;
    
	if (file_name_str == L"\\" || file_name_str == L"\\Device" || file_name_str == L"\\KnownDlls") {
		status = STATUS_SUCCESS;
		emu->write(rcx, &fake_handle, sizeof(fake_handle));
    	Logger::Log(true, ConsoleColor::RED, "Exist, Return Fake Handle: 0xBADF00D\n");
	}
	else {
		Logger::Log(true, ConsoleColor::DARK_GREEN, "Path does not exist, return STATUS_OBJECT_NAME_NOT_FOUND");
	}

	emu->rax(status);

	RetHook(uc);
}
void Emulate::ObReferenceObjectByHandle(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t rcx = emu->rcx();
    uint64_t rdx = emu->rdx();
    uint64_t r8 = emu->r8();
    UNREFERENCED_PARAMETER(rdx);
	UNREFERENCED_PARAMETER(r8);
	Logger::Log(true, ConsoleColor::RED, "ObReferenceObjectByHandle\n");

	uint64_t status = STATUS_INVALID_HANDLE;

	Logger::Log(true, ConsoleColor::DARK_GREEN, "Not Vaild Handle: 0x%llx \n ", rcx);

	status = 0;
	emu->rax(status);
    RetHook(uc);
}
void Emulate::NtClose(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t rcx = emu->rcx();
	Logger::Log(true, ConsoleColor::RED, "NtClose\n");
	uint64_t status = STATUS_SUCCESS;
	emu->rax(status);
	RetHook(uc);
}

void Emulate::ExAcquireFastMutex(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t rcx = emu->rcx(); 
	Logger::Log(true, ConsoleColor::RED, "ExAcquireFastMutex\n");
	if (rcx == 0) {
		Logger::Log(true, ConsoleColor::DARK_GREEN, "NULL\n");
		RetHook(uc);
		return;
	}

	uint32_t count = 0;
	emu->try_read(rcx, &count, sizeof(count));

	if (count == 1) {
		count = 0;
		uint64_t ownerThread = 0xDEADBEEF;
		emu->write(rcx, &count, sizeof(count));
		emu->write(rcx + 8, &ownerThread, sizeof(ownerThread));
		Logger::Log(true, ConsoleColor::DARK_GREEN, "FastMutex\n");
	}
	else {
		Logger::Log(true, ConsoleColor::DARK_GREEN, " FastMutex Lock, waiting...\n");
	}
	RetHook(uc);
}


void Emulate::KeReleaseGuardedMutex(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t rcx = emu->rcx();
	Logger::Log(true, ConsoleColor::RED, "KeReleaseGuardedMutex\n");
	if (rcx == 0) {
		std::cerr << "[-] KeReleaseGuardedMutex: GuardedMutex is NULL" << std::endl;
		RetHook(uc);
		return;
	}

	uint64_t ownerThread = 0;
	uint32_t count = 0;
	emu->try_read(rcx, &count, sizeof(count));
	emu->try_read(rcx + 8, &ownerThread, sizeof(ownerThread));
	uint64_t currentThread = 0xDEADBEEF;
    if (ownerThread != currentThread) {
		std::cerr << "[-] KeReleaseGuardedMutex: Attempting to release GuardedMutex of non-current thread, may cause BSOD!" << std::endl;
		RetHook(uc);
		return;
	}

	count = 1;
	ownerThread = 0;
	emu->write(rcx, &count, sizeof(count));
	emu->write(rcx + 8, &ownerThread, sizeof(ownerThread));
	Logger::Log(true, ConsoleColor::RED, "KeReleaseGuardedMutex: GuardedMutex Release\n");
	RetHook(uc);
}
void Emulate::KeWaitForSingleObject(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t rcx = emu->rcx();
	uint64_t rdx = emu->rdx();
	uint64_t r8 = emu->r8();
	uint64_t r9 = emu->r9();
	Logger::Log(true, ConsoleColor::RED, "KeWaitForSingleObject\n");
	if (rcx == 0) {
		Logger::Log(true, ConsoleColor::DARK_GREEN, "Object is null\n");
		uint64_t status = STATUS_INVALID_PARAMETER;
		emu->rax(status);
		RetHook(uc);
		return;
	}

	int32_t signalState = 0;
	emu->try_read(rcx + 4, &signalState, sizeof(signalState));
	if (signalState == 1) {
		Logger::Log(true, ConsoleColor::DARK_GREEN, "Return Success\n");
		uint64_t status = STATUS_SUCCESS;
		emu->rax(status);
		RetHook(uc);
		return;
	}

	uint64_t rsp = emu->rsp();
	uint64_t timeout = 0;
	emu->try_read(rsp + 0x28, &timeout, sizeof(timeout));
	
	HANDLE handle = nullptr;
	emu->try_read(rcx, &handle, sizeof(handle));
	WaitForSingleObject((HANDLE)handle, INFINITE);

	uint64_t status = STATUS_SUCCESS;
	emu->rax(status);
	RetHook(uc);
}
void Emulate::KeQueryTimeIncrement(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	uint32_t time_increment = 156250;
	Logger::Log(true, ConsoleColor::RED, "KeQueryTimeIncrement\n");
	Logger::Log(true, ConsoleColor::RED, " Return: %d\n", time_increment);

	auto emu = Emu(uc);
	emu->rax(time_increment);
	RetHook(uc);
}

void Emulate::PsIsSystemThread(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t rcx = emu->rcx();
	Logger::Log(true, ConsoleColor::RED, "PsIsSystemThread\n");

	uint8_t system_thread_flag = 0;
	emu->try_read(rcx + 0x74, &system_thread_flag, sizeof(system_thread_flag));

	Logger::Log(true, ConsoleColor::RED, "Read ETHEAD %llx SystemThread Flag: %d\n", rcx, system_thread_flag);
	uint64_t result = (system_thread_flag == 1) ? TRUE : FALSE;
	emu->rax(result);
	RetHook(uc);
}

void Emulate::PsTerminateSystemThread(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t exit_status = emu->rcx();

	Logger::Log(true, ConsoleColor::RED, "PsTerminateSystemThread: ExitStatus: 0x%llx\n", exit_status);
	Sleep(2000);
	uc_emu_stop(uc);
	return;
	ThreadInfo_t* ti = loader->Threads.front();

	loader->Threads.erase(
		std::remove_if(loader->Threads.begin(), loader->Threads.end(),
			[](ThreadInfo_t* ti) {
				return ti->threadId == GetCurrentThreadId();
			}),
		loader->Threads.end());

	ExitThread(1);
}


void Emulate::RtlGetVersion(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t rcx = emu->rcx();
	Logger::Log(true, ConsoleColor::RED, "RtlGetVersion\n");
	RTL_OSVERSIONINFOW version_info = { 0 };
	version_info.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
	version_info.dwMajorVersion = 10;
	version_info.dwMinorVersion = 0;
	version_info.dwBuildNumber = 19041;
	version_info.dwPlatformId = 2;
	wcscpy_s(version_info.szCSDVersion, L"Service Pack 1");
	emu->write(rcx, &version_info, sizeof(version_info));
	uint64_t status = STATUS_SUCCESS;
	emu->rax(status); 

	Logger::Log(true, ConsoleColor::DARK_GREEN, "RtlGetVersion\n");
	RetHook(uc);
}
void Emulate::KeDelayExecutionThread(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t rcx = emu->rcx();
	uint64_t rdx = emu->rdx();
	uint64_t r8 = emu->r8();
	UNREFERENCED_PARAMETER(rcx);
	UNREFERENCED_PARAMETER(rdx);
	int64_t interval = 0;
	emu->try_read(r8, &interval, sizeof(interval));

	int64_t delay_ms = -(interval / 10000);
	if (delay_ms < 0) delay_ms = 0;
    int thread = loader->Threads.size();

	Sleep(delay_ms);

	uint64_t status = STATUS_SUCCESS;
	emu->rax(status);
	RetHook(uc);
}

void Emulate::ZwQueryFullAttributesFile(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t rcx = emu->rcx();
	uint64_t rdx = emu->rdx();
	Logger::Log(true, ConsoleColor::RED, "ZwQueryFullAttributesFile\n");

	OBJECT_ATTRIBUTES ObjectAttributes;
	emu->try_read(rcx, &ObjectAttributes, sizeof(ObjectAttributes));
	std::wstring file_name_str = read_unicode_string(uc, (uint64_t)ObjectAttributes.ObjectName);



	std::wcout << "[+] Search File: " << file_name_str << std::endl;

	NTSTATUS status = STATUS_OBJECT_NAME_NOT_FOUND;

	std::wstring target_filename = L"\\??\\C:\\fakefile.txt";

	if (file_name_str.compare(target_filename) == 0) {
		FILE_NETWORK_OPEN_INFORMATION file_info = { 0 };
		file_info.EndOfFile.QuadPart = 1024;
		file_info.CreationTime.QuadPart = 132456789000000000;
		file_info.LastAccessTime.QuadPart = 132456789000000000;
		file_info.LastWriteTime.QuadPart = 132456789000000000;
		file_info.ChangeTime.QuadPart = 132456789000000000;
		file_info.FileAttributes = FILE_ATTRIBUTE_NORMAL;

		emu->write(rdx, &file_info, sizeof(file_info));
		status = STATUS_SUCCESS;

		std::wcout << L"[+] FileSize: " << file_info.EndOfFile.QuadPart << " bytes" << std::endl;
	}

	emu->rax(status);
	RetHook(uc);
}

void Emulate::KeEnterCriticalRegion(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {

}
void Emulate::ExReleaseResourceLite(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	auto emu = Emu(uc);
	emu->rax(0);
	RetHook(uc);
}
void Emulate::KeLeaveCriticalRegion(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
}
void Emulate::ExAcquireFastMutexUnsafe(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t rcx = emu->rcx();
	Logger::Log(true, ConsoleColor::RED, "ExAcquireFastMutexUnsafe\n");
	Logger::Log(true, ConsoleColor::RED, "FAST_MUTEX addr: %llx\n", rcx);

	RetHook(uc);
}
void Emulate::ExReleaseFastMutexUnsafe(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t rcx = emu->rcx();
	Logger::Log(true, ConsoleColor::RED, "ExReleaseFastMutexUnsafe\n");
	Logger::Log(true, ConsoleColor::RED, "FAST_MUTEX addr: %llx\n", rcx);
	RetHook(uc);
}

void Emulate::RtlUnicodeStringToAnsiString(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
}
void Emulate::IoDeleteSymbolicLink(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t rcx = emu->rcx();
	Logger::Log(true, ConsoleColor::RED, "IoDeleteSymbolicLink\n");
	if (rcx == 0) {
		Logger::Log(true, ConsoleColor::DARK_GREEN, "Invalid UNICODE_STRING pointer\n");
		uint64_t status = STATUS_INVALID_PARAMETER;
		emu->rax(status);
		RetHook(uc);
		return;
	}

	UNICODE_STRING us;
	emu->try_read(rcx, &us, sizeof(UNICODE_STRING));

	if (us.Length == 0 || us.Buffer == 0) {
		Logger::Log(true, ConsoleColor::DARK_GREEN, "Invalid SymbolicLinkName\n");
		uint64_t status = STATUS_OBJECT_NAME_NOT_FOUND;
		emu->rax(status);
		RetHook(uc);
		return;
	}

	std::vector<wchar_t> buffer(us.Length / sizeof(wchar_t) + 1);
	emu->try_read(reinterpret_cast<uint64_t>(us.Buffer), buffer.data(), us.Length);
	buffer[us.Length / sizeof(wchar_t)] = L'\0';

	std::wstring symbolic_link_name(buffer.begin(), buffer.end());

	Logger::Log(true, ConsoleColor::DARK_GREEN, "Delete Symbolic link -> %s\n", symbolic_link_name.c_str());

	static std::unordered_set<std::wstring> symbolic_links = {
		L"\\DosDevices\\ExampleLink"
	};

	uint64_t status = STATUS_OBJECT_NAME_NOT_FOUND;
	if (symbolic_links.count(symbolic_link_name)) {
		symbolic_links.erase(symbolic_link_name);
		std::wcout << L"[+] Symbolic link " << symbolic_link_name << L" deleted" << std::endl;
		status = STATUS_SUCCESS;
	}
	else {
		Logger::Log(true, ConsoleColor::DARK_GREEN, "Symbolic link %s does not exist\n", symbolic_link_name.c_str());
	}

	emu->rax(status);
	RetHook(uc);
}

std::map<uint64_t, BCRYPT_HASH_HANDLE> g_HashHandleMap;

uint64_t g_HashHandleSeed = 0xBC0000000000;

void Emulate::BCryptOpenAlgorithmProvider(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t phAlgorithm_ptr = emu->rcx();
	uint64_t pszAlgId_ptr = emu->rdx();
	uint64_t pszImpl_ptr = emu->r8();
	uint64_t dwFlags = emu->r9();
	Logger::Log(true, ConsoleColor::RED, "BCryptOpenAlgorithmProvider\n");
	std::wstring wstr;
	read_null_unicode_string(uc, pszAlgId_ptr, wstr);
	BCRYPT_ALG_HANDLE hAlg = nullptr;
	NTSTATUS status = ::BCryptOpenAlgorithmProvider(
		&hAlg,
		wstr.c_str(),
		nullptr,
		static_cast<ULONG>(dwFlags)
	);

	if (status == 0) {
		emu->write(phAlgorithm_ptr, &hAlg, sizeof(hAlg));
	}
	else {
		std::wcerr << "Fail, NTSTATUS = 0x" << std::hex << status << std::endl;
	}

	emu->rax(status);
	RetHook(uc);
}


void Emulate::BCryptCloseAlgorithmProvider(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t hFakeAlg = emu->rcx();
	uint64_t dwFlags = emu->rdx();
	Logger::Log(true, ConsoleColor::RED, "BCryptCloseAlgorithmProvider\n");
	auto it = g_HashHandleMap.find(hFakeAlg);


	BCRYPT_ALG_HANDLE realAlg = (BCRYPT_ALG_HANDLE)hFakeAlg;

	NTSTATUS status = ::BCryptCloseAlgorithmProvider(realAlg, static_cast<ULONG>(dwFlags));
	if (status == 0) {
		Logger::Log(true, ConsoleColor::RED, "Close, FakeHandle = 0x%llx\n", hFakeAlg);
	}
	else {
		Logger::Log(true, ConsoleColor::GREEN, "Failed, NTSTATUS = 0x%llx\n", status);
	}

	emu->rax(status);
	RetHook(uc);
}


void Emulate::BCryptCreateHash(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t hAlg = emu->rcx();
	uint64_t phHash = emu->rdx();
	uint64_t pbHashObject = emu->r8();
	uint64_t cbHashObject = emu->r9();
	UNREFERENCED_PARAMETER(pbHashObject);
	UNREFERENCED_PARAMETER(cbHashObject);
	uint64_t pbSecret = 0;
	uint64_t cbSecret = 0;
	uint64_t dwFlags = 0;
	Logger::Log(true, ConsoleColor::RED, "BCryptCreateHash\n");
	uint64_t rsp = emu->rsp();
	rsp = rsp + 8;
	emu->try_read(rsp + 0x20, &pbSecret, sizeof(uint64_t));
	emu->try_read(rsp + 0x28, &cbSecret, sizeof(uint64_t));
	emu->try_read(rsp + 0x30, &dwFlags, sizeof(uint64_t));

	BCRYPT_ALG_HANDLE realAlgHandle = reinterpret_cast<BCRYPT_ALG_HANDLE>(hAlg);

	BCRYPT_HASH_HANDLE realHashHandle = nullptr;
	NTSTATUS status = ::BCryptCreateHash(
		realAlgHandle,
		&realHashHandle,
		nullptr, 0,
		(PUCHAR)pbSecret,
		static_cast<ULONG>(cbSecret),
		0
	);

	if (status == 0) {
		uint64_t fakeHashHandle = g_HashHandleSeed++;
		g_HashHandleMap[(uint64_t)realHashHandle] = realHashHandle;

		emu->write(phHash, &realHashHandle, sizeof(realHashHandle));
		Logger::Log(true, ConsoleColor::RED, "fakeHashHandle = 0x%llx\n", realHashHandle);
	}
	else {
		std::cerr << "[-] Fail, NTSTATUS = 0x" << std::hex << status << std::endl;
	}

	emu->rax(status);
	RetHook(uc);
}

void Emulate::BCryptHashData(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t hFakeHash = emu->rcx();
	uint64_t pbInput = emu->rdx();
	uint64_t cbInput = emu->r8();
	uint64_t dwFlags = emu->r9();
	Logger::Log(true, ConsoleColor::RED, "BCryptHashData\n");
	auto it = g_HashHandleMap.find(hFakeHash);
	if (it == g_HashHandleMap.end()) {
		std::cerr << "[-] non hash handle: 0x" << std::hex << hFakeHash << std::endl;
		uint64_t status = 0xC0000008;
		emu->rax(status);
		RetHook(uc);
		return;
	}

	BCRYPT_HASH_HANDLE realHash = it->second;

	std::vector<uint8_t> buffer(cbInput);
	emu->try_read(pbInput, buffer.data(), cbInput);

	NTSTATUS status = ::BCryptHashData(
		realHash,
		buffer.data(),
		static_cast<ULONG>(cbInput),
		static_cast<ULONG>(dwFlags)
	);

	if (status == 0) {
		Logger::Log(true, ConsoleColor::RED, "Write %d bytes\n", cbInput);
	}
	else {
		std::cerr << "[-] Failed, NTSTATUS = 0x" << std::hex << status << std::endl;
	}

	emu->rax(status);
	RetHook(uc);
}
void Emulate::BCryptGetProperty(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t hAlgo = emu->rcx();
	uint64_t pszProp = emu->rdx();
	uint64_t pbOutput = emu->r8();
	uint64_t cbOutput = emu->r9();
	uint64_t pcbResult = 0;
	uint64_t dwFlags = 0;
	Logger::Log(true, ConsoleColor::RED, "BCryptGetProperty\n");
	uint64_t rsp = emu->rsp();
	rsp = rsp + 8;
	emu->try_read(rsp + 0x20, &pcbResult, sizeof(uint64_t));
    emu->try_read(rsp + 0x28, &dwFlags, sizeof(uint64_t));

	std::wstring suckmyname = read_unicode_string(uc, pszProp);
	std::wstring propName;
	read_null_unicode_string(uc, pszProp, propName);
	DWORD resultLength = 0;
	BYTE outputBuffer[64] = { 0 };

	NTSTATUS status = ::BCryptGetProperty(
		(BCRYPT_HASH_HANDLE)hAlgo,
		propName.c_str(),
		outputBuffer,
		static_cast<ULONG>(cbOutput),
		&resultLength,
		0
	);

	if (status == 0) {
		emu->write(pbOutput, outputBuffer, resultLength);
		emu->write(pcbResult, &resultLength, sizeof(DWORD));
		std::wcout << L"[+] (\"" << propName << L"\") = " << resultLength << L" bytes\n";
	}
	else {
		std::wcerr << L"[-]  Failed. Status: 0x" << std::hex << status << std::endl;
	}

	emu->rax(status);
	RetHook(uc);
}

void Emulate::BCryptFinishHash(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t hFakeHash = emu->rcx();
    uint64_t pbOutput = emu->rdx();
    uint64_t cbOutput = emu->r8();
    uint64_t dwFlags = emu->r9();
    Logger::Log(true, ConsoleColor::RED, "BCryptFinishHash\n");
	auto it = g_HashHandleMap.find(hFakeHash);
	if (it == g_HashHandleMap.end()) {
		std::cerr << "[-] Unknown Hash Handle: 0x" << std::hex << hFakeHash << std::endl;
		uint64_t status = 0xC0000008;
		emu->rax(status);
		RetHook(uc);
		return;
	}

	BCRYPT_HASH_HANDLE realHash = it->second;
	std::vector<BYTE> output(cbOutput);

	NTSTATUS status = ::BCryptFinishHash(
		realHash,
		output.data(),
		static_cast<ULONG>(cbOutput),
		static_cast<ULONG>(dwFlags)
	);

	if (status == 0) {
		emu->write(pbOutput, output.data(), cbOutput);
		Logger::Log(true, ConsoleColor::RED, "Write 0x%llx (%d bytes)\n", pbOutput, cbOutput);
	}
	else {
		Logger::Log(true, ConsoleColor::GREEN, "Failed, NTSTATUS = 0x%llx\n", status);
	}

	emu->rax(status);
	RetHook(uc);
}
void Emulate::BCryptDestroyHash(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
	auto emu = Emu(uc);
	uint64_t hashHandle = emu->rcx();
	Logger::Log(true, ConsoleColor::RED, "BCryptDestroyHash\n");
	Logger::Log(true, ConsoleColor::DARK_GREEN, " Destroy Hash Handle = 0x%llx\n", hashHandle);
	uint8_t zero[0x100] = {};
    g_HashHandleMap.erase(hashHandle);

	uint64_t status = 0;
	emu->rax(status);

	RetHook(uc);
}