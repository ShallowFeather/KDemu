#include "Global.h"
#include "UnicornEmu.hpp"
#include <stdarg.h>
#include <windows.h>
#include <mutex>
#include <array>
#include <vector>
#include <cstdio>
#include <cstring>

namespace {
	std::wstring BuildThreadPrefix(bool showThreadId) {
		if (!showThreadId) {
			return L" ";
		}

		wchar_t buffer[64] = {};
		_snwprintf_s(buffer, _TRUNCATE, L"[tid: %llx]  ", static_cast<unsigned long long>(GetCurrentThreadId()));
		return buffer;
	}

	void WriteWideToConsole(HANDLE console, const std::wstring& text) {
		if (!console || text.empty()) {
			return;
		}

		DWORD consoleMode = 0;
		if (GetConsoleMode(console, &consoleMode)) {
			DWORD written = 0;
			WriteConsoleW(console, text.c_str(), static_cast<DWORD>(text.size()), &written, nullptr);
		}
		else {
			int required = WideCharToMultiByte(GetACP(), 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
			if (required > 0) {
				std::string narrow(static_cast<size_t>(required), '\0');
				WideCharToMultiByte(GetACP(), 0, text.c_str(), static_cast<int>(text.size()), narrow.data(), required, nullptr, nullptr);
				fwrite(narrow.data(), 1, narrow.size(), stdout);
			}
		}
	}
}

void Logger::Log(bool tid_show, int color, const char* format,  ...) {
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, static_cast<WORD>(color));

	char sBuffer[2048] = { 0 };
	va_list args;
	va_start(args, format);
	_vsnprintf_s(sBuffer, _countof(sBuffer), _TRUNCATE, format, args);
	va_end(args);

	std::wstring prefix = BuildThreadPrefix(tid_show);
	std::wstring wideMessage;

	int required = MultiByteToWideChar(GetACP(), 0, sBuffer, -1, nullptr, 0);
	if (required > 0) {
		wideMessage.resize(static_cast<size_t>(required - 1));
		MultiByteToWideChar(GetACP(), 0, sBuffer, -1, wideMessage.data(), required);
	}

	WriteWideToConsole(hConsole, prefix + wideMessage);
	fflush(stdout);
}

void Logger::Log(bool tid_show, int color, const wchar_t* format, ...) {
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, static_cast<WORD>(color));

	wchar_t wBuffer[2048] = { 0 };
	va_list args;
	va_start(args, format);
	_vsnwprintf_s(wBuffer, _countof(wBuffer), _TRUNCATE, format, args);
	va_end(args);

	std::wstring prefix = BuildThreadPrefix(tid_show);
	WriteWideToConsole(hConsole, prefix + wBuffer);
	fflush(stdout);
}

void UnicodeToANSI(const std::wstring& str, std::string& out) {
	int len = WideCharToMultiByte(CP_ACP, 0, str.c_str(), (int)str.length(), NULL, 0, NULL, NULL);
	out.resize(len);
	WideCharToMultiByte(CP_ACP, 0, str.c_str(), (int)str.length(), (LPSTR)out.data(), len, NULL, NULL);
}

void ANSIToUnicode(const std::string& str, std::wstring& out) {
	int len = MultiByteToWideChar(CP_ACP, 0, str.c_str(), (int)str.length(), NULL, 0);
	out.resize(len);
	MultiByteToWideChar(CP_ACP, 0, str.c_str(), (int)str.length(), &out[0], len);
}
void ConvertToUnicodeString(UNICODE_STRING& KeyPath, const std::wstring& file_name_str) {
	__NtRoutine("RtlInitUnicodeString", &KeyPath, file_name_str.c_str());
}

bool read_null_unicode_string(uc_engine* uc, uint64_t address, std::wstring& str)
{
	auto emu = Emu(uc);
	size_t len = 0;
	while (true) {
		wchar_t c = emu->read<wchar_t>(address + len);
		if (c == L'\0') {
			break;
		}
		str.push_back(c);
		len += sizeof(wchar_t);
		if (len > 1024 * sizeof(wchar_t)) {
			break;
		}
	}
	return true;
}

std::wstring read_unicode_string(uc_engine* uc, uint64_t unicode_string_addr) {
	auto emu = Emu(uc);
	uint16_t length = emu->word(unicode_string_addr);
	uint16_t max_length = emu->word(unicode_string_addr + 2);
	(void)max_length;
	uint64_t buffer_addr = emu->qword(unicode_string_addr + 8);

	if (buffer_addr == 0 || length == 0) {
		return L"";
	}

	std::vector<uint8_t> raw = emu->read(buffer_addr, length);
	std::wstring result(raw.size() / sizeof(wchar_t), L'\0');
	std::memcpy(result.data(), raw.data(), raw.size());
	return result;
}
std::string read_ansi_string(uc_engine* uc, uint64_t ansi_string_addr) {
	auto emu = Emu(uc);
	uint16_t length = emu->word(ansi_string_addr);
	uint16_t max_length = emu->word(ansi_string_addr + 2);
	(void)max_length;
	uint64_t buffer_addr = emu->qword(ansi_string_addr + 8);

	if (buffer_addr == 0 || length == 0)
		return "";

	std::vector<uint8_t> raw = emu->read(buffer_addr, length);
	return std::string(reinterpret_cast<const char*>(raw.data()), raw.size());
}

uint64_t qword_load(uc_engine* uc, uint64_t addr) {
	return Emu(uc)->qword(addr);
}

void errorRetHook(uc_engine* uc) {
	auto emu = Emu(uc);
	uint64_t rsp = emu->rsp();
	uint64_t ret_addr = emu->qword(rsp);
	Logger::Log(true,ConsoleColor::DARK_GRAY, "RetHook�^��a�} : 0x%llx\n", ret_addr);
	emu->rsp(rsp - 8);
	emu->rip(ret_addr);
	emu->tlb_flush();
}

void RetHook(uc_engine* uc) {
	auto emu = Emu(uc);
	uint64_t rsp = emu->rsp();
	uint64_t ret_addr = emu->qword(rsp);
	emu->rsp(rsp + 8);
	emu->rip(ret_addr);
	emu->tlb_flush();
}

void fastCallRetHook(uc_engine* uc) {
	auto emu = Emu(uc);
	uint64_t rsp = emu->rsp();
	uint64_t ret_addr = emu->qword(rsp);
	emu->rsp(rsp - 0x4);
	emu->rip(ret_addr);
	emu->tlb_flush();
}

void print_xmm_register(const char* reg, const uint8_t* value, int length) {
	Logger::Log(false,ConsoleColor::DARK_GREEN, "%s", reg);
	for (int i = 0; i < length; ++i) {
		Logger::Log(false,ConsoleColor::DARK_GREEN, "%02x ", static_cast<int>(value[i]));
	}
	Logger::Log(false,ConsoleColor::DARK_GREEN, "\n");
}


void dump_stack(uc_engine* uc, uint64_t rsp, size_t num_entries) {
	auto emu = Emu(uc);
	std::vector<uint8_t> raw = emu->read(rsp, num_entries * sizeof(uint64_t));
	const uint64_t* stack_content = reinterpret_cast<const uint64_t*>(raw.data());

	Logger::Log(true,ConsoleColor::DARK_GREEN, "Stack contents near RSP (0x%llx)\n", rsp);
	for (size_t i = 0; i < num_entries; i++) {
		Logger::Log(false,ConsoleColor::DARK_GREEN, "  [0x%llx] = 0x%llx\n", (rsp + i * sizeof(uint64_t)), stack_content[i]);
	}
}

void ShowRegister(uc_engine* uc) {

	const auto emu = Emu(uc);
	std::array<std::array<uint8_t, 16>, 21> xmm_values{};
	for (int i = 0; i <= 20; ++i) {
		emu->xmm(i, xmm_values[i].data());
	}

	for (int i = 0; i <= 20; ++i) {
		char label[8] = {};
		if (i < 10) {
			sprintf_s(label, "xmm%d :", i);
		}
		else {
			sprintf_s(label, "xmm%d:", i);
		}
		print_xmm_register(label, xmm_values[i].data(), 16);
	}

	uint64_t rax = emu->rax();
	uint64_t memory_value = emu->qword(rax);
	uint64_t rbx = emu->rbx();
	printf("RAX: 0x%016llx   Value at memory[0x%016llx]   RBX: 0x%016llx\n", rax, memory_value, rbx);

	uint64_t rcx = emu->rcx();
	uint64_t rdx = emu->rdx();
	printf("RCX: 0x%016llx   RDX: 0x%016llx\n", rcx, rdx);
	uint64_t memory_address = rcx;
	memory_value = emu->qword(memory_address);
	printf("Address: 0x%016llx   Value at memory[0x%016llx]\n", memory_address, memory_value);
	uint64_t rsi = emu->rsi();
	uint64_t rdi = emu->rdi();
	printf("RSI: 0x%016llx   RDI: 0x%016llx\n", rsi, rdi);
	uint64_t rsp = emu->rsp();
	uint64_t rbp = emu->rbp();
	printf("RSP: 0x%016llx   RBP: 0x%016llx\n", rsp, rbp);
	uint64_t rip = emu->rip();
	uint64_t r8 = emu->r8();
	printf("RIP: 0x%016llx   R8:  0x%016llx\n", rip, r8);
	uint64_t r9 = emu->r9();
	uint64_t r10 = emu->r10();
	printf("R9:  0x%016llx   R10: 0x%016llx\n", r9, r10);
	uint64_t r11 = emu->r11();
	uint64_t r12 = emu->r12();
	printf("R11: 0x%016llx   R12: 0x%016llx\n", r11, r12);
	uint64_t r13 = emu->r13();
	uint64_t r14 = emu->r14();
	printf("R13: 0x%016llx   R14: 0x%016llx\n", r13, r14);
	uint64_t r15 = emu->r15();
	uint64_t cs = emu->cs();
	printf("R15: 0x%016llx   CS:  0x%016llx\n", r15, cs);
	uint64_t ds = emu->ds();
	uint64_t es = emu->es();
	printf("DS:  0x%016llx   ES:  0x%016llx\n", ds, es);
	uint64_t fs = emu->fs();
	uint64_t gs = emu->gs();
	printf("FS:  0x%016llx   GS:  0x%016llx\n", fs, gs);
	uint64_t ss = emu->ss();
	uint64_t cr0 = emu->cr0();
	printf("SS:  0x%016llx   CR0: 0x%016llx\n", ss, cr0);
	uint64_t cr2 = emu->cr2();
	uint64_t cr3 = emu->cr3();
	printf("CR2: 0x%016llx   CR3: 0x%016llx\n", cr2, cr3);
	uint64_t cr4 = emu->cr4();
	uint64_t cr8 = emu->cr8();
	printf("CR4: 0x%016llx   CR8: 0x%016llx\n", cr4, cr8);
	uint64_t eflags = emu->eflags();
	printf("EFLAGS: 0x%016llx\n", eflags);

	uint64_t gdtr_base = 0, idtr_base = 0;
	uint32_t gdtr_limit = 0, idtr_limit = 0;
	emu->gdtr(&gdtr_base, &gdtr_limit);
	emu->idtr(&idtr_base, &idtr_limit);
	printf("GDTR Base: 0x%llx, Limit: 0x%x  IDTR Base: 0x%llx, Limit: 0x%x\n", gdtr_base, gdtr_limit, idtr_base, idtr_limit);

}


