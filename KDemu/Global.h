#pragma once
#include <Windows.h>
#include <unicorn/unicorn.h>
#include <queue>
#include <ntstatus.h>

#ifdef NDEBUG
#define __debugbreak() ((void)0)
#endif
#ifdef NDEBUG
#define assert(x) ((void)0)
#endif

#ifdef IGNORE
#define RESTORE_IGNORE IGNORE
#undef IGNORE
#endif

#ifdef CONST
#define RESTORE_CONST CONST
#undef CONST
#endif
#include "LIEF/LIEF.hpp"


#ifdef RESTORE_CONST
#define CONST RESTORE_CONST
#undef RESTORE_IGNORE
#endif

#ifdef RESTORE_IGNORE
#define IGNORE RESTORE_IGNORE
#undef RESTORE_IGNORE
#endif

#include <iostream>
#define PAGE_SHIFT 12
#define PAGE_SIZE (1ULL << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define PAGE_ALIGN(addr) (((addr) + PAGE_SIZE - 1) & PAGE_MASK)
// code to be emulated
#define KB 1024
#define MB 1024 * KB
#define GB 1024 * MB
#define MEMORY_ALLOCATION 1 * MB

#define KUSER_SHARED_DATA_ADDRESS 0xFFFFF78000000000
#define KUSER_SHARED_ADDRESS 0x7FFE0000
#define KUSER_SHARED_DATA_SIZE 0x1000

#define UNWIND_HISTORY_TABLE_NONE 0
#define UNWIND_HISTORY_TABLE_GLOBAL 1
#define UNWIND_HISTORY_TABLE_LOCAL 2
#define MAXIMUM_INVERTED_FUNCTION_TABLE_SIZE 160 

#define EXCP00_DIVZ	0
#define EXCP01_DB	1
#define EXCP02_NMI	2
#define EXCP03_INT3	3
#define EXCP04_INTO	4
#define EXCP05_BOUND	5
#define EXCP06_ILLOP	6
#define EXCP07_PREX	7
#define EXCP08_DBLE	8
#define EXCP09_XERR	9
#define EXCP0A_TSS	10
#define EXCP0B_NOSEG	11
#define EXCP0C_STACK	12
#define EXCP0D_GPF	13
#define EXCP0E_PAGE	14
#define EXCP10_COPR	16
#define EXCP11_ALGN	17
#define EXCP12_MCHK	18

#define EXCP_SYSCALL    0x100 /* only happens in user only emulation
								 for syscall instruction */
#include <string>
class Logger {

public:
    static void Log(bool tid_show, int color, const char* std, ...);
    static void Log(bool tid_show, int color, const wchar_t* std, ...);
};



/// <summary>
/// LOG�C��
/// </summary>
enum ConsoleColor {
    BLACK = 0x0,
    DARK_BLUE = 0x1,
    DARK_GREEN = 0x2,
    DARK_CYAN = 0x3,
    DARK_RED = 0x4,
    DARK_MAGENTA = 0x5,
    DARK_YELLOW = 0x6,
    GRAY = 0x7,
    DARK_GRAY = 0x8,
    BLUE = 0x9,
    GREEN = 0xA,
    CYAN = 0xB,
    RED = 0xC,
    MAGENTA = 0xD,
    YELLOW = 0xE,
    WHITE = 0xF
};

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;
/// <summary>
/// �Q�� windows���WideCharToMultiByte�Nwstring�নstring
/// </summary>
/// <param name="str">Ū�J�ഫ�r�ꪺ�ܼ�</param>
/// <param name="out">�x�s�ഫ�r�ꪺ�ܼ�</param>
void UnicodeToANSI(const std::wstring& str, std::string& out);
/// <summary>
/// �Q��windows���WideCharToMultiByte�Nstring�নwstring
/// </summary>
/// <param name="str">Ū�J�ഫ�r�ꪺ�ܼ�</param>
/// <param name="out">�x�s�ഫ�r�ꪺ�ܼ�</param>
void ANSIToUnicode(const std::string& str, std::wstring& out);

/// <summary>
/// �Q��windows���RtlInitUnicodeString�Nwstring�নUNICODE_STRING
/// </summary>
/// <param name="KeyPath">�x�s�ഫ�r�ꪺ�ܼ�</param>
/// <param name="file_name_str">Ū�J�ഫ�r�ꪺ�ܼ�</param>
void ConvertToUnicodeString(UNICODE_STRING& KeyPath, const std::wstring& file_name_str);
/// <summary>
/// �q memŪ�Junicode�r����নwstring
/// </summary>
/// <param name="uc"></param>
/// <param name="address">Ū�����_�l�a�}</param>
/// <param name="str">�x�s�ഫ�r�ꪺ�ܼ�</param>
/// <returns></returns>
bool read_null_unicode_string(uc_engine* uc, uint64_t address, std::wstring& str);
/// <summary>
/// Ū�� UNICODE_STRING ���c���
/// </summary>
/// <param name="uc"></param>
/// <param name="unicode_string_addr">Ū�J���_�l��m</param>
/// <returns></returns>
std::wstring read_unicode_string(uc_engine* uc, uint64_t unicode_string_addr);
/// <summary>
/// Ū�� ANSI_STRING ���c���
/// </summary>
/// <param name="uc"></param>
/// <param name="ansi_string_addr">Ū�J���_�l��m</param>
/// <returns></returns>
std::string read_ansi_string(uc_engine* uc, uint64_t ansi_string_addr);

void fastCallRetHook(uc_engine* uc);
void errorRetHook(uc_engine* uc);
void RetHook(uc_engine* uc);
void print_xmm_register(const char* reg, const uint8_t* value, int length);
void ShowRegister(uc_engine* uc);
void dump_stack(uc_engine* uc, uint64_t rsp, size_t num_entries);
uint64_t qword_load(uc_engine* uc, uint64_t addr);

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

typedef void(*udbserver)(void* handle, uint16_t port, uint64_t start_addr);

#define UC_CTL(type, nr, rw)                                                   \
    (uc_control_type)((type) | ((nr) << 26) | ((rw) << 30))
#define UC_CTL_NONE(type, nr) UC_CTL(type, nr, UC_CTL_IO_NONE)
#define UC_CTL_READ(type, nr) UC_CTL(type, nr, UC_CTL_IO_READ)
#define UC_CTL_WRITE(type, nr) UC_CTL(type, nr, UC_CTL_IO_WRITE)
#define UC_CTL_READ_WRITE(type, nr) UC_CTL(type, nr, UC_CTL_IO_READ_WRITE)

typedef uint64_t(__fastcall* fnFreeCall)(...);

template <typename... Params>
static NTSTATUS __NtRoutine(const char* Name, Params&&... params) {
    auto fn = (fnFreeCall)GetProcAddress(GetModuleHandleA("ntdll.dll"), Name);
    return fn(std::forward<Params>(params)...);
}

struct Object {
    std::string name;
    uint64_t address;
    uint64_t size;
    Object(const std::string& n, uint64_t addr, uint64_t sz) : name(n), address(addr), size(sz) {}
};

static inline const char* uc_err_name(uc_err e) {
    static const char* kNames[] = {
        "UC_ERR_OK",
        "UC_ERR_NOMEM",
        "UC_ERR_ARCH",
        "UC_ERR_HANDLE",
        "UC_ERR_MODE",
        "UC_ERR_VERSION",
        "UC_ERR_READ_UNMAPPED",
        "UC_ERR_WRITE_UNMAPPED",
        "UC_ERR_FETCH_UNMAPPED",
        "UC_ERR_HOOK",
        "UC_ERR_INSN_INVALID",
        "UC_ERR_MAP",
        "UC_ERR_WRITE_PROT",
        "UC_ERR_READ_PROT",
        "UC_ERR_FETCH_PROT",
        "UC_ERR_ARG",
        "UC_ERR_READ_UNALIGNED",
        "UC_ERR_WRITE_UNALIGNED",
        "UC_ERR_FETCH_UNALIGNED",
        "UC_ERR_HOOK_EXIST",
        "UC_ERR_RESOURCE",
        "UC_ERR_EXCEPTION",
        "UC_ERR_OVERFLOW",
    };
    return (e >= 0 && (size_t)e < (sizeof kNames / sizeof kNames[0]))
        ? kNames[e] : "UC_ERR_UNKNOWN";
}