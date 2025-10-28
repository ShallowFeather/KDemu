#ifndef PELOADER_HPP
#define PELOADER_HPP
#include "Global.h"
#include "kdmp-parser/kdmp-parser.h"

typedef struct ThreadInfo {
	int id;
	uc_context* uc_ctx;
	uint64_t routineStart;
	uint64_t routineContext;
	uc_engine* tuc;
	HANDLE Event;
	HANDLE handle;
	DWORD threadId;
	uint64_t paddress;
} ThreadInfo_t;

typedef struct _INVERTED_FUNCTION_TABLE_ENTRY {
	PRUNTIME_FUNCTION FunctionTable;
	PVOID ImageBase;
	ULONG SizeOfImage;
	ULONG SizeOfTable;
} INVERTED_FUNCTION_TABLE_ENTRY, * PINVERTED_FUNCTION_TABLE_ENTRY;

typedef struct _INVERTED_FUNCTION_TABLE {
	ULONG CurrentSize;
	ULONG MaximumSize;
	BOOLEAN Overflow;
	INVERTED_FUNCTION_TABLE_ENTRY TableEntry[160];
} INVERTED_FUNCTION_TABLE, * PINVERTED_FUNCTION_TABLE;

typedef enum my_uc_prot {
	MUC_PROT_NONE = 0,
	MUC_PROT_READ = 1,
	MUC_PROT_WRITE = 2,
	MUC_PORT_READ_WRITE = 3,
	MUC_PROT_EXEC = 4,
	MUC_PROT_ALL = 7,
} my_uc_prot;


class PEloader {
private:
public:
	PEloader() = default;

	static PEloader& GetInstance() {
		static PEloader instance;
		return instance;
	}
	PEloader(const PEloader&) = delete;
	PEloader& operator=(const PEloader&) = delete;

	uint64_t sysinfo_addr = 0;
	uint32_t SystemInformationClass = 0;
	kdmpparser::KernelDumpParser kdmp;
	uc_engine* uc;
	uint64_t PsLoadedModuleListBase;
	uint64_t RtlRaiseStatusBase;
	INVERTED_FUNCTION_TABLE PsInvertedFunctionTable;
	std::map<std::string, uint64_t> AllDriverBaseAddr;
	void GetAllDriverBaseAddresses();
	void MapAllDriversFromKdmp();
	std::unordered_map<uint32_t, std::pair<uint64_t, std::string>> MSRList;

	std::vector<Object*> objectList;

	static const uint64_t Emu_file_Base = 0xfffff805dc9a0000;

	uint64_t NtoskrnlBase = 0xfffff8052e400000;

	uint64_t StackBase = 0xffff890a9a3c7000;

	uint64_t cibase = 0xfffff80532e00000;

	uint64_t halbase = 0xfffff8052d520000;

	uint64_t cngbase = 0xfffff80532ef0000;
	const uint64_t GsBase = 0xfffff80506d51000;
	static const uint64_t scratch = 0xffffffff00000000;

	const uint64_t StackSize = 0x1000;

	static const uint64_t AllocBase = 0xffffff000000000;

	uint64_t AllocatedContiguous = 0;
	uint64_t rsdtc_r8 = 0;
	uint64_t rsdtc_r9 = 0;
	bool go_addr = false;
	std::map<uint64_t, std::string> hook_addr_fn;

	std::vector<ThreadInfo_t*> Threads;

	std::vector<HANDLE> waitHandles;

	uint64_t lastExcept;

	uint64_t lastAlloc;
	volatile LONG g_flag = 0;
	volatile LONG g_running = 1;
	CRITICAL_SECTION cs;

	HANDLE errorevent;

	uc_context* ucContext = nullptr;

	std::map<uint64_t, std::pair<void*, uint64_t>>  real_mem_map;
	std::map<uint64_t, std::pair<void*, my_uc_prot>>  real_mem_map_type_read;
	std::map<uint64_t, std::pair<void*, my_uc_prot>>  real_mem_map_type_read_write;
	std::map<uint64_t, std::pair<void*, my_uc_prot>>  real_mem_map_type_all;



	std::map<uint64_t, uint64_t> hook;
	uint64_t ExecuteFromRip;
	int ExecuteExceptionHandler = 0;
	int LastException;


	struct VirtualFile {
		uint64_t handle;
		uint64_t size;
		uint64_t FileBase;
	};

	std::map<std::wstring, VirtualFile> virtual_files;

	std::map<uint64_t, std::wstring> handle_table;

	uint64_t FILE_handle;


	typedef struct PEfile {
		std::unique_ptr<LIEF::PE::Binary> Binary;
		void* memMap;
		uint64_t Base;
		uint64_t End;
		uint64_t Entry;
		ULONG64 ExceptionTable;
		ULONG ExceptionTableSize;
		uint64_t LdrEntry;
		std::map<uint64_t, std::string> FuncRVA;
		std::map<std::string, uint64_t> FuncAddr;
		std::string FileName;
	} PEfile_t;



	std::vector<PEfile_t*> peFiles;
	std::map<uint64_t, std::string> ntoskrnlRVA;

	struct _stack {
		uint64_t address;
		PVOID buffer;
		size_t size;
	} stack;
	void InsertTailList(
		IN ULONG64 ListHeadAddress,
		IN ULONG64 EntryAddress
	);


	void InitProcessor();

	void Init();

	void LoadDmp();

	void map_kuser_shared_data();

	void InitPsLoadedModule(uint64_t imageBase, uint64_t imageEntry, uint64_t imageSize, std::wstring dllName, int type);

	void Relocation(uint64_t newBase, int type);

	void FixImport(uint64_t baseAddr, LIEF::PE::Binary::it_imports imports);

	bool LoadPE(const std::string path);


	void LoadModule(std::string path, int type);
};

#endif
