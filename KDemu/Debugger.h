#pragma once

#include <dbgeng.h>

#include <optional>
#include <filesystem>
#include <unordered_map>

#pragma comment(lib, "dbgeng.lib")

namespace fs = std::filesystem;

struct ModuleInfo {
	std::string Name;
	std::string ImageName;
	std::uint64_t BaseAddress;
	std::uint64_t Size;
};
struct ExportFunctionInfo {
	std::string Name;
	uint64_t    Va;
	ULONG Flags;
	ULONG TypeId;
	ULONG NameSize;
	ULONG Token;
	ULONG Tag;
	ULONG Arg32;
	ULONG Reserved;
};

class Debugger_t {
public:
	Debugger_t() = default;

	~Debugger_t();

	Debugger_t(const Debugger_t&) = delete;
	Debugger_t& operator=(const Debugger_t&) = delete;

	[[nodiscard]] bool Initialize(const fs::path& DumpPath);

	std::uint64_t GetSymbol(std::string_view Name) const;

	std::string GetName(std::uint64_t SymbolAddress, bool Symbolized) const;

	const std::vector<ModuleInfo>& GetModules() const;

	const std::uint8_t* GetVirtualPage(std::uint64_t Gva);

	std::uint64_t Evaluate64(const char* Expr) const;

	uint64_t Reg64(std::string_view name) const;

	//
	// Get system module information via MODULE NAME (i.e. "nt", ...)
	//
	const ModuleInfo* GetModule(std::string_view modName);

	//
	// Get system module information via IMAGE NAME (i.e. "ntoskrnl.exe", ...)
	//
	const ModuleInfo* GetModuleByFileName(std::string_view fileName);

	uint64_t GetFunctionVaFromExport(const std::string& fileName, const std::string& funcName);

	std::vector<std::string> GetAllExportFunctionNames(const std::string& fileName);

	std::vector<ExportFunctionInfo> GetAllExportFunctions(const std::string& fileName);


	std::vector<ExportFunctionInfo> ListAllFunctionsByDbgEng(const std::string& fileName);


private:
	IDebugClient4* Client_;
	IDebugControl4* Control_;
	IDebugRegisters2* Registers_;
	IDebugDataSpaces4* DataSpaces_;
	IDebugSymbols3* Symbols_;

	std::vector<ModuleInfo> Modules_;

	std::unordered_map<std::uint64_t, std::unique_ptr<std::uint8_t[]>> DumpedPages_;
	std::unordered_map<uint64_t, std::vector<uint8_t>> MappedBinaryContent_;

	std::unordered_map<std::string, const ModuleInfo*> NameToModuleInfo_;
	std::unordered_map<std::string, const ModuleInfo*> ImageNameToModuleInfo_;

};

extern Debugger_t* g_Debugger;