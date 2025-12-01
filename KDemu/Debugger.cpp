
#include "Debugger.h"
#include "Global.h"

Debugger_t* g_Debugger = nullptr;

Debugger_t::~Debugger_t() {
    if (Client_) {
        Client_->EndSession(DEBUG_END_ACTIVE_DETACH);
        Client_->Release();
    }

    if (Control_) {
        Control_->Release();
    }

    if (Registers_) {
        Registers_->Release();
    }

    if (Symbols_) {
        Symbols_->Release();
    }
}

[[nodiscard]] bool Debugger_t::Initialize(const fs::path& DumpPath) {
    Logger::Log(true, ConsoleColor::DARK_GREEN, "[*] Initializing the debugger instance..\n");

    char ExePathBuffer[MAX_PATH];
    if (!GetModuleFileNameA(nullptr, &ExePathBuffer[0],
        sizeof(ExePathBuffer))) {
        Logger::Log(true, ConsoleColor::RED, "GetModuleFileNameA failed.\n");
        return false;
    }

    const fs::path ExePath(ExePathBuffer);
    const fs::path ParentDir(ExePath.parent_path());
    const std::vector<std::string_view> Dlls = { "dbghelp.dll", "symsrv.dll",
                                                "dbgeng.dll", "dbgcore.dll" };
    const fs::path DefaultDbgDllLocation(
        R"(c:\program Files (x86)\windows kits\10\debuggers\x64)");

    for (const auto& Dll : Dlls) {
        if (fs::exists(ParentDir / Dll)) {
            continue;
        }

        const fs::path DbgDllLocation(DefaultDbgDllLocation / Dll);
        if (!fs::exists(DbgDllLocation)) {
            Logger::Log(true, ConsoleColor::RED, "Cannot find required dll needed for dbgeng\n");
            return false;
        }

        fs::copy(DbgDllLocation, ParentDir);
    }

    HRESULT Status = DebugCreate(__uuidof(IDebugClient), (void**)&Client_);
    if (FAILED(Status)) {
        Logger::Log(true, ConsoleColor::RED, "[-] DebugCreate failed with hr=0x%lx\n", Status);
        return false;
    }

    Status =
        Client_->QueryInterface(__uuidof(IDebugControl), (void**)&Control_);
    if (FAILED(Status)) {
        Logger::Log(true, ConsoleColor::RED, "[-] QueryInterface/IDebugControl failed with hr=0x%lx\n", Status);
        return false;
    }

    Status = Client_->QueryInterface(__uuidof(IDebugRegisters),
        (void**)&Registers_);
    if (FAILED(Status)) {
        Logger::Log(true, ConsoleColor::RED, "[-] QueryInterface/IDebugRegisters failed with hr=0x%lx\n",
            Status);
        return false;
    }

    Status =
        Client_->QueryInterface(__uuidof(IDebugSymbols3), (void**)&Symbols_);
    if (FAILED(Status)) {
        Logger::Log(true, ConsoleColor::RED, "[-] QueryInterface/IDebugSymbols failed with hr=0x%lx\n", Status);
        return false;
    }

    Status =
        Client_->QueryInterface(__uuidof(IDebugDataSpaces4), (void**)&DataSpaces_);
    if (FAILED(Status)) {
        Logger::Log(true, ConsoleColor::RED, "[-] QueryInterface/IDebugDataSpaces4 failed with hr=0x%lx\n", Status);
        return false;
    }

    const std::string& DumpFileString = DumpPath.string();
    const char* DumpFileA = DumpFileString.c_str();

    Logger::Log(true, ConsoleColor::DARK_GREEN, "[*] Processing dump file... %s\n", DumpFileA);

    Status = Client_->OpenDumpFile(DumpFileA);
    if (FAILED(Status)) {
        Logger::Log(true, ConsoleColor::RED, "[-] OpenDumpFile(%s) failed with hr=0x%lx\n", DumpFileString,
            Status);
        return false;
    }

    Logger::Log(true, ConsoleColor::DARK_GREEN, "[*] Dump file opened.\n");

    Status = Control_->WaitForEvent(DEBUG_WAIT_DEFAULT, INFINITE);
    if (FAILED(Status)) {
        Logger::Log(true, ConsoleColor::RED, "[-] WaitForEvent for OpenDumpFile failed with hr=0x%lx\n",
            Status);
        return false;
    }

    //
    // initialize modules
    //

    ULONG loaded, unloaded;
    if (FAILED(this->Symbols_->GetNumberModules(&loaded, &unloaded)))
        return false;

    for (ULONG i = 0; i < loaded; i++) {
        DEBUG_MODULE_PARAMETERS params{};
        if (FAILED(this->Symbols_->GetModuleParameters(1, nullptr, i, &params)))
            continue;

        char name[MAX_PATH] = {};
        char image[MAX_PATH] = {};

        if (FAILED(this->Symbols_->GetModuleNameString(DEBUG_MODNAME_MODULE, i, 0, name, sizeof(name), nullptr)))
            strcpy_s(name, "unknown");

        if (FAILED(this->Symbols_->GetModuleNameString(DEBUG_MODNAME_IMAGE, i, 0, image, sizeof(image), nullptr)))
            strcpy_s(image, "unknown");



        ModuleInfo info{
            .Name = name,
            .ImageName = image,
            .BaseAddress = params.Base,
            .Size = params.Size
        };
        Modules_.emplace_back(std::move(info));
    }

    Logger::Log(true, ConsoleColor::DARK_GREEN, "[*] Debugger initialized\n");

    return true;
}

const std::vector<ModuleInfo>& Debugger_t::GetModules() const {
    return Modules_;
}

std::uint64_t Debugger_t::GetSymbol(std::string_view Name) const {
    uint64_t Offset = 0;

    HRESULT Status = Symbols_->GetOffsetByName(Name.data(), &Offset);

    if (FAILED(Status)) {
        if (Status == S_FALSE) {
            return 0ull;
        }
    }

    return Offset;
}

std::string Debugger_t::GetName(std::uint64_t SymbolAddress, bool Symbolized) const {
    const size_t NameSizeMax = MAX_PATH;
    char Buffer[NameSizeMax];
    uint64_t Offset = 0;

    if (Symbolized) {
        const HRESULT Status = Symbols_->GetNameByOffset(
            SymbolAddress, Buffer, NameSizeMax, nullptr, &Offset);
        if (FAILED(Status)) {
            return "";
        }
    }
    else {
        ULONG Index;
        ULONG64 Base;
        HRESULT Status =
            Symbols_->GetModuleByOffset(SymbolAddress, 0, &Index, &Base);

        if (FAILED(Status)) {
            return "";
        }

        ULONG NameSize;
        Status = Symbols_->GetModuleNameString(DEBUG_MODNAME_MODULE, Index, Base,
            Buffer, NameSizeMax, &NameSize);

        if (FAILED(Status)) {
            return "";
        }

        Offset = SymbolAddress - Base;
    }

    return std::format("{}{}", Buffer, Offset ? std::format("+{:#x}", Offset) : "");
}

std::uint64_t Debugger_t::Evaluate64(const char* Expr) const {
    DEBUG_VALUE Value;
    Control_->Evaluate(Expr, DEBUG_VALUE_INT64, &Value, NULL);
    return Value.I64;
}

const std::uint8_t* Debugger_t::GetVirtualPage(std::uint64_t VirtualAddress) {
    std::uint64_t PageAddress = VirtualAddress & ~0xfff;
    if (DumpedPages_.contains(PageAddress)) {
        return DumpedPages_.at(PageAddress).get();
    }

    auto Page = std::make_unique<std::uint8_t[]>(0x1000);

    ULONG BytesRead = 0;
    HRESULT hr = DataSpaces_->ReadVirtual(PageAddress, Page.get(), 0x1000, &BytesRead);
    if (FAILED(hr) || BytesRead != 0x1000) {
        std::memset(Page.get(), 0, 0x1000);
    }

    DumpedPages_[PageAddress] = std::move(Page);
    return DumpedPages_.at(PageAddress).get();
}

uint64_t Debugger_t::Reg64(std::string_view name) const {
    ULONG Index = 0;
    if (FAILED(Registers_->GetIndexByName(name.data(), &Index))) {
        return 0ull;
    }

    DEBUG_VALUE RegVal;
    if (FAILED(Registers_->GetValue(Index, &RegVal))) {
        return 0ull;
    }

    return RegVal.I64;
}

const ModuleInfo* Debugger_t::GetModule(std::string_view modName) {
    std::string modNameStr{ modName };
    if (!ImageNameToModuleInfo_.contains(modNameStr)) {
        for (const auto& Mod : Modules_) {
            if (Mod.Name == modName) {
                ImageNameToModuleInfo_[modNameStr] = &Mod;
            }
        }
    }

    return ImageNameToModuleInfo_.contains(modNameStr) ? ImageNameToModuleInfo_.at(modNameStr) : nullptr;
}

const ModuleInfo* Debugger_t::GetModuleByFileName(std::string_view fileName) {
    std::string fileNameStr{ fileName };

    if (!NameToModuleInfo_.contains(fileNameStr)) {
        for (const auto& Mod : Modules_) {
            if (Mod.ImageName.ends_with(fileName)) {
                NameToModuleInfo_[fileNameStr] = &Mod;
            }
        }
    }

    return NameToModuleInfo_.contains(fileNameStr) ? NameToModuleInfo_.at(fileNameStr) : nullptr;
}

#undef min

uint64_t Debugger_t::GetFunctionVaFromExport(const std::string& fileName,
    const std::string& funcName) {

    auto moduleInfo = GetModuleByFileName(fileName);
    if (fileName == "ntoskrnl.exe") {
        moduleInfo = GetModule("nt");
    }

    if (!moduleInfo) {
        Logger::Log(true, RED, "Failed to find module %s to load its content", fileName.data());
        return false;
    }

    uint64_t moduleBaseVa = moduleInfo->BaseAddress;

    if (!MappedBinaryContent_.contains(moduleBaseVa)) {
        std::vector<uint8_t> contigusBinaryData_(moduleInfo->Size, 0);

        for (size_t offset = 0; offset < moduleInfo->Size; offset += 0x1000) {
            auto data = GetVirtualPage(moduleBaseVa + offset);
            if (!data) continue;

            size_t copySize = std::min(static_cast<size_t>(0x1000), moduleInfo->Size - offset);
            std::memcpy(contigusBinaryData_.data() + offset, data, copySize);
        }

        MappedBinaryContent_[moduleBaseVa] = contigusBinaryData_;
    }

    auto& contigusBinaryData = MappedBinaryContent_.at(moduleBaseVa);

    auto moduleBase = contigusBinaryData.data();
    auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(moduleBase);
    auto ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(
        (uint8_t*)moduleBase + dosHeader->e_lfanew);

    auto exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportDirRVA)
        return 0;

    auto exportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
        (uint8_t*)moduleBase + exportDirRVA);

    auto names = reinterpret_cast<uint32_t*>((uint8_t*)moduleBase + exportDir->AddressOfNames);
    auto funcs = reinterpret_cast<uint32_t*>((uint8_t*)moduleBase + exportDir->AddressOfFunctions);
    auto ordinals = reinterpret_cast<uint16_t*>((uint8_t*)moduleBase + exportDir->AddressOfNameOrdinals);

    for (uint32_t i = 0; i < exportDir->NumberOfNames; i++) {
        const char* name = (const char*)((uint8_t*)moduleBase + names[i]);
        if (funcName == name) {
            uint16_t ordinal = ordinals[i];
            uint32_t funcRVA = funcs[ordinal];
            return funcRVA + moduleBaseVa;
        }
    }

    return 0;
}


std::vector<std::string> Debugger_t::GetAllExportFunctionNames(const std::string& fileName)
{
    std::vector<std::string> result;

    auto moduleInfo = GetModuleByFileName(fileName);
    if (fileName == "ntoskrnl.exe") {
        moduleInfo = GetModule("nt");
    }

    if (!moduleInfo) {
        Logger::Log(true, RED, "Failed to find module %s to load its content\n", fileName.c_str());
        return result;
    }

    uint64_t moduleBaseVa = moduleInfo->BaseAddress;

    // 跟原本一樣：從 dump 把整個模組拼成一塊連續 buffer
    if (!MappedBinaryContent_.contains(moduleBaseVa)) {
        std::vector<uint8_t> contigusBinaryData_(moduleInfo->Size, 0);

        for (size_t offset = 0; offset < moduleInfo->Size; offset += 0x1000) {
            auto data = GetVirtualPage(moduleBaseVa + offset);
            if (!data) continue;

            size_t copySize = std::min(static_cast<size_t>(0x1000), moduleInfo->Size - offset);
            std::memcpy(contigusBinaryData_.data() + offset, data, copySize);
        }

        MappedBinaryContent_[moduleBaseVa] = std::move(contigusBinaryData_);
    }

    auto& contigusBinaryData = MappedBinaryContent_.at(moduleBaseVa);

    auto moduleBase = contigusBinaryData.data();
    auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(moduleBase);
    auto ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(
        (uint8_t*)moduleBase + dosHeader->e_lfanew);

    auto exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportDirRVA)
        return result; // no export

    auto exportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
        (uint8_t*)moduleBase + exportDirRVA);

    auto names = reinterpret_cast<uint32_t*>((uint8_t*)moduleBase + exportDir->AddressOfNames);
    auto funcs = reinterpret_cast<uint32_t*>((uint8_t*)moduleBase + exportDir->AddressOfFunctions);
    auto ordinals = reinterpret_cast<uint16_t*>((uint8_t*)moduleBase + exportDir->AddressOfNameOrdinals);

    for (uint32_t i = 0; i < exportDir->NumberOfNames; i++) {
        const char* name = (const char*)((uint8_t*)moduleBase + names[i]);
        if (!name || !*name)
            continue;

        // 這裡單純收集名字
        result.emplace_back(name);

        // 如果只要名字就這樣，VA 不用管
        // 如果之後要 VA，可以再補：
        // uint16_t ordinal = ordinals[i];
        // uint32_t funcRVA = funcs[ordinal];
        // uint64_t funcVA  = funcRVA + moduleBaseVa;
    }

    return result;
}




std::vector<ExportFunctionInfo> Debugger_t::GetAllExportFunctions(const std::string& fileName)
{
    std::vector<ExportFunctionInfo> result;

    auto moduleInfo = GetModuleByFileName(fileName);
    if (fileName == "ntoskrnl.exe") {
        moduleInfo = GetModule("nt");
    }

    if (!moduleInfo) {
        Logger::Log(true, RED, "Failed to find module %s to load its content\n", fileName.c_str());
        return result;
    }

    uint64_t moduleBaseVa = moduleInfo->BaseAddress;

    if (!MappedBinaryContent_.contains(moduleBaseVa)) {
        std::vector<uint8_t> contigusBinaryData_(moduleInfo->Size, 0);

        for (size_t offset = 0; offset < moduleInfo->Size; offset += 0x1000) {
            auto data = GetVirtualPage(moduleBaseVa + offset);
            if (!data) continue;

            size_t copySize = std::min(static_cast<size_t>(0x1000), moduleInfo->Size - offset);
            std::memcpy(contigusBinaryData_.data() + offset, data, copySize);
        }

        MappedBinaryContent_[moduleBaseVa] = std::move(contigusBinaryData_);
    }

    auto& contigusBinaryData = MappedBinaryContent_.at(moduleBaseVa);

    auto moduleBase = contigusBinaryData.data();
    auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(moduleBase);
    auto ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(
        (uint8_t*)moduleBase + dosHeader->e_lfanew);

    auto exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportDirRVA)
        return result;

    auto exportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
        (uint8_t*)moduleBase + exportDirRVA);

    auto names = reinterpret_cast<uint32_t*>((uint8_t*)moduleBase + exportDir->AddressOfNames);
    auto funcs = reinterpret_cast<uint32_t*>((uint8_t*)moduleBase + exportDir->AddressOfFunctions);
    auto ordinals = reinterpret_cast<uint16_t*>((uint8_t*)moduleBase + exportDir->AddressOfNameOrdinals);

    for (uint32_t i = 0; i < exportDir->NumberOfNames; i++) {
        const char* name = (const char*)((uint8_t*)moduleBase + names[i]);
        if (!name || !*name)
            continue;

        uint16_t ordinal = ordinals[i];
        uint32_t funcRVA = funcs[ordinal];
        uint64_t funcVA = funcRVA + moduleBaseVa;

        result.push_back(ExportFunctionInfo{
            .Name = name,
            .Va = funcVA,
            });
    }

    return result;
}



std::vector<ExportFunctionInfo> Debugger_t::ListAllFunctionsByDbgEng(const std::string& fileName)
{
    std::vector<ExportFunctionInfo> result;

    // 先用你現有的 API 找到模組
    const ModuleInfo* moduleInfo = GetModuleByFileName(fileName);
    if (fileName == "ntoskrnl.exe") {
        int Status = Symbols_->Reload("nt");   // 可以給 pattern，例如 "nt"
        if (FAILED(Status)) {
            Logger::Log(true, ConsoleColor::RED,
                "[-] Symbols_->Reload failed, hr=0x%lx\n", Status);
        }
        moduleInfo = GetModule("nt");   // 跟 GetFunctionVaFromExport 同樣特例
    }

    if (!moduleInfo) {
        Logger::Log(true, ConsoleColor::RED,
            "[-] ListAllFunctionsByDbgEng: module %s not found\n",
            fileName.c_str());
        return result;
    }

    // DbgEng 的 symbol pattern: "modname!*"
    // 例如 nt!*、win32kfull!* ...
    std::string pattern = moduleInfo->Name + "!*";

    // 第一次呼叫只拿 count
    ULONG count = 0;
    HRESULT hr = Symbols_->GetSymbolEntriesByName(
        pattern.c_str(),
        0,          // Flags = 0
        nullptr,    // Ids = nullptr (只拿數量)
        0,          // IdsCount = 0
        &count      // Entries = 符合個數
    );

    if (FAILED(hr) || count == 0) {
        Logger::Log(true, ConsoleColor::RED,
            "[-] GetSymbolEntriesByName(%s) failed or no symbol (hr=0x%lx, count=%lu)\n",
            pattern.c_str(), hr, count);
        return result;
    }

    std::vector<DEBUG_MODULE_AND_ID> ids(count);

    // 第二次真的把每個 symbol 的 DEBUG_MODULE_AND_ID 取出來
    hr = Symbols_->GetSymbolEntriesByName(
        pattern.c_str(),
        0,
        ids.data(),
        count,
        nullptr      // Entries 可以為 nullptr，因為我們只要 ids
    );

    if (FAILED(hr)) {
        Logger::Log(true, ConsoleColor::RED,
            "[-] GetSymbolEntriesByName(%s) (2nd) failed, hr=0x%lx\n",
            pattern.c_str(), hr);
        return result;
    }

    // 逐個 symbol 取資訊
    for (ULONG i = 0; i < count; ++i) {
        const DEBUG_MODULE_AND_ID& id = ids[i];

        DEBUG_SYMBOL_ENTRY entry{};
        hr = Symbols_->GetSymbolEntryInformation(
            const_cast<DEBUG_MODULE_AND_ID*>(&id),
            &entry
        );
        if (FAILED(hr))
            continue;



        char nameBuf[512] = {};
        ULONG nameLen = 0;

        hr = Symbols_->GetSymbolEntryString(
            const_cast<DEBUG_MODULE_AND_ID*>(&id),
            0x00000000, // 要 name
            nameBuf,
            static_cast<ULONG>(sizeof(nameBuf)),
            &nameLen
        );
        if (FAILED(hr))
            continue;



        ExportFunctionInfo info{};
        info.Name = nameBuf;
        info.Va = entry.Offset;   // entry.Offset 就是該函式的 VA
        info.Flags = entry.Flags;
        info.TypeId = entry.TypeId;
        info.NameSize = entry.NameSize;
        info.Token = entry.Token;
        info.Tag = entry.Tag;
        info.Arg32 = entry.Arg32;
        info.Reserved = entry.Reserved;

        result.emplace_back(std::move(info));
    }

    return result;
}
