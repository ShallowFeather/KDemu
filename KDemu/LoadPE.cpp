#include "LoadPE.hpp"
#include "NtType.hpp"
#include "Emulate.hpp"
#include "UnicornEmu.hpp"
#include <fstream>
#include <psapi.h>
#include "cpu.h"

#pragma comment(lib,"ntdll.lib")

#pragma warning(disable : 4996)
extern "C"
{
	NTSYSAPI
		PVOID
		NTAPI
		RtlImageDirectoryEntryToData(
			PVOID BaseAddress,
			BOOLEAN MappedAsImage,
			USHORT Directory,
			PULONG Size
		);
}

void PEloader::GetAllDriverBaseAddresses() {
	DWORD cbNeeded = 0;
	if (!EnumDeviceDrivers(NULL, 0, &cbNeeded)) {
		std::cerr << "EnumDeviceDrivers failed to get size: " << GetLastError() << std::endl;
		return;
	}

	std::vector<void*> driverAddresses(cbNeeded / sizeof(void*));
	if (!EnumDeviceDrivers(driverAddresses.data(), cbNeeded, &cbNeeded)) {
		std::cerr << "EnumDeviceDrivers failed: " << GetLastError() << std::endl;
		return;
	}
	for (void* baseAddr : driverAddresses) {
		if (baseAddr == nullptr) break;

		wchar_t driverName[MAX_PATH] = { 0 };
		if (GetDeviceDriverBaseName(baseAddr, driverName, MAX_PATH)) {
			int len = WideCharToMultiByte(CP_UTF8, 0, driverName, -1, nullptr, 0, nullptr, nullptr);
			if (len > 0) {
				std::string strName(len - 1, 0);
				int result = WideCharToMultiByte(CP_UTF8, 0, driverName, -1, &strName[0], len, nullptr, nullptr);
				if (result > 0) {
					this->AllDriverBaseAddr[strName] = (uint64_t)baseAddr;
					if (strName == "ntoskrnl.exe" || strName == "CI.dll" || strName == "cng.sys")
						LoadModule(strName, 0);
				}
				else {
					std::cerr << "WideCharToMultiByte failed: " << GetLastError() << std::endl;
				}
			}
		}
	}
}

void PEloader::MapAllDriversFromKdmp() {
    auto emu = Emu(uc);

    auto to_lower = [](std::string s) {
        for (auto &c : s) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
        return s;
    };
    auto basename_no_ext = [&](const std::string &path) {
        size_t pos = path.find_last_of("/\\");
        std::string fname = (pos == std::string::npos) ? path : path.substr(pos + 1);
        size_t dot = fname.find_last_of('.');
        if (dot != std::string::npos) fname = fname.substr(0, dot);
        return to_lower(fname);
    };
    std::vector<std::string> processed_names;
    processed_names.reserve(peFiles.size());
    for (auto *pf : peFiles) {
        if (!pf) continue;
        processed_names.emplace_back(basename_no_ext(pf->FileName));
    }

    int ntIndex = -1;
    for (size_t i = 0; i < peFiles.size(); ++i) {
        if (peFiles[i] && peFiles[i]->FileName == "ntoskrnl.exe") {
            ntIndex = static_cast<int>(i);
            break;
        }
    }
    if (ntIndex < 0) {
		Logger::Log(true, ConsoleColor::RED, "[KDMP] Failed to find ntoskrnl.exe PE metadata; unable to locate PsLoadedModuleList.\n");
        return;
    }

    uint64_t psListRva = 0;
    {
        auto it = peFiles[ntIndex]->FuncAddr.find("PsLoadedModuleList");
        if (it != peFiles[ntIndex]->FuncAddr.end())
            psListRva = it->second;
    }
	if (psListRva == 0) {
		Logger::Log(true, ConsoleColor::RED, "[KDMP] PsLoadedModuleList symbol not found (RVA=0).\n");
        return;
    }

    uint64_t ntCandidates[3] = { 0, 0, 0 };
    int candCount = 0;
    if (peFiles[ntIndex]->Base) ntCandidates[candCount++] = peFiles[ntIndex]->Base;
    if (NtoskrnlBase) ntCandidates[candCount++] = NtoskrnlBase;
    auto itLive = AllDriverBaseAddr.find("ntoskrnl.exe");
    if (itLive != AllDriverBaseAddr.end()) ntCandidates[candCount++] = itLive->second;

    auto read_kdmp = [this](uint64_t addr, void* out, size_t sz) -> bool {
        uint8_t* dst = reinterpret_cast<uint8_t*>(out);
        size_t rem = sz;
        while (rem > 0) {
            uint64_t page_base = addr & ~0xfffull;
            const uint8_t* page = kdmp.GetVirtualPage(page_base);
            if (!page) return false;
            size_t off = static_cast<size_t>(addr & 0xfff);
            size_t avail = 0x1000ull - off;
            size_t n = (rem < avail) ? rem : avail;
            const uint8_t* src = page + off;
            for (size_t i = 0; i < n; ++i) dst[i] = src[i];
            dst += n;
            addr += n;
            rem -= n;
        }
        return true;
    };

    LIST_ENTRY listHead{};
    uint64_t psListHeadAddr = 0;
    bool headOk = false;
    for (int i = 0; i < candCount; ++i) {
        uint64_t base = ntCandidates[i];
        if (!base) continue;
        uint64_t addr = base + psListRva;
        if (read_kdmp(addr, &listHead, sizeof(listHead))) {
            psListHeadAddr = addr;
            headOk = true;
			Logger::Log(true, ConsoleColor::DARK_GREEN, "[KDMP] PsLoadedModuleList OK, nt base=0x%llx -> head=0x%llx.\n", base, addr);
            break;
        } else {
			Logger::Log(true, ConsoleColor::YELLOW, "[KDMP] Attempt with nt base=0x%llx failed (addr=0x%llx).\n", base, addr);
        }
    }
    if (!headOk) {
		Logger::Log(true, ConsoleColor::RED, "[KDMP] Reading PsLoadedModuleList failed; all candidate bases were invalid.\n");
        return;
    }

    uint64_t current = reinterpret_cast<uint64_t>(listHead.Flink);
    const uint64_t listHeadVA = psListHeadAddr;
    const int kMaxModules = 4096;
    int mod_count = 0;

    while (current && current != listHeadVA && mod_count < kMaxModules) {
        _LDR_DATA_TABLE_ENTRY ldr{};
        if (!read_kdmp(current, &ldr, sizeof(ldr))) {
			Logger::Log(true, ConsoleColor::YELLOW, "[KDMP] Failed to read LDR_DATA_TABLE_ENTRY (addr=0x%llx).\n", current);
            break;
        }

        const uint64_t imageBase = reinterpret_cast<uint64_t>(ldr.DllBase);
        const uint64_t imageSize = static_cast<uint64_t>(ldr.SizeOfImage);

        std::wstring wname;
        if (ldr.BaseDllName.Length && ldr.BaseDllName.Buffer) {
            uint16_t len = ldr.BaseDllName.Length;
            std::vector<wchar_t> buf((len / sizeof(wchar_t)) + 1, L'\0');
            read_kdmp(reinterpret_cast<uint64_t>(ldr.BaseDllName.Buffer), buf.data(), len);
            wname.assign(buf.data(), buf.data() + (len / sizeof(wchar_t)));
        } else {
            wname = L"(unknown)";
        }
        std::string name;
        UnicodeToANSI(wname, name);

        if (imageBase && imageSize) {
            const uint64_t alignedStart = imageBase & ~0xfffull;
            const uint64_t alignedEnd   = (imageBase + imageSize + 0xfff) & ~0xfffull;
            const uint64_t alignedSize  = alignedEnd - alignedStart;
            std::string baseNameNoExt = basename_no_ext(name);
            bool skip_by_name = false;
            for (const auto &pn : processed_names) {
                if (pn == baseNameNoExt || pn.find(baseNameNoExt) != std::string::npos || baseNameNoExt.find(pn) != std::string::npos) {
                    skip_by_name = true;
                    break;
                }
            }

            bool skip_by_range = false;
            uint64_t imgStart = imageBase;
            uint64_t imgEnd = imageBase + imageSize - 1;
            for (auto *pf : peFiles) {
                if (!pf) continue;
                uint64_t peStart = pf->Base;
                uint64_t peEnd = pf->End;
				if (imgStart <= peEnd && imgEnd >= peStart) {
                    skip_by_range = true;
                    break;
                }
            }

            if (skip_by_name || skip_by_range) {
                Logger::Log(true, ConsoleColor::YELLOW,
					"[KDMP] Skip previously processed module: %s Base=0x%llx Size=0x%llx (by %s)\n",
                    name.c_str(), imageBase, imageSize,
                    skip_by_name ? "name" : "range");
                current = reinterpret_cast<uint64_t>(ldr.InLoadOrderLinks.Flink);
                continue;
            }

            void* host_buf = _aligned_malloc(static_cast<size_t>(alignedSize), 0x1000);
            if (!host_buf) {
				Logger::Log(true, ConsoleColor::RED, "[KDMP] Buffer allocation failed: %s Base=0x%llx Size=0x%llx\n", name.c_str(), imageBase, imageSize);
            } else {
                uint8_t* p = reinterpret_cast<uint8_t*>(host_buf);
                for (uint64_t i = 0; i < alignedSize; ++i) p[i] = 0;

                uint64_t filled = 0;
                for (uint64_t addr = alignedStart; addr < alignedEnd; addr += 0x1000) {
                    const uint8_t* page = kdmp.GetVirtualPage(addr);
                    if (!page) continue;
                    uint64_t off = addr - alignedStart;
                    for (size_t i = 0; i < 0x1000; ++i) p[off + i] = page[i];
                    filled += 0x1000;
                }

                bool already_mapped = false;
                uint8_t probe = 0;
                if (emu->try_read(alignedStart, &probe, sizeof(probe))) {
                    already_mapped = true;
                }

                if (!already_mapped) {
                    uc_err err = emu->mem_map_ptr(alignedStart, static_cast<size_t>(alignedSize), UC_PROT_ALL, host_buf);
                    if (err != UC_ERR_OK) {
						Logger::Log(true, ConsoleColor::RED, "[KDMP] uc_mem_map_ptr failed: %s err=%d Base=0x%llx Size=0x%llx\n",
                            name.c_str(), err, alignedStart, alignedSize);
                        _aligned_free(host_buf);
                    } else {
                        real_mem_map[alignedStart] = { host_buf, alignedSize };
                        real_mem_map_type_all[alignedStart] = { host_buf, MUC_PROT_ALL };

                        Logger::Log(true, ConsoleColor::DARK_GREEN,
							"[KDMP] Mapped driver: %s Base=0x%llx Size=0x%llx (filled: %llu KB, buffered mapping)\n",
							name.c_str(), imageBase, imageSize, filled / 1024);
                        ++mod_count;
                    }
                } else {
                    _aligned_free(host_buf);
                    Logger::Log(true, ConsoleColor::YELLOW,
						"[KDMP] Skip already mapped module: %s Base=0x%llx Size=0x%llx (no overwrite)\n",
                        name.c_str(), imageBase, imageSize);
                }
            }
        }

        current = reinterpret_cast<uint64_t>(ldr.InLoadOrderLinks.Flink);
    }

    if (mod_count >= kMaxModules) {
		Logger::Log(true, ConsoleColor::YELLOW, "[KDMP] Module count reached limit %d; stopping early.\n", kMaxModules);
    }
	Logger::Log(true, ConsoleColor::GREEN, "[KDMP] Completed driver mapping (buffered batch), total %d.\n", mod_count);
}

void PEloader::map_kuser_shared_data() {
	Emu(uc)->alloc(KUSER_SHARED_DATA_SIZE, KUSER_SHARED_DATA_ADDRESS);
	Emu(uc)->write(KUSER_SHARED_DATA_ADDRESS, (VOID*)kdmp.GetVirtualPage(KUSER_SHARED_DATA_ADDRESS), KUSER_SHARED_DATA_SIZE);
	bool data = 0;
	Emu(uc)->write(KUSER_SHARED_DATA_ADDRESS + 0x2d4, &data, sizeof(data));
	Logger::Log(true, ConsoleColor::DARK_GREEN, "KUSER_SHARED_DATA mapped and initialized at 0x%llx \n", KUSER_SHARED_DATA_ADDRESS);
}
void PEloader::InitProcessor() {
	auto emu = Emu(uc);
	SegmentSelector cs = { 0 };
	cs.fields.index = 1;
	emu->cs(cs.all);

	SegmentSelector ds = { 0 };
	ds.fields.index = 2;
	emu->ds(ds.all);

	SegmentSelector ss = { 0 };
	ss.fields.index = 2;
	emu->ss(ss.all);

	SegmentSelector es = { 0 };
	es.fields.index = 2;
	emu->es(es.all);
	uint64_t idtr = 0xfffff8050af9b000;
	Object* idtrObj = new Object("idtr", idtr, 0x1000);
	this->objectList.emplace_back(idtrObj);
	emu->idtr(idtr, 0x0FFF);
	emu->alloc(0x1000, idtr);
	emu->write(idtr, kdmp.GetVirtualPage(idtr), 0x1000);
	/* Init GS Segment */
	uint64_t gsBase = GsBase;
	gsBase = emu->alloc(0x1000, gsBase);
	emu->gs_base(gsBase);
	uint64_t CsBase = 0xfffff80508227900;

	emu->cs(CsBase);
	Object* gsObj = new Object("GS Segment", gsBase, 0x1000);
	emu->write(gsBase, kdmp.GetVirtualPage(gsBase), 0x1000);

	uint64_t kpcrBase;
	uint64_t KPCRCBBase;
	uint64_t kThreadBase;

	kpcrBase = emu->read<uint64_t>(gsBase + 0x18);
	kThreadBase = emu->read<uint64_t>(gsBase + 0x188);
	emu->alloc(0x1000, kThreadBase & ~0xfff, MUC_PROT_ALL);
	emu->write(kThreadBase & ~0xfff, kdmp.GetVirtualPage(kThreadBase & ~0xfff), 0x1000);



	Object* kThreadObj = new Object("KThread", kThreadBase, 0x1000);
	uint64_t currentApcState;
	currentApcState = emu->read<uint64_t>(kThreadBase + 0x98);


	uint64_t KPCRCB;

	FlagRegister eflags = { 0 };
	eflags.fields.id = 1;
	eflags.fields.intf = 1;
	eflags.fields.reserved1 = 1;

	emu->eflags(eflags.all);



	uint64_t cr0 = 0x80050033;
	uint64_t cr2 = 0x29c81264717;
	uint64_t cr3 = 0x1ad000;
	uint64_t cr4 = 0x3506f8;
	uint64_t cr8 = 0xf;



	emu->cr0(cr0);
	emu->cr2(cr2);
	emu->cr3(cr3);
	emu->alloc(0x10000, cr3);
	Object* cr3Obj = new Object("CR3", cr3, 0x1000);
	this->objectList.emplace_back(cr3Obj);
	emu->cr4(cr4);
	emu->cr8(cr8);
	emu->alloc(0x1ad000, 0xfffff0f87c3e0000);
	uint64_t tr = 0x40;
	emu->tr(tr);

	MSRList[0x1D9] = { 0, "DBGCTL_MSR" };
	MSRList[0x122] = { 0, "IA32_TSX_CTRL MSR" };
	MSRList[0x1DB] = { 0, "MSRLASTBRANCH-_FROM_IP_MSR" };
	MSRList[0x680] = { 0, "LastBranchFromIP_MSR" };
	MSRList[0x1c9] = { 0, "MSR_LASTBRANCH_TOS" };
	MSRList[0] = { 0xFFF, "MSR_0_P5_IP_ADDR" };
	MSRList[0xc0000082] = { 0x10000, "MSR_LSTAR" };
	MSRList[0x1B] = { 0xfee00800, "IA32_APIC_BASE" };
}
void PEloader::InsertTailList(
	IN ULONG64 ListHeadAddress,
	IN ULONG64 EntryAddress
)
{
	auto emu = Emu(uc);
	PLIST_ENTRY Blink;

	Blink = emu->read<PLIST_ENTRY>(ListHeadAddress + offsetof(LIST_ENTRY, Blink));


	emu->write(EntryAddress + offsetof(LIST_ENTRY, Flink), &ListHeadAddress, sizeof(ListHeadAddress));


	emu->write(EntryAddress + offsetof(LIST_ENTRY, Blink), &Blink, sizeof(Blink));


	emu->write((uint64_t)Blink + offsetof(LIST_ENTRY, Flink), &EntryAddress, sizeof(EntryAddress));


	emu->write(ListHeadAddress + offsetof(LIST_ENTRY, Blink), &EntryAddress, sizeof(EntryAddress));
}

void PEloader::Init() {
	/* Init Stack */
	uint64_t rsp_MapBase = 0xffff890a9a3c1000;
	auto emu = Emu(uc);
	emu->alloc(0x20000, rsp_MapBase);
	uint64_t Rsp = 0xffff890a9a3c72b8;

	auto driverEnd = peFiles[0]->End;
	auto driverEntry = peFiles[0]->Entry;

	emu->write(Rsp, &driverEnd, sizeof(Rsp));

	/* Init Register */
	printf("RSP: %llx\n", Rsp);
	emu->rsp(Rsp);
	uint64_t Rcx = 0xffff8f8b8b05f000;
	emu->alloc(0x1000, Rcx);
	uint64_t Rdx = 0xffff8f8b89e67000;
	emu->alloc(0x1000, Rdx);
	emu->write(Rdx, kdmp.GetVirtualPage(Rdx), 0x1000);
	const wchar_t* driverName = L"\\Driver\\vgk";



	auto drvObj = std::make_unique<_DRIVER_OBJECT>();
	drvObj->Type = 0x00000004;

	drvObj->Size = 0x150;
	drvObj->Flags = 2;
	drvObj->DriverStart = (void*)peFiles[0]->Entry;
	drvObj->DriverSize = peFiles[0]->Binary->virtual_size();

	drvObj->DriverName.Buffer = (WCHAR*)driverName;
	drvObj->DriverName.Length = lstrlenW(driverName) * sizeof(WCHAR);
	drvObj->DriverName.MaximumLength = 16;

	drvObj->DriverSection = (PVOID)peFiles[0]->LdrEntry;

	uint64_t majorFunctionTable[IRP_MJ_MAXIMUM_FUNCTION + 1] = { 0 };
	majorFunctionTable[IRP_MJ_CREATE] = driverEntry + 1;
	majorFunctionTable[IRP_MJ_READ] = driverEntry + 2;
	majorFunctionTable[IRP_MJ_WRITE] = driverEntry + 3;
	majorFunctionTable[IRP_MJ_DEVICE_CONTROL] = driverEntry + 4;
	majorFunctionTable[IRP_MJ_PNP] = driverEntry + 5;
	majorFunctionTable[IRP_MJ_INTERNAL_DEVICE_CONTROL] = driverEntry + 6;


	uint64_t majorFunctionAddr = Emu(uc)->HeapAlloc(sizeof(majorFunctionTable));
	Emu(uc)->write(majorFunctionAddr, &majorFunctionTable, sizeof(majorFunctionTable));

	drvObj->MajorFunction = (PVOID)majorFunctionAddr;

	const wchar_t* registry = L"\\Registry\\Machine\\SYSTEM\\ControlSet001\\Services\\vgk";
	uint64_t _registry = Emu(uc)->HeapAlloc(lstrlenW(registry) * sizeof(WCHAR));
	Emu(uc)->write(_registry, registry, lstrlenW(registry) * sizeof(WCHAR));

	const wchar_t* HardwareDatabase = L"\\REGISTRY\\MACHINE\\HARDWARE\\DESCRIPTION\\SYSTEM";
	_PRIMITIVE_UNICODE_STRING hwDatabase;
	hwDatabase.Buffer = (WCHAR*)HardwareDatabase;
	hwDatabase.Length = lstrlenW(HardwareDatabase) * sizeof(WCHAR);
	hwDatabase.MaximumLength = 0x5C;

	drvObj->HardwareDatabase = &hwDatabase;

	uint64_t drvObjAddr = 0xffff8f8b8b05fe30;

	emu->write(drvObjAddr, drvObj.get(), sizeof(_DRIVER_OBJECT));
	uint64_t regPathAddr = Rdx;
	USHORT registrySize = lstrlenW(registry) * sizeof(WCHAR);;
	emu->write(regPathAddr + offsetof(UNICODE_STRING, Length), &registrySize, sizeof(registrySize));
	emu->write(regPathAddr + offsetof(UNICODE_STRING, MaximumLength), &registrySize + 10, sizeof(registrySize));
	emu->write(regPathAddr + offsetof(UNICODE_STRING, Buffer), &_registry, sizeof(_registry));

	Logger::Log(true, ConsoleColor::DARK_GREEN, "DriverObject written to Unicorn memory at 0x%llx \n", drvObjAddr);
	emu->rcx(drvObjAddr);
	emu->rdx(regPathAddr);
}

void PEloader::LoadDmp()
{
	std::string path = "mem.dmp";
	kdmp.Parse(path.data());
}

void PEloader::FixImport(uint64_t baseAddr, LIEF::PE::Binary::it_imports imports) {
	int type = 1;
	for (auto & import : imports) {
		std::string dllName = import.name();
		std::transform(dllName.begin(), dllName.end(), dllName.begin(),
			[](unsigned char c) { return std::tolower(c); });

		bool check = false;
		for (int i = 0; i < peFiles.size(); i++)
		{
			if (peFiles[i]->FileName.find(dllName, 0) != std::string::npos)
			{
				type = i;
				check = true;
				break;
			}
		}
		if (check == false)
		{
			type = peFiles.size();
			LoadModule(dllName, type);
		}

		printf("Import DLL: %s\n", dllName.c_str());
		for (auto & entry : import.entries()) {
			std::string funcName = entry.name();
			uint64_t iatAddr = baseAddr + entry.iat_address();
			printf("Import function: %s\n", funcName.c_str());
			try {
				uint64_t funcRva = peFiles[type]->FuncAddr[funcName];
				uint64_t funcAddr = peFiles[type]->Base + peFiles[type]->FuncAddr[funcName];
				printf("Writing function address 0x%llx for %s at IAT 0x%llx\n", funcAddr, funcName.c_str(), iatAddr);
				Emu(uc)->write(iatAddr, &funcAddr, sizeof(funcAddr));
			}
			catch (...)
			{
			}

		}

	}
}

bool PEloader::LoadPE(const std::string path) {
	auto peBinary = LIEF::PE::Parser::parse(path);
	if (!peBinary) {
		std::cerr << "Failed to parse PE binary." << std::endl;
		return false;
	}
	PEfile* pe = new PEfile_t();
	uint64_t peBase = peBinary->imagebase();
	pe->Base = Emu_file_Base;
	pe->Entry = pe->Base + peBinary->optional_header().addressof_entrypoint();
	pe->End = pe->Base + peBinary->virtual_size() - 1;
	pe->memMap = malloc(peBinary->virtual_size());
	peFiles.insert(peFiles.begin(), pe);
	/* Security Cookie */
	LIEF::PE::LoadConfiguration* loadConfig = peBinary->load_configuration();
	uint64_t securityCookie = loadConfig->security_cookie();
	peBinary->patch_address(securityCookie, 0x2);

	auto peSections = peBinary->sections();;

	uint64_t peHeaderSize = peBinary->optional_header().sizeof_headers();
	std::ifstream file(path, std::ios::binary);

	uint64_t image_size = peBinary->virtual_size();

	if (!file.is_open()) {
		std::cerr << "Failed to open file: " << path << std::endl;
		return false;
	}
	file.read(reinterpret_cast<char*>(pe->memMap), peBinary->virtual_size());
	file.close();
	peFiles[0]->Binary = std::move(peBinary);
	peFiles[0]->FileName = path;
	auto imports = peFiles[0]->Binary->imports();
	int page = PAGE_ALIGN(peHeaderSize);
	Emu(uc)->alloc(image_size, pe->Base);
	Emu(uc)->write(pe->Base, pe->memMap, peHeaderSize);
	for (const auto& section : peSections) {
		uint64_t sectionAddress = pe->Base + section.virtual_address();
		uint64_t sectionSize = PAGE_ALIGN(section.virtual_size());
		auto sectionContent = section.content();
		Emu(uc)->write(sectionAddress, sectionContent.data(), sectionContent.size());
	}

	auto ExceptionTable = RtlImageDirectoryEntryToData((PVOID)peFiles[0]->memMap,
		TRUE,
		IMAGE_DIRECTORY_ENTRY_EXCEPTION,
		&peFiles[0]->ExceptionTableSize);
	peFiles[0]->ExceptionTable = peFiles[0]->Base + ((PUCHAR)ExceptionTable - (PUCHAR)peFiles[0]->memMap);

	uint64_t RtlpInvertedFunctionTableList = 0xfffff80508c18088;
	uint64_t imagebase = 0xfffff80508c18090;
	uint64_t imagesizebase = 0xfffff80508c18098;
	uint64_t ExceptionTableSizebase = 0xfffff80508c1809C;
	Emu(uc)->try_write(RtlpInvertedFunctionTableList, &peFiles[0]->ExceptionTable, sizeof(peFiles[0]->ExceptionTable));
	Emu(uc)->try_write(imagebase, &Emu_file_Base, sizeof(Emu_file_Base));
	Emu(uc)->try_write(imagesizebase, &image_size, sizeof(uint32_t));
	Emu(uc)->try_write(ExceptionTableSizebase, &peFiles[0]->ExceptionTableSize, sizeof(uint32_t));
	FixImport(pe->Base, imports);
	return true;
}

void PEloader::LoadModule(const std::string path, int type) {
	auto peBinary = LIEF::PE::Parser::parse(path);
	if (path == "ntoskrnl.exe") {
		int i = 0;
	}
	if (!peBinary) {
		char mpath[MAX_PATH];
		ExpandEnvironmentStringsA("%windir%\\System32\\", mpath, MAX_PATH);

		std::string system32Path(mpath);
		system32Path = system32Path + path;
		if (path == "ntoskrnl.exe") {
			system32Path = "E:\\KDemulator - Copy\\KDemu\\" + path;
		}
		peBinary = LIEF::PE::Parser::parse(system32Path);
		if (!peBinary)
		{

			std::cerr << "Failed to parse PE binary." << std::endl;
			return;
		}
	}

	auto peSections = peBinary->sections();;
	PEfile* pe = new PEfile_t();


	uint64_t peHeaderSize = peBinary->optional_header().sizeof_headers();

	std::ifstream file(path, std::ios::binary);

	if (!file.is_open()) {
		std::cerr << "Failed to open file: " << path << std::endl;
		return;
	}
	pe->memMap = malloc(peBinary->virtual_size());
	file.read(reinterpret_cast<char*>(pe->memMap), peBinary->virtual_size());
	file.close();
	int page = PAGE_ALIGN(peHeaderSize);
	
	for (auto i : peBinary->exported_functions()) {
		pe->FuncRVA[i.address()] = i.name();
		pe->FuncAddr[i.name()] = i.address();
	}
	if (path == "ntoskrnl.exe")
	{
		peBinary->optional_header().imagebase(0xfffff80507e17000);
		pe->Base = peBinary->imagebase();
	}

	if (path == "CI.dll")
	{
		peBinary->optional_header().imagebase(0xfffff80509550000);
		pe->Base = peBinary->imagebase();
	}

	if (path == "cng.sys")
	{
		peBinary->optional_header().imagebase(0xfffff80509640000);
		pe->Base = peBinary->imagebase();
	}

	if (path == "ntoskrnl.exe" || path == "CI.dll" || path == "cng.sys") {

		Emu(uc)->alloc(peBinary->virtual_size(), pe->Base);
		Emu(uc)->write(pe->Base, pe->memMap, peHeaderSize);
		pe->Entry = pe->Base + peBinary->optional_header().addressof_entrypoint();
		pe->End = pe->Base + peBinary->virtual_size();
		peFiles.push_back(pe);
		uint64_t vsize = peBinary->virtual_size();
		
		for (const auto& section : peSections) {
			uint64_t sectionAddress = pe->Base + section.virtual_address();
			uint64_t sectionSize = PAGE_ALIGN(section.virtual_size());
			auto sectionContent = section.content();
			Emu(uc)->write(sectionAddress, sectionContent.data(), sectionContent.size());
		}
		if (path == "ntoskrnl.exe") {
			this->PsLoadedModuleListBase = pe->Base + pe->FuncAddr["PsLoadedModuleList"];
			uint64_t PsLoadedModuleList = this->PsLoadedModuleListBase;
			Emu(uc)->write(this->PsLoadedModuleListBase, &PsLoadedModuleList, sizeof(PsLoadedModuleList));
		}
		int k = (pe->End - pe->Base) / 0x1000;
		for (int i = 0; i < k; i++) {
			auto page = kdmp.GetVirtualPage(pe->Base + i * 0x1000);
			if (page != NULL) {
				Emu(uc)->write(pe->Base + i * 0x1000, kdmp.GetVirtualPage(pe->Base + i * 0x1000), 0x1000);
			}
			else
				Logger::Log(true, ConsoleColor::RED, "Page error : %llx\n", pe->Base + i * 0x1000);
		}
	}
	else {
		return;
		if (pe->Base == 0)
			pe->Base = AllDriverBaseAddr[path];
		if (pe->Base != 0)
			Emu(uc)->alloc(page, pe->Base);
		else
			pe->Base = Emu(uc)->HeapAlloc(page);

		pe->Entry = pe->Base + peBinary->optional_header().addressof_entrypoint();
		pe->End = pe->Entry + peBinary->virtual_size();
		peFiles.push_back(pe);

		Emu(uc)->write(pe->Base, pe->memMap, peHeaderSize);

		for (const auto& section : peSections) {
			uint64_t sectionAddress = pe->Base + section.virtual_address();
			uint64_t sectionSize = PAGE_ALIGN(section.virtual_size());
			auto sectionContent = section.content();

			Emu(uc)->alloc(sectionSize, sectionAddress);

			Emu(uc)->write(sectionAddress, sectionContent.data(), sectionContent.size());
		}
	}
	std::wstring temp;
	ANSIToUnicode(path, temp);

	peFiles[peFiles.size() - 1]->Binary = std::move(peBinary);
	peFiles[peFiles.size() - 1]->FileName = path;
	file.close();
	return;
}