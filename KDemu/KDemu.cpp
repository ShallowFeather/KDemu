#include "LoadPE.hpp"
#include "NtType.hpp"
#include "Emulate.hpp"
#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <cstdint>
#include <windows.h>
#include <mutex>
#include "UnicornEmu.hpp"



void gdbServer(uc_engine* uc, uint64_t entry) {
	HMODULE hDll = LoadLibrary(TEXT("udbserver.dll"));
	if (!hDll) {
		std::cerr << "Failed to load DLL!" << std::endl;
		return;
	}
	udbserver Udbserver = (udbserver)GetProcAddress(hDll, "udbserver");
	if (!Udbserver) {
		std::cerr << "Failed to get function address!" << std::endl;
		FreeLibrary(hDll);
		return;
	}
	Udbserver(uc, 10098, entry);
}

// MOD_TEST
void mainThread() {
	fasttest();
	printf("Unicorn version: %x\n", uc_version(NULL, NULL));
	PEloader& peLoader = PEloader::GetInstance();
	UnicornEmu::open(&peLoader.uc);

	uc_engine* uc = peLoader.uc;
	Emu(uc)->set_cpu_model(UC_CPU_X86_QEMU64);
	Emu(uc)->set_tlb_mode(UC_TLB_VIRTUAL);
	Emu(uc)->ctl(UC_CTL_UC_PAGE_SIZE, 0x100000000);
	char buffer[MAX_PATH];
	uint64_t status_register = 0x400024;

	ThreadInfo_t* ti = reinterpret_cast<ThreadInfo_t*>(malloc(sizeof(ThreadInfo_t)));
	ti->routineContext = 0;
	ti->routineStart = peLoader.ExecuteFromRip;
	ti->uc_ctx = nullptr;
	ti->Event = nullptr;
	ti->handle = GetCurrentThread();
	ti->threadId = GetCurrentThreadId();
	ti->tuc = uc;
	uc_context_alloc(uc, &ti->uc_ctx);
	ti->Event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
	peLoader.waitHandles.push_back(ti->Event);
	ti->id = peLoader.Threads.size();
	peLoader.Threads.push_back(ti);

	DWORD length = GetCurrentDirectoryA(MAX_PATH, buffer);
	std::string ntoskrnl2(buffer);
	std::string cng(buffer);
	std::string fltMgr(buffer);
	std::string vgk(buffer);
	std::string ntdll(buffer);
	std::string halDll(buffer);
	std::string cidll(buffer);

	if (length > 0 && length < MAX_PATH)
	{
		//vgk += "\\vgk_new.sys";
		vgk += "\\EasyAntiCheat_26aa6eb638137d17330be2df98352115.sys";
		Logger::Log(true, ConsoleColor::DARK_GREEN, "Full path: %s \n", ntoskrnl2);
	}
	else {
		std::cerr << "Error getting current directory" << std::endl;
	}

	peLoader.FILE_handle = 0x1000;

	peLoader.GetAllDriverBaseAddresses();

	uc_context_alloc(uc, &peLoader.ucContext);

	Unicorn _uc{};
	bool check = peLoader.LoadPE(vgk);
	if (check == false)
	{
		return;
	}

	peLoader.Init();
	peLoader.InitProcessor();
	peLoader.map_kuser_shared_data();
	peLoader.MapAllDriversFromKdmp();

	uc_hook trace, traces, trace_mem, trace_nt, t;

	Emu(uc)->hook_add(&trace_mem, UC_HOOK_MEM_INVALID, (void*)Unicorn::hook_mem_invalid, ti, 1, 0);
	Emu(uc)->hook_add(&trace_mem, UC_HOOK_INSN_INVALID, (void*)Unicorn::hook_mem_invalid, ti, 1, 0);
	Emu(uc)->hook_add(&intr_hook, UC_HOOK_INTR, (void*)Unicorn::catch_error, nullptr, 1, 0);
	uc_hook h_block;
	//uc_hook_add(uc, &h_block,UC_HOOK_BLOCK,(void*)Unicorn::hook_block_track,NULL,peLoader.peFiles[0]->Base, peLoader.peFiles[0]->End);
	uc_hook h_edge;
	//c_hook_add(uc, &h_edge,UC_HOOK_EDGE_GENERATED,(void*)Unicorn::hook_edge_generated,NULL,peLoader.peFiles[0]->Base, peLoader.peFiles[0]->End);
	//Emu(uc)->hook_add(&t, UC_HOOK_CODE, Unicorn::register_hook, NULL, peLoader.peFiles[0]->Base, peLoader.peFiles[0]->End);
	//Emu(uc)->hook_add(&t, UC_HOOK_CODE, Unicorn::register_hook, NULL, 1,0);
	//Emu(uc)->hook_add(&t, UC_HOOK_CODE, Unicorn::register_hook, NULL, 0xfffff805dc9a154d, 0xfffff805dc9a154d);
	//Emu(uc)->hook_add(&t, UC_HOOK_CODE, Unicorn::register_hook, NULL, 0xfffff805dca8e6f5, 0xfffff805dca8e6f5);
	//Emu(uc)->hook_add(&t, UC_HOOK_CODE, Unicorn::register_hook, NULL, 0xfffff805dca31d56, 0xfffff805dca31d56);
	//Emu(uc)->hook_add(&t, UC_HOOK_CODE, Unicorn::register_hook, NULL, 0xfffff805dca31d80, 0xfffff805dca31d80);
	//Emu(uc)->hook_add(&t, UC_HOOK_CODE, Unicorn::register_hook, NULL, 0xfffff805dca31d82, 0xfffff805dca31d82);
	//Emu(uc)->hook_add(&t, UC_HOOK_CODE, Unicorn::register_hook, NULL, 0xfffff805dca31dd0, 0xfffff805dca31dd0);
	//Emu(uc)->hook_add(&t, UC_HOOK_CODE, Unicorn::register_hook, NULL, 0xfffff805dcabbff9, 0xfffff805dcabbff9);
	//Emu(uc)->hook_add(&t, UC_HOOK_CODE, Unicorn::register_hook, NULL, 0xfffff805dca31c02, 0xfffff805dca31c02);
	//Emu(uc)->hook_add(&t, UC_HOOK_CODE, Unicorn::register_hook, NULL, 0xfffff805dca31c46, 0xfffff805dca31c46);
	//Emu(uc)->hook_add(&t, UC_HOOK_CODE, Unicorn::register_hook, NULL, 0xfffff805dca31c93, 0xfffff805dca31c93);

	auto exports = g_Debugger->ListAllFunctionsByDbgEng("ntoskrnl.exe");

	for (const auto& pair : _uc.NtfuncMap) {
		_uc.hook_Symbol_func(uc, exports, ti, pair.first, pair.second);
	}
	/*for (auto& exporta : exports) {
		if (peLoader.Ntoskrnl_data_Base < exporta.Va && exporta.Va < peLoader.Ntoskrnl_data_End)
		{
			auto Obj = std::make_shared<Object>(exporta.Name, exporta.Va, 0);
			peLoader.objectList.emplace_back(Obj);
		}
	}*/

	ULONG SYM_TAG_FUNCTION = 5;
	ULONG SYM_TAG_PUBLIC_SYMBOL = 10;
	ULONG SYM_TAG_THUNK = 14;
	for (auto& exporta : exports) {

		if (exporta.Tag == SYM_TAG_FUNCTION || exporta.Tag == SYM_TAG_PUBLIC_SYMBOL)
		{

			auto Obj = std::make_shared<Object>(exporta.Name, exporta.Va, 0);
			peLoader.objectList.emplace_back(Obj);
		}

	}


	/*for (const auto& pair : _uc.NtfuncMap) {
		_uc.hook_File_func(uc, "t", pair.first, pair.second);
	}*/
	for (const auto& pair : _uc.CngFuncMap) {
		_uc.hook_File_func(uc, "t", pair.first, pair.second);
	}
	for (const auto& pair : _uc.CiFuncMap) {
		_uc.hook_File_func(uc, "t", pair.first, pair.second);
	}


	bool KdDebuggerNotPresent = 1;
	bool KdDebuggerEnabled = 0;
	for (auto& peFile : peLoader.peFiles)
	{
		if (peFile->FileName == "ntoskrnl.exe")
		{
			uint64_t KdDebuggerNotPresentaddress = peFile->Base + peFile->FuncAddr["KdDebuggerNotPresent"];
			uint64_t KdDebuggerEnabledaddress = peFile->Base + peFile->FuncAddr["KdDebuggerEnabled"];
			peLoader.RtlRaiseStatusBase = peFile->Base + peFile->FuncAddr["RtlRaiseStatus"];
			Emu(uc)->write(KdDebuggerNotPresentaddress, &KdDebuggerNotPresent, sizeof(KdDebuggerNotPresent));
			Emu(uc)->write(KdDebuggerEnabledaddress, &KdDebuggerEnabled, sizeof(KdDebuggerEnabled));
		}

	}
	for (auto object : peLoader.objectList) {
		// MOD_TEST
		// Emu(uc)->hook_add(&t, UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, (void*)Unicorn::hook_access_object, (void*)object, object->address, object->address + object->size);
		Emu(uc)->hook_add(&t, UC_HOOK_CODE, (void*)Unicorn::hook_access_objectH, (void*)object.get(), object->address, object->address + object->size);
	}
	/*for (auto object : peLoader.objectList) {
		Emu(uc)->hook_add(&t, UC_HOOK_MEM_READ, (void*)Unicorn::hook_access_object, (void*)object.get(), object->address, object->address + object->size);
	}*/

	peLoader.ExecuteFromRip = peLoader.peFiles[0]->Entry;

	uc_err err;
	Logger::Log(true, ConsoleColor::DARK_GREEN, "entry: 0x%llx  0%llx \n", peLoader.peFiles[0]->Entry, peLoader.ExecuteFromRip);

	while (true) {
		Emu(uc)->start(peLoader.ExecuteFromRip, peLoader.peFiles[0]->End, 0, 0);
		uint64_t rip = Emu(uc)->rip();
		if (peLoader.peFiles[0]->Base > rip || peLoader.peFiles[0]->End < rip) {
			break;
		}
		if (peLoader.LastException != STATUS_SUCCESS) {

			auto except = peLoader.LastException;
			break;
			Unicorn::seh_Handle(uc);
		}
		else {
			break;
		}
		printf("ExecuteFromRip %llx\n", peLoader.ExecuteFromRip);
	}
	Logger::Log(true, ConsoleColor::DARK_GREEN, "Main thread exited\n");
	DWORD exitCode = 0;
	while (true) {
		for (auto i : peLoader.Threads) {
			if (i->tuc != nullptr && i->id != 0)
			{
				if (GetExitCodeThread(i->handle, &exitCode)) {
					if (exitCode == STILL_ACTIVE) {
					}
					else {
						std::cout << "Thread ended, exit code: " << exitCode << std::endl;
						break;
					}
				}
				else {
					break;
				}
			}
		}

		Sleep(1000);
	}
}

int main(int argc, char** argv, char** envp) {

	// 行程級：一次就好
	SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);

	PROCESS_POWER_THROTTLING_STATE p{};
	p.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
	p.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
	p.StateMask = 0; // 關節流
	SetProcessInformation(GetCurrentProcess(), ProcessPowerThrottling, &p, sizeof(p));


	PEloader& peLoader = PEloader::GetInstance();
	if (!peLoader.LoadDmp()) {
		Logger::Log(true, RED, "Failed to load dump file");
		return EXIT_FAILURE;
	}

	DWORD s = GetCurrentThreadId();
	HANDLE thread = CreateThread(nullptr, 8192, (LPTHREAD_START_ROUTINE)mainThread, 0, 0, nullptr);

	WaitForSingleObject(thread, INFINITE);

	return 0;
}