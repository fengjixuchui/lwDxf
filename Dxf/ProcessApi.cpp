#include "stdafx.h"
#include "ProcessApi.h"


ProcessApi::ProcessApi(LPCWSTR lpClassName, LPCWSTR lpWindowName)
{
	if (hWnd == 0) hWnd = ::FindWindow(lpClassName, lpWindowName);

	if (ProcessId == 0) ::GetWindowThreadProcessId(hWnd, &ProcessId);

	if (hProcess == 0) hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, false, ProcessId);

	
}


ProcessApi::~ProcessApi()
{
}

bool ProcessApi::readMemory(LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize)
{
	HANDLE h = hProcess;
	FARPROC addr = this->ntReadVirtualMemoryAddress;

	DWORD _eax;
	if (addr == NULL) {
		addr = GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtReadVirtualMemory");
		this->ntReadVirtualMemoryAddress = addr;
	}
	__asm {
		push 0
		push nSize
		push lpBuffer
		push lpBaseAddress
		push h
		mov eax,0x3f
		mov edx, addr
		add edx,5
		call edx
		lea edx, _eax
		mov [edx],eax
	}
	if (_eax !=0 ) {
		printf("readMemory [0x%x] fail!\n", (int)lpBaseAddress);
		system("pause");
		return false;
	}
	return true;
}

byte ProcessApi::readByte(int baseAddress)
{
	byte lpBuffer;
	readMemory((LPCVOID)baseAddress, &lpBuffer, sizeof(lpBuffer));
	return lpBuffer;
}

short ProcessApi::readShort(int baseAddress)
{
	short lpBuffer;
	readMemory((LPCVOID)baseAddress, &lpBuffer, sizeof(lpBuffer));
	return lpBuffer;
}

int ProcessApi::readInteger(int baseAddress)
{
	int lpBuffer;
	readMemory((LPCVOID)baseAddress, &lpBuffer, sizeof(lpBuffer));
	return lpBuffer;
}

LONGLONG ProcessApi::readLong(int baseAddress)
{
	LONGLONG lpBuffer;
	readMemory((LPCVOID)baseAddress, &lpBuffer, sizeof(lpBuffer));
	return lpBuffer;
}

float ProcessApi::readFloat(int baseAddress)
{
	float lpBuffer;
	readMemory((LPCVOID)baseAddress, &lpBuffer, sizeof(lpBuffer));
	return lpBuffer;
}

double ProcessApi::readDouble(int baseAddress)
{
	double lpBuffer;
	readMemory((LPCVOID)baseAddress, &lpBuffer, sizeof(lpBuffer));
	return lpBuffer;
}

vector<byte> ProcessApi::readBytes(int baseAddress, int len)
{
	byte * lpBuffer;
	lpBuffer = new byte[len];
	memset(lpBuffer, 0, len);
	readMemory((LPCVOID)baseAddress, lpBuffer, len);
	vector<byte>  result;
	result.resize(len);
	for (int i = 0; i < len; i++)
	{
		result[i] = lpBuffer[i];
	}
	delete[]lpBuffer;
	return result;
}

char* ProcessApi::readString(int baseAddress, int len)
{
	TCHAR *lpBuffer;
	len = len * 2 + 2;
	lpBuffer = new TCHAR[len];
	readMemory((LPCVOID)baseAddress, lpBuffer, len);
	char * str = ToolsApi::unicodeToAnsi(lpBuffer);
	return str;
}

bool ProcessApi::writeMemory(int lpBaseAddress, LPCVOID lpBuffer, int nSize)
{
	SIZE_T lpNumberOfBytesRead;
	if (!WriteProcessMemory(hProcess, (LPVOID)lpBaseAddress, lpBuffer, (SIZE_T)(nSize), &lpNumberOfBytesRead)) {
		printf("写入 %x 内存时失败！\n", lpBaseAddress);
		return false;
	}
	if (lpNumberOfBytesRead != nSize) {
		printf("写入 %x 内存时实际写入的长度与要写入的长度不一致！\n", lpBaseAddress);
		return false;
	}
	return true;
}

bool ProcessApi::writeByte(int lpBaseAddress, byte lpBuffer)
{
	return writeMemory(lpBaseAddress, &lpBuffer, sizeof(lpBuffer));
}

bool ProcessApi::writeShort(int lpBaseAddress, short lpBuffer)
{
	return writeMemory(lpBaseAddress, &lpBuffer, sizeof(lpBuffer));
}

bool ProcessApi::writeInteger(int lpBaseAddress, int lpBuffer)
{
	return writeMemory(lpBaseAddress, &lpBuffer, sizeof(lpBuffer));
}

bool ProcessApi::writeLong(int lpBaseAddress, LONGLONG lpBuffer)
{
	return writeMemory(lpBaseAddress, &lpBuffer, sizeof(lpBuffer));
}

bool ProcessApi::writeFloat(int lpBaseAddress, float lpBuffer)
{
	return writeMemory(lpBaseAddress, &lpBuffer, sizeof(lpBuffer));
}

bool ProcessApi::writeDouble(int lpBaseAddress, double lpBuffer)
{
	return writeMemory(lpBaseAddress, &lpBuffer, sizeof(lpBuffer));
}

bool ProcessApi::writeString(int lpBaseAddress, LPCWSTR lpBuffer)
{
	int len = wcslen(lpBuffer) * 2 + 2;
	return writeMemory(lpBaseAddress, (LPCVOID)lpBuffer, len);
}

bool ProcessApi::writeBytes(int lpBaseAddress, vector<byte> bytes)
{
	int size = bytes.size();
	byte *lpBuffer = new byte[size];
	for (int i = 0; i < size; i++)
	{
		lpBuffer[i] = bytes[i];
	}
	bool result = writeMemory(lpBaseAddress, lpBuffer, size);
	delete[]lpBuffer;
	return result;
}

int ProcessApi::allocMemory(const char *name, int size)
{
	MemoryStruct memoryStruct = alloc_memory_map_box[name];
	if (memoryStruct.size == size) {
		return memoryStruct.first_addr;
	}
	else {
		memoryStruct.first_addr = (int)VirtualAllocEx(hProcess, NULL, (SIZE_T)size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!memoryStruct.first_addr) {
			printf("%s 分配内存失败!\n", name);
			return -1;
		}
		memoryStruct.size = size;
		alloc_memory_map_box[name] = memoryStruct;
		return memoryStruct.first_addr;
	}
}

bool ProcessApi::freeMemory(const char *name)
{
	MemoryStruct memoryStruct = alloc_memory_map_box[name];
	if (VirtualFreeEx(hProcess, (LPVOID)memoryStruct.first_addr, 0, MEM_RELEASE))
	{
		printf("%s 释放成功!\n", name);
		return true;
	}
	else {
		printf("%s 释放失败!\n", name);
		return false;
	}
}

void ProcessApi::freeAllAlloc()
{
	map<const char*, MemoryStruct > ::iterator mapi;
	mapi = alloc_memory_map_box.begin();
	MemoryStruct tmp;
	while (mapi != alloc_memory_map_box.end())
	{
		tmp = mapi->second;
		VirtualFreeEx(hProcess, (LPVOID)tmp.first_addr, 0, MEM_RELEASE);
		mapi++;
	}
}

bool ProcessApi::createThread(int lpStartAddress, LPVOID lpParameter)
{
	if (!CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpStartAddress, lpParameter, 0, NULL, 0)) {
		printf("创建线程失败！");
		return false;
	}
	return true;
}

int ProcessApi::injectDll(LPCTSTR dll_path)
{
	int addr = allocMemory(__FUNCTION__, MAX_PATH);
	int fun_add = ToolsApi::getWinApiAddr("kernel32.dll", "LoadLibraryW");
	bool result = this->writeMemory((int)addr, (PVOID)dll_path, (_tcslen(dll_path) + 1) * sizeof(dll_path[0]));
	if (result == false) {
		printf("InjectDll Fail!\n");
		system("pause");
		return 0;
	}
	if (createThread(fun_add, (LPVOID)addr)) {
		printf("注入成功！\n");
		return addr;
	}
	else {
		printf("创建线程失败！\n");
		system("pause");
	}
	return 0;
}