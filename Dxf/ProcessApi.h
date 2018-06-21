#pragma once
struct MemoryStruct
{
	int first_addr;
	int size;
};
class ProcessApi
{
public:
	ProcessApi(LPCWSTR lpClassName = L"地下城与勇士", LPCWSTR lpWindowName = L"地下城与勇士");

	~ProcessApi();

	bool readMemory(LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize);

	byte readByte(int lpBaseAddress);

	short readShort(int baseAddress);

	int readInteger(int baseAddress);

	LONGLONG readLong(int lpBaseAddress);

	float readFloat(int baseAddress);

	double readDouble(int baseAddress);

	vector<byte> readBytes(int lpBaseAddress, int len);

	char * readString(int lpBaseAddress, int len);

	/*写内存*/
	bool writeMemory(int lpBaseAddress, LPCVOID lpBuffer, int nSize);
	/*写字节型*/
	bool writeByte(int lpBaseAddress, byte lpBuffer);
	/*写短整型*/
	bool writeShort(int lpBaseAddress, short lpBuffer);
	/*写整型*/
	bool writeInteger(int lpBaseAddress, int lpBuffer);
	/*写长整型*/
	bool writeLong(int lpBaseAddress, LONGLONG lpBuffer);
	/*写单浮点型*/
	bool writeFloat(int lpBaseAddress, float lpBuffer);
	/*写双浮点型*/
	bool writeDouble(int lpBaseAddress, double lpBuffer);
	/*写字符串*/
	bool writeString(int lpBaseAddress, LPCWSTR lpBuffer);
	/*写字节集*/
	bool writeBytes(int lpBaseAddress, vector<byte> bytes);
	/*申请内存*/
	int allocMemory(const char * name, int size);
	/*释放内存*/
	bool freeMemory(const char * name);
	/*释放所有申请的内存*/
	void freeAllAlloc();
	/*创建远程线程*/
	bool createThread(int lpStartAddress, LPVOID lpParameter = NULL);
	/*注入DLL*/
	int injectDll(LPCTSTR dll_path);

	HWND hWnd = NULL;

	HANDLE hProcess = NULL;

	DWORD ProcessId = NULL;

	FARPROC ntReadVirtualMemoryAddress = NULL;

	map<const char*, MemoryStruct>alloc_memory_map_box;
};

