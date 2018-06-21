#pragma once
struct MemoryStruct
{
	int first_addr;
	int size;
};
class ProcessApi
{
public:
	ProcessApi(LPCWSTR lpClassName = L"���³�����ʿ", LPCWSTR lpWindowName = L"���³�����ʿ");

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

	/*д�ڴ�*/
	bool writeMemory(int lpBaseAddress, LPCVOID lpBuffer, int nSize);
	/*д�ֽ���*/
	bool writeByte(int lpBaseAddress, byte lpBuffer);
	/*д������*/
	bool writeShort(int lpBaseAddress, short lpBuffer);
	/*д����*/
	bool writeInteger(int lpBaseAddress, int lpBuffer);
	/*д������*/
	bool writeLong(int lpBaseAddress, LONGLONG lpBuffer);
	/*д��������*/
	bool writeFloat(int lpBaseAddress, float lpBuffer);
	/*д˫������*/
	bool writeDouble(int lpBaseAddress, double lpBuffer);
	/*д�ַ���*/
	bool writeString(int lpBaseAddress, LPCWSTR lpBuffer);
	/*д�ֽڼ�*/
	bool writeBytes(int lpBaseAddress, vector<byte> bytes);
	/*�����ڴ�*/
	int allocMemory(const char * name, int size);
	/*�ͷ��ڴ�*/
	bool freeMemory(const char * name);
	/*�ͷ�����������ڴ�*/
	void freeAllAlloc();
	/*����Զ���߳�*/
	bool createThread(int lpStartAddress, LPVOID lpParameter = NULL);
	/*ע��DLL*/
	int injectDll(LPCTSTR dll_path);

	HWND hWnd = NULL;

	HANDLE hProcess = NULL;

	DWORD ProcessId = NULL;

	FARPROC ntReadVirtualMemoryAddress = NULL;

	map<const char*, MemoryStruct>alloc_memory_map_box;
};

