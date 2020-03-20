#define _CRT_SECURE_NO_WARNINGS

#include<stdio.h>
#include<stdlib.h>
#include<windows.h>
#include<tchar.h>
#include<stdint.h>
#include<vector>
#include<string>

typedef struct Section
{
	char Name[8];
	int VirtualSize;
	int RVA;
	int SizeOfRawData;
	int PoitnerToRawData;
	int POinterToRelocations;
	int PointerToLineNumber;
	WORD NumberOfRelocations;
	WORD NumberOfLineNumbers;
	int Characteristics;
	int TempOffset;
}Section;

typedef struct RelocData
{
	int TypeRva;
	int i32LoadOffset;
	int i32MemoryOffset;
	int i32FileOffset;
}RelocData;


#define BUF_SIZE 1024
#define PIPE_NAME _T("\\\\.\\pipe\\FLProtectionPipe")

#pragma comment(lib, "ntdll.lib")

EXTERN_C NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtGetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtSetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);
EXTERN_C NTSTATUS NTAPI NtResumeThread(HANDLE, PULONG);
EXTERN_C NTSTATUS NTAPI NtProtectVirtualMemory(HANDLE, PVOID, PULONG, ULONG, PULONG);

IMAGE_DOS_HEADER* cDosHeader = NULL;
IMAGE_NT_HEADERS32* cNtHeader = NULL;
IMAGE_SECTION_HEADER* cTextHeader = NULL;
IMAGE_SECTION_HEADER* pSecH = NULL;
char* pBuf = NULL;
char* pBufReloc = NULL;
char* buf = NULL;
std::vector<std::pair<int, int> > vctSectionRva;
char cName[0x50] = { 0 };

int CommToClient(HANDLE);

int main(int argc, char** argv)
{
	HANDLE hPipe;

	while (1)
	{
		hPipe = CreateNamedPipe(PIPE_NAME, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, BUF_SIZE, BUF_SIZE, 2000, NULL);

		if (hPipe == INVALID_HANDLE_VALUE)
		{
			printf("CreatePipe Failed\n");
			return -1;
		}

		BOOL bIsSuccess = false;
		bIsSuccess = ConnectNamedPipe(hPipe, NULL);// ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);


		if (bIsSuccess)
			CommToClient(hPipe);
		else
			CloseHandle(hPipe);
	}

	return 1;
}

int CommToClient(HANDLE hPipe)
{
	DWORD dwBytesWritten = BUF_SIZE;
	DWORD dwBytesRead = BUF_SIZE;

	char readDataBuf[BUF_SIZE] = { 0 };

	//for(int i = 0; i < 2; i++)
	//{

	ReadFile(hPipe, readDataBuf, BUF_SIZE * sizeof(char), &dwBytesRead, NULL);//

	if (dwBytesRead != 0)
	{
		int32_t i32BaseAddress = 0;
		int32_t i32GetProcessId = 0;
		int32_t i32OEP = 0;
		int32_t i32FileBaseAddress = 0;


		memcpy((void*)&i32BaseAddress, (void*)&readDataBuf, 4);
		memcpy((void*)&i32GetProcessId, (void*)&readDataBuf[4], 4);
		memcpy((void*)&i32OEP, (void*)&readDataBuf[8], 4);
		memcpy((void*)&i32FileBaseAddress, (void*)&readDataBuf[0xc], 4);

		int i32cnt = 0x1c;
		int i32Namecnt = 0;
		memset(cName, '\x0', sizeof(cName));
		while (1)
		{
			if (readDataBuf[i32cnt] == '\x0')
			{
				break;
			}
			cName[i32Namecnt++] = readDataBuf[i32cnt];
			i32cnt += 2;
		}

		if (!strcmp(cName, "MainDOriginal.exe"))
			return 1;
		/*
		if (!strcmp(cName, "RavidSecurityD.dll"))
		{
			DisconnectNamedPipe(hPipe);
			CloseHandle(hPipe);
			return 1;
		}*/
		printf("%x %x\n %s\n", i32BaseAddress, i32GetProcessId, cName);

		cDosHeader = new IMAGE_DOS_HEADER;
		cNtHeader = new IMAGE_NT_HEADERS32;
		cTextHeader = new IMAGE_SECTION_HEADER;

		memset(cDosHeader, '\x0', sizeof(IMAGE_DOS_HEADER));
		memset(cNtHeader, '\x0', sizeof(IMAGE_NT_HEADERS32));
		memset(cTextHeader, '\x0', sizeof(IMAGE_SECTION_HEADER));


		int32_t i32GetNumber = 0;
		HANDLE hGetHandle = OpenProcess(MAXIMUM_ALLOWED, TRUE, i32GetProcessId);

		int32_t i32OffsetNtHeader = 0;

		int32_t i32OffsetToText = 0;

		ReadProcessMemory((HANDLE)hGetHandle, (PVOID)i32BaseAddress, cDosHeader, sizeof(IMAGE_DOS_HEADER), (PULONG)i32GetNumber);

		memcpy((void*)&i32OffsetNtHeader, (void*)&cDosHeader->e_lfanew, 4);

		ReadProcessMemory((HANDLE)hGetHandle, (PVOID)(i32BaseAddress + i32OffsetNtHeader), cNtHeader, sizeof(IMAGE_NT_HEADERS32), (PULONG)i32GetNumber);

		int32_t i32RelocRVA = 0;
		int32_t i32RelocPointerToRawData = 0;
		int32_t i32RelocSizeofRawData = 0;
		int32_t i32RelocVirtualSize = 0;

		int32_t i32VirtualSizeText = 0;
		int32_t i32PointerToRawData = 0;
		int32_t i32RVA = 0;
		int32_t i32SizeOfRawData = 0;
		int32_t i32FileTextRva = 0;
		int32_t i32SizeOfCode = cNtHeader->OptionalHeader.SizeOfCode;
		int32_t i32TextSection = 0;
		int32_t i32CfgSection = -2;
		int32_t i32cfgRVA = 0;
		int32_t i32cfgPointerToRawData = 0;
		int32_t i32cfgSizeofRawData = 0;

		for (int i = 0; i < cNtHeader->FileHeader.NumberOfSections; i++)
		{
			int32_t i32SectionOffset = (int32_t)(cDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
			IMAGE_SECTION_HEADER* pSecH = new IMAGE_SECTION_HEADER;

			ReadProcessMemory((HANDLE)hGetHandle, (PVOID)(i32BaseAddress + i32SectionOffset), pSecH, sizeof(IMAGE_SECTION_HEADER), (PULONG)i32GetNumber);

			vctSectionRva.push_back({ pSecH->VirtualAddress , pSecH->PointerToRawData });

			if (!strcmp((const char*)pSecH->Name, ".text"))
			{
				i32PointerToRawData = pSecH->PointerToRawData;
				i32RVA = pSecH->VirtualAddress;
				i32SizeOfRawData = pSecH->SizeOfRawData;

				i32VirtualSizeText = pSecH->Misc.VirtualSize;
				i32FileTextRva = cDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER));
				i32FileTextRva += 0xc;
				i32TextSection = i;
				//i32TextSizeOfCode=
			}
			else if (!strcmp((const char*)pSecH->Name, ".reloc"))
			{
				i32RelocRVA = pSecH->VirtualAddress;
				i32RelocPointerToRawData = pSecH->PointerToRawData;
				i32RelocSizeofRawData = pSecH->SizeOfRawData;
				i32RelocVirtualSize = pSecH->Misc.VirtualSize;
			}
			else if (!strcmp((const char*)pSecH->Name, ".00cfg"))
			{
				i32cfgRVA = pSecH->VirtualAddress;
				i32cfgPointerToRawData = pSecH->PointerToRawData;
				i32cfgSizeofRawData = pSecH->SizeOfRawData;
				i32CfgSection = i;
			}
			delete[] pSecH;
		}


		int32_t i32SizeOfImage = cNtHeader->OptionalHeader.SizeOfImage;

		int32_t i32SizeOfImageTemp = i32SizeOfImage - i32RVA;

		pBuf = new char[i32SizeOfImageTemp];
		memset(pBuf, '\x00', sizeof(char) * i32SizeOfImageTemp);
		ReadProcessMemory((HANDLE)hGetHandle, (PVOID)(i32BaseAddress + i32RVA), pBuf, i32SizeOfImageTemp, (PULONG)i32GetNumber);

		//i32VirtualSizeText = 0x1000 + (i32VirtualSizeText & 0xfffff000);
		
		for (int i = 0; i < i32SizeOfCode; i++)
		{
			pBuf[i] = ~pBuf[i];
		}

		pBufReloc = new char[i32RelocVirtualSize];
		memset(pBufReloc, '\x00', sizeof(char) * i32RelocVirtualSize);
		ReadProcessMemory((HANDLE)hGetHandle, (PVOID)(i32BaseAddress + i32RelocRVA), pBufReloc, i32RelocVirtualSize, NULL);

		int32_t i32RelocCnt = 0;


		FILE* fp = fopen(cName, "rb");
		size_t stSize = 0;
		if (fp)
		{
			fseek(fp, 0, SEEK_END);//
			stSize = ftell(fp);
			buf = new char[stSize];
			memset(buf, '\x00', sizeof(char) * stSize);
			fseek(fp, 0, SEEK_SET);
			fread(buf, stSize, 1, fp);

			fclose(fp);
		}

		std::vector<RelocData > vctCheck;
		vctCheck.clear();
		while (1)
		{
			int32_t i32RVAofBlock = 0;
			int32_t i32SizeofBlock = 0;
			memcpy((void*)&i32RVAofBlock, (void*)&pBufReloc[i32RelocCnt], 4);
			i32RelocCnt += 4;
			memcpy((void*)&i32SizeofBlock, (void*)&pBufReloc[i32RelocCnt], 4);
			i32RelocCnt += 4;
			if (i32SizeofBlock == 0)
				break;

			int32_t i32SecionIdx = -1;

			for (int i = 0; i < vctSectionRva.size() - 1; i++)
			{
				int32_t i32FromRva = vctSectionRva[i].first;
				int32_t i32ToRva = vctSectionRva[i + 1].first;

				if (i32FromRva <= i32RVAofBlock && i32RVAofBlock < i32ToRva)
				{
					i32SecionIdx = i;
					break;
				}
			}
			int32_t i32BaseRelocationSize = i32SizeofBlock - 8;
			/*		if ((i32TextSection != i32SecionIdx) && (i32SecionIdx != i32CfgSection))
					{
						i32RelocCnt += i32BaseRelocationSize;
						continue;
					}*/
			for (int i = 0; i < i32BaseRelocationSize; i += 2)
			{
				int32_t i32Delta = i32BaseAddress - i32FileBaseAddress;
			/*	if (i32Delta > i32FileBaseAddress)
					i32Delta = i32Delta - i32FileBaseAddress;
				else
					i32Delta = i32FileBaseAddress - i32Delta;*/
				WORD TypeRva = 0;
				int32_t i32FileOffset = i32RVAofBlock - vctSectionRva[i32SecionIdx].first;

				memcpy((void*)&TypeRva, (void*)&pBufReloc[i32RelocCnt], 2);
				if (TypeRva == 0)
				{
					i32RelocCnt += 2;
					continue;
				}

				TypeRva &= 0x0fff;
				i32FileOffset += TypeRva + vctSectionRva[i32SecionIdx].second;

				int32_t i32MemoryOffset = 0;


				int32_t i32LoadOffset = 0;
				i32LoadOffset = TypeRva + i32RVAofBlock - i32RVA;

				/*	if (i32LoadOffset <= i32SizeOfCode)
					{
						for (int j = 0;j < 4;j++)
						{
							pBuf[i32LoadOffset + j] = ~pBuf[i32LoadOffset + j];
						}
					}*/

				memcpy((void*)&i32MemoryOffset, (void*)&buf[i32FileOffset], 4);

				i32MemoryOffset += i32Delta;

				vctCheck.push_back({ TypeRva,i32LoadOffset,i32MemoryOffset,i32FileOffset });
				//i32FileOffset += i32BaseAddress;
				//if (TypeRva + i32RVAofBlock - vctSectionRva[i32SecionIdx].first < i32SizeOfCode)
				memcpy((void*)&pBuf[i32LoadOffset], (void*)&i32MemoryOffset, 4);

				i32RelocCnt += 2;
			}
		}

		int32_t i32Result = WriteProcessMemory((HANDLE)hGetHandle, (PVOID)(i32BaseAddress + i32RVA), pBuf, i32SizeOfImageTemp, NULL);

		if (!i32Result)
		{
			printf("error code: %d \n", GetLastError());
			return 1;
		}



		////int32_t i32SetPermission = (int32_t)VirtualAllocEx(hGetHandle, (PVOID)(i32BaseAddress-0x1000), 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		//DWORD dwOld = 0;

		//NtProtectVirtualMemory(hGetHandle, (PVOID)(i32BaseAddress-0x1000),(PULONG)0x1000, PAGE_READWRITE, &dwOld);

		///*if(!i32SetPermission)
		//{
		//	printf("error code: %d \n", GetLastError());
		//	return 1;
		//}*/

		
		int32_t i32CheckFinishEncoding = cNtHeader->OptionalHeader.AddressOfEntryPoint + 0x260;

		int32_t i32FinshEncoding = 1;

		i32Result = WriteProcessMemory((HANDLE)hGetHandle, (PVOID)(i32BaseAddress + i32CheckFinishEncoding), (void*)&i32FinshEncoding, 4, NULL);

		if (!i32Result)//
		{
			printf("error code: %d \n", GetLastError());
			return 1;
		}

		//int32_t i32EntryPointIdxAddress = cDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + 0x10;

		//char cOEP[4] = { 0 };
		//memcpy((void*)&cOEP, (void*)&i32OEP, 4);

		//i32Result = WriteProcessMemory((HANDLE)hGetHandle, (PVOID)(i32BaseAddress + i32EntryPointIdxAddress), cOEP, 4, NULL);

		//if(!i32Result)
		//{
		//	printf("error code: %d \n", GetLastError());
		//	return 1;
		//}
		//

		vctSectionRva.clear();
		dwBytesRead = 0;
		if (pBuf != NULL)
			delete pBuf;
		if (pBufReloc != NULL)
			delete pBufReloc;
		if (buf != NULL)
			delete buf;
	}

	//Sleep(5);
	DisconnectNamedPipe(hPipe);
	CloseHandle(hPipe);
	return 1;
}