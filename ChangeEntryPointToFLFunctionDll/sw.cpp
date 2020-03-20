#define _CRT_SECURE_NO_WARNINGS

#include<stdio.h>
#include<string>
#include<Windows.h>
#include<vector>


std::vector<std::pair<int, std::pair<int, int > > > vctParseRelocation;
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


/*
void Decrypt(int Raw, int VA, int PointerToRawData, int Size)
{
	int* BaseAddress = FindMemoryBaseAddress(L"TestFunctionFixed.exe");

	int Start = Raw + VA - PointerToRawData;
	int From = Start + Size;

	for(int i = Start; i < From; i++)
	{
		BaseAddress[i] ^= 7;
	}
}
*/

int main(int argc, char* argv[])
{
	if(argc != 3)
	{
		printf("FLProtection.exe Source Destion");
		return 1;
	}

	char pNameSrc[0x100] = { 0 };
	char pNameDes[0x100] = { 0 };

	strcpy(pNameSrc, argv[1]);
	strcpy(pNameDes, argv[2]);

	FILE* fp = fopen(pNameSrc, "rb");//

	if(fp)
	{
		fseek(fp, 0, SEEK_END);//
		size_t stSize = ftell(fp);

		int i32FLSize = 0x1000;

		char* buf = new char[stSize + i32FLSize];

		fseek(fp, 0, SEEK_SET);
		fread(buf, stSize, 1, fp);

		fclose(fp);

		PIMAGE_DOS_HEADER pDosH;
		PIMAGE_NT_HEADERS pNtH;
		PIMAGE_SECTION_HEADER pSecH;

		pDosH = (PIMAGE_DOS_HEADER)buf;
		pNtH = (PIMAGE_NT_HEADERS)((LPBYTE)buf + pDosH->e_lfanew);

		if(pNtH->Signature != 0x4550)
		{
			printf("윈도우 실행 파일이 아닙니다.\n");

			return 1;
		}

		fp = fopen(pNameDes, "wb");
		fseek(fp, 0, SEEK_SET);

		int i32FileBaseAddress = pNtH->OptionalHeader.ImageBase;
		int i32EntryPoint = pNtH->OptionalHeader.AddressOfEntryPoint;
		int i32PointerToRawData = 0;
		int i32RVA = 0;
		int i32SizeOfRawData = 0;
		int i32SizeOfCode = pNtH->OptionalHeader.SizeOfCode;
		int i32SizeOfImage = pNtH->OptionalHeader.SizeOfImage;
		int i32TextSizeOfCode = 0;
		int i32FileEntryPointAddress = 0;
		int i32TextSection = 0;

		int i32cfgRVA = 0;
		int i32cfgPointerToRawData = 0;
		int i32cfgSizeofRawData = 0;
		int i32cfgSection = 0;

		int i32RelocRVA = 0;
		int i32RelocPointerToRawData = 0;
		int i32RelocSizeofRawData = 0;
		int i32FileTextRva = 0;

		std::vector< Section> vctSection;

		int* pModifiedTextCharacteristics = (int*)0xe0000060;
		int i32FLStart = pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS);
		i32FileEntryPointAddress = pDosH->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + 0x10;

		int i32Start = 0;
		int OriginalImageOfSize = i32SizeOfImage;

		int32_t i32RdataSection = 0;

		for(int i = 0; i < pNtH->FileHeader.NumberOfSections; i++)
		{
			pSecH = (PIMAGE_SECTION_HEADER)((LPBYTE)buf + pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));

			Section Temp;
			int i32SectionParse = pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER));

			int i32OrigialSize = 0;

			memcpy((void*)&i32OrigialSize, (void*)&buf[i32SectionParse + 0x10], 4);

			if(i == pNtH->FileHeader.NumberOfSections - 1)
			{
				i32Start = pSecH->SizeOfRawData + pSecH->PointerToRawData;
				//i32Start /= 4;

				i32OrigialSize += i32FLSize;
				memcpy((void*)&buf[i32SectionParse + 0x10], (void*)&i32OrigialSize, 4);

				int32_t i32Original = 0;
				memcpy((void*)&i32Original, (void*)&buf[i32SectionParse + 0x8], 4);

				i32Original &= 0xfffff000;

				i32Original += 0x2000;
				memcpy((void*)&buf[i32SectionParse + 0x8], (void*)&i32Original, 4);


			}

			Temp.PoitnerToRawData = pSecH->PointerToRawData;
			Temp.RVA = pSecH->VirtualAddress;
			Temp.SizeOfRawData = pSecH->SizeOfRawData;
			strcpy(Temp.Name, (const char*)pSecH->Name);
			vctSection.push_back(Temp);

			memcpy((void*)&pSecH->Characteristics, (void*)&pModifiedTextCharacteristics, 4);
			i32FLStart += sizeof(IMAGE_SECTION_HEADER);

			if(!strcmp((const char*)pSecH->Name, ".text"))
			{
				i32PointerToRawData = pSecH->PointerToRawData;
				i32RVA = pSecH->VirtualAddress;
				i32SizeOfRawData = pSecH->SizeOfRawData;
				i32FileTextRva = pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER));
				i32FileTextRva += 0xc;
				i32TextSection = i;
				//i32TextSizeOfCode=
			}
			else if(!strcmp((const char*)pSecH->Name, ".reloc"))
			{
				i32RelocRVA = pSecH->VirtualAddress;
				i32RelocPointerToRawData = pSecH->PointerToRawData;
				i32RelocSizeofRawData = pSecH->SizeOfRawData;
			}
			else if(!strcmp((const char*)pSecH->Name, ".00cfg"))
			{
				i32cfgRVA = pSecH->VirtualAddress;
				i32cfgPointerToRawData = pSecH->PointerToRawData;
				i32cfgSizeofRawData = pSecH->SizeOfRawData;
				i32cfgSection = i;
			}
			else if(!strcmp((const char*)pSecH->Name, ".rdata"))
			{
				i32RdataSection = i;
			}
		}

		int i32RollBackEntryPoint = i32RelocRVA + i32Start - i32RelocPointerToRawData;

		int* ModifiedSizeOfImage = (int*)(pNtH->OptionalHeader.SizeOfImage + i32FLSize);
		int* ModifiedEntryPoint = (int*)(i32RelocRVA + i32Start - i32RelocPointerToRawData + 0x10);
		WORD* NumberOfSection = (WORD*)(pNtH->FileHeader.NumberOfSections);

		memcpy((void*)&pNtH->OptionalHeader.SizeOfImage, (void*)&ModifiedSizeOfImage, 4);
		memcpy((void*)&pNtH->OptionalHeader.AddressOfEntryPoint, (void*)&ModifiedEntryPoint, 4);
		memcpy((void*)&pNtH->FileHeader.NumberOfSections, (void*)&NumberOfSection, 2);

		int i32stSizeCnt = 0x10;

		buf[stSize + i32stSizeCnt++] = '\x90';
		buf[stSize + i32stSizeCnt++] = '\x81';
		buf[stSize + i32stSizeCnt++] = '\xc1';
		buf[stSize + i32stSizeCnt++] = '\x60';
		buf[stSize + i32stSizeCnt++] = '\x02';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';// add ecx,0x270

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x09';//mov ecx,dword ptr[ecx]

		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xf9';
		buf[stSize + i32stSizeCnt++] = '\x01';// cmp ecx, 1



		int i32AlreadyDecoding = i32stSizeCnt + i32RollBackEntryPoint;
		int i32FLfunctionToEntryPointDecoding = i32EntryPoint - i32AlreadyDecoding - 6;// -3;

		char cFLfunctionToEntryPointDecoding[4] = { 0, };

		memcpy((void*)&cFLfunctionToEntryPointDecoding, (void*)&i32FLfunctionToEntryPointDecoding, 4);

		buf[stSize + i32stSizeCnt++] = '\x0f';
		buf[stSize + i32stSizeCnt++] = '\x83';

		buf[stSize + i32stSizeCnt++] = cFLfunctionToEntryPointDecoding[0];
		buf[stSize + i32stSizeCnt++] = cFLfunctionToEntryPointDecoding[1];
		buf[stSize + i32stSizeCnt++] = cFLfunctionToEntryPointDecoding[2];
		buf[stSize + i32stSizeCnt++] = cFLfunctionToEntryPointDecoding[3];

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\xcf';

		buf[stSize + i32stSizeCnt++] = '\x60';


		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\xf1';

		bool bCheckExeOrDLL = FALSE;

		if((pNtH->FileHeader.Characteristics & 0xf000) == 0x2000)
		{
			bCheckExeOrDLL = true;
		}
		if(bCheckExeOrDLL == true)
		{
			buf[stSize + i32stSizeCnt++] = '\x81';
			buf[stSize + i32stSizeCnt++] = '\xc1';
			buf[stSize + i32stSizeCnt++] = '\x54';
			buf[stSize + i32stSizeCnt++] = '\x02';
			buf[stSize + i32stSizeCnt++] = '\x0';
			buf[stSize + i32stSizeCnt++] = '\x0';

			buf[stSize + i32stSizeCnt++] = '\x89';
			buf[stSize + i32stSizeCnt++] = '\x11';

			buf[stSize + i32stSizeCnt++] = '\x81';
			buf[stSize + i32stSizeCnt++] = '\xc1';
			buf[stSize + i32stSizeCnt++] = '\x8';
			buf[stSize + i32stSizeCnt++] = '\x0';
			buf[stSize + i32stSizeCnt++] = '\x0';
			buf[stSize + i32stSizeCnt++] = '\x0';
		}
		else
		{
			buf[stSize + i32stSizeCnt++] = '\x81';
			buf[stSize + i32stSizeCnt++] = '\xc1';
			buf[stSize + i32stSizeCnt++] = '\x5c';
			buf[stSize + i32stSizeCnt++] = '\x02';
			buf[stSize + i32stSizeCnt++] = '\x0';
			buf[stSize + i32stSizeCnt++] = '\x0';

		}
		char cOEP[4] = { 0 };
		memcpy((void*)&cOEP, (void*)&i32EntryPoint, 4);

		buf[stSize + i32stSizeCnt++] = '\xbf';
		buf[stSize + i32stSizeCnt++] = cOEP[0];
		buf[stSize + i32stSizeCnt++] = cOEP[1];
		buf[stSize + i32stSizeCnt++] = cOEP[2];
		buf[stSize + i32stSizeCnt++] = cOEP[3];

		buf[stSize + i32stSizeCnt++] = '\x89';
		buf[stSize + i32stSizeCnt++] = '\x39';


		char cImageBase[4] = { 0 };
		memcpy((void*)&cImageBase, (void*)&pNtH->OptionalHeader.ImageBase, 4);

		buf[stSize + i32stSizeCnt++] = '\x81';
		buf[stSize + i32stSizeCnt++] = '\xc1';
		buf[stSize + i32stSizeCnt++] = '\x04';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';

		buf[stSize + i32stSizeCnt++] = '\xbf';
		buf[stSize + i32stSizeCnt++] = cImageBase[0];
		buf[stSize + i32stSizeCnt++] = cImageBase[1];
		buf[stSize + i32stSizeCnt++] = cImageBase[2];
		buf[stSize + i32stSizeCnt++] = cImageBase[3];

		buf[stSize + i32stSizeCnt++] = '\x89';
		buf[stSize + i32stSizeCnt++] = '\x39';

		/*
		buf[stSize + i32stSizeCnt++] = '\x6a';
		buf[stSize + i32stSizeCnt++] = '\x00';

		buf[stSize + i32stSizeCnt++] = '\x68';
		buf[stSize + i32stSizeCnt++] = '\x4c';
		buf[stSize + i32stSizeCnt++] = '\x00';
		buf[stSize + i32stSizeCnt++] = '\x4c';
		buf[stSize + i32stSizeCnt++] = '\x00';

		buf[stSize + i32stSizeCnt++] = '\x68';
		buf[stSize + i32stSizeCnt++] = '\x2e';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x44';
		buf[stSize + i32stSizeCnt++] = '\x0';

		buf[stSize + i32stSizeCnt++] = '\x68';
		buf[stSize + i32stSizeCnt++] = '\x33';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x32';
		buf[stSize + i32stSizeCnt++] = '\x0';

		buf[stSize + i32stSizeCnt++] = '\x68';
		buf[stSize + i32stSizeCnt++] = '\x45';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x4c';
		buf[stSize + i32stSizeCnt++] = '\x0';

		buf[stSize + i32stSizeCnt++] = '\x68';
		buf[stSize + i32stSizeCnt++] = '\x52';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x4e';
		buf[stSize + i32stSizeCnt++] = '\x0';

		buf[stSize + i32stSizeCnt++] = '\x68';
		buf[stSize + i32stSizeCnt++] = '\x4b';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x45';
		buf[stSize + i32stSizeCnt++] = '\x0';

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\xf4';// push KERNEL32.DLL and Push esi
		*/

		buf[stSize + i32stSizeCnt++] = '\x64';
		buf[stSize + i32stSizeCnt++] = '\xa1';
		buf[stSize + i32stSizeCnt++] = '\x18';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';// mov eax, fs: [0x18]

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x40';
		buf[stSize + i32stSizeCnt++] = '\x30';// mov eax, [eax+0x30]

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x40';
		buf[stSize + i32stSizeCnt++] = '\x0c';// mov eax, [eax+0xc]

		buf[stSize + i32stSizeCnt++] = '\x8d';
		buf[stSize + i32stSizeCnt++] = '\x58';
		buf[stSize + i32stSizeCnt++] = '\x0c';// lea ebx, [eax+0xc]
		/*
		buf[stSize + i32stSizeCnt++] = '\x89';
		buf[stSize + i32stSizeCnt++] = '\x5d';
		buf[stSize + i32stSizeCnt++] = '\xe8';// mov orgPtr, ebx
		*/

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x13';// mov edx, [ebx]<--here

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x7a';
		buf[stSize + i32stSizeCnt++] = '\x18';// mov edi, [ edx+0x1c ]


		if(bCheckExeOrDLL == FALSE)
		{
			buf[stSize + i32stSizeCnt++] = '\x83';
			buf[stSize + i32stSizeCnt++] = '\xe9';
			buf[stSize + i32stSizeCnt++] = '\x0c';// sub ecx, 0xc

			buf[stSize + i32stSizeCnt++] = '\x89';
			buf[stSize + i32stSizeCnt++] = '\x39';// mov [ecx],edi
		}

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x4a';
		buf[stSize + i32stSizeCnt++] = '\x1c';// mov ecx, [ edx+0x18 ]

		//buf[stSize + i32stSizeCnt++] = '\x81';
		//buf[stSize + i32stSizeCnt++] = '\xc1';
		//buf[stSize + i32stSizeCnt++] = '\x64';
		//buf[stSize + i32stSizeCnt++] = '\x02';
		//buf[stSize + i32stSizeCnt++] = '\x0';
		//buf[stSize + i32stSizeCnt++] = '\x0';// add ecx,0x264h

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\xce';

		//buf[stSize + i32stSizeCnt++] = '\x89';
		//buf[stSize + i32stSizeCnt++] = '\x39';// mov dword ptr [ecx], edi

		buf[stSize + i32stSizeCnt++] = '\x81';
		buf[stSize + i32stSizeCnt++] = '\xc6';
		buf[stSize + i32stSizeCnt++] = '\xf0';
		buf[stSize + i32stSizeCnt++] = '\x01';
		buf[stSize + i32stSizeCnt++] = '\x00';
		buf[stSize + i32stSizeCnt++] = '\x00';// add esi,0x1f0

		int loaderloop = i32stSizeCnt;

		buf[stSize + i32stSizeCnt++] = '\x53';//push ebx

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x13';// mov edx, [ebx]<--here

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x7a';
		buf[stSize + i32stSizeCnt++] = '\x30';// mov edi, [ edx + 0x30 ] <-DllName

		buf[stSize + i32stSizeCnt++] = '\x52';// push edx
		//buf[stSize + i32stSizeCnt++] = '\x57';// push edx

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x7a';
		buf[stSize + i32stSizeCnt++] = '\x30';// mov edi, [ edx + 0x30 ] <-DllName

		buf[stSize + i32stSizeCnt++] = '\x57';// push edi

		buf[stSize + i32stSizeCnt++] = '\x56';// push esi

		buf[stSize + i32stSizeCnt++] = '\xb9';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';// mov ecx,0

		int From = i32stSizeCnt;

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x3c';
		buf[stSize + i32stSizeCnt++] = '\x24';// mov edi, dword ptr [esp]

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x74';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\x4';// mov esi, dword ptr [esp+4]

		buf[stSize + i32stSizeCnt++] = '\x03';
		buf[stSize + i32stSizeCnt++] = '\xf9';// add edi, ecx

		buf[stSize + i32stSizeCnt++] = '\x03';
		buf[stSize + i32stSizeCnt++] = '\xf1';// add esi, ecx

		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xc1';
		buf[stSize + i32stSizeCnt++] = '\x02';// add ecx, 2

		buf[stSize + i32stSizeCnt++] = '\x66';
		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x36';//mov si, [esi]

		buf[stSize + i32stSizeCnt++] = '\x66';
		buf[stSize + i32stSizeCnt++] = '\x39';
		buf[stSize + i32stSizeCnt++] = '\x37';// cmp word ptr [edi],[si]


		int To = i32stSizeCnt;

		char offset[4] = { 0 };

		int FromTo = From - To - 2;
		memcpy((void*)&offset, (void*)&(FromTo), 4);


		buf[stSize + i32stSizeCnt++] = '\x74';
		buf[stSize + i32stSizeCnt++] = offset[0];

		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xf9';
		buf[stSize + i32stSizeCnt++] = '\x1c';// cmp ecx,0x1c

		buf[stSize + i32stSizeCnt++] = '\x74';
		buf[stSize + i32stSizeCnt++] = '\xa';// je 0xc

		buf[stSize + i32stSizeCnt++] = '\x5e';// pop esi

		buf[stSize + i32stSizeCnt++] = '\x5f';// pop edi


		buf[stSize + i32stSizeCnt++] = '\x5b';// pop ebx

		buf[stSize + i32stSizeCnt++] = '\x5a';// pop edx

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x1b';//mov ebx,dword ptr [ebx]

		buf[stSize + i32stSizeCnt++] = '\x3b';
		buf[stSize + i32stSizeCnt++] = '\xda';//mov ebx,dword ptr [ebx]

		int loaderloopto = i32stSizeCnt;

		int LoaderOffset = loaderloop - loaderloopto - 2;

		memcpy((void*)&offset, (void*)&(LoaderOffset), 4);

		buf[stSize + i32stSizeCnt++] = '\x75';
		buf[stSize + i32stSizeCnt++] = offset[0];//jne loaderloop

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x42';
		buf[stSize + i32stSizeCnt++] = '\x18';//Get BaseAddress

		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xc4';
		buf[stSize + i32stSizeCnt++] = '\x10';//add esp,0x10

		buf[stSize + i32stSizeCnt++] = '\x50';//push eax <- BaseAddress

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\xd8';//mov ebx, eax

		buf[stSize + i32stSizeCnt++] = '\x81';
		buf[stSize + i32stSizeCnt++] = '\xc3';
		buf[stSize + i32stSizeCnt++] = '\x10';
		buf[stSize + i32stSizeCnt++] = '\xc6';
		buf[stSize + i32stSizeCnt++] = '\x02';
		buf[stSize + i32stSizeCnt++] = '\x00';//add ebx, 0x23eb0 <- CreateFile

		/*
		buf[stSize + i32stSizeCnt++] = '\x6a';
		buf[stSize + i32stSizeCnt++] = '\x00';

		buf[stSize + i32stSizeCnt++] = '\x68';
		buf[stSize + i32stSizeCnt++] = '\x6f';
		buf[stSize + i32stSizeCnt++] = '\x00';
		buf[stSize + i32stSizeCnt++] = '\x00';
		buf[stSize + i32stSizeCnt++] = '\x00';

		buf[stSize + i32stSizeCnt++] = '\x68';
		buf[stSize + i32stSizeCnt++] = '\x63';
		buf[stSize + i32stSizeCnt++] = '\x00';
		buf[stSize + i32stSizeCnt++] = '\x68';
		buf[stSize + i32stSizeCnt++] = '\x00';

		buf[stSize + i32stSizeCnt++] = '\x68';
		buf[stSize + i32stSizeCnt++] = '\x5c';
		buf[stSize + i32stSizeCnt++] = '\x00';
		buf[stSize + i32stSizeCnt++] = '\x65';
		buf[stSize + i32stSizeCnt++] = '\x00';

		buf[stSize + i32stSizeCnt++] = '\x68';
		buf[stSize + i32stSizeCnt++] = '\x70';
		buf[stSize + i32stSizeCnt++] = '\x00';
		buf[stSize + i32stSizeCnt++] = '\x65';
		buf[stSize + i32stSizeCnt++] = '\x00';

		buf[stSize + i32stSizeCnt++] = '\x68';
		buf[stSize + i32stSizeCnt++] = '\x70';
		buf[stSize + i32stSizeCnt++] = '\x00';
		buf[stSize + i32stSizeCnt++] = '\x69';
		buf[stSize + i32stSizeCnt++] = '\x00';

		buf[stSize + i32stSizeCnt++] = '\x68';
		buf[stSize + i32stSizeCnt++] = '\x2e';
		buf[stSize + i32stSizeCnt++] = '\x00';
		buf[stSize + i32stSizeCnt++] = '\x5c';
		buf[stSize + i32stSizeCnt++] = '\x00';

		buf[stSize + i32stSizeCnt++] = '\x68';
		buf[stSize + i32stSizeCnt++] = '\x5c';
		buf[stSize + i32stSizeCnt++] = '\x00';
		buf[stSize + i32stSizeCnt++] = '\x5c';
		buf[stSize + i32stSizeCnt++] = '\x00';//  \\pipe\\echo

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\xf4';//  mov esi, esp
		*/
		buf[stSize + i32stSizeCnt++] = '\x6a';
		buf[stSize + i32stSizeCnt++] = '\x00';//  push 0

		buf[stSize + i32stSizeCnt++] = '\x6a';
		buf[stSize + i32stSizeCnt++] = '\x00';//  push 0

		buf[stSize + i32stSizeCnt++] = '\x6a';
		buf[stSize + i32stSizeCnt++] = '\x03';//  push 3

		buf[stSize + i32stSizeCnt++] = '\x6a';
		buf[stSize + i32stSizeCnt++] = '\x00';//  push 0

		buf[stSize + i32stSizeCnt++] = '\x6a';
		buf[stSize + i32stSizeCnt++] = '\x00';//  push 0

		buf[stSize + i32stSizeCnt++] = '\x68';
		buf[stSize + i32stSizeCnt++] = '\x00';
		buf[stSize + i32stSizeCnt++] = '\x00';
		buf[stSize + i32stSizeCnt++] = '\x00';
		buf[stSize + i32stSizeCnt++] = '\xc0';// push c00000000

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x74';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\x1c';// mov esi, [esp+0x1c]

		buf[stSize + i32stSizeCnt++] = '\x81';
		buf[stSize + i32stSizeCnt++] = '\xc6';
		buf[stSize + i32stSizeCnt++] = '\x10';
		buf[stSize + i32stSizeCnt++] = '\x02';
		buf[stSize + i32stSizeCnt++] = '\x00';
		buf[stSize + i32stSizeCnt++] = '\x00';// add esi,0x200

		buf[stSize + i32stSizeCnt++] = '\x56';// push esi


		buf[stSize + i32stSizeCnt++] = '\xff';
		buf[stSize + i32stSizeCnt++] = '\xd3';// call ebx<-CreateFile

	//	buf[stSize + i32stSizeCnt++] = '\x83';
		//buf[stSize + i32stSizeCnt++] = '\xc4';
		//buf[stSize + i32stSizeCnt++] = '\x20';//add esp,0x20

		buf[stSize + i32stSizeCnt++] = '\x50';// push eax <- PipeNumber

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x44';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\x04';//mov eax,dword ptr[esp+4]

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\xd8';//mov ebx,eax

		buf[stSize + i32stSizeCnt++] = '\x81';
		buf[stSize + i32stSizeCnt++] = '\xc3';
		buf[stSize + i32stSizeCnt++] = '\x50';
		buf[stSize + i32stSizeCnt++] = '\xc3';
		buf[stSize + i32stSizeCnt++] = '\x02';
		buf[stSize + i32stSizeCnt++] = '\x00';//add ebx, 0x23c00

		buf[stSize + i32stSizeCnt++] = '\xff';
		buf[stSize + i32stSizeCnt++] = '\xd3';// call ebx <- GetCurrentProcessId

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\xfe';// mov edi,esi

		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xc7';
		buf[stSize + i32stSizeCnt++] = '\x48';//add edi,0x48

		buf[stSize + i32stSizeCnt++] = '\x89';
		buf[stSize + i32stSizeCnt++] = '\x07';// mov [edi],eax

		buf[stSize + i32stSizeCnt++] = '\x50';// push eax <- ProcessId

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x54';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\x04';//mov edx,dword ptr[esp+0x4]

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x44';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\x08';//mov eax,dword ptr[esp+0x8]

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\xd8';//mov ebx,eax

		buf[stSize + i32stSizeCnt++] = '\x81';
		buf[stSize + i32stSizeCnt++] = '\xc3';
		buf[stSize + i32stSizeCnt++] = '\x80';
		buf[stSize + i32stSizeCnt++] = '\xca';
		buf[stSize + i32stSizeCnt++] = '\x02';
		buf[stSize + i32stSizeCnt++] = '\x00';//add ebx, 0x23c00

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x44';
		buf[stSize + i32stSizeCnt++] = '\x24';
		buf[stSize + i32stSizeCnt++] = '\xc';// eax, dword ptr[esp+0x28]

		buf[stSize + i32stSizeCnt++] = '\x05';
		buf[stSize + i32stSizeCnt++] = '\x50';
		buf[stSize + i32stSizeCnt++] = '\x02';
		buf[stSize + i32stSizeCnt++] = '\x00';
		buf[stSize + i32stSizeCnt++] = '\x00';//add eax,0x220

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\xf0';//mov edi,eax

		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xc0';
		buf[stSize + i32stSizeCnt++] = '\x4';//add eax, 04

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\xf8';//mov esi,eax

		buf[stSize + i32stSizeCnt++] = '\x6a';
		buf[stSize + i32stSizeCnt++] = '\x0';//push 0

		buf[stSize + i32stSizeCnt++] = '\x56';// push edi

		buf[stSize + i32stSizeCnt++] = '\x68';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x04';
		buf[stSize + i32stSizeCnt++] = '\x0';
		buf[stSize + i32stSizeCnt++] = '\x0';// push 0x400

		buf[stSize + i32stSizeCnt++] = '\x57';//push esi

		buf[stSize + i32stSizeCnt++] = '\x52';//push edx

		buf[stSize + i32stSizeCnt++] = '\xff';
		buf[stSize + i32stSizeCnt++] = '\xd3';// call ebx <- WriteFile

		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xc4';
		buf[stSize + i32stSizeCnt++] = '\x0c';//add esp,0c

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x04';
		buf[stSize + i32stSizeCnt++] = '\x24';//mov eax,[esp]

		buf[stSize + i32stSizeCnt++] = '\x5';
		buf[stSize + i32stSizeCnt++] = '\x60';
		buf[stSize + i32stSizeCnt++] = '\x02';
		buf[stSize + i32stSizeCnt++] = '\x00';
		buf[stSize + i32stSizeCnt++] = '\x0';//add eax,0x260

		buf[stSize + i32stSizeCnt++] = '\x8b';
		buf[stSize + i32stSizeCnt++] = '\x00';

		buf[stSize + i32stSizeCnt++] = '\x83';
		buf[stSize + i32stSizeCnt++] = '\xf8';
		buf[stSize + i32stSizeCnt++] = '\x01';//cmp eax, 1

		buf[stSize + i32stSizeCnt++] = '\x75';
		buf[stSize + i32stSizeCnt++] = '\xf1';//if(eax==1)

		//buf[stSize + i32stSizeCnt++] = '\xeb';
		//buf[stSize + i32stSizeCnt++] = '\xfe';// while(1)

		buf[stSize + i32stSizeCnt++] = '\x61';//popad <- Last

		int i32FLLast = i32stSizeCnt + i32RollBackEntryPoint;
		int i32FLfunctionToEntryPoint = i32EntryPoint - i32FLLast - 5;// -3;

		char cFLfunctionToEntryPoint[4] = { 0, };

		memcpy((void*)&cFLfunctionToEntryPoint, (void*)&i32FLfunctionToEntryPoint, 4);


		buf[stSize + i32stSizeCnt++] = '\xe9';

		buf[stSize + i32stSizeCnt++] = cFLfunctionToEntryPoint[0];
		buf[stSize + i32stSizeCnt++] = cFLfunctionToEntryPoint[1];
		buf[stSize + i32stSizeCnt++] = cFLfunctionToEntryPoint[2];
		buf[stSize + i32stSizeCnt++] = cFLfunctionToEntryPoint[3];

		char cKernel32[] = "KERNEL32.DLL";
		char cPipe[] = "\\\\.\\pipe\\FLProtectionPipe";
		int i32KenrelSize = strlen(cKernel32);
		int i32PipeSize = strlen(cPipe);
		int i32Name = strlen(pNameDes);



		for(int i = 0; i < i32KenrelSize; i++)
		{
			buf[stSize + 0x200 + 2 * i] = cKernel32[i];
			buf[stSize + 0x200 + 2 * i + 1] = '\x00';
			if(i == i32KenrelSize - 1)
			{
				buf[stSize + 0x200 + 2 * (i + 1)] = '\x00';
				buf[stSize + 0x200 + 2 * (i + 1) + 1] = '\x00';

			}
			i32stSizeCnt += 2;
		}

		for(int i = 0; i < i32PipeSize; i++)
		{
			buf[stSize + 0x220 + 2 * i] = cPipe[i];
			buf[stSize + 0x220 + 2 * i + 1] = '\x00';
			if(i == i32PipeSize - 1)
			{
				buf[stSize + 0x220 + 2 * (i + 1)] = '\x00';
				buf[stSize + 0x220 + 2 * (i + 1) + 1] = '\x00';

			}
			i32stSizeCnt += 2;
		}


		for(int i = 0; i < i32Name; i++)
		{
			buf[stSize + 0x280 + 2 * i] = pNameDes[i];
			buf[stSize + 0x280 + 2 * i + 1] = '\x00';
			if(i == i32Name - 1)
			{
				buf[stSize + 0x280 + 2 * (i + 1)] = '\x00';
				buf[stSize + 0x280 + 2 * (i + 1) + 1] = '\x00';

			}
		}
		buf[stSize + 0x270] = '\x00';
		buf[stSize + 0x271] = '\x00';
		buf[stSize + 0x272] = '\x00';
		buf[stSize + 0x273] = '\x00';

		std::vector<std::pair<int, int> > vctRelocationVector;

		int RvaOfBlock = 0;
		int SizeOfBlock = 0;

		int i32RelocPointerToRawDataToRelocSizeOfBlock = i32RelocPointerToRawData + 4;

		memcpy((void*)&RvaOfBlock, (void*)&i32RelocPointerToRawData, 4);
		memcpy((void*)&SizeOfBlock, (void*)&i32RelocPointerToRawDataToRelocSizeOfBlock, 4);

		if(i32RelocRVA != 0)
		{
			vctRelocationVector.push_back({ RvaOfBlock,SizeOfBlock });
			while(1)
			{
				int TempRelocPointerToRawData = 0;
				memcpy((void*)&TempRelocPointerToRawData, (void*)&buf[SizeOfBlock], 4);
				i32RelocPointerToRawData += TempRelocPointerToRawData;

				i32RelocPointerToRawDataToRelocSizeOfBlock = i32RelocPointerToRawData + 4;

				int i32TempSizeOfBlock = 0;
				memcpy((void*)&i32TempSizeOfBlock, (void*)&buf[SizeOfBlock], 4);
				if(i32TempSizeOfBlock == 0)
					break;
				memcpy((void*)&RvaOfBlock, (void*)&i32RelocPointerToRawData, 4);
				memcpy((void*)&SizeOfBlock, (void*)(&i32RelocPointerToRawDataToRelocSizeOfBlock), 4);
				vctRelocationVector.push_back({ RvaOfBlock,SizeOfBlock });
			}
		}

		for(int i = 0; i < vctRelocationVector.size(); i++)
		{
			int RvaOfBlock = vctRelocationVector[i].first;
			int DeicdeToRvaOfBlock = 0;
			memcpy((void*)&DeicdeToRvaOfBlock, (void*)&buf[RvaOfBlock], 4);
			int Section = 0;
			for(int j = 0; j < vctSection.size() - 1; j++)
			{
				int FromRvaOfBlock = vctSection[j].RVA;
				int ToRvaOfBlock = vctSection[j + 1].RVA;

				if(FromRvaOfBlock <= DeicdeToRvaOfBlock && DeicdeToRvaOfBlock < ToRvaOfBlock)
				{
					Section = j;
					break;
				}
			}

			int Size = 0;
			memcpy((void*)&Size, (void*)&buf[vctRelocationVector[i].second], 4);

			int Start = vctRelocationVector[i].second + 4;

			for(int j = 0; j < Size - 8; j += 2)
			{
				WORD Data = 0;
				int i32RvaOfBlock = 0;

				memcpy((void*)&i32RvaOfBlock, (void*)&buf[RvaOfBlock], 4);
				memcpy((void*)&Data, (void*)&buf[Start], 2);
				if(Data == 0)
				{
					//Start += 2;
					//break;
					continue;
				}
				Data &= 0x0fff;

				int RelocData = i32RvaOfBlock + Data;

				//			RelocData -= vctSection[Section].RVA;
			//				RelocData += vctSection[Section].PoitnerToRawData;
							//RelocData += 2;

				int i32FileRelocOffset = Data + i32RvaOfBlock - vctSection[Section].RVA + vctSection[Section].PoitnerToRawData;// +2;


				vctParseRelocation.push_back({ Section,{RelocData,i32FileRelocOffset} });

				Start += 2;
			}
		}


		for(int i = i32PointerToRawData; i < i32SizeOfCode + i32PointerToRawData; i++)
		{
			buf[i] = ~buf[i];
		}


		for(int i = 0; i < vctParseRelocation.size(); i++)
		{
			int32_t i32Section = vctParseRelocation[i].first;
			int32_t i32ParseReloc = vctParseRelocation[i].second.second;
			if(i32ParseReloc < i32SizeOfCode + i32PointerToRawData)
			{
				for(int j = 0; j < 4; j++)
				{
					buf[i32ParseReloc + j] = ~buf[i32ParseReloc + j];
				}
			}

		}

		fwrite(buf, sizeof(char), stSize + i32FLSize, fp);
		fclose(fp);
	}
	else
	{
		printf("파일이 존재하지 않습니다\n");
	}

}