#include "PEParser.h"

#include <stdlib.h>
#include <stdio.h>

extern void print_word_array(WORD *arr, SIZE_T len);


PEParser::PEParser() { 
  this->peFileName = 0;
  this->peFileSize = 0;
  this->peBuffer = 0;
}


PEParser::~PEParser() {
  
  if (this->peBuffer) {
    free(this->peBuffer);
  }

}


BOOL PEParser::readPE(const char *pe_file_name) {
  if (!pe_file_name) return 0;

 
  HANDLE file_handle = 
  CreateFile(pe_file_name, GENERIC_READ, 0, 0, OPEN_EXISTING,
             FILE_ATTRIBUTE_NORMAL, 0);

  if (file_handle == INVALID_HANDLE_VALUE) {
    printf("INVALID_HANDLE_VALUE\n");
    return FALSE;
  }
 
  DWORD file_size =  GetFileSize(file_handle, 0);

  char *buffer = (char *)malloc(file_size);


  if (!buffer) {
    printf("buffer malloc(%d) error\n", file_size);
    return FALSE;
  }

  ZeroMemory(buffer, file_size);
  
  DWORD read_size;

  if (!ReadFile(file_handle, buffer, file_size, &read_size, 0)) {
    free(buffer);
    printf("ReadFile() error: %d\n", GetLastError());
    return FALSE;
  }

  CloseHandle(file_handle);

  this->peFileName = pe_file_name;
  this->peFileSize = file_size;
  this->peBuffer = buffer;

  return TRUE;
}


BOOL PEParser::initPE() { 
  if (!this->peBuffer) {
    printf("Please call PEParser.readPE first");
    return FALSE;
  }

  this->peDosHeader = (IMAGE_DOS_HEADER *)this->peBuffer;

  if (this->peDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
    printf("Invalid PE file: %s\n", this->peFileName);
    return FALSE;
  }

  this->peNtHeader =
      (IMAGE_NT_HEADERS *)(this->peBuffer + this->peDosHeader->e_lfanew);

  if (this->peNtHeader->Signature != IMAGE_NT_SIGNATURE) {
    printf("Invalid PE file: %s\n", this->peFileName);
    return FALSE;
  }
  
  this->peFileHeader = 
    (IMAGE_FILE_HEADER *)&this->peNtHeader->FileHeader;
    
  this->peOptionalHeader =
      (IMAGE_OPTIONAL_HEADER *)&this->peNtHeader->OptionalHeader;
  
  this->peFirstSectionHeader = 
    (IMAGE_SECTION_HEADER *)((char *)this->peOptionalHeader +
                                   this->peFileHeader->SizeOfOptionalHeader);

  return TRUE;
}


DWORD PEParser::rvaToFoa(DWORD rva) {
  
  IMAGE_SECTION_HEADER *sech = this->peFirstSectionHeader;

  for (int i = 0; i < this->peFileHeader->NumberOfSections; i++) {

    if (rva >= sech->VirtualAddress &&
        rva <= sech->VirtualAddress + sech->Misc.VirtualSize) {
      return rva - sech->VirtualAddress + sech->PointerToRawData;
    }
    sech++;
  }

  return 0; 
}

void PEParser::exportsInfo() { 
  IMAGE_DATA_DIRECTORY dir = (IMAGE_DATA_DIRECTORY)this->peOptionalHeader->DataDirectory[0];

  IMAGE_EXPORT_DIRECTORY *exdir =
      (IMAGE_EXPORT_DIRECTORY *)(this->peBuffer +
                                 this->rvaToFoa(dir.VirtualAddress));

   char *name = this->peBuffer + this->rvaToFoa(exdir->Name);

   DWORD *funcAddr =
       (DWORD *)(this->peBuffer + this->rvaToFoa(exdir->AddressOfFunctions));

   WORD *funcOrd =
       (WORD *)(this->peBuffer + this->rvaToFoa(exdir->AddressOfNameOrdinals));
  
   DWORD *funcName = (DWORD *)(this->peBuffer + this->rvaToFoa(exdir->AddressOfNames));

   printf("DLL Name: %s\n", name);

   for (int i = 0; i < exdir->NumberOfFunctions; i++) {
     printf("Func Name Addr: 0x%x ", *funcAddr);
     for (int j = 0; j < exdir->NumberOfNames; j++) {
       if (funcOrd[j] == i) {
         printf(", Name: %s", (char *)(this->peBuffer + this->rvaToFoa(funcName[j])));
         break;
       }
     }
     printf("\n");
     funcAddr++;
   }

}


void PEParser::sectionsHeaderInfo() {

  IMAGE_SECTION_HEADER *section = this->peFirstSectionHeader;
  
  for (int i = 0; i < this->peFileHeader->NumberOfSections; i++) {
    BYTE name[9] = {0};
    ZeroMemory(name, 8);
    memcpy_s(name, 9, section->Name, 8);
    printf("Name: %s\n", name);
    printf("PhysicalAddress: %d\n", section->Misc.PhysicalAddress);
    printf("VirtualAddress: %d\n", section->VirtualAddress);
    printf("SizeOfRawData: %d\n", section->SizeOfRawData);
    printf("PointerToRawData: %d\n", section->PointerToRawData);
    printf("PointerToRelocations: %d\n", section->PointerToRelocations);
    printf("PointerToLinenumbers: %d\n", section->PointerToLinenumbers);
    printf("NumberOfRelocations: %d\n", section->NumberOfRelocations);
    printf("NumberOfLinenumbers: %d\n", section->NumberOfLinenumbers);
    printf("Characteristics: %d\n", section->Characteristics);
    printf("\n\n");
    section++;
  }
}


void PEParser::dosHeaderInfo() {
  printf("e_magic: %d\n", this->peDosHeader->e_magic);
  printf("e_cblp: %d\n", this->peDosHeader->e_cblp);
  printf("e_cp: %d\n", this->peDosHeader->e_cp);
  printf("e_crlc: %d\n", this->peDosHeader->e_crlc);
  printf("e_cparhdr: %d\n", this->peDosHeader->e_cparhdr);
  printf("e_minalloc: %d\n", this->peDosHeader->e_minalloc);
  printf("e_maxalloc: %d\n", this->peDosHeader->e_maxalloc);
  printf("e_ss: %d\n", this->peDosHeader->e_ss);
  printf("e_sp: %d\n", this->peDosHeader->e_sp);
  printf("e_csum: %d\n", this->peDosHeader->e_csum);
  printf("e_ip: %d\n", this->peDosHeader->e_ip);
  printf("e_cs: %d\n", this->peDosHeader->e_cs);
  printf("e_lfarlc: %d\n", this->peDosHeader->e_lfarlc);
  printf("e_ovno: %d\n", this->peDosHeader->e_ovno);
  printf("e_res[4]: ");
  print_word_array(this->peDosHeader->e_res, 4);
  printf("e_oemid: %d\n", this->peDosHeader->e_oemid);
  printf("e_res2[10]: ");
  print_word_array(this->peDosHeader->e_res2, 10);
  printf("e_lfanew: %d\n", this->peDosHeader->e_lfanew);
}


void PEParser::ntFileHeaderInfo() { 
  
  printf("Machine: %d\n",this->peFileHeader->Machine);
  printf("NumberOfSections: %d\n", this->peFileHeader->NumberOfSections);
  printf("TimeDateStamp: %d\n", this->peFileHeader->TimeDateStamp);
  printf("PointerToSymbolTable: %d\n",
         this->peFileHeader->PointerToSymbolTable);
  printf("SizeOfOptionalHeader: %d\n", this->peFileHeader->SizeOfOptionalHeader);
  printf("Characteristics: %d\n", this->peFileHeader->Characteristics);

}


void PEParser::ntOptionalHeaderInfo() { 

  printf("Magic: %d\n", this->peOptionalHeader->Magic);
  printf("MajorLinkerVersion: %d\n", this->peOptionalHeader->MajorLinkerVersion);
  printf("MinorLinkerVersion: %d\n", this->peOptionalHeader->MinorLinkerVersion);
  printf("SizeOfCode: %d\n", this->peOptionalHeader->SizeOfCode);
  printf("SizeOfInitializedData: %d\n", this->peOptionalHeader->SizeOfInitializedData);
  printf("SizeOfUninitializedData: %d\n", this->peOptionalHeader->SizeOfUninitializedData);
  printf("AddressOfEntryPoint: %d\n", this->peOptionalHeader->AddressOfEntryPoint);
  printf("BaseOfCode: %d\n", this->peOptionalHeader->BaseOfCode);
  printf("BaseOfData: %d\n", this->peOptionalHeader->BaseOfData);
  printf("ImageBase: %d\n", this->peOptionalHeader->ImageBase);
  printf("SectionAlignment: %d\n", this->peOptionalHeader->SectionAlignment);
  printf("FileAlignment: %d\n", this->peOptionalHeader->FileAlignment);
  printf("MajorOperatingSystemVersion: %d\n", this->peOptionalHeader->MajorOperatingSystemVersion);
  printf("MinorOperatingSystemVersion: %d\n", this->peOptionalHeader->MinorOperatingSystemVersion);
  printf("MajorImageVersion: %d\n", this->peOptionalHeader->MajorImageVersion);
  printf("MinorImageVersion: %d\n", this->peOptionalHeader->MinorImageVersion);
  printf("MajorSubsystemVersion: %d\n", this->peOptionalHeader->MajorSubsystemVersion);
  printf("MinorSubsystemVersion: %d\n", this->peOptionalHeader->MinorSubsystemVersion);
  printf("Win32VersionValue: %d\n", this->peOptionalHeader->Win32VersionValue);
  printf("SizeOfImage: %d\n", this->peOptionalHeader->SizeOfImage);
  printf("SizeOfHeaders: %d\n", this->peOptionalHeader->SizeOfHeaders);
  printf("CheckSum: %d\n", this->peOptionalHeader->CheckSum);
  printf("Subsystem: %d\n", this->peOptionalHeader->Subsystem);
  printf("DllCharacteristics: %d\n", this->peOptionalHeader->DllCharacteristics);
  printf("SizeOfStackReserve: %d\n", this->peOptionalHeader->SizeOfStackReserve);
  printf("SizeOfStackCommit: %d\n", this->peOptionalHeader->SizeOfStackCommit);
  printf("SizeOfHeapReserve: %d\n", this->peOptionalHeader->SizeOfHeapReserve);
  printf("SizeOfHeapCommit: %d\n", this->peOptionalHeader->SizeOfHeapCommit);
  printf("LoaderFlags: %d\n", this->peOptionalHeader->LoaderFlags);
  printf("NumberOfRvaAndSizes: %d\n", this->peOptionalHeader->NumberOfRvaAndSizes);
}


void PEParser::ntHeaderInfo() {
  
  printf("Signature: %d\n", this->peNtHeader->Signature);
  puts("============= IMAGE_FILE_HEADER ===============");
  this->ntFileHeaderInfo();
  puts("============= IMAGE_OPTIONAL_HEADER ===============");
  this->ntOptionalHeaderInfo();
}


void PEParser::peInfo() { 
  printf("File Name: %s\n", this->peFileName);
  printf("File Size: %d\n", this->peFileSize);
  printf("Header Size: %d\n",  this->peDosHeader->e_lfanew); 
 
  printf("========= IMAGE_DOS_HEADER ========\n");
  this->dosHeaderInfo();
  printf("========= IMAGE_NT_HEADERS ========\n");
  this->ntHeaderInfo();
  printf("========= IMAGE_SECTIONS_HEADER ========\n");
  this->sectionsHeaderInfo();
  printf("========= EXPORTS_TABLE_HEADER ========\n");
  this->exportsInfo();
}


void print_word_array(WORD *arr, SIZE_T len) {
  
  for (int i = 0; i < len; i++) {

    printf("%d ", arr[i]);
  
  }

  printf("\n");
}