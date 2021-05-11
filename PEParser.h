#ifndef __PE_PARSER_H__

#include <Windows.h>


class PEParser {
 private:
  const char *peFileName;
  char *peBuffer;
  DWORD peFileSize;
  IMAGE_DOS_HEADER *peDosHeader;
  IMAGE_NT_HEADERS *peNtHeader;
  IMAGE_FILE_HEADER *peFileHeader;
  IMAGE_OPTIONAL_HEADER *peOptionalHeader;
  IMAGE_SECTION_HEADER *peFirstSectionHeader;

 public:

   PEParser();

   ~PEParser();

   BOOL readPE(const char *pe_file_name);

   BOOL initPE();

   void peInfo();

   void dosHeaderInfo();

   void ntHeaderInfo();

   void ntFileHeaderInfo();

   void ntOptionalHeaderInfo();

   void sectionsHeaderInfo();

   void exportsInfo();

   DWORD rvaToFoa(DWORD num);
};


#endif  // !__PE_PARSER_H__
