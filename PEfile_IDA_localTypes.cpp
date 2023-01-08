typedef struct _IMAGE_DOS_HEADER
{
  _WORD e_magic;
  _WORD e_cblp;
  _WORD e_cp;
  _WORD e_crlc;
  _WORD e_cparhdr;
  _WORD e_minalloc;
  _WORD e_maxalloc;
  _WORD e_ss;
  _WORD e_sp;
  _WORD e_csum;
  _WORD e_ip;
  _WORD e_cs;
  _WORD e_lfarlc;
  _WORD e_ovno;
  _WORD e_res[4];
  _WORD e_oemid;
  _WORD e_oeminfo;
  _WORD e_res2[10];
  _DWORD e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER
{
  _WORD Machine;
  _WORD NumberOfSections;
  _DWORD TimeDateStamp;
  _DWORD PointerToSymbolTable;
  _DWORD NumberOfSymbols;
  _WORD SizeOfOptionalHeader;
  _WORD Characteristics;
} IMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY
{
  _DWORD VirtualAddr;
  _DWORD Size;
} IMAGE_DATA_DIRECTORY;


typedef enum dir_entry
{
  DIR_EXPORT = 0x0,
  DIR_IMPORT = 0x1,
  DIR_RESOURCE = 0x2,
  DIR_EXCEPTION = 0x3,
  DIR_SECURITY = 0x4,
  DIR_BASERELOC = 0x5,
  DIR_DEBUG = 0x6,
  DIR_ARCHITECTURE = 0x7,
  DIR_GLOBALPTR = 0x8,
  DIR_TLS = 0x9,
  DIR_LOAD_CONFIG = 0xA,
  DIR_BOUND_IMPORT = 0xB,
  DIR_IAT = 0xC,
  DIR_DELAY_IMPORT = 0xD,
  DIR_COM_DESCRIPTOR = 0xE,
  DIR_ENTRIES_COUNT = 0xF,
} DIR_ENTRY;


typedef struct _IMAGE_OPTIONAL_HEADER32
{
  _WORD Magic;
  _BYTE MajorLinkerVersion;
  _BYTE MinorLinkerVersion;
  _DWORD SizeOfCode;
  _DWORD SizeOfInitializedData;
  _DWORD SizeOfUninitializedData;
  _DWORD AddressOfEntryPoint;
  _DWORD BaseOfCode;
  _DWORD BaseOfData;
  _DWORD ImageBase;
  _DWORD SectionAlignment;
  _DWORD FileAlignment;
  _WORD MajorOperatingSystemVersion;
  _WORD MinorOperatingSystemVersion;
  _WORD MajorImageVersion;
  _WORD MinorImageVersion;
  _WORD MajorSubsystemVersion;
  _WORD MinorSubsystemVersion;
  _DWORD Win32VersionValue;
  _DWORD SizeOfImage;
  _DWORD SizeOfHeaders;
  _DWORD CheckSum;
  _WORD Subsystem;
  _WORD DllCharacteristics;
  _DWORD SizeOfStackReserve;
  _DWORD SizeOfStackCommit;
  _DWORD SizeOfHeapReserve;
  _DWORD SizeOfHeapCommit;
  _DWORD LoaderFlags;
  _DWORD NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[DIR_ENTRIES_COUNT];
} IMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_NT_HEADERS32
{
  _DWORD Signature;
  IMAGE_FILE_HEADER FileHeader;
  IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32;

typedef struct _IMAGE_SECTION_HEADER
{
  _BYTE Name[8];
  _DWORD VirtualSize;
  _DWORD VirtualAddress;
  _DWORD SizeOfRawData;
  _DWORD PointerToRawData;
  _DWORD PointerToRelocations;
  _DWORD PointerToLinenumbers;
  _WORD NumberOfRelocations;
  _WORD NumberOfLinenumbers;
  _DWORD Characteristics;
} IMAGE_SECTION_HEADER;
