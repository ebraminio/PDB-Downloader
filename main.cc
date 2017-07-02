// Ported [back, possibly] to C from https://github.com/rajkumar-rangaraj/PDB-Downloader
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#pragma pack(1)
struct IMAGE_DOS_HEADER {
    uint16_t e_magic;              // Magic number
    uint16_t e_cblp;               // Bytes on last page of file
    uint16_t e_cp;                 // Pages in file
    uint16_t e_crlc;               // Relocations
    uint16_t e_cparhdr;            // Size of header in paragraphs
    uint16_t e_minalloc;           // Minimum extra paragraphs needed
    uint16_t e_maxalloc;           // Maximum extra paragraphs needed
    uint16_t e_ss;                 // Initial (relative) SS value
    uint16_t e_sp;                 // Initial SP value
    uint16_t e_csum;               // Checksum
    uint16_t e_ip;                 // Initial IP value
    uint16_t e_cs;                 // Initial (relative) CS value
    uint16_t e_lfarlc;             // File address of relocation table
    uint16_t e_ovno;               // Overlay number
    uint16_t e_res_0;              // Reserved words
    uint16_t e_res_1;              // Reserved words
    uint16_t e_res_2;              // Reserved words
    uint16_t e_res_3;              // Reserved words
    uint16_t e_oemid;              // OEM identifier (for e_oeminfo)
    uint16_t e_oeminfo;            // OEM information; e_oemid specific
    uint16_t e_res2_0;             // Reserved words
    uint16_t e_res2_1;             // Reserved words
    uint16_t e_res2_2;             // Reserved words
    uint16_t e_res2_3;             // Reserved words
    uint16_t e_res2_4;             // Reserved words
    uint16_t e_res2_5;             // Reserved words
    uint16_t e_res2_6;             // Reserved words
    uint16_t e_res2_7;             // Reserved words
    uint16_t e_res2_8;             // Reserved words
    uint16_t e_res2_9;             // Reserved words
    uint32_t e_lfanew;             // File address of new exe header
};

struct IMAGE_DATA_DIRECTORY {
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct IMAGE_OPTIONAL_HEADER32 {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;

    IMAGE_DATA_DIRECTORY ExportTable;
    IMAGE_DATA_DIRECTORY ImportTable;
    IMAGE_DATA_DIRECTORY ResourceTable;
    IMAGE_DATA_DIRECTORY ExceptionTable;
    IMAGE_DATA_DIRECTORY CertificateTable;
    IMAGE_DATA_DIRECTORY BaseRelocationTable;
    IMAGE_DATA_DIRECTORY Debug;
    IMAGE_DATA_DIRECTORY Architecture;
    IMAGE_DATA_DIRECTORY GlobalPtr;
    IMAGE_DATA_DIRECTORY TLSTable;
    IMAGE_DATA_DIRECTORY LoadConfigTable;
    IMAGE_DATA_DIRECTORY BoundImport;
    IMAGE_DATA_DIRECTORY IAT;
    IMAGE_DATA_DIRECTORY DelayImportDescriptor;
    IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
    IMAGE_DATA_DIRECTORY Reserved;
};

struct IMAGE_OPTIONAL_HEADER64 {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;

    IMAGE_DATA_DIRECTORY ExportTable;
    IMAGE_DATA_DIRECTORY ImportTable;
    IMAGE_DATA_DIRECTORY ResourceTable;
    IMAGE_DATA_DIRECTORY ExceptionTable;
    IMAGE_DATA_DIRECTORY CertificateTable;
    IMAGE_DATA_DIRECTORY BaseRelocationTable;
    IMAGE_DATA_DIRECTORY Debug;
    IMAGE_DATA_DIRECTORY Architecture;
    IMAGE_DATA_DIRECTORY GlobalPtr;
    IMAGE_DATA_DIRECTORY TLSTable;
    IMAGE_DATA_DIRECTORY LoadConfigTable;
    IMAGE_DATA_DIRECTORY BoundImport;
    IMAGE_DATA_DIRECTORY IAT;
    IMAGE_DATA_DIRECTORY DelayImportDescriptor;
    IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
    IMAGE_DATA_DIRECTORY Reserved;
};

struct IMAGE_FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

enum DataSectionFlags : uint32_t {
    TypeReg = 0x00000000,
    TypeDsect = 0x00000001,
    TypeNoLoad = 0x00000002,
    TypeGroup = 0x00000004,
    TypeNoPadded = 0x00000008,
    TypeCopy = 0x00000010,
    ContentCode = 0x00000020,
    ContentInitializedData = 0x00000040,
    ContentUninitializedData = 0x00000080,
    LinkOther = 0x00000100,
    LinkInfo = 0x00000200,
    TypeOver = 0x00000400,
    LinkRemove = 0x00000800,
    LinkComDat = 0x00001000,
    NoDeferSpecExceptions = 0x00004000,
    RelativeGP = 0x00008000,
    MemPurgeable = 0x00020000,
    Memory16Bit = 0x00020000,
    MemoryLocked = 0x00040000,
    MemoryPreload = 0x00080000,
    Align1Bytes = 0x00100000,
    Align2Bytes = 0x00200000,
    Align4Bytes = 0x00300000,
    Align8Bytes = 0x00400000,
    Align16Bytes = 0x00500000,
    Align32Bytes = 0x00600000,
    Align64Bytes = 0x00700000,
    Align128Bytes = 0x00800000,
    Align256Bytes = 0x00900000,
    Align512Bytes = 0x00A00000,
    Align1024Bytes = 0x00B00000,
    Align2048Bytes = 0x00C00000,
    Align4096Bytes = 0x00D00000,
    Align8192Bytes = 0x00E00000,
    LinkExtendedRelocationOverflow = 0x01000000,
    MemoryDiscardable = 0x02000000,
    MemoryNotCached = 0x04000000,
    MemoryNotPaged = 0x08000000,
    MemoryShared = 0x10000000,
    MemoryExecute = 0x20000000,
    MemoryRead = 0x40000000,
    MemoryWrite = 0x80000000
};

struct IMAGE_SECTION_HEADER {
    uint8_t Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    DataSectionFlags Characteristics;
};

struct IMAGE_DEBUG_DIRECTORY {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Type;
    uint32_t SizeOfData;
    uint32_t AddressOfRawData;
    uint32_t PointerToRawData;
};

struct IMAGE_DEBUG_DIRECTORY_RAW {
    uint8_t format[4];
    uint8_t guid[16];
    uint32_t age;
    uint8_t name[255];
};
#pragma pack()

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Please enter your DLL file name");
        return 1;
    }

    FILE *file = fopen(argv[1], "rb");

    IMAGE_DOS_HEADER dosHeader;
    fread(&dosHeader, sizeof (IMAGE_DOS_HEADER), 1, file);
    fseek(file, dosHeader.e_lfanew, SEEK_SET);

    // Add 4 bytes to the offset
    uint32_t ntHeadersSignature;
    fread(&ntHeadersSignature, 4, 1, file);

    IMAGE_FILE_HEADER fileHeader;
    fread(&fileHeader, sizeof (IMAGE_FILE_HEADER), 1, file);

    // uint16_t IMAGE_FILE_32BIT_MACHINE = 0x0100;
    // return (IMAGE_FILE_32BIT_MACHINE & FileHeader.Characteristics) == IMAGE_FILE_32BIT_MACHINE;
    bool is32BitHeader = fileHeader.Machine == 0x14C; // 0x14C = X86

    IMAGE_OPTIONAL_HEADER32 optionalHeader32;
    IMAGE_OPTIONAL_HEADER64 optionalHeader64;
    if (is32BitHeader)
        fread(&optionalHeader32, sizeof (IMAGE_OPTIONAL_HEADER32), 1, file);
    else
        fread(&optionalHeader64, sizeof (IMAGE_OPTIONAL_HEADER64), 1, file);

    uint32_t offDebug = 0;
    uint32_t cbFromHeader = 0;

    uint32_t cbDebug = is32BitHeader ? optionalHeader32.Debug.Size : optionalHeader64.Debug.Size;

    for (int headerNo = 0; headerNo < fileHeader.NumberOfSections; ++headerNo) {
        IMAGE_SECTION_HEADER header;
        fread(&header, sizeof (IMAGE_SECTION_HEADER), 1, file);

        if ((header.PointerToRawData != 0) && (header.SizeOfRawData != 0) &&
                (cbFromHeader < (header.PointerToRawData + header.SizeOfRawData))) {
            cbFromHeader = header.PointerToRawData + header.SizeOfRawData;
        }

        if (cbDebug != 0) {
            if (is32BitHeader) {
                if (header.VirtualAddress <= optionalHeader32.Debug.VirtualAddress &&
                        ((header.VirtualAddress + header.SizeOfRawData) > optionalHeader32.Debug.VirtualAddress)) {
                    offDebug = optionalHeader32.Debug.VirtualAddress - header.VirtualAddress + header.PointerToRawData;
                }
            } else {
                if (header.VirtualAddress <= optionalHeader64.Debug.VirtualAddress &&
                    ((header.VirtualAddress + header.SizeOfRawData) > optionalHeader64.Debug.VirtualAddress)) {
                    offDebug = optionalHeader64.Debug.VirtualAddress - header.VirtualAddress + header.PointerToRawData;
                }
            }
        }
    }

    fseek(file, offDebug, SEEK_SET);

    bool loopexit = false;

    IMAGE_DEBUG_DIRECTORY_RAW debugInfo;
    while (cbDebug >= sizeof (IMAGE_DEBUG_DIRECTORY)) {
        if (loopexit == false) {
            
            IMAGE_DEBUG_DIRECTORY imageDebugDirectory;

            fread(&imageDebugDirectory, sizeof (IMAGE_DEBUG_DIRECTORY), 1, file);

            long seekPosition = ftell(file);

            if (imageDebugDirectory.Type == 0x2) {
                fseek(file, imageDebugDirectory.PointerToRawData, SEEK_SET);
                fread(&debugInfo, sizeof (IMAGE_DEBUG_DIRECTORY_RAW), 1, file);
                loopexit = true;

                // Downloading logic for .NET native images
                if (strstr((char *) debugInfo.name, ".ni.") != 0) {
                    fseek(file, seekPosition, SEEK_SET);
                    loopexit = false;
                }
            }

            if ((imageDebugDirectory.PointerToRawData != 0) && (imageDebugDirectory.SizeOfData != 0) &&
                    (cbFromHeader < (imageDebugDirectory.PointerToRawData + imageDebugDirectory.SizeOfData))) {
                cbFromHeader = imageDebugDirectory.PointerToRawData + imageDebugDirectory.SizeOfData;
            }
        }

        cbDebug -= sizeof (IMAGE_DEBUG_DIRECTORY);
    }

    fclose(file);

    if (loopexit) {
        char *pdbName = (char *) strrchr((char *) debugInfo.name, '\\');
        pdbName = pdbName ? pdbName + 1 : (char *) debugInfo.name;

        char cabName[256];
        strcpy(cabName, pdbName);
        cabName[strlen(pdbName) - 1] = '_';
        
        printf("http://msdl.microsoft.com/download/symbols/%s/%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%d/%s",
            pdbName,
            debugInfo.guid[3], debugInfo.guid[2],
            debugInfo.guid[1], debugInfo.guid[0],
            debugInfo.guid[5], debugInfo.guid[4],
            debugInfo.guid[7], debugInfo.guid[6],
            debugInfo.guid[8], debugInfo.guid[9],
            debugInfo.guid[10], debugInfo.guid[11],
            debugInfo.guid[12], debugInfo.guid[13],
            debugInfo.guid[14], debugInfo.guid[15],
            debugInfo.age, cabName);

        return 0;
    } else {
        return 2; // failed to find pdb link
    }
}
