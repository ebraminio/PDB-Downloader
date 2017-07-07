const r = require('restructure');

const IMAGE_DOS_HEADER = new r.Struct({
    e_magic: r.uint16le,              // Magic number
    e_cblp: r.uint16le,               // Bytes on last page of file
    e_cp: r.uint16le,                 // Pages in file
    e_crlc: r.uint16le,               // Relocations
    e_cparhdr: r.uint16le,            // Size of header in paragraphs
    e_minalloc: r.uint16le,           // Minimum extra paragraphs needed
    e_maxalloc: r.uint16le,           // Maximum extra paragraphs needed
    e_ss: r.uint16le,                 // Initial (relative) SS value
    e_sp: r.uint16le,                 // Initial SP value
    e_csum: r.uint16le,               // Checksum
    e_ip: r.uint16le,                 // Initial IP value
    e_cs: r.uint16le,                 // Initial (relative) CS value
    e_lfarlc: r.uint16le,             // File address of relocation table
    e_ovno: r.uint16le,               // Overlay number
    e_res_0: r.uint16le,              // Reserved words
    e_res_1: r.uint16le,              // Reserved words
    e_res_2: r.uint16le,              // Reserved words
    e_res_3: r.uint16le,              // Reserved words
    e_oemid: r.uint16le,              // OEM identifier (for e_oeminfo)
    e_oeminfo: r.uint16le,            // OEM information: r.uint16le, e_oemid specific
    e_res2_0: r.uint16le,             // Reserved words
    e_res2_1: r.uint16le,             // Reserved words
    e_res2_2: r.uint16le,             // Reserved words
    e_res2_3: r.uint16le,             // Reserved words
    e_res2_4: r.uint16le,             // Reserved words
    e_res2_5: r.uint16le,             // Reserved words
    e_res2_6: r.uint16le,             // Reserved words
    e_res2_7: r.uint16le,             // Reserved words
    e_res2_8: r.uint16le,             // Reserved words
    e_res2_9: r.uint16le,             // Reserved words
    e_lfanew: r.uint32le              // File address of new exe header
});

const IMAGE_DATA_DIRECTORY = new r.Struct({
    VirtualAddress: r.uint32le,
    Size: r.uint32le
});

const IMAGE_OPTIONAL_HEADER32 = new r.Struct({
    Magic: r.uint16le,
    MajorLinkerVersion: r.uint8,
    MinorLinkerVersion: r.uint8,
    SizeOfCode: r.uint32le,
    SizeOfInitializedData: r.uint32le,
    SizeOfUninitializedData: r.uint32le,
    AddressOfEntryPoint: r.uint32le,
    BaseOfCode: r.uint32le,
    BaseOfData: r.uint32le,
    ImageBase: r.uint32le,
    SectionAlignment: r.uint32le,
    FileAlignment: r.uint32le,
    MajorOperatingSystemVersion: r.uint16le,
    MinorOperatingSystemVersion: r.uint16le,
    MajorImageVersion: r.uint16le,
    MinorImageVersion: r.uint16le,
    MajorSubsystemVersion: r.uint16le,
    MinorSubsystemVersion: r.uint16le,
    Win32VersionValue: r.uint32le,
    SizeOfImage: r.uint32le,
    SizeOfHeaders: r.uint32le,
    CheckSum: r.uint32le,
    Subsystem: r.uint16le,
    DllCharacteristics: r.uint16le,
    SizeOfStackReserve: r.uint32le,
    SizeOfStackCommit: r.uint32le,
    SizeOfHeapReserve: r.uint32le,
    SizeOfHeapCommit: r.uint32le,
    LoaderFlags: r.uint32le,
    NumberOfRvaAndSizes: r.uint32le,

    ExportTable: IMAGE_DATA_DIRECTORY,
    ImportTable: IMAGE_DATA_DIRECTORY,
    ResourceTable: IMAGE_DATA_DIRECTORY,
    ExceptionTable: IMAGE_DATA_DIRECTORY,
    CertificateTable: IMAGE_DATA_DIRECTORY,
    BaseRelocationTable: IMAGE_DATA_DIRECTORY,
    Debug: IMAGE_DATA_DIRECTORY,
    Architecture: IMAGE_DATA_DIRECTORY,
    GlobalPtr: IMAGE_DATA_DIRECTORY,
    TLSTable: IMAGE_DATA_DIRECTORY,
    LoadConfigTable: IMAGE_DATA_DIRECTORY,
    BoundImport: IMAGE_DATA_DIRECTORY,
    IAT: IMAGE_DATA_DIRECTORY,
    DelayImportDescriptor: IMAGE_DATA_DIRECTORY,
    CLRRuntimeHeader: IMAGE_DATA_DIRECTORY,
    Reserved: IMAGE_DATA_DIRECTORY
});

const IMAGE_OPTIONAL_HEADER64 = new r.Struct({
    Magic: r.uint16le,
    MajorLinkerVersion: r.uint8,
    MinorLinkerVersion: r.uint8,
    SizeOfCode: r.uint32le,
    SizeOfInitializedData: r.uint32le,
    SizeOfUninitializedData: r.uint32le,
    AddressOfEntryPoint: r.uint32le,
    BaseOfCode: r.uint32le,
    ImageBase: r.uint64le,
    SectionAlignment: r.uint32le,
    FileAlignment: r.uint32le,
    MajorOperatingSystemVersion: r.uint16le,
    MinorOperatingSystemVersion: r.uint16le,
    MajorImageVersion: r.uint16le,
    MinorImageVersion: r.uint16le,
    MajorSubsystemVersion: r.uint16le,
    MinorSubsystemVersion: r.uint16le,
    Win32VersionValue: r.uint32le,
    SizeOfImage: r.uint32le,
    SizeOfHeaders: r.uint32le,
    CheckSum: r.uint32le,
    Subsystem: r.uint16le,
    DllCharacteristics: r.uint16le,
    SizeOfStackReserve: r.uint64le,
    SizeOfStackCommit: r.uint64le,
    SizeOfHeapReserve: r.uint64le,
    SizeOfHeapCommit: r.uint64le,
    LoaderFlags: r.uint32le,
    NumberOfRvaAndSizes: r.uint32le,

    ExportTable: IMAGE_DATA_DIRECTORY,
    ImportTable: IMAGE_DATA_DIRECTORY,
    ResourceTable: IMAGE_DATA_DIRECTORY,
    ExceptionTable: IMAGE_DATA_DIRECTORY,
    CertificateTable: IMAGE_DATA_DIRECTORY,
    BaseRelocationTable: IMAGE_DATA_DIRECTORY,
    Debug: IMAGE_DATA_DIRECTORY,
    Architecture: IMAGE_DATA_DIRECTORY,
    GlobalPtr: IMAGE_DATA_DIRECTORY,
    TLSTable: IMAGE_DATA_DIRECTORY,
    LoadConfigTable: IMAGE_DATA_DIRECTORY,
    BoundImport: IMAGE_DATA_DIRECTORY,
    IAT: IMAGE_DATA_DIRECTORY,
    DelayImportDescriptor: IMAGE_DATA_DIRECTORY,
    CLRRuntimeHeader: IMAGE_DATA_DIRECTORY,
    Reserved: IMAGE_DATA_DIRECTORY
});

const IMAGE_FILE_HEADER = new r.Struct({
    Machine: r.uint16le,
    NumberOfSections: r.uint16le,
    TimeDateStamp: r.uint32le,
    PointerToSymbolTable: r.uint32le,
    NumberOfSymbols: r.uint32le,
    SizeOfOptionalHeader: r.uint16le,
    Characteristics: r.uint16le,
});

const DataSectionFlags = new r.Enum(r.uint32le, {
    TypeReg: 0x00000000,
    TypeDsect: 0x00000001,
    TypeNoLoad: 0x00000002,
    TypeGroup: 0x00000004,
    TypeNoPadded: 0x00000008,
    TypeCopy: 0x00000010,
    ContentCode: 0x00000020,
    ContentInitializedData: 0x00000040,
    ContentUninitializedData: 0x00000080,
    LinkOther: 0x00000100,
    LinkInfo: 0x00000200,
    TypeOver: 0x00000400,
    LinkRemove: 0x00000800,
    LinkComDat: 0x00001000,
    NoDeferSpecExceptions: 0x00004000,
    RelativeGP: 0x00008000,
    MemPurgeable: 0x00020000,
    Memory16Bit: 0x00020000,
    MemoryLocked: 0x00040000,
    MemoryPreload: 0x00080000,
    Align1Bytes: 0x00100000,
    Align2Bytes: 0x00200000,
    Align4Bytes: 0x00300000,
    Align8Bytes: 0x00400000,
    Align16Bytes: 0x00500000,
    Align32Bytes: 0x00600000,
    Align64Bytes: 0x00700000,
    Align128Bytes: 0x00800000,
    Align256Bytes: 0x00900000,
    Align512Bytes: 0x00A00000,
    Align1024Bytes: 0x00B00000,
    Align2048Bytes: 0x00C00000,
    Align4096Bytes: 0x00D00000,
    Align8192Bytes: 0x00E00000,
    LinkExtendedRelocationOverflow: 0x01000000,
    MemoryDiscardable: 0x02000000,
    MemoryNotCached: 0x04000000,
    MemoryNotPaged: 0x08000000,
    MemoryShared: 0x10000000,
    MemoryExecute: 0x20000000,
    MemoryRead: 0x40000000,
    MemoryWrite: 0x80000000
});

const IMAGE_SECTION_HEADER = new r.Struct({
    Name: new r.String(8),
    VirtualSize: r.uint32le,
    VirtualAddress: r.uint32le,
    SizeOfRawData: r.uint32le,
    PointerToRawData: r.uint32le,
    PointerToRelocations: r.uint32le,
    PointerToLinenumbers: r.uint32le,
    NumberOfRelocations: r.uint16le,
    NumberOfLinenumbers: r.uint16le,
    Characteristics: DataSectionFlags
});

const IMAGE_DEBUG_DIRECTORY = new r.Struct({
    Characteristics: r.uint32le,
    TimeDateStamp: r.uint32le,
    MajorVersion: r.uint16le,
    MinorVersion: r.uint16le,
    Type: r.uint32le,
    SizeOfData: r.uint32le,
    AddressOfRawData: r.uint32le,
    PointerToRawData: r.uint32le
});

const IMAGE_DEBUG_DIRECTORY_RAW = new r.Struct({
    format: new r.Array(r.uint8, 4),
    guid: new r.Array(r.uint8, 16),
    age: r.uint32le,
    name: new r.String() // 255
});

module.exports = function (buffer) {
    const stream = new r.DecodeStream(buffer);
    const dosHeader = IMAGE_DOS_HEADER.decode(stream);
    stream.pos = dosHeader.e_lfanew;

    const ntHeadersSignature = stream.readBuffer(4);

    const fileHeader = IMAGE_FILE_HEADER.decode(stream);
    
    const is32BitHeader = fileHeader.Machine === 0x14C; // 0x14C = X86

    let optionalHeader32;
    let optionalHeader64;
    if (is32BitHeader)
        optionalHeader32 = IMAGE_OPTIONAL_HEADER32.decode(stream);
    else
        optionalHeader64 = IMAGE_OPTIONAL_HEADER64.decode(stream);

    let offDebug = 0;
    let cbDebug = 0;
    let cbFromHeader = 0;
    let loopexit = false;

    cbDebug = is32BitHeader ? optionalHeader32.Debug.Size : optionalHeader64.Debug.Size;

    for (let headerNo = 0; headerNo < fileHeader.NumberOfSections; ++headerNo) {
        let header = IMAGE_SECTION_HEADER.decode(stream);

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

    stream.pos = offDebug;

    let debugInfo;
    while (cbDebug >= IMAGE_DEBUG_DIRECTORY.size()) {
        if (loopexit === false) {
            
            const imageDebugDirectory = IMAGE_DEBUG_DIRECTORY.decode(stream);
            const seekPosition = stream.pos;

            if (imageDebugDirectory.Type === 0x2) {
                stream.pos = imageDebugDirectory.PointerToRawData;
                debugInfo = IMAGE_DEBUG_DIRECTORY_RAW.decode(stream);
                loopexit = true;

                // Downloading logic for .NET native images
                if (debugInfo.name.indexOf(".ni.") !== -1) {
                    stream.pos = seekPosition;
                    loopexit = false;
                }
            }

            if ((imageDebugDirectory.PointerToRawData != 0) && (imageDebugDirectory.SizeOfData != 0) &&
                    (cbFromHeader < (imageDebugDirectory.PointerToRawData + imageDebugDirectory.SizeOfData))) {
                cbFromHeader = imageDebugDirectory.PointerToRawData + imageDebugDirectory.SizeOfData;
            }
        }

        cbDebug -= IMAGE_DEBUG_DIRECTORY.size();
    }

    if (loopexit) {
        const pdbName = debugInfo.name.split('\\').slice(-1)[0];
        const cabName = pdbName.replace(/.$/, '_');

        return 'http://msdl.microsoft.com/download/symbols/' + pdbName + '/' +
            [3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15]
                .map(x => (debugInfo.guid[x] + 0x100).toString(16).toUpperCase().slice(1, 3)).join('') +
            debugInfo.age + '/' + cabName;
    }
}