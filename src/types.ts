import BigNumber from 'bignumber.js';

export const IMAGE_SIZEOF_SHORT_NAME = 8;

export const IMAGE_OPTIONAL_HEADER_MAGIC32 = 0x010B;
export const IMAGE_OPTIONAL_HEADER_MAGIC64 = 0x020b;

/**
 * IMAGE_FILE_HEADER
 *
 * size: 20 bytes
 */
export interface IImageFileHeader {
  /* WORD */ machine: number;
  /* WORD */ numberOfSections: number;
  /* DWORD */ timeDateStamp: number;
  /* DWORD */ pointerToSymbolTable: number;
  /* DWORD */ numberOfSymbols: number;
  /* WORD */ sizeOfOptionalHeader: number;
  /* WORD */ characteristics: number;
}

export interface IImageSectionHeader {
  /* BYTE[IMAGE_SIZEOF_SHORT_NAME = 8] */ name: string;
  /* union { */
  /* DWORD */ physicalAddress: number;
  /* DWORD */ virtualSize: number;
  /* } Misc */
  /* DWORD */ virtualAddress: number;
  /* DWORD */ sizeOfRawData: number;
  /* DWORD */ pointerToRawData: number;
  /* DWORD */ pointerToRelocations: number;
  /* DWORD */ pointerToLinenumbers: number;
  /* WORD */ numberOfRelocations: number;
  /* WORD */ numberOfLinenumbers: number;
  /* DWORD */ characteristics: number;
}

export interface IImageOptionHeader {
  /* WORD */ magic: number;
  /* BYTE */ majorLinkerVersion: number;
  /* BYTE */ minorLinkerVersion: number;
  /* DWORD */ sizeOfCode: number;
  /* DWORD */ sizeOfInitializedData: number;
  /* DWORD */ sizeOfUninitializedData: number;
  /* DWORD */ addressOfEntryPoint: number;
  /* DWORD */ baseOfCode: number;
  /* DWORD */ baseOfData: number; /* IMAGE_OPTIONAL_HEADER32 */ only
  /* PVOID */ imageBase: BigNumber;
  /* DWORD */ sectionAlignment: number;
  /* DWORD */ fileAlignment: number;
  /* WORD */ majorOperatingSystemVersion: number;
  /* WORD */ minorOperatingSystemVersion: number;
  /* WORD */ majorImageVersion: number;
  /* WORD */ minorImageVersion: number;
  /* WORD */ majorSubsystemVersion: number;
  /* WORD */ minorSubsystemVersion: number;
  /* DWORD */ win32VersionValue: number;
  /* DWORD */ sizeOfImage: number;
  /* DWORD */ sizeOfHeaders: number;
  /* DWORD */ checkSum: number;
  /* WORD */ subsystem: number;
  /* WORD */ dllCharacteristics: number;
  /* PVOID */ sizeOfStackReserve: BigNumber;
  /* PVOID */ sizeOfStackCommit: BigNumber;
  /* PVOID */ sizeOfHeapReserve: BigNumber;
  /* PVOID */ sizeOfHeapCommit: BigNumber;
  /* DWORD */ loaderFlags: number;
  /* DWORD */ numberOfRvaAndSizes: number;
}
