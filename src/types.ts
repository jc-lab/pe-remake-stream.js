export const IMAGE_SIZEOF_SHORT_NAME = 8;

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
