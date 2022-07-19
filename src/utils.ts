import BigNumber from 'bignumber.js';
import {
  IImageFileHeader, IImageOptionHeader, IImageSectionHeader, IMAGE_OPTIONAL_HEADER_MAGIC32, IMAGE_SIZEOF_SHORT_NAME
} from './types';

export function writeInt32ToBuffer(buffer: Buffer, offset: number, value: number) {
  buffer[offset] = value & 0xff;
  buffer[offset + 1] = (value >>> 8) & 0xff;
  buffer[offset + 2] = (value >>> 16) & 0xff;
  buffer[offset + 3] = (value >>> 24) & 0xff;
}

const c_2 = Object.freeze(new BigNumber(2));

export function readUint16FromBuffer(buffer: Buffer, offset: number): number {
  let out = buffer[offset] & 0xff;
  out |= (buffer[offset + 1] & 0xff) << 8;
  return out;
}

export function readUint32FromBuffer(buffer: Buffer, offset: number): number {
  let out = buffer[offset] & 0xff;
  out |= (buffer[offset + 1] & 0xff) << 8;
  out |= (buffer[offset + 2] & 0xff) << 16;
  out |= (buffer[offset + 3] & 0xff) << 24;
  return out;
}

export function readUint32BNFromBuffer(buffer: Buffer, offset: number): BigNumber {
  let out = new BigNumber(buffer[offset] & 0xff);
  out = out.plus((buffer[offset + 1] & 0xff) << 8);
  out = out.plus((buffer[offset + 2] & 0xff) << 16);
  out = out.plus((buffer[offset + 3] & 0xff) << 24);
  return out;
}

export function readUint64BNFromBuffer(buffer: Buffer, offset: number): BigNumber {
  let out = readUint32BNFromBuffer(buffer, offset);
  out = out.plus(new BigNumber(buffer[offset + 4] & 0xff).multipliedBy(c_2.pow(32)));
  out = out.plus(new BigNumber(buffer[offset + 5] & 0xff).multipliedBy(c_2.pow(40)));
  out = out.plus(new BigNumber(buffer[offset + 6] & 0xff).multipliedBy(c_2.pow(48)));
  out = out.plus(new BigNumber(buffer[offset + 7] & 0xff).multipliedBy(c_2.pow(56)));
  return out;
}

export function parseImageFileHeader(buffer: Buffer, offset: number): IImageFileHeader {
  return {
    machine: readUint16FromBuffer(buffer, offset),
    numberOfSections: readUint16FromBuffer(buffer, offset),
    timeDateStamp: readUint32FromBuffer(buffer, offset),
    pointerToSymbolTable: readUint32FromBuffer(buffer, offset),
    numberOfSymbols: readUint32FromBuffer(buffer, offset),
    sizeOfOptionalHeader: readUint16FromBuffer(buffer, offset),
    characteristics: readUint16FromBuffer(buffer, offset)
  };
}

export function parseImageSectionHeader(buffer: Buffer, offset: number): IImageSectionHeader | false {
  let position = offset;
  const nameBuffer = buffer.slice(offset, offset + IMAGE_SIZEOF_SHORT_NAME);
  position += IMAGE_SIZEOF_SHORT_NAME;

  let nameLength = nameBuffer.indexOf(0);
  if (nameLength < 0) {
    nameLength = nameBuffer.length;
  }

  const name = nameBuffer.subarray(0, nameLength).toString('utf-8');
  if (name.length <= 0) return false;

  return {
    name,
    /* union { */
    physicalAddress: readUint32FromBuffer(buffer, position),
    virtualSize: readUint32FromBuffer(buffer, position),
    /* } Misc */
    /* DWORD */ virtualAddress: readUint32FromBuffer(buffer, position + 4),
    /* DWORD */ sizeOfRawData: readUint32FromBuffer(buffer, position + 8),
    /* DWORD */ pointerToRawData: readUint32FromBuffer(buffer, position + 12),
    /* DWORD */ pointerToRelocations: readUint32FromBuffer(buffer, position + 16),
    /* DWORD */ pointerToLinenumbers: readUint32FromBuffer(buffer, position + 20),
    /* WORD */ numberOfRelocations: readUint16FromBuffer(buffer, position + 24),
    /* WORD */ numberOfLinenumbers: readUint16FromBuffer(buffer, position + 26),
    /* DWORD */ characteristics: readUint32FromBuffer(buffer, position + 28)
  };
}

export function parseImageOptionalHeader(buffer: Buffer, offset: number, magic: number): IImageOptionHeader {
  let position = offset;
  const result: IImageOptionHeader = {} as any;
  result.magic = magic;
  result.majorLinkerVersion = buffer[position + 0];
  result.minorLinkerVersion = buffer[position + 1];
  result.sizeOfCode = readUint32FromBuffer(buffer, position + 2);
  result.sizeOfInitializedData = readUint32FromBuffer(buffer, position + 6);
  result.sizeOfUninitializedData = readUint32FromBuffer(buffer, position + 10);
  result.addressOfEntryPoint = readUint32FromBuffer(buffer, position + 14);
  result.baseOfCode = readUint32FromBuffer(buffer, position + 18);
  if (result.magic === IMAGE_OPTIONAL_HEADER_MAGIC32) {
    result.baseOfData = readUint32FromBuffer(buffer, position + 22);
    result.imageBase = new BigNumber(readUint32FromBuffer(buffer, position + 26));
  } else {
    result.imageBase = readUint64BNFromBuffer(buffer, position + 22);
  }
  result.sectionAlignment = readUint32FromBuffer(buffer, position + 30);
  result.fileAlignment = readUint32FromBuffer(buffer, position + 34);
  result.majorOperatingSystemVersion = readUint16FromBuffer(buffer, position + 38);
  result.minorOperatingSystemVersion = readUint16FromBuffer(buffer, position + 40);
  result.majorImageVersion = readUint16FromBuffer(buffer, position + 42);
  result.minorImageVersion = readUint16FromBuffer(buffer, position + 44);
  result.majorSubsystemVersion = readUint16FromBuffer(buffer, position + 46);
  result.minorSubsystemVersion = readUint16FromBuffer(buffer, position + 48);
  result.win32VersionValue = readUint32FromBuffer(buffer, position + 50);
  result.sizeOfImage = readUint32FromBuffer(buffer, position + 54);
  result.sizeOfHeaders = readUint32FromBuffer(buffer, position + 58);
  result.checkSum = readUint32FromBuffer(buffer, position + 62);
  result.subsystem = readUint16FromBuffer(buffer, position + 66);
  result.dllCharacteristics = readUint16FromBuffer(buffer, position + 68);
  position += 70;

  if (result.magic === IMAGE_OPTIONAL_HEADER_MAGIC32) {
    result.sizeOfStackReserve = readUint32BNFromBuffer(buffer, position); position += 4;
    result.sizeOfStackCommit = readUint32BNFromBuffer(buffer, position); position += 4;
    result.sizeOfHeapReserve = readUint32BNFromBuffer(buffer, position); position += 4;
    result.sizeOfHeapCommit = readUint32BNFromBuffer(buffer, position); position += 4;
  } else {
    result.sizeOfStackReserve = readUint64BNFromBuffer(buffer, position); position += 8;
    result.sizeOfStackCommit = readUint64BNFromBuffer(buffer, position); position += 8;
    result.sizeOfHeapReserve = readUint64BNFromBuffer(buffer, position); position += 8;
    result.sizeOfHeapCommit = readUint64BNFromBuffer(buffer, position); position += 8;
  }

  result.loaderFlags = readUint32FromBuffer(buffer, position); position += 4;
  result.numberOfRvaAndSizes = readUint32FromBuffer(buffer, position); position += 4;

  return result;
}

export class RWBuffer {
  public readonly buffer: Buffer | null;
  public readPositionHandler: ((size) => void) | null = null;
  public writePositionHandler: ((size) => void) | null = null;
  public size: number = 0;

  private _readPosition: number = 0;
  private _writePosition: number = 0;

  constructor(buffer: Buffer | null, size?: number) {
    this.buffer = buffer;
    this.size = size || buffer && buffer.length || 0;
  }

  public get hasBuffer(): boolean {
    return !!this.buffer;
  }

  public get readRemaining(): number {
    return this.size - this._readPosition;
  }

  public get writeRemaining(): number {
    return this.size - this._writePosition;
  }

  private _incrementReadPosition(size: number) {
    this._readPosition += size;
    if (this.readPositionHandler) {
      this.readPositionHandler(size);
    }
  }

  private _incrementWritePosition(size: number) {
    this._writePosition += size;
    if (this.writePositionHandler) {
      this.writePositionHandler(size);
    }
  }

  public writeWithCopyFrom(src: RWBuffer, size?: number): Buffer;
  public writeWithCopyFrom(src: RWBuffer, copyBuffer: Buffer): number;
  public writeWithCopyFrom(src: RWBuffer, size: number, copyBuffer: Buffer): number;
  public writeWithCopyFrom(src: RWBuffer, sizeOrCopyBuffer?: number | Buffer, copyBuffer?: Buffer): Buffer | number {
    let avail = Math.min(src.readRemaining, this.writeRemaining);
    let returnIsSize = false;
    let _copyBuffer: Buffer;
    if (typeof sizeOrCopyBuffer === 'number') {
      avail = Math.min(avail, sizeOrCopyBuffer);
      if (copyBuffer) {
        returnIsSize = true;
        _copyBuffer = copyBuffer;
      } else {
        _copyBuffer = Buffer.alloc(avail);
      }
    } else if (sizeOrCopyBuffer) {
      returnIsSize = true;
      _copyBuffer = sizeOrCopyBuffer;
    } else {
      _copyBuffer = Buffer.alloc(avail);
    }
    if (src.buffer) {
      src.buffer.copy(_copyBuffer, 0, src._readPosition, src._readPosition + avail);
      if (this.buffer) {
        src.buffer.copy(this.buffer, this._writePosition, src._readPosition, src._readPosition + avail);
      }
    }
    src._incrementReadPosition(avail);
    this._incrementWritePosition(avail);
    return returnIsSize ? avail : _copyBuffer;
  }

  public writeFrom(src: RWBuffer, size?: number): number {
    let avail = Math.min(src.readRemaining, this.writeRemaining);
    if (typeof size !== 'undefined') {
      avail = Math.min(avail, size);
    }
    if (this.buffer && src.buffer) {
      src.buffer.copy(this.buffer, this._writePosition, src._readPosition, src._readPosition + avail);
    }
    src._incrementReadPosition(avail);
    this._incrementWritePosition(avail);
    return avail;
  }

  public writeFromBuffer(src: Buffer, offset: number, size?: number): number {
    let avail = Math.min(src.length, this.writeRemaining);
    if (typeof size !== 'undefined') {
      avail = Math.min(avail, size);
    }
    if (this.buffer) {
      src.copy(this.buffer, this._writePosition, offset, offset + avail);
    }
    this._incrementWritePosition(avail);
    return avail;
  }

  public readInt16At(absPos: number): number {
    if (!this.buffer) throw new Error('buffer is null');
    let value = this.buffer[absPos] & 0xFF;
    value |= (this.buffer[absPos + 1] & 0xFF) << 8;
    return value;
  }

  public readInt32At(absPos: number): number {
    if (!this.buffer) throw new Error('buffer is null');
    let value = this.buffer[absPos] & 0xFF;
    value |= (this.buffer[absPos + 1] & 0xFF) << 8;
    value |= (this.buffer[absPos + 2] & 0xFF) << 16;
    value |= (this.buffer[absPos + 3] & 0xFF) << 24;
    return value;
  }

  public getRemainBuffer(size?: number): Buffer {
    const specificSize = typeof size !== 'undefined';
    const readSize = (typeof size !== 'undefined') ? size : this.readRemaining;

    if (!this.buffer) {
      throw new Error('Illegal state');
    }

    if (this._readPosition === 0 && !specificSize) {
      this._incrementReadPosition(this.readRemaining);
      return this.buffer;
    }

    const buf = this.buffer.slice(this._readPosition, this._readPosition + readSize);
    this._incrementReadPosition(readSize);
    return buf;
  }
}
