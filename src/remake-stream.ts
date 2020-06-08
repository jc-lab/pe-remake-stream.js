import * as streams from 'stream';
import BigNumber from 'bignumber.js';

import {
  RWBuffer,
  parseImageFileHeader,
  readUint32BNFromBuffer,
  readUint32FromBuffer,
  writeInt32ToBuffer, parseImageSectionHeader
} from './utils';
import {
  IImageFileHeader, IImageSectionHeader
} from './types';

enum ReadStatus {
  DOS_HEADER,
  BEFORE_PE,
  NT_HEADER,
  OPTIONAL_HEADER_A,
  OPTIONAL_HEADER_B,
  DATA_DIRECTORIES_A,
  DATA_DIRECTORIES_B,
  IMAGE_SECTION_HEADER,
  MIDDLE_PAYLOAD
}

enum ReadFlag {
  DUMMY = (1 << 0),
  PASSTHROUGH = (1 << 1),
}

const CONST_MZ = Buffer.from('MZ'.split('').map(v => v.charCodeAt(0)));
const CONST_PE = Buffer.from('PE'.split('').map(v => v.charCodeAt(0)));

export enum DataDirectoryType {
  ExportTable = 0,
  ImportTable = 1,
  ResourceTable = 2,
  ExceptionTable = 3,
  CertificateTable = 4,
  RelocationTable = 5,
  DebugData = 6,
  ArchitectureData = 7,
  MachineValue = 8,
  TLSTable = 9,
  LoadConfigurationTable = 10,
  BoundImportTable = 11,
  ImportAddressTable = 12,
  DelayImportDescriptor = 13,
  COMRuntimeHeader = 14,
  Reserved = 15
}

export interface IDataDirectory {
  type: DataDirectoryType;
  address: number;
  size: number;
}

export interface ITableData {
  type: DataDirectoryType;
  address: number;
  size: number;
  data: Buffer;
}

function isInRange(value: number, begin: number, end: number) {
  return ((begin <= value) && (value < end));
}

enum RangeCheckResult {
  OVER_TARGET_BEGIN = 0x01,
  OVER_TARGET_END = 0x02,
}
function isRangeInRange(bufferPosition: number, bufferEnd: number, targetBegin: number, targetEnd: number): RangeCheckResult {
  const a = isInRange(bufferPosition, targetBegin, targetEnd);
  const b = isInRange(bufferEnd, targetBegin, targetEnd);
  return (a && RangeCheckResult.OVER_TARGET_BEGIN || 0) | (b && RangeCheckResult.OVER_TARGET_END || 0);
}

export interface IPERemakeStreamEvents {
  emit(event: 'data-directories', item: IDataDirectory[], next: (replaced?: IDataDirectory[]) => void): boolean;
  on(event: 'data-directories', listener: (item: IDataDirectory[], next: (replaced?: IDataDirectory[]) => void) => void): this;

  emit(event: 'before-table', type: IDataDirectory, next: (buffering?: boolean) => void): boolean;
  on(event: 'before-table', listener: (type: IDataDirectory, next: (buffering?: boolean) => void) => void): this;

  emit(event: 'table', table: ITableData, next: () => void): boolean;
  on(event: 'table', listener: (table: ITableData, next: () => void) => void): this;

  emit(event: 'before-finish', next: () => void): boolean;
  on(event: 'before-finish', listener: (next: () => void) => void): this;
}

export class PERemakeStream extends streams.Transform implements IPERemakeStreamEvents {
  private _filePosition: number = 0;

  private _state!: ReadStatus;
  private _componentBuffer: RWBuffer | null = null;
  private _readFlags: ReadFlag = 0;

  private _lastProcessingBuffer: RWBuffer | null = null;
  private _runningBuffers: Buffer[] = [];

  private _imageFileHeader!: IImageFileHeader;

  private _peOffset: number = -1;
  private _optionalHeaderMagic: number = -1;
  private _optionalHeader!: Buffer;

  private _imageSectionHeader!: IImageSectionHeader;

  private _imageBase!: BigNumber;

  private _remainingDataDirectories: IDataDirectory[] = [];

  constructor(streamOpts?: streams.TransformOptions) {
    super(streamOpts);
    this._startReadComponent(ReadStatus.DOS_HEADER, 64, ReadFlag.PASSTHROUGH);
  }

  private _startReadComponent(state: ReadStatus, size: number, flags?: ReadFlag) {
    const _flags = flags || 0;
    this._state = state;
    if (_flags & ReadFlag.DUMMY) {
      if (size > 0) {
        this._componentBuffer = new RWBuffer(null, size);
      } else {
        this._componentBuffer = null;
      }
    } else {
      this._componentBuffer = new RWBuffer(Buffer.alloc(size));
    }
    this._readFlags = _flags;
  }

  /**
   * _readRemainingPayload
   *
   * @param chunkBuffer
   * @return is read completed
   */
  private _readRemainingPayload(chunkBuffer: RWBuffer): boolean {
    if (this._readFlags & ReadFlag.PASSTHROUGH) {
      const buf = this._componentBuffer?.writeWithCopyFrom(chunkBuffer);
      this.push(buf);
    } else {
      this._componentBuffer?.writeFrom(chunkBuffer);
    }
    return (this._componentBuffer?.writeRemaining === 0);
  }

  private _setReadFlag(flag: ReadFlag) {
    this._readFlags |= flag;
  }

  private _clearReadFlag(flag: ReadFlag) {
    this._readFlags &= ~flag;
  }

  private rvaToRaw(rva: number): number {
    // return new BigNumber(rva)
    //   .minus(this._imageSectionHeader.virtualAddress)
    //   .plus(this._imageSectionHeader.pointerToRawData)
    // ;
    return rva - this._imageSectionHeader.virtualAddress + this._imageSectionHeader.pointerToRawData;
  }

  private _verifyDosHeader(): Error | null {
    const buf = this._componentBuffer?.buffer as Buffer;
    if (buf.length != 64) {
      return new Error(`PE Header verification failed: incorrect size (correct=64, current=${buf.length})`);
    }
    if (CONST_MZ.compare(buf, 0, CONST_MZ.length) != 0) {
      return new Error(
        `DOS Header verification failed: incorrect size (correct=[${
          [CONST_MZ[0], CONST_MZ[1]].map(v => v.toString(16))
        }], current=${
          [buf[0], buf[1]].map(v => v.toString(16))
        })`
      );
    }
    return null;
  }

  private _verifyNtHeader(): Error | null {
    const buf = this._componentBuffer?.buffer as Buffer;
    if (buf.length != 24) {
      return new Error(`PE Header verification failed: incorrect size (correct=64, current=${buf.length})`);
    }
    if (CONST_PE.compare(buf, 0, CONST_PE.length) != 0) {
      return new Error(
        `NT Header verification failed: incorrect size (correct=[${
          [CONST_PE[0], CONST_PE[1]].map(v => v.toString(16))
        }], current=${
          [buf[0], buf[1]].map(v => v.toString(16))
        })`
      );
    }
    return null;
  }

  private _pushReplacedDataDirectories(dataDirectories: IDataDirectory[]) {
    const buf = Buffer.alloc(16 * 8);
    dataDirectories.forEach(item => {
      const position = item.type;
      writeInt32ToBuffer(buf, position * 8, item.address);
      writeInt32ToBuffer(buf, position * 8 + 4, item.size);
    });
    this.push(buf);
  }

  private _processDataDirectories(next: streams.TransformCallback) {
    const componentBuffer: RWBuffer = this._componentBuffer as RWBuffer;
    const dataDirectories: IDataDirectory[] = [];
    for (let index = 0; index < 16; index++) {
      const position = index * 8;
      const address = componentBuffer.readInt32At(position);
      const size = componentBuffer.readInt32At(position + 4);
      dataDirectories.push({
        type: index as DataDirectoryType,
        address,
        size
      });
    }

    this._remainingDataDirectories = dataDirectories
      .filter(v => v.address && v.size)
      .sort((x, y) => {
        if (x.address > y.address) {
          return 1;
        } else if (x.address < y.address) {
          return -1;
        } else {
          return 0;
        }
      });

    const writeCallback = (replaced: IDataDirectory[]) => {
      this._pushReplacedDataDirectories(replaced || dataDirectories);
      const lastProcessingBuffer = this._lastProcessingBuffer as RWBuffer;
      this._state = ReadStatus.DATA_DIRECTORIES_B;
      if (this.isPaused()) {
        this.resume();
      }
      this._proecssBuffer(lastProcessingBuffer, next);
    };
    const paused = !this.isPaused();
    if (paused) {
      this.pause();
    }
    if (this.emit('data-directories', dataDirectories, writeCallback)) {
      if (paused) {
        this.resume();
      }
      return true;
    } else {
      this._pushReplacedDataDirectories(dataDirectories);
      return false;
    }
  }

  private _checkAndPause(chunkBuffer: RWBuffer): boolean {
    const state = !this.isPaused();
    this._lastProcessingBuffer = chunkBuffer;
    if (state) {
      this.pause();
    }
    return state;
  }
  private _checkAndResume(state: boolean, next?: () => void): void {
    if (state) {
      this.resume();
    }
    const lastProcessingBuffer = this._lastProcessingBuffer as RWBuffer;
    this._lastProcessingBuffer = null;
    if (next) {
      this._proecssBuffer(lastProcessingBuffer, next);
    }
  }

  private _readingTableDirectory: IDataDirectory | null = null;
  private _readingTableBuffer!: RWBuffer;
  private _proecssBuffer(chunkBuffer: RWBuffer, next: streams.TransformCallback) {
    const loopCount = 0;
    while (chunkBuffer.readRemaining > 0) {
      if (!this._componentBuffer && (this._readFlags & ReadFlag.PASSTHROUGH)) {
        const currentDataDirectory = (this._remainingDataDirectories.length > 0) && this._remainingDataDirectories[0];
        const rawAddress = (currentDataDirectory && this.rvaToRaw(currentDataDirectory.address)) as number;
        const testResult = currentDataDirectory && isRangeInRange(rawAddress, rawAddress + currentDataDirectory.size, this._filePosition, this._filePosition + chunkBuffer.readRemaining);
        if (currentDataDirectory && testResult) {
          if (!this._readingTableDirectory) {
            // Start read table
            const paused = this._checkAndPause(chunkBuffer);
            const callback = (buffering?: boolean) => {
              this._readingTableBuffer = new RWBuffer(
                buffering && Buffer.alloc(currentDataDirectory.size) || null,
                currentDataDirectory.size
              );
              this._checkAndResume(paused, next);
            };
            this._readingTableDirectory = currentDataDirectory;
            if (this.emit('before-table', currentDataDirectory, callback)) {
              return ;
            }
            this._readingTableBuffer = new RWBuffer(
              null,
              currentDataDirectory.size
            );
            this._checkAndResume(paused);
          } else {
            const midBegin = Math.max(this._filePosition, currentDataDirectory.address);
            const midEnd = Math.max(this._filePosition + chunkBuffer.readRemaining, rawAddress + currentDataDirectory.size);
            const midSize = midEnd - midBegin;
            const skipLength = midBegin - this._filePosition;
            if (skipLength > 0) {
              this.push(chunkBuffer.getRemainBuffer(skipLength));
            }
            if (!this._readingTableBuffer.hasBuffer) {
              this.push(
                this._readingTableBuffer.writeWithCopyFrom(chunkBuffer, midSize)
              );
            } else {
              this._readingTableBuffer.writeFrom(chunkBuffer, midSize);
            }
            if (this._readingTableBuffer.writeRemaining === 0) {
              if (this._readingTableBuffer.hasBuffer) {
                const paused = this._checkAndPause(chunkBuffer);
                const data = this._readingTableBuffer.buffer as Buffer;
                const table: ITableData = {
                  ...this._readingTableDirectory,
                  data
                };
                const callback = () => {
                  this.push(data);
                  (this as any)._readingTableBuffer = null;
                  this._readingTableDirectory = null;
                  this._remainingDataDirectories.shift();
                  this._checkAndResume(paused, next);
                };
                if (this.emit('table', table, callback)) {
                  return;
                }
                this.push(data);
                this._checkAndResume(paused);
              }
              (this as any)._readingTableBuffer = null;
              this._readingTableDirectory = null;
              this._remainingDataDirectories.shift();
            }
          }
        } else {
          this.push(chunkBuffer.getRemainBuffer());
        }
      } else {
        if (this._readRemainingPayload(chunkBuffer)) {
          const componentBuffer: RWBuffer = this._componentBuffer as RWBuffer;
          let err: any = null;

          switch (this._state) {
          case ReadStatus.DOS_HEADER:
            this._peOffset = componentBuffer?.readInt32At(60);

            if ((err = this._verifyDosHeader())) {
              this.destroy(err);
              break;
            }

            this._startReadComponent(
              ReadStatus.BEFORE_PE,
              this._peOffset - this._filePosition,
              ReadFlag.DUMMY | ReadFlag.PASSTHROUGH
            );
            break;

          case ReadStatus.BEFORE_PE:
            this._startReadComponent(
              ReadStatus.NT_HEADER,
              24,
              ReadFlag.PASSTHROUGH
            );
            break;

          case ReadStatus.NT_HEADER:
            if ((err = this._verifyNtHeader())) {
              break;
            }
            this._imageFileHeader = parseImageFileHeader(componentBuffer.buffer as Buffer, 0);
            this._startReadComponent(
              ReadStatus.OPTIONAL_HEADER_A,
              2,
              ReadFlag.PASSTHROUGH
            );
            break;

          case ReadStatus.OPTIONAL_HEADER_A:
            this._optionalHeaderMagic = componentBuffer.readInt16At(0);
            this._runningBuffers = [
              componentBuffer.buffer as Buffer
            ];
            if (this._optionalHeaderMagic == 0x010B) {
              this._startReadComponent(
                ReadStatus.OPTIONAL_HEADER_B,
                94,
                ReadFlag.PASSTHROUGH
              );
            } else if (this._optionalHeaderMagic == 0x020b) {
              this._startReadComponent(
                ReadStatus.OPTIONAL_HEADER_B,
                110,
                ReadFlag.PASSTHROUGH
              );
            } else {
              err = new Error(`Optional Header verification failed: unknown magic=${this._optionalHeaderMagic.toString(16)}`);
            }

            break;

          case ReadStatus.OPTIONAL_HEADER_B:
            this._runningBuffers.push(componentBuffer.buffer as Buffer);
            this._optionalHeader = Buffer.concat(this._runningBuffers);

            if (this._optionalHeaderMagic == 0x010B) {
              this._imageBase = readUint32BNFromBuffer(componentBuffer.buffer as Buffer, 28);
              this._startReadComponent(
                ReadStatus.OPTIONAL_HEADER_B,
                94,
                ReadFlag.DUMMY | ReadFlag.PASSTHROUGH
              );
            } else if (this._optionalHeaderMagic == 0x020b) {
              this._imageBase = readUint32BNFromBuffer(componentBuffer.buffer as Buffer, 24);
              this._startReadComponent(
                ReadStatus.OPTIONAL_HEADER_B,
                110,
                ReadFlag.DUMMY | ReadFlag.PASSTHROUGH
              );
            }

            this._startReadComponent(
              ReadStatus.DATA_DIRECTORIES_A,
              8 * 16
            );
            break;

          case ReadStatus.DATA_DIRECTORIES_A:
            this._lastProcessingBuffer = chunkBuffer;
            if (this._processDataDirectories(next)) {
              return;
            }
            this._lastProcessingBuffer = null;
            this._state = ReadStatus.DATA_DIRECTORIES_B;
            break;

          case ReadStatus.DATA_DIRECTORIES_B:
            this._startReadComponent(
              ReadStatus.IMAGE_SECTION_HEADER,
              40,
              ReadFlag.PASSTHROUGH
            );
            break;

          case ReadStatus.IMAGE_SECTION_HEADER:
            this._imageSectionHeader = parseImageSectionHeader(componentBuffer.buffer as Buffer, 0);
            this._startReadComponent(
              ReadStatus.MIDDLE_PAYLOAD,
              -1,
              ReadFlag.DUMMY | ReadFlag.PASSTHROUGH
            );
            break;
          }

          if (err) {
            this.destroy(err);
            return;
          }
        }
      }
    }
    next();
  }

  _transform(chunk: Buffer, encoding: string, callback: streams.TransformCallback) {
    const chunkBuffer = new RWBuffer(chunk);
    chunkBuffer.readPositionHandler = (size) => {
      this._filePosition += size;
    };
    this._proecssBuffer(chunkBuffer, callback);
  }


  _final(callback: (error?: (Error | null)) => void) {
    const nextCallback = () => {
      callback();
    };
    if (!this.emit('before-finish', nextCallback)) {
      nextCallback();
    }
  }
}

export default function create(streamOpts?: streams.TransformOptions): PERemakeStream {
  return new PERemakeStream(streamOpts);
}
