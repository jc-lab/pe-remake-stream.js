import * as streams from 'stream';
import BigNumber from 'bignumber.js';

import {
  RWBuffer,
  parseImageFileHeader,
  readUint32BNFromBuffer,
  readUint32FromBuffer,
  writeInt32ToBuffer, parseImageSectionHeader, parseImageOptionalHeader
} from './utils';
import {
  IImageFileHeader,
  IImageOptionHeader,
  IImageSectionHeader,
  IMAGE_OPTIONAL_HEADER_MAGIC32,
  IMAGE_OPTIONAL_HEADER_MAGIC64
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
  HEADER_FOOTER,
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

interface ImageSectionReadContext extends IImageSectionHeader {
  position: number;
}

interface TableReadContext {
  dataDirectory: IDataDirectory;
  buffer: RWBuffer;
}

export interface IPERemakeStreamEvents {
  emit(event: 'data-directories', item: IDataDirectory[], next: (replaced?: IDataDirectory[]) => void): boolean;
  on(event: 'data-directories', listener: (item: IDataDirectory[], next: (replaced?: IDataDirectory[]) => void) => void): this;

  emit(event: 'table', table: ITableData): boolean;
  on(event: 'table', listener: (table: ITableData) => void): this;

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
  private _imageOptionalHeader!: IImageOptionHeader;

  private _peOffset: number = -1;
  private _optionalHeaderMagic: number = -1;
  private _optionalHeader!: Buffer;

  private _imageSectionHeaders: Record<string, IImageSectionHeader> = {};
  private _remainingImageSections: IImageSectionHeader[] = [];
  private _readingImageSection: ImageSectionReadContext | null = null;

  private _tables: Record<DataDirectoryType, TableReadContext> = {} as any;

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

  private rvaToRaw(sectionHeader: IImageSectionHeader, rva: number): number {
    return rva - sectionHeader.virtualAddress + sectionHeader.pointerToRawData;
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
    const count = this._imageOptionalHeader.numberOfRvaAndSizes || 16;
    for (let index = 0; index < count; index++) {
      const position = index * 8;
      const address = componentBuffer.readInt32At(position);
      const size = componentBuffer.readInt32At(position + 4);
      dataDirectories.push({
        type: index as DataDirectoryType,
        address,
        size
      });
    }

    this._tables = dataDirectories
      .filter((v) => v.address && v.size)
      .map((v) => {
        return {
          dataDirectory: v,
          buffer: new RWBuffer(Buffer.alloc(v.size), v.size),
        } as TableReadContext;
      }) as any;

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

  private _proecssBuffer(chunkBuffer: RWBuffer, next: streams.TransformCallback) {
    while (chunkBuffer.readRemaining > 0) {
      if (!this._componentBuffer && (this._readFlags & ReadFlag.PASSTHROUGH)) {
        const certificateTable = Object.values(this._tables)
          .find(v => v.dataDirectory.type === DataDirectoryType.CertificateTable && v.dataDirectory.address);

        let tmpCurrentSection: ImageSectionReadContext | null = null;

        const screenedPosition = this._filePosition;
        let screenedBuffer!: Buffer;

        if (this._readingImageSection) {
          tmpCurrentSection = this._readingImageSection;
        } else {
          const firstSection = (this._remainingImageSections.length > 0) && this._remainingImageSections[0];
          const sectionTestResult = firstSection && isRangeInRange(
            firstSection.pointerToRawData,
            firstSection.pointerToRawData + firstSection.sizeOfRawData,
            this._filePosition,
            this._filePosition + chunkBuffer.readRemaining
          );
          if (firstSection && sectionTestResult) {
            tmpCurrentSection = {
              ...firstSection,
              position: 0,
            };
            this._readingImageSection = tmpCurrentSection;
          }
        }

        if (tmpCurrentSection) {
          const nextSection = (this._remainingImageSections.length > 1) && this._remainingImageSections[1];
          const currentSection = tmpCurrentSection;
          const sectionRemaining = currentSection.sizeOfRawData - currentSection.position;
          const sectionChunkSize = Math.min(chunkBuffer.readRemaining, sectionRemaining);
          const sectionStart = currentSection.virtualAddress;
          const sectionEnd = nextSection ? nextSection.virtualAddress : (currentSection.virtualAddress + currentSection.sizeOfRawData);
          const sectionChunkBuffer = chunkBuffer.getRemainBuffer(sectionChunkSize);
          const sectionVirtualPosition = currentSection.virtualAddress + currentSection.position;

          this.push(sectionChunkBuffer);
          screenedBuffer = sectionChunkBuffer;

          Object.values(this._tables)
            .filter((v) => {
              return v.dataDirectory.type !== DataDirectoryType.CertificateTable && sectionStart <= v.dataDirectory.address && v.dataDirectory.address <= sectionEnd;
            })
            .forEach((v) => {
              let readPosition = 0;
              if (sectionVirtualPosition < v.dataDirectory.address) {
                const skipLength = v.dataDirectory.address - sectionVirtualPosition;
                if (skipLength >= sectionChunkSize) {
                  return ;
                }
                readPosition = skipLength;
              } else if (v.buffer.writeRemaining === 0) {
                return ;
              }

              const tableAvail = Math.min(sectionChunkSize - readPosition, v.buffer.writeRemaining);
              v.buffer.writeFromBuffer(sectionChunkBuffer, readPosition, tableAvail);
              if (v.buffer.writeRemaining === 0) {
                const table: ITableData = {
                  ...v.dataDirectory,
                  data: v.buffer.buffer as Buffer,
                };
                this.emit('table', table);
              }
            });

          currentSection.position += sectionChunkSize;
          if (currentSection.position === currentSection.sizeOfRawData) {
            this._readingImageSection = null;
            this._remainingImageSections.shift();
          }
        } else {
          const buffer = chunkBuffer.getRemainBuffer();
          screenedBuffer = buffer;
          this.push(buffer);
        }

        if (certificateTable) {
          do {
            let readPosition = 0;
            if (screenedPosition < certificateTable.dataDirectory.address) {
              const skipLength = certificateTable.dataDirectory.address - screenedPosition;
              if (skipLength >= screenedBuffer.length) {
                break;
              }
              readPosition = skipLength;
            }

            if (certificateTable.buffer.writeRemaining === 0) {
              break;
            }

            const tableAvail = Math.min(screenedBuffer.length - readPosition, certificateTable.buffer.writeRemaining);
            certificateTable.buffer.writeFromBuffer(screenedBuffer, readPosition, tableAvail);
            if (certificateTable.buffer.writeRemaining === 0) {
              const table: ITableData = {
                ...certificateTable.dataDirectory,
                data: certificateTable.buffer.buffer as Buffer,
              };
              this.emit('table', table);
            }
          } while (0);
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
            if (this._optionalHeaderMagic == IMAGE_OPTIONAL_HEADER_MAGIC32) {
              this._startReadComponent(
                ReadStatus.OPTIONAL_HEADER_B,
                94,
                ReadFlag.PASSTHROUGH
              );
            } else if (this._optionalHeaderMagic == IMAGE_OPTIONAL_HEADER_MAGIC64) {
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

            this._imageOptionalHeader = parseImageOptionalHeader(componentBuffer.buffer as Buffer, 0, this._optionalHeaderMagic);

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
            do {
              let remainging = this._imageOptionalHeader.sizeOfHeaders;
              remainging -= this._filePosition;
              remainging -= 8 * 16;

              this._runningBuffers = [];
              this._startReadComponent(
                ReadStatus.IMAGE_SECTION_HEADER,
                remainging,
                ReadFlag.PASSTHROUGH
              );
            } while (0);
            break;

          case ReadStatus.IMAGE_SECTION_HEADER:
            do {
              const buffer = componentBuffer.buffer as Buffer;
              let position = 0;

              while (position < buffer.length) {
                const sectionHeader = parseImageSectionHeader(buffer, position);
                position += 40;
                if (sectionHeader) {
                  this._imageSectionHeaders[sectionHeader.name] = sectionHeader;
                } else {
                  break;
                }
              }

              const remaining = this._imageOptionalHeader.sizeOfHeaders - this._filePosition;
              this._startReadComponent(
                ReadStatus.HEADER_FOOTER,
                remaining,
                ReadFlag.PASSTHROUGH
              );

              this._remainingImageSections = Object.values(this._imageSectionHeaders)
                .sort((x, y) => {
                  if (x.pointerToRawData > y.pointerToRawData) {
                    return 1;
                  } else if (x.pointerToRawData < y.pointerToRawData) {
                    return -1;
                  } else {
                    return 0;
                  }
                });
            } while (0);
            break;

          case ReadStatus.HEADER_FOOTER:
            do {
              this._startReadComponent(
                ReadStatus.MIDDLE_PAYLOAD,
                -1,
                ReadFlag.DUMMY | ReadFlag.PASSTHROUGH
              );
              break;
            } while (0);
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
