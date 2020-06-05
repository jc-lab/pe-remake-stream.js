

export function writeInt32ToBuffer(buffer: Buffer, offset: number, value: number) {
  buffer[offset] = value & 0xff;
  buffer[offset + 1] = (value >>> 8) & 0xff;
  buffer[offset + 2] = (value >>> 16) & 0xff;
  buffer[offset + 3] = (value >>> 24) & 0xff;
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

  public getRemainBuffer(): Buffer {
    if (!this.buffer) {
      throw new Error('Illegal state');
    }

    if (this._readPosition === 0) {
      return this.buffer;
    }

    return this.buffer.slice(this._readPosition);
  }
}
