import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

import PERemakeStream from '../src/';
import {
  DataDirectoryType, IDataDirectory, ITableData
} from '../lib';

const chai = require('chai');
const expect = chai.expect;
const assert = chai.assert;
const should = chai.should();

function bufferToSha1(data: Buffer): string {
  return crypto.createHash('sha1').update(data).digest().toString('hex');
}

function fileToSha1(file: string): string {
  return crypto.createHash('sha1').update(fs.readFileSync(file)).digest().toString('hex');
}

const sampleFile = path.join(__dirname, '../test-resources/services.exe');

describe('sample-services.exe', function () {
  it('rsrc section test', async function () {
    const inputStream = fs.createReadStream(sampleFile);
    const remakeStream = PERemakeStream();
    let rsrcTable!: ITableData;
    let certTable!: ITableData;
    let outputBuffers: Buffer = Buffer.alloc(0);

    await new Promise<void>((resolve, reject) => {
      inputStream
        .pipe(remakeStream)
        .on('error', (e) => {
          reject(e);
        })
        .on('data-directories', (dataDirectories, next) => {
          next(dataDirectories);
        })
        .on('table', (tableInfo: ITableData) => {
          if (tableInfo.type === DataDirectoryType.ResourceTable) {
            rsrcTable = tableInfo;
          } else if (tableInfo.type === DataDirectoryType.CertificateTable) {
            certTable = tableInfo;
          }
        })
        .on('before-finish', (next) => {
          next();
        })
        .on('data', (chunk) => {
          outputBuffers = Buffer.concat([outputBuffers, chunk]);
        })
        .on('finish', () => {
        })
        .on('end', () => {
          resolve();
        });
    });

    // Must not changed to original
    expect(bufferToSha1(outputBuffers)).eq(fileToSha1(sampleFile));

    expect({type: rsrcTable.type, address: rsrcTable.address, size: rsrcTable.size}).eql({type: 2, address: 688128, size: 26616});
    expect(rsrcTable.data.subarray(0, 16)).eql(Buffer.from('00000000000000000000000002000200', 'hex'));

    expect(bufferToSha1(certTable.data).toUpperCase()).eq('1EF576B04BCB93E753FA2960DAAD3C62A4B58070');
  });

  it('append to certificate table', async function () {
    const inputStream = fs.createReadStream(sampleFile);
    const remakeStream = PERemakeStream();
    let rsrcTable!: ITableData;
    let certTable!: ITableData;
    let outputBuffers: Buffer = Buffer.alloc(0);

    await new Promise<void>((resolve, reject) => {
      inputStream
        .pipe(remakeStream)
        .on('error', (e) => {
          reject(e);
        })
        .on('data-directories', (dataDirectories, next) => {
          dataDirectories.forEach((v) => {
            if (v.type === DataDirectoryType.CertificateTable) {
              v.size += 4;
            }
          });
          next(dataDirectories);
        })
        .on('table', (tableInfo: ITableData) => {
          if (tableInfo.type === DataDirectoryType.ResourceTable) {
            rsrcTable = tableInfo;
          } else if (tableInfo.type === DataDirectoryType.CertificateTable) {
            certTable = tableInfo;
          }
        })
        .on('before-finish', (next) => {
          remakeStream.push(Buffer.from([0xaa, 0xbb, 0xcc, 0xdd]));
          next();
        })
        .on('data', (chunk) => {
          outputBuffers = Buffer.concat([outputBuffers, chunk]);
        })
        .on('finish', () => {
        })
        .on('end', () => {
          resolve();
        });
    });

    expect(bufferToSha1(outputBuffers).toUpperCase()).eq('64D163A24E0C597B26C122433C356CBF40D07BA0');
  });
});
