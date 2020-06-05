import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

import PERemakeStream from '../src/';

const chai = require('chai');
const expect = chai.expect;
const assert = chai.assert;
const should = chai.should();

function bufferToSha1(data: Buffer): string {
  return crypto.createHash('sha1').update(data).digest().toString('hex');
}

describe('feature test', function () {

  it('32bit exe: order', async function () {
    const inputStream = fs.createReadStream(path.join(__dirname, '../test-resources/hello-32.exe'));
    const remakeStream = PERemakeStream();
    let output!: Buffer;

    const runList: number[] = [];

    await new Promise((resolve, reject) => {
      const outputBufs: Buffer[] = [];
      inputStream
        .pipe(remakeStream)
        .on('error', (e) => {
          reject(e);
        })
        .on('data-directories', (dataDirectories, next) => {
          runList.push(1);
          next(dataDirectories);
        })
        .on('before-finish', (next) => {
          runList.push(2);
          next();
        })
        .on('data', (chunk) => {
          outputBufs.push(chunk);
        })
        .on('finish', () => {
          runList.push(3);
        })
        .on('end', () => {
          runList.push(4);
          output = Buffer.concat(outputBufs);
          resolve();
        });
    });

    expect(runList).eql([1, 2, 3, 4]);
  });

  it('32bit exe: passthrough', async function () {
    const inputStream = fs.createReadStream(path.join(__dirname, '../test-resources/hello-32.exe'));
    const remakeStream = PERemakeStream();
    let output!: Buffer;

    await new Promise((resolve, reject) => {
      const outputBufs: Buffer[] = [];
      inputStream
        .pipe(remakeStream)
        .on('error', (e) => {
          reject(e);
        })
        .on('data-directories', (dataDirectories, next) => {
          next(dataDirectories);
        })
        .on('before-finish', (next) => {
          next();
        })
        .on('data', (chunk) => {
          outputBufs.push(chunk);
        })
        .on('end', () => {
          output = Buffer.concat(outputBufs);
          resolve();
        });
    });

    expect(bufferToSha1(output)).eq('a2687a35d748d2beefee6b52a27559813699917c');
  });

  it('32bit exe: modify data directory', async function () {
    const inputStream = fs.createReadStream(path.join(__dirname, '../test-resources/hello-32.exe'));
    const remakeStream = PERemakeStream();
    let output!: Buffer;

    await new Promise((resolve, reject) => {
      const outputBufs: Buffer[] = [];
      inputStream
        .pipe(remakeStream)
        .on('error', (e) => {
          reject(e);
        })
        .on('data-directories', (dataDirectories, next) => {
          dataDirectories[15].address = 0x11223344;
          dataDirectories[15].size = 0x01020304;
          next(dataDirectories);
        })
        .on('before-finish', (next) => {
          next();
        })
        .on('data', (chunk) => {
          outputBufs.push(chunk);
        })
        .on('end', () => {
          output = Buffer.concat(outputBufs);
          resolve();
        });
    });

    expect(bufferToSha1(output)).eq('d8ad28cd2a6b1bc255cd17174e450e5e93b3e646');
  });

  it('64bit exe: order', async function () {
    const inputStream = fs.createReadStream(path.join(__dirname, '../test-resources/hello-64.exe'));
    const remakeStream = PERemakeStream();
    let output!: Buffer;

    const runList: number[] = [];

    await new Promise((resolve, reject) => {
      const outputBufs: Buffer[] = [];
      inputStream
        .pipe(remakeStream)
        .on('error', (e) => {
          reject(e);
        })
        .on('data-directories', (dataDirectories, next) => {
          runList.push(1);
          next(dataDirectories);
        })
        .on('before-finish', (next) => {
          runList.push(2);
          next();
        })
        .on('data', (chunk) => {
          outputBufs.push(chunk);
        })
        .on('finish', () => {
          runList.push(3);
        })
        .on('end', () => {
          runList.push(4);
          output = Buffer.concat(outputBufs);
          resolve();
        });
    });

    expect(runList).eql([1, 2, 3, 4]);
  });

  it('64bit exe: passthrough', async function () {
    const inputStream = fs.createReadStream(path.join(__dirname, '../test-resources/hello-64.exe'));
    const remakeStream = PERemakeStream();
    let output!: Buffer;

    await new Promise((resolve, reject) => {
      const outputBufs: Buffer[] = [];
      inputStream
        .pipe(remakeStream)
        .on('error', (e) => {
          reject(e);
        })
        .on('data-directories', (dataDirectories, next) => {
          next(dataDirectories);
        })
        .on('before-finish', (next) => {
          next();
        })
        .on('data', (chunk) => {
          outputBufs.push(chunk);
        })
        .on('end', () => {
          output = Buffer.concat(outputBufs);
          resolve();
        });
    });

    expect(bufferToSha1(output)).eq('8365fdc4f033da2a557cb51c3202505ce39dec53');
  });

  it('64bit exe: modify data directory', async function () {
    const inputStream = fs.createReadStream(path.join(__dirname, '../test-resources/hello-64.exe'));
    const remakeStream = PERemakeStream();
    let output!: Buffer;

    await new Promise((resolve, reject) => {
      const outputBufs: Buffer[] = [];
      inputStream
        .pipe(remakeStream)
        .on('error', (e) => {
          reject(e);
        })
        .on('data-directories', (dataDirectories, next) => {
          dataDirectories[15].address = 0x11223344;
          dataDirectories[15].size = 0x01020304;
          next(dataDirectories);
        })
        .on('before-finish', (next) => {
          next();
        })
        .on('data', (chunk) => {
          outputBufs.push(chunk);
        })
        .on('end', () => {
          output = Buffer.concat(outputBufs);
          resolve();
        });
    });

    expect(bufferToSha1(output)).eq('7ca36c96aae3bebbd53ecf061d46ceff4eace363');
  });

});
