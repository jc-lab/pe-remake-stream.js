import * as fs from 'fs';
import * as path from 'path';

import PERemakeStream from './index';

const remakeStream = PERemakeStream();

const inputStream = fs.createReadStream('D:\\temp\\hello-world\\hello-32.exe');
const outputStream = fs.createWriteStream(path.resolve(__dirname, '../test-resources/out-1.exe'));

inputStream
  .pipe(remakeStream)
  .on('error', (e) => {
    console.log('remakeStream: EVENT: error: ', e);
  })
  .on('data-directories', (dataDirectories, next) => {
    console.log('data-directories => ', dataDirectories);
    dataDirectories[4].size = 0xffffffff;
    setTimeout(() => next(dataDirectories), 500);
  })
  .on('before-finish', (next) => {
    console.log('before-finish');
    remakeStream.push(Buffer.from([1,2,3,4,4,3,2,1]));
    setTimeout(() => next(), 500);
  })
  .pipe(outputStream)
  .on('close', () => {
    console.log('outputStream: EVENT: close');
  })
  .on('error', (e) => {
    console.log('outputStream: EVENT: error: ', e);
  })
  .on('finish', () => {
    console.log('outputStream: EVENT: finish');
  });
