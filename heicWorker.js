// heicWorker.js
const { parentPort } = require('worker_threads');
const heicConvert = require('heic-convert');
const sharp = require('sharp');
const fs = require('fs');
const path = require('path');
const os = require('os');

parentPort.on('message', async (fileData) => {
  const { heicBuffer, cacheFilePath } = fileData;

  try {
    // Convert HEIC to JPEG
    const outputBuffer = await heicConvert({ buffer: heicBuffer, format: 'JPEG', quality: 1 });
    // Resize and save the image
    const resizedBuffer = await sharp(outputBuffer).rotate().resize(800, 600).toBuffer();

    fs.writeFileSync(cacheFilePath, resizedBuffer); // Save to cache
    parentPort.postMessage({ success: true, cacheFilePath });
  } catch (error) {
    parentPort.postMessage({ success: false, error });
  }
});
