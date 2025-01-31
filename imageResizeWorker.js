const { parentPort } = require('worker_threads');
const sharp = require('sharp');

parentPort.on('message', (data) => {
  const { imageBuffer } = data;

  // Resize the image to a smaller size for thumbnails
  sharp(imageBuffer)
    .resize(800, 600)  // You can adjust the size to your preference
    .toBuffer((err, resizedBuffer) => {
      if (err) {
        parentPort.postMessage({ error: err.message });
      } else {
        parentPort.postMessage({ resizedBuffer });
      }
    });
});
