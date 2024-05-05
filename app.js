// app.js
require('dotenv').config();
const express = require('express');
const { Client } = require('ssh2');
const fileUpload = require('express-fileupload');
const path = require('path');
const EventEmitter = require('events');
const async = require('async');
const fs = require('fs');
const JSZip = require('jszip');
const concat = require('concat-stream');
const { pipeline } = require('stream/promises');
const { promisify } = require('util');
const os = require('os');
const { promises: fsPromises } = require('fs');
const { join } = require('path');
const { exec } = require('child_process');

const app = express();
const port = 3000;
const sftpStat = promisify((sftp, path, callback) => sftp.stat(path, callback));
const sftpReaddir = promisify((sftp, path, callback) => sftp.readdir(path, callback));
const sftpReadStream = (sftp, path) => sftp.createReadStream(path);

EventEmitter.defaultMaxListeners = 20;

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(fileUpload());

let currentPath = '/';  // Default directory path

// Connect to SFTP and perform operations
function sftpOperation(operation, options, callback) {
  const conn = new Client();
  conn.on('ready', () => {
    conn.sftp((err, sftp) => {
      if (err) return callback(err);

      switch (operation) {
        case 'list':
          sftp.readdir(options.path, (err, list) => {
            if (err) return callback(err);
            // Filter out files starting with a dot
            const filteredList = list.filter(item => !item.filename.startsWith('.'));
            callback(null, filteredList);
          });
          break;
        case 'download':
          sftp.fastGet(options.path, options.destination, callback);
          break;
        case 'upload':
          sftp.fastPut(options.source, options.destination, callback);
          break;
        default:
          callback(new Error('Unsupported operation'));
      }
    });
  }).connect({
    host: process.env.SFTP_HOST,
    port: process.env.SFTP_PORT,
    username: process.env.SFTP_USERNAME,
    password: process.env.SFTP_PASSWORD,
    keepaliveInterval: 5000,  // Send a keep-alive packet every 5000 ms (5 seconds)
    keepaliveCountMax: -1,    // Setting this to -1 can disable any limit on the number of keep-alive packets
  });
}

app.get('/', (req, res) => {
  sftpOperation('list', { path: currentPath }, (err, list) => {
    if (err) {
      return res.status(500).send('Error accessing SFTP server');
    }
    const files = list.map(item => ({
      name: item.filename,
      type: item.longname.substr(0, 1) === 'd' ? 'directory' : 'file',
      path: path.join(currentPath, item.filename)
    }));
    res.render('index', { files: files, currentPath: currentPath });
  });
});

app.post('/change-directory', (req, res) => {
  currentPath = req.body.path;
  res.redirect('/');
});

app.post('/open-directory', (req, res) => {
  currentPath = req.body.path;
  res.redirect('/');
});


app.post('/download', async (req, res) => {
  const filePath = req.body.path;
  const filename = path.basename(filePath);
  const localPath = path.join(os.tmpdir(), filename); // Local path to save directory

  const conn = new Client();
  conn.on('ready', () => {
      conn.sftp(async (err, sftp) => {
          if (err) {
              console.error('SFTP connection error:', err);
              res.status(500).end('SFTP connection error: ' + err.message);
              return;
          }

          try {
              const stats = await sftpStat(sftp, filePath);
              if (stats.isDirectory()) {
                  await downloadDirectory(sftp, filePath, localPath); // Function to recursively download directory
                  const zipPath = await zipDirectory(localPath, filename);
                  res.download(zipPath, `${filename}.zip`, (err) => {
                      if (err) {
                          console.error('Error sending the zip file:', err);
                      }
                      // Cleanup local files after sending
                      exec(`rm -rf "${localPath}" "${zipPath}"`);
                  });
              } else {
                  // Handle single file download
                  res.cookie('fileDownload', 'true', { path: '/', httpOnly: true });
                  res.attachment(filename);
                  const fileStream = sftpReadStream(sftp, filePath);
                  res.setHeader('Content-Length', stats.size);
                  await pipeline(fileStream, res);
                  console.log('File has been sent.');
              }
          } catch (error) {
              console.error('Failed to process download:', error);
              res.status(500).send('Failed to process download: ' + error.message);
          } finally {
              conn.end();
          }
      });
  }).connect({
      host: process.env.SFTP_HOST,
      port: process.env.SFTP_PORT,
      username: process.env.SFTP_USERNAME,
      password: process.env.SFTP_PASSWORD
  });
});
const zipDirectory = async (localPath, filename) => {
  const zipPath = `${localPath}/${filename}.zip`;
  // Ensure paths are correctly quoted to handle spaces and special characters
  const command = `cd "${localPath}" && zip -r "${zipPath}" .`;

  return new Promise((resolve, reject) => {
      exec(command, (error, stdout, stderr) => {
          if (error) {
              console.error('Error zipping file:', stderr);
              reject(stderr);
          } else {
              console.log('Zipping complete:', stdout);
              resolve(zipPath);
          }
      });
  });
};
async function downloadDirectory(sftp, remotePath, localPath) {
  // Ensure the local directory exists
  await fsPromises.mkdir(localPath, { recursive: true });

  // Get list of files/directories from the remote directory
  const items = await new Promise((resolve, reject) => {
      sftp.readdir(remotePath, (err, list) => {
          if (err) reject(err);
          else resolve(list);
      });
  });

  // Process each item in the directory
  for (const item of items) {
      const remoteItemPath = join(remotePath, item.filename);
      const localItemPath = join(localPath, item.filename);

      if (item.attrs.isDirectory()) {
          // Recursive call to download directory
          await downloadDirectory(sftp, remoteItemPath, localItemPath);
      } else {
          // Download file
          await new Promise((resolve, reject) => {
              sftp.fastGet(remoteItemPath, localItemPath, (err) => {
                  if (err) reject(err);
                  else resolve();
              });
          });
      }
  }
}
async function addDirectoryToZip(sftp, zip, dirPath, zipPath) {
  const files = await sftpReaddir(sftp, dirPath);
  for (const file of files) {
    const filePath = path.join(dirPath, file.filename);
    const fileZipPath = path.join(zipPath, file.filename);
    const stats = await sftpStat(sftp, filePath);
    if (stats.isDirectory()) {
      await addDirectoryToZip(sftp, zip, filePath, fileZipPath);
    } else {
      const data = await new Promise((resolve, reject) => {
        const stream = sftpReadStream(sftp, filePath);
        const chunks = [];
        stream.on('data', chunk => chunks.push(chunk));
        stream.on('end', () => resolve(Buffer.concat(chunks)));
        stream.on('error', reject);
      });
      zip.file(fileZipPath, data);
    }
  }
}
app.post('/upload', (req, res) => {
  if (!req.files || !req.files.fileToUpload) {
    return res.status(400).send('No files were uploaded.');
  }

  const file = req.files.fileToUpload;
  const uploadPath = path.join(req.body.destination, file.name);

  file.mv('/tmp/' + file.name, err => {
    if (err) {
      return res.status(500).send(err);
    }
    sftpOperation('upload', { source: '/tmp/' + file.name, destination: uploadPath }, (err) => {
      if (err) {
        console.error('Upload failed:', err);
        return res.status(500).send('Upload failed');
      }
      res.redirect('/');
    });
  });
});

app.listen(port, '0.0.0.0', () => {
  console.log(`Server running on http://localhost:${port}`);
});
