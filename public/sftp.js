let ws;
let reconnectAttempts = 0;
const MAX_RETRIES = 10;

function setupWebSocket() {
    if (reconnectAttempts >= MAX_RETRIES) {
        console.error('[DEBUG] Max WebSocket reconnect attempts reached.');
        return;
    }

    ws = new WebSocket(`wss://${window.location.host}/lovely`);


    ws.onopen = function () {
        console.log('[DEBUG] WebSocket connected.');
        reconnectAttempts = 0;
    };

    ws.onmessage = function (event) {
        console.log(`[DEBUG] WebSocket raw message: ${event.data}`);
    
        try {
            const message = JSON.parse(event.data);
            console.log(`[DEBUG] Parsed WebSocket message:`, message);
    
            if (message.type === 'progress') {
                console.log(`[DEBUG] Progress update: ${message.progress}% for Request ID: ${message.requestId}`);
                updateZipProgress(message.requestId, message.progress);
            } else if (message.type === 'done') {
                console.log(`[DEBUG] Download ready for Request ID: ${message.requestId}`);
                updateZipProgress(message.requestId, 100);
            
                // Initiate the file download
                setTimeout(() => {
                    console.log(`[DEBUG] Initiating final file download for Request ID: ${message.requestId}`);
            
                    const downloadLink = document.createElement('a');
                    downloadLink.href = `/lovely/download-file?requestId=${message.requestId}`;
                    downloadLink.setAttribute('download', message.filename || 'download.zip');
                    document.body.appendChild(downloadLink);
                    downloadLink.click();
                    document.body.removeChild(downloadLink);
                }, 500);
            }require('dotenv').config();
const express = require('express');
const { exec, execSync, spawn } = require('child_process');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const WebSocket = require('ws');  // Import the WebSocket library
const recursive = require('recursive-readdir');
const sqlite3 = require('sqlite3').verbose();
const { Client } = require('ssh2');
const os = require('os');
const util = require('util');
const JSZip = require('jszip');
const fsPromises = require('fs').promises;
const { promisify } = require('util');
const { pipeline } = require('stream/promises');
const { join } = require('path');
const fileUpload = require('express-fileupload');
const unzipper = require('unzipper');
const heicConvert = require('heic-convert');
const { readdir } = require('fs/promises');
const sharp = require('sharp');  // For image resizing
const { Worker } = require('worker_threads');
const { PDFDocument } = require('pdf-lib');
const { PDFImage } = require('pdf-image');
let wss;

const { getEasternTime, getFormattedDate, getEasternDateHour, cleanupExpiredTokens, logServerAction, logSFTPServerAction } = require('./utils');  // Adjust the path as necessary based on your file structure
const app = express();
const port = 8088;
const users = {
  admin: {
    username: "admin",
    password: process.env.ADMIN_PASSWORD_HASH // Already hashed in .env file
  },
  bear: {
    username: "bear",
    password: process.env.BEAR_PASSWORD_HASH,
    passKey: null // Optional PassKey
  },
  bee: {
    username: "bee",
    password: process.env.BEE_PASSWORD_HASH,
    passKey: null // Optional PassKey
  }
};

const sftpConnectionDetails = {
  host: process.env.SFTP_HOST,
  port: process.env.SFTP_PORT,
  username: process.env.SFTP_USERNAME,
  password: process.env.SFTP_PASSWORD,
  readyTimeout: 600000,  // 10 minutes (600000 ms)
  keepaliveInterval: 10000
};
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (authHeader) {
    const token = authHeader.split(' ')[1];

    db.get('SELECT token FROM blacklisted_tokens WHERE token = ?', [token], (err, row) => {
      if (err) {
        return res.status(500).send('Error checking token');
      }
      if (row) {
        return res.status(401).send('Token has been blacklisted');
      }

      jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
          return res.sendStatus(403);
        }
        req.user = user;
        next();
      });
    });
  } else {
    res.sendStatus(401);
  }
};

const db = new sqlite3.Database('./token_blacklist.db', sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
  if (err) {
    console.error(err.message);
  }
  db.run('CREATE TABLE IF NOT EXISTS blacklisted_tokens(token TEXT UNIQUE)', (err) => {
    if (err) {
      console.error(err.message);
    }
  });
});


const sftpStat = (sftp, filePath) => {
  return new Promise((resolve, reject) => {
    sftp.stat(filePath, (err, stats) => {
      if (err) reject(err);
      else resolve(stats);
    });
  });
};
const sftpReadStream = (sftp, filePath) => {
  return sftp.createReadStream(filePath);
};
const videoCacheDir = process.env.VIDEO_CACHE_DIR;

// Ensure the video cache directory exists
if (!fs.existsSync(videoCacheDir)) {
  fs.mkdirSync(videoCacheDir, { recursive: true });
}


app.get('/lovely/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});


app.use('/lovely', express.static(path.join(__dirname, 'public'))); // Serve static files from 'public' directory
// Serve static files from 'assets' directory
// Middleware to parse URL-encoded bodies (as sent by HTML forms)
app.use(express.urlencoded({ extended: true, limit: '50gb' }));
app.use('/lovely/assets', express.static(path.join(__dirname, 'assets')));

app.use(express.json({ limit: '50gb' })); // Parse JSON bodies
app.use(fileUpload({
  useTempFiles: true,
  tempFileDir: process.env.TMP_UPLOAD_SERVER_PATH,  // Adjust this to your preferred temporary directory
  limits: { fileSize: 50 * 1024 * 1024 * 1024 }  // Set the limit to 2GB
}));
app.use((err, req, res, next) => {
  if (err && err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).send('File size exceeds the 50GB limit. Please upload a smaller file.');
  }
  next(err);
});

app.post('/lovely/login', async (req, res) => {

  const { username, password } = req.body;

  // Check if the user exists
  const user = users[username];
  if (user) {
    // Compare hashed password
    const match = await bcrypt.compare(password, user.password);
    if (match) {
      // Create and assign a token
      const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
      res.json({ message: "Authentication successful!", token });
      logServerAction('Logged In');
    } else {
      res.status(401).send("Invalid Credentials");
    }
  } else {
    res.status(401).send("User does not exist");
  }
});
app.post('/lovely/logout', authenticateJWT, (req, res) => {
  const token = req.headers.authorization.split(' ')[1];
  db.run('INSERT INTO blacklisted_tokens(token) VALUES(?)', [token], function (err) {
    if (err) {
      res.status(500).send("Failed to blacklist token");
      return console.error(err.message);
    }
    console.log('Logged out');
    logServerAction('Logged Out');
    cleanupExpiredTokens();
    res.send("Logged out");
  });
});

// Endpoint to list files in a directory
app.get('/lovely/sftp/list', authenticateJWT, (req, res) => {
  const dirPath = req.query.path || '/'; // Default path is the root directory

  const conn = new Client();
  conn.on('ready', () => {
    conn.sftp((err, sftp) => {
      if (err) {
        console.error('SFTP session error:', err);
        res.status(500).send('Failed to start SFTP session');
        return;
      }

      sftp.readdir(dirPath, (err, list) => {
        if (err) {
          console.error('Directory read error:', err);
          res.status(500).send('Failed to read directory');
          return;
        }
        const filteredList = list.filter(item => !item.filename.startsWith('.'));
        // Sort the list by modification time (mtime)
        filteredList.sort((a, b) => b.attrs.mtime - a.attrs.mtime);
        res.json(filteredList.map(item => ({
          name: item.filename,
          type: item.longname[0] === 'd' ? 'directory' : 'file',
          size: item.attrs.size,
          modified: item.attrs.mtime * 1000 // Convert to milliseconds
        })));
        conn.end();
      });
    });
  }).on('error', (err) => {
    console.error('Connection error:', err);
    res.status(500).send('Failed to connect to SFTP server');
  }).connect(sftpConnectionDetails);
});

let currentPath = '/'; // default path

app.post('/lovely/change-directory', authenticateJWT, (req, res) => {
  const newPath = req.body.path;
  // You may want to add some validation here to ensure the path is safe to use
  currentPath = newPath;
  res.json({ path: currentPath });
});

app.post('/lovely/open-directory', authenticateJWT, (req, res) => {
  const newPath = req.body.path;
  if (!newPath.startsWith('/')) {
    // Ensuring the path is absolute and normalized, preventing directory traversal attacks
    currentPath = path.join(currentPath, newPath);
  } else {
    currentPath = newPath;
  }
  res.json({ path: currentPath });
});


app.post('/lovely/download', (req, res) => {
  const token = req.body.token;
  const filePath = req.body.path;
  const filename = path.basename(filePath);
  const localPath = path.join(os.tmpdir(), filename);
  const zipFilePath = path.join(os.tmpdir(), `${filename}.zip`);
  const requestId = req.body.requestId || generateUniqueId();

  const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.socket.remoteAddress || req.connection.socket.remoteAddress;
  const formattedIpAddress = ipAddress.startsWith('::ffff:') ? ipAddress.replace('::ffff:', '') : (ipAddress === '::1' ? '127.0.0.1' : ipAddress);

  jwt.verify(token, process.env.JWT_SECRET, async (err, user) => {
    if (err) {
      console.error(`Failed token verification for download attempt on ${filePath}`);
      logSFTPServerAction('unknown', 'download', filePath, ipAddress, 0, 'Token verification failed');
      return res.sendStatus(403);
    }

    console.log(`User ${user.username} is attempting to download ${filePath}`);
    logSFTPServerAction(user.username, 'download_attempt', filePath, formattedIpAddress);

    const conn = new Client();
    conn.on('ready', () => {
      conn.sftp(async (err, sftp) => {
        if (err) {
          console.error('SFTP connection error:', err);
          logSFTPServerAction(user.username, 'download', filePath, ipAddress, 0, 'SFTP connection error');
          return res.status(500).send('SFTP connection error: ' + err.message);
        }

        try {
          const stats = await sftpStat(sftp, filePath);

          if (stats.isDirectory()) {
            console.log(`Downloading directory: ${filePath}`);

            // Ensure old extracted directory is deleted before re-downloading
            if (fs.existsSync(localPath)) {
              console.log(`Deleting old extracted directory: ${localPath}`);
              fs.rmSync(localPath, { recursive: true, force: true });
            }

            await fsPromises.mkdir(localPath, { recursive: true });

            const totalSize = await getTotalSize(sftp, filePath);
            let downloadedSize = 0;

            async function downloadWithProgress(sftp, remotePath, localPath) {
              await fsPromises.mkdir(localPath, { recursive: true });

              const items = await new Promise((resolve, reject) => {
                sftp.readdir(remotePath, (err, list) => {
                  if (err) reject(err);
                  else resolve(list);
                });
              });

              for (const item of items) {
                const remoteItemPath = path.join(remotePath, item.filename);
                const localItemPath = path.join(localPath, item.filename);

                if (item.longname.startsWith('d')) {
                  await downloadWithProgress(sftp, remoteItemPath, localItemPath);
                } else {
                  await new Promise((resolve, reject) => {
                    sftp.fastGet(remoteItemPath, localItemPath, (err) => {
                      if (err) reject(err);
                      else resolve();
                    });
                  });

                  downloadedSize += item.attrs.size;
                  const progress = Math.min((downloadedSize / totalSize) * 100, 100);
                  console.log(`[DEBUG] Broadcasting progress ${progress}% for Request ID: ${requestId}`);
                  broadcastProgress(requestId, progress);
                  
                }
              }
            }

            await downloadWithProgress(sftp, filePath, localPath);
            console.log(`Directory download complete: ${filePath}`);

            let totalFiles = 1;
            try {
              const stdout = execSync(`find "${localPath}" -type f | wc -l`).toString().trim();
              totalFiles = parseInt(stdout, 10) || 1;
              console.log(`Total files to zip: ${totalFiles}`);
            } catch (err) {
              console.error("Error counting files:", err);
              totalFiles = 1;
            }

            console.log(`Starting ZIP compression for: ${localPath}`);

            // Ensure old ZIP file is deleted before creating a new one
            if (fs.existsSync(zipFilePath)) {
              console.log(`Deleting old ZIP file: ${zipFilePath}`);
              fs.unlinkSync(zipFilePath);
            }

            await new Promise((resolve, reject) => {
              const zipProcess = spawn('stdbuf', ['-oL', 'zip', '-r', zipFilePath, '.'], { cwd: localPath });

              let zippedFiles = 0;
              zipProcess.stdout.setEncoding('utf8');
              zipProcess.stdout.on('data', (data) => {
                process.stdout.write(data);

                const matches = data.match(/adding: ([^ ]+)/g);
                if (matches) {
                  zippedFiles += matches.length;
                }

                const progress = totalFiles > 0 ? Math.min((zippedFiles / totalFiles) * 100, 100) : 100;
                console.log(`[ZIP PROGRESS] ${progress.toFixed(2)}% (${zippedFiles}/${totalFiles} files)`);
                
                console.log(`[DEBUG] Broadcasting progress ${progress}% for Request ID: ${requestId}`);
                broadcastProgress(requestId, progress);
                
              });

              zipProcess.on('close', (code) => {
                if (code !== 0) {
                  reject(new Error(`ZIP process exited with code ${code}`));
                } else {
                  resolve();
                }
              });

              zipProcess.on('error', (err) => {
                reject(err);
              });
            });

            console.log(`ZIP file created: ${zipFilePath}`);

            if (!res.headersSent) {
              res.setHeader('Content-Disposition', `attachment; filename="${filename}.zip"`);
              res.setHeader('Content-Type', 'application/zip');
            }

            const fileStream = fs.createReadStream(zipFilePath);
            fileStream.pipe(res);

            fileStream.on('close', () => {
              console.log(`ZIP file streamed successfully for ${filePath}`);
              logSFTPServerAction(user.username, 'download', filePath, formattedIpAddress);
              exec(`rm -rf "${localPath}" && rm -f "${zipFilePath}"`);
              broadcastProgress(requestId, 100);
            });

            fileStream.on('error', (error) => {
              console.error('Error streaming ZIP file:', error);
              if (!res.headersSent) {
                res.status(500).send('Error streaming ZIP file');
              }
            });

          } else {
            console.log(`Downloading file: ${filePath}`);

            await new Promise((resolve, reject) => {
              sftp.fastGet(filePath, localPath, (err) => {
                if (err) reject(err);
                else resolve();
              });
            });

            if (!res.headersSent) {
              res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
              res.setHeader('Content-Type', 'application/octet-stream');
            }

            const fileStream = fs.createReadStream(localPath);
            fileStream.pipe(res);

            fileStream.on('close', () => {
              console.log(`File ${filePath} successfully downloaded by ${user.username}`);
              logSFTPServerAction(user.username, 'download', filePath, formattedIpAddress);
              exec(`rm -rf "${localPath}"`);
            });

            fileStream.on('error', (error) => {
              console.error('Error reading file:', error);
              if (!res.headersSent) {
                res.status(500).send('Error reading file');
              }
            });
          }
        } catch (error) {
          console.error('Failed to process download:', error);
          logSFTPServerAction(user.username, 'download', filePath, formattedIpAddress, 0, error.message);
          if (!res.headersSent) {
            res.status(500).send('Failed to process download: ' + error.message);
          }
        } finally {
          conn.end();
        }
      });
    }).connect(sftpConnectionDetails);
  });
});






async function getTotalSize(sftp, dirPath) {
  let totalSize = 0;
  const items = await new Promise((resolve, reject) => {
    sftp.readdir(dirPath, (err, list) => {
      if (err) reject(err);
      else resolve(list);
    });
  });

  for (const item of items) {
    const remoteItemPath = path.join(dirPath, item.filename);
    const stats = await sftpStat(sftp, remoteItemPath);
    if (stats.isDirectory()) {
      totalSize += await getTotalSize(sftp, remoteItemPath);
    } else {
      totalSize += stats.size;
    }
  }

  return totalSize;
}

function broadcastProgress(requestId, progress) {
  if (!requestId) {
      console.error("[ERROR] broadcastProgress called without a valid requestId");
      return;
  }

  if (!wss || !wss.clients) {
      console.error("[ERROR] WebSocket Server is not initialized yet.");
      return;
  }

  console.log(`[DEBUG] Broadcasting progress ${progress}% for Request ID: ${requestId}`);

  wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
          console.log(`[DEBUG] Sending progress update: ${progress}% to WebSocket client`);
          client.send(JSON.stringify({ type: 'progress', requestId, value: progress }));
      }
  });
}



function generateUniqueId() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
    const r = Math.random() * 16 | 0,
      v = c === 'x' ? r : (c === 'y' ? (r & 0x3 | 0x8) : r);
    return v.toString(16);
  });
}

/* 

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
    const remoteItemPath = path.join(remotePath, item.filename);
    const localItemPath = path.join(localPath, item.filename);

    if (item.longname[0] === 'd') {
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

      // Preserve the original modification and access times
      const stats = await sftpStat(sftp, remoteItemPath);
      const mtime = stats.mtime;
      const atime = stats.atime || new Date();
      await fsPromises.utimes(localItemPath, atime, mtime);
    }
  }
} */


app.post('/lovely/upload', authenticateJWT, (req, res) => {
  let files = req.files.files; // Files uploaded
  const destinationPath = req.body.path; // Destination directory
  const lastModified = req.body.lastModified ? parseInt(req.body.lastModified) : Date.now(); // Use provided lastModified timestamp or fallback to current time

  console.log('Files received:', files);
  console.log('Destination path:', destinationPath);

  const conn = new Client();
  conn.on('ready', () => {
    conn.sftp(async (err, sftp) => {
      if (err) {
        console.error('SFTP connection error:', err);
        res.status(500).send('SFTP connection error: ' + err.message);
        return;
      }

      try {
        if (!Array.isArray(files)) {
          files = [files]; // Ensure it's an array
        }

        for (const file of files) {
          let localFilePath = file.tempFilePath || file.path;
          console.log('Processing file:', file.name);
          console.log('Local file path:', localFilePath);

          if (!localFilePath) {
            throw new Error('Local file path is undefined for file: ' + file.name);
          }

          let relativeFilePath = file.name;
          let remoteFilePath = path.join(destinationPath, relativeFilePath);

          // Ensure the remote directory exists
          const remoteDir = path.dirname(remoteFilePath);
          await ensureDirectoryExists(sftp, remoteDir);

          // Check if the file exists and modify the file name if necessary
          remoteFilePath = await getUniqueFilePath(sftp, remoteFilePath);

          console.log(`Uploading ${localFilePath} to ${remoteFilePath}`);

          // Upload the file
          await new Promise((resolve, reject) => {
            sftp.fastPut(localFilePath, remoteFilePath, (err) => {
              if (err) reject(err);
              else resolve();
            });
          });

          // Set the modification and access times on the remote file using lastModified
          const modifiedDate = new Date(lastModified);
          await new Promise((resolve, reject) => {
            sftp.utimes(remoteFilePath, modifiedDate, modifiedDate, (err) => {
              if (err) reject(err);
              else resolve();
            });
          });

          console.log(`Uploaded ${file.name} with original metadata`);

          // If the file is a ZIP file, unzip it into a new directory
          if (path.extname(file.name) === '.zip') {
            let baseName = path.basename(file.name, '.zip');
            let tempDir = path.join(os.tmpdir(), baseName);
            let newDir = path.join(destinationPath, baseName);

            // Ensure the directory does not overwrite an existing one
            newDir = await getUniqueDirectoryPath(sftp, newDir);

            fs.mkdirSync(tempDir, { recursive: true });
            await unzipFile(localFilePath, tempDir);
            await ensureDirectoryExists(sftp, newDir);
            await uploadDirectory(sftp, tempDir, newDir);
            fs.rmSync(tempDir, { recursive: true, force: true });
            // Remove the ZIP file after extraction and upload
            await new Promise((resolve, reject) => {
              sftp.unlink(remoteFilePath, (err) => {
                if (err) reject(err);
                else resolve();
              });
            });
            console.log(`Deleted ZIP file: ${remoteFilePath}`);
          }

          // Clean up the temporary file after all operations are completed
          fs.unlink(localFilePath, (err) => {
            if (err) console.error('Error deleting temp file:', err);
            else console.log('Temp file deleted:', localFilePath);
          });

          // Log the upload activity
          const formattedIpAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
          console.log('IP Address:', formattedIpAddress); // Debug logging
          logSFTPServerAction(req.user.username, 'upload', remoteFilePath, formattedIpAddress);
        }

        res.send('Files uploaded successfully');
      } catch (error) {
        console.error('Error uploading files:', error);
        res.status(500).send('Error uploading files: ' + error.message);
      } finally {
        conn.end();
      }
    });
  }).connect(sftpConnectionDetails);
});



async function getUniqueFilePath(sftp, remoteFilePath) {
  let baseName = path.basename(remoteFilePath, path.extname(remoteFilePath));
  let ext = path.extname(remoteFilePath);
  let dir = path.dirname(remoteFilePath);
  let uniqueFilePath = remoteFilePath;
  let counter = 1;

  // Check if file exists and modify name if necessary
  while (await fileExists(sftp, uniqueFilePath)) {
    uniqueFilePath = path.join(dir, `${baseName} copy${counter}${ext}`);
    counter++;
  }

  return uniqueFilePath;
}
async function getUniqueDirectoryPath(sftp, remoteDirPath) {
  let uniqueDirPath = remoteDirPath;
  let counter = 2;

  // Check if directory exists and modify the name if necessary
  while (await fileExists(sftp, uniqueDirPath)) {
    uniqueDirPath = path.join(path.dirname(remoteDirPath), `${path.basename(remoteDirPath)}-${counter}`);
    counter++;
  }

  return uniqueDirPath;
}

async function fileExists(sftp, remoteFilePath) {
  return new Promise((resolve, reject) => {
    sftp.stat(remoteFilePath, (err, stats) => {
      if (err) {
        if (err.code === 2) {
          // File or directory does not exist
          resolve(false);
        } else {
          // Some other error
          reject(err);
        }
      } else {
        // File or directory exists
        resolve(true);
      }
    });
  });
}

async function unzipFile(zipFilePath, destinationPath) {
  return new Promise((resolve, reject) => {
    fs.createReadStream(zipFilePath)
      .pipe(unzipper.Extract({ path: destinationPath }))
      .on('close', () => {
        console.log(`Unzipped file to ${destinationPath}`);
        resolve();
      })
      .on('error', (err) => {
        console.error(`Error unzipping file: ${err}`);
        reject(err);
      });
  });
}

async function uploadDirectory(sftp, localDir, remoteDir) {
  const items = fs.readdirSync(localDir);
  for (const item of items) {
    const localItemPath = path.join(localDir, item);
    const remoteItemPath = path.join(remoteDir, item);

    const stats = fs.statSync(localItemPath);
    if (stats.isDirectory()) {
      await ensureDirectoryExists(sftp, remoteItemPath);
      await uploadDirectory(sftp, localItemPath, remoteItemPath);
    } else {
      await new Promise((resolve, reject) => {
        sftp.fastPut(localItemPath, remoteItemPath, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
    }
  }
}

async function ensureDirectoryExists(sftp, dir) {
  const dirs = dir.split('/');
  let currentDir = '';

  for (const part of dirs) {
    if (part) {
      currentDir += '/' + part;

      try {
        await new Promise((resolve, reject) => {
          sftp.stat(currentDir, (err, stats) => {
            if (err) {
              if (err.code === 2) {
                // Directory does not exist, create it
                sftp.mkdir(currentDir, (err) => {
                  if (err) reject(err);
                  else resolve();
                });
              } else {
                reject(err);
              }
            } else {
              // Directory exists, continue
              resolve();
            }
          });
        });
      } catch (error) {
        if (error.code !== 4) {
          // Ignore "Failure" code if directory already exists
          throw error;
        }
      }
    }
  }
}


const cacheDir = path.join(os.tmpdir(), 'image_cache');

// Ensure the cache directory exists
if (!fs.existsSync(cacheDir)) {
  fs.mkdirSync(cacheDir);
}

app.get('/lovely/download-preview', authenticateJWT, (req, res) => {
  const filePath = req.query.path;

  const conn = new Client();
  conn.on('ready', () => {
    conn.sftp((err, sftp) => {
      if (err) {
        console.error('SFTP connection error:', err);
        res.status(500).send('SFTP connection error');
        return;
      }

      const fileExtension = path.extname(filePath).toLowerCase();
      const cacheFilePath = path.join(cacheDir, path.basename(filePath) + '.jpg');

      if (fileExtension === '.pdf') {
        handlePDF(sftp, filePath, cacheFilePath, res);
      } else if (fileExtension === '.heic') {
        handleHEIC(sftp, filePath, cacheFilePath, res);
      } else if (/\.(mp4|mov|avi|webm|mkv)$/i.test(filePath)) {
        handleVideo(sftp, filePath, cacheFilePath, res);
      } else if (/\.(jpg|jpeg|png|gif|bmp|webp)$/i.test(filePath)) {
        handleImage(sftp, filePath, cacheFilePath, res);
      } else {
        streamFile(sftp, filePath, res);
      }
    });
  }).connect(sftpConnectionDetails);
});


function handleVideo(sftp, filePath, cacheFilePath, res) {
  const videoCacheFilePath = path.join(videoCacheDir, path.basename(filePath) + '.jpg');

  if (fs.existsSync(videoCacheFilePath)) {
    console.log('Serving cached video thumbnail from custom directory:', videoCacheFilePath);
    return res.sendFile(videoCacheFilePath);
  }

  const tempLocalVideoPath = path.join(os.tmpdir(), `${path.basename(filePath)}`);
  const tempThumbnailPath = path.join(os.tmpdir(), `${path.basename(filePath)}.jpg`);
  const videoStream = sftp.createReadStream(filePath);
  const videoFileWriteStream = fs.createWriteStream(tempLocalVideoPath);

  videoStream.pipe(videoFileWriteStream);

  videoFileWriteStream.on('finish', () => {
    const ffmpeg = spawn('ffmpeg', [
      '-i', tempLocalVideoPath,
      '-ss', '00:01:00',
      '-vframes', '1',
      '-q:v', '5',
      '-vf', 'eq=brightness=0.05:saturation=1.2',
      tempThumbnailPath
    ]);

    ffmpeg.on('close', (code) => {
      if (code !== 0) {
        console.error(`ffmpeg exited with code ${code}`);
        return res.status(500).send('Error generating video thumbnail');
      }

      fs.copyFileSync(tempThumbnailPath, videoCacheFilePath);
      res.setHeader('Content-Type', 'image/jpeg');
      res.sendFile(videoCacheFilePath, (err) => cleanupFiles(tempLocalVideoPath, tempThumbnailPath, err, res));
    });

    ffmpeg.on('error', (error) => {
      console.error('Error executing ffmpeg:', error);
      res.status(500).send('Error generating video thumbnail');
    });
  });

  videoFileWriteStream.on('error', (err) => {
    console.error('Error writing video file:', err);
    res.status(500).send('Error downloading video for thumbnail generation');
  });
}

const MAX_WORKERS = os.cpus().filter(cpu => cpu.speed > 2000).length; // Approximation for performance cores
const workerPool = []; // Prewarmed worker pool
const taskQueue = []; // Queue for tasks
let activeWorkers = 0;

// Prewarm workers
for (let i = 0; i < MAX_WORKERS; i++) {
  const worker = new Worker(path.join(__dirname, 'heicWorker.js'));
  workerPool.push(worker);
}

// Assign a task to an available worker
function assignTaskToWorker(task) {
  if (workerPool.length > 0) {
    const worker = workerPool.pop();
    activeWorkers++;

    worker.postMessage(task.data);

    worker.once('message', (message) => {
      task.resolve(message);
      workerPool.push(worker); // Return worker to the pool
      activeWorkers--;
      processQueue(); // Continue processing queued tasks
    });

    worker.once('error', (error) => {
      task.reject(error);
      workerPool.push(worker); // Return worker to the pool
      activeWorkers--;
      processQueue();
    });

    worker.once('exit', (code) => {
      if (code !== 0) {
        console.error(`Worker exited with code ${code}`);
        task.reject(new Error(`Worker exited with code ${code}`));
      }
      workerPool.push(worker); // Return worker to the pool
      activeWorkers--;
      processQueue();
    });
  } else {
    taskQueue.push(task); // Add task to the queue if no workers are available
  }
}
// Public interface to schedule a task
function scheduleTask(data) {
  return new Promise((resolve, reject) => {
    assignTaskToWorker({ data, resolve, reject });
  });
}
// Function to handle HEIC thumbnail generation with multithreading
function handleHEIC(sftp, filePath, cacheFilePath, res) {
  const placeholderImagePath = path.join(__dirname, 'assets', 'android-chrome-512x512.png'); // Path to your placeholder image

  // Check if the thumbnail is already cached
  if (fs.existsSync(cacheFilePath)) {
    console.log('Serving cached HEIC thumbnail:', cacheFilePath);
    return res.sendFile(cacheFilePath);
  }

  const chunks = [];
  const readStream = sftp.createReadStream(filePath);

  readStream.on('data', (chunk) => chunks.push(chunk));
  readStream.on('end', () => {
    const heicBuffer = Buffer.concat(chunks);

    // Schedule a task to process the HEIC file using the worker pool
    scheduleTask({ heicBuffer, cacheFilePath })
      .then((message) => {
        if (message.success) {
          console.log('HEIC thumbnail generated and cached:', cacheFilePath);
          res.setHeader('Content-Type', 'image/jpeg');
          res.sendFile(message.cacheFilePath); // Serve the cached thumbnail
        } else {
          console.error('Error generating HEIC thumbnail:', message.error);
          res.sendFile(placeholderImagePath); // Serve the placeholder image on error
        }
      })
      .catch((error) => {
        console.error('Error processing HEIC file:', error);
        res.sendFile(placeholderImagePath); // Serve the placeholder image on error
      });
  });

  readStream.on('error', (err) => {
    console.error('Error reading HEIC file:', err.message);
    res.sendFile(placeholderImagePath); // Serve the placeholder image on error
  });
}


// Process the task queue
function processQueue() {
  if (taskQueue.length > 0 && activeWorkers < MAX_WORKERS) {
    const task = taskQueue.shift();
    assignTaskToWorker(task);
  }
}

// Function to process HEIC in a worker thread
/* function processHEICWorker(heicBuffer, cacheFilePath, res) {
  const placeholderImagePath = path.join(__dirname, 'assets', 'android-chrome-512x512.png');
  return new Promise((resolve, reject) => {
    // Spawn a new worker thread for HEIC conversion
    const worker = new Worker(path.join(__dirname, 'heicWorker.js'));

    worker.postMessage({ heicBuffer, cacheFilePath }); // Send data to the worker

    worker.on('message', (message) => {
      if (message.success) {
        console.log('HEIC thumbnail generated and cached:', cacheFilePath);
        res.setHeader('Content-Type', 'image/jpeg');
        res.sendFile(message.cacheFilePath); // Serve the cached thumbnail
        resolve();
      } else {
        console.error('Error generating HEIC thumbnail:', message.error);

        // Serve the placeholder image on error
        res.sendFile(placeholderImagePath);
        resolve(); // Resolve instead of rejecting to prevent the queue from halting
      }
    });

    worker.on('error', (error) => {
      console.error('Worker error:', error);

      // Serve the placeholder image if the worker fails
      res.sendFile(placeholderImagePath);
      resolve(); // Resolve instead of rejecting to ensure graceful queue processing
    });

    worker.on('exit', (code) => {
      if (code !== 0) {
        console.error(`Worker exited with code ${code}`);

        // Serve the placeholder image on worker exit error
        res.sendFile(placeholderImagePath);
        resolve(); // Resolve instead of rejecting
      }
    });
  });
} */



function handleImage(sftp, filePath, cacheFilePath, res) {
  if (fs.existsSync(cacheFilePath)) {
    console.log('Serving cached image thumbnail:', cacheFilePath);
    return res.sendFile(cacheFilePath);
  }

  const chunks = [];
  const readStream = sftp.createReadStream(filePath);
  readStream.on('data', (chunk) => chunks.push(chunk));
  readStream.on('end', async () => {
    const imageBuffer = Buffer.concat(chunks);
    try {
      sharp(imageBuffer)
        .rotate()
        .resize(800, 600)
        .toBuffer((err, resizedBuffer) => {
          if (err) {
            console.error('Error resizing image:', err);
            return res.status(500).send('Error resizing image');
          }
          fs.writeFileSync(cacheFilePath, resizedBuffer);
          res.setHeader('Content-Type', 'image/jpeg');
          res.send(resizedBuffer);
        });
    } catch (error) {
      console.error('Error processing image:', error);
      res.status(500).send('Error processing image');
    }
  });
  readStream.on('error', (err) => {
    console.error('Error in file stream:', err);
    res.status(500).send('Error streaming image');
  });
}


function streamFile(sftp, filePath, res) {
  const readStream = sftp.createReadStream(filePath);
  res.setHeader('Content-Type', 'application/octet-stream');
  readStream.pipe(res);

  readStream.on('error', (err) => {
    console.error('Error in file stream:', err);
    res.status(500).send('Error streaming file');
  });
}

function cleanupFiles(tempLocalVideoPath, tempThumbnailPath, err, res) {
  if (err) {
    console.error('Error sending thumbnail:', err);
    return res.status(500).send('Error sending thumbnail');
  }
  // Clean up temporary video and thumbnail files
  fs.unlink(tempLocalVideoPath, (err) => {
    if (err) console.error('Error deleting temp video file:', err);
  });
  fs.unlink(tempThumbnailPath, (err) => {
    if (err) console.error('Error deleting temp thumbnail file:', err);
  });
}


function handlePDF(sftp, filePath, cacheFilePath, res) {
  if (fs.existsSync(cacheFilePath)) {
    console.log('Serving cached PDF thumbnail:', cacheFilePath);
    return res.sendFile(cacheFilePath);
  }

  const tempPDFPath = path.join(os.tmpdir(), `${path.basename(filePath)}`);

  // Download the PDF from SFTP to a local temporary file
  const pdfStream = sftp.createReadStream(filePath);
  const pdfFileWriteStream = fs.createWriteStream(tempPDFPath);

  pdfStream.pipe(pdfFileWriteStream);

  pdfFileWriteStream.on('finish', () => {
    // Use pdf-image to generate a thumbnail from the first page
    const pdfImage = new PDFImage(tempPDFPath, { combinedImage: false });

    pdfImage.convertPage(0)  // 0 is the first page
      .then((imagePath) => {
        // Move the generated image to the cache location
        fs.renameSync(imagePath, cacheFilePath);
        console.log('PDF thumbnail generated:', cacheFilePath);

        // Serve the generated thumbnail
        res.setHeader('Content-Type', 'image/jpeg');
        res.sendFile(cacheFilePath);
      })
      .catch(err => {
        console.error('Error converting PDF to thumbnail:', err);
        res.status(500).send('Error generating PDF thumbnail');
      })
      .finally(() => {
        // Clean up the temporary PDF file
        fs.unlink(tempPDFPath, (err) => {
          if (err) console.error('Error deleting temp PDF file:', err);
        });
      });
  });

  pdfFileWriteStream.on('error', (err) => {
    console.error('Error writing PDF file to temp path:', err);
    res.status(500).send('Error processing PDF');
  });
}



// Function to pre-cache video thumbnails
async function precacheVideoThumbnails() {
  const conn = new Client();
  conn.on('ready', () => {
    conn.sftp(async (err, sftp) => {
      if (err) {
        console.error('SFTP session error:', err);
        return;
      }

      try {
        // Define the directory you want to start caching from (e.g., root directory)
        const startDir = '/';

        // Recursively fetch all files from the SFTP server
        await processDirectory(sftp, startDir);

        conn.end();
      } catch (error) {
        console.error('Error during video pre-caching:', error);
      }
    });
  }).connect(sftpConnectionDetails);
}

async function processDirectory(sftp, dirPath) {
  const files = await new Promise((resolve, reject) => {
    sftp.readdir(dirPath, (err, list) => {
      if (err) reject(err);
      else resolve(list);
    });
  });

  for (const file of files) {
    const fullPath = path.join(dirPath, file.filename);
    if (file.longname.startsWith('d')) {
      // If it's a directory, recursively process it
      await processDirectory(sftp, fullPath);
    } else if (/\.(mp4|mov|avi|webm|mkv)$/i.test(file.filename)) {
      // If it's a video, generate and cache the thumbnail
      await generateThumbnailForVideo(sftp, fullPath);
    }
  }
}

async function generateThumbnailForVideo(sftp, filePath) {
  const cacheFilePath = path.join(videoCacheDir, path.basename(filePath) + '.jpg');
  const placeholderImagePath = path.join(__dirname, 'assets', 'android-chrome-512x512.png'); // Path to your placeholder image

  if (fs.existsSync(cacheFilePath)) {
    console.log(`Thumbnail already cached for ${filePath}`);
    return;
  }

  const tempLocalVideoPath = path.join(os.tmpdir(), `${path.basename(filePath)}`);
  const tempThumbnailPath = path.join(os.tmpdir(), `${path.basename(filePath)}.jpg`);

  console.log('Starting video download:', tempLocalVideoPath);

  // Download the video to a local temp path
  const videoStream = sftp.createReadStream(filePath);
  const videoFileWriteStream = fs.createWriteStream(tempLocalVideoPath);

  videoStream.pipe(videoFileWriteStream);

  return new Promise((resolve, reject) => {
    videoFileWriteStream.on('finish', () => {
      console.log('Video downloaded successfully:', tempLocalVideoPath);

      if (!fs.existsSync(tempLocalVideoPath)) {
        console.error('Downloaded video file not found:', tempLocalVideoPath);
        fs.copyFileSync(placeholderImagePath, cacheFilePath); // Copy placeholder on error
        return resolve(); // Resolve and continue
      }

      // Generate the thumbnail using ffmpeg
      const ffmpeg = spawn('ffmpeg', [
        '-i', tempLocalVideoPath,
        '-ss', '00:01:00',
        '-vframes', '1',
        '-q:v', '5',
        '-vf', 'eq=brightness=0.05:saturation=1.2',
        tempThumbnailPath
      ]);

      ffmpeg.on('close', (code) => {
        if (code !== 0) {
          console.error(`ffmpeg process exited with code ${code} for file: ${filePath}`);
          console.log(`Skipping thumbnail generation for unsupported file: ${filePath}`);
          fs.copyFileSync(placeholderImagePath, cacheFilePath); // Copy placeholder on error
          return resolve(); // Skip the file and resolve to continue
        }

        console.log('Thumbnail generated:', tempThumbnailPath);

        // Cache the thumbnail
        fs.copyFileSync(tempThumbnailPath, cacheFilePath);
        resolve();
      });

      ffmpeg.on('error', (error) => {
        console.error('Error executing ffmpeg for file:', filePath, error);
        fs.copyFileSync(placeholderImagePath, cacheFilePath); // Copy placeholder on error
        resolve(); // Log the error, resolve, and continue to the next file
      });
    });

    videoFileWriteStream.on('error', (err) => {
      console.error('Error writing video file to local temp path for file:', filePath, err);
      fs.copyFileSync(placeholderImagePath, cacheFilePath); // Copy placeholder on error
      resolve(); // Log the error, resolve, and continue
    });
  }).finally(() => {
    // Always clean up temp files, regardless of success or failure, but check existence first
    if (fs.existsSync(tempLocalVideoPath)) {
      fs.unlink(tempLocalVideoPath, (err) => {
        if (err) console.error('Error deleting temp video file:', err);
      });
    }

    if (fs.existsSync(tempThumbnailPath)) {
      fs.unlink(tempThumbnailPath, (err) => {
        if (err) console.error('Error deleting temp thumbnail file:', err);
      });
    }
  });
}

app.post('/lovely/sftp/create-directory', authenticateJWT, (req, res) => {
  const { path, directoryName } = req.body;

  if (!directoryName || !path) {
    return res.status(400).json({ message: 'Invalid directory name or path' });
  }

  const newDirectoryPath = path.endsWith('/') ? path + directoryName : path + '/' + directoryName;

  const conn = new Client();
  conn.on('ready', () => {
    conn.sftp((err, sftp) => {
      if (err) {
        console.error('SFTP session error:', err);
        res.status(500).json({ message: 'Failed to start SFTP session' });
        return;
      }

      // Check if the directory already exists
      sftp.stat(newDirectoryPath, (err, stats) => {
        if (err && err.code === 2) { // If error code is 2, the directory does not exist
          // Directory does not exist, proceed to create it
          sftp.mkdir(newDirectoryPath, (err) => {
            if (err) {
              console.error('Error creating directory:', err);
              res.status(500).json({ message: 'Failed to create directory' });
            } else {
              console.log(`Directory created: ${newDirectoryPath}`);
              res.json({ message: 'Directory created successfully', path: newDirectoryPath });
            }
            conn.end();
          });
        } else if (stats) {
          // Directory exists
          console.log('A directory with that name already exists:', newDirectoryPath);
          res.status(400).json({ message: 'A directory with that name already exists' });
          conn.end();
        } else {
          console.error('Error checking directory existence:', err);
          res.status(500).json({ message: 'Failed to check directory existence' });
          conn.end();
        }
      });
    });
  }).on('error', (err) => {
    console.error('Connection error:', err);
    res.status(500).json({ message: 'Failed to connect to SFTP server' });
  }).connect(sftpConnectionDetails);
});












app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'sftp.html'));
});


const server = app.listen(port, () => {
  console.log(`Server listening at http://localhost:${port}`);
  server.timeout = 0;

  // Attach WebSocket server to the same HTTP server
  wss = new WebSocket.Server({ server });

  wss.on('connection', function connection(ws) {
    console.log('Client connected to WebSocket.');
    // Add any message handlers or other WebSocket-related code here
  });

  // Start pre-caching video thumbnails
  console.log('Starting video thumbnail pre-caching...');
  precacheVideoThumbnails();
});


        } catch (error) {
            console.error(`[ERROR] Failed to parse WebSocket message: ${error.message}`, event.data);
        }
    };
    
    
    
    
    
    

    ws.onclose = function (e) {
        console.error(`[DEBUG] WebSocket closed (code: ${e.code}, reason: ${e.reason}). Attempting to reconnect.`);
        reconnectAttempts++;
    
        if (reconnectAttempts < MAX_RETRIES) {
            console.log(`[DEBUG] WebSocket reconnect attempt #${reconnectAttempts}`);
            setTimeout(setupWebSocket, 1000);
        } else {
            console.error('[DEBUG] Max WebSocket reconnect attempts reached.');
        }
    };
    

    ws.onerror = function (err) {
        console.error(`[DEBUG] WebSocket error: ${err.message}`);
        ws.close();
    };
}

// Ensure WebSocket starts on page load
setupWebSocket();



// Listen for popstate event to handle back/forward browser navigation
// Listen for popstate event to handle back/forward browser navigation
window.addEventListener('popstate', throttle(function (event) {
    console.log('popstate triggered, event state:', event.state);
    if (event.state && event.state.path) {
        console.log('Navigating to path from history:', event.state.path);
        // Fetch files based on the stored path in the history state
        fetchFiles(event.state.path, false); // Do not push state again when using history
    } else {
        console.log('No valid state in popstate event');
    }
}, 200)); // Throttle to prevent multiple rapid calls

let typingInProgress = false;  // Declare at global scope

document.addEventListener('DOMContentLoaded', function () {
    fetchFiles('/');

    // Initialize WebSocket inside DOMContentLoaded
    setupWebSocket();

    const logoutButton = document.getElementById('logout-button');
    logoutButton.addEventListener('click', function () {
        logout();
    });

    const pathInput = document.getElementById('path-input');
    pathInput.addEventListener('keypress', function (event) {
        if (event.key === 'Enter') {
            changeDirectory();
        }
    });

    pathInput.addEventListener('input', function () {
        typingInProgress = true;  // User is typing
    });

    pathInput.addEventListener('blur', function () {
        typingInProgress = false; // User stopped typing (input lost focus)
    });

    const createDirectoryButton = document.getElementById('create-directory-button');
    createDirectoryButton.addEventListener('click', function () {
        const directoryName = prompt('Enter the new directory name:');
        if (directoryName) {
            createDirectory(directoryName);
        }
    });

    // Add event listener for file upload
    const uploadForm = document.getElementById('upload-form');
    uploadForm.addEventListener('submit', function (event) {
        event.preventDefault();
        uploadFiles();
    });

    // Trigger upload when files are selected
    const fileInput = document.getElementById('file-input');
    fileInput.addEventListener('change', function () {
        if (this.files.length > 0) {
            uploadFiles();
        }
    });

    const uploadButton = document.getElementById('upload-button');
    uploadButton.addEventListener('click', function () {
        triggerFileUpload();
    });

    // Detect user activity
    detectUserActivity();
});


let activityTimeout;
let refreshInterval;
const debouncedOpenDirectory = debounce(openDirectory, 300); // Delay of 300ms
const debouncedUpDirectory = debounce(upDirectory, 300);

function detectUserActivity() {
    document.addEventListener('mousemove', resetActivityTimeout);
    document.addEventListener('keypress', resetActivityTimeout);
    document.addEventListener('click', resetActivityTimeout);
    document.addEventListener('scroll', resetActivityTimeout);

    resetActivityTimeout(); // Initialize activity detection
}

function resetActivityTimeout() {
    clearTimeout(activityTimeout);
    activityTimeout = setTimeout(setUserInactive, 300000); // 5 minutes of inactivity

    // Use the last successful path (currentDisplayedPath) for auto-refresh
    if (!refreshInterval) {
        refreshInterval = setInterval(() => {
            fetchFiles(currentDisplayedPath, false, true);  // Use the current displayed path, force update
        }, 1000);  // Refresh every 1 second
    }
}



function setUserInactive() {
    clearInterval(refreshInterval);
    refreshInterval = null;
    console.log('Auto-refresh stopped due to inactivity'); // Add log
}

function triggerFileUpload() {
    document.getElementById('file-input').click();
}
let currentDisplayedPath = null; // Track the currently displayed path to prevent unnecessary reloads

function fetchFiles(path, shouldPushState = true, forceUpdate = false) {
    // Avoid unnecessary fetching when the path hasn't changed (unless forceUpdate is true)
    if (!forceUpdate && currentDisplayedPath === path) {
        console.log('Path has not changed. Skipping fetch.');
        return;
    }

    currentDisplayedPath = path; // Update the current path to avoid redundant fetch calls

    const token = localStorage.getItem('token');

    // Avoid updating the path input if the user is typing
    if (!typingInProgress) {
        const pathInput = document.getElementById('path-input');
        pathInput.value = path; // Update the path in the search bar
    }

    if (!token) {
        alert('You are not authenticated.');
        window.location.href = '/lovely';
        return;
    }

    // Push state only when explicitly told to do so
    if (shouldPushState) {
        history.pushState({ path }, null, `/lovely/sftp?path=${encodeURIComponent(path)}`);
    }

    fetch(`/lovely/sftp/list?path=${encodeURIComponent(path)}`, {
        headers: {
            'Authorization': 'Bearer ' + token
        }
    })
        .then(response => {
            // If the token is invalid or expired, redirect to login
            if (response.status === 403) {
                alert('Session has expired, please log in again.');
                localStorage.removeItem('token');
                window.location.href = '/lovely';
                throw new Error('Session expired');
            }
            if (!response.ok) {
                throw new Error('Failed to fetch files');
            }
            return response.json();
        })
        .then(files => {
            const fileList = document.getElementById('file-list');
            const existingItems = Array.from(fileList.children);

            // Map existing file list for comparison
            const existingFileMap = {};
            existingItems.forEach(item => {
                const name = item.querySelector('span').textContent;
                existingFileMap[name] = item;
            });

            // Add or update the new file list
            files.forEach(file => {
                const existingItem = existingFileMap[file.name];

                if (!existingItem) {
                    // Create new file/directory entry
                    const fileItem = document.createElement('li');
                    fileItem.classList.add('directory-item');

                    let fileIcon;
                    if (file.type === 'directory') {
                        fileIcon = document.createElement('img');
                        fileIcon.src = '/lovely/assets/folder-icon.png';
                        fileIcon.alt = 'Folder';
                        fileIcon.classList.add('folder-icon');
                        fileIcon.onclick = () => openDirectory(path, file.name);

                        const fileName = document.createElement('span');
                        fileName.classList.add('file-name');
                        fileName.classList.add('directory');
                        fileName.textContent = file.name;
                        fileName.onclick = () => openDirectory(path, file.name);

                        fileItem.appendChild(fileIcon);
                        fileItem.appendChild(fileName);
                    } else {
                        const fileName = document.createElement('span');
                        fileName.textContent = file.name;

                        // Check for image or video and create a preview
                        if (isImage(file.name)) {
                            fileIcon = createImagePreview(file, path); // Create image preview
                        } else if (isVideo(file.name)) {
                            fileIcon = createVideoPreview(file, path); // Create video preview
                        } else if (file.name.endsWith('.pdf')) {
                            fileIcon = createPDFPreview(file, path);  // Add this check for PDFs
                        }
                        else if (file.name.endsWith('.jar')) {
                            fileIcon = document.createElement('img');
                            fileIcon.src = '/lovely/assets/jar.png';
                            fileIcon.alt = 'JAR File';
                        } else if (file.name.endsWith('.gz')) {
                            fileIcon = document.createElement('img');
                            fileIcon.src = '/lovely/assets/gz.png';
                            fileIcon.alt = 'GZ File';
                        } else if (file.name.endsWith('.png')) {
                            fileIcon = document.createElement('img');
                            fileIcon.src = '/lovely/assets/png.png';
                            fileIcon.alt = 'PNG File';
                        } else if (file.name.endsWith('.zip')) {
                            fileIcon = document.createElement('img');
                            fileIcon.src = '/lovely/assets/zip-icon.png';
                            fileIcon.alt = 'ZIP File';
                        } else {
                            fileIcon = document.createElement('img');
                            fileIcon.src = '/lovely/assets/file.png';
                            fileIcon.alt = 'File';
                        }
                        fileIcon.classList.add('file-icon');
                        fileItem.appendChild(fileIcon);
                        fileName.classList.add('file-name');
                        fileItem.appendChild(fileName);
                    }

                    const downloadForm = document.createElement('form');
                    downloadForm.method = 'POST';
                    downloadForm.action = '/lovely/download';
                    downloadForm.onsubmit = function (event) {
                        event.preventDefault();  // Prevent navigation away from the page
                        
                        const requestId = generateUniqueId(); // Generate the request ID only once here
                        console.log(`[DEBUG] Download started. Setting Request ID: ${requestId}`);
                    
                        // Assign requestId to the form immediately
                        downloadForm.dataset.requestId = requestId;
                    
                        fetch('/lovely/download', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({
                                token: localStorage.getItem('token'),
                                path: pathInput.value,
                                requestId: requestId  // Ensure frontend-sent request ID is passed
                            })
                        })
                        .then(response => response.json())
                        .then(data => {
                            console.log(`[DEBUG] Backend acknowledged Request ID: ${data.requestId}`);
                            
                            // Ensure backend’s response ID matches frontend ID
                            if (data.requestId !== requestId) {
                                console.warn(`[DEBUG] Mismatch detected! Backend Request ID: ${data.requestId}, Expected: ${requestId}`);
                            }
                    
                            // Re-confirm form's dataset requestId
                            downloadForm.dataset.requestId = data.requestId;
                        })
                        .catch(error => {
                            console.error('Download initiation failed:', error);
                            alert('Error initiating download.');
                        });
                    
                        showLoadingSpinner(downloadForm, requestId);
                        return false;  // Prevent form submission
                    };
                    
                    
                    
                    
                    



                    const pathInput = document.createElement('input');
                    pathInput.type = 'hidden';
                    pathInput.name = 'path';
                    pathInput.value = path.endsWith('/') ? path + file.name : path + '/' + file.name;

                    const downloadButton = document.createElement('button');
                    downloadButton.type = 'submit';
                    downloadButton.classList.add('download-button');
                    downloadButton.textContent = 'Download';

                    downloadForm.appendChild(pathInput);
                    downloadForm.appendChild(downloadButton);

                    fileItem.appendChild(downloadForm);
                    fileList.appendChild(fileItem);
                } else {
                    // Remove from map if it already exists to handle removed files
                    delete existingFileMap[file.name];
                }
            });

            // Remove files that no longer exist in the fetched list
            Object.values(existingFileMap).forEach(item => {
                fileList.removeChild(item); // Remove old items not in the current list
            });
        })
        .catch(error => {
            console.error('Error fetching files:', error);
            if (error.message !== 'Session expired') {
                alert('Error fetching files. Please try again.');
            }
        });
}



function createDirectory(directoryName) {
    const token = localStorage.getItem('token');
    const currentPath = document.getElementById('path-input').value;

    fetch('/lovely/sftp/create-directory', {
        method: 'POST',
        headers: {
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            path: currentPath,
            directoryName: directoryName,
        }),
    })
        .then(response => {
            if (!response.ok) {
                return response.json().then(data => {
                    throw new Error(data.message || 'Error creating directory. Please try again.');
                });
            }
            return response.json();
        })
        .then(data => {
            alert('Directory created successfully');
            fetchFiles(data.path); // Refresh the file list
        })
        .catch(error => {
            if (error.message === 'A directory with that name already exists') {
                alert('A directory with that name already exists. Please choose a different name.');
            } else {
                console.error('Error creating directory:', error);
                alert('Error creating directory. Please try again.');
            }
        });
}




function showLoadingSpinner(form, requestId) {
    console.log(`[DEBUG] Showing loading spinner for Request ID: ${requestId}`);

    let progressBar = form.querySelector('.zip-progress-bar');
    if (!progressBar) {
        console.warn(`[DEBUG] No existing progress bar found, creating one.`);
        progressBar = document.createElement('progress');
        progressBar.classList.add('zip-progress-bar');
        progressBar.value = 0;
        progressBar.max = 100;
        progressBar.style.display = 'block';
        progressBar.style.width = '100%';
        progressBar.style.height = '10px';
        form.appendChild(progressBar);
    } else {
        console.log(`[DEBUG] Found existing progress bar. Resetting.`);
        progressBar.value = 0;
        progressBar.style.display = 'block';
    }

    form.dataset.requestId = requestId;
}







function hideLoadingSpinner(form) {
    const progressBar = form.querySelector('.zip-progress-bar');
    if (progressBar) {
        progressBar.remove();
    }

    const spinner = form.querySelector('.spinner');
    if (spinner) {
        spinner.remove();
    }

    const downloadButton = form.querySelector('.download-button');
    if (downloadButton) {
        downloadButton.style.display = 'inline-block';
    }
}



window.addEventListener('message', function (event) {
    if (event.data === 'hideLoadingSpinner') {
        hideLoadingSpinner();
    }
});

function logout() {
    const token = localStorage.getItem('token');
    if (!token) {
        alert('No active session.');
        window.location.href = '/lovely';
        return;
    }

    fetch('/lovely/logout', {  // Updated path
        method: 'POST',
        headers: {
            'Authorization': 'Bearer ' + token
        }
    })
        .then(handleFetchResponse)
        .then(response => {
            if (response && response.ok) {
                console.log('Logout successful on server.');
                localStorage.removeItem('token'); // Clear the token
                window.location.href = '/lovely'; // Redirect to login
            } else {
                console.log('Server responded with an error during logout.');
            }
        })
        .catch(error => {
            console.error('Error during logout:', error);
            alert('Error logging out.');
        });
}

function handleFetchResponse(response) {
    if (response.status === 403) {
        alert('Session has expired, please log in again.');
        localStorage.removeItem('token');
        window.location.href = '/';
        return null;
    } else if (!response.ok) {
        throw new Error('Failed to fetch data');
    }
    return response;
}
// Modify the event listener for pressing Enter (no debounce, no automatic directory fetching)
const pathInput = document.getElementById('path-input');
pathInput.addEventListener('keypress', function (event) {
    if (event.key === 'Enter') {
        changeDirectory(); // Only trigger directory change on Enter
    }
});

function changeDirectory() {
    const path = document.getElementById('path-input').value;

    // Ensure path is not empty
    if (!path || path.trim() === '') {
        console.log('Empty path, skipping fetch');
        return;
    }

    const token = localStorage.getItem('token');
    fetch('/lovely/change-directory', {
        method: 'POST',
        headers: {
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ path: path })
    })
        .then(handleFetchResponse)
        .then(response => response.json())
        .then(data => fetchFiles(data.path))
        .catch(error => {
            console.error('Error changing directory:', error);
            alert('Error fetching files. Please try again.');
        });
}


function openDirectory(currentPath, dirName) {
    const token = localStorage.getItem('token');
    const newPath = currentPath.endsWith('/') ? currentPath + dirName : currentPath + '/' + dirName;

    console.log('Attempting to open directory:', newPath); // Log each click

    // Only push state if the directory is actually changing
    if (newPath !== currentPath && window.location.pathname !== `/lovely/sftp?path=${encodeURIComponent(newPath)}`) {
        console.log('Pushing state for new directory:', newPath); // Log state change
        history.pushState({ path: newPath }, null, `/lovely/sftp?path=${encodeURIComponent(newPath)}`);
    } else {
        console.log('State already exists or path has not changed.');
    }

    fetch(`/lovely/open-directory`, {
        method: 'POST',
        headers: {
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ path: newPath })
    })
        .then(handleFetchResponse)
        .then(response => response.json())
        .then(data => {
            console.log('Directory opened successfully. Fetch response received.');
            fetchFiles(data.path, false); // Do not push state again when navigating
        })
        .catch(error => {
            console.error('Error opening directory:', error);
        });
}


function throttle(func, limit) {
    let inThrottle;
    return function (...args) {
        if (!inThrottle) {
            func.apply(this, args);
            inThrottle = true;
            setTimeout(() => (inThrottle = false), limit);
        }
    };
}

function debounce(func, delay) {
    let timeout;
    return function (...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(this, args), delay);
    };
}

function updatePathInput(path) {
    const pathInput = document.getElementById('path-input');
    pathInput.value = path; // Update the path in the search bar
}

function upDirectory() {
    let currentPath = document.getElementById('path-input').value;
    if (currentPath === '/' || currentPath === '') {
        return; // Already at the root, cannot go up
    }

    const newPath = currentPath.split('/').slice(0, -1).join('/') || '/';

    if (newPath !== currentPath) {
        console.log('Pushing state for moving up directory:', newPath);
        history.pushState({ path: newPath }, null, `/lovely/sftp?path=${encodeURIComponent(newPath)}`);
    }

    const token = localStorage.getItem('token');
    fetch(`/lovely/open-directory`, {
        method: 'POST',
        headers: {
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ path: newPath })
    })
        .then(handleFetchResponse)
        .then(response => response.json())
        .then(data => fetchFiles(data.path, false)) // Do not push state again
        .catch(error => console.error('Error going up directory:', error));
}



function toggleUpDirectoryButton(path) {
    const upDirectoryButton = document.getElementById('up-directory-button');
    if (path === '/' || path === '') {
        upDirectoryButton.style.display = 'none'; // Hide button at root
    } else {
        upDirectoryButton.style.display = 'inline'; // Show button otherwise
    }
}

function uploadFiles() {
    const token = localStorage.getItem('token');
    const fileInput = document.getElementById('file-input');
    const currentPath = document.getElementById('path-input').value;
    const files = Array.from(fileInput.files);
    const formData = new FormData();

    // Append each file and its lastModified timestamp
    files.forEach(file => {
        formData.append('files', file, file.webkitRelativePath || file.name);
        formData.append('lastModified', file.lastModified); // Include the lastModified date
    });

    formData.append('path', currentPath);

    // Hide the upload button and show the progress bar
    const uploadButton = document.getElementById('upload-button');
    const progressContainer = document.getElementById('progress-container');
    const progressBar = document.getElementById('upload-progress');
    const uploadPercentage = document.getElementById('upload-percentage');
    uploadButton.style.display = 'none';
    progressContainer.style.display = 'block';

    // Set the progress bar to 100% by default and show "Uploading..."
    progressBar.value = 100;
    uploadPercentage.textContent = 'Uploading...';  // Default text

    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/lovely/upload', true);  // Updated path
    xhr.setRequestHeader('Authorization', 'Bearer ' + token);

    let progressDetected = false;

    // Monitor the upload progress
    xhr.upload.onprogress = function (event) {
        if (event.lengthComputable) {
            progressDetected = true;
            const percentComplete = (event.loaded / event.total) * 100;
            if (percentComplete >= 1) {
                progressBar.value = percentComplete;  // Update the progress bar with actual progress
                uploadPercentage.textContent = `${Math.round(percentComplete)}%`;  // Update the text
            }

            if (percentComplete === 100) {
                uploadPercentage.textContent = 'Processing...';
            }
        }
    };

    // Handle the response after upload completion
    xhr.onload = function () {
        if (xhr.status === 200) {
            alert('Upload successful!');
            fetchFiles(currentPath); // Refresh the file list
        } else {
            alert('Upload failed: ' + xhr.statusText);
        }

        // Hide the progress bar and percentage, show the upload button
        progressContainer.style.display = 'none';
        progressBar.value = 0;
        uploadPercentage.textContent = '';
        uploadButton.style.display = 'block';
    };

    // Handle errors during upload
    xhr.onerror = function () {
        alert('Upload failed: ' + xhr.statusText);

        // Hide the progress bar and percentage, show the upload button
        progressContainer.style.display = 'none';
        progressBar.value = 0;
        uploadPercentage.textContent = '';
        uploadButton.style.display = 'block';
    };

    // If no progress is detected after a short delay, keep the bar full and show "Uploading..."
    setTimeout(() => {
        if (!progressDetected) {
            progressBar.value = 100;  // Keep the bar full
            uploadPercentage.textContent = 'Uploading...';  // Keep "Uploading..." if no progress events fired
        }
    }, 500);  // Adjust this delay as necessary

    xhr.send(formData);
}



function generateUniqueId() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        const r = Math.random() * 16 | 0,
            v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

function goToRoot() {
    fetchFiles('/');
}

function isImage(filename) {
    return /\.(jpg|jpeg|png|gif|bmp|webp|heic)$/i.test(filename);
}


function isVideo(filename) {
    return /\.(mp4|mov|avi|webm|mkv)$/i.test(filename);
}


function createImagePreview(file, path) {
    const imageElement = document.createElement('img');
    const filePath = `${path}/${file.name}`;

    fetch(`/lovely/download-preview?path=${encodeURIComponent(filePath)}`, {
        headers: {
            'Authorization': 'Bearer ' + localStorage.getItem('token')
        }
    })
        .then(response => response.blob())
        .then(blob => {
            const url = URL.createObjectURL(blob);
            imageElement.src = url; // Set preview URL
            imageElement.classList.add('image-preview'); // Add some CSS class for styling
            imageElement.alt = file.name;
        })
        .catch(err => console.error('Error fetching image preview:', err));

    return imageElement;
}
function createVideoPreview(file, path) {
    const videoThumbnail = document.createElement('img'); // Use an image element for the video thumbnail
    const filePath = `${path}/${file.name}`;

    fetch(`/lovely/download-preview?path=${encodeURIComponent(filePath)}`, {
        headers: {
            'Authorization': 'Bearer ' + localStorage.getItem('token')
        }
    })
        .then(response => response.blob())
        .then(blob => {
            const url = URL.createObjectURL(blob);
            videoThumbnail.src = url; // Set the thumbnail image URL
            videoThumbnail.classList.add('video-thumbnail'); // Add a class for custom styling
            videoThumbnail.alt = `Thumbnail for ${file.name}`;
        })
        .catch(err => console.error('Error fetching video thumbnail:', err));

    return videoThumbnail;
}

function createPDFPreview(file, path) {
    const pdfThumbnail = document.createElement('img');
    const filePath = `${path}/${file.name}`;

    fetch(`/lovely/download-preview?path=${encodeURIComponent(filePath)}`, {
        headers: {
            'Authorization': 'Bearer ' + localStorage.getItem('token')
        }
    })
        .then(response => response.blob())
        .then(blob => {
            const url = URL.createObjectURL(blob);
            pdfThumbnail.src = url;  // Set the thumbnail image URL
            pdfThumbnail.classList.add('pdf-thumbnail');  // Add a class for styling
            pdfThumbnail.alt = `Thumbnail for ${file.name}`;
        })
        .catch(err => console.error('Error fetching PDF thumbnail:', err));

    return pdfThumbnail;
}
function updateZipProgress(requestId, progress) {
    console.log(`[DEBUG] Received progress update: ${progress}% for Request ID: ${requestId}`);

    const forms = document.querySelectorAll('form');
    let formFound = false; 

    forms.forEach(form => {
        const formRequestId = form.dataset.requestId;

        if (!formRequestId) {
            console.warn(`[DEBUG] Skipping form with undefined request ID.`);
            return;
        }

        console.log(`[DEBUG] Checking form. Form Request ID: ${formRequestId}, Expected: ${requestId}`);

        if (formRequestId === requestId) {
            formFound = true;
            let progressBar = form.querySelector('.zip-progress-bar');

            if (!progressBar) {
                console.warn(`[DEBUG] No progress bar found for Request ID: ${requestId}. Creating one.`);
                progressBar = document.createElement('progress');
                progressBar.classList.add('zip-progress-bar');
                progressBar.value = 0;
                progressBar.max = 100;
                progressBar.style.width = '100%';
                progressBar.style.height = '10px';
                form.appendChild(progressBar);
            }

            // Force UI update by toggling display off and on
            progressBar.style.display = 'none'; // Hide temporarily
            progressBar.value = progress; // Update progress value
            progressBar.style.display = 'block'; // Show again

            requestAnimationFrame(() => {
                progressBar.style.display = 'block'; // Show again
                progressBar.offsetHeight; // Force reflow
            });
            

            console.log(`[DEBUG] Updated progress bar to ${progress}% for Request ID: ${requestId}`);

            if (progress >= 100) {
                console.log(`[DEBUG] Hiding spinner for Request ID: ${requestId}`);
                hideLoadingSpinner(form);
            }
        }
    });

    if (!formFound) {
        console.warn(`[DEBUG] No matching form found for Request ID: ${requestId}`);
    }
}






