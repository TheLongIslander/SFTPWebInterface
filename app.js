require('dotenv').config();
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
    password: process.env.BEAR_PASSWORD_HASH, // Regular password (to be set later)
    passKey: null // Optional PassKey
  },
  bee: {
    username: "bee",
    password: process.env.BEE_PASSWORD_HASH, // Regular password (to be set later)
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
  const localPath = path.join(os.tmpdir(), filename); // Local path to save the directory
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

            // Ensure the localPath exists
            await fsPromises.mkdir(localPath, { recursive: true });

            // Download the directory to localPath
            await downloadDirectory(sftp, filePath, localPath);

            // Remove any existing zip files in the directory to avoid redundancy
            const filesInDir = await fsPromises.readdir(localPath);
            for (const file of filesInDir) {
              if (file.endsWith('.zip')) {
                console.log(`Removing redundant zip file: ${file}`);
                await fsPromises.unlink(path.join(localPath, file));
              }
            }

            res.setHeader('Content-Disposition', `attachment; filename=${filename}.zip`);
            res.setHeader('Content-Type', 'application/zip');

            const zipProcess = spawn('zip', ['-r', '-', '.'], {
              cwd: localPath, // Use the directory as the working directory
            });

            zipProcess.stdout.pipe(res); // Stream ZIP output to the response

            zipProcess.stderr.on('data', (data) => {
              console.error(`ZIP Error: ${data}`);
            });

            zipProcess.on('close', (code) => {
              if (code !== 0) {
                console.error(`ZIP process exited with code ${code}`);
                if (!res.headersSent) {
                  res.status(500).send('Error creating ZIP file');
                }
              } else {
                console.log(`ZIP file streamed successfully for ${filePath}`);
                logSFTPServerAction(user.username, 'download', filePath, formattedIpAddress);
                exec(`rm -rf "${localPath}"`); // Clean up after streaming
              }
            });

            zipProcess.on('error', (error) => {
              console.error('Error with ZIP process:', error);
              if (!res.headersSent) {
                res.status(500).send('Error creating ZIP file');
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

            res.setHeader('Content-Disposition', `attachment; filename=${filename}`);
            res.setHeader('Content-Type', 'application/octet-stream');

            const fileStream = fs.createReadStream(localPath);
            fileStream.pipe(res);

            fileStream.on('error', (error) => {
              console.error('Error reading file:', error);
              if (!res.headersSent) {
                res.status(500).send('Error reading file');
              }
            });

            fileStream.on('close', () => {
              console.log(`File ${filePath} successfully downloaded by ${user.username}`);
              logSFTPServerAction(user.username, 'download', filePath, formattedIpAddress);
              exec(`rm -rf "${localPath}"`);
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
}


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
function processHEICWorker(heicBuffer, cacheFilePath, res) {
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
}



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
  });

  // Run the video thumbnail pre-caching process on server startup
  precacheVideoThumbnails();
});


