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
  password: process.env.SFTP_PASSWORD
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

const sftpStat = promisify((sftp, path, callback) => sftp.stat(path, callback));
const sftpReadStream = (sftp, remotePath) => sftp.createReadStream(remotePath);

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

// Download route
app.post('/lovely/download', (req, res) => {
  const token = req.body.token;
  const filePath = req.body.path;
  const filename = path.basename(filePath);
  const localPath = path.join(os.tmpdir(), filename); // Local path to save directory

  jwt.verify(token, process.env.JWT_SECRET, async (err, user) => {
      if (err) {
          return res.sendStatus(403);
      }

      const conn = new Client();
      conn.on('ready', () => {
          conn.sftp(async (err, sftp) => {
              if (err) {
                  console.error('SFTP connection error:', err);
                  return res.status(500).send('SFTP connection error: ' + err.message);
              }

              try {
                  const stats = await sftpStat(sftp, filePath);
                  
                  if (stats.isDirectory()) {
                      await downloadDirectory(sftp, filePath, localPath); // Recursively download directory
                      const zipPath = await zipDirectory(localPath, filename);
                      
                      res.download(zipPath, `${filename}.zip`, (err) => {
                          if (err) {
                              console.error('Error sending the zip file:', err);
                              return; // Stop any further execution
                          }
                          // Log the download activity after sending the zip file
                          const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
                          logSFTPServerAction(user.username, 'download', filePath, ipAddress);
                          // Cleanup local files after sending
                          exec(`rm -rf "${localPath}" "${zipPath}"`);
                      });
                  } else {
                      // Handle single file download
                      res.cookie('fileDownload', 'true', { path: '/', httpOnly: true });
                      res.attachment(filename);
                      const fileStream = sftpReadStream(sftp, filePath);
                      
                      // Ensure the stream is piped correctly and errors are caught
                      await pipeline(fileStream, res).catch((err) => {
                          console.error('Pipeline error:', err);
                          res.status(500).send('Error streaming file');
                      });

                      // Log the download activity
                      const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
                      logSFTPServerAction(user.username, 'download', filePath, ipAddress);
                  }
              } catch (error) {
                  console.error('Failed to process download:', error);
                  if (!res.headersSent) {
                      res.status(500).send('Failed to process download: ' + error.message);
                  }
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

app.post('/lovely/upload', authenticateJWT, (req, res) => {
  let files = req.files.files; // Files uploaded
  const destinationPath = req.body.path; // Destination directory

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
                  files = [files];
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
                  const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
                  console.log('IP Address:', ipAddress); // Debug logging
                  logSFTPServerAction(req.user.username, 'upload', remoteFilePath, ipAddress);
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



const server = app.listen(port, () => {
  console.log(`Server listening at http://localhost:${port}`);
  server.timeout = 0;
  // Attach WebSocket server to the same HTTP server
  wss = new WebSocket.Server({ server });

  wss.on('connection', function connection(ws) {
    console.log('Client connected to WebSocket.');

    // Add any message handlers or other WebSocket-related code here
  });
});


