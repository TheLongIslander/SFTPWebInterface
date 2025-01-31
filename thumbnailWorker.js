const { parentPort, workerData } = require('worker_threads');
const { Client } = require('ssh2');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn } = require('child_process');

// Path to the placeholder image (this can be passed from workerData or hardcoded)
const placeholderImagePath = workerData.placeholderImagePath || '/Users/adityarajesh/Pictures/lovely-server/assets/android-chrome-512x512.png';

async function generateThumbnailForVideo(filePath, cacheDir, sftpConnectionDetails) {
    const tempLocalVideoPath = path.join(os.tmpdir(), `${path.basename(filePath)}`);
    const tempThumbnailPath = path.join(os.tmpdir(), `${path.basename(filePath)}.jpg`);
    const cacheFilePath = path.join(cacheDir, path.basename(filePath) + '.jpg');

    if (fs.existsSync(cacheFilePath)) {
        parentPort.postMessage({ success: `Thumbnail already cached for ${filePath}` });
        return;
    }

    console.log('Starting video download:', tempLocalVideoPath);

    const conn = new Client();
    conn.on('ready', () => {
        conn.sftp((err, sftp) => {
            if (err) {
                console.error('SFTP session error:', err);
                parentPort.postMessage({ error: `SFTP session error for ${filePath}` });
                return;
            }

            const videoStream = sftp.createReadStream(filePath);
            const videoFileWriteStream = fs.createWriteStream(tempLocalVideoPath);

            videoStream.pipe(videoFileWriteStream);

            videoFileWriteStream.on('finish', () => {
                console.log('Video downloaded successfully:', tempLocalVideoPath);

                if (!fs.existsSync(tempLocalVideoPath)) {
                    console.error('Downloaded video file not found:', tempLocalVideoPath);
                    parentPort.postMessage({ error: `Video file not found: ${filePath}` });
                    return;
                }

                // Generate the thumbnail using ffmpeg
                const ffmpeg = spawn('ffmpeg', [
                    '-y',                           // Overwrite any existing files without prompt
                    '-i', tempLocalVideoPath,       // Local path to the downloaded video
                    '-ss', '00:01:00',              // Capture frame at 60 seconds in
                    '-vframes', '1',                // Capture one frame
                    '-vf', 'scale=1280:-1,format=yuv420p', // Scale and format the output
                    '-q:v', '5',                    // Quality level for the thumbnail
                    tempThumbnailPath               // Output file for the thumbnail
                ]);

                // Log ffmpeg stderr output to capture errors
                ffmpeg.stderr.on('data', (data) => {
                    console.error(`ffmpeg stderr for ${filePath}: ${data}`);
                });

                ffmpeg.on('close', (code) => {
                    if (code !== 0) {
                        console.error(`ffmpeg process exited with code ${code} for file: ${filePath}`);
                        // Copy the placeholder image on ffmpeg failure
                        fs.copyFileSync(placeholderImagePath, cacheFilePath);
                        parentPort.postMessage({ error: `ffmpeg error, using placeholder for ${filePath}` });
                        cleanupTempFiles(tempLocalVideoPath, tempThumbnailPath);
                        return;
                    }

                    // Cache the generated thumbnail
                    fs.copyFileSync(tempThumbnailPath, cacheFilePath);

                    // Clean up the temporary video and thumbnail files
                    cleanupTempFiles(tempLocalVideoPath, tempThumbnailPath);

                    parentPort.postMessage({ success: `Thumbnail generated for ${filePath}` });
                });

                ffmpeg.on('error', (error) => {
                    console.error('Error executing ffmpeg for file:', filePath, error);
                    // Copy the placeholder image if ffmpeg encounters an error
                    fs.copyFileSync(placeholderImagePath, cacheFilePath);
                    parentPort.postMessage({ error: `ffmpeg execution error: ${error.message}, using placeholder for ${filePath}` });
                    cleanupTempFiles(tempLocalVideoPath, tempThumbnailPath);
                });
            });

            videoFileWriteStream.on('error', (err) => {
                console.error('Error writing video file to local temp path for file:', filePath, err);
                parentPort.postMessage({ error: `Error writing video file: ${err.message}` });
            });
        });
    }).connect(sftpConnectionDetails);
}

// Helper function to clean up temporary files
function cleanupTempFiles(tempVideoPath, tempThumbnailPath) {
    fs.unlink(tempVideoPath, (err) => {
        if (err && err.code !== 'ENOENT') {
            console.error('Error deleting temp video file:', err);
        } else {
            console.log('Temp video file deleted:', tempVideoPath);
        }
    });

    fs.access(tempThumbnailPath, fs.constants.F_OK, (err) => {
        if (!err) {
            fs.unlink(tempThumbnailPath, (unlinkErr) => {
                if (unlinkErr) {
                    console.error('Error deleting temp thumbnail file:', unlinkErr);
                } else {
                    console.log('Temp thumbnail file deleted:', tempThumbnailPath);
                }
            });
        } else {
            console.log('No temp thumbnail file to delete:', tempThumbnailPath);
        }
    });
}

// Start generating the thumbnail
generateThumbnailForVideo(workerData.filePath, workerData.cacheDir, workerData.sftpConnectionDetails);
