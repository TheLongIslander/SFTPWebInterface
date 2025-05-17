const downloadWindows = {};  // Map to track opened popup windows by requestId
const progressStateMap = {}; // Tracks previous progress and inferred phase per requestId


function setupWebSocket() {
    if (window.ws && window.ws.readyState !== WebSocket.CLOSED) {
        console.log("[DEBUG] WebSocket is already open. Skipping new connection.");
        return;
    }

    console.log("[DEBUG] Initializing new WebSocket connection...");
    window.ws = new WebSocket(`wss://${window.location.host}/lovely`);

    window.ws.onopen = function () {
        console.log("[DEBUG] WebSocket connected successfully.");
    };

    window.ws.onmessage = function (event) {
        try {
            const message = JSON.parse(event.data);
            console.log("[DEBUG] Received WebSocket message:", message);

            if (!message.requestId) {
                console.error("[ERROR] WebSocket message missing requestId:", message);
                return;
            }

            const requestId = message.requestId;

            if (message.type === "progress") {
                updateZipProgress(requestId, message.progress);
            } // inside setupWebSocket().onmessage:
            else if (message.type === "complete") {
                console.log(`[DEBUG] Download ready for Request ID: ${requestId}`);
            
                // Just in case compressing didn't clean it up
                const form = document.querySelector(`form[data-request-id="${requestId}"]`);
                if (form) {
                    console.log(`[DEBUG] Final cleanup: hiding spinner for Request ID ${requestId}`);
                    hideLoadingSpinner(form);
                }
            
                const fullUrl = `${window.location.origin}/lovely/downloads/${requestId}`;
                console.log("[DEBUG] Full download URL:", fullUrl);
            
                const popup = downloadWindows[requestId];
                if (popup && !popup.closed) {
                    console.log("[DEBUG] Navigating pre-opened window to:", fullUrl);
                    popup.location = fullUrl;
                } else {
                    console.warn("[DEBUG] No pre-opened window found; opening new tab.");
                    window.open(fullUrl, "_blank");
                }
            
                delete downloadWindows[requestId];
            }
            

        } catch (error) {
            console.error("[ERROR] Failed to parse WebSocket message:", error.message, event.data);
        }
    };

    window.ws.onerror = function (err) {
        console.error("[DEBUG] WebSocket error:", err.message);
        window.ws.close();
    };

    window.ws.onclose = function (event) {
        console.warn("[DEBUG] WebSocket closed:", event.reason || "No reason provided.");
        setTimeout(() => {
            if (!window.ws || window.ws.readyState === WebSocket.CLOSED) {
                console.log("[DEBUG] Attempting to reconnect WebSocket...");
                setupWebSocket();
            }
        }, 3000);
    };
}




// Ensure the WebSocket is only initialized once on DOMContentLoaded
document.addEventListener("DOMContentLoaded", function () {
    if (!window.ws || window.ws.readyState === WebSocket.CLOSED) {
        console.log("[DEBUG] DOMContentLoaded: Setting up WebSocket.");
        setupWebSocket();
    } else {
        console.log("[DEBUG] WebSocket already exists. Skipping reinitialization.");
    }
});


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
        typingInProgress = true;
    });

    pathInput.addEventListener('blur', function () {
        typingInProgress = false;
    });

    const createDirectoryButton = document.getElementById('create-directory-button');
    createDirectoryButton.addEventListener('click', function () {
        const directoryName = prompt('Enter the new directory name:');
        if (directoryName) {
            createDirectory(directoryName);
        }
    });

    const uploadForm = document.getElementById('upload-form');
    uploadForm.addEventListener('submit', function (event) {
        event.preventDefault();
        uploadFiles();
    });

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

    detectUserActivity();

    document.querySelectorAll('.download-form').forEach(downloadForm => {
        downloadForm.onsubmit = async function (event) {
            event.preventDefault();

            const token = localStorage.getItem('token');
            if (!token) {
                alert('Authentication required. Please log in again.');
                return false;
            }

            const filePath = this.querySelector('input[name="path"]').value;
            const requestId = generateUniqueId();
            this.dataset.requestId = requestId;

            // Open a blank popup immediately (user gesture)
            const popup = window.open('', '', 'width=600,height=400');
            downloadWindows[requestId] = popup;

            showLoadingSpinner(this, requestId);

            try {
                const res = await fetch('/lovely/download', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + token
                    },
                    body: JSON.stringify({ token, path: filePath, requestId })
                });
                if (!res.ok) throw new Error(res.statusText);

                const { requestId: confirmed } = await res.json();
                console.log('Download started (ID):', confirmed);
            } catch (err) {
                console.error('Failed to initiate download:', err);
                hideLoadingSpinner(this);
                alert('Download initiation failed: ' + err.message);
                // If popup exists, close it
                if (popup && !popup.closed) popup.close();
                delete downloadWindows[requestId];
            }

            return false;
        };
    });

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

                        fetch('/lovely/download', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                token: localStorage.getItem('token'),
                                path: pathInput.value
                            })
                        })
                            .then(response => response.json())
                            .then(data => {
                                if (!data.requestId) {
                                    throw new Error('Backend did not return a requestId!');
                                }

                                console.log(`[DEBUG] Received Request ID from Backend: ${data.requestId}`);
                                const requestId = data.requestId;  // Define requestId properly here
                                downloadForm.dataset.requestId = requestId; // Assign backend's request ID


                                showLoadingSpinner(downloadForm, requestId);

                                return fetch('/lovely/download', {
                                    method: 'POST',
                                    headers: {
                                        'Content-Type': 'application/json'
                                    },
                                    body: JSON.stringify({
                                        token: localStorage.getItem('token'),
                                        path: pathInput.value,
                                        requestId: requestId  // Use requestId properly
                                    })
                                });
                            })
                            .then(response => response.json())
                            .then(data => {
                                console.log(`[DEBUG] Download initiated with Request ID: ${data.requestId}`);
                            })
                            .catch(error => {
                                console.error('Download initiation failed:', error);
                                alert('Error initiating download.');
                            });

                        return false;  // Prevent the form from actually submitting
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

    const progressLabel = form.querySelector('.zip-progress-label');
    if (progressLabel) {
        progressLabel.remove();
    }

    // 🧹 Clean up request progress tracking
    if (form.dataset.requestId) {
        delete progressStateMap[form.dataset.requestId];
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
    const forms = document.querySelectorAll('form');
    let formFound = false;

    // Get or initialize previous state
    if (!progressStateMap[requestId]) {
        progressStateMap[requestId] = { lastProgress: -1, phase: 'retrieving' };
    }

    const state = progressStateMap[requestId];

    // Detect phase switch: went from 100 to 0
    // Infer compressing phase more reliably
    console.log(`[DEBUG] Checking phase switch: last=${state.lastProgress}, current=${progress}`);
    if (state.phase === 'retrieving' && progress <= 1 && state.lastProgress >= 98) {
        console.log(`[DEBUG] Phase switch detected: retrieving → compressing`);
        state.phase = 'compressing';
    }

    state.lastProgress = progress;

    forms.forEach(form => {
        const formRequestId = form.dataset.requestId;
        if (!formRequestId) {
            console.warn(`[DEBUG] Skipping form with undefined request ID.`);
            return;
        }

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

            // === Add/update label ===
            let progressLabel = form.querySelector('.zip-progress-label');
            if (!progressLabel) {
                progressLabel = document.createElement('div');
                progressLabel.classList.add('zip-progress-label');
                progressLabel.style.fontSize = '0.9em';
                progressLabel.style.marginTop = '4px';
                progressLabel.style.color = '#ccc';
                form.appendChild(progressLabel);
            }

            const label = `${capitalize(state.phase)} ${Math.round(progress)}%`;
            progressLabel.textContent = label;
            // =========================

            progressBar.style.display = 'none';
            progressBar.value = progress;
            progressBar.style.display = 'block';

            requestAnimationFrame(() => {
                progressBar.style.display = 'block';
                progressBar.offsetHeight;
            });

            if (progress >= 100) {
                if (state.phase === 'compressing') {
                    console.log(`[DEBUG] Hiding spinner for Request ID: ${requestId} (compression done)`);
                    hideLoadingSpinner(form);
                } else {
                    // retrieving just finished — leave the bar & label in place
                    console.log(`[DEBUG] Phase “retrieving” completed for ${requestId}, now waiting for compressing…`);
                }
            }
        }
    });

    if (!formFound) {
        console.warn(`[DEBUG] No matching form found for Request ID: ${requestId}`);
    }
}

function capitalize(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
}








