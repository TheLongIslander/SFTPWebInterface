const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();

// Initialize the SQLite database for blacklisted tokens
const db = new sqlite3.Database('./token_blacklist.db', sqlite3.OPEN_READWRITE, (err) => {
    if (err) {
        return console.error('Error opening database:', err.message);
    }
    console.log('Connected to the token blacklist database.');
});

// Initialize the database for general server logs
const logDB = new sqlite3.Database('./server_logs.db', sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
    if (err) {
        console.error('Error when creating the server logs database', err);
    } else {
        console.log('Server logs database created!');
        logDB.run(`CREATE TABLE IF NOT EXISTS server_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )`);
    }
});

// Initialize the database for SFTP activity logs
const activityDb = new sqlite3.Database('./sftp_activity_log.db', sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
    if (err) {
      console.error(err.message);
    }
    activityDb.run(`
      CREATE TABLE IF NOT EXISTS sftp_activity_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        action TEXT,
        file_path TEXT,
        timestamp TEXT,
        ip_address TEXT
      )
    `, (err) => {
      if (err) {
        console.error('Error creating sftp_activity_log table:', err.message);
      }
    });
});

// Get current Eastern Time as a formatted string
function getEasternTime() {
    const date = new Date();
    return date.toLocaleString('en-US', { timeZone: 'America/New_York' });
}

// Get formatted date in a more readable format
function getFormattedDate() {
    const date = new Date();
    const day = date.getDate();
    const month = date.toLocaleString('en-US', { month: 'long', timeZone: 'America/New_York' });
    const year = date.getFullYear();
    let suffix = 'th';
    if (day % 10 === 1 && day !== 11) suffix = 'st';
    else if (day % 10 === 2 && day !== 12) suffix = 'nd';
    else if (day % 10 === 3 && day !== 13) suffix = 'rd';

    return `${month} ${day}${suffix}, ${year}`;
}

// Get Eastern Date and hour in numeric format
function getEasternDateHour() {
    const date = new Date();
    return date.toLocaleString('en-US', { timeZone: 'America/New_York', hour12: false, hour: 'numeric', year: 'numeric', month: 'long', day: 'numeric' });
}

// Cleanup expired tokens in the blacklist database
function cleanupExpiredTokens() {
    console.log("Running cleanup...");
    db.all('SELECT token FROM blacklisted_tokens', [], (err, rows) => {
        if (err) {
            return console.error(err.message);
        }
        rows.forEach(row => {
            const decoded = jwt.decode(row.token, { complete: true });
            if (decoded && decoded.payload.exp * 1000 < Date.now()) {
                db.run('DELETE FROM blacklisted_tokens WHERE token = ?', [row.token], (err) => {
                    if (err) {
                        console.error('Failed to delete expired token:', err.message);
                    }
                });
            }
        });
    });
}

// Log general server actions
function logServerAction(action) {
    const timestamp = getEasternTime(); // This will fetch the time in Eastern Time
    logDB.run('INSERT INTO server_logs (action, timestamp) VALUES (?, ?)', [action, timestamp], (err) => {
        if (err) {
            return console.error('Error logging to server_logs database:', err.message);
        }
        console.log(`Logged action "${action}" at ${timestamp}`);
    });
}

// Log SFTP server actions with detailed information
function logSFTPServerAction(username, action, filePath, ipAddress) {
    const timestamp = getEasternTime(); // Fetch the time in Eastern Time
    console.log(`Attempting to log action: ${action} by ${username} on ${filePath} at ${timestamp} from IP ${ipAddress}`); // Debug log
    activityDb.run(`
        INSERT INTO sftp_activity_log (username, action, file_path, timestamp, ip_address)
        VALUES (?, ?, ?, ?, ?)
    `, [username, action, filePath, timestamp, ipAddress], (err) => {
        if (err) {
            return console.error('Error logging to sftp_activity_log database:', err.message);
        }
        console.log(`Logged SFTP action "${action}" by ${username} on ${filePath} at ${timestamp} from IP ${ipAddress}`);
    });
}

module.exports = {
    getEasternTime,
    getFormattedDate,
    getEasternDateHour,
    cleanupExpiredTokens,
    logServerAction,
    logSFTPServerAction
};
