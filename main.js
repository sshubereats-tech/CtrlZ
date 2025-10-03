const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const fsp = fs.promises;
const { exec } = require('child_process');
const { disk } = require('node-disk-info');
const os = require('os');

let usnScanner = null;
try {
    usnScanner = require('./native/usnscanner');
} catch (error) {
    console.warn('USN scanner native module not available:', error.message || error);
}

let mainWindow;

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1000,
        height: 700,
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: true,
            preload: path.join(__dirname, 'preload.js')
        },
        icon: path.join(__dirname, 'assets', 'icon.png')
    });

    mainWindow.loadFile('index.html');
    
    // Open DevTools in development
    // mainWindow.webContents.openDevTools();
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
        createWindow();
    }
});

// IPC Handlers
ipcMain.handle('get-drives', async () => {
    try {
        if (process.platform === 'win32') {
            return await getWindowsDrives();
        } else if (process.platform === 'darwin') {
            return await getMacDrives();
        } else {
            return await getLinuxDrives();
        }
    } catch (error) {
        console.error('Error getting drives:', error);
        return [];
    }
});

ipcMain.handle('scan-drive', async (event, drivePath) => {
    try {
        const files = await scanForDeletedFiles(drivePath, (progress) => {
            event.sender.send('scan-progress', progress);
        });
        return files;
    } catch (error) {
        console.error('Error scanning drive:', error);
        throw error;
    }
});

ipcMain.handle('recover-file', async (event, fileInfo, options = {}) => {
    try {
        const result = await recoverFile(fileInfo, options);
        return result;
    } catch (error) {
        console.error('Error recovering file:', error);
        throw error;
    }
});

ipcMain.handle('select-recovery-directory', async () => {
    try {
        const { canceled, filePaths } = await dialog.showOpenDialog({
            properties: ['openDirectory', 'createDirectory']
        });

        if (canceled || !filePaths || filePaths.length === 0) {
            return null;
        }

        return filePaths[0];
    } catch (error) {
        console.error('Error selecting recovery directory:', error);
        throw error;
    }
});

// Platform-specific drive detection
async function getWindowsDrives() {
    const providers = [getDrivesFromNodeDiskInfo, getDrivesFromPowerShell, legacyWmicDriveLookup];

    for (const provider of providers) {
        try {
            const drives = await provider();
            if (Array.isArray(drives) && drives.length > 0) {
                return drives;
            }
        } catch (error) {
            console.warn('Drive provider failed:', provider.name || 'anonymous', error);
        }
    }

    return [];
}

async function getDrivesFromNodeDiskInfo() {
    const disks = await disk.getDiskInfo();
    const formatted = disks
        .filter(entry => entry.mounted && /^[A-Z]:/.test(entry.mounted))
        .map(entry => {
            const usedValue = safeNumber(entry.used);
            const freeValue = safeNumber(entry.available);
            const multiplier = 1024; // node-disk-info reports KiB on Windows
            const usedBytes = usedValue !== null ? usedValue * multiplier : null;
            const freeBytes = freeValue !== null ? freeValue * multiplier : null;

            return {
                name: entry.mounted,
                description: buildWindowsDescription({
                    mounted: entry.mounted,
                    friendlyName: entry.volumeName,
                    usedPercent: parsePercent(entry.capacity),
                    usedBytes,
                    freeBytes
                }),
                filesystem: entry.filesystem || 'Unknown'
            };
        })
        .filter(Boolean);

    return formatted;
}

async function getDrivesFromPowerShell() {
    return new Promise((resolve, reject) => {
        const psScript = 'Get-Volume | Where-Object DriveLetter -ne $null | Select-Object DriveLetter, FileSystemType, FriendlyName, SizeRemaining, Size | ConvertTo-Json -Compress';
        const command = `powershell -NoProfile -Command "${psScript}"`;

        exec(command, { windowsHide: true, maxBuffer: 5 * 1024 * 1024 }, (error, stdout) => {
            if (error) {
                reject(error);
                return;
            }

            const trimmed = stdout.trim();
            if (!trimmed) {
                resolve([]);
                return;
            }

            let volumes;
            try {
                volumes = JSON.parse(trimmed.replace(/^\uFEFF/, ''));
            } catch (parseError) {
                reject(parseError);
                return;
            }

            const list = Array.isArray(volumes) ? volumes : [volumes];
            const drives = list
                .filter(volume => volume && volume.DriveLetter)
                .map(volume => {
                    const name = `${String(volume.DriveLetter).toUpperCase()}:`;
                    const size = safeNumber(volume.Size);
                    const freeBytes = safeNumber(volume.SizeRemaining);
                    const usedBytes = size !== null && freeBytes !== null ? Math.max(size - freeBytes, 0) : null;
                    const usedPercent = size ? (usedBytes / size) * 100 : null;

                    return {
                        name,
                        description: buildWindowsDescription({
                            mounted: name,
                            friendlyName: volume.FriendlyName,
                            usedBytes,
                            freeBytes,
                            usedPercent
                        }),
                        filesystem: volume.FileSystemType || 'Unknown'
                    };
                });

            resolve(drives);
        });
    });
}

function legacyWmicDriveLookup() {
    return new Promise((resolve, reject) => {
        exec('wmic logicaldisk get caption,filesystem,volumename', (error, stdout) => {
            if (error) {
                reject(error);
                return;
            }

            const lines = stdout.split(/\r?\n/).slice(1);
            const drives = lines
                .map(line => line.trim())
                .filter(Boolean)
                .map(line => {
                    const match = line.match(/^([A-Z]:)\s+(\S*)\s*(.*)$/);
                    if (!match) {
                        return null;
                    }

                    const [, caption, filesystem, volumeName] = match;
                    return {
                        name: caption,
                        description: buildWindowsDescription({
                            mounted: caption,
                            friendlyName: volumeName
                        }),
                        filesystem: filesystem || 'Unknown'
                    };
                })
                .filter(Boolean);

            resolve(drives);
        });
    });
}

function buildWindowsDescription(data = {}) {
    const parts = [];
    const friendlyName = (data.friendlyName || '').trim();

    if (friendlyName && friendlyName.toLowerCase() !== String(data.mounted || '').toLowerCase()) {
        parts.push(friendlyName);
    }

    const usageSegments = [];

    if (Number.isFinite(data.usedPercent)) {
        usageSegments.push(`Used ${Math.round(data.usedPercent)}%`);
    } else if (Number.isFinite(data.usedBytes)) {
        const usedDisplay = formatBytes(data.usedBytes);
        if (usedDisplay) {
            usageSegments.push(`Used ${usedDisplay}`);
        }
    } else if (typeof data.capacity === 'string' && data.capacity.trim()) {
        usageSegments.push(`Used ${data.capacity.trim()}`);
    }

    if (Number.isFinite(data.freeBytes)) {
        usageSegments.push(`Free ${formatBytes(data.freeBytes)}`);
    } else if (data.available) {
        const freeDisplay = toDisplayBytes(data.available);
        if (freeDisplay) {
            usageSegments.push(`Free ${freeDisplay}`);
        }
    }

    if (usageSegments.length) {
        parts.push(usageSegments.join(' • '));
    }

    if (!parts.length) {
        parts.push(`Drive ${data.mounted || ''}`.trim());
    }

    return parts.join(' — ');
}

function safeNumber(value) {
    if (value === null || value === undefined) {
        return null;
    }

    const parsed = Number(String(value).replace(/[^0-9.-]/g, ''));
    return Number.isFinite(parsed) ? parsed : null;
}

function parsePercent(value) {
    if (typeof value === 'number' && Number.isFinite(value)) {
        return value;
    }

    if (typeof value === 'string') {
        const numeric = Number(value.replace('%', '').trim());
        return Number.isFinite(numeric) ? numeric : null;
    }

    return null;
}

function toDisplayBytes(value) {
    const numeric = safeNumber(value);
    if (numeric === null) {
        return null;
    }

    return formatBytes(numeric);
}

function formatBytes(bytes) {
    if (!Number.isFinite(bytes) || bytes < 0) {
        return null;
    }

    if (bytes === 0) {
        return '0 B';
    }

    const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    const value = bytes / Math.pow(1024, index);
    return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[index]}`;
}

async function getMacDrives() {
    return new Promise((resolve, reject) => {
        exec('diskutil list', (error, stdout) => {
            if (error) {
                reject(error);
                return;
            }
            
            const drives = [{
                name: '/',
                description: 'Main Drive',
                filesystem: 'APFS'
            }];
            
            resolve(drives);
        });
    });
}

async function getLinuxDrives() {
    return new Promise((resolve, reject) => {
        exec('lsblk -o NAME,MOUNTPOINT,FSTYPE -J', (error, stdout) => {
            if (error) {
                reject(error);
                return;
            }
            
            try {
                const data = JSON.parse(stdout);
                const drives = data.blockdevices
                    .filter(dev => dev.mountpoint)
                    .map(dev => ({
                        name: dev.mountpoint,
                        description: dev.name,
                        filesystem: dev.fstype || 'Unknown'
                    }));
                
                resolve(drives);
            } catch (e) {
                reject(e);
            }
        });
    });
}

// Scan for deleted files (simplified implementation)
async function scanForDeletedFiles(drivePath, progressCallback) {
    if (process.platform !== 'win32') {
        throw new Error('Native deleted-file scanning is only implemented for Windows in this build.');
    }

    const driveLetterMatch = typeof drivePath === 'string' ? drivePath.match(/[A-Za-z]/) : null;
    if (!driveLetterMatch) {
        throw new Error('Invalid drive path provided');
    }

    const driveLetter = driveLetterMatch[0].toUpperCase();
    const progress = (value) => {
        if (typeof progressCallback === 'function') {
            const clamped = Math.max(0, Math.min(100, Math.round(value)));
            progressCallback(clamped);
        }
    };

    progress(0);
    const recycleResults = await scanWindowsRecycleBin(driveLetter, (value) => {
        progress(value * 0.65);
    });

    let usnResults = [];
    if (usnScanner) {
        progress(70);
        try {
            usnResults = await scanWindowsUsnJournal(driveLetter);
        } catch (error) {
            console.warn('USN journal scan failed:', error);
        }
    }

    const combined = mergeDeletionResults(recycleResults, usnResults);
    progress(100);
    return combined;
}

// Recover file (simplified implementation)
async function recoverFile(fileInfo, options = {}) {
    const baseDirectory = options.outputDir || process.cwd();
    const prefix = options.prefix === undefined ? 'recovered_' : options.prefix;
    const useOriginalName = options.useOriginalName || prefix === '';
    const safeName = path.basename(fileInfo.name || 'file');
    const targetName = useOriginalName ? safeName : `${prefix}${safeName}`;
    const outputPath = path.join(baseDirectory, targetName);

    await fsp.mkdir(baseDirectory, { recursive: true });

    if (fileInfo.recycleBinPath) {
        await copyFile(fileInfo.recycleBinPath, outputPath);
        return { success: true, outputPath };
    }

    if (
        usnScanner &&
        fileInfo &&
        fileInfo.source === 'usn-journal' &&
        fileInfo.metadata &&
        fileInfo.metadata.fileReferenceNumber
    ) {
        const drive = extractDriveLetter(fileInfo) || (fileInfo.metadata.drive || '').toUpperCase();
        if (!drive) {
            throw new Error('Unable to determine drive letter for USN recovery.');
        }

        const record = await usnScanner.getFileRecord(drive, fileInfo.metadata.fileReferenceNumber);
        const attributes = Array.isArray(record.attributes) ? record.attributes : [];
        const dataAttribute = attributes.find((attr) => attr.type === 0x80 && (!attr.name || attr.name.length === 0))
            || attributes.find((attr) => attr.type === 0x80);

        if (!dataAttribute) {
            throw new Error('Data attribute not found in MFT record.');
        }

        const fileSizeString = dataAttribute.dataSize || dataAttribute.allocatedSize || '0';
        const clusterSizeString = record.clusterSize || String(record.bytesPerSector * record.sectorsPerCluster || 0);
        const parsedSize = Number.parseInt(fileSizeString, 10);
        if (Number.isFinite(parsedSize) && parsedSize >= 0) {
            fileInfo.size = parsedSize;
        }

        if (dataAttribute.nonResident) {
            const runs = Array.isArray(dataAttribute.runs) ? dataAttribute.runs : [];
            if (!runs.length) {
                throw new Error('Non-resident attribute lacks data runs.');
            }

            await usnScanner.recoverDataRuns(
                drive,
                runs,
                clusterSizeString,
                fileSizeString,
                outputPath
            );
            return { success: true, outputPath };
        }

        if (dataAttribute.residentDataBase64) {
            const buffer = Buffer.from(dataAttribute.residentDataBase64, 'base64');
            await fsp.writeFile(outputPath, buffer);
            fileInfo.size = buffer.length;
            return { success: true, outputPath };
        }

        throw new Error('Resident data missing payload for recovery.');
    }

    throw new Error('Binary source not available for this file.');
}

async function scanWindowsRecycleBin(driveLetter, progressCallback) {
    const letter = String(driveLetter || '').trim().toUpperCase();
    if (!letter || letter.length === 0) {
        if (typeof progressCallback === 'function') {
            progressCallback(100);
        }
        return [];
    }

    const recycleRoot = `${letter}:\\$Recycle.Bin`;

    const updateProgress = (value) => {
        if (typeof progressCallback === 'function') {
            const clamped = Math.max(0, Math.min(100, Math.round(value)));
            progressCallback(clamped);
        }
    };

    updateProgress(0);

    let sidEntries = [];
    try {
        sidEntries = await fsp.readdir(recycleRoot, { withFileTypes: true });
    } catch (error) {
        console.warn('Unable to read recycle bin root:', recycleRoot, error);
        updateProgress(100);
        return [];
    }

    const metadataFiles = [];
    for (const sidEntry of sidEntries) {
        if (!sidEntry.isDirectory()) {
            continue;
        }

        const sidPath = path.join(recycleRoot, sidEntry.name);
        let entries;
        try {
            entries = await fsp.readdir(sidPath, { withFileTypes: true });
        } catch (error) {
            continue;
        }

        for (const fileEntry of entries) {
            if (fileEntry.isFile() && fileEntry.name.startsWith('$I')) {
                metadataFiles.push(path.join(sidPath, fileEntry.name));
            }
        }
    }

    if (metadataFiles.length === 0) {
        updateProgress(100);
        return [];
    }

    const results = [];
    let processed = 0;
    const total = metadataFiles.length;

    for (const metadataPath of metadataFiles) {
        processed += 1;

        try {
            const info = await parseRecycleBinMetadata(metadataPath);
            if (!info) {
                continue;
            }

            if (!info.originalPath || !info.originalPath.toUpperCase().startsWith(`${letter}:\\`)) {
                continue;
            }

            const dataFilePath = getRecycleDataPath(metadataPath);
            const dataFileExists = await fileExists(dataFilePath);
            const deletionDate = info.deletionDate ? info.deletionDate.toISOString() : new Date().toISOString();

            results.push({
                name: path.basename(info.originalPath),
                path: path.dirname(info.originalPath),
                size: info.size,
                deletedTime: deletionDate,
                recoveryChance: dataFileExists ? 94 : 10,
                type: inferFileType(info.originalPath),
                recycleBinPath: dataFileExists ? dataFilePath : null,
                source: 'recycle-bin'
            });
        } catch (error) {
            console.warn('Failed to process recycle bin entry:', metadataPath, error);
        } finally {
            const progress = Math.min(100, Math.round((processed / total) * 100));
            updateProgress(progress);
        }
    }

    updateProgress(100);
    return results;
}

async function scanWindowsUsnJournal(driveLetter) {
    if (!usnScanner || typeof usnScanner.scan !== 'function') {
        return [];
    }

    const letter = String(driveLetter || '').trim().toUpperCase();
    if (!letter) {
        return [];
    }

    const entries = await usnScanner.scan(letter);
    const normalized = [];

    entries.forEach((entry) => {
        if (!entry || !entry.path || entry.isDirectory) {
            return;
        }

        const normalizedPath = path.win32.normalize(entry.path);
        const baseName = path.win32.basename(normalizedPath);
        const directory = path.win32.dirname(normalizedPath);
        const timestamp = Number.isFinite(entry.timestampMs) ? new Date(entry.timestampMs).toISOString() : new Date().toISOString();

        normalized.push({
            name: baseName,
            path: directory,
            size: 0,
            deletedTime: timestamp,
            recoveryChance: 25,
            type: inferFileType(normalizedPath),
            recycleBinPath: null,
            source: 'usn-journal',
            drive: letter,
            metadata: {
                reason: entry.reason,
                fileReferenceNumber: entry.fileReferenceNumber,
                parentReferenceNumber: entry.parentReferenceNumber,
                isDirectory: entry.isDirectory,
                drive: letter
            }
        });
    });

    return normalized;
}

function mergeDeletionResults(recycleEntries, usnEntries) {
    const combined = new Map();

    const addEntry = (entry) => {
        if (!entry || !entry.name) {
            return;
        }

        const fullPath = path.win32.normalize(path.win32.join(entry.path || '', entry.name));
        const key = fullPath.toLowerCase();

        if (!combined.has(key)) {
            combined.set(key, { ...entry, fullPath });
            return;
        }

        const existing = combined.get(key);
        const preferNew = entry.source === 'recycle-bin' && existing.source !== 'recycle-bin';
        if (preferNew) {
            combined.set(key, { ...entry, fullPath });
        }
    };

    (recycleEntries || []).forEach(addEntry);
    (usnEntries || []).forEach(addEntry);

    return Array.from(combined.values()).sort((a, b) => {
        if (a.deletedTime && b.deletedTime) {
            return b.deletedTime.localeCompare(a.deletedTime);
        }
        return 0;
    });
}

async function parseRecycleBinMetadata(metadataPath) {
    let buffer;
    try {
        buffer = await fsp.readFile(metadataPath);
    } catch (error) {
        return null;
    }

    if (!buffer || buffer.length < 24) {
        return null;
    }

    const version = buffer.readUInt8(0);
    if (version !== 1 && version !== 2) {
        return null;
    }

    const size = Number(buffer.readBigUInt64LE(8));
    const rawFileTime = buffer.readBigUInt64LE(16);
    const deletionDate = fileTimeToDate(rawFileTime);

    const pathBuffer = buffer.slice(24);
    const originalPath = pathBuffer.toString('utf16le').replace(/\u0000+$/g, '').trim();

    if (!originalPath) {
        return null;
    }

    return {
        size,
        deletionDate,
        originalPath
    };
}

function getRecycleDataPath(metadataPath) {
    const baseName = path.basename(metadataPath);
    const dataName = baseName.replace(/^\$I/i, '$R');
    return path.join(path.dirname(metadataPath), dataName);
}

async function copyFile(source, destination) {
    await new Promise((resolve, reject) => {
        const readStream = fs.createReadStream(source);
        const writeStream = fs.createWriteStream(destination);

        readStream.on('error', reject);
        writeStream.on('error', reject);
        writeStream.on('close', resolve);

        readStream.pipe(writeStream);
    });
}

async function fileExists(targetPath) {
    try {
        await fsp.access(targetPath, fs.constants.F_OK);
        return true;
    } catch (error) {
        return false;
    }
}

function fileTimeToDate(fileTime) {
    const WINDOWS_EPOCH_OFFSET_MS = 11644473600000;
    const hundredNanosecondsPerMillisecond = 10_000n;

    const asBigInt = typeof fileTime === 'bigint' ? fileTime : BigInt(fileTime);
    const millisecondsSinceWindowsEpoch = asBigInt / hundredNanosecondsPerMillisecond;
    const unixMilliseconds = Number(millisecondsSinceWindowsEpoch - BigInt(WINDOWS_EPOCH_OFFSET_MS));

    if (!Number.isFinite(unixMilliseconds)) {
        return null;
    }

    return new Date(unixMilliseconds);
}

function extractDriveLetter(fileInfo) {
    if (!fileInfo) {
        return '';
    }

    const candidates = [];

    if (typeof fileInfo.fullPath === 'string') {
        candidates.push(fileInfo.fullPath);
    }
    if (typeof fileInfo.path === 'string') {
        const joined = fileInfo.name ? path.join(fileInfo.path, fileInfo.name) : fileInfo.path;
        candidates.push(joined);
    }

    const meta = fileInfo.metadata || {};
    if (typeof meta.fullPath === 'string') {
        candidates.push(meta.fullPath);
    }
    if (typeof meta.originalPath === 'string') {
        candidates.push(meta.originalPath);
    }

    if (typeof fileInfo.drive === 'string') {
        candidates.push(fileInfo.drive);
    }
    if (typeof meta.drive === 'string') {
        candidates.push(meta.drive);
    }

    for (const candidate of candidates) {
        if (typeof candidate === 'string' && candidate.length >= 2 && candidate[1] === ':') {
            return candidate[0].toUpperCase();
        }
        if (typeof candidate === 'string' && candidate.length === 1 && /[a-zA-Z]/.test(candidate)) {
            return candidate.toUpperCase();
        }
    }

    return '';
}

function inferFileType(originalPath) {
    const extension = path.extname(originalPath).toLowerCase();
    if (!extension) {
        return 'other';
    }

    if (['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tif', '.tiff', '.heic', '.psd', '.raw'].includes(extension)) {
        return 'image';
    }

    if (['.doc', '.docx', '.pdf', '.txt', '.rtf', '.xls', '.xlsx', '.ppt', '.pptx', '.csv', '.json', '.md'].includes(extension)) {
        return 'document';
    }

    if (['.mp4', '.mov', '.avi', '.mkv', '.wmv', '.m4v'].includes(extension)) {
        return 'video';
    }

    if (['.mp3', '.wav', '.flac', '.aac', '.ogg', '.m4a'].includes(extension)) {
        return 'audio';
    }

    return 'other';
}
