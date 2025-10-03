const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
    getDrives: () => ipcRenderer.invoke('get-drives'),
    scanDrive: (drivePath) => ipcRenderer.invoke('scan-drive', drivePath),
    recoverFile: (fileInfo, options) => ipcRenderer.invoke('recover-file', fileInfo, options),
    selectRecoveryDirectory: () => ipcRenderer.invoke('select-recovery-directory'),
    onScanProgress: (callback) => ipcRenderer.on('scan-progress', (event, progress) => callback(progress))
});
