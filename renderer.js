let foundFiles = [];
let selectedFiles = new Set();
let recoveryDirectory = null;

// DOM Elements
const driveSelect = document.getElementById('drive-select');
const scanBtn = document.getElementById('scan-btn');
const recoverBtn = document.getElementById('recover-btn');
const progressFill = document.getElementById('progress-fill');
const statusText = document.getElementById('status-text');
const filesTbody = document.getElementById('files-tbody');
const selectAllCheckbox = document.getElementById('select-all');
const selectedCountSpan = document.getElementById('selected-count');
const chooseRecoveryBtn = document.getElementById('choose-recovery');
const recoveryPathDisplay = document.getElementById('recovery-path');

// Filter checkboxes
const filterAll = document.getElementById('filter-all');
const filterImages = document.getElementById('filter-images');
const filterDocuments = document.getElementById('filter-documents');
const filterVideos = document.getElementById('filter-videos');

// Initialize
async function init() {
    scanBtn.disabled = true;
    await loadDrives();
    setupEventListeners();
    setupProgressListener();
    updateRecoveryPathDisplay();
}

// Load available drives
async function loadDrives() {
    try {
        const drives = await window.electronAPI.getDrives();
        driveSelect.innerHTML = '';

        if (drives.length === 0) {
            driveSelect.innerHTML = '<option value="">No drives found</option>';
            scanBtn.disabled = true;
            statusText.textContent = 'No drives detected. Try running the app as administrator.';
            return;
        }

        scanBtn.disabled = false;
        statusText.textContent = 'Ready to scan...';

        drives.forEach(drive => {
            const option = document.createElement('option');
            option.value = drive.name;
            option.textContent = `${drive.name} - ${drive.description} (${drive.filesystem})`;
            driveSelect.appendChild(option);
        });

        driveSelect.value = drives[0].name;
    } catch (error) {
        console.error('Error loading drives:', error);
        statusText.textContent = 'Error loading drives';
        scanBtn.disabled = true;
    }
}

// Setup event listeners
function setupEventListeners() {
    scanBtn.addEventListener('click', startScan);
    recoverBtn.addEventListener('click', recoverSelected);
    selectAllCheckbox.addEventListener('change', toggleSelectAll);

    if (chooseRecoveryBtn) {
        chooseRecoveryBtn.addEventListener('click', selectRecoveryFolder);
    }
    
    // Filter checkboxes
    filterAll.addEventListener('change', () => {
        if (filterAll.checked) {
            filterImages.checked = false;
            filterDocuments.checked = false;
            filterVideos.checked = false;
        }
        applyFilters();
    });
    
    [filterImages, filterDocuments, filterVideos].forEach(checkbox => {
        checkbox.addEventListener('change', () => {
            if (checkbox.checked) {
                filterAll.checked = false;
            }
            applyFilters();
        });
    });
}

// Setup progress listener
function setupProgressListener() {
    window.electronAPI.onScanProgress((progress) => {
        updateProgress(progress);
    });
}

// Start scanning
async function startScan() {
    const selectedDrive = driveSelect.value;
    
    if (!selectedDrive) {
        alert('Please select a drive to scan');
        return;
    }
    
    // Reset state
    foundFiles = [];
    selectedFiles.clear();
    filesTbody.innerHTML = '<tr class="empty-state"><td colspan="9">Scanning...</td></tr>';
    
    // Disable controls
    scanBtn.disabled = true;
    recoverBtn.disabled = true;
    statusText.textContent = 'Scanning drive...';
    updateProgress(0);
    
    try {
        const files = await window.electronAPI.scanDrive(selectedDrive);
        foundFiles = files.map(file => ({
            ...file,
            recoveryStatus: 'Not recovered',
            recoveredPath: null,
            recoveryError: null
        }));
        renderFiles();
        statusText.textContent = `Scan completed. Found ${files.length} deleted file(s)`;
        updateProgress(100);
    } catch (error) {
        console.error('Error scanning drive:', error);
        statusText.textContent = 'Error scanning drive';
        filesTbody.innerHTML = '<tr class="empty-state"><td colspan="9">Error scanning drive</td></tr>';
    } finally {
        scanBtn.disabled = false;
    }
}

// Display files in table
function displayFiles(files) {
    if (files.length === 0) {
        filesTbody.innerHTML = '<tr class="empty-state"><td colspan="9">No deleted files found</td></tr>';
        updateSelectAllCheckbox([]);
        return;
    }

    filesTbody.innerHTML = '';

    const filteredIndexes = [];

    files.forEach((file, index) => {
        const row = document.createElement('tr');
        const globalIndex = foundFiles.indexOf(file);

        if (globalIndex === -1) {
            return;
        }

        row.dataset.index = globalIndex;
        filteredIndexes.push(globalIndex);

        const recoveryClass = file.recoveryChance >= 80 ? 'recovery-excellent' :
                            file.recoveryChance >= 50 ? 'recovery-good' : 'recovery-poor';

        const statusText = file.recoveryChance >= 80 ? 'Excellent' :
                          file.recoveryChance >= 50 ? 'Good' : 'Poor';

        const recoveryResult = formatRecoveryResult(file);

        row.innerHTML = `
            <td><input type="checkbox" class="file-checkbox" data-index="${globalIndex}"></td>
            <td>${escapeHtml(file.name)}</td>
            <td>${escapeHtml(file.path)}</td>
            <td>${formatFileSize(file.size)}</td>
            <td>${formatDate(file.deletedTime)}</td>
            <td>${file.recoveryChance}%</td>
            <td><span class="recovery-badge ${recoveryClass}">${statusText}</span></td>
            <td>${formatSource(file)}</td>
            <td>${recoveryResult}</td>
        `;

        filesTbody.appendChild(row);
    });

    // Add checkbox listeners
    document.querySelectorAll('.file-checkbox').forEach(checkbox => {
        const index = parseInt(checkbox.dataset.index, 10);
        if (selectedFiles.has(index)) {
            checkbox.checked = true;
        }
        checkbox.addEventListener('change', handleFileSelection);
    });

    updateSelectAllCheckbox(filteredIndexes);
}

// Apply filters
function applyFilters() {
    const filtered = getFilteredFiles();
    displayFiles(filtered);
}

// Handle file selection
function handleFileSelection(event) {
    const index = parseInt(event.target.dataset.index, 10);

    if (event.target.checked) {
        selectedFiles.add(index);
    } else {
        selectedFiles.delete(index);
    }

    updateSelectedCount();
    updateSelectAllCheckbox(getVisibleIndexes());
}

// Toggle select all
function toggleSelectAll() {
    const checkboxes = document.querySelectorAll('.file-checkbox');
    const indices = [];

    if (selectAllCheckbox.checked) {
        checkboxes.forEach(checkbox => {
            const index = parseInt(checkbox.dataset.index, 10);
            if (Number.isInteger(index)) {
                checkbox.checked = true;
                selectedFiles.add(index);
                indices.push(index);
            }
        });
    } else {
        checkboxes.forEach(checkbox => {
            const index = parseInt(checkbox.dataset.index, 10);
            if (Number.isInteger(index)) {
                checkbox.checked = false;
                selectedFiles.delete(index);
                indices.push(index);
            }
        });
    }

    updateSelectedCount();
    updateSelectAllCheckbox(indices);
}

// Update selected count
function updateSelectedCount() {
    selectedCountSpan.textContent = selectedFiles.size;
    recoverBtn.disabled = selectedFiles.size === 0;
}

function renderFiles() {
    const filtered = getFilteredFiles();
    displayFiles(filtered);
}

function getFilteredFiles() {
    const showAll = filterAll.checked;
    const showImages = filterImages.checked;
    const showDocuments = filterDocuments.checked;
    const showVideos = filterVideos.checked;

    if (!showAll && !showImages && !showDocuments && !showVideos) {
        filterAll.checked = true;
        return foundFiles.slice();
    }

    return foundFiles.filter(file => {
        if (showAll) return true;
        if (showImages && file.type === 'image') return true;
        if (showDocuments && file.type === 'document') return true;
        if (showVideos && file.type === 'video') return true;
        return false;
    });
}

function updateSelectAllCheckbox(indexes = []) {
    if (!selectAllCheckbox) {
        return;
    }

    const validIndexes = indexes.filter(index => Number.isInteger(index) && index >= 0);
    const hasVisible = validIndexes.length > 0;

    if (!hasVisible) {
        selectAllCheckbox.checked = false;
        selectAllCheckbox.indeterminate = false;
        return;
    }

    const allSelected = validIndexes.every(index => selectedFiles.has(index));
    const someSelected = validIndexes.some(index => selectedFiles.has(index));

    selectAllCheckbox.checked = allSelected;
    selectAllCheckbox.indeterminate = !allSelected && someSelected;
}

function getVisibleIndexes() {
    return Array.from(document.querySelectorAll('.file-checkbox'))
        .map(checkbox => parseInt(checkbox.dataset.index, 10))
        .filter(index => Number.isInteger(index) && index >= 0);
}

function formatRecoveryResult(file) {
    const status = file.recoveryStatus || 'Not recovered';
    let cssClass = 'result-badge pending';
    let title = '';

    if (status === 'Recovered') {
        cssClass = 'result-badge success';
        if (file.recoveredPath) {
            title = `Recovered to: ${file.recoveredPath}`;
        }
    } else if (status === 'Failed') {
        cssClass = 'result-badge error';
        if (file.recoveryError) {
            title = `Error: ${file.recoveryError}`;
        }
    }

    const span = document.createElement('span');
    span.className = cssClass;
    span.textContent = status;
    if (title) {
        span.title = title;
    }

    const wrapper = document.createElement('div');
    wrapper.appendChild(span);
    return wrapper.innerHTML;
}

async function selectRecoveryFolder() {
    try {
        const directory = await window.electronAPI.selectRecoveryDirectory();
        if (directory) {
            recoveryDirectory = directory;
            updateRecoveryPathDisplay(directory);
        }
    } catch (error) {
        console.error('Error selecting recovery directory:', error);
    }
}

function updateRecoveryPathDisplay(directory = recoveryDirectory) {
    if (!recoveryPathDisplay) {
        return;
    }

    const label = directory || 'Application folder';
    recoveryPathDisplay.textContent = label;
    recoveryPathDisplay.title = label;
}

// Recover selected files
async function recoverSelected() {
    if (selectedFiles.size === 0) {
        alert('Please select files to recover');
        return;
    }

    const filesToRecover = Array.from(selectedFiles)
        .map(index => foundFiles[index])
        .filter(Boolean);

    if (filesToRecover.length === 0) {
        alert('Selected files are no longer available. Please rescan.');
        selectedFiles.clear();
        updateSelectedCount();
        renderFiles();
        return;
    }

    if (!recoveryDirectory) {
        const confirmDefault = confirm('No recovery folder selected. Recovered files will be saved in the application folder. Continue?');
        if (!confirmDefault) {
            return;
        }
    }

    statusText.textContent = `Recovering ${filesToRecover.length} file(s)...`;
    recoverBtn.disabled = true;

    let recovered = 0;
    let failed = 0;
    const errors = [];

    const recoveryOptions = recoveryDirectory ? { outputDir: recoveryDirectory } : {};

    for (const file of filesToRecover) {
        try {
            const result = await window.electronAPI.recoverFile(file, recoveryOptions);
            if (result && result.success) {
                file.recoveryStatus = 'Recovered';
                file.recoveredPath = result.outputPath;
                file.recoveryError = null;
                recovered++;
            } else {
                file.recoveryStatus = 'Failed';
                file.recoveredPath = null;
                file.recoveryError = (result && result.error) || 'Unknown error';
                failed++;
                errors.push({ file, error: file.recoveryError });
            }
        } catch (error) {
            console.error('Error recovering file:', error);
            file.recoveryStatus = 'Failed';
            file.recoveredPath = null;
            file.recoveryError = error.message;
            failed++;
            errors.push({ file, error: error.message });
        }
    }

    selectedFiles.clear();
    renderFiles();
    updateSelectedCount();
    updateSelectAllCheckbox(getVisibleIndexes());

    const destinationText = recoveryDirectory ? `the selected folder (${recoveryDirectory})` : 'the application folder';
    const summary = `Recovered ${recovered} of ${filesToRecover.length} file(s) to ${destinationText}.`;
    statusText.textContent = summary;

    if (failed > 0) {
        const errorDetails = errors.slice(0, 5)
            .map(({ file, error }) => `${file.name}: ${error}`)
            .join('\n');
        const suffix = errors.length > 5 ? '\n...' : '';
        alert(`${summary}\n${failed} file(s) could not be recovered. Check the status column for details.\n${errorDetails}${suffix}`);
    } else {
        alert(summary);
    }

    recoverBtn.disabled = false;
}

// Update progress bar
function updateProgress(progress) {
    progressFill.style.width = `${progress}%`;
    progressFill.textContent = progress > 0 ? `${progress}%` : '';
}

// Utility functions
function formatSource(file) {
    const source = file && file.source ? file.source : 'unknown';
    if (source === 'recycle-bin') {
        return 'Recycle Bin';
    }
    if (source === 'usn-journal') {
        return 'USN Journal';
    }
    return source;
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Initialize app
init();
