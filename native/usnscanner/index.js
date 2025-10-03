const path = require('path');

function loadBinding() {
  const release = path.join(__dirname, '..', '..', 'build', 'Release', 'usnscanner.node');
  const debug = path.join(__dirname, '..', '..', 'build', 'Debug', 'usnscanner.node');

  try {
    return require(release);
  } catch (error) {
    if (error.code !== 'MODULE_NOT_FOUND') {
      throw error;
    }
  }

  return require(debug);
}

const binding = loadBinding();

function scan(driveLetter) {
  return new Promise((resolve, reject) => {
    binding.scan(driveLetter, (err, result) => {
      if (err) {
        reject(err);
      } else {
        resolve(result);
      }
    });
  });
}

function getFileRecord(driveLetter, fileReference) {
  return new Promise((resolve, reject) => {
    binding.getFileRecord(driveLetter, String(fileReference), (err, result) => {
      if (err) {
        reject(err);
      } else {
        resolve(result);
      }
    });
  });
}

function recoverDataRuns(driveLetter, runs, clusterSize, fileSize, outputPath) {
  return new Promise((resolve, reject) => {
    binding.recoverDataRuns(
      driveLetter,
      runs,
      String(clusterSize),
      String(fileSize),
      outputPath,
      (err) => {
        if (err) {
          reject(err);
        } else {
          resolve();
        }
      }
    );
  });
}

module.exports = {
  scan,
  getFileRecord,
  recoverDataRuns,
};
