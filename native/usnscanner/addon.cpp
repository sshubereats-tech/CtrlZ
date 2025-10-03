#include <napi.h>
#include <windows.h>
#include <winioctl.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <algorithm>
#include <cstring>
#include <cwctype>

namespace {

struct FileEntry {
    ULONGLONG parentRef;
    std::string name;
    bool isDirectory;
};

struct DeletedRecord {
    ULONGLONG fileRef;
    ULONGLONG parentRef;
    std::string name;
    bool isDirectory;
    double timestampMs;
    DWORD reason;
};

#pragma pack(push, 1)
#pragma pack(push, 1)
struct NtfsFileRecordInputBuffer {
    ULONGLONG FileReferenceNumber;
};

struct NtfsFileRecordOutputBuffer {
    ULONGLONG FileReferenceNumber;
    DWORD FileRecordLength;
    BYTE FileRecordBuffer[1];
};

struct FileRecordHeader {
    DWORD Magic; // 'FILE'
    WORD UpdateSequenceOffset;
    WORD UpdateSequenceSize;
    ULONGLONG LogFileSequenceNumber;
    WORD SequenceNumber;
    WORD HardLinkCount;
    WORD FirstAttributeOffset;
    WORD Flags;
    DWORD BytesInUse;
    DWORD BytesAllocated;
    ULONGLONG BaseFileRecord;
    WORD NextAttributeId;
    WORD Padding;
    DWORD MftRecordNumber;
};

struct AttributeRecordHeader {
    DWORD Type;
    DWORD Length;
    BYTE NonResident;
    BYTE NameLength;
    WORD NameOffset;
    WORD Flags;
    WORD Instance;
    union {
        struct {
            DWORD ValueLength;
            WORD ValueOffset;
            BYTE Flags;
            BYTE Reserved;
        } Resident;
        struct {
            ULONGLONG LowestVcn;
            ULONGLONG HighestVcn;
            WORD RunOffset;
            WORD CompressionUnit;
            DWORD Padding;
            ULONGLONG AllocatedSize;
            ULONGLONG DataSize;
            ULONGLONG InitializedSize;
            ULONGLONG CompressedSize;
        } NonResidentData;
    };
};
#pragma pack(pop)

struct DataRunSegment {
    long long vcnStart;
    long long lcn;
    long long length;
    bool sparse;
};

struct AttributeInfo {
    DWORD type;
    std::string typeName;
    bool nonResident;
    std::string name;
    ULONGLONG dataSize;
    ULONGLONG allocatedSize;
    std::vector<DataRunSegment> runs;
    std::vector<uint8_t> residentData;
};

std::string WideToUtf8(const std::wstring &input) {
    if (input.empty()) {
        return std::string();
    }

    int required = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), static_cast<int>(input.size()), nullptr, 0, nullptr, nullptr);
    if (required <= 0) {
        return std::string();
    }

    std::string output(static_cast<size_t>(required), '\0');
    WideCharToMultiByte(CP_UTF8, 0, input.c_str(), static_cast<int>(input.size()), output.data(), required, nullptr, nullptr);
    return output;
}

std::wstring Utf8ToWide(const std::string &input) {
    if (input.empty()) {
        return std::wstring();
    }

    int required = MultiByteToWideChar(CP_UTF8, 0, input.c_str(), static_cast<int>(input.size()), nullptr, 0);
    if (required <= 0) {
        return std::wstring();
    }

    std::wstring output(static_cast<size_t>(required), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, input.c_str(), static_cast<int>(input.size()), output.data(), required);
    return output;
}

std::string Base64Encode(const uint8_t *data, size_t length) {
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string output;
    output.reserve(((length + 2) / 3) * 4);

    size_t i = 0;
    while (i + 2 < length) {
        uint32_t triple = (static_cast<uint32_t>(data[i]) << 16) |
                          (static_cast<uint32_t>(data[i + 1]) << 8) |
                          static_cast<uint32_t>(data[i + 2]);
        output.push_back(alphabet[(triple >> 18) & 0x3F]);
        output.push_back(alphabet[(triple >> 12) & 0x3F]);
        output.push_back(alphabet[(triple >> 6) & 0x3F]);
        output.push_back(alphabet[triple & 0x3F]);
        i += 3;
    }

    if (i < length) {
        uint32_t triple = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < length) {
            triple |= static_cast<uint32_t>(data[i + 1]) << 8;
        }

        output.push_back(alphabet[(triple >> 18) & 0x3F]);
        output.push_back(alphabet[(triple >> 12) & 0x3F]);
        if (i + 1 < length) {
            output.push_back(alphabet[(triple >> 6) & 0x3F]);
        } else {
            output.push_back('=');
        }
        output.push_back('=');
    }

    return output;
}

double FileTimeToUnixMilliseconds(const LARGE_INTEGER &time) {
    const long long WINDOWS_EPOCH_OFFSET_MS = 11644473600000LL;
    const long long HUNDRED_NANOSECONDS_PER_MILLISECOND = 10000LL;

    long long fileTime = time.QuadPart;
    long long unixMs = (fileTime / HUNDRED_NANOSECONDS_PER_MILLISECOND) - WINDOWS_EPOCH_OFFSET_MS;
    return static_cast<double>(unixMs);
}

std::string AttributeTypeToString(DWORD type) {
    switch (type) {
        case 0x10: return "StandardInformation";
        case 0x20: return "AttributeList";
        case 0x30: return "FileName";
        case 0x40: return "ObjectId";
        case 0x50: return "SecurityDescriptor";
        case 0x60: return "VolumeName";
        case 0x70: return "VolumeInformation";
        case 0x80: return "Data";
        case 0x90: return "IndexRoot";
        case 0xA0: return "IndexAllocation";
        case 0xB0: return "Bitmap";
        case 0xC0: return "ReparsePoint";
        case 0xD0: return "EAInformation";
        case 0xE0: return "EA";
        case 0xF0: return "PropertySet";
        case 0x100: return "LoggedUtilityStream";
        default: return "Unknown";
    }
}

std::string ExtractAttributeName(const AttributeRecordHeader *header) {
    if (!header || header->NameLength == 0) {
        return std::string();
    }

    const WCHAR *namePtr = reinterpret_cast<const WCHAR *>(
        reinterpret_cast<const BYTE *>(header) + header->NameOffset
    );
    std::wstring wide(namePtr, header->NameLength);
    return WideToUtf8(wide);
}

long long ReadSignedValue(const BYTE *data, int size) {
    if (size <= 0 || size > 8) {
        return 0;
    }

    long long value = 0;
    for (int i = 0; i < size; ++i) {
        value |= static_cast<long long>(data[i]) << (8 * i);
    }

    if (size < 8 && (data[size - 1] & 0x80)) {
        value |= -1LL << (size * 8);
    }

    return value;
}

std::vector<DataRunSegment> ParseRunList(const AttributeRecordHeader *header) {
    std::vector<DataRunSegment> runs;
    if (!header || header->NonResident == 0) {
        return runs;
    }

    const BYTE *base = reinterpret_cast<const BYTE *>(header);
    const BYTE *runPtr = base + header->NonResidentData.RunOffset;
    const BYTE *end = base + header->Length;

    long long currentVCN = static_cast<long long>(header->NonResidentData.LowestVcn);
    long long currentLCN = 0;

    while (runPtr < end && *runPtr != 0) {
        BYTE headerByte = *runPtr++;
        int lengthFieldSize = headerByte & 0x0F;
        int offsetFieldSize = (headerByte >> 4) & 0x0F;

        if (lengthFieldSize <= 0 || offsetFieldSize < 0 || runPtr + lengthFieldSize + offsetFieldSize > end) {
            break;
        }

        long long runLength = 0;
        for (int i = 0; i < lengthFieldSize; ++i) {
            runLength |= static_cast<long long>(runPtr[i]) << (8 * i);
        }
        runPtr += lengthFieldSize;

        bool sparse = (offsetFieldSize == 0);
        long long runOffset = ReadSignedValue(runPtr, offsetFieldSize);
        runPtr += offsetFieldSize;

        currentLCN += runOffset;
        runs.push_back({ currentVCN, currentLCN, runLength, sparse });
        currentVCN += runLength;
    }

    return runs;
}

bool TryParseUnsigned(const std::string &input, ULONGLONG &output) {
    try {
        size_t idx = 0;
        output = std::stoull(input, &idx, 10);
        return idx == input.size();
    } catch (...) {
        return false;
    }
}

bool TryParseSigned(const std::string &input, long long &output) {
    try {
        size_t idx = 0;
        output = std::stoll(input, &idx, 10);
        return idx == input.size();
    } catch (...) {
        return false;
    }
}

struct FileRecordDetails {
    bool inUse;
    bool isDirectory;
    ULONGLONG baseReference;
    DWORD hardLinkCount;
    DWORD flags;
    std::vector<AttributeInfo> attributes;
    DWORD bytesPerSector;
    DWORD sectorsPerCluster;
    ULONGLONG clusterSize;
};

bool ParseFileRecord(const BYTE *buffer, DWORD length, FileRecordDetails &details) {
    if (!buffer || length < sizeof(FileRecordHeader)) {
        return false;
    }

    const FileRecordHeader *header = reinterpret_cast<const FileRecordHeader *>(buffer);
    if (header->Magic != 0x454C4946) { // 'FILE'
        return false;
    }

    details.inUse = (header->Flags & 0x0001) != 0;
    details.isDirectory = (header->Flags & 0x0002) != 0;
    details.baseReference = header->BaseFileRecord;
    details.hardLinkCount = header->HardLinkCount;
    details.flags = header->Flags;
    details.attributes.clear();
    details.bytesPerSector = 0;
    details.sectorsPerCluster = 0;
    details.clusterSize = 0;

    const BYTE *attrPtr = buffer + header->FirstAttributeOffset;
    const BYTE *end = buffer + length;

    while (attrPtr + sizeof(AttributeRecordHeader) <= end) {
        const AttributeRecordHeader *attr = reinterpret_cast<const AttributeRecordHeader *>(attrPtr);
        if (attr->Type == 0xFFFFFFFF || attr->Length == 0) {
            break;
        }
        if (attrPtr + attr->Length > end) {
            break;
        }

        AttributeInfo info{};
        info.type = attr->Type;
        info.typeName = AttributeTypeToString(attr->Type);
        info.nonResident = attr->NonResident != 0;
        info.name = ExtractAttributeName(attr);
        info.dataSize = 0;
        info.allocatedSize = 0;

        if (info.nonResident) {
            info.dataSize = attr->NonResidentData.DataSize;
            info.allocatedSize = attr->NonResidentData.AllocatedSize;
            info.runs = ParseRunList(attr);
        } else {
            info.dataSize = attr->Resident.ValueLength;
            info.allocatedSize = attr->Resident.ValueLength;
            DWORD valueOffset = attr->Resident.ValueOffset;
            DWORD valueLength = attr->Resident.ValueLength;
            if (valueOffset + valueLength <= attr->Length && valueLength > 0) {
                const BYTE *valuePtr = reinterpret_cast<const BYTE *>(attr) + valueOffset;
                info.residentData.assign(valuePtr, valuePtr + valueLength);
            }
        }

        details.attributes.push_back(std::move(info));
        attrPtr += attr->Length;
    }

    return true;
}

class ScanUsnWorker : public Napi::AsyncWorker {
  public:
    ScanUsnWorker(const std::string &driveLetter, const Napi::Function &callback)
        : Napi::AsyncWorker(callback), drive_(driveLetter) {}

    void Execute() override {
        if (drive_.empty()) {
            SetError("Drive letter is required");
            return;
        }

        wchar_t driveChar = static_cast<wchar_t>(::towupper(static_cast<unsigned char>(drive_[0])));
        std::wstring volumePath = L"\\.\\";
        volumePath.push_back(driveChar);
        volumePath.push_back(L':');

        DWORD sectorsPerCluster = 0;
        DWORD bytesPerSector = 0;
        DWORD numberOfFreeClusters = 0;
        DWORD totalNumberOfClusters = 0;

        std::wstring rootPath;
        rootPath.push_back(driveChar);
        rootPath.append(L":\\");

        ::GetDiskFreeSpaceW(
            rootPath.c_str(),
            &sectorsPerCluster,
            &bytesPerSector,
            &numberOfFreeClusters,
            &totalNumberOfClusters
        );

        HANDLE volumeHandle = ::CreateFileW(
            volumePath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            nullptr
        );

        if (volumeHandle == INVALID_HANDLE_VALUE) {
            DWORD err = ::GetLastError();
            errorMessage_ = "CreateFile failed with error " + std::to_string(err);
            SetError(errorMessage_);
            return;
        }

        const DWORD bufferSize = 1024 * 1024;
        std::vector<BYTE> buffer(bufferSize);
        MFT_ENUM_DATA_V0 med;
        std::memset(&med, 0, sizeof(med));
        med.StartFileReferenceNumber = 0;
        med.LowUsn = 0;
        med.HighUsn = MAXLONGLONG;

        std::unordered_map<ULONGLONG, FileEntry> fileTable;
        std::vector<DeletedRecord> deleted;

        while (true) {
            DWORD bytesReturned = 0;
            BOOL ok = ::DeviceIoControl(
                volumeHandle,
                FSCTL_ENUM_USN_DATA,
                &med,
                sizeof(med),
                buffer.data(),
                bufferSize,
                &bytesReturned,
                nullptr
            );

            if (!ok) {
                DWORD err = ::GetLastError();
                if (err == ERROR_HANDLE_EOF) {
                    break;
                }
                errorMessage_ = "FSCTL_ENUM_USN_DATA failed with error " + std::to_string(err);
                ::CloseHandle(volumeHandle);
                SetError(errorMessage_);
                return;
            }

            if (bytesReturned <= sizeof(ULONGLONG)) {
                continue;
            }

            ULONGLONG *nextUsn = reinterpret_cast<ULONGLONG *>(buffer.data());
            BYTE *recordPtr = buffer.data() + sizeof(ULONGLONG);
            DWORD recordBytes = bytesReturned - sizeof(ULONGLONG);

            while (recordBytes > 0) {
                if (recordBytes < sizeof(USN_RECORD_V2)) {
                    break;
                }

                auto record = reinterpret_cast<USN_RECORD_V2 *>(recordPtr);
                if (record->RecordLength == 0 || record->RecordLength > recordBytes) {
                    break;
                }

                ULONGLONG fileRef = record->FileReferenceNumber;
                ULONGLONG parentRef = record->ParentFileReferenceNumber;
                std::wstring wName(record->FileName, record->FileNameLength / sizeof(WCHAR));
                std::string name = WideToUtf8(wName);
                bool isDirectory = (record->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

                fileTable[fileRef] = { parentRef, name, isDirectory };

                if (record->Reason & USN_REASON_FILE_DELETE) {
                    DeletedRecord item{};
                    item.fileRef = fileRef;
                    item.parentRef = parentRef;
                    item.name = name;
                    item.isDirectory = isDirectory;
                    item.timestampMs = FileTimeToUnixMilliseconds(record->TimeStamp);
                    item.reason = record->Reason;
                    deleted.push_back(item);
                }

                recordBytes -= record->RecordLength;
                recordPtr += record->RecordLength;
            }

            med.StartFileReferenceNumber = *nextUsn;
        }

        ::CloseHandle(volumeHandle);

        results_.reserve(deleted.size());
        const char upperDriveChar = drive_.empty() ? '?' : static_cast<char>(::toupper(static_cast<unsigned char>(drive_[0])));

        for (const auto &item : deleted) {
            std::string fullPath;
            fullPath.push_back(upperDriveChar);
            fullPath.append(":\\");

            std::vector<std::string> segments;
            segments.push_back(item.name);

            ULONGLONG current = item.parentRef;
            int guard = 0;
            const int maxDepth = 1024;
            while (current != 0 && guard < maxDepth) {
                auto it = fileTable.find(current);
                if (it == fileTable.end()) {
                    break;
                }
                if (!it->second.name.empty()) {
                    segments.push_back(it->second.name);
                }
                if (current == it->second.parentRef) {
                    break;
                }
                current = it->second.parentRef;
                guard++;
            }

            for (auto it = segments.rbegin(); it != segments.rend(); ++it) {
                if (!fullPath.empty() && fullPath.back() != '\\') {
                    fullPath.push_back('\\');
                }
                fullPath += *it;
            }

            Result result;
            result.fileRef = item.fileRef;
            result.parentRef = item.parentRef;
            result.name = item.name;
            result.fullPath = fullPath;
            result.isDirectory = item.isDirectory;
            result.timestampMs = item.timestampMs;
            result.reason = item.reason;
            results_.push_back(result);
        }
    }

    void OnOK() override {
        Napi::Env env = Env();
        Napi::HandleScope scope(env);

        Napi::Array arr = Napi::Array::New(env, results_.size());
        for (size_t i = 0; i < results_.size(); ++i) {
            const auto &res = results_[i];
            Napi::Object obj = Napi::Object::New(env);
            obj.Set("name", Napi::String::New(env, res.name));
            obj.Set("path", Napi::String::New(env, res.fullPath));
            obj.Set("fileReferenceNumber", Napi::String::New(env, std::to_string(res.fileRef)));
            obj.Set("parentReferenceNumber", Napi::String::New(env, std::to_string(res.parentRef)));
            obj.Set("isDirectory", Napi::Boolean::New(env, res.isDirectory));
            obj.Set("timestampMs", Napi::Number::New(env, res.timestampMs));
            obj.Set("reason", Napi::Number::New(env, static_cast<double>(res.reason)));
            obj.Set("drive", Napi::String::New(env, drive_));
            arr.Set(i, obj);
        }

        Callback().Call({ env.Null(), arr });
    }

    void OnError(const Napi::Error &e) override {
        Napi::Env env = Env();
        Napi::HandleScope scope(env);
        Callback().Call({ e.Value(), env.Undefined() });
    }

  private:
    struct Result {
        ULONGLONG fileRef;
        ULONGLONG parentRef;
        std::string name;
        std::string fullPath;
        bool isDirectory;
        double timestampMs;
        DWORD reason;
    };

    std::string drive_;
    std::string errorMessage_;
    std::vector<Result> results_;
};

class FileRecordWorker : public Napi::AsyncWorker {
  public:
    FileRecordWorker(const std::string &driveLetter, ULONGLONG fileReference, const Napi::Function &callback)
        : Napi::AsyncWorker(callback), drive_(driveLetter), fileRef_(fileReference) {}

    void Execute() override {
        if (drive_.empty()) {
            SetError("Drive letter is required");
            return;
        }

        wchar_t driveChar = static_cast<wchar_t>(::towupper(static_cast<unsigned char>(drive_[0])));
        std::wstring volumePath = L"\\\\.\\";
        volumePath.push_back(driveChar);
        volumePath.push_back(L':');

        DWORD sectorsPerCluster = 0;
        DWORD bytesPerSector = 0;
        DWORD numberOfFreeClusters = 0;
        DWORD totalNumberOfClusters = 0;

        std::wstring rootPath;
        rootPath.push_back(driveChar);
        rootPath.append(L":\\");
        ::GetDiskFreeSpaceW(
            rootPath.c_str(),
            &sectorsPerCluster,
            &bytesPerSector,
            &numberOfFreeClusters,
            &totalNumberOfClusters
        );

        HANDLE volumeHandle = ::CreateFileW(
            volumePath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            nullptr
        );

        if (volumeHandle == INVALID_HANDLE_VALUE) {
            DWORD err = ::GetLastError();
            errorMessage_ = "CreateFile failed with error " + std::to_string(err);
            SetError(errorMessage_);
            return;
        }

        const DWORD bufferSize = 1024 * 1024; // 1 MB buffer for file record and attributes
        std::vector<BYTE> buffer(bufferSize);

        NtfsFileRecordInputBuffer input{};
        input.FileReferenceNumber = fileRef_;

        DWORD bytesReturned = 0;
        BOOL ok = ::DeviceIoControl(
            volumeHandle,
            FSCTL_GET_NTFS_FILE_RECORD,
            &input,
            sizeof(input),
            buffer.data(),
            bufferSize,
            &bytesReturned,
            nullptr
        );

        if (!ok) {
            DWORD err = ::GetLastError();
            ::CloseHandle(volumeHandle);
            errorMessage_ = "FSCTL_GET_NTFS_FILE_RECORD failed with error " + std::to_string(err);
            SetError(errorMessage_);
            return;
        }

        ::CloseHandle(volumeHandle);

        if (bytesReturned < sizeof(NtfsFileRecordOutputBuffer)) {
            SetError("File record response too small");
            return;
        }

        auto *output = reinterpret_cast<NtfsFileRecordOutputBuffer *>(buffer.data());
        FileRecordDetails details{};
        if (!ParseFileRecord(output->FileRecordBuffer, output->FileRecordLength, details)) {
            SetError("Failed to parse file record");
            return;
        }

        details.bytesPerSector = bytesPerSector;
        details.sectorsPerCluster = sectorsPerCluster;
        details.clusterSize = static_cast<ULONGLONG>(bytesPerSector) * sectorsPerCluster;
        details_ = std::move(details);
    }

    void OnOK() override {
        Napi::Env env = Env();
        Napi::HandleScope scope(env);

        Napi::Object result = Napi::Object::New(env);
        result.Set("inUse", Napi::Boolean::New(env, details_.inUse));
        result.Set("isDirectory", Napi::Boolean::New(env, details_.isDirectory));
        result.Set("baseReference", Napi::String::New(env, std::to_string(details_.baseReference)));
        result.Set("hardLinkCount", Napi::Number::New(env, details_.hardLinkCount));
        result.Set("flags", Napi::Number::New(env, details_.flags));
        result.Set("bytesPerSector", Napi::Number::New(env, details_.bytesPerSector));
        result.Set("sectorsPerCluster", Napi::Number::New(env, details_.sectorsPerCluster));
        result.Set("clusterSize", Napi::String::New(env, std::to_string(details_.clusterSize)));

        Napi::Array attrArray = Napi::Array::New(env, details_.attributes.size());
        for (size_t i = 0; i < details_.attributes.size(); ++i) {
            const auto &attr = details_.attributes[i];
            Napi::Object attrObj = Napi::Object::New(env);
            attrObj.Set("type", Napi::Number::New(env, attr.type));
            attrObj.Set("typeName", Napi::String::New(env, attr.typeName));
            attrObj.Set("nonResident", Napi::Boolean::New(env, attr.nonResident));
            if (!attr.name.empty()) {
                attrObj.Set("name", Napi::String::New(env, attr.name));
            }
            attrObj.Set("dataSize", Napi::String::New(env, std::to_string(attr.dataSize)));
            attrObj.Set("allocatedSize", Napi::String::New(env, std::to_string(attr.allocatedSize)));

            if (!attr.runs.empty()) {
                Napi::Array runs = Napi::Array::New(env, attr.runs.size());
                for (size_t r = 0; r < attr.runs.size(); ++r) {
                    const auto &run = attr.runs[r];
                    Napi::Object runObj = Napi::Object::New(env);
                    runObj.Set("vcn", Napi::String::New(env, std::to_string(run.vcnStart)));
                    runObj.Set("lcn", Napi::String::New(env, std::to_string(run.lcn)));
                    runObj.Set("length", Napi::String::New(env, std::to_string(run.length)));
                    runObj.Set("sparse", Napi::Boolean::New(env, run.sparse));
                    runs.Set(r, runObj);
                }
                attrObj.Set("runs", runs);
            } else if (!attr.residentData.empty()) {
                attrObj.Set(
                    "residentDataBase64",
                    Napi::String::New(env, Base64Encode(attr.residentData.data(), attr.residentData.size()))
                );
            }

            attrArray.Set(i, attrObj);
        }

        result.Set("attributes", attrArray);
        Callback().Call({ env.Null(), result });
    }

    void OnError(const Napi::Error &e) override {
        Napi::Env env = Env();
        Napi::HandleScope scope(env);
        Callback().Call({ e.Value(), env.Undefined() });
    }

  private:
    std::string drive_;
    ULONGLONG fileRef_;
    std::string errorMessage_;
    FileRecordDetails details_;
};

class DataRunRecoveryWorker : public Napi::AsyncWorker {
  public:
    DataRunRecoveryWorker(
        const std::string &driveLetter,
        std::vector<DataRunSegment> runs,
        ULONGLONG clusterSize,
        ULONGLONG fileSize,
        const std::wstring &outputPath,
        const Napi::Function &callback)
        : Napi::AsyncWorker(callback),
          drive_(driveLetter),
          runs_(std::move(runs)),
          clusterSize_(clusterSize),
          fileSize_(fileSize),
          outputPath_(outputPath),
          badSectorCount_(0),
          recoveredBytes_(0),
          totalBytes_(fileSize) {}

    void Execute() override {
        if (drive_.empty()) {
            SetError("Drive letter is required");
            return;
        }

        if (clusterSize_ == 0) {
            SetError("Cluster size is required");
            return;
        }

        if (fileSize_ == 0) {
            SetError("Target file size is zero");
            return;
        }

        if (outputPath_.empty()) {
            SetError("Output path is required");
            return;
        }

        wchar_t driveChar = static_cast<wchar_t>(::towupper(static_cast<unsigned char>(drive_[0])));
        std::wstring volumePath = L"\\\\.\\";
        volumePath.push_back(driveChar);
        volumePath.push_back(L':');

        HANDLE volumeHandle = ::CreateFileW(
            volumePath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if (volumeHandle == INVALID_HANDLE_VALUE) {
            DWORD err = ::GetLastError();
            SetError("CreateFile (volume) failed with error " + std::to_string(err));
            return;
        }

        HANDLE outHandle = ::CreateFileW(
            outputPath_.c_str(),
            GENERIC_WRITE,
            0,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if (outHandle == INVALID_HANDLE_VALUE) {
            DWORD err = ::GetLastError();
            ::CloseHandle(volumeHandle);
            SetError("CreateFile (output) failed with error " + std::to_string(err));
            return;
        }

        const size_t chunkClusters = 16;
        std::vector<BYTE> buffer(static_cast<size_t>(clusterSize_ * chunkClusters));
        std::vector<BYTE> zeroBuffer(buffer.size(), 0);

        ULONGLONG remaining = fileSize_;
        for (const auto &run : runs_) {
            if (remaining == 0) {
                break;
            }

            if (run.length <= 0) {
                continue;
            }

            ULONGLONG runBytesTotal = static_cast<ULONGLONG>(run.length) * clusterSize_;
            ULONGLONG bytesToCopy = std::min(runBytesTotal, remaining);

            if (run.sparse || run.lcn <= 0) {
                ULONGLONG produced = 0;
                while (produced < bytesToCopy) {
                    ULONGLONG chunk = std::min<ULONGLONG>(bytesToCopy - produced, zeroBuffer.size());
                    DWORD written = 0;
                    if (!::WriteFile(outHandle, zeroBuffer.data(), static_cast<DWORD>(chunk), &written, nullptr)) {
                        DWORD err = ::GetLastError();
                        ::CloseHandle(outHandle);
                        ::CloseHandle(volumeHandle);
                        SetError("WriteFile (sparse) failed with error " + std::to_string(err));
                        return;
                    }
                    produced += written;
                }
            } else {
                LONGLONG absoluteOffset = static_cast<LONGLONG>(run.lcn) * static_cast<LONGLONG>(clusterSize_);
                LARGE_INTEGER distance;
                distance.QuadPart = absoluteOffset;
                if (!::SetFilePointerEx(volumeHandle, distance, nullptr, FILE_BEGIN)) {
                    DWORD err = ::GetLastError();
                    ::CloseHandle(outHandle);
                    ::CloseHandle(volumeHandle);
                    SetError("SetFilePointerEx failed with error " + std::to_string(err));
                    return;
                }

                ULONGLONG processed = 0;
                while (processed < bytesToCopy) {
                    ULONGLONG chunk = std::min<ULONGLONG>(bytesToCopy - processed, buffer.size());
                    DWORD read = 0;
                    if (!::ReadFile(volumeHandle, buffer.data(), static_cast<DWORD>(chunk), &read, nullptr)) {
                        DWORD err = ::GetLastError();
                        ::CloseHandle(outHandle);
                        ::CloseHandle(volumeHandle);
                        SetError("ReadFile failed with error " + std::to_string(err));
                        return;
                    }

                    if (read == 0) {
                        ::CloseHandle(outHandle);
                        ::CloseHandle(volumeHandle);
                        SetError("Unexpected end of volume data while reading run");
                        return;
                    }

                    DWORD written = 0;
                    if (!::WriteFile(outHandle, buffer.data(), read, &written, nullptr) || written != read) {
                        DWORD err = ::GetLastError();
                        ::CloseHandle(outHandle);
                        ::CloseHandle(volumeHandle);
                        SetError("WriteFile failed with error " + std::to_string(err));
                        return;
                    }

                    processed += read;
                }
            }

            remaining -= bytesToCopy;
        }

        if (remaining > 0) {
            while (remaining > 0) {
                ULONGLONG chunk = std::min<ULONGLONG>(remaining, zeroBuffer.size());
                DWORD written = 0;
                if (!::WriteFile(outHandle, zeroBuffer.data(), static_cast<DWORD>(chunk), &written, nullptr)) {
                    DWORD err = ::GetLastError();
                    ::CloseHandle(outHandle);
                    ::CloseHandle(volumeHandle);
                    SetError("WriteFile (padding) failed with error " + std::to_string(err));
                    return;
                }
                remaining -= written;
            }
        }

        ::CloseHandle(outHandle);
        ::CloseHandle(volumeHandle);
    }

    void OnOK() override {
        Napi::Env env = Env();
        Napi::HandleScope scope(env);
        Callback().Call({ env.Null(), env.Null() });
    }

    void OnError(const Napi::Error &e) override {
        Napi::Env env = Env();
        Napi::HandleScope scope(env);
        Callback().Call({ e.Value(), env.Undefined() });
    }

  private:
    std::string drive_;
    std::vector<DataRunSegment> runs_;
    ULONGLONG clusterSize_;
    ULONGLONG fileSize_;
    std::wstring outputPath_;
};
Napi::Value ScanUsn(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();

    if (info.Length() < 2) {
        Napi::TypeError::New(env, "Expected drive letter and callback").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    if (!info[0].IsString()) {
        Napi::TypeError::New(env, "Drive letter must be a string").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    if (!info[1].IsFunction()) {
        Napi::TypeError::New(env, "Callback must be a function").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    std::string drive = info[0].As<Napi::String>();
    Napi::Function callback = info[1].As<Napi::Function>();

    auto *worker = new ScanUsnWorker(drive, callback);
    worker->Queue();
    return env.Undefined();
}

bool ParseRunsArray(const Napi::Env &env, const Napi::Array &array, std::vector<DataRunSegment> &out, std::string &error) {
    out.clear();
    const uint32_t length = array.Length();
    out.reserve(length);

    for (uint32_t i = 0; i < length; ++i) {
        Napi::Value value = array.Get(i);
        if (!value.IsObject()) {
            error = "Run entry must be an object";
            return false;
        }

        Napi::Object obj = value.As<Napi::Object>();

        long long lengthClusters = 0;
        long long lcnValue = 0;
        bool sparse = false;

        Napi::Value lengthValue = obj.Get("length");
        if (lengthValue.IsString()) {
            if (!TryParseSigned(lengthValue.As<Napi::String>(), lengthClusters)) {
                error = "Invalid run length";
                return false;
            }
        } else if (lengthValue.IsNumber()) {
            lengthClusters = static_cast<long long>(lengthValue.As<Napi::Number>().DoubleValue());
        } else {
            error = "Run length missing";
            return false;
        }

        Napi::Value lcnField = obj.Get("lcn");
        if (lcnField.IsString()) {
            if (!TryParseSigned(lcnField.As<Napi::String>(), lcnValue)) {
                error = "Invalid run LCN";
                return false;
            }
        } else if (lcnField.IsNumber()) {
            lcnValue = static_cast<long long>(lcnField.As<Napi::Number>().DoubleValue());
        } else {
            error = "Run LCN missing";
            return false;
        }

        Napi::Value sparseValue = obj.Get("sparse");
        if (sparseValue.IsBoolean()) {
            sparse = sparseValue.As<Napi::Boolean>();
        }

        long long vcnValue = 0;
        Napi::Value vcnField = obj.Get("vcn");
        if (vcnField.IsString()) {
            TryParseSigned(vcnField.As<Napi::String>(), vcnValue);
        } else if (vcnField.IsNumber()) {
            vcnValue = static_cast<long long>(vcnField.As<Napi::Number>().DoubleValue());
        }

        DataRunSegment segment{};
        segment.vcnStart = vcnValue;
        segment.lcn = lcnValue;
        segment.length = lengthClusters;
        segment.sparse = sparse;
        out.push_back(segment);
    }

    return true;
}

Napi::Value GetFileRecord(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();

    if (info.Length() < 3) {
        Napi::TypeError::New(env, "Expected drive letter, file reference, and callback").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    if (!info[0].IsString()) {
        Napi::TypeError::New(env, "Drive letter must be a string").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    ULONGLONG fileReference = 0;
    if (info[1].IsString()) {
        std::string refStr = info[1].As<Napi::String>();
        try {
            fileReference = std::stoull(refStr);
        } catch (...) {
            Napi::TypeError::New(env, "Invalid file reference string").ThrowAsJavaScriptException();
            return env.Undefined();
        }
    } else if (info[1].IsNumber()) {
        double value = info[1].As<Napi::Number>().DoubleValue();
        if (value < 0) {
            Napi::TypeError::New(env, "File reference must be positive").ThrowAsJavaScriptException();
            return env.Undefined();
        }
        fileReference = static_cast<ULONGLONG>(value);
    } else {
        Napi::TypeError::New(env, "File reference must be a string or number").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    if (!info[2].IsFunction()) {
        Napi::TypeError::New(env, "Callback must be a function").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    std::string drive = info[0].As<Napi::String>();
    Napi::Function callback = info[2].As<Napi::Function>();

    auto *worker = new FileRecordWorker(drive, fileReference, callback);
    worker->Queue();
    return env.Undefined();
}

Napi::Value RecoverDataRuns(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();

    if (info.Length() < 6) {
        Napi::TypeError::New(env, "Expected drive, runs, cluster size, file size, output path, and callback").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    if (!info[0].IsString()) {
        Napi::TypeError::New(env, "Drive letter must be a string").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    if (!info[1].IsArray()) {
        Napi::TypeError::New(env, "Runs must be an array").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    ULONGLONG clusterSize = 0;
    if (info[2].IsString()) {
        if (!TryParseUnsigned(info[2].As<Napi::String>(), clusterSize)) {
            Napi::TypeError::New(env, "Invalid cluster size").ThrowAsJavaScriptException();
            return env.Undefined();
        }
    } else if (info[2].IsNumber()) {
        double value = info[2].As<Napi::Number>().DoubleValue();
        if (value <= 0) {
            Napi::TypeError::New(env, "Cluster size must be positive").ThrowAsJavaScriptException();
            return env.Undefined();
        }
        clusterSize = static_cast<ULONGLONG>(value);
    } else {
        Napi::TypeError::New(env, "Cluster size must be numeric").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    ULONGLONG fileSize = 0;
    if (info[3].IsString()) {
        if (!TryParseUnsigned(info[3].As<Napi::String>(), fileSize)) {
            Napi::TypeError::New(env, "Invalid file size").ThrowAsJavaScriptException();
            return env.Undefined();
        }
    } else if (info[3].IsNumber()) {
        double value = info[3].As<Napi::Number>().DoubleValue();
        if (value < 0) {
            Napi::TypeError::New(env, "File size must be positive").ThrowAsJavaScriptException();
            return env.Undefined();
        }
        fileSize = static_cast<ULONGLONG>(value);
    } else {
        Napi::TypeError::New(env, "File size must be numeric").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    if (!info[4].IsString()) {
        Napi::TypeError::New(env, "Output path must be a string").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    if (!info[5].IsFunction()) {
        Napi::TypeError::New(env, "Callback must be a function").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    std::vector<DataRunSegment> runs;
    std::string parseError;
    if (!ParseRunsArray(env, info[1].As<Napi::Array>(), runs, parseError)) {
        Napi::TypeError::New(env, parseError).ThrowAsJavaScriptException();
        return env.Undefined();
    }

    std::string drive = info[0].As<Napi::String>();
    std::wstring outputPath = Utf8ToWide(info[4].As<Napi::String>());
    Napi::Function callback = info[5].As<Napi::Function>();

    auto *worker = new DataRunRecoveryWorker(drive, std::move(runs), clusterSize, fileSize, outputPath, callback);
    worker->Queue();
    return env.Undefined();
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("scan", Napi::Function::New(env, ScanUsn));
    exports.Set("getFileRecord", Napi::Function::New(env, GetFileRecord));
    exports.Set("recoverDataRuns", Napi::Function::New(env, RecoverDataRuns));
    return exports;
}

} // namespace

NODE_API_MODULE(usnscanner, Init)
