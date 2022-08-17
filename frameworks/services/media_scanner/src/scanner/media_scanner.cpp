/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define MLOG_TAG "Scanner"

#include "media_scanner.h"

#include "hitrace_meter.h"

#include "media_log.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace OHOS::AppExecFwk;
using namespace OHOS::DataShare;

vector<string> MediaScannerObj::GetSupportedMimeTypes()
{
    vector<string> mimeTypeList;
    mimeTypeList.push_back(DEFAULT_AUDIO_MIME_TYPE);
    mimeTypeList.push_back(DEFAULT_VIDEO_MIME_TYPE);
    mimeTypeList.push_back(DEFAULT_IMAGE_MIME_TYPE);
    mimeTypeList.push_back(DEFAULT_FILE_MIME_TYPE);

    return mimeTypeList;
}

int32_t MediaScannerObj::ScanFile()
{
    MEDIA_INFO_LOG("begin");

    int32_t err = ScanFileInternal(path_);
    if (err != 0) {
        MEDIA_ERR_LOG("ScanFileInternal err %{public}d", err);
    }

    return InvokeCallback(err);
}

int32_t MediaScannerObj::ScanDir()
{
    MEDIA_INFO_LOG("begin");

    int32_t err = ScanDirInternal(path_);
    if (err != 0) {
        MEDIA_ERR_LOG("ScanDirInternal err %{public}d", err);
    }

    return InvokeCallback(err);
}

int32_t MediaScannerObj::InvokeCallback(int32_t err)
{
    sptr<IMediaScannerOperationCallback> callback = iface_cast<IMediaScannerOperationCallback>(callback_);
    return callback->OnScanFinishedCallback(err, uri_, path_);
}

void MediaScannerObj::CleanupDirectory(const string &path)
{
    vector<int32_t> toBeDeletedIds = {};
    unordered_set<MediaType> mediaTypeSet = {};
    unordered_map<int32_t, MediaType> prevIdMap = {};

    prevIdMap = mediaScannerDb_->GetIdsFromFilePath(path);
    for (auto itr : prevIdMap) {
        auto it = scannedIds_.find(itr.first);
        if (it != scannedIds_.end()) {
            scannedIds_.erase(it);
        } else {
            toBeDeletedIds.push_back(itr.first);
            mediaTypeSet.insert(itr.second);
        }
    }

    // convert deleted id list to vector of strings
    vector<string> deleteIdList;    
    for (auto id : toBeDeletedIds) {
        deleteIdList.push_back(to_string(id));
    }

    if (!deleteIdList.empty()) {
        mediaScannerDb_->DeleteMetadata(deleteIdList);
    }

    // Send notify to the modified URIs
    for (const MediaType &mediaType : mediaTypeSet) {
        mediaScannerDb_->NotifyDatabaseChange(mediaType);
    }

    scannedIds_.clear();
}

int32_t MediaScannerObj::StartBatchProcessingToDB()
{
    unordered_set<MediaType> mediaTypeSet = {};
    string uri = "";
    Metadata metaData;

    for (uint32_t i = 0; i < batchUpdate_.size(); i++) {
        metaData = (Metadata)batchUpdate_[i];
        mediaTypeSet.insert(metaData.GetFileMediaType());

        if (metaData.GetFileId() != FILE_ID_DEFAULT) {
            uri = mediaScannerDb_->UpdateMetadata(metaData);
            scannedIds_.insert(metaData.GetFileId());
        } else {
            uri = mediaScannerDb_->InsertMetadata(metaData);
            scannedIds_.insert(mediaScannerDb_->GetIdFromUri(uri));
        }
        this->uri_ = uri;
    }
    batchUpdate_.clear();

    // Send notify to the modified URIs
    for (const MediaType &mediaType : mediaTypeSet) {
        mediaScannerDb_->NotifyDatabaseChange(mediaType);
    }

    return ERR_SUCCESS;
}

int32_t MediaScannerObj::StartBatchProcessIfFull()
{
    if (batchUpdate_.size() >= MAX_BATCH_SIZE) {
        return StartBatchProcessingToDB();
    }
    return ERR_SUCCESS;
}

int32_t MediaScannerObj::BatchUpdateRequest(Metadata &fileMetadata)
{
    batchUpdate_.push_back(fileMetadata);
    return StartBatchProcessIfFull();
}

// Check if the file entry already exists in the DB. Compare filename, size,
// path, and modified date.
bool MediaScannerObj::IsFileScanned(Metadata &fileMetadata)
{
    string filePath = fileMetadata.GetFilePath();
    unique_ptr<Metadata> md = mediaScannerDb_->GetFileModifiedInfo(filePath);
    if (md != nullptr &&
        md->GetFileDateModified() == fileMetadata.GetFileDateModified() &&
        md->GetFileName() == fileMetadata.GetFileName() &&
        md->GetFileSize() == fileMetadata.GetFileSize()) {
        scannedIds_.insert(md->GetFileId());
        return true;
    }

    if (md != nullptr) {
        int32_t fileId = md->GetFileId();
        fileMetadata.SetFileId(fileId);
        fileMetadata.SetOrientation(md->GetOrientation());
    }

    MEDIA_INFO_LOG("the file hasn't been scanned yet");
    return false;
}

int32_t MediaScannerObj::RetrieveMetadata(Metadata &fileMetadata)
{
    // Stub impl. This will be implemented by the extractor
    return metadataExtract_.Extract(fileMetadata, fileMetadata.GetFilePath());
}

// Visit the File
int32_t MediaScannerObj::VisitFile(const Metadata &fileMD)
{
    StartTrace(HITRACE_TAG_FILEMANAGEMENT, "VisitFile");

    auto fileMetadata = const_cast<Metadata *>(&fileMD);
    string mimeType = DEFAULT_FILE_MIME_TYPE;
    vector<string> supportedMimeTypes;
    int32_t errCode = ERR_MIMETYPE_NOTSUPPORT;

    mimeType = ScannerUtils::GetMimeTypeFromExtension(fileMetadata->GetFileExtension());
    supportedMimeTypes = GetSupportedMimeTypes();
    if (find(supportedMimeTypes.begin(), supportedMimeTypes.end(), mimeType) != supportedMimeTypes.end()) {
        errCode = ERR_SUCCESS;
        if (!IsFileScanned(*fileMetadata)) {
            errCode = RetrieveMetadata(*fileMetadata);
            if (errCode == ERR_SUCCESS) {
                errCode = BatchUpdateRequest(*fileMetadata);
            }
        }
    }

    FinishTrace(HITRACE_TAG_FILEMANAGEMENT);
    return errCode;
}

// Get Basic File Metadata from the file
unique_ptr<Metadata> MediaScannerObj::GetFileMetadata(const string &path, const int32_t parentId)
{
    StartTrace(HITRACE_TAG_FILEMANAGEMENT, "GetFileMetaData");

    unique_ptr<Metadata> fileMetadata = make_unique<Metadata>();
    if (fileMetadata == nullptr) {
        MEDIA_ERR_LOG("File metadata is null");
        FinishTrace(HITRACE_TAG_FILEMANAGEMENT);
        return nullptr;
    }

    struct stat statInfo = { 0 };
    if (stat(path.c_str(), &statInfo) == ERR_SUCCESS) {
        fileMetadata->SetFileSize(static_cast<int64_t>(statInfo.st_size));
        fileMetadata->SetFileDateModified(static_cast<int64_t>(statInfo.st_mtime));
    }

    fileMetadata->SetFilePath(path);
    fileMetadata->SetFileName(ScannerUtils::GetFileNameFromUri(path));

    string fileExtn = ScannerUtils::GetFileExtensionFromFileUri(path);
    fileMetadata->SetFileExtension(fileExtn);

    string mimetype = ScannerUtils::GetMimeTypeFromExtension(fileExtn);
    fileMetadata->SetFileMimeType(mimetype);

    fileMetadata->SetFileMediaType(ScannerUtils::GetMediatypeFromMimetype(mimetype));

    if (parentId != NO_PARENT) {
        fileMetadata->SetParentId(parentId);
    }

    string::size_type len = 0;
    string rootDir;

    ScannerUtils::GetRootMediaDir(rootDir);
    if (rootDir.empty()) {
        MEDIA_ERR_LOG("Root dir path is empty!");
        FinishTrace(HITRACE_TAG_FILEMANAGEMENT);
        return fileMetadata;
    }

    len = rootDir.length();
    string parentPath = ScannerUtils::GetParentPath(path) + SLASH_CHAR; // GetParentPath without slash at end
    if (parentPath.substr(0, len).compare(rootDir) == 0) {
        parentPath.erase(0, len);
        if (!parentPath.empty()) {
            fileMetadata->SetRelativePath(parentPath);
            parentPath = string("/") + parentPath.substr(0, parentPath.length() - 1);
            fileMetadata->SetAlbumName(ScannerUtils::GetFileNameFromUri(parentPath));
        }
    } else {
        MEDIA_ERR_LOG("path: %{private}s is not correct, right is begin with %{private}s",
                      path.c_str(), rootDir.c_str());
    }

    FinishTrace(HITRACE_TAG_FILEMANAGEMENT);
    return fileMetadata;
}


// Get the internal details of the file
int32_t MediaScannerObj::ScanFileContent(const string &path, const int32_t parentId)
{
    unique_ptr<Metadata> fileMetadata = nullptr;
    int32_t errCode = ERR_FAIL;

    fileMetadata = GetFileMetadata(path, parentId);
    if (fileMetadata != nullptr) {
        errCode = VisitFile(*fileMetadata);
    } else {
        MEDIA_ERR_LOG("Failed to allocate memory for file metadata");
        return ERR_MEM_ALLOC_FAIL;
    }

    return errCode;
}

// Scan the file path
int32_t MediaScannerObj::ScanFileInternal(const string &path)
{
    int32_t errCode = ERR_FAIL;

    string parentFolder = ScannerUtils::GetParentPath(path);
    if (ScannerUtils::IsFileHidden(path) || (!parentFolder.empty() && IsDirHiddenRecursive(parentFolder))) {
        MEDIA_ERR_LOG("File Parent path not accessible");
        return ERR_NOT_ACCESSIBLE;
    }

    int32_t parentId = mediaScannerDb_->ReadAlbumId(parentFolder);

    errCode = ScanFileContent(path, parentId);
    if (errCode == ERR_SUCCESS) {
        // to write the remaining to DB
        errCode = StartBatchProcessingToDB();
    }

    return errCode;
}

int32_t MediaScannerObj::InsertAlbumInfo(string &albumPath, int32_t parentId, string albumName)
{
    int32_t albumId = ERR_FAIL;

    bool update = false;

    if (albumMap_.find(albumPath) != albumMap_.end()) {
        // It Exists
        Metadata albumInfo = albumMap_.at(albumPath);
        struct stat statInfo {};
        albumId = albumInfo.GetFileId();

        if (stat(albumPath.c_str(), &statInfo) == ERR_SUCCESS) {
            if (albumInfo.GetFileDateModified() == statInfo.st_mtime) {
                scannedIds_.insert(albumId);
                return albumId;
            } else {
                update = true;
            }
        }
    }

    unique_ptr<Metadata> fileMetadata = GetFileMetadata(albumPath, parentId);
    if (fileMetadata != nullptr) {
        fileMetadata->SetFileMediaType(static_cast<MediaType>(MEDIA_TYPE_ALBUM));
        fileMetadata->SetAlbumName(albumName);

        if (update) {
            fileMetadata->SetFileId(albumId);
            albumId = mediaScannerDb_->UpdateAlbum(*fileMetadata);
        } else {
            albumId = mediaScannerDb_->InsertAlbum(*fileMetadata);
        }
        scannedIds_.insert(albumId);
    }

    return albumId;
}

int32_t MediaScannerObj::WalkFileTree(const string &path, int32_t parentId)
{
    int32_t errCode = ERR_SUCCESS;
    DIR *dirPath = nullptr;
    struct dirent *ent = nullptr;
    size_t len = path.length();
    struct stat statInfo;

    if (len >= FILENAME_MAX - 1) {
        return ERR_INCORRECT_PATH;
    }

    auto fName = (char *)calloc(FILENAME_MAX, sizeof(char));
    if (fName == nullptr) {
        return ERR_MEM_ALLOC_FAIL;
    }

    if (strcpy_s(fName, FILENAME_MAX, path.c_str()) != ERR_SUCCESS) {
        FREE_MEMORY_AND_SET_NULL(fName);
        return ERR_MEM_ALLOC_FAIL;
    }
    fName[len++] = '/';

    if ((dirPath = opendir(path.c_str())) == nullptr) {
        MEDIA_ERR_LOG("Failed to opendir %{private}s, errno %{private}d", path.c_str(), errno);
        FREE_MEMORY_AND_SET_NULL(fName);
        return ERR_NOT_ACCESSIBLE;
    }

    while ((ent = readdir(dirPath)) != nullptr && errCode != ERR_MEM_ALLOC_FAIL) {
        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) {
            continue;
        }

        if (strncpy_s(fName + len, FILENAME_MAX - len, ent->d_name, FILENAME_MAX - len)) {
            continue;
        }

        if (lstat(fName, &statInfo) == -1) {
            continue;
        }

        string currentPath = fName;
        if (S_ISDIR(statInfo.st_mode)) {
            if (IsDirHidden(currentPath)) {
                continue;
            }

            int32_t albumId = InsertAlbumInfo(currentPath, parentId, ent->d_name);
            if (albumId == ERR_FAIL) {
                errCode = ERR_FAIL;
                break;
            }

            errCode = WalkFileTree(currentPath, albumId);
        } else if (!ScannerUtils::IsFileHidden(currentPath)) {
            errCode = ScanFileContent(currentPath, parentId);
        }
    }

    closedir(dirPath);
    FREE_MEMORY_AND_SET_NULL(fName);

    return errCode;
}

// Initialize the skip list
void MediaScannerObj::InitSkipList()
{
    hash<string> hashStr;
    size_t hashPath;
    string path;

    ifstream skipFile(SKIPLIST_FILE_PATH.c_str());
    if (skipFile.is_open()) {
        while (getline(skipFile, path)) {
            hashPath = hashStr(path);
            skipList_.insert(skipList_.begin(), hashPath);
        }
        skipFile.close();
    }

    return;
}

// Check if path is part of Skip scan list
bool MediaScannerObj::CheckSkipScanList(const string &path)
{
    hash<string> hashStr;
    size_t hashPath;

    if (skipList_.empty()) {
        InitSkipList();
    }

    hashPath = hashStr(path);
    if (find(skipList_.begin(), skipList_.end(), hashPath) != skipList_.end()) {
        return true;
    }

    return false;
}

// Check if the directory is hidden
bool MediaScannerObj::IsDirHidden(const string &path)
{
    bool dirHid = false;

    if (!path.empty()) {
        string dirName = ScannerUtils::GetFileNameFromUri(path);
        if (!dirName.empty() && dirName.at(0) == '.') {
            MEDIA_ERR_LOG("Directory is of hidden type");
            return true;
        }

        string curPath = path;
        string excludePath = curPath.append("/.nomedia");
        // Check is the folder consist of .nomedia file
        if (ScannerUtils::IsExists(excludePath)) {
            return true;
        }

        // Check is the dir is part of skiplist
        if (CheckSkipScanList(path)) {
            return true;
        }
    }

    return dirHid;
}

// Check if the dir is hidden
bool MediaScannerObj::IsDirHiddenRecursive(const string &path)
{
    bool dirHid = false;
    string curPath = path;

    do {
        dirHid = IsDirHidden(curPath);
        if (dirHid) {
            break;
        }

        curPath = ScannerUtils::GetParentPath(curPath);
        if (curPath.empty()) {
            break;
        }
    } while (true);

    return dirHid;
}

// Scan the directory path recursively
int32_t MediaScannerObj::ScanDirInternal(const string &path)
{
    int32_t errCode = ERR_FAIL;

    // Check if it is hidden folder
    if (IsDirHiddenRecursive(path)) {
        MEDIA_ERR_LOG("MediaData %{private}s is hidden", path.c_str());
        return ERR_NOT_ACCESSIBLE;
    }

    mediaScannerDb_->ReadAlbums(path, albumMap_);

    // Walk the folder tree
    errCode = WalkFileTree(path, NO_PARENT);
    if (errCode == ERR_SUCCESS) {
        // write the remaining metadata to DB
        errCode = StartBatchProcessingToDB();
        if (errCode == ERR_SUCCESS) {
            CleanupDirectory(path);
        }
    }

    albumMap_.clear();

    return errCode;
}

int32_t MediaScannerObj::GetAvailableRequestId()
{
    static atomic<int32_t> i(0);

    return i.fetch_add(1);
}

void MediaScannerObj::SetAbilityContext(void)
{
}

void MediaScannerObj::ReleaseAbilityHelper()
{
    if (mediaScannerDb_ != nullptr) {
        mediaScannerDb_->SetRdbHelper();
    }

    isScannerInitDone_ = false;
}

bool MediaScannerObj::IsScannerRunning()
{
    return !scanResultCbMap_.empty();
}
} // namespace Media
} // namespace OHOS
