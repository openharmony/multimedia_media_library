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
#include "medialibrary_errno.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace OHOS::AppExecFwk;
using namespace OHOS::DataShare;

bool MediaScannerObj::isDir()
{
    return isDir_;
}

int32_t MediaScannerObj::ScanFile()
{
    MEDIA_INFO_LOG("begin");

    int32_t ret = ScanFileInternal();
    if (ret != E_OK) {
        MEDIA_ERR_LOG("ScanFileInternal err %{public}d", ret);
    }

    return InvokeCallback(ret);
}

int32_t MediaScannerObj::ScanDir()
{
    MEDIA_INFO_LOG("begin");

    int32_t ret = ScanDirInternal();
    if (ret != E_OK) {
        MEDIA_ERR_LOG("ScanDirInternal err %{public}d", ret);
    }

    return InvokeCallback(ret);
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

    for (const MediaType &mediaType : mediaTypeSet) {
        mediaScannerDb_->NotifyDatabaseChange(mediaType);
    }

    scannedIds_.clear();
}

int32_t MediaScannerObj::CommitTransaction()
{
    unordered_set<MediaType> mediaTypeSet = {};
    string uri = "";
    unique_ptr<Metadata> data;

    // will begin a transaction in later pr
    for (uint32_t i = 0; i < dataBuffer_.size(); i++) {
        data = move(dataBuffer_[i]);


        if (data->GetFileId() != FILE_ID_DEFAULT) {
            uri = mediaScannerDb_->UpdateMetadata(*data);
            scannedIds_.insert(data->GetFileId());
        } else {
            uri = mediaScannerDb_->InsertMetadata(*data);
            scannedIds_.insert(data->GetFileId());
        }

        // set uri for scan file callback
        this->uri_ = uri;
        mediaTypeSet.insert(data->GetFileMediaType());
    }

    dataBuffer_.clear();

    for (const MediaType &mediaType : mediaTypeSet) {
        mediaScannerDb_->NotifyDatabaseChange(mediaType);
    }

    return E_OK;
}

int32_t MediaScannerObj::AddToTransaction()
{
    dataBuffer_.emplace_back(move(data_));
    if (dataBuffer_.size() >= MAX_BATCH_SIZE) {
        return CommitTransaction();
    }

    return E_OK;
}

int32_t MediaScannerObj::GetMediaInfo()
{
    if (find(EXTRACTOR_SUPPORTED_MIME.begin(), EXTRACTOR_SUPPORTED_MIME.end(),
        data_->GetFileMimeType()) != EXTRACTOR_SUPPORTED_MIME.end()) {
        return MetadataExtractor::Extract(data_);
    }

    return E_OK;
}

int32_t MediaScannerObj::GetParentDirInfo(string &parentFolder)
{
    int32_t parentId = mediaScannerDb_->GetIdFromPath(parentFolder);
    if (parentId < 0) {
        if (parentFolder == ROOT_MEDIA_DIR) {
            parentId = 0;
        } else {
            MEDIA_ERR_LOG("failed to get parent id");
            return E_DATA;
        }
    }

    data_->SetParentId(parentId);

    size_t len = ROOT_MEDIA_DIR.length();
    string parentPath = parentFolder + SLASH_CHAR;
    if (parentPath.substr(0, len).compare(ROOT_MEDIA_DIR) == 0) {
        parentPath.erase(0, len);
        if (!parentPath.empty()) {
            data_->SetRelativePath(parentPath);
            parentPath = string("/") + parentPath.substr(0, parentPath.length() - 1);
            data_->SetAlbumName(ScannerUtils::GetFileNameFromUri(parentPath));
        }
    } else {
        MEDIA_ERR_LOG("path: %{private}s is not correct, right is begin with %{private}s",
                      path_.c_str(), ROOT_MEDIA_DIR.c_str());
        return E_DATA;
    }

    return E_OK;
}

int32_t MediaScannerObj::GetFileMetadata()
{
    struct stat statInfo = { 0 };
    if (stat(path_.c_str(), &statInfo) != 0) {
        MEDIA_ERR_LOG("stat syscall err %{public}d", errno);
        return E_SYSCALL;
    }

    data_ = mediaScannerDb_->GetFileModifiedInfo(path_);
    if (data_ == nullptr) {
        MEDIA_ERR_LOG("failed to get file db info");
        return E_DATA;
    }

    // may need isPending here
    if (data_ != nullptr &&
        data_->GetFileDateModified() == statInfo.st_mtime &&
        data_->GetFileSize() == statInfo.st_size) {
        scannedIds_.insert(data_->GetFileId());
        return E_SCANNED;
    }

    data_->SetFilePath(path_);
    data_->SetFileName(ScannerUtils::GetFileNameFromUri(path_));

    data_->SetFileSize(statInfo.st_size);
    data_->SetFileDateAdded(static_cast<int64_t>(statInfo.st_ctime));
    data_->SetFileDateModified(static_cast<int64_t>(statInfo.st_mtime));

    string extension = ScannerUtils::GetFileExtensionFromFileUri(path_);
    string mimeType = ScannerUtils::GetMimeTypeFromExtension(extension);
    data_->SetFileExtension(extension);
    data_->SetFileMimeType(mimeType);
    data_->SetFileMediaType(ScannerUtils::GetMediatypeFromMimetype(mimeType));

    return E_OK;
}

int32_t MediaScannerObj::ScanFileInternal()
{
    if (ScannerUtils::IsFileHidden(path_)) {
        MEDIA_ERR_LOG("the file is hidden");
        return E_FILE_HIDDEN;
    }

    string parentFolder = ScannerUtils::GetParentPath(path_);
    if ((!parentFolder.empty() && IsDirHiddenRecursive(parentFolder))) {
        MEDIA_ERR_LOG("the dir is hidden");
        return E_DIR_HIDDEN;
    }

    int32_t err = GetFileMetadata();
    if (err != E_OK) {
        if (err != E_SCANNED) {
            MEDIA_ERR_LOG("failed to get file metadata");
        }
        return err;
    }

    err = GetParentDirInfo(parentFolder);
    if (err != E_OK) {
        MEDIA_ERR_LOG("failed to get dir info");
        return err;
    }

    err = GetMediaInfo();
    if (err != E_OK) {
        MEDIA_ERR_LOG("failed to get media info");
        // no return here for fs metadata being updated or inserted
    }

    return AddToTransaction();
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

    unique_ptr<Metadata> fileMetadata;
    // unique_ptr<Metadata> fileMetadata = GetFileMetadata(albumPath, parentId);
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
            // errCode = ScanFileContent(currentPath, parentId);
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
int32_t MediaScannerObj::ScanDirInternal()
{
    int32_t errCode = ERR_FAIL;

    // Check if it is hidden folder
    if (IsDirHiddenRecursive(path_)) {
        MEDIA_ERR_LOG("MediaData %{private}s is hidden", path_.c_str());
        return ERR_NOT_ACCESSIBLE;
    }

    mediaScannerDb_->ReadAlbums(path_, albumMap_);

    // Walk the folder tree
    errCode = WalkFileTree(path_, NO_PARENT);
    if (errCode == ERR_SUCCESS) {
        // write the remaining metadata to DB
        errCode = CommitTransaction();
        if (errCode == ERR_SUCCESS) {
            CleanupDirectory(path_);
        }
    }

    albumMap_.clear();

    return errCode;
}
} // namespace Media
} // namespace OHOS
