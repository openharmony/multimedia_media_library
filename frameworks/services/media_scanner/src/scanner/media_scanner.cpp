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
#include "medialibrary_data_manager_utils.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace OHOS::AppExecFwk;
using namespace OHOS::DataShare;

MediaScannerObj::MediaScannerObj(const std::string &path, const std::shared_ptr<IMediaScannerCallback> &callback,
    bool isDir) : isDir_(isDir), callback_(callback)
{
    if (isDir) {
        dir_ = path;
    } else {
        path_ = path;
    }
}

void MediaScannerObj::SetStopFlag(std::shared_ptr<bool> &flag)
{
    stopFlag_ = flag;
}

int32_t MediaScannerObj::ScanFile()
{
    MEDIA_DEBUG_LOG("scan file %{private}s", path_.c_str());

    int32_t ret = ScanFileInternal();
    if (ret != E_OK) {
        MEDIA_ERR_LOG("ScanFileInternal err %{public}d", ret);
    }

    (void)InvokeCallback(ret);

    return ret;
}

int32_t MediaScannerObj::ScanDir()
{
    MEDIA_INFO_LOG("scan dir %{private}s", path_.c_str());

    int32_t ret = ScanDirInternal();
    if (ret != E_OK) {
        MEDIA_ERR_LOG("ScanDirInternal err %{public}d", ret);
    }

    (void)InvokeCallback(ret);

    return ret;
}

void MediaScannerObj::Scan()
{
    if (isDir_) {
        ScanDir();
    } else {
        ScanFile();
    }
}

int32_t MediaScannerObj::InvokeCallback(int32_t err)
{
    if (callback_ == nullptr) {
        return E_OK;
    }

    return callback_->OnScanFinished(err, uri_, path_);
}

int32_t MediaScannerObj::CommitTransaction()
{
    unordered_set<MediaType> mediaTypeSet = {};
    string uri;
    unique_ptr<Metadata> data;

    // will begin a transaction in later pr
    for (uint32_t i = 0; i < dataBuffer_.size(); i++) {
        data = move(dataBuffer_[i]);
        if (data->GetFileId() != FILE_ID_DEFAULT) {
            uri = mediaScannerDb_->UpdateMetadata(*data);
            scannedIds_.insert(data->GetFileId());
        } else {
            uri = mediaScannerDb_->InsertMetadata(*data);
            scannedIds_.insert(stoi(MediaLibraryDataManagerUtils::GetIdFromUri(uri)));
        }

        // set uri for callback
        uri_ = uri;
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

int32_t MediaScannerObj::Commit()
{
    if (data_->GetFileId() != FILE_ID_DEFAULT) {
        uri_ = mediaScannerDb_->UpdateMetadata(*data_);
    } else {
        uri_ = mediaScannerDb_->InsertMetadata(*data_);
    }

    // notify change
    mediaScannerDb_->NotifyDatabaseChange(data_->GetFileMediaType());
    data_ = nullptr;

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

int32_t MediaScannerObj::GetParentDirInfo(const string &parent, int32_t parentId)
{
    size_t len = ROOT_MEDIA_DIR.length();
    string parentPath = parent + SLASH_CHAR;

    if (parentPath.find(ROOT_MEDIA_DIR) != 0) {
        MEDIA_ERR_LOG("invaid path %{private}s, not managed by scanner", path_.c_str());
        return E_DATA;
    }

    parentPath.erase(0, len);
    if (!parentPath.empty()) {
        data_->SetRelativePath(parentPath);
        parentPath = string("/") + parentPath.substr(0, parentPath.length() - 1);
        data_->SetAlbumName(ScannerUtils::GetFileNameFromUri(parentPath));
    }

    if (parentId == UNKNOWN_ID) {
        parentId = mediaScannerDb_->GetIdFromPath(parent);
        if (parentId == UNKNOWN_ID) {
            if (parent == ROOT_MEDIA_DIR) {
                parentId = 0;
            } else {
                MEDIA_ERR_LOG("failed to get parent id");
                return E_DATA;
            }
        }
    }
    data_->SetParentId(parentId);

    return E_OK;
}

int32_t MediaScannerObj::GetFileMetadata()
{
    struct stat statInfo = { 0 };
    if (stat(path_.c_str(), &statInfo) != 0) {
        MEDIA_ERR_LOG("stat syscall err %{public}d", errno);
        return E_SYSCALL;
    }

    data_ = make_unique<Metadata>();
    if (data_ == nullptr) {
        MEDIA_ERR_LOG("failed to make unique ptr for metadata");
        return E_DATA;
    }

    int32_t err = mediaScannerDb_->GetFileBasicInfo(path_, data_);
    if (err != E_OK) {
        MEDIA_ERR_LOG("failed to get file basic info");
        return err;
    }

    // may need isPending here
    if ((data_->GetFileDateModified() == statInfo.st_mtime) && (data_->GetFileSize() == statInfo.st_size)) {
        scannedIds_.insert(data_->GetFileId());
        return E_SCANNED;
    }

    // file path
    data_->SetFilePath(path_);
    data_->SetFileName(ScannerUtils::GetFileNameFromUri(path_));
    data_->SetFileTitle(ScannerUtils::GetFileTitle(data_->GetFileName()));

    // statinfo
    data_->SetFileSize(statInfo.st_size);
    data_->SetFileDateModified(static_cast<int64_t>(statInfo.st_mtime));

    // extension and type
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

    string parent = ScannerUtils::GetParentPath(path_);
    if ((!parent.empty() && ScannerUtils::CheckSkipScanList(parent))) {
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

    err = GetParentDirInfo(parent, UNKNOWN_ID);
    if (err != E_OK) {
        MEDIA_ERR_LOG("failed to get dir info");
        return err;
    }

    err = GetMediaInfo();
    if (err != E_OK) {
        MEDIA_ERR_LOG("failed to get media info");
        // no return here for fs metadata being updated or inserted
    }

    err = Commit();
    if (err != E_OK) {
        MEDIA_ERR_LOG("failed to commit err %{public}d", err);
        return err;
    }

    return E_OK;
}

int32_t MediaScannerObj::ScanFileInTraversal(const string &path, const string &parent, int32_t parentId)
{
    path_ = path;

    if (ScannerUtils::IsFileHidden(path_)) {
        MEDIA_ERR_LOG("the file is hidden");
        return E_FILE_HIDDEN;
    }

    int32_t err = GetFileMetadata();
    if (err != E_OK) {
        if (err != E_SCANNED) {
            MEDIA_ERR_LOG("failed to get file metadata");
        }
        return err;
    }

    err = GetParentDirInfo(parent, parentId);
    if (err != E_OK) {
        MEDIA_ERR_LOG("failed to get dir info");
        return err;
    }

    err = GetMediaInfo();
    if (err != E_OK) {
        MEDIA_ERR_LOG("failed to get media info");
        // no return here for fs metadata being updated or inserted
    }

    err = AddToTransaction();
    if (err != E_OK) {
        MEDIA_ERR_LOG("failed to add to transaction err %{public}d", err);
        return err;
    }

    return E_OK;
}

int32_t MediaScannerObj::InsertOrUpdateAlbumInfo(const string &albumPath, int32_t parentId,
    const string &albumName)
{
    struct stat statInfo;
    int32_t albumId = UNKNOWN_ID;
    bool update = false;

    if (stat(albumPath.c_str(), &statInfo)) {
        MEDIA_ERR_LOG("stat dir error %{public}d", errno);
        return UNKNOWN_ID;
    }

    if (albumMap_.find(albumPath) != albumMap_.end()) {
        Metadata albumInfo = albumMap_.at(albumPath);
        albumId = albumInfo.GetFileId();

        if (albumInfo.GetFileDateModified() == statInfo.st_mtime) {
            scannedIds_.insert(albumId);
            return albumId;
        } else {
            update = true;
        }
    }

    Metadata metadata;
    metadata.SetFilePath(albumPath);
    metadata.SetFileName(ScannerUtils::GetFileNameFromUri(albumPath));
    metadata.SetFileTitle(ScannerUtils::GetFileTitle(metadata.GetFileName()));
    metadata.SetFileMediaType(static_cast<MediaType>(MEDIA_TYPE_ALBUM));
    metadata.SetFileSize(statInfo.st_size);
    metadata.SetFileDateModified(statInfo.st_mtime);

    string relativePath = ScannerUtils::GetParentPath(albumPath) + SLASH_CHAR;
    metadata.SetRelativePath(relativePath.erase(0, ROOT_MEDIA_DIR.length()));
    metadata.SetParentId(parentId);
    metadata.SetAlbumName(albumName);

    if (update) {
        metadata.SetFileId(albumId);
        albumId = mediaScannerDb_->UpdateAlbum(metadata);
    } else {
        albumId = mediaScannerDb_->InsertAlbum(metadata);
    }
    scannedIds_.insert(albumId);

    return albumId;
}

int32_t MediaScannerObj::CleanupDirectory()
{
    vector<int32_t> toBeDeletedIds;
    unordered_set<MediaType> mediaTypeSet;
    unordered_map<int32_t, MediaType> prevIdMap;

    prevIdMap = mediaScannerDb_->GetIdsFromFilePath(dir_);
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

    return E_OK;
}

int32_t MediaScannerObj::WalkFileTree(const string &path, int32_t parentId)
{
    int err = E_OK;
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

    while ((ent = readdir(dirPath)) != nullptr && err != ERR_MEM_ALLOC_FAIL) {
        if (*stopFlag_) {
            break;
        }

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
            if (ScannerUtils::IsDirHidden(currentPath)) {
                continue;
            }

            int32_t albumId = InsertOrUpdateAlbumInfo(currentPath, parentId, ent->d_name);
            if (albumId == UNKNOWN_ID) {
                err = E_DATA;
                // might break in later pr for a rescan
                continue;
            }

            (void)WalkFileTree(currentPath, albumId);
        } else {
            (void)ScanFileInTraversal(currentPath, path, parentId);
        }
    }

    closedir(dirPath);
    FREE_MEMORY_AND_SET_NULL(fName);

    return E_OK;
}

int32_t MediaScannerObj::ScanDirInternal()
{
    if (ScannerUtils::IsDirHiddenRecursive(dir_)) {
        MEDIA_ERR_LOG("the dir %{private}s is hidden", dir_.c_str());
        return E_DIR_HIDDEN;
    }

    /*
     * 1. may query ablums in batch for the big data case
     * 2. postpone this operation might avoid some conflicts
     */
    int32_t err = mediaScannerDb_->ReadAlbums(dir_, albumMap_);
    if (err != E_OK) {
        MEDIA_ERR_LOG("read albums err %{public}d", err);
        return err;
    }

    err = WalkFileTree(dir_, NO_PARENT);
    if (err != E_OK) {
        MEDIA_ERR_LOG("walk file tree err %{public}d", err);
        return err;
    }

    err = CommitTransaction();
    if (err != E_OK) {
        MEDIA_ERR_LOG("commit transaction err %{public}d", err);
        return err;
    }

    err = CleanupDirectory();
    if (err != E_OK) {
        MEDIA_ERR_LOG("clean up dir err %{public}d", err);
        return err;
    }

    return E_OK;
}
} // namespace Media
} // namespace OHOS
