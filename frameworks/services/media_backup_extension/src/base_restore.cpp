/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#define MLOG_TAG "MediaLibraryBaseRestore"

#include "base_restore.h"
#include "application_context.h"
#include "extension_context.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "media_scanner_manager.h"
#include "medialibrary_asset_operations.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_type_const.h"
#include "medialibrary_errno.h"
#include "photo_album_column.h"
#include "result_set_utils.h"
#include "userfilemgr_uri.h"

namespace OHOS {
namespace Media {
const std::string DATABASE_PATH = "/data/storage/el2/database/rdb/media_library.db";

void BaseRestore::StartRestore(const std::string &orignPath, const std::string &updatePath)
{
    int32_t errorCode = Init(orignPath, updatePath, true);
    if (errorCode == E_OK) {
        RestorePhoto();
    }
    // Re-scanning is required when the system is restarted
    MediaScannerManager::GetInstance()->ScanDirSync(RESTORE_CLOUD_DIR, nullptr);
    HandleRestData();
}

int32_t BaseRestore::Init(void)
{
    if (mediaLibraryRdb_ != nullptr) {
        return E_OK;
    }

    NativeRdb::RdbStoreConfig config(MEDIA_DATA_ABILITY_DB_NAME);
    config.SetPath(DATABASE_PATH);
    config.SetBundleName(BUNDLE_NAME);
    config.SetReadConSize(CONNECT_SIZE);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S3);
    config.SetScalarFunction("cloud_sync_func", 0, CloudSyncTriggerFunc);
    config.SetScalarFunction("is_caller_self_func", 0, IsCallerSelfFunc);

    int32_t err;
    RdbCallback cb;
    mediaLibraryRdb_ = NativeRdb::RdbHelper::GetRdbStore(config, MEDIA_RDB_VERSION, cb, err);
    if (mediaLibraryRdb_ == nullptr) {
        MEDIA_ERR_LOG("Init media rdb fail, err = %{public}d", err);
        return E_FAIL;
    }

    auto context = AbilityRuntime::Context::GetApplicationContext();
    if (context == nullptr) {
        MEDIA_ERR_LOG("Failed to get context");
        return E_FAIL;
    }
    int32_t errCode = MediaLibraryDataManager::GetInstance()->InitMediaLibraryMgr(context, nullptr);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("When restore, InitMediaLibraryMgr fail, errcode = %{public}d", errCode);
        return errCode;
    }
    return E_OK;
}

std::string BaseRestore::CloudSyncTriggerFunc(const std::vector<std::string> &args)
{
    return "";
}

std::string BaseRestore::IsCallerSelfFunc(const std::vector<std::string> &args)
{
    return "false";
}

bool BaseRestore::ConvertPathToRealPath(const std::string &srcPath, const std::string &prefix,
    std::string &newPath, std::string &relativePath)
{
    int32_t pos = 0;
    int32_t count = 0;
    constexpr int32_t prefixLevel = 4;
    for (size_t i = 0; i < srcPath.length(); i++) {
        if (srcPath[i] == '/') {
            count++;
            if (count == prefixLevel) {
                pos = i;
                break;
            }
        }
    }
    if (count < prefixLevel) {
        return false;
    }
    relativePath = srcPath.substr(pos);
    newPath = prefix + relativePath;
    return true;
}

shared_ptr<NativeRdb::ResultSet> BaseRestore::QuerySql(const string &sql, const vector<string> &selectionArgs) const
{
    if (mediaLibraryRdb_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdb_ is nullptr. Maybe it didn't init successfully.");
        return nullptr;
    }

    return mediaLibraryRdb_->QuerySql(sql, selectionArgs);
}

int32_t BaseRestore::MoveFile(const std::string &srcFile, const std::string &dstFile) const
{
    if (MediaFileUtils::MoveFile(srcFile, dstFile)) {
        return E_OK;
    }

    if (!MediaFileUtils::CopyFileUtil(srcFile, dstFile)) {
        MEDIA_ERR_LOG("CopyFile failed, filePath: %{private}s, errmsg: %{public}s", srcFile.c_str(),
            strerror(errno));
        return E_FAIL;
    }
    (void)MediaFileUtils::DeleteFile(srcFile);
    return E_OK;
}

bool BaseRestore::IsSameFile(const FileInfo &fileInfo) const
{
    std::string originPath = ORIGIN_PATH + RESTORE_CLOUD_DIR;
    std::string srcPath = fileInfo.filePath;
    std::string tmpPath = fileInfo.filePath;
    std::string dstPath =  tmpPath.replace(0, originPath.length(), RESTORE_LOCAL_DIR);
    struct stat srcStatInfo {};
    struct stat dstStatInfo {};

    if (access(srcPath.c_str(), F_OK) || access(dstPath.c_str(), F_OK)) {
        return false;
    }
    if (stat(srcPath.c_str(), &srcStatInfo) != 0) {
        MEDIA_ERR_LOG("Failed to get file %{private}s StatInfo, err=%{public}d", srcPath.c_str(), errno);
        return false;
    }
    if (stat(dstPath.c_str(), &dstStatInfo) != 0) {
        MEDIA_ERR_LOG("Failed to get file %{private}s StatInfo, err=%{public}d", dstPath.c_str(), errno);
        return false;
    }
    if (fileInfo.fileSize != srcStatInfo.st_size) {
        MEDIA_ERR_LOG("Internal error");
        return false;
    }
    if (srcStatInfo.st_size != dstStatInfo.st_size) { /* file size */
        return false;
    }
    if (srcStatInfo.st_mtime != dstStatInfo.st_mtime) { /* last motify time */
        return false;
    }
    return true;
}

void BaseRestore::InsertPhoto(int32_t sceneCode, const std::vector<FileInfo> &fileInfos, int32_t sourceType) const
{
    for (size_t i = 0; i < fileInfos.size(); i++) {
        if (!MediaFileUtils::IsFileExists(fileInfos[i].filePath)) {
            MEDIA_WARN_LOG("File is not exist, filePath = %{private}s.", fileInfos[i].filePath.c_str());
            continue;
        }
        if ((sceneCode != UPDATE_RESTORE_ID) && (IsSameFile(fileInfos[i]) == true)) {
            (void)MediaFileUtils::DeleteFile(fileInfos[i].filePath);
            MEDIA_WARN_LOG("File %{private}s already exists.", fileInfos[i].filePath.c_str());
            continue;
        }
        std::string cloudPath;
        int32_t uniqueId = MediaLibraryAssetOperations::CreateAssetUniqueId(fileInfos[i].fileType);
        int32_t errCode = MediaLibraryAssetOperations::CreateAssetPathById(uniqueId, fileInfos[i].fileType,
            MediaFileUtils::GetExtensionFromPath(fileInfos[i].displayName), cloudPath);
        if (errCode != E_OK) {
            MEDIA_ERR_LOG("Create Asset Path failed, errCode=%{public}d", errCode);
            continue;
        }
        NativeRdb::ValuesBucket values = GetInsertValue(fileInfos[i], cloudPath, sourceType);
        if (mediaLibraryRdb_ == nullptr) {
            MEDIA_ERR_LOG("mediaLibraryRdb_ is null");
            return;
        }
        int64_t rowNum = 0;
        if (mediaLibraryRdb_->Insert(rowNum, PhotoColumn::PHOTOS_TABLE, values) != E_OK) {
            MEDIA_ERR_LOG("InsertSql failed, filePath = %{private}s.", fileInfos[i].filePath.c_str());
            continue;
        }

        // file move to local path, not cloud path
        std::string tmpPath = cloudPath;
        std::string localPath = tmpPath.replace(0, RESTORE_CLOUD_DIR.length(), RESTORE_LOCAL_DIR);
        if (MoveFile(fileInfos[i].filePath, localPath) != E_OK) {
            MEDIA_ERR_LOG("MoveFile failed, filePath = %{private}s.", fileInfos[i].filePath.c_str());
            continue;
        }
    }
}

NativeRdb::ValuesBucket BaseRestore::GetInsertValue(const FileInfo &fileInfo, const std::string &newPath,
    int32_t sourceType) const
{
    NativeRdb::ValuesBucket values;
    values.PutString(MediaColumn::MEDIA_FILE_PATH, newPath);
    values.PutString(MediaColumn::MEDIA_TITLE, fileInfo.title);
    values.PutString(MediaColumn::MEDIA_NAME, fileInfo.displayName);
    values.PutLong(MediaColumn::MEDIA_SIZE, fileInfo.fileSize);
    values.PutInt(MediaColumn::MEDIA_TYPE, fileInfo.fileType);
    values.PutLong(MediaColumn::MEDIA_DATE_ADDED, fileInfo.showDateToken);
    values.PutLong(MediaColumn::MEDIA_DURATION, fileInfo.duration);
    values.PutInt(MediaColumn::MEDIA_IS_FAV, fileInfo.isFavorite);
    values.PutLong(MediaColumn::MEDIA_DATE_TRASHED, fileInfo.recycledTime);
    values.PutInt(MediaColumn::MEDIA_HIDDEN, fileInfo.hidden);
    values.PutInt(PhotoColumn::PHOTO_HEIGHT, fileInfo.height);
    values.PutInt(PhotoColumn::PHOTO_WIDTH, fileInfo.width);
    values.PutString(PhotoColumn::PHOTO_USER_COMMENT, fileInfo.userComment);

    return values;
}
} // namespace Media
} // namespace OHOS
