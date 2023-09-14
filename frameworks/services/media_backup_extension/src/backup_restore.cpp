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

#define MLOG_TAG "MediaLibraryRestore"

#include "backup_restore.h"
#include "media_log.h"
#include "media_file_utils.h"
#include "medialibrary_errno.h"
#include "result_set_utils.h"
#include "media_column.h"
#include "userfile_manager_types.h"

namespace OHOS {
namespace Media {
const std::string DATABASE_NAME = "media_library.db";
const std::string DATABASE_PATH = "/data/storage/el2/database/rdb/media_library.db";

constexpr int32_t IMAGE_TYPE = 1;
constexpr int32_t VIDEO_TYPE = 3;

constexpr int32_t CONNECT_SIZE = 10;
constexpr int ASSET_IN_BUCKET_NUM_MAX = 1000;
constexpr int ASSET_DIR_START_NUM = 16;
constexpr int ASSET_MAX_COMPLEMENT_ID = 999;
const std::string DEFAULT_IMAGE_NAME = "IMG_";
const std::string DEFAULT_VIDEO_NAME = "VID_";
const std::string RESTORE_MEDIA_DIR = "/storage/cloud/files/Photo/";
const std::string RESTORE_LOCAL_DIR = "/storage/media/local/files/Photo/";

BackupRestore &BackupRestore::GetInstance(void)
{
    static BackupRestore inst;
    return inst;
}

const std::string CloudSyncTriggerFunc(const std::vector<std::string> &args)
{
    return "";
}

const std::string IsCallerSelfFunc(const std::vector<std::string> &args)
{
    return "false";
}

int32_t BackupRestore::InitRdb(void)
{
    if (rdb_ != nullptr) {
        return E_OK;
    }
    NativeRdb::RdbStoreConfig config(DATABASE_NAME);
    config.SetPath(DATABASE_PATH);
    config.SetBundleName(BUNDLE_NAME);
    config.SetReadConSize(CONNECT_SIZE);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S3);
    config.SetScalarFunction("cloud_sync_func", 0, CloudSyncTriggerFunc);
    config.SetScalarFunction("is_caller_self_func", 0, IsCallerSelfFunc);

    int32_t err;
    RdbCallback cb;
    rdb_ = NativeRdb::RdbHelper::GetRdbStore(config, MEDIA_RDB_VERSION, cb, err);
    if (rdb_ == nullptr) {
        MEDIA_ERR_LOG("gallyer data syncer init rdb fail");
        return E_FAIL;
    }
    return E_OK;
}

int32_t BackupRestore::ExecuteSql(const std::string &sql) const
{
    if (rdb_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdb_ is nullptr. Maybe it didn't init successfully.");
        return E_FAIL;
    }
    int32_t ret = rdb_->ExecuteSql(sql);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("rdbStore_->ExecuteSql failed, ret = %{public}d", ret);
        return E_HAS_DB_ERROR;
    }
    return E_OK;
}

shared_ptr<NativeRdb::ResultSet> BackupRestore::QuerySql(const string &sql, const vector<string> &selectionArgs) const
{
    if (rdb_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdb_ is nullptr. Maybe it didn't init successfully.");
        return nullptr;
    }

    return rdb_->QuerySql(sql, selectionArgs);
}

int32_t BackupRestore::CreateAssetBucket(int32_t fileId, int32_t &bucketNum) const
{
    if (fileId < 0) {
        MEDIA_ERR_LOG("input fileId [%{private}d] is invalid", fileId);
        return E_FAIL;
    }
    int start = ASSET_DIR_START_NUM;
    int divider = ASSET_DIR_START_NUM;
    while (fileId > start * ASSET_IN_BUCKET_NUM_MAX) {
        divider = start;
        start <<= 1;
    }

    int fileIdRemainder = fileId % divider;
    if (fileIdRemainder == 0) {
        bucketNum = start + fileIdRemainder;
    } else {
        bucketNum = (start - divider) + fileIdRemainder;
    }
    return E_OK;
}

int32_t BackupRestore::CreateAssetRealName(int32_t fileId, int32_t mediaType, const std::string &extension,
    std::string &name) const
{
    std::string fileNumStr = std::to_string(fileId);
    if (fileId <= ASSET_MAX_COMPLEMENT_ID) {
        size_t fileIdLen = fileNumStr.length();
        fileNumStr = ("00" + fileNumStr).substr(fileIdLen - 1);
    }

    std::string mediaTypeStr;
    switch (mediaType) {
        case IMAGE_TYPE:
            mediaTypeStr = DEFAULT_IMAGE_NAME;
            break;
        case VIDEO_TYPE:
            mediaTypeStr = DEFAULT_VIDEO_NAME;
            break;
        default:
            MEDIA_ERR_LOG("This mediatype %{public}d can not get real name", mediaType);
            return E_FAIL;
    }
    name = mediaTypeStr + std::to_string(MediaFileUtils::UTCTimeSeconds()) + "_" + fileNumStr + "." + extension;
    return E_OK;
}

static inline int32_t PrepareAssetDir(const std::string &dirPath)
{
    CHECK_AND_RETURN_RET(!dirPath.empty(), E_FAIL);
    if (!MediaFileUtils::IsFileExists(dirPath)) {
        bool ret = MediaFileUtils::CreateDirectory(dirPath);
        CHECK_AND_RETURN_RET_LOG(ret, E_CHECK_DIR_FAIL, "Create Dir Failed! dirPath=%{private}s",
            dirPath.c_str());
    }
    return E_OK;
}

int32_t BackupRestore::CreateAssetPathById(int32_t fileId, FileInfo &fileInfo, std::string &cloudPath,
    std::string &localPath) const
{
    int32_t mediaType = fileInfo.fileType;
    std::string extension = MediaFileUtils::GetExtensionFromPath(fileInfo.displayName);

    int32_t bucketNum = 0;
    int32_t errCode = CreateAssetBucket(fileId, bucketNum);
    if (errCode != E_OK) {
        return errCode;
    }

    std::string realName;
    errCode = CreateAssetRealName(fileId, mediaType, extension, realName);
    if (errCode != E_OK) {
        return errCode;
    }

    std::string dirPath = RESTORE_MEDIA_DIR + std::to_string(bucketNum);
    errCode = PrepareAssetDir(dirPath);
    if (errCode != E_OK) {
        return errCode;
    }

    cloudPath = dirPath + "/" + realName;
    localPath = RESTORE_LOCAL_DIR + std::to_string(bucketNum) + "/" + realName;
    return E_OK;
}

int32_t BackupRestore::GetFileId(int32_t type) const
{
    int32_t result = -1;
    string typeString;
    switch (type) {
        case IMAGE_TYPE:
            typeString += IMAGE_ASSET_TYPE;
            break;
        case VIDEO_TYPE:
            typeString += VIDEO_ASSET_TYPE;
            break;
        default:
            MEDIA_ERR_LOG("This type %{public}d can not get unique id", type);
            return result;
    }

    const string updateSql = "UPDATE " + ASSET_UNIQUE_NUMBER_TABLE + " SET " + UNIQUE_NUMBER +
        "=" + UNIQUE_NUMBER + "+1" " WHERE " + ASSET_MEDIA_TYPE + "='" + typeString + "';";
    const string querySql = "SELECT " + UNIQUE_NUMBER + " FROM " + ASSET_UNIQUE_NUMBER_TABLE +
        " WHERE " + ASSET_MEDIA_TYPE + "='" + typeString + "';";

    int32_t errCode = ExecuteSql(updateSql);
    if (errCode < 0) {
        MEDIA_ERR_LOG("execute update unique number failed, ret=%{public}d", errCode);
        return errCode;
    }

    auto resultSet = QuerySql(querySql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return E_HAS_DB_ERROR;
    }
    return GetInt32Val(UNIQUE_NUMBER, resultSet) - 1;
}

int32_t BackupRestore::QueryMaxId(void) const
{
    const string querySql = "SELECT MAX(file_id) as maxId FROM Photos;";

    auto resultSet = QuerySql(querySql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return E_HAS_DB_ERROR;
    }
    return GetInt32Val("maxId", resultSet);
}

void BackupRestore::StartRestore(std::vector<FileInfo> &fileInfos)
{
    InitRdb();
    for (size_t i = 0; i < fileInfos.size(); i++) {
        if (!MediaFileUtils::IsFileExists(fileInfos[i].filePath)) {
            MEDIA_WARN_LOG("File is not exist, filePath = %{private}s.", fileInfos[i].filePath.c_str());
            continue;
        }
        std::string localPath;
        std::string cloudPath;
        int32_t fileId = GetFileId(fileInfos[i].fileType);
        if (CreateAssetPathById(fileId, fileInfos[i], cloudPath, localPath) != E_OK) {
            MEDIA_ERR_LOG("CreateAssetPathById failed, filePath = %{private}s.", fileInfos[i].filePath.c_str());
            continue;
        }
        if (InsertSql(fileInfos[i], cloudPath) != E_OK) {
            MEDIA_ERR_LOG("InsertSql failed, filePath = %{private}s.", fileInfos[i].filePath.c_str());
            continue;
        }
        if (!MediaFileUtils::MoveFile(fileInfos[i].filePath, localPath) &&
            !MediaFileUtils::CopyFileUtil(fileInfos[i].filePath, localPath)) {
            MEDIA_ERR_LOG("MoveFile failed, filePath = %{private}s.", fileInfos[i].filePath.c_str());
            continue;
        }
        NotifyPhotoAdd(cloudPath, fileInfos[i]);
    }
}

void BackupRestore::MoveFiles(const std::string &originPath) const
{
    const std::string DOCUMENT_PATH = "/storage/media/local/files/Documents";
    if (!MediaFileUtils::RenameDir(originPath, DOCUMENT_PATH)) {
        MEDIA_ERR_LOG("Move media file failed.");
    }
}

int32_t BackupRestore::InsertSql(FileInfo &fileInfo, std::string &newPath) const
{
    std::string displayName = fileInfo.displayName;
    std::string data = newPath;
    std::string fileSize = std::to_string(fileInfo._size);
    std::string duration = std::to_string(fileInfo.duration);
    std::string date_added = std::to_string(fileInfo.showDateToken);
    std::string media_type = std::to_string(fileInfo.fileType == IMAGE_TYPE ?
        MediaType::MEDIA_TYPE_IMAGE : MediaType::MEDIA_TYPE_VIDEO);
    std::string title = MediaFileUtils::GetTitleFromDisplayName(fileInfo.displayName);
    std::string is_favorite = std::to_string(fileInfo.is_hw_favorite);
    std::string date_trashed = std::to_string(fileInfo.recycledTime);
    std::string hidden = std::to_string(fileInfo.hidden);
    std::string height = std::to_string(fileInfo.height);
    std::string width = std::to_string(fileInfo.width);

    std::string insertStatement = "INSERT INTO Photos (data,title,display_name,media_type,date_added, \
        is_favorite, date_trashed, hidden, size, duration, height, width) VALUES ('" + data +
        "','" + title + "','" + displayName + "'," + media_type + "," + date_added + "," + is_favorite +
        "," + date_trashed + "," + hidden + "," + fileSize + "," + duration + "," + height + "," + width + ");";
    return ExecuteSql(insertStatement);
}

int32_t BackupRestore::UpdaterAlbum(const std::string &notifyUri, const std::string &albumSubtype) const
{
    std::string updaterSql = "UPDATE PhotoAlbum SET cover_uri = '" + notifyUri +
        "', count = count + 1 WHERE album_subtype = " + albumSubtype + ";";
    return ExecuteSql(updaterSql);
}

void BackupRestore::NotifyPhotoAdd(const std::string &path, const FileInfo &fileInfo) const
{
    std::string prefix = PhotoColumn::PHOTO_URI_PREFIX;
    int32_t rowId = QueryMaxId();
    if (rowId <= 0) {
        MEDIA_ERR_LOG("Invalid rowId for query max id.");
    }
    std::string extraUri = MediaFileUtils::GetExtraUri(fileInfo.displayName, path);
    std::string notifyUri = MediaFileUtils::GetUriByExtrConditions(prefix, std::to_string(rowId), extraUri);

    if (fileInfo.recycledTime != 0) {
        UpdaterAlbum(notifyUri, std::to_string(PhotoAlbumSubType::TRASH));
        return;
    }
    if (fileInfo.hidden != 0) {
        UpdaterAlbum(notifyUri, std::to_string(PhotoAlbumSubType::HIDDEN));
        return;
    }

    if (fileInfo.fileType == IMAGE_TYPE) {
        UpdaterAlbum(notifyUri, std::to_string(PhotoAlbumSubType::IMAGES));
    } else {
        UpdaterAlbum(notifyUri, std::to_string(PhotoAlbumSubType::VIDEO));
    }

    if (fileInfo.is_hw_favorite != 0) {
        UpdaterAlbum(notifyUri, std::to_string(PhotoAlbumSubType::FAVORITE));
    }
}
} // namespace Media
} // namespace OHOS
