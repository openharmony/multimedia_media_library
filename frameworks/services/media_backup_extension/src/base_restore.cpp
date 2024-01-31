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

#include "backup_database_utils.h"
#include "backup_file_utils.h"
#include "application_context.h"
#include "extension_context.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "media_file_utils.h"
#include "media_scanner_manager.h"
#include "medialibrary_asset_operations.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_type_const.h"
#include "medialibrary_errno.h"
#include "metadata.h"
#include "photo_album_column.h"
#include "result_set_utils.h"
#include "userfilemgr_uri.h"

namespace OHOS {
namespace Media {
const std::string DATABASE_PATH = "/data/storage/el2/database/rdb/media_library.db";

void BaseRestore::StartRestore(const std::string &backupRetoreDir, const std::string &upgradePath)
{
    int32_t errorCode = Init(backupRetoreDir, upgradePath, true);
    if (errorCode == E_OK) {
        RestorePhoto();
        MEDIA_INFO_LOG("migrate database number: %{public}lld, file number: %{public}lld",
            (long long) migrateDatabaseNumber_, (long long) migrateFileNumber_);
        MediaLibraryRdbUtils::UpdateAllAlbums(mediaLibraryRdb_);
        MediaLibraryRdbUtils::UpdateSourceAlbumInternal(mediaLibraryRdb_);
        string notifyImage = MediaFileUtils::GetMediaTypeUri(MediaType::MEDIA_TYPE_IMAGE);
        Uri notifyImageUri(notifyImage);
        MediaLibraryDataManager::GetInstance()->NotifyChange(notifyImageUri);
        string notifyVideo = MediaFileUtils::GetMediaTypeUri(MediaType::MEDIA_TYPE_VIDEO);
        Uri notifyVideoUri(notifyVideo);
        MediaLibraryDataManager::GetInstance()->NotifyChange(notifyVideoUri);
    }
    HandleRestData();
}

int32_t BaseRestore::Init(void)
{
    if (mediaLibraryRdb_ != nullptr) {
        return E_OK;
    }
    int32_t err = BackupDatabaseUtils::InitDb(mediaLibraryRdb_, MEDIA_DATA_ABILITY_DB_NAME, DATABASE_PATH, BUNDLE_NAME,
        true);
    if (err != E_OK) {
        MEDIA_ERR_LOG("medialibrary rdb fail, err = %{public}d", err);
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
    migrateDatabaseNumber_ = 0;
    migrateFileNumber_ = 0;
    return E_OK;
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

vector<NativeRdb::ValuesBucket> BaseRestore::GetInsertValues(const int32_t sceneCode, std::vector<FileInfo> &fileInfos,
    int32_t sourceType)
{
    vector<NativeRdb::ValuesBucket> values;
    for (size_t i = 0; i < fileInfos.size(); i++) {
        if (!MediaFileUtils::IsFileExists(fileInfos[i].filePath)) {
            MEDIA_WARN_LOG("File is not exist, filePath = %{public}s.",
                BackupFileUtils::GarbleFilePath(fileInfos[i].filePath, sceneCode).c_str());
            continue;
        }
        if ((sceneCode == CLONE_RESTORE_ID) && (IsSameFile(fileInfos[i]))) {
            (void)MediaFileUtils::DeleteFile(fileInfos[i].filePath);
            MEDIA_WARN_LOG("File %{public}s already exists.",
                BackupFileUtils::GarbleFilePath(fileInfos[i].filePath, sceneCode).c_str());
            continue;
        }
        std::string cloudPath;
        int32_t uniqueId = MediaLibraryAssetOperations::CreateAssetUniqueId(fileInfos[i].fileType);
        int32_t errCode = BackupFileUtils::CreateAssetPathById(uniqueId, fileInfos[i].fileType,
            MediaFileUtils::GetExtensionFromPath(fileInfos[i].displayName), cloudPath);
        if (errCode != E_OK) {
            MEDIA_ERR_LOG("Create Asset Path failed, errCode=%{public}d", errCode);
            continue;
        }
        fileInfos[i].cloudPath = cloudPath;
        NativeRdb::ValuesBucket value = GetInsertValue(fileInfos[i], cloudPath, sourceType);
        SetValueFromMetaData(fileInfos[i], value);
        values.emplace_back(value);
    }
    return values;
}

void BaseRestore::SetValueFromMetaData(FileInfo &fileInfo, NativeRdb::ValuesBucket &value)
{
    std::unique_ptr<Metadata> data = make_unique<Metadata>();
    data->SetFilePath(fileInfo.filePath);
    data->SetFileMediaType(fileInfo.fileType);
    BackupFileUtils::FillMetadata(data);
    MediaType mediaType = data->GetFileMediaType();

    value.PutString(MediaColumn::MEDIA_FILE_PATH, data->GetFilePath());
    value.PutString(MediaColumn::MEDIA_MIME_TYPE, data->GetFileMimeType());
    value.PutInt(MediaColumn::MEDIA_TYPE, mediaType);
    value.PutString(MediaColumn::MEDIA_TITLE, data->GetFileTitle());
    value.PutLong(MediaColumn::MEDIA_SIZE, data->GetFileSize());
    value.PutLong(MediaColumn::MEDIA_DATE_MODIFIED, data->GetFileDateModified());
    value.PutInt(MediaColumn::MEDIA_DURATION, data->GetFileDuration());
    value.PutLong(MediaColumn::MEDIA_DATE_TAKEN, data->GetDateTaken());
    value.PutLong(MediaColumn::MEDIA_TIME_PENDING, 0);
    value.PutInt(PhotoColumn::PHOTO_HEIGHT, data->GetFileHeight());
    value.PutInt(PhotoColumn::PHOTO_WIDTH, data->GetFileWidth());
    value.PutInt(PhotoColumn::PHOTO_ORIENTATION, data->GetOrientation());
    value.PutDouble(PhotoColumn::PHOTO_LONGITUDE, data->GetLongitude());
    value.PutDouble(PhotoColumn::PHOTO_LATITUDE, data->GetLatitude());
    value.PutString(PhotoColumn::PHOTO_ALL_EXIF, data->GetAllExif());
    value.PutString(PhotoColumn::PHOTO_SHOOTING_MODE, data->GetShootingMode());
    value.PutString(PhotoColumn::PHOTO_SHOOTING_MODE_TAG, data->GetShootingModeTag());
    value.PutLong(PhotoColumn::PHOTO_LAST_VISIT_TIME, data->GetLastVisitTime());
    int64_t dateAdded = 0;
    ValueObject valueObject;
    if (value.GetObject(MediaColumn::MEDIA_DATE_ADDED, valueObject)) {
        valueObject.GetLong(dateAdded);
    }
    value.PutString(PhotoColumn::PHOTO_DATE_YEAR,
        MediaFileUtils::StrCreateTimeByMilliseconds(PhotoColumn::PHOTO_DATE_YEAR_FORMAT, dateAdded));
    value.PutString(PhotoColumn::PHOTO_DATE_MONTH,
        MediaFileUtils::StrCreateTimeByMilliseconds(PhotoColumn::PHOTO_DATE_MONTH_FORMAT, dateAdded));
    value.PutString(PhotoColumn::PHOTO_DATE_DAY,
        MediaFileUtils::StrCreateTimeByMilliseconds(PhotoColumn::PHOTO_DATE_DAY_FORMAT, dateAdded));
}

bool BaseRestore::IsSameFile(const FileInfo &fileInfo) const
{
    std::string originPath = BACKUP_RESTORE_DIR + RESTORE_CLOUD_DIR;
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

void BaseRestore::InsertPhoto(int32_t sceneCode, std::vector<FileInfo> &fileInfos, int32_t sourceType)
{
    if (mediaLibraryRdb_ == nullptr) {
        MEDIA_ERR_LOG("mediaLibraryRdb_ is null");
        return;
    }
    if (fileInfos.empty()) {
        MEDIA_ERR_LOG("fileInfos are empty");
        return;
    }
    int64_t startInsert = MediaFileUtils::UTCTimeMilliSeconds();
    vector<NativeRdb::ValuesBucket> values = GetInsertValues(sceneCode, fileInfos, sourceType);
    int64_t rowNum = 0;
    int32_t errCode = mediaLibraryRdb_->BatchInsert(rowNum, PhotoColumn::PHOTOS_TABLE, values);
    if (errCode == SQLITE3_DATABASE_LOCKER) {
        errCode = BatchInsertWithRetry(values, rowNum);
    } else if (errCode != E_OK) {
        MEDIA_ERR_LOG("InsertSql failed, errCode: %{public}d, rowNum: %{public}ld.", errCode, (long)rowNum);
        return;
    }
    int64_t startMove = MediaFileUtils::UTCTimeMilliSeconds();
    migrateDatabaseNumber_ += rowNum;
    int32_t fileMoveCount = 0;
    for (size_t i = 0; i < fileInfos.size(); i++) {
        if (!MediaFileUtils::IsFileExists(fileInfos[i].filePath)) {
            continue;
        }
        std::string tmpPath = fileInfos[i].cloudPath;
        std::string localPath = tmpPath.replace(0, RESTORE_CLOUD_DIR.length(), RESTORE_LOCAL_DIR);
        if (MoveFile(fileInfos[i].filePath, localPath) != E_OK) {
            MEDIA_ERR_LOG("MoveFile failed, filePath = %{public}s.",
                BackupFileUtils::GarbleFilePath(fileInfos[i].filePath, sceneCode).c_str());
            continue;
        }
        fileMoveCount++;
    }
    migrateFileNumber_ += fileMoveCount;
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("insert %{public}ld assets cost %{public}ld and move %{public}ld file cost %{public}ld.",
        (long)rowNum, (long)(startMove - startInsert), (long)fileMoveCount, (long)(end - startMove));
}

int32_t BaseRestore::BatchInsertWithRetry(std::vector<NativeRdb::ValuesBucket> &values, int64_t &rowNum)
{
    int32_t errCode = E_ERR;
    if (mediaLibraryRdb_ == nullptr) {
        MEDIA_ERR_LOG("mediaLibraryRdb_ is null");
        return errCode;
    }
    for (size_t i = 0; i < RETRY_TIME; i++) {
        sleep(SLEEP_INTERVAL);
        MEDIA_WARN_LOG("try batchInsert time: %{public}d", (int)i);
        errCode = mediaLibraryRdb_->BatchInsert(rowNum, PhotoColumn::PHOTOS_TABLE, values);
        if (errCode == SQLITE3_DATABASE_LOCKER) {
            continue;
        }
        if (errCode != E_OK) {
            MEDIA_ERR_LOG("try batchInsert failed, errCode: %{public}d, rowNum: %{public}ld.", errCode, (long)rowNum);
            return errCode;
        }
        return errCode;
    }
    return errCode;
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
