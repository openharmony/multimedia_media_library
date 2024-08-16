/*
 * Copyright (C) 2023-2024 Huawei Device Co., Ltd.
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
#include "background_task_mgr_helper.h"
#include "backup_database_utils.h"
#include "backup_dfx_utils.h"
#include "backup_file_utils.h"
#include "extension_context.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "media_file_utils.h"
#include "media_scanner_manager.h"
#include "medialibrary_asset_operations.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_type_const.h"
#include "medialibrary_errno.h"
#include "metadata.h"
#include "parameters.h"
#include "photo_album_column.h"
#include "result_set_utils.h"
#include "resource_type.h"
#include "userfilemgr_uri.h"
#include "medialibrary_notify.h"

namespace OHOS {
namespace Media {
const std::string DATABASE_PATH = "/data/storage/el2/database/rdb/media_library.db";
const std::string singleDirName = "A";
const std::string CLONE_FLAG = "multimedia.medialibrary.cloneFlag";

void BaseRestore::StartRestore(const std::string &backupRetoreDir, const std::string &upgradePath)
{
    backupRestoreDir_ = backupRetoreDir;
    int32_t errorCode = Init(backupRetoreDir, upgradePath, true);
    if (errorCode == E_OK) {
        RestorePhoto();
        RestoreAudio();
        MEDIA_INFO_LOG("migrate database number: %{public}lld, file number: %{public}lld (%{public}lld + "
            "%{public}lld), duplicate number: %{public}lld + %{public}lld, audio database number:%{public}lld, "
            "audio file number:%{public}lld, duplicate audio number: %{public}lld, map number: %{public}lld",
            (long long)migrateDatabaseNumber_, (long long)migrateFileNumber_,
            (long long)(migrateFileNumber_ - migrateVideoFileNumber_), (long long)migrateVideoFileNumber_,
            (long long)migratePhotoDuplicateNumber_, (long long)migrateVideoDuplicateNumber_,
            (long long)migrateAudioDatabaseNumber_, (long long)migrateAudioFileNumber_,
            (long long)migrateAudioDuplicateNumber_, (long long) migrateDatabaseMapNumber_);
        MediaLibraryRdbUtils::UpdateAllAlbums(mediaLibraryRdb_);
        BackupDatabaseUtils::UpdateUniqueNumber(mediaLibraryRdb_, imageNumber_, IMAGE_ASSET_TYPE);
        BackupDatabaseUtils::UpdateUniqueNumber(mediaLibraryRdb_, videoNumber_, VIDEO_ASSET_TYPE);
        BackupDatabaseUtils::UpdateUniqueNumber(mediaLibraryRdb_, audioNumber_, AUDIO_ASSET_TYPE);
        auto watch = MediaLibraryNotify::GetInstance();
        if (watch == nullptr) {
            MEDIA_ERR_LOG("Can not get MediaLibraryNotify Instance");
            return;
        }
        watch->Notify(PhotoColumn::DEFAULT_PHOTO_URI, NotifyType::NOTIFY_ADD);
    } else {
        SetErrorCode(RestoreError::INIT_FAILED);
    }
    HandleRestData();
}

int32_t BaseRestore::Init(void)
{
    if (mediaLibraryRdb_ != nullptr) {
        return E_OK;
    }
    auto context = AbilityRuntime::Context::GetApplicationContext();
    if (context == nullptr) {
        MEDIA_ERR_LOG("Failed to get context");
        return E_FAIL;
    }
    BackgroundTaskMgr::EfficiencyResourceInfo resourceInfo =
        BackgroundTaskMgr::EfficiencyResourceInfo(BackgroundTaskMgr::ResourceType::CPU, true, 0, "apply", true, true);
    BackgroundTaskMgr::BackgroundTaskMgrHelper::ApplyEfficiencyResources(resourceInfo);
    int32_t err = BackupDatabaseUtils::InitDb(mediaLibraryRdb_, MEDIA_DATA_ABILITY_DB_NAME, DATABASE_PATH, BUNDLE_NAME,
        true, context->GetArea());
    if (err != E_OK) {
        MEDIA_ERR_LOG("medialibrary rdb fail, err = %{public}d", err);
        return E_FAIL;
    }
    migrateDatabaseNumber_ = 0;
    migrateFileNumber_ = 0;
    migrateVideoFileNumber_ = 0;
    migrateAudioDatabaseNumber_ = 0;
    migrateAudioFileNumber_ = 0;
    imageNumber_ = BackupDatabaseUtils::QueryUniqueNumber(mediaLibraryRdb_, IMAGE_ASSET_TYPE);
    videoNumber_ = BackupDatabaseUtils::QueryUniqueNumber(mediaLibraryRdb_, VIDEO_ASSET_TYPE);
    audioNumber_ = BackupDatabaseUtils::QueryUniqueNumber(mediaLibraryRdb_, AUDIO_ASSET_TYPE);
    MEDIA_INFO_LOG("imageNumber: %{public}d", (int)imageNumber_);
    MEDIA_INFO_LOG("videoNumber: %{public}d", (int)videoNumber_);
    MEDIA_INFO_LOG("audioNumber: %{public}d", (int)audioNumber_);
    return E_OK;
}

bool BaseRestore::ConvertPathToRealPath(const std::string &srcPath, const std::string &prefix,
    std::string &newPath, std::string &relativePath)
{
    size_t pos = 0;
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
    if (!dualDirName_.empty() && relativePath.find(dualDirName_) != string::npos) {
        std::size_t posStart = relativePath.find_first_of("/");
        std::size_t posEnd = relativePath.find_first_of("/", posStart + 1);
        if (posEnd != string::npos) {
            string temp = relativePath.substr(posStart + 1, posEnd - posStart -1);
            if (temp == dualDirName_) {
                relativePath.replace(relativePath.find(dualDirName_), dualDirName_.length(), singleDirName);
            }
        }
    }
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
        if (!MediaFileUtils::IsFileValid(fileInfos[i].filePath)) {
            MEDIA_WARN_LOG("File is not exist, filePath = %{public}s.",
                BackupFileUtils::GarbleFilePath(fileInfos[i].filePath, sceneCode).c_str());
            UpdateFailedFiles(fileInfos[i].fileType, fileInfos[i].oldPath, RestoreError::FILE_INVALID);
            continue;
        }
        std::string cloudPath;
        int32_t uniqueId;
        if (fileInfos[i].fileType == MediaType::MEDIA_TYPE_IMAGE) {
            lock_guard<mutex> lock(imageMutex_);
            uniqueId = static_cast<int32_t>(imageNumber_);
            imageNumber_++;
        } else {
            lock_guard<mutex> lock(videoMutex_);
            uniqueId = static_cast<int32_t>(videoNumber_);
            videoNumber_++;
        }
        int32_t errCode = BackupFileUtils::CreateAssetPathById(uniqueId, fileInfos[i].fileType,
            MediaFileUtils::GetExtensionFromPath(fileInfos[i].displayName), cloudPath);
        if (errCode != E_OK) {
            MEDIA_ERR_LOG("Create Asset Path failed, errCode=%{public}d", errCode);
            continue;
        }
        fileInfos[i].cloudPath = cloudPath;
        NativeRdb::ValuesBucket value = GetInsertValue(fileInfos[i], cloudPath, sourceType);
        SetValueFromMetaData(fileInfos[i], value);
        if (sceneCode == DUAL_FRAME_CLONE_RESTORE_ID && maxFileId_ > 0 &&
            HasSameFileForDualClone(mediaLibraryRdb_, PhotoColumn::PHOTOS_TABLE, fileInfos[i])) {
            (void)MediaFileUtils::DeleteFile(fileInfos[i].filePath);
            MEDIA_WARN_LOG("File %{public}s already exists.",
                BackupFileUtils::GarbleFilePath(fileInfos[i].filePath, sceneCode).c_str());
            UpdateDuplicateNumber(fileInfos[i].fileType);
            continue;
        }
        values.emplace_back(value);
    }
    return values;
}

void BaseRestore::GetMaxFileId(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore)
{
    string maxFileId = "max(" + MediaColumn::MEDIA_ID + ")";
    string querySql = "SELECT " + maxFileId + "," + MEDIA_COLUMN_COUNT_1 + " FROM Photos";
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(rdbStore, querySql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        maxFileId_ = 0;
        return;
    }
    maxFileId_ = GetInt32Val(maxFileId, resultSet);
    maxCount_ = GetInt32Val(MEDIA_COLUMN_COUNT_1, resultSet);
    MEDIA_INFO_LOG("maxFIleId:%{public}d, maxCount:%{public}d", maxFileId_, maxCount_);
}

bool BaseRestore::HasSameFileForDualClone(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
    const std::string &tableName, FileInfo &fileInfo)
{
    string querySql = "SELECT p." + MediaColumn::MEDIA_ID + " , p." + MediaColumn::MEDIA_FILE_PATH +
        " FROM (SELECT file_id, size, orientation, data FROM Photos " + \
        " where file_id <= " + to_string(maxFileId_) + " AND display_name = '" + fileInfo.displayName + "' limit " + \
        to_string(maxCount_) + ") as p INNER JOIN PhotoMap ON p.file_id = PhotoMap.map_asset " + \
        "INNER JOIN PhotoAlbum ON PhotoAlbum.album_id = PhotoMap.map_album Where size = " +
        to_string(fileInfo.fileSize) + \
        " AND (((PhotoAlbum.bundle_name = '' OR PhotoAlbum.bundle_name is null ) AND PhotoAlbum.album_name = '" +
        fileInfo.packageName + "') OR (((PhotoAlbum.bundle_name != '' AND PhotoAlbum.bundle_name is not null) " + \
        "AND PhotoAlbum.bundle_name = '" + fileInfo.bundleName + "') OR PhotoAlbum.album_name = '" +
        fileInfo.packageName + "'))";

    if (fileInfo.fileType != MEDIA_TYPE_VIDEO) {
        querySql += " AND p.orientation = " + to_string(fileInfo.orientation);
    }
    querySql += " LIMIT 1 ";
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(rdbStore, querySql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return false;
    }
    int32_t fileId = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
    string cloudPath = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
    if (fileId <= 0 || cloudPath.empty()) {
        MEDIA_ERR_LOG("Get invalid fileId or cloudPath: %{public}d", fileId);
        return false;
    }
    fileInfo.fileIdNew = fileId;
    fileInfo.cloudPath = cloudPath;
    return true;
}

static void InsertDateAdded(std::unique_ptr<Metadata> &metadata, NativeRdb::ValuesBucket &value)
{
    int64_t dateAdded = metadata->GetFileDateAdded();
    if (dateAdded != 0) {
        value.PutLong(MediaColumn::MEDIA_DATE_ADDED, dateAdded);
        return;
    }

    int64_t dateTaken = metadata->GetDateTaken();
    if (dateTaken == 0) {
        int64_t dateModified = metadata->GetFileDateModified();
        if (dateModified == 0) {
            dateAdded = MediaFileUtils::UTCTimeMilliSeconds();
            MEDIA_WARN_LOG("Invalid dateAdded time, use current time instead: %{public}lld",
                static_cast<long long>(dateAdded));
        } else {
            dateAdded = dateModified;
            MEDIA_WARN_LOG("Invalid dateAdded time, use dateModified instead: %{public}lld",
                static_cast<long long>(dateAdded));
        }
    } else {
        dateAdded = dateTaken * MSEC_TO_SEC;
        MEDIA_WARN_LOG("Invalid dateAdded time, use dateTaken instead: %{public}lld",
            static_cast<long long>(dateAdded));
    }
    value.PutLong(MediaColumn::MEDIA_DATE_ADDED, dateAdded);
}

static void InsertOrientation(std::unique_ptr<Metadata> &metadata, NativeRdb::ValuesBucket &value,
    const FileInfo &fileInfo)
{
    bool hasOrientation = value.HasColumn(PhotoColumn::PHOTO_ORIENTATION);
    if (hasOrientation && fileInfo.fileType != MEDIA_TYPE_VIDEO) {
        return; // image use orientation in rdb
    }
    if (hasOrientation) {
        value.Delete(PhotoColumn::PHOTO_ORIENTATION);
    }
    value.PutInt(PhotoColumn::PHOTO_ORIENTATION, metadata->GetOrientation()); // video use orientation in metadata
}

void BaseRestore::SetValueFromMetaData(FileInfo &fileInfo, NativeRdb::ValuesBucket &value)
{
    std::unique_ptr<Metadata> data = make_unique<Metadata>();
    data->SetFilePath(fileInfo.filePath);
    data->SetFileMediaType(fileInfo.fileType);
    data->SetFileDateModified(fileInfo.dateModified);
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
    value.PutDouble(PhotoColumn::PHOTO_LONGITUDE, data->GetLongitude());
    value.PutDouble(PhotoColumn::PHOTO_LATITUDE, data->GetLatitude());
    value.PutString(PhotoColumn::PHOTO_ALL_EXIF, data->GetAllExif());
    value.PutString(PhotoColumn::PHOTO_SHOOTING_MODE, data->GetShootingMode());
    value.PutString(PhotoColumn::PHOTO_SHOOTING_MODE_TAG, data->GetShootingModeTag());
    value.PutLong(PhotoColumn::PHOTO_LAST_VISIT_TIME, data->GetLastVisitTime());
    value.PutString(PhotoColumn::PHOTO_FRONT_CAMERA, data->GetFrontCamera());
    InsertDateAdded(data, value);
    InsertOrientation(data, value, fileInfo);
    int64_t dateAdded = 0;
    ValueObject valueObject;
    if (value.GetObject(MediaColumn::MEDIA_DATE_ADDED, valueObject)) {
        valueObject.GetLong(dateAdded);
    }
    fileInfo.dateAdded = dateAdded;
    value.PutString(PhotoColumn::PHOTO_DATE_YEAR,
        MediaFileUtils::StrCreateTimeByMilliseconds(PhotoColumn::PHOTO_DATE_YEAR_FORMAT, dateAdded));
    value.PutString(PhotoColumn::PHOTO_DATE_MONTH,
        MediaFileUtils::StrCreateTimeByMilliseconds(PhotoColumn::PHOTO_DATE_MONTH_FORMAT, dateAdded));
    value.PutString(PhotoColumn::PHOTO_DATE_DAY,
        MediaFileUtils::StrCreateTimeByMilliseconds(PhotoColumn::PHOTO_DATE_DAY_FORMAT, dateAdded));
}

void BaseRestore::SetAudioValueFromMetaData(FileInfo &fileInfo, NativeRdb::ValuesBucket &value)
{
    std::unique_ptr<Metadata> data = make_unique<Metadata>();
    data->SetFilePath(fileInfo.filePath);
    data->SetFileMediaType(fileInfo.fileType);
    data->SetFileTitle(fileInfo.title);
    data->SetFileDateModified(fileInfo.dateModified);
    BackupFileUtils::FillMetadata(data);
    fileInfo.fileSize = data->GetFileSize();
    MediaType mediaType = data->GetFileMediaType();

    value.PutString(MediaColumn::MEDIA_TITLE, data->GetFileTitle());
    value.PutString(MediaColumn::MEDIA_MIME_TYPE, data->GetFileMimeType());
    value.PutInt(MediaColumn::MEDIA_TYPE, mediaType);
    value.PutLong(MediaColumn::MEDIA_SIZE, data->GetFileSize());
    value.PutLong(MediaColumn::MEDIA_DATE_MODIFIED, data->GetFileDateModified());
    value.PutInt(MediaColumn::MEDIA_DURATION, data->GetFileDuration());
    value.PutLong(MediaColumn::MEDIA_DATE_TAKEN, data->GetDateTaken());
    value.PutLong(MediaColumn::MEDIA_TIME_PENDING, 0);
    value.PutString(AudioColumn::AUDIO_ALBUM, data->GetAlbum());
    value.PutString(AudioColumn::AUDIO_ARTIST, data->GetFileArtist());
    InsertDateAdded(data, value);
}

std::vector<NativeRdb::ValuesBucket> BaseRestore::GetAudioInsertValues(int32_t sceneCode,
    std::vector<FileInfo> &fileInfos)
{
    vector<NativeRdb::ValuesBucket> values;
    for (size_t i = 0; i < fileInfos.size(); i++) {
        if (!MediaFileUtils::IsFileExists(fileInfos[i].filePath)) {
            MEDIA_WARN_LOG("File is not exist, filePath = %{public}s.",
                BackupFileUtils::GarbleFilePath(fileInfos[i].filePath, sceneCode).c_str());
            UpdateFailedFiles(fileInfos[i].fileType, fileInfos[i].oldPath, RestoreError::FILE_INVALID);
            continue;
        }
        std::string cloudPath;
        int32_t uniqueId;
        {
            lock_guard<mutex> lock(audioMutex_);
            uniqueId = static_cast<int32_t>(audioNumber_);
            audioNumber_++;
        }
        int32_t errCode = BackupFileUtils::CreateAssetPathById(uniqueId, fileInfos[i].fileType,
            MediaFileUtils::GetExtensionFromPath(fileInfos[i].displayName), cloudPath);
        if (errCode != E_OK) {
            MEDIA_ERR_LOG("Create Asset Path failed, errCode=%{public}d", errCode);
            continue;
        }
        fileInfos[i].cloudPath = cloudPath;
        NativeRdb::ValuesBucket value = GetAudioInsertValue(fileInfos[i], cloudPath);
        SetAudioValueFromMetaData(fileInfos[i], value);
        if (sceneCode == DUAL_FRAME_CLONE_RESTORE_ID &&
            HasSameFile(mediaLibraryRdb_, AudioColumn::AUDIOS_TABLE, fileInfos[i])) {
            (void)MediaFileUtils::DeleteFile(fileInfos[i].filePath);
            MEDIA_WARN_LOG("File %{public}s already exists.",
                BackupFileUtils::GarbleFilePath(fileInfos[i].filePath, sceneCode).c_str());
            UpdateDuplicateNumber(fileInfos[i].fileType);
            continue;
        }
        values.emplace_back(value);
    }
    return values;
}

void BaseRestore::InsertAudio(int32_t sceneCode, std::vector<FileInfo> &fileInfos)
{
    if (mediaLibraryRdb_ == nullptr) {
        MEDIA_ERR_LOG("mediaLibraryRdb_ is null");
        return;
    }
    if (fileInfos.empty()) {
        MEDIA_ERR_LOG("fileInfos are empty");
        return;
    }
    int64_t startGenerate = MediaFileUtils::UTCTimeMilliSeconds();
    vector<NativeRdb::ValuesBucket> values = GetAudioInsertValues(sceneCode, fileInfos);
    int64_t startMove = MediaFileUtils::UTCTimeMilliSeconds();
    int32_t fileMoveCount = 0;
    for (size_t i = 0; i < fileInfos.size(); i++) {
        if (!MediaFileUtils::IsFileExists(fileInfos[i].filePath)) {
            continue;
        }
        std::string tmpPath = fileInfos[i].cloudPath;
        std::string localPath = tmpPath.replace(0, RESTORE_AUDIO_CLOUD_DIR.length(), RESTORE_AUDIO_LOCAL_DIR);
        if (!BackupFileUtils::MoveFile(fileInfos[i].filePath, localPath, sceneCode)) {
            MEDIA_ERR_LOG("MoveFile failed, filePath = %{public}s.",
                BackupFileUtils::GarbleFilePath(fileInfos[i].filePath, sceneCode).c_str());
            continue;
        }
        BackupFileUtils::ModifyFile(localPath, fileInfos[i].dateModified / MSEC_TO_SEC);
        fileMoveCount++;
    }
    migrateAudioFileNumber_ += fileMoveCount;
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();

    int64_t startInsert = MediaFileUtils::UTCTimeMilliSeconds();
    int64_t rowNum = 0;
    int32_t errCode = BatchInsertWithRetry(AudioColumn::AUDIOS_TABLE, values, rowNum);
    if (errCode != E_OK) {
        UpdateFailedFiles(fileInfos, RestoreError::INSERT_FAILED);
        return;
    }
    migrateAudioDatabaseNumber_ += rowNum;
    MEDIA_INFO_LOG("generate values cost %{public}ld, insert %{public}ld assets cost %{public}ld and move " \
        "%{public}ld file cost %{public}ld.", (long)(startInsert - startGenerate), (long)rowNum,
        (long)(startInsert - startMove), (long)fileMoveCount, (long)(end - startMove));
}

NativeRdb::ValuesBucket BaseRestore::GetAudioInsertValue(const FileInfo &fileInfo, const std::string &newPath) const
{
    NativeRdb::ValuesBucket value;
    value.PutString(MediaColumn::MEDIA_FILE_PATH, fileInfo.cloudPath);
    value.PutString(MediaColumn::MEDIA_NAME, fileInfo.displayName);
    value.PutInt(MediaColumn::MEDIA_IS_FAV, fileInfo.isFavorite);
    value.PutLong(MediaColumn::MEDIA_DATE_TRASHED, fileInfo.recycledTime);
    return value;
}

void BaseRestore::MoveMigrateFile(std::vector<FileInfo> &fileInfos, int32_t &fileMoveCount, int32_t &videoFileMoveCount,
    int32_t sceneCode)
{
    vector<std::string> moveFailedData;
    for (size_t i = 0; i < fileInfos.size(); i++) {
        if (!MediaFileUtils::IsFileExists(fileInfos[i].filePath)) {
            continue;
        }
        std::string tmpPath = fileInfos[i].cloudPath;
        std::string localPath = tmpPath.replace(0, RESTORE_CLOUD_DIR.length(), RESTORE_LOCAL_DIR);
        if (!BackupFileUtils::MoveFile(fileInfos[i].filePath, localPath, sceneCode)) {
            MEDIA_ERR_LOG("MoveFile failed, filePath = %{public}s, errno:%{public}s",
                BackupFileUtils::GarbleFilePath(fileInfos[i].filePath, sceneCode).c_str(), strerror(errno));
            UpdateFailedFiles(fileInfos[i].fileType, fileInfos[i].oldPath, RestoreError::MOVE_FAILED);
            moveFailedData.push_back(fileInfos[i].cloudPath);
            continue;
        }
        BackupFileUtils::ModifyFile(localPath, fileInfos[i].dateModified);
        fileMoveCount++;
        videoFileMoveCount += fileInfos[i].fileType == MediaType::MEDIA_TYPE_VIDEO;
    }
    DeleteMoveFailedData(moveFailedData);
    migrateFileNumber_ += fileMoveCount;
    migrateVideoFileNumber_ += videoFileMoveCount;
}

void BaseRestore::InsertPhoto(int32_t sceneCode, std::vector<FileInfo> &fileInfos, int32_t sourceType)
{
    MEDIA_INFO_LOG("Start insert %{public}zu photos", fileInfos.size());
    if (mediaLibraryRdb_ == nullptr) {
        MEDIA_ERR_LOG("mediaLibraryRdb_ is null");
        return;
    }
    if (fileInfos.empty()) {
        MEDIA_ERR_LOG("fileInfos are empty");
        return;
    }
    int64_t startGenerate = MediaFileUtils::UTCTimeMilliSeconds();
    vector<NativeRdb::ValuesBucket> values = GetInsertValues(sceneCode, fileInfos, sourceType);
    int64_t startInsert = MediaFileUtils::UTCTimeMilliSeconds();
    int64_t rowNum = 0;
    int32_t errCode = BatchInsertWithRetry(PhotoColumn::PHOTOS_TABLE, values, rowNum);
    if (errCode != E_OK) {
        UpdateFailedFiles(fileInfos, RestoreError::INSERT_FAILED);
        return;
    }

    int64_t startInsertRelated = MediaFileUtils::UTCTimeMilliSeconds();
    InsertPhotoRelated(fileInfos, sourceType);

    int64_t startMove = MediaFileUtils::UTCTimeMilliSeconds();
    migrateDatabaseNumber_ += rowNum;
    int32_t fileMoveCount = 0;
    int32_t videoFileMoveCount = 0;
    MoveMigrateFile(fileInfos, fileMoveCount, videoFileMoveCount, sceneCode);
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("generate values cost %{public}ld, insert %{public}ld assets cost %{public}ld, insert photo related"
        " cost %{public}ld, and move %{public}ld files (%{public}ld + %{public}ld) cost %{public}ld.",
        (long)(startInsert - startGenerate), (long)rowNum, (long)(startInsertRelated - startInsert),
        (long)(startMove - startInsertRelated), (long)fileMoveCount, (long)(fileMoveCount - videoFileMoveCount),
        (long)videoFileMoveCount, (long)(end - startMove));
}

void BaseRestore::DeleteMoveFailedData(std::vector<std::string> &moveFailedData)
{
    if (moveFailedData.empty()) {
        MEDIA_INFO_LOG("No move failed");
        return;
    }
    MEDIA_INFO_LOG("%{public}d file move failed", static_cast<int>(moveFailedData.size()));
    NativeRdb::AbsRdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.In(MediaColumn::MEDIA_FILE_PATH, moveFailedData);
    int32_t changedRows = 0;
    int deleteRes = BackupDatabaseUtils::Delete(predicates, changedRows, mediaLibraryRdb_);
    MEDIA_INFO_LOG("changeRows:%{public}d, deleteRes:%{public}d", changedRows, deleteRes);
}

int32_t BaseRestore::BatchInsertWithRetry(const std::string &tableName, std::vector<NativeRdb::ValuesBucket> &values,
    int64_t &rowNum)
{
    if (values.empty()) {
        return 0;
    }
    int32_t errCode = E_ERR;
    TransactionOperations transactionOprn(mediaLibraryRdb_);
    errCode = transactionOprn.Start(true);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("can not get rdb before batch insert");
        return errCode;
    }
    errCode = mediaLibraryRdb_->BatchInsert(rowNum, tableName, values);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("InsertSql failed, errCode: %{public}d, rowNum: %{public}ld.", errCode, (long)rowNum);
        return errCode;
    }
    transactionOprn.Finish();
    return errCode;
}

int32_t BaseRestore::MoveDirectory(const std::string &srcDir, const std::string &dstDir) const
{
    if (!MediaFileUtils::CreateDirectory(dstDir)) {
        MEDIA_ERR_LOG("Create dstDir %{private}s failed", dstDir.c_str());
        return E_FAIL;
    }
    for (const auto &dirEntry : std::filesystem::directory_iterator{ srcDir }) {
        std::string srcFilePath = dirEntry.path();
        std::string tmpFilePath = srcFilePath;
        std::string dstFilePath = tmpFilePath.replace(0, srcDir.length(), dstDir);
        if (MoveFile(srcFilePath, dstFilePath) != E_OK) {
            MEDIA_ERR_LOG("Move file from %{private}s to %{private}s failed", srcFilePath.c_str(), dstFilePath.c_str());
            return E_FAIL;
        }
    }
    return E_OK;
}

bool BaseRestore::IsSameFile(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore, const std::string &tableName,
    FileInfo &fileInfo)
{
    string srcPath = fileInfo.filePath;
    string dstPath = BackupFileUtils::GetFullPathByPrefixType(PrefixType::LOCAL, fileInfo.relativePath);
    struct stat srcStatInfo {};
    struct stat dstStatInfo {};

    if (access(dstPath.c_str(), F_OK)) {
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
    if ((srcStatInfo.st_size != dstStatInfo.st_size || srcStatInfo.st_mtime != dstStatInfo.st_mtime) &&
        !HasSameFile(rdbStore, tableName, fileInfo)) { /* file size & last modify time */
        MEDIA_INFO_LOG("Size (%{public}lld -> %{public}lld) or mtime (%{public}lld -> %{public}lld) differs",
            (long long)srcStatInfo.st_size, (long long)dstStatInfo.st_size, (long long)srcStatInfo.st_mtime,
            (long long)dstStatInfo.st_mtime);
        return false;
    }
    fileInfo.isNew = false;
    return true;
}

bool BaseRestore::HasSameFile(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore, const std::string &tableName,
    FileInfo &fileInfo)
{
    string querySql;
    if (tableName != PhotoColumn::PHOTOS_TABLE) {
        querySql = "SELECT " + MediaColumn::MEDIA_ID + ", " + MediaColumn::MEDIA_FILE_PATH + " FROM " +
            tableName + " WHERE " + MediaColumn::MEDIA_NAME + " = '" + fileInfo.displayName + "' AND " +
            MediaColumn::MEDIA_SIZE + " = " + to_string(fileInfo.fileSize) + " AND " +
            MediaColumn::MEDIA_DATE_MODIFIED + " = " + to_string(fileInfo.dateModified);
    } else {
        querySql = GetSameFileQuerySql(fileInfo);
    }
    querySql += " LIMIT 1";
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(rdbStore, querySql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return false;
    }
    int32_t fileId = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
    string cloudPath = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
    if (fileId <= 0 || cloudPath.empty()) {
        MEDIA_ERR_LOG("Get invalid fileId or cloudPath: %{public}d", fileId);
        return false;
    }
    fileInfo.fileIdNew = fileId;
    fileInfo.cloudPath = cloudPath;
    return true;
}

void BaseRestore::InsertPhotoMap(std::vector<FileInfo> &fileInfos, int64_t &mapRowNum)
{
    BatchInsertMap(fileInfos, mapRowNum);
    migrateDatabaseMapNumber_ += mapRowNum;
}

void BaseRestore::BatchQueryPhoto(vector<FileInfo> &fileInfos, bool isFull, const NeedQueryMap &needQueryMap)
{
    string querySql = "SELECT " + MediaColumn::MEDIA_ID + " , " + MediaColumn::MEDIA_FILE_PATH + " FROM " +
        PhotoColumn::PHOTOS_TABLE + " WHERE ";
    bool firstSql = false;
    std::vector<std::string> cloudPathArgs;
    for (auto &fileInfo : fileInfos) {
        if (!isFull && !NeedQuery(fileInfo, needQueryMap)) {
            continue;
        }
        if (firstSql) {
            querySql += " OR ";
        } else {
            firstSql = true;
        }
        querySql += MediaColumn::MEDIA_FILE_PATH + " = ? ";
        cloudPathArgs.push_back(fileInfo.cloudPath);
    }
    auto result = BackupDatabaseUtils::GetQueryResultSet(mediaLibraryRdb_, querySql, cloudPathArgs);
    if (result == nullptr) {
        MEDIA_ERR_LOG("Query resultSql is null.");
        return;
    }
    while (result->GoToNextRow() == NativeRdb::E_OK) {
        int32_t fileId = GetInt32Val(MediaColumn::MEDIA_ID, result);
        std::string path = GetStringVal(MediaColumn::MEDIA_FILE_PATH, result);
        auto pathMatch = [path {path}](const auto &fileInfo) {
            return fileInfo.cloudPath == path;
        };
        auto it = std::find_if(fileInfos.begin(), fileInfos.end(), pathMatch);
        if (it != fileInfos.end() && fileId > 0) {
            it->fileIdNew = fileId;
        }
    }
}

void BaseRestore::BatchInsertMap(const vector<FileInfo> &fileInfos, int64_t &totalRowNum)
{
    vector<NativeRdb::ValuesBucket> values;
    for (const auto &fileInfo : fileInfos) {
        if (!fileInfo.packageName.empty()) {
            // add for trigger insert_photo_insert_source_album
            continue;
        }
        if (fileInfo.cloudPath.empty() || fileInfo.mediaAlbumId <= 0 || fileInfo.fileIdNew <= 0) {
            MEDIA_ERR_LOG("AlbumMap error file name = %{public}s.", fileInfo.displayName.c_str());
            continue;
        }
        NativeRdb::ValuesBucket value;
        value.PutInt(PhotoMap::ASSET_ID, fileInfo.fileIdNew);
        value.PutInt(PhotoMap::ALBUM_ID, fileInfo.mediaAlbumId);
        values.emplace_back(value);
    }
    int64_t rowNum = 0;
    int32_t errCode = BatchInsertWithRetry(PhotoMap::TABLE, values, rowNum);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("Batch insert map failed, errCode: %{public}d", errCode);
    }
    totalRowNum += rowNum;
}

void BaseRestore::StartRestoreEx(const std::string &backupRetoreDir, const std::string &upgradePath,
    std::string &restoreExInfo)
{
    StartRestore(backupRetoreDir, upgradePath);
    restoreExInfo = GetRestoreExInfo();
}

std::string BaseRestore::GetRestoreExInfo()
{
    nlohmann::json restoreExInfoJson;
    restoreExInfoJson[STAT_KEY_RESULT_INFO] = { GetErrorInfoJson(), GetCountInfoJson(STAT_TYPES) };
    return restoreExInfoJson.dump();
}

nlohmann::json BaseRestore::GetErrorInfoJson()
{
    int32_t errorCode = errorCode_ == RestoreError::SUCCESS ? STAT_DEFAULT_ERROR_CODE_SUCCESS :
        STAT_DEFAULT_ERROR_CODE_FAILED;
    nlohmann::json errorInfoJson = {
        { STAT_KEY_TYPE, STAT_VALUE_ERROR_INFO },
        { STAT_KEY_ERROR_CODE, std::to_string(errorCode) },
        { STAT_KEY_ERROR_INFO, errorInfo_ }
    };
    return errorInfoJson;
}

nlohmann::json BaseRestore::GetCountInfoJson(const std::vector<std::string> &countInfoTypes)
{
    nlohmann::json countInfoJson;
    countInfoJson[STAT_KEY_TYPE] = STAT_VALUE_COUNT_INFO;
    for (const auto &type : countInfoTypes) {
        SubCountInfo subCountInfo = GetSubCountInfo(type);
        MEDIA_INFO_LOG("SubCountInfo %{public}s success: %{public}lld, duplicate: %{public}lld, failed: %{public}zu",
            type.c_str(), (long long)subCountInfo.successCount, (long long)subCountInfo.duplicateCount,
            subCountInfo.failedFiles.size());
        countInfoJson[STAT_KEY_INFOS].push_back(GetSubCountInfoJson(type, subCountInfo));
    }
    return countInfoJson;
}

SubCountInfo BaseRestore::GetSubCountInfo(const std::string &type)
{
    std::unordered_map<std::string, int32_t> failedFiles = GetFailedFiles(type);
    if (type == STAT_TYPE_PHOTO) {
        return SubCountInfo(migrateFileNumber_ - migrateVideoFileNumber_, migratePhotoDuplicateNumber_, failedFiles);
    }
    if (type == STAT_TYPE_VIDEO) {
        return SubCountInfo(migrateVideoFileNumber_, migrateVideoDuplicateNumber_, failedFiles);
    }
    return SubCountInfo(migrateAudioFileNumber_, migrateAudioDuplicateNumber_, failedFiles);
}

std::unordered_map<std::string, int32_t> BaseRestore::GetFailedFiles(const std::string &type)
{
    std::unordered_map<std::string, int32_t> failedFiles;
    auto iter = failedFilesMap_.find(type);
    if (iter != failedFilesMap_.end()) {
        return iter->second;
    }
    return failedFiles;
}

nlohmann::json BaseRestore::GetSubCountInfoJson(const std::string &type, const SubCountInfo &subCountInfo)
{
    nlohmann::json subCountInfoJson;
    subCountInfoJson[STAT_KEY_BACKUP_INFO] = type;
    subCountInfoJson[STAT_KEY_SUCCESS_COUNT] = subCountInfo.successCount;
    subCountInfoJson[STAT_KEY_DUPLICATE_COUNT] = subCountInfo.duplicateCount;
    subCountInfoJson[STAT_KEY_FAILED_COUNT] = subCountInfo.failedFiles.size();
    subCountInfoJson[STAT_KEY_DETAILS] = BackupFileUtils::GetDetailsPath(type, subCountInfo.failedFiles);
    return subCountInfoJson;
}

std::string BaseRestore::GetBackupInfo()
{
    return "";
}

void BaseRestore::SetErrorCode(int32_t errorCode)
{
    errorCode_ = errorCode;
    auto iter = RESTORE_ERROR_MAP.find(errorCode_);
    if (iter == RESTORE_ERROR_MAP.end()) {
        errorInfo_ = "";
        return;
    }
    errorInfo_ = iter->second;
}

void BaseRestore::UpdateFailedFileByFileType(int32_t fileType, const std::string &filePath, int32_t errorCode)
{
    std::lock_guard<mutex> lock(failedFilesMutex_);
    if (fileType == static_cast<int32_t>(MediaType::MEDIA_TYPE_IMAGE)) {
        failedFilesMap_[STAT_TYPE_PHOTO][filePath] = errorCode;
        return;
    }
    if (fileType == static_cast<int32_t>(MediaType::MEDIA_TYPE_VIDEO)) {
        failedFilesMap_[STAT_TYPE_VIDEO][filePath] = errorCode;
        return;
    }
    if (fileType == static_cast<int32_t>(MediaType::MEDIA_TYPE_AUDIO)) {
        failedFilesMap_[STAT_TYPE_AUDIO][filePath] = errorCode;
        return;
    }
    MEDIA_ERR_LOG("Unsupported file type: %{public}d", fileType);
}

void BaseRestore::UpdateFailedFiles(int32_t fileType, const std::string &filePath, int32_t errorCode)
{
    SetErrorCode(errorCode);
    std::string realPath = sceneCode_ != CLONE_RESTORE_ID ? filePath :
        BackupFileUtils::GetReplacedPathByPrefixType(PrefixType::CLOUD, PrefixType::LOCAL, filePath);
    UpdateFailedFileByFileType(fileType, realPath, errorCode);
}

void BaseRestore::UpdateFailedFiles(const std::vector<FileInfo> &fileInfos, int32_t errorCode)
{
    SetErrorCode(errorCode);
    for (const auto &fileInfo : fileInfos) {
        UpdateFailedFileByFileType(fileInfo.fileType, fileInfo.oldPath, errorCode);
    }
}

void BaseRestore::UpdateDuplicateNumber(int32_t fileType)
{
    if (fileType == static_cast<int32_t>(MediaType::MEDIA_TYPE_IMAGE)) {
        migratePhotoDuplicateNumber_++;
        return;
    }
    if (fileType == static_cast<int32_t>(MediaType::MEDIA_TYPE_VIDEO)) {
        migrateVideoDuplicateNumber_++;
        return;
    }
    if (fileType == static_cast<int32_t>(MediaType::MEDIA_TYPE_AUDIO)) {
        migrateAudioDuplicateNumber_++;
        return;
    }
    MEDIA_ERR_LOG("Unsupported file type: %{public}d", fileType);
}

void BaseRestore::SetParameterForClone()
{
    auto currentTime = to_string(MediaFileUtils::UTCTimeSeconds());
    MEDIA_INFO_LOG("SetParameterForClone currentTime:%{public}s", currentTime.c_str());
    bool retFlag = system::SetParameter(CLONE_FLAG, currentTime);
    if (!retFlag) {
        MEDIA_ERR_LOG("Failed to set parameter cloneFlag, retFlag:%{public}d", retFlag);
    }
}

void BaseRestore::StopParameterForClone(int32_t sceneCode)
{
    if (sceneCode == UPGRADE_RESTORE_ID) {
        return;
    }
    bool retFlag = system::SetParameter(CLONE_FLAG, "0");
    if (!retFlag) {
        MEDIA_ERR_LOG("Failed to set parameter cloneFlag, retFlag:%{public}d", retFlag);
    }
}

std::string BaseRestore::GetSameFileQuerySql(const FileInfo &fileInfo)
{
    std::string querySql = "SELECT P." + MediaColumn::MEDIA_ID + ", P." + MediaColumn::MEDIA_FILE_PATH;
    if (!fileInfo.packageName.empty() || !fileInfo.bundleName.empty()) {
        querySql += " FROM (SELECT file_id, size, orientation, data, date_added FROM Photos WHERE file_id <= " +
            to_string(maxFileId_) + " AND display_name = '" + fileInfo.displayName + "' LIMIT " +
            to_string(maxCount_) + ") AS P INNER JOIN PhotoMap AS PM ON P.file_id = PM.map_asset " +
            "INNER JOIN PhotoAlbum AS PA ON PA.album_id = PM.map_album AND PA.album_type = " +
            to_string(PhotoAlbumType::SOURCE) + " AND PA.album_subtype = " +
            to_string(PhotoAlbumSubType::SOURCE_GENERIC) + " WHERE P.size = " + to_string(fileInfo.fileSize) +
            " AND (((PA.bundle_name = '' OR PA.bundle_name is null ) AND PA.album_name = '" + fileInfo.packageName +
            "') OR (((PA.bundle_name != '' AND PA.bundle_name is not null) AND PA.bundle_name = '" +
            fileInfo.bundleName + "') OR PA.album_name = '" + fileInfo.packageName + "'))";
    } else {
        querySql += " FROM " + PhotoColumn::PHOTOS_TABLE + " AS P WHERE " + MediaColumn::MEDIA_ID + " <= " +
            to_string(maxFileId_) + " AND " + MediaColumn::MEDIA_NAME + " = '" + fileInfo.displayName + "' AND " +
            MediaColumn::MEDIA_SIZE + " = " + to_string(fileInfo.fileSize) + " AND NOT EXISTS (SELECT 1 FROM " +
            PhotoMap::TABLE + " AS PM INNER JOIN " + PhotoAlbumColumns::TABLE + " AS PA ON PM." + PhotoMap::ALBUM_ID +
            " = PA." + PhotoAlbumColumns::ALBUM_ID + " WHERE PA." + PhotoAlbumColumns::ALBUM_TYPE + " = " +
            to_string(PhotoAlbumType::SOURCE) + " AND PA." + PhotoAlbumColumns::ALBUM_SUBTYPE + " = " +
            to_string(PhotoAlbumSubType::SOURCE_GENERIC) + " AND PM." + PhotoMap::ASSET_ID + " = P." +
            MediaColumn::MEDIA_ID + ")";
    }
    if (fileInfo.fileType != MEDIA_TYPE_VIDEO) {
        querySql += " AND P.orientation = " + to_string(fileInfo.orientation);
    }
    querySql += " ORDER BY ABS(P." + MediaColumn::MEDIA_DATE_ADDED + " - " + to_string(fileInfo.dateAdded) + ")";
    return querySql;
}

void BaseRestore::InsertPhotoRelated(std::vector<FileInfo> &fileInfos, int32_t sourceType)
{
    if (sourceType != SourceType::GALLERY) {
        return;
    }
    NeedQueryMap needQueryMap;
    if (!NeedBatchQueryPhoto(fileInfos, needQueryMap)) {
        MEDIA_INFO_LOG("There is no need to batch query photo");
        return;
    }
    int64_t startQuery = MediaFileUtils::UTCTimeMilliSeconds();
    BatchQueryPhoto(fileInfos, false, needQueryMap);
    int64_t startInsertMap = MediaFileUtils::UTCTimeMilliSeconds();
    int64_t mapRowNum = 0;
    InsertPhotoMap(fileInfos, mapRowNum);
    int64_t startInsertPortrait = MediaFileUtils::UTCTimeMilliSeconds();
    int64_t faceRowNum = 0;
    int64_t portraitMapRowNum = 0;
    int64_t portraitPhotoNum = 0;
    InsertFaceAnalysisData(fileInfos, needQueryMap, faceRowNum, portraitMapRowNum, portraitPhotoNum);
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("query cost %{public}ld, insert %{public}ld maps cost %{public}ld, insert face analysis data of "
        "%{public}ld photos (%{public}ld faces + %{public}ld maps) cost %{public}ld",
        (long)(startInsertMap - startQuery), (long)mapRowNum, (long)(startInsertPortrait - startInsertMap),
        (long)portraitPhotoNum, (long)faceRowNum, (long)portraitMapRowNum, (long)(end - startInsertPortrait));
}

bool BaseRestore::NeedBatchQueryPhoto(const std::vector<FileInfo> &fileInfos, NeedQueryMap &needQueryMap)
{
    return NeedBatchQueryPhotoForPhotoMap(fileInfos, needQueryMap) ||
        NeedBatchQueryPhotoForPortrait(fileInfos, needQueryMap);
}

bool BaseRestore::NeedBatchQueryPhotoForPhotoMap(const std::vector<FileInfo> &fileInfos, NeedQueryMap &needQueryMap)
{
    std::unordered_set<std::string> needQuerySet;
    for (const auto &fileInfo : fileInfos) {
        if (!fileInfo.packageName.empty()) {
            continue;
        }
        if (fileInfo.cloudPath.empty() || fileInfo.mediaAlbumId <= 0) {
            MEDIA_ERR_LOG("Album error file name = %{public}s.", fileInfo.displayName.c_str());
            continue;
        }
        needQuerySet.insert(fileInfo.cloudPath);
    }
    if (needQuerySet.empty()) {
        return false;
    }
    needQueryMap[PhotoRelatedType::PHOTO_MAP] = needQuerySet;
    return true;
}

bool BaseRestore::NeedBatchQueryPhotoForPortrait(const std::vector<FileInfo> &fileInfos, NeedQueryMap &needQueryMap)
{
    return false;
}

bool BaseRestore::NeedQuery(const FileInfo &fileInfo, const NeedQueryMap &needQueryMap)
{
    for (auto iter = needQueryMap.begin(); iter != needQueryMap.end(); ++iter) {
        if (NeedQueryByPhotoRelatedType(fileInfo, iter->first, iter->second)) {
            return true;
        }
    }
    return false;
}

bool BaseRestore::NeedQueryByPhotoRelatedType(const FileInfo &fileInfo, PhotoRelatedType photoRelatedType,
    const std::unordered_set<std::string> &needQuerySet)
{
    std::string searchPath;
    switch (photoRelatedType) {
        case PhotoRelatedType::PHOTO_MAP: {
            searchPath = fileInfo.cloudPath;
            break;
        }
        case PhotoRelatedType::PORTRAIT: {
            searchPath = fileInfo.hashCode;
            break;
        }
        default:
            MEDIA_ERR_LOG("Unsupported photo related type: %{public}d", static_cast<int32_t>(photoRelatedType));
    }
    return !searchPath.empty() && needQuerySet.count(searchPath) > 0;
}

void BaseRestore::InsertFaceAnalysisData(const std::vector<FileInfo> &fileInfos, const NeedQueryMap &needQueryMap,
    int64_t &faceRowNum, int64_t &mapRowNum, int64_t &photoNum)
{
    return;
}

void BaseRestore::ReportPortraitStat(int32_t sceneCode)
{
    if (sceneCode != UPGRADE_RESTORE_ID) {
        return;
    }
    MEDIA_INFO_LOG("PortraitStat: album %{public}zu, photo %{public}lld, face %{public}lld, cost %{public}lld",
        portraitAlbumIdMap_.size(), (long long)migratePortraitPhotoNumber_, (long long)migratePortraitFaceNumber_,
        (long long)migratePortraitTotalTimeCost_);
    BackupDfxUtils::PostPortraitStat(static_cast<uint32_t>(portraitAlbumIdMap_.size()), migratePortraitPhotoNumber_,
        migratePortraitFaceNumber_, migratePortraitTotalTimeCost_);
}

void BaseRestore::UpdateFaceAnalysisStatus()
{
    if (portraitAlbumIdMap_.empty()) {
        MEDIA_INFO_LOG("There is no need to update face analysis status");
        return;
    }
    int64_t startUpdateGroupTag = MediaFileUtils::UTCTimeMilliSeconds();
    BackupDatabaseUtils::UpdateGroupTag(mediaLibraryRdb_, groupTagMap_);
    int64_t startUpdateTotal = MediaFileUtils::UTCTimeMilliSeconds();
    BackupDatabaseUtils::UpdateAnalysisTotalStatus(mediaLibraryRdb_);
    int64_t startUpdateFaceTag = MediaFileUtils::UTCTimeMilliSeconds();
    BackupDatabaseUtils::UpdateAnalysisFaceTagStatus(mediaLibraryRdb_);
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("Update group tag cost %{public}lld, update total table cost %{public}lld, update face tag table "
        "cost %{public}lld", (long long)(startUpdateTotal - startUpdateGroupTag),
        (long long)(startUpdateFaceTag - startUpdateTotal), (long long)(end - startUpdateFaceTag));
    migratePortraitTotalTimeCost_ += end - startUpdateGroupTag;
}
} // namespace Media
} // namespace OHOS
