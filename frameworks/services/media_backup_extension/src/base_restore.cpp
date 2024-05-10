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
#include "medialibrary_notify.h"

namespace OHOS {
namespace Media {
const std::string DATABASE_PATH = "/data/storage/el2/database/rdb/media_library.db";
const std::string singleDirName = "A";

void BaseRestore::StartRestore(const std::string &backupRetoreDir, const std::string &upgradePath)
{
    int32_t errorCode = Init(backupRetoreDir, upgradePath, true);
    if (errorCode == E_OK) {
        RestorePhoto();
        RestoreAudio();
        MEDIA_INFO_LOG("migrate database number: %{public}lld, file number: %{public}lld," \
            "audio database number:%{public}lld, audio file number:%{public}lld",
            (long long) migrateDatabaseNumber_, (long long) migrateFileNumber_,
            (long long) migrateAudioDatabaseNumber_, (long long) migrateAudioFileNumber_);
        std::unordered_map<int32_t, int32_t>  updateResult;
        MediaLibraryRdbUtils::UpdateAllAlbums(mediaLibraryRdb_, updateResult);
        MediaLibraryRdbUtils::UpdateSourceAlbumInternal(mediaLibraryRdb_, updateResult);
        BackupDatabaseUtils::UpdateUniqueNumber(mediaLibraryRdb_, imageNumber_, IMAGE_ASSET_TYPE);
        BackupDatabaseUtils::UpdateUniqueNumber(mediaLibraryRdb_, videoNumber_, VIDEO_ASSET_TYPE);
        BackupDatabaseUtils::UpdateUniqueNumber(mediaLibraryRdb_, audioNumber_, AUDIO_ASSET_TYPE);
        auto watch = MediaLibraryNotify::GetInstance();
        if (watch == nullptr) {
            MEDIA_ERR_LOG("Can not get MediaLibraryNotify Instance");
            return;
        }
        watch->Notify(PhotoColumn::DEFAULT_PHOTO_URI, NotifyType::NOTIFY_ADD);
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
    int32_t err = BackupDatabaseUtils::InitDb(mediaLibraryRdb_, MEDIA_DATA_ABILITY_DB_NAME, DATABASE_PATH, BUNDLE_NAME,
        true, context->GetArea());
    if (err != E_OK) {
        MEDIA_ERR_LOG("medialibrary rdb fail, err = %{public}d", err);
        return E_FAIL;
    }
    int32_t errCode = MediaLibraryDataManager::GetInstance()->InitMediaLibraryMgr(context, nullptr);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("When restore, InitMediaLibraryMgr fail, errcode = %{public}d", errCode);
        return errCode;
    }
    migrateDatabaseNumber_ = 0;
    migrateFileNumber_ = 0;
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
        if (!MediaFileUtils::IsFileExists(fileInfos[i].filePath)) {
            MEDIA_WARN_LOG("File is not exist, filePath = %{public}s.",
                BackupFileUtils::GarbleFilePath(fileInfos[i].filePath, sceneCode).c_str());
            continue;
        }
        std::string cloudPath;
        int32_t uniqueId;
        if (fileInfos[i].fileType == MediaType::MEDIA_TYPE_IMAGE) {
            uniqueId = imageNumber_;
            imageNumber_++;
        } else {
            uniqueId = videoNumber_;
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
            continue;
        }
        std::string cloudPath;
        int32_t uniqueId = audioNumber_;
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
            continue;
        }
        audioNumber_++;
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
        if (!BackupFileUtils::MoveFile(fileInfos[i].filePath, localPath, sceneCode)) {
            MEDIA_ERR_LOG("MoveFile failed, filePath = %{public}s.",
                BackupFileUtils::GarbleFilePath(fileInfos[i].filePath, sceneCode).c_str());
            continue;
        }
        BackupFileUtils::ModifyFile(localPath, fileInfos[i].dateModified);
        fileMoveCount++;
    }
    migrateFileNumber_ += fileMoveCount;
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("generate values cost %{public}ld, insert %{public}ld assets cost %{public}ld and move " \
        "%{public}ld file cost %{public}ld.", (long)(startInsert - startGenerate), (long)rowNum,
        (long)(startMove - startInsert), (long)fileMoveCount, (long)(end - startMove));
}

int32_t BaseRestore::BatchInsertWithRetry(const std::string &tableName, std::vector<NativeRdb::ValuesBucket> &values,
    int64_t &rowNum)
{
    if (values.empty()) {
        return 0;
    }
    int32_t errCode = E_ERR;
    TransactionOperations transactionOprn(mediaLibraryRdb_);
    errCode = transactionOprn.Start();
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
    string querySql = "SELECT " + MediaColumn::MEDIA_ID + ", " + MediaColumn::MEDIA_FILE_PATH + " FROM " +
        tableName + " WHERE " + MediaColumn::MEDIA_NAME + " = '" + fileInfo.displayName + "' AND " +
        MediaColumn::MEDIA_SIZE + " = " + to_string(fileInfo.fileSize) + " AND " +
        MediaColumn::MEDIA_DATE_MODIFIED + " = " + to_string(fileInfo.dateModified);
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
} // namespace Media
} // namespace OHOS
