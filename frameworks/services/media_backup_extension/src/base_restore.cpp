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
#include "directory_ex.h"
#include "extension_context.h"
#include "media_column.h"
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
#include "moving_photo_file_utils.h"
#include "parameters.h"
#include "photo_album_column.h"
#include "result_set_utils.h"
#include "resource_type.h"
#include "userfilemgr_uri.h"
#include "medialibrary_notify.h"
#include "upgrade_restore_task_report.h"
#include "medialibrary_rdb_transaction.h"

namespace OHOS {
namespace Media {
const std::string DATABASE_PATH = "/data/storage/el2/database/rdb/media_library.db";
const std::string singleDirName = "A";
const std::string CLONE_FLAG = "multimedia.medialibrary.cloneFlag";
const int32_t UNIQUEID_OFFSET_CLONE = 10000000;
const int32_t UNIQUEID_OFFSET_UPGRADE = 20000000;

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
        UpdateDatabase();
    } else {
        if (errorCode != EXTERNAL_DB_NOT_EXIST) {
            SetErrorCode(RestoreError::INIT_FAILED);
        }
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
    int32_t sceneCode = 0;
    int32_t errCode = MediaLibraryDataManager::GetInstance()->InitMediaLibraryMgr(context, nullptr, sceneCode, false);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("When restore, InitMediaLibraryMgr fail, errcode = %{public}d", errCode);
        return errCode;
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
    if (this->CopyFile(srcFile, dstFile) != E_OK) {
        return E_FAIL;
    }
    (void)MediaFileUtils::DeleteFile(srcFile);
    return E_OK;
}

int32_t BaseRestore::CopyFile(const std::string &srcFile, const std::string &dstFile) const
{
    if (!MediaFileUtils::CopyFileUtil(srcFile, dstFile)) {
        MEDIA_ERR_LOG("CopyFile failed, filePath: %{private}s, errmsg: %{public}s", srcFile.c_str(),
            strerror(errno));
        return E_FAIL;
    }
    return E_OK;
}

int32_t BaseRestore::IsFileValid(FileInfo &fileInfo, const int32_t sceneCode)
{
    int32_t errCode = BackupFileUtils::IsFileValid(fileInfo.filePath, DUAL_FRAME_CLONE_RESTORE_ID,
        fileInfo.relativePath, hasLowQualityImage_);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("File is not valid: %{public}s, errno=%{public}d.",
            BackupFileUtils::GarbleFilePath(fileInfo.filePath, sceneCode).c_str(), errno);
        return errCode;
    }

    if (BackupFileUtils::IsLivePhoto(fileInfo)) {
        errCode = MediaFileUtils::IsFileValid(fileInfo.movingPhotoVideoPath);
        if (errCode != E_OK) {
            MEDIA_ERR_LOG("Moving photo video is not valid: %{public}s, errno=%{public}d.",
                BackupFileUtils::GarbleFilePath(fileInfo.movingPhotoVideoPath, sceneCode).c_str(), errno);
            return errCode;
        }

        errCode = MediaFileUtils::IsFileValid(fileInfo.extraDataPath);
        if (errCode != E_OK) {
            MEDIA_WARN_LOG("Media extra data is not valid: %{public}s, errno=%{public}d.",
                BackupFileUtils::GarbleFilePath(fileInfo.extraDataPath, sceneCode).c_str(), errno);
            return errCode;
        }
    }
    return E_OK;
}

static void RemoveDuplicateDualCloneFiles(const FileInfo &fileInfo)
{
    (void)MediaFileUtils::DeleteFile(fileInfo.filePath);
    if (BackupFileUtils::IsLivePhoto(fileInfo)) {
        (void)MediaFileUtils::DeleteFile(fileInfo.movingPhotoVideoPath);
        (void)MediaFileUtils::DeleteFile(fileInfo.extraDataPath);
    }
}

vector<NativeRdb::ValuesBucket> BaseRestore::GetInsertValues(const int32_t sceneCode, std::vector<FileInfo> &fileInfos,
    int32_t sourceType)
{
    vector<NativeRdb::ValuesBucket> values;
    for (size_t i = 0; i < fileInfos.size(); i++) {
        int32_t errCode = IsFileValid(fileInfos[i], sceneCode);
        if (errCode != E_OK) {
            fileInfos[i].needMove = false;
            MEDIA_ERR_LOG("File is invalid: sceneCode: %{public}d, sourceType: %{public}d, filePath: %{public}s, "
                "size: %{public}lld",
                sceneCode,
                sourceType,
                BackupFileUtils::GarbleFilePath(fileInfos[i].filePath, sceneCode).c_str(),
                (long long)fileInfos[i].fileSize);
            CheckInvalidFile(fileInfos[i], errCode);
            continue;
        }
        std::string cloudPath;
        int32_t uniqueId = GetUniqueId(fileInfos[i].fileType);
        errCode = BackupFileUtils::CreateAssetPathById(uniqueId, fileInfos[i].fileType,
            MediaFileUtils::GetExtensionFromPath(fileInfos[i].displayName), cloudPath);
        if (errCode != E_OK) {
            fileInfos[i].needMove = false;
            MEDIA_ERR_LOG("Create Asset Path failed, errCode=%{public}d, path: %{public}s", errCode,
                BackupFileUtils::GarbleFilePath(fileInfos[i].filePath, sceneCode).c_str());
            continue;
        }
        fileInfos[i].cloudPath = cloudPath;
        NativeRdb::ValuesBucket value = GetInsertValue(fileInfos[i], cloudPath, sourceType);
        SetValueFromMetaData(fileInfos[i], value);
        if ((sceneCode == DUAL_FRAME_CLONE_RESTORE_ID || sceneCode == OTHERS_PHONE_CLONE_RESTORE ||
            sceneCode == I_PHONE_CLONE_RESTORE) && this->HasSameFileForDualClone(fileInfos[i])) {
            fileInfos[i].needMove = false;
            RemoveDuplicateDualCloneFiles(fileInfos[i]);
            MEDIA_WARN_LOG("File %{public}s already exists.",
                BackupFileUtils::GarbleFilePath(fileInfos[i].filePath, sceneCode).c_str());
            UpdateDuplicateNumber(fileInfos[i].fileType);
            continue;
        }
        values.emplace_back(value);
    }
    return values;
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
        } else {
            dateAdded = dateModified;
        }
    } else {
        dateAdded = dateTaken;
    }
    value.PutLong(MediaColumn::MEDIA_DATE_ADDED, dateAdded);
}

static void InsertOrientation(std::unique_ptr<Metadata> &metadata, NativeRdb::ValuesBucket &value,
    FileInfo &fileInfo, int32_t sceneCode)
{
    bool hasOrientation = value.HasColumn(PhotoColumn::PHOTO_ORIENTATION);
    if (hasOrientation && fileInfo.fileType != MEDIA_TYPE_VIDEO) {
        return; // image use orientation in rdb
    }
    if (hasOrientation) {
        value.Delete(PhotoColumn::PHOTO_ORIENTATION);
    }
    value.PutInt(PhotoColumn::PHOTO_ORIENTATION, metadata->GetOrientation()); // video use orientation in metadata
    if (sceneCode == OTHERS_PHONE_CLONE_RESTORE || sceneCode == I_PHONE_CLONE_RESTORE) {
        fileInfo.orientation = metadata->GetOrientation();
    }
}

static void SetCoverPosition(const FileInfo &fileInfo,
    const unique_ptr<Metadata> &imageMetaData, NativeRdb::ValuesBucket &value)
{
    uint64_t coverPosition = 0;
    if (BackupFileUtils::IsLivePhoto(fileInfo)) {
        uint32_t version = 0;
        uint32_t frameIndex = 0;
        bool hasCinemagraphInfo = false;
        string absExtraDataPath;
        if (!PathToRealPath(fileInfo.extraDataPath, absExtraDataPath)) {
            MEDIA_ERR_LOG("file is not real path: %{private}s, errno: %{public}d",
                fileInfo.extraDataPath.c_str(), errno);
            value.PutLong(PhotoColumn::PHOTO_COVER_POSITION, static_cast<int64_t>(coverPosition));
            return;
        }
        UniqueFd extraDataFd(open(absExtraDataPath.c_str(), O_RDONLY));
        (void)MovingPhotoFileUtils::GetVersionAndFrameNum(extraDataFd.Get(), version, frameIndex, hasCinemagraphInfo);
        (void)MovingPhotoFileUtils::GetCoverPosition(fileInfo.movingPhotoVideoPath,
            frameIndex, coverPosition, Scene::AV_META_SCENE_CLONE);
    }
    value.PutLong(PhotoColumn::PHOTO_COVER_POSITION, static_cast<int64_t>(coverPosition));
}

void BaseRestore::SetValueFromMetaData(FileInfo &fileInfo, NativeRdb::ValuesBucket &value)
{
    std::unique_ptr<Metadata> data = make_unique<Metadata>();
    data->SetFilePath(fileInfo.filePath);
    data->SetFileMediaType(fileInfo.fileType);
    data->SetFileDateModified(fileInfo.dateModified);
    data->SetFileName(fileInfo.displayName);
    BackupFileUtils::FillMetadata(data);
    MediaType mediaType = data->GetFileMediaType();

    value.PutString(MediaColumn::MEDIA_FILE_PATH, data->GetFilePath());
    value.PutString(MediaColumn::MEDIA_MIME_TYPE, data->GetFileMimeType());
    value.PutInt(MediaColumn::MEDIA_TYPE, mediaType);
    value.PutString(MediaColumn::MEDIA_TITLE, data->GetFileTitle());
    if (fileInfo.fileSize != 0) {
        value.PutLong(MediaColumn::MEDIA_SIZE, fileInfo.fileSize);
    } else {
        MEDIA_WARN_LOG("DB file size is zero!");
        value.PutLong(MediaColumn::MEDIA_SIZE, data->GetFileSize());
        fileInfo.fileSize = data->GetFileSize();
    }
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
    value.PutInt(PhotoColumn::PHOTO_DYNAMIC_RANGE_TYPE, data->GetDynamicRangeType());
    InsertDateAdded(data, value);
    InsertOrientation(data, value, fileInfo, sceneCode_);
    int64_t dateAdded = 0;
    NativeRdb::ValueObject valueObject;
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
    SetCoverPosition(fileInfo, data, value);
}

void BaseRestore::CreateDir(std::string &dir)
{
    if (!MediaFileUtils::IsFileExists(dir)) {
        MediaFileUtils::CreateDirectory(dir);
    }
}

void BaseRestore::RecursiveCreateDir(std::string &relativePath, std::string &suffix)
{
    CreateDir(relativePath);
    size_t pos = suffix.find('/');
    if (pos == std::string::npos) {
        return;
    }
    std::string prefix = suffix.substr(0, pos + 1);
    std::string suffixTmp = suffix.erase(0, prefix.length());
    prefix = relativePath + prefix;
    RecursiveCreateDir(prefix, suffixTmp);
}

void BaseRestore::InsertAudio(int32_t sceneCode, std::vector<FileInfo> &fileInfos)
{
    if (fileInfos.empty()) {
        MEDIA_ERR_LOG("fileInfos are empty");
        return;
    }
    int64_t startMove = MediaFileUtils::UTCTimeMilliSeconds();
    int32_t fileMoveCount = 0;
    for (size_t i = 0; i < fileInfos.size(); i++) {
        if (!MediaFileUtils::IsFileExists(fileInfos[i].filePath)) {
            MEDIA_ERR_LOG("File is not exist: filePath: %{public}s, size: %{public}lld",
                BackupFileUtils::GarbleFilePath(fileInfos[i].filePath, sceneCode).c_str(),
                (long long)fileInfos[i].fileSize);
            continue;
        }
        string relativePath0 = RESTORE_MUSIC_LOCAL_DIR;
        string relativePath1 = fileInfos[i].relativePath;
        if (relativePath1[0] == '/') {
            relativePath1.erase(0, 1);
        }
        string dstPath = RESTORE_MUSIC_LOCAL_DIR + relativePath1;
        RecursiveCreateDir(relativePath0, relativePath1);
        if (MediaFileUtils::IsFileExists(dstPath)) {
            MEDIA_INFO_LOG("dstPath %{public}s already exists.",
                BackupFileUtils::GarbleFilePath(fileInfos[i].filePath, sceneCode).c_str());
            UpdateDuplicateNumber(fileInfos[i].fileType);
            continue;
        }
        int32_t moveErrCode = BackupFileUtils::MoveFile(fileInfos[i].filePath, dstPath, sceneCode);
        if (moveErrCode != E_SUCCESS) {
            MEDIA_ERR_LOG("MoveFile failed, filePath: %{public}s, errCode: %{public}d, errno: %{public}d",
                BackupFileUtils::GarbleFilePath(fileInfos[i].filePath, sceneCode).c_str(), moveErrCode, errno);
            UpdateFailedFiles(fileInfos[i].fileType, fileInfos[i], RestoreError::MOVE_FAILED);
            continue;
        }
        BackupFileUtils::ModifyFile(dstPath, fileInfos[i].dateModified / MSEC_TO_SEC);
        fileMoveCount++;
    }
    migrateAudioFileNumber_ += fileMoveCount;
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("move %{public}ld file cost %{public}ld.", (long)fileMoveCount, (long)(end - startMove));
}

static bool MoveExtraData(const FileInfo &fileInfo, int32_t sceneCode)
{
    string localExtraDataDir = BackupFileUtils::GetReplacedPathByPrefixType(
        PrefixType::CLOUD, PrefixType::LOCAL, MovingPhotoFileUtils::GetMovingPhotoExtraDataDir(fileInfo.cloudPath));
    if (localExtraDataDir.empty()) {
        MEDIA_WARN_LOG("Failed to get local extra data dir");
        return false;
    }
    if (!MediaFileUtils::IsFileExists(localExtraDataDir) && !MediaFileUtils::CreateDirectory(localExtraDataDir)) {
        MEDIA_WARN_LOG("Failed to create local extra data dir, errno:%{public}d", errno);
        return false;
    }

    string localExtraDataPath = BackupFileUtils::GetReplacedPathByPrefixType(
        PrefixType::CLOUD, PrefixType::LOCAL, MovingPhotoFileUtils::GetMovingPhotoExtraDataPath(fileInfo.cloudPath));
    if (localExtraDataPath.empty()) {
        MEDIA_WARN_LOG("Failed to get local extra data path");
        return false;
    }
    int32_t errCode = BackupFileUtils::MoveFile(fileInfo.extraDataPath, localExtraDataPath, sceneCode);
    if (errCode != E_OK) {
        MEDIA_WARN_LOG("MoveFile failed, src:%{public}s, dest:%{public}s, err:%{public}d, errno:%{public}d",
            BackupFileUtils::GarbleFilePath(fileInfo.extraDataPath, sceneCode).c_str(),
            BackupFileUtils::GarbleFilePath(localExtraDataPath, sceneCode).c_str(), errCode, errno);
        return false;
    }
    return true;
}

static bool MoveAndModifyFile(const FileInfo &fileInfo, int32_t sceneCode)
{
    string tmpPath = fileInfo.cloudPath;
    string localPath = tmpPath.replace(0, RESTORE_CLOUD_DIR.length(), RESTORE_LOCAL_DIR);
    int32_t errCode = BackupFileUtils::MoveFile(fileInfo.filePath, localPath, sceneCode);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("MoveFile failed, src:%{public}s, dest:%{public}s, err:%{public}d, errno:%{public}d",
            BackupFileUtils::GarbleFilePath(fileInfo.filePath, sceneCode).c_str(),
            BackupFileUtils::GarbleFilePath(localPath, sceneCode).c_str(), errCode, errno);
        return false;
    }
    BackupFileUtils::ModifyFile(localPath, fileInfo.dateModified / MSEC_TO_SEC);

    if (BackupFileUtils::IsLivePhoto(fileInfo)) {
        string tmpVideoPath = MovingPhotoFileUtils::GetMovingPhotoVideoPath(fileInfo.cloudPath);
        string localVideoPath = tmpVideoPath.replace(0, RESTORE_CLOUD_DIR.length(), RESTORE_LOCAL_DIR);
        errCode = BackupFileUtils::MoveFile(fileInfo.movingPhotoVideoPath, localVideoPath, sceneCode);
        if (errCode != E_OK) {
            MEDIA_ERR_LOG(
                "MoveFile failed for mov video, src:%{public}s, dest:%{public}s, err:%{public}d, errno:%{public}d",
                BackupFileUtils::GarbleFilePath(fileInfo.movingPhotoVideoPath, sceneCode).c_str(),
                BackupFileUtils::GarbleFilePath(localVideoPath, sceneCode).c_str(), errCode, errno);
            (void)MediaFileUtils::DeleteFile(localPath);
            return false;
        }
        BackupFileUtils::ModifyFile(localVideoPath, fileInfo.dateModified / MSEC_TO_SEC);
        return MoveExtraData(fileInfo, sceneCode);
    }
    return true;
}

void BaseRestore::MoveMigrateFile(std::vector<FileInfo> &fileInfos, int32_t &fileMoveCount, int32_t &videoFileMoveCount,
    int32_t sceneCode)
{
    vector<std::string> moveFailedData;
    for (size_t i = 0; i < fileInfos.size(); i++) {
        if (!fileInfos[i].needMove) {
            continue;
        }
        if (IsFileValid(fileInfos[i], sceneCode) != E_OK) {
            continue;
        }
        if (!MoveAndModifyFile(fileInfos[i], sceneCode)) {
            UpdateFailedFiles(fileInfos[i].fileType, fileInfos[i], RestoreError::MOVE_FAILED);
            moveFailedData.push_back(fileInfos[i].cloudPath);
            continue;
        }
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
    this->tabOldPhotosRestore_.Restore(this->mediaLibraryRdb_, fileInfos);
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
    TransactionOperations trans{ __func__ };
    trans.SetBackupRdbStore(mediaLibraryRdb_);
    std::function<int(void)> func = [&]()->int {
        errCode = trans.BatchInsert(rowNum, tableName, values);
        if (errCode != E_OK) {
            MEDIA_ERR_LOG("InsertSql failed, errCode: %{public}d, rowNum: %{public}ld.", errCode, (long)rowNum);
        }
        return errCode;
    };
    errCode = trans.RetryTrans(func, true);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("BatchInsertWithRetry: tans finish fail!, ret:%{public}d", errCode);
    }
    return errCode;
}

int32_t BaseRestore::MoveDirectory(const std::string &srcDir, const std::string &dstDir, bool deleteOriginalFile) const
{
    if (!MediaFileUtils::CreateDirectory(dstDir)) {
        MEDIA_ERR_LOG("Create dstDir %{public}s failed",
            BackupFileUtils::GarbleFilePath(dstDir, DEFAULT_RESTORE_ID).c_str());
        return E_FAIL;
    }
    if (!MediaFileUtils::IsFileExists(srcDir)) {
        MEDIA_WARN_LOG("%{public}s doesn't exist, skip.", srcDir.c_str());
        return E_OK;
    }
    for (const auto &dirEntry : std::filesystem::directory_iterator{ srcDir }) {
        std::string srcFilePath = dirEntry.path();
        std::string tmpFilePath = srcFilePath;
        std::string dstFilePath = tmpFilePath.replace(0, srcDir.length(), dstDir);
        int32_t opRet = E_FAIL;
        if (deleteOriginalFile) {
            opRet = this->MoveFile(srcFilePath, dstFilePath);
        } else {
            opRet = this->CopyFile(srcFilePath, dstFilePath);
        }
        if (opRet != E_OK) {
            MEDIA_ERR_LOG("Move file from %{public}s to %{public}s failed, deleteOriginalFile=%{public}d",
                BackupFileUtils::GarbleFilePath(srcFilePath, sceneCode_).c_str(),
                BackupFileUtils::GarbleFilePath(dstFilePath, DEFAULT_RESTORE_ID).c_str(),
                deleteOriginalFile);
            return E_FAIL;
        }
    }
    return E_OK;
}

bool BaseRestore::IsSameAudioFile(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore, const std::string &tableName,
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
        !HasSameAudioFile(rdbStore, tableName, fileInfo)) { /* file size & last modify time */
        MEDIA_INFO_LOG("Size (%{public}lld -> %{public}lld) or mtime (%{public}lld -> %{public}lld) differs",
            (long long)srcStatInfo.st_size, (long long)dstStatInfo.st_size, (long long)srcStatInfo.st_mtime,
            (long long)dstStatInfo.st_mtime);
        return false;
    }
    fileInfo.isNew = false;
    return true;
}

bool BaseRestore::HasSameAudioFile(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore, const std::string &tableName,
    FileInfo &fileInfo)
{
    string querySql = "SELECT " + MediaColumn::MEDIA_ID + ", " + MediaColumn::MEDIA_FILE_PATH + " FROM " +
        tableName + " WHERE " + MediaColumn::MEDIA_NAME + " = '" + fileInfo.displayName + "' AND " +
        MediaColumn::MEDIA_SIZE + " = " + to_string(fileInfo.fileSize) + " AND " +
        MediaColumn::MEDIA_DATE_MODIFIED + " = " + to_string(fileInfo.dateModified);
    querySql += " LIMIT 1";
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(rdbStore, querySql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return false;
    }
    int32_t fileId = GetInt32Val(MediaColumn::MEDIA_ID, resultSet);
    string cloudPath = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
    if (fileId <= 0 || cloudPath.empty()) {
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
    UpgradeRestoreTaskReport().SetSceneCode(this->sceneCode_).SetTaskId(this->taskId_).Report(restoreExInfo);
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
    size_t limit = MAX_FAILED_FILES_LIMIT;
    for (const auto &type : countInfoTypes) {
        SubCountInfo subCountInfo = GetSubCountInfo(type);
        MEDIA_INFO_LOG("SubCountInfo %{public}s success: %{public}lld, duplicate: %{public}lld, failed: %{public}zu",
            type.c_str(), (long long)subCountInfo.successCount, (long long)subCountInfo.duplicateCount,
            subCountInfo.failedFiles.size());
        countInfoJson[STAT_KEY_INFOS].push_back(GetSubCountInfoJson(type, subCountInfo, limit));
    }
    return countInfoJson;
}

SubCountInfo BaseRestore::GetSubCountInfo(const std::string &type)
{
    std::unordered_map<std::string, FailedFileInfo> failedFiles = GetFailedFiles(type);
    if (type == STAT_TYPE_PHOTO) {
        return SubCountInfo(migrateFileNumber_ - migrateVideoFileNumber_, migratePhotoDuplicateNumber_, failedFiles);
    }
    if (type == STAT_TYPE_VIDEO) {
        return SubCountInfo(migrateVideoFileNumber_, migrateVideoDuplicateNumber_, failedFiles);
    }
    return SubCountInfo(migrateAudioFileNumber_, migrateAudioDuplicateNumber_, failedFiles);
}

std::unordered_map<std::string, FailedFileInfo> BaseRestore::GetFailedFiles(const std::string &type)
{
    std::lock_guard<mutex> lock(failedFilesMutex_);
    std::unordered_map<std::string, FailedFileInfo> failedFiles;
    auto iter = failedFilesMap_.find(type);
    if (iter != failedFilesMap_.end()) {
        return iter->second;
    }
    return failedFiles;
}

nlohmann::json BaseRestore::GetSubCountInfoJson(const std::string &type, const SubCountInfo &subCountInfo,
    size_t &limit)
{
    nlohmann::json subCountInfoJson;
    subCountInfoJson[STAT_KEY_BACKUP_INFO] = type;
    subCountInfoJson[STAT_KEY_SUCCESS_COUNT] = subCountInfo.successCount;
    subCountInfoJson[STAT_KEY_DUPLICATE_COUNT] = subCountInfo.duplicateCount;
    subCountInfoJson[STAT_KEY_FAILED_COUNT] = subCountInfo.failedFiles.size();
    // update currentLimit = min(limit, failedFiles.size())
    size_t currentLimit = limit <= subCountInfo.failedFiles.size() ? limit : subCountInfo.failedFiles.size();
    std::string detailsPath;
    std::vector<std::string> failedFilesList;
    if (sceneCode_ == UPGRADE_RESTORE_ID) {
        detailsPath = BackupFileUtils::GetDetailsPath(sceneCode_, type, subCountInfo.failedFiles, currentLimit);
        subCountInfoJson[STAT_KEY_DETAILS] = detailsPath;
    } else {
        failedFilesList = BackupFileUtils::GetFailedFilesList(sceneCode_, subCountInfo.failedFiles, currentLimit);
        subCountInfoJson[STAT_KEY_DETAILS] = failedFilesList;
    }
    MEDIA_INFO_LOG("Get %{public}s details size: %{public}zu", type.c_str(), currentLimit);
    limit -= currentLimit; // update total limit
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

void BaseRestore::UpdateFailedFileByFileType(int32_t fileType, const FileInfo &fileInfo, int32_t errorCode)
{
    std::lock_guard<mutex> lock(failedFilesMutex_);
    FailedFileInfo failedFileInfo(sceneCode_, fileInfo, errorCode);
    if (fileType == static_cast<int32_t>(MediaType::MEDIA_TYPE_IMAGE)) {
        failedFilesMap_[STAT_TYPE_PHOTO].emplace(fileInfo.oldPath, failedFileInfo);
        return;
    }
    if (fileType == static_cast<int32_t>(MediaType::MEDIA_TYPE_VIDEO)) {
        failedFilesMap_[STAT_TYPE_VIDEO].emplace(fileInfo.oldPath, failedFileInfo);
        return;
    }
    if (fileType == static_cast<int32_t>(MediaType::MEDIA_TYPE_AUDIO)) {
        failedFilesMap_[STAT_TYPE_AUDIO].emplace(fileInfo.oldPath, failedFileInfo);
        return;
    }
    MEDIA_ERR_LOG("Unsupported file type: %{public}d", fileType);
}

void BaseRestore::UpdateFailedFiles(int32_t fileType, const FileInfo &fileInfo, int32_t errorCode)
{
    SetErrorCode(errorCode);
    UpdateFailedFileByFileType(fileType, fileInfo, errorCode);
}

void BaseRestore::UpdateFailedFiles(const std::vector<FileInfo> &fileInfos, int32_t errorCode)
{
    SetErrorCode(errorCode);
    for (const auto &fileInfo : fileInfos) {
        UpdateFailedFileByFileType(fileInfo.fileType, fileInfo, errorCode);
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
    bool retFlag = system::SetParameter(CLONE_FLAG, "0");
    if (!retFlag) {
        MEDIA_ERR_LOG("Failed to set parameter cloneFlag, retFlag:%{public}d", retFlag);
    }
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
    MEDIA_INFO_LOG("PortraitStat: album %{public}zu, photo %{public}lld, face %{public}lld, cost %{public}lld",
        portraitAlbumIdMap_.size(), (long long)migratePortraitPhotoNumber_, (long long)migratePortraitFaceNumber_,
        (long long)migratePortraitTotalTimeCost_);
    BackupDfxUtils::PostPortraitStat(static_cast<uint32_t>(portraitAlbumIdMap_.size()), migratePortraitPhotoNumber_,
        migratePortraitFaceNumber_, migratePortraitTotalTimeCost_);
}

int32_t BaseRestore::GetUniqueId(int32_t fileType)
{
    int32_t uniqueId = -1;
    switch (fileType) {
        case MediaType::MEDIA_TYPE_IMAGE: {
            lock_guard<mutex> lock(imageMutex_);
            uniqueId = static_cast<int32_t>(imageNumber_);
            imageNumber_++;
            break;
        }
        case MediaType::MEDIA_TYPE_VIDEO: {
            lock_guard<mutex> lock(videoMutex_);
            uniqueId = static_cast<int32_t>(videoNumber_);
            videoNumber_++;
            break;
        }
        case MediaType::MEDIA_TYPE_AUDIO: {
            lock_guard<mutex> lock(audioMutex_);
            uniqueId = static_cast<int32_t>(audioNumber_);
            audioNumber_++;
            break;
        }
        default:
            MEDIA_ERR_LOG("Unsupported file type: %{public}d", fileType);
    }
    if (uniqueId == -1) {
        return uniqueId;
    }
    if (sceneCode_ == UPGRADE_RESTORE_ID) {
        uniqueId += UNIQUEID_OFFSET_UPGRADE;
    } else {
        uniqueId += UNIQUEID_OFFSET_CLONE;
    }
    return uniqueId;
}

std::string BaseRestore::GetProgressInfo()
{
    nlohmann::json progressInfoJson;
    for (const auto &type : STAT_PROGRESS_TYPES) {
        SubProcessInfo subProcessInfo = GetSubProcessInfo(type);
        progressInfoJson[STAT_KEY_PROGRESS_INFO].push_back(GetSubProcessInfoJson(type, subProcessInfo));
    }
    return progressInfoJson.dump();
}

SubProcessInfo BaseRestore::GetSubProcessInfo(const std::string &type)
{
    uint64_t success = 0;
    uint64_t duplicate = 0;
    uint64_t failed = 0;
    uint64_t total = 0;
    if (type == STAT_TYPE_PHOTO_VIDEO) {
        success = migrateFileNumber_;
        duplicate = migratePhotoDuplicateNumber_ + migrateVideoDuplicateNumber_;
        failed = static_cast<uint64_t>(GetFailedFiles(STAT_TYPE_PHOTO).size() + GetFailedFiles(STAT_TYPE_VIDEO).size());
        total = totalNumber_;
    } else if (type == STAT_TYPE_AUDIO) {
        success = migrateAudioFileNumber_;
        duplicate = migrateAudioDuplicateNumber_;
        failed = static_cast<uint64_t>(GetFailedFiles(type).size());
        total = audioTotalNumber_;
    } else if (type == STAT_TYPE_UPDATE) {
        UpdateProcessedNumber(updateProcessStatus_, updateProcessedNumber_, updateTotalNumber_);
        success = updateProcessedNumber_;
        total = updateTotalNumber_;
    } else if (type == STAT_TYPE_OTHER) {
        UpdateProcessedNumber(otherProcessStatus_, otherProcessedNumber_, otherTotalNumber_);
        success = otherProcessedNumber_;
        total = otherTotalNumber_;
    } else {
        ongoingTotalNumber_++;
        success = ongoingTotalNumber_;
        total = ongoingTotalNumber_; // make sure progressInfo changes as process goes on
    }
    uint64_t processed = success + duplicate + failed;
    return SubProcessInfo(processed, total);
}

void BaseRestore::UpdateProcessedNumber(const std::atomic<int32_t> &processStatus,
    std::atomic<uint64_t> &processedNumber, const std::atomic<uint64_t> &totalNumber)
{
    if (processStatus == ProcessStatus::STOP) {
        processedNumber = totalNumber.load();
        return;
    }
    processedNumber += processedNumber < totalNumber ? 1 : 0;
}

nlohmann::json BaseRestore::GetSubProcessInfoJson(const std::string &type, const SubProcessInfo &subProcessInfo)
{
    nlohmann::json subProcessInfoJson;
    subProcessInfoJson[STAT_KEY_NAME] = type;
    subProcessInfoJson[STAT_KEY_PROCESSED] = subProcessInfo.processed;
    subProcessInfoJson[STAT_KEY_TOTAL] = subProcessInfo.total;
    subProcessInfoJson[STAT_KEY_IS_PERCENTAGE] = false;
    return subProcessInfoJson;
}

void BaseRestore::UpdateDatabase()
{
    updateProcessStatus_ = ProcessStatus::START;
    GetUpdateTotalCount();
    MEDIA_INFO_LOG("Start update all albums");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    MediaLibraryRdbUtils::UpdateAllAlbums(rdbStore);
    MEDIA_INFO_LOG("Start update unique number");
    BackupDatabaseUtils::UpdateUniqueNumber(mediaLibraryRdb_, imageNumber_, IMAGE_ASSET_TYPE);
    BackupDatabaseUtils::UpdateUniqueNumber(mediaLibraryRdb_, videoNumber_, VIDEO_ASSET_TYPE);
    BackupDatabaseUtils::UpdateUniqueNumber(mediaLibraryRdb_, audioNumber_, AUDIO_ASSET_TYPE);
    MEDIA_INFO_LOG("Start notify");
    NotifyAlbum();
    updateProcessStatus_ = ProcessStatus::STOP;
}

void BaseRestore::NotifyAlbum()
{
    auto watch = MediaLibraryNotify::GetInstance();
    if (watch == nullptr) {
        MEDIA_ERR_LOG("Can not get MediaLibraryNotify Instance");
        return;
    }
    watch->Notify(PhotoColumn::DEFAULT_PHOTO_URI, NotifyType::NOTIFY_ADD);
}

void BaseRestore::GetUpdateTotalCount()
{
    GetUpdateAllAlbumsCount();
    GetUpdateUniqueNumberCount();
}

void BaseRestore::GetUpdateAllAlbumsCount()
{
    const std::vector<std::string> ALBUM_TABLE_LIST = { "PhotoAlbum", "AnalysisAlbum" };
    int32_t albumTotalCount = 0;
    for (const auto &tableName : ALBUM_TABLE_LIST) {
        std::string querySql = "SELECT count(1) as count FROM " + tableName;
        albumTotalCount += BackupDatabaseUtils::QueryInt(mediaLibraryRdb_, querySql, CUSTOM_COUNT);
    }
    updateTotalNumber_ += static_cast<uint64_t>(albumTotalCount);
    MEDIA_INFO_LOG("onProcess Update updateTotalNumber_: %{public}lld", (long long)updateTotalNumber_);
}

void BaseRestore::GetUpdateUniqueNumberCount()
{
    updateTotalNumber_ += UNIQUE_NUMBER_NUM;
    MEDIA_INFO_LOG("onProcess Update updateTotalNumber_: %{public}lld", (long long)updateTotalNumber_);
}

void BaseRestore::RestoreThumbnail()
{
    // restore thumbnail for date fronted 500 photos
    MEDIA_INFO_LOG("Start RestoreThumbnail");
    otherProcessStatus_ = ProcessStatus::START;
    otherTotalNumber_ += THUMBNAIL_NUM;
    MEDIA_INFO_LOG("onProcess Update otherTotalNumber_: %{public}lld", (long long)otherTotalNumber_);
    BackupFileUtils::GenerateThumbnailsAfterRestore();
    otherProcessStatus_ = ProcessStatus::STOP;
}

void BaseRestore::StartBackup()
{}

void BaseRestore::CheckInvalidFile(const FileInfo &fileInfo, int32_t errCode)
{
    return;
}
} // namespace Media
} // namespace OHOS
