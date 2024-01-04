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

#define MLOG_TAG "MediaLibraryUpgradeRestore"

#include "upgrade_restore.h"

#include "backup_database_utils.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_data_manager.h"
#include "result_set_utils.h"
#include "userfile_manager_types.h"
#include "ffrt.h"

namespace OHOS {
namespace Media {
constexpr int32_t GALLERY_IMAGE_TYPE = 1;
constexpr int32_t GALLERY_VIDEO_TYPE = 3;

UpgradeRestore::UpgradeRestore(const std::string &galleryAppName, const std::string &mediaAppName, int32_t sceneCode)
{
    galleryAppName_ = galleryAppName;
    mediaAppName_ = mediaAppName;
    sceneCode_ = sceneCode;
}

int32_t UpgradeRestore::Init(const std::string &backupRetoreDir, const std::string &upgradeFilePath, bool isUpgrade)
{
    appDataPath_ = backupRetoreDir;
    if (sceneCode_ == DUAL_FRAME_CLONE_RESTORE_ID) {
        filePath_ = backupRetoreDir;
        galleryDbPath_ = backupRetoreDir + "/" + GALLERY_DB_NAME;
    } else {
        filePath_ = upgradeFilePath;
        galleryDbPath_ = backupRetoreDir + "/" + galleryAppName_ + "/ce/databases/gallery.db";
        externalDbPath_ = backupRetoreDir + "/" + mediaAppName_ + "/ce/databases/external.db";
        if (!MediaFileUtils::IsFileExists(externalDbPath_)) {
            MEDIA_ERR_LOG("External db is not exist.");
            return E_FAIL;
        }
        int32_t externalErr = BackupDatabaseUtils::InitDb(externalRdb_, EXTERNAL_DB_NAME, externalDbPath_,
            mediaAppName_, false);
        if (externalRdb_ == nullptr) {
            MEDIA_ERR_LOG("External init rdb fail, err = %{public}d", externalErr);
            return E_FAIL;
        }
    }

    if (isUpgrade && BaseRestore::Init() != E_OK) {
        return E_FAIL;
    }
    if (!MediaFileUtils::IsFileExists(galleryDbPath_)) {
        MEDIA_ERR_LOG("Gallery media db is not exist.");
    } else {
        int32_t galleryErr = BackupDatabaseUtils::InitDb(galleryRdb_, GALLERY_DB_NAME, galleryDbPath_,
            galleryAppName_, false);
        if (galleryRdb_ == nullptr) {
            MEDIA_ERR_LOG("Gallery init rdb fail, err = %{public}d", galleryErr);
            return E_FAIL;
        }
    }
    MEDIA_INFO_LOG("Init db succ.");
    return E_OK;
}

void UpgradeRestore::RestorePhoto(void)
{
    InitGarbageAlbum();
    RestoreFromGallery();
    if (sceneCode_ == UPGRADE_RESTORE_ID) {
        RestoreFromExternal(true);
        RestoreFromExternal(false);
    }
    (void)NativeRdb::RdbHelper::DeleteRdbStore(galleryDbPath_);
    (void)NativeRdb::RdbHelper::DeleteRdbStore(externalDbPath_);
}

void UpgradeRestore::InitGarbageAlbum()
{
    BackupDatabaseUtils::InitGarbageAlbum(galleryRdb_, cacheSet_, nickMap_);
}

void UpgradeRestore::RestoreFromGallery()
{
    int32_t totalNumber = QueryTotalNumber();
    MEDIA_INFO_LOG("totalNumber = %{public}d", totalNumber);
    for (int32_t offset = 0; offset < totalNumber; offset += QUERY_COUNT) {
        ffrt::submit([this, offset]() { RestoreBatch(offset); }, { &offset });
    }
    ffrt::wait();
}

void UpgradeRestore::RestoreBatch(int32_t offset)
{
    std::vector<FileInfo> infos = QueryFileInfos(offset);
    InsertPhoto(UPGRADE_RESTORE_ID, infos, SourceType::GALLERY);
}

void UpgradeRestore::RestoreFromExternal(bool isCamera)
{
    MEDIA_INFO_LOG("start restore from %{public}s", (isCamera ? "camera" : "others"));
    int32_t maxId = BackupDatabaseUtils::QueryInt(galleryRdb_, isCamera ?
        QUERY_MAX_ID_CAMERA_SCREENSHOT : QUERY_MAX_ID_OTHERS, MAX_ID);
    int32_t type = isCamera ? SourceType::EXTERNAL_CAMERA : SourceType::EXTERNAL_OTHERS;
    int32_t totalNumber = QueryNotSyncTotalNumber(maxId, isCamera);
    MEDIA_INFO_LOG("totalNumber = %{public}d", totalNumber);
    for (int32_t offset = 0; offset < totalNumber; offset += QUERY_COUNT) {
        ffrt::submit([this, offset, maxId, isCamera, type]() {
                RestoreExternalBatch(offset, maxId, isCamera, type);
            }, { &offset });
    }
    ffrt::wait();
}

void UpgradeRestore::RestoreExternalBatch(int32_t offset, int32_t maxId, bool isCamera, int32_t type)
{
    std::vector<FileInfo> infos = QueryFileInfosFromExternal(offset, maxId, isCamera);
    InsertPhoto(UPGRADE_RESTORE_ID, infos, type);
}

int32_t UpgradeRestore::QueryNotSyncTotalNumber(int32_t maxId, bool isCamera)
{
    std::string queryCamera = isCamera ? IN_CAMERA : NOT_IN_CAMERA;
    std::string queryNotSyncByCount = QUERY_COUNT_FROM_FILES + queryCamera + " AND " +
        COMPARE_ID + std::to_string(maxId) + " AND " + QUERY_NOT_SYNC;
    return BackupDatabaseUtils::QueryInt(externalRdb_, queryNotSyncByCount, COUNT);
}

void UpgradeRestore::HandleRestData(void)
{
    MEDIA_INFO_LOG("Start to handle rest data in native.");
    std::string photoData = appDataPath_ + "/" + galleryAppName_;
    std::string mediaData = appDataPath_ + "/" + mediaAppName_;
    if (MediaFileUtils::IsFileExists(photoData)) {
        MEDIA_DEBUG_LOG("Start to delete photo data.");
        (void)MediaFileUtils::DeleteDir(photoData);
    }
    if (MediaFileUtils::IsFileExists(mediaData)) {
        MEDIA_DEBUG_LOG("Start to delete media data.");
        (void)MediaFileUtils::DeleteDir(mediaData);
    }
    if ((sceneCode_ == UPGRADE_RESTORE_ID) && MediaFileUtils::IsFileExists(UPGRADE_FILE_DIR)) {
        (void)MediaFileUtils::RenameDir(UPGRADE_FILE_DIR, DOCUMENT_PATH);
    }
}

int32_t UpgradeRestore::QueryTotalNumber(void)
{
    return BackupDatabaseUtils::QueryInt(galleryRdb_, QUERY_GALLERY_COUNT, COUNT);
}

std::vector<FileInfo> UpgradeRestore::QueryFileInfos(int32_t offset)
{
    std::vector<FileInfo> result;
    result.reserve(QUERY_COUNT);
    if (galleryRdb_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdb_ is nullptr, Maybe init failed.");
        return result;
    }
    std::string queryAllPhotosByCount = QUERY_ALL_PHOTOS + "limit " + std::to_string(offset) + ", " +
        std::to_string(QUERY_COUNT);
    auto resultSet = galleryRdb_->QuerySql(queryAllPhotosByCount);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Query resultSql is null.");
        return result;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        FileInfo tmpInfo;
        if (ParseResultSet(resultSet, tmpInfo)) {
            result.emplace_back(tmpInfo);
        }
    }
    return result;
}

std::vector<FileInfo> UpgradeRestore::QueryFileInfosFromExternal(int32_t offset, int32_t maxId, bool isCamera)
{
    std::vector<FileInfo> result;
    result.reserve(QUERY_COUNT);
    if (externalRdb_ == nullptr) {
        MEDIA_ERR_LOG("Pointer rdb_ is nullptr, Maybe init failed.");
        return result;
    }
    std::string queryCamera = isCamera ? IN_CAMERA : NOT_IN_CAMERA;
    std::string queryFilesByCount = QUERY_FILE_COLUMN + queryCamera + " AND " +
        COMPARE_ID + std::to_string(maxId) + " AND " + QUERY_NOT_SYNC + " limit " + std::to_string(offset) + ", " +
        std::to_string(QUERY_COUNT);
    auto resultSet = externalRdb_->QuerySql(queryFilesByCount);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Query resultSql is null.");
        return result;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        FileInfo tmpInfo;
        if (ParseResultSetFromExternal(resultSet, tmpInfo)) {
            std::string findPath = tmpInfo.relativePath;
            bool isValid = IsValidDir(findPath);
            if (isValid) {
                result.emplace_back(tmpInfo);
            }
        }
    }
    return result;
}

bool UpgradeRestore::IsValidDir(const string &path)
{
    bool isValid = true;
    for (auto &cacheDir : cacheSet_) {
        if (path.find(cacheDir) == 0) {
            isValid = false;
            break;
        }
    }
    return isValid;
}
bool UpgradeRestore::ParseResultSet(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &info)
{
    // only parse image and video
    int32_t mediaType = GetInt32Val(GALLERY_MEDIA_TYPE, resultSet);
    if (mediaType != GALLERY_IMAGE_TYPE && mediaType != GALLERY_VIDEO_TYPE) {
        MEDIA_ERR_LOG("Invalid media type: %{public}d.", mediaType);
        return false;
    }
    std::string oldPath = GetStringVal(GALLERY_FILE_DATA, resultSet);
    if (sceneCode_ == UPGRADE_RESTORE_ID ?
        !BaseRestore::ConvertPathToRealPath(oldPath, filePath_, info.filePath, info.relativePath) :
        !ConvertPathToRealPath(oldPath, filePath_, info.filePath, info.relativePath)) {
        MEDIA_ERR_LOG("Invalid path: %{private}s.", oldPath.c_str());
        return false;
    }

    int32_t localMediaId = GetInt32Val(GALLERY_LOCAL_MEDIA_ID, resultSet);
    info.displayName = GetStringVal(GALLERY_DISPLAY_NAME, resultSet);
    info.title = GetStringVal(GALLERY_TITLE, resultSet);
    info.userComment = GetStringVal(GALLERY_DESCRIPTION, resultSet);
    info.fileSize = GetInt64Val(GALLERY_FILE_SIZE, resultSet);
    info.duration = GetInt64Val(GALLERY_DURATION, resultSet);
    info.recycledTime = GetInt64Val(GALLERY_RECYCLED_TIME, resultSet);
    info.hidden = (localMediaId == GALLERY_HIDDEN_ID) ? 1 : 0;
    info.isFavorite = GetInt32Val(GALLERY_IS_FAVORITE, resultSet);
    info.fileType = (mediaType == GALLERY_VIDEO_TYPE) ? MediaType::MEDIA_TYPE_VIDEO : MediaType::MEDIA_TYPE_IMAGE;
    info.showDateToken = GetInt64Val(GALLERY_SHOW_DATE_TOKEN, resultSet);
    info.height = GetInt64Val(GALLERY_HEIGHT, resultSet);
    info.width = GetInt64Val(GALLERY_WIDTH, resultSet);
    info.dateAdded = GetInt64Val(DATE_ADDED, resultSet);
    info.orientation = GetInt64Val(GALLERY_ORIENTATION, resultSet);
    return true;
}

bool UpgradeRestore::ParseResultSetFromExternal(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &info)
{
    bool isSuccess = ParseResultSet(resultSet, info);
    if (!isSuccess) {
        MEDIA_ERR_LOG("ParseResultSetFromExternal fail");
        return isSuccess;
    }
    info.dateAdded = GetInt64Val(DATE_ADDED, resultSet);
    return isSuccess;
}

NativeRdb::ValuesBucket UpgradeRestore::GetInsertValue(const FileInfo &fileInfo, const std::string &newPath,
    int32_t sourceType) const
{
    NativeRdb::ValuesBucket values;
    values.PutString(MediaColumn::MEDIA_FILE_PATH, newPath);
    values.PutString(MediaColumn::MEDIA_TITLE, fileInfo.title);
    values.PutString(MediaColumn::MEDIA_NAME, fileInfo.displayName);
    values.PutLong(MediaColumn::MEDIA_SIZE, fileInfo.fileSize);
    values.PutInt(MediaColumn::MEDIA_TYPE, fileInfo.fileType);
    if (sourceType == SourceType::EXTERNAL_CAMERA || sourceType == SourceType::EXTERNAL_OTHERS) {
        values.PutLong(MediaColumn::MEDIA_DATE_ADDED, fileInfo.dateAdded);
    } else {
        values.PutLong(MediaColumn::MEDIA_DATE_ADDED, fileInfo.showDateToken);
    }
    values.PutLong(MediaColumn::MEDIA_DURATION, fileInfo.duration);
    values.PutInt(MediaColumn::MEDIA_IS_FAV, fileInfo.isFavorite);
    values.PutLong(MediaColumn::MEDIA_DATE_TRASHED, fileInfo.recycledTime);
    values.PutInt(MediaColumn::MEDIA_HIDDEN, fileInfo.hidden);
    values.PutInt(PhotoColumn::PHOTO_HEIGHT, fileInfo.height);
    values.PutInt(PhotoColumn::PHOTO_WIDTH, fileInfo.width);
    values.PutString(PhotoColumn::PHOTO_USER_COMMENT, fileInfo.userComment);
    values.PutLong(MediaColumn::MEDIA_DATE_TAKEN, fileInfo.showDateToken / MILLISECONDS);
    values.PutInt(PhotoColumn::PHOTO_ORIENTATION, fileInfo.orientation);
    std::string package_name = "";
    std::string findPath = fileInfo.relativePath;
    for (auto &nickItem : nickMap_) {
        if (findPath.find(nickItem.first) == 0) {
            package_name = nickItem.second;
            break;
        }
    }
    if (package_name != "") {
        values.PutString(PhotoColumn::MEDIA_PACKAGE_NAME, package_name);
    }
    return values;
}

bool UpgradeRestore::ConvertPathToRealPath(const std::string &srcPath, const std::string &prefix,
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
    newPath = prefix + srcPath;
    relativePath = srcPath.substr(pos);
    return true;
}
} // namespace Media
} // namespace OHOS
