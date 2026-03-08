/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include "photos_clone.h"

#include <uuid.h>
#include <numeric>

#include "rdb_store.h"
#include "result_set_utils.h"
#include "photo_album_dao.h"
#include "backup_const.h"
#include "media_log.h"
#include "album_plugin_config.h"
#include "userfile_manager_types.h"

#include <sys/stat.h>
#include "backup_adapters.h"
#include "backup_file_utils.h"
#include "medialibrary_errno.h"
#include "media_file_utils.h"

namespace OHOS::Media {
std::string PhotosClone::ToString(const FileInfo &fileInfo)
{
    return "FileInfo[ fileId: " + std::to_string(fileInfo.fileIdOld) + ", displayName: " + fileInfo.displayName +
           ", bundleName: " + fileInfo.bundleName + ", lPath: " + fileInfo.lPath +
           ", size: " + std::to_string(fileInfo.fileSize) + ", fileType: " + std::to_string(fileInfo.fileType) + " ]";
}

std::string PhotosClone::ToLower(const std::string &str)
{
    std::string lowerStr;
    std::transform(
        str.begin(), str.end(), std::back_inserter(lowerStr), [](unsigned char c) { return std::tolower(c); });
    return lowerStr;
}

/**
 * @brief Get Row Count of Photos in Album.
 */
int32_t PhotosClone::GetPhotosRowCountInPhotoMap()
{
    std::string querySql = this->SQL_PHOTOS_TABLE_COUNT_IN_PHOTO_MAP;
    CHECK_AND_RETURN_RET_LOG(this->mediaLibraryOriginalRdb_ != nullptr, 0,
        "Media_Restore: mediaLibraryOriginalRdb_ is null.");
    auto resultSet = this->mediaLibraryOriginalRdb_->QuerySql(querySql);
    CHECK_AND_RETURN_RET(resultSet != nullptr, 0);
    if (resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        resultSet->Close();
        return 0;
    }
    int32_t count = GetInt32Val("count", resultSet);
    return count;
}

/**
 * @brief Get Row Count of Cloud Photos in Album.
 */
int32_t PhotosClone::GetCloudPhotosRowCountInPhotoMap()
{
    std::string querySql = this->SQL_CLOUD_PHOTOS_TABLE_COUNT_IN_PHOTO_MAP;
    CHECK_AND_RETURN_RET_LOG(this->mediaLibraryOriginalRdb_ != nullptr, 0,
        "singleCloud Media_Restore: mediaLibraryOriginalRdb_ is null.");
    auto resultSet = this->mediaLibraryOriginalRdb_->QuerySql(querySql);
    CHECK_AND_RETURN_RET(resultSet != nullptr, 0);
    if (resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        resultSet->Close();
        return 0;
    }
    int32_t count = GetInt32Val("count", resultSet);
    return count;
}

/**
 * @brief Get Row Count of Photos not in Album.
 */
int32_t PhotosClone::GetPhotosRowCountNotInPhotoMap()
{
    std::string querySql = this->SQL_PHOTOS_TABLE_COUNT_NOT_IN_PHOTO_MAP;
    CHECK_AND_RETURN_RET_LOG(this->mediaLibraryOriginalRdb_ != nullptr, 0,
        "Media_Restore: mediaLibraryOriginalRdb_ is null.");
    auto resultSet = this->mediaLibraryOriginalRdb_->QuerySql(querySql);
    CHECK_AND_RETURN_RET(resultSet != nullptr, 0);
    if (resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        resultSet->Close();
        return 0;
    }
    int32_t count = GetInt32Val("count", resultSet);
    return count;
}

/**
 * @brief Get Row Count of Cloud Photos not in Album.
 */
int32_t PhotosClone::GetCloudPhotosRowCountNotInPhotoMap()
{
    std::string querySql = this->SQL_CLOUD_PHOTOS_TABLE_COUNT_NOT_IN_PHOTO_MAP;
    CHECK_AND_RETURN_RET_LOG(this->mediaLibraryOriginalRdb_ != nullptr, 0,
        "singleCloud Media_Restore: mediaLibraryOriginalRdb_ is null.");
    auto resultSet = this->mediaLibraryOriginalRdb_->QuerySql(querySql);
    CHECK_AND_RETURN_RET(resultSet != nullptr, 0);
    if (resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        resultSet->Close();
        return 0;
    }
    int32_t count = GetInt32Val("count", resultSet);
    return count;
}

/**
 * @brief Query the Photos Info, which is in PhotoAlbum, from the Original MediaLibrary Database.
 */
std::shared_ptr<NativeRdb::ResultSet> PhotosClone::GetPhotosInPhotoMap(int32_t offset, int32_t pageSize)
{
    std::vector<NativeRdb::ValueObject> bindArgs = {offset, pageSize};
    CHECK_AND_RETURN_RET_LOG(this->mediaLibraryOriginalRdb_ != nullptr, nullptr,
        "Media_Restore: mediaLibraryOriginalRdb_ is null.");
    return this->mediaLibraryOriginalRdb_->QuerySql(this->SQL_PHOTOS_TABLE_QUERY_IN_PHOTO_MAP, bindArgs);
}

/**
 * @brief Query the Cloud Photos Info, which is in PhotoAlbum, from the Original MediaLibrary Database.
 */
std::shared_ptr<NativeRdb::ResultSet> PhotosClone::GetCloudPhotosInPhotoMap(int32_t offset, int32_t pageSize)
{
    std::vector<NativeRdb::ValueObject> bindArgs = {offset, pageSize};
    CHECK_AND_RETURN_RET_LOG(this->mediaLibraryOriginalRdb_ != nullptr, nullptr,
        "singleCloud Media_Restore: mediaLibraryOriginalRdb_ is null.");
    return this->mediaLibraryOriginalRdb_->QuerySql(this->SQL_CLOUD_PHOTOS_TABLE_QUERY_IN_PHOTO_MAP, bindArgs);
}

/**
 * @brief Query the Photos Info, which is not in PhotoAlbum, from the Original MediaLibrary Database.
 */
std::shared_ptr<NativeRdb::ResultSet> PhotosClone::GetPhotosNotInPhotoMap(int32_t offset, int32_t pageSize)
{
    std::vector<NativeRdb::ValueObject> bindArgs = {offset, pageSize};
    CHECK_AND_RETURN_RET_LOG(this->mediaLibraryOriginalRdb_ != nullptr, nullptr,
        "Media_Restore: mediaLibraryOriginalRdb_ is null.");
    return this->mediaLibraryOriginalRdb_->QuerySql(this->SQL_PHOTOS_TABLE_QUERY_NOT_IN_PHOTO_MAP, bindArgs);
}

/**
 * @brief Query the Cloud Photos Info, which is not in PhotoAlbum, from the Original MediaLibrary Database.
 */
std::shared_ptr<NativeRdb::ResultSet> PhotosClone::GetCloudPhotosNotInPhotoMap(int32_t offset, int32_t pageSize)
{
    std::vector<NativeRdb::ValueObject> bindArgs = {offset, pageSize};
    CHECK_AND_RETURN_RET_LOG(this->mediaLibraryOriginalRdb_ != nullptr, nullptr,
        "singleCloud Media_Restore: mediaLibraryOriginalRdb_ is null.");
    return this->mediaLibraryOriginalRdb_->QuerySql(this->SQL_CLOUD_PHOTOS_TABLE_QUERY_NOT_IN_PHOTO_MAP, bindArgs);
}

/**
 * @note If the lPath is empty, return '/Pictures/其它' string.
 *      If the lPath is '/Pictures/ScreenShots', return '/Pictures/ScreenShots' string.
 *      Otherwise, return the lPath of the FileInfo.
 */
PhotoAlbumDao::PhotoAlbumRowData PhotosClone::FindAlbumInfo(const FileInfo &fileInfo)
{
    PhotoAlbumDao::PhotoAlbumRowData albumInfo;
    std::string lPath = fileInfo.lPath;
    // Scenario 2, WHEN FileInfo is in hidden album, THEN override lPath to the folder in sourcePath.
    // Scenario 3, WHEN FileInfo is not belongs to any album, THEN override lPath to the folder in sourcePath.
    // Note, sourcePath is a sign of the possible scenaio that the file is not in any album.
    bool islPathMiss = !fileInfo.sourcePath.empty() && (fileInfo.hidden == 1 || fileInfo.recycledTime != 0);
    islPathMiss = islPathMiss || fileInfo.lPath.empty();
    if (islPathMiss) {
        lPath = this->photoAlbumDao_.ParseSourcePathToLPath(fileInfo.sourcePath);
        MEDIA_INFO_LOG("Media_Restore: fix lPath of album.fileInfo.lPath: %{public}s, "
                       "lPathFromSourcePath: %{public}s, lowercase: %{public}s, FileInfo Object: %{public}s",
            MediaFileUtils::DesensitizePath(fileInfo.lPath).c_str(),
            MediaFileUtils::DesensitizePath(lPath).c_str(),
            MediaFileUtils::DesensitizePath(this->ToLower(lPath)).c_str(),
            this->ToString(fileInfo).c_str());
    }
    // Scenario 1, WHEN FileInfo is in /Pictures/Screenshots and Video type, THEN redirect to /Pictures/Screenrecords
    if (this->ToLower(lPath) == this->ToLower(AlbumPlugin::LPATH_SCREEN_SHOTS) &&
        fileInfo.fileType == MediaType::MEDIA_TYPE_VIDEO) {
        albumInfo = this->photoAlbumDao_.BuildAlbumInfoOfRecorders();
        albumInfo = this->photoAlbumDao_.GetOrCreatePhotoAlbum(albumInfo);
        MEDIA_INFO_LOG("Media_Restore: screenshots redirect to screenrecords, fileInfo.lPath: %{public}s, "
                       "lPath: %{public}s, Object: %{public}s, albumInfo: %{public}s",
            MediaFileUtils::DesensitizePath(fileInfo.lPath).c_str(),
            MediaFileUtils::DesensitizePath(lPath).c_str(),
            this->ToString(fileInfo).c_str(),
            this->photoAlbumDao_.ToString(albumInfo).c_str());
        return albumInfo;
    }
    return BuildAlbumInfoByCondition(fileInfo, lPath);
}

PhotoAlbumDao::PhotoAlbumRowData PhotosClone::BuildAlbumInfoByCondition(const FileInfo &fileInfo,
    const std::string &lPath)
{
    PhotoAlbumDao::PhotoAlbumRowData albumInfo = this->photoAlbumDao_.BuildAlbumInfoByLPath(lPath);
    if (fileInfo.hidden == 0 && fileInfo.recycledTime == 0) {
        return this->photoAlbumDao_.GetOrCreatePhotoAlbum(albumInfo);
    }
    return this->photoAlbumDao_.GetOrCreatePhotoAlbumForClone(albumInfo);
}

/**
 * @brief Find the lPath of the PhotoAlbum related to Photos from target database.
 */
std::string PhotosClone::FindlPath(const FileInfo &fileInfo)
{
    PhotoAlbumDao::PhotoAlbumRowData albumInfo = this->FindAlbumInfo(fileInfo);
    return albumInfo.lPath;
}

/**
 * @brief Find the albumId of the PhotoAlbum related to Photos from target database.
 */
int32_t PhotosClone::FindAlbumId(const FileInfo &fileInfo)
{
    PhotoAlbumDao::PhotoAlbumRowData albumInfo = this->FindAlbumInfo(fileInfo);
    bool cond = albumInfo.albumId > static_cast<int32_t>(PhotoAlbumId::DEFAULT) ||
        (fileInfo.hidden == 0 && fileInfo.recycledTime == 0);
    CHECK_AND_RETURN_RET(!cond, albumInfo.albumId);
    return fileInfo.recycledTime != 0 ? static_cast<int32_t>(PhotoAlbumId::TRASH) :
        static_cast<int32_t>(PhotoAlbumId::HIDDEN);
}

/**
 * @brief Find the packageName of the PhotoAlbum related to Photos from target database.
 */
std::string PhotosClone::FindPackageName(const FileInfo &fileInfo)
{
    PhotoAlbumDao::PhotoAlbumRowData albumInfo = this->FindAlbumInfo(fileInfo);
    // Only provide the package name of the existing SOURCE album.
    CHECK_AND_RETURN_RET(albumInfo.IsValidSourceAlbum(), "");
    return albumInfo.albumName;
}

/**
 * @brief Find the bundleName of the PhotoAlbum related to Photos from target database.
 */
std::string PhotosClone::FindBundleName(const FileInfo &fileInfo)
{
    PhotoAlbumDao::PhotoAlbumRowData albumInfo = this->FindAlbumInfo(fileInfo);
    // Only provide the bundle name of the existing SOURCE album.
    CHECK_AND_RETURN_RET(albumInfo.IsValidSourceAlbum(), "");
    return albumInfo.bundleName;
}

std::vector<PhotosDao::PhotosRowData> PhotosClone::FindDuplicateBurstKey()
{
    std::vector<PhotosDao::PhotosRowData> result;
    std::string querySql = this->SQL_PHOTOS_TABLE_BURST_KEY_DUPLICATE_QUERY;
    int rowCount = 0;
    int offset = 0;
    int pageSize = 200;
    do {
        std::vector<NativeRdb::ValueObject> bindArgs = {offset, pageSize};
        CHECK_AND_BREAK_ERR_LOG(this->mediaLibraryOriginalRdb_ != nullptr,
            "Media_Restore: mediaLibraryOriginalRdb_ is null.");
        auto resultSet = this->mediaLibraryTargetRdb_->QuerySql(querySql, bindArgs);
        CHECK_AND_BREAK_ERR_LOG(resultSet != nullptr, "Query resultSql is null.");
        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            PhotosDao::PhotosRowData info;
            info.burstKey = GetStringVal("burst_key", resultSet);
            info.ownerAlbumId = GetInt32Val("owner_album_id", resultSet);
            result.emplace_back(info);
        }
        // Check if there are more rows to fetch.
        resultSet->GetRowCount(rowCount);
        offset += pageSize;
        resultSet->Close();
    } while (rowCount > 0);
    return result;
}

int32_t PhotosClone::FindPhotoQuality(const FileInfo &fileInfo)
{
    CHECK_AND_RETURN_RET(fileInfo.photoQuality != 1, 0);
    return fileInfo.photoQuality;
}

std::string PhotosClone::ToString(const std::vector<NativeRdb::ValueObject> &values)
{
    std::vector<std::string> result;
    for (auto &value : values) {
        std::string str;
        value.GetString(str);
        result.emplace_back(str + ", ");
    }
    return std::accumulate(result.begin(), result.end(), std::string());
}

/**
 * @brief generate a uuid
 *
 * @return std::string uuid with 32 characters
 */
std::string PhotosClone::GenerateUuid()
{
    uuid_t uuid;
    uuid_generate(uuid);
    char str[UUID_STR_LENGTH] = {};
    uuid_unparse(uuid, str);
    return str;
}

/**
 * @brief Fix Duplicate burst_key in Photos, which is used in different PhotoAlbum.
 */
int32_t PhotosClone::FixDuplicateBurstKeyInDifferentAlbum(std::atomic<uint64_t> &totalNumber)
{
    std::vector<PhotosDao::PhotosRowData> duplicateBurstKeyList = this->FindDuplicateBurstKey();
    totalNumber += static_cast<uint64_t>(duplicateBurstKeyList.size());
    MEDIA_INFO_LOG("Media_Restore: onProcess Update otherTotalNumber_: %{public}lld", (long long)totalNumber);
    std::string executeSql = this->SQL_PHOTOS_TABLE_BURST_KEY_UPDATE;
    for (auto &info : duplicateBurstKeyList) {
        CHECK_AND_CONTINUE(!info.burstKey.empty());
        std::string burstKeyNew = this->GenerateUuid();
        std::vector<NativeRdb::ValueObject> bindArgs = {burstKeyNew, info.ownerAlbumId, info.burstKey};
        MEDIA_INFO_LOG("Media_Restore: executeSql = %{public}s, bindArgs=%{public}s",
            executeSql.c_str(),
            this->ToString(bindArgs).c_str());
        CHECK_AND_BREAK_ERR_LOG(this->mediaLibraryOriginalRdb_ != nullptr,
            "Media_Restore: mediaLibraryOriginalRdb_ is null.");
        int32_t ret = this->mediaLibraryTargetRdb_->ExecuteSql(executeSql, bindArgs);
        CHECK_AND_PRINT_LOG(ret == NativeRdb::E_OK,
            "Media_Restore: FixDuplicateBurstKeyInDifferentAlbum failed,"
            " ret=%{public}d, sql=%{public}s, bindArgs=%{public}s",
            ret, executeSql.c_str(), this->ToString(bindArgs).c_str());
    }
    return 0;
}

std::string PhotosClone::FindSourcePath(const FileInfo &fileInfo)
{
    CHECK_AND_RETURN_RET(!fileInfo.lPath.empty(), fileInfo.sourcePath);
    CHECK_AND_RETURN_RET(fileInfo.sourcePath.empty(), fileInfo.sourcePath);
    bool cond = (fileInfo.hidden == 0 && fileInfo.recycledTime == 0);
    CHECK_AND_RETURN_RET(!cond, fileInfo.sourcePath);
    return this->SOURCE_PATH_PREFIX + fileInfo.lPath + "/" + fileInfo.displayName;
}

/**
 * @brief Get Row Count of Photos No Need Migrate.
 */
int32_t PhotosClone::GetNoNeedMigrateCount()
{
    std::string querySql = this->SQL_PHOTOS_TABLE_COUNT_NO_NEED_MIGRATE;
    CHECK_AND_RETURN_RET_LOG(this->mediaLibraryOriginalRdb_ != nullptr, 0,
        "Media_Restore: mediaLibraryOriginalRdb_ is null.");
    auto resultSet = this->mediaLibraryOriginalRdb_->QuerySql(querySql);
    CHECK_AND_RETURN_RET(resultSet != nullptr, 0);
    if (resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        resultSet->Close();
        return 0;
    }
    int32_t count = GetInt32Val("count", resultSet);
    return count;
}

void PhotosClone::SetFilePath(std::vector<FileInfo> &fileInfos)
{
    SetIsStoragePathExistInDb(fileInfos);
    // use std::remove_if to filter out lake files unable to set file path
    auto validEnd = std::remove_if(fileInfos.begin(), fileInfos.end(), [this](FileInfo &fileInfo) {
        bool success = SetFilePathForLakeFile(fileInfo);
        CHECK_AND_PRINT_LOG(success,
            "Set filePath for %{public}s failed, remove it from fileInfos", ToString(fileInfo).c_str());
        return !success;
    });
    fileInfos.erase(validEnd, fileInfos.end());
    // in case that storage_path changes
    SetIsStoragePathExistInDb(fileInfos);
    SetIsCloudPathExistInDb(fileInfos);
}

void PhotosClone::SetIsStoragePathExistInDb(std::vector<FileInfo> &fileInfos)
{
    int32_t existCount = 0;
    int64_t startTime = MediaFileUtils::UTCTimeMilliSeconds();
    std::vector<std::string> storagePaths;
    for (const auto &fileInfo : fileInfos) {
        CHECK_AND_CONTINUE(FileAdapter::IsLakeFile(fileInfo));
        storagePaths.emplace_back(fileInfo.storagePath);
    }
    std::unordered_set<std::string> existingStoragePaths =
        photosDao_.GetExistingStoragePaths(storagePaths, photosBasicInfo_.maxFileId);
    for (auto &fileInfo : fileInfos) {
        CHECK_AND_CONTINUE(FileAdapter::IsLakeFile(fileInfo));
        fileInfo.isStoragePathExistInDb = existingStoragePaths.count(fileInfo.storagePath) > 0;
        existCount += fileInfo.isStoragePathExistInDb;
    }
    int64_t endTime = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("LakeClone: TimeCost: SetIsStoragePathExistInDb cost %{public}" PRId64 ", existCount: %{public}d",
        endTime - startTime, existCount);
}

void PhotosClone::SetIsCloudPathExistInDb(std::vector<FileInfo> &fileInfos)
{
    int32_t existCount = 0;
    int64_t startTime = MediaFileUtils::UTCTimeMilliSeconds();
    std::vector<std::string> cloudPaths;
    for (const auto &fileInfo : fileInfos) {
        CHECK_AND_CONTINUE(FileAdapter::IsLakeFile(fileInfo));
        cloudPaths.emplace_back(fileInfo.oldPath);
    }
    std::unordered_set<std::string> existingCloudPaths =
        photosDao_.GetExistingData(cloudPaths, photosBasicInfo_.maxFileId);
    for (auto &fileInfo : fileInfos) {
        CHECK_AND_CONTINUE(FileAdapter::IsLakeFile(fileInfo));
        fileInfo.isCloudPathExistInDb = existingCloudPaths.count(fileInfo.oldPath) > 0;
        existCount += fileInfo.isCloudPathExistInDb;
    }
    int64_t endTime = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("LakeClone: TimeCost: SetIsCloudPathExistInDb cost %{public}" PRId64 ", existCount: %{public}d",
        endTime - startTime, existCount);
}

bool PhotosClone::SetFilePathForLakeFile(FileInfo &fileInfo)
{
    if (!FileAdapter::IsLakeFile(fileInfo)) {
        fileInfo.inode.clear();
        fileInfo.storagePath.clear(); // in case of hidden or trashed file originally from lake, remove lake info
        return true;
    }
    std::string storagePath = FindStoragePath(fileInfo);
    CHECK_AND_RETURN_RET(!storagePath.empty(), false);
    SetLakeFileInfo(fileInfo, storagePath);
    return true;
}

std::string PhotosClone::FindStoragePath(const FileInfo &fileInfo)
{
    bool cond = !fileInfo.isStoragePathExistInDb && IsFileSizeMatched(fileInfo, fileInfo.storagePath);
    CHECK_AND_RETURN_RET(!cond, fileInfo.storagePath);
    return FindStoragePathByFile(fileInfo);
}

bool PhotosClone::IsFileSizeMatched(const FileInfo &fileInfo, const std::string &storagePath)
{
    struct stat statInfo {};
    CHECK_AND_RETURN_RET(stat(storagePath.c_str(), &statInfo) == E_SUCCESS, false);
    CHECK_AND_RETURN_RET_LOG(statInfo.st_size == fileInfo.fileSize, false,
        "%{public}s size not matched, %{public}" PRId64 " != %{public}" PRId64,
        fileInfo.storagePath.c_str(), statInfo.st_size, fileInfo.fileSize);
    return true;
}

std::string PhotosClone::FindStoragePathByFile(const FileInfo &fileInfo)
{
    const uint32_t MAX_TRY_TIMES = 50;
    std::vector<std::string> candidateStoragePaths;
    for (uint32_t number = 0; number < MAX_TRY_TIMES; number++) {
        std::string numberedStoragePath = GetNumberedStoragePath(fileInfo.storagePath, number);
        CHECK_AND_BREAK_INFO_LOG(MediaFileUtils::IsFileExists(numberedStoragePath),
            "LakeClone: no need to search more, stop at %{public}s",
            BackupFileUtils::GarbleFilePath(numberedStoragePath, DEFAULT_RESTORE_ID).c_str());
        CHECK_AND_CONTINUE(IsFileSizeMatched(fileInfo, numberedStoragePath));
        candidateStoragePaths.emplace_back(numberedStoragePath);
    }

    CHECK_AND_RETURN_RET_LOG(!candidateStoragePaths.empty(), "",
        "No candidate storagePaths for %{public}s", ToString(fileInfo).c_str());
    CHECK_AND_RETURN_RET(candidateStoragePaths.size() > 1, candidateStoragePaths[0]);
    for (auto it = candidateStoragePaths.rbegin(); it != candidateStoragePaths.rend(); ++it)
    {
        const auto& storagePath = *it;
        CHECK_AND_RETURN_RET(!IsMetadataMatched(fileInfo, storagePath), storagePath);
    }
    return "";
}

bool PhotosClone::IsMetadataMatched(const FileInfo &fileInfo, const std::string &storagePath)
{
    auto iter = storagePathToMetadataInfoMap_.find(storagePath);
    CHECK_AND_RETURN_RET(iter == storagePathToMetadataInfoMap_.end(), iter->second.orientation == fileInfo.orientation);
    std::unique_ptr<Metadata> data = make_unique<Metadata>();
    data->SetFilePath(storagePath);
    data->SetFileMediaType(fileInfo.fileType);
    data->SetFileDateModified(fileInfo.dateModified);
    data->SetFileName(fileInfo.displayName);
    BackupFileUtils::FillMetadata(data);
    MetadataInfo metadataInfo = { data->GetOrientation() };
    storagePathToMetadataInfoMap_[storagePath] = metadataInfo;
    return metadataInfo.orientation == fileInfo.orientation;
}

std::string PhotosClone::GetNumberedStoragePath(const std::string &storagePath, uint32_t number)
{
    CHECK_AND_RETURN_RET(number > 0, storagePath);
    size_t pos = storagePath.find_last_of(".");
    CHECK_AND_RETURN_RET(pos != std::string::npos, storagePath + "(" + std::to_string(number) + ")");
    std::string title = storagePath.substr(0, pos);
    std::string extension = storagePath.substr(pos + 1);
    return title + "(" + std::to_string(number) + ")." + extension;
}

void PhotosClone::SetLakeFileInfo(FileInfo &fileInfo, const std::string &storagePath)
{
    struct stat statInfo {};
    CHECK_AND_RETURN(stat(storagePath.c_str(), &statInfo) == E_SUCCESS);
    fileInfo.inode = std::to_string(statInfo.st_ino);
    fileInfo.storagePath = storagePath;
    fileInfo.filePath = storagePath;
    fileInfo.displayName = MediaFileUtils::GetFileName(fileInfo.filePath);
    fileInfo.title = MediaFileUtils::GetTitleFromDisplayName(fileInfo.displayName);
    MEDIA_INFO_LOG("LakeClone: fileInfo inode: %{public}s, storagePath: %{public}s, displayName: %{private}s",
        fileInfo.inode.c_str(), BackupFileUtils::GarbleFilePath(storagePath, DEFAULT_RESTORE_ID).c_str(),
        BackupFileUtils::GarbleFilePath(fileInfo.displayName, DEFAULT_RESTORE_ID).c_str());
}

bool PhotosClone::ShouldDeleteDuplicateLakeFile(const FileInfo &fileInfo)
{
    // if not a lake file, return true as default;
    CHECK_AND_RETURN_RET(FileAdapter::IsLakeFile(fileInfo), true);
    // if the file has existing storage_path, the file should not be deleted
    return !fileInfo.isStoragePathExistInDb;
}

bool PhotosClone::IsCloudPathExist(const FileInfo &fileInfo)
{
    CHECK_AND_RETURN_RET(FileAdapter::IsLakeFile(fileInfo), MediaFileUtils::IsFileExists(fileInfo.cloudPath));
    return fileInfo.isCloudPathExistInDb;
}

int32_t PhotosClone::CreateCloudPath(int32_t uniqueId, FileInfo &fileInfo)
{
    int32_t fixedBucketNum = FileAdapter::IsLakeFile(fileInfo) ? 0 : -1;
    return BackupFileUtils::CreateAssetPathById(uniqueId, fileInfo.fileType,
        MediaFileUtils::GetExtensionFromPath(fileInfo.displayName), fileInfo.cloudPath, fixedBucketNum);
}
}  // namespace OHOS::Media