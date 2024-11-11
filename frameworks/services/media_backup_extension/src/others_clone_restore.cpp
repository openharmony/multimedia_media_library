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

#define MLOG_TAG "MediaLibraryOthersCloneRestore"

#include "others_clone_restore.h"

#include <securec.h>
#include <dirent.h>
#include <sys/stat.h>

#include "backup_database_utils.h"
#include "backup_file_utils.h"
#include "datashare_abs_result_set.h"
#include "directory_ex.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "media_file_utils.h"
#include "media_file_uri.h"
#include "media_log.h"
#include "media_scanner.h"

namespace OHOS {
namespace Media {
const int PHONE_FIRST_NUMBER = 105;
const int PHONE_SECOND_NUMBER = 80;
const int PHONE_THIRD_NUMBER = 104;
const int PHONE_FOURTH_NUMBER = 111;
const int PHONE_FIFTH_NUMBER = 110;
const int PHONE_SIXTH_NUMBER = 101;
const int QUERY_NUMBER = 200;
constexpr int32_t MAX_THREAD_NUM = 4;
constexpr int64_t SECONDS_LEVEL_LIMIT = 1e10;
const std::string I_PHONE_LPATH = "/Pictures/";
const std::string PHONE_TYPE = "type";
const std::string PHONE_DEVICE_TYPE = "deviceType";
const std::string PHONE_DETAIL = "detail";
const std::string PHOTO_DB_NAME = "photo_MediaInfo.db";
const std::string VIDEO_DB_NAME = "video_MediaInfo.db";
const std::string OTHER_CLONE_DB_PATH = "/storage/media/local/files/.backup/restore/storage/emulated/0/";
const std::string OTHER_CLONE_DISPLAYNAME = "primaryStr";
const std::string OTHER_CLONE_MODIFIED = "date_modified";
const std::string OTHER_CLONE_TAKEN = "datetaken";

static std::string GetPhoneName()
{
    int arr[] = { PHONE_FIRST_NUMBER, PHONE_SECOND_NUMBER, PHONE_THIRD_NUMBER, PHONE_FOURTH_NUMBER, PHONE_FIFTH_NUMBER,
        PHONE_SIXTH_NUMBER };
    int len = sizeof(arr) / sizeof(arr[0]);
    std::string phoneName = "";
    for (int i = 0; i < len; i++) {
        phoneName += static_cast<char>(arr[i]);
    }
    return phoneName;
}

OthersCloneRestore::OthersCloneRestore(int32_t sceneCode, const std::string &mediaAppName,
    const std::string &bundleInfo)
{
    sceneCode_ = sceneCode;
    mediaAppName_ = mediaAppName;
    if (sceneCode_ == I_PHONE_CLONE_RESTORE) {
        nlohmann::json jsonObj = nlohmann::json::parse(bundleInfo, nullptr, false);
        if (jsonObj.is_discarded()) {
            MEDIA_ERR_LOG("parse json failed");
            clonePhoneName_ = GetPhoneName();
            return;
        }
        for (auto &obj : jsonObj) {
            if (obj.contains(PHONE_TYPE) && obj.at(PHONE_TYPE) == PHONE_DEVICE_TYPE) {
                clonePhoneName_ = obj.at(PHONE_DETAIL);
            }
        }
        if (clonePhoneName_.empty()) {
            MEDIA_ERR_LOG("read json error");
            clonePhoneName_ = GetPhoneName();
        }
    }
}

static void HandleSelectBatch(std::shared_ptr<NativeRdb::RdbStore> mediaRdb, int32_t offset,
    std::vector<CloneDbInfo> &mediaDbInfo)
{
    MEDIA_INFO_LOG("start handle clone batch, offset: %{public}d", offset);
    if (mediaRdb == nullptr) {
        MEDIA_ERR_LOG("rdb is nullptr, Maybe init failed.");
        return;
    }
    std::string queryExternalMayClonePhoto = "SELECT primaryStr, date_modified, datetaken FROM mediainfo LIMIT "
        + std::to_string(offset) + ", " + std::to_string(QUERY_NUMBER);
    auto resultSet = mediaRdb->QuerySql(queryExternalMayClonePhoto);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Query resultSql is null.");
        return;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        CloneDbInfo tmpDbInfo;
        tmpDbInfo.displayName = GetStringVal(OTHER_CLONE_DISPLAYNAME, resultSet);
        tmpDbInfo.dateModified = GetDoubleVal(OTHER_CLONE_MODIFIED, resultSet);
        tmpDbInfo.dateTaken = GetDoubleVal(OTHER_CLONE_TAKEN, resultSet);
        mediaDbInfo.push_back(tmpDbInfo);
    };
}

void OthersCloneRestore::GetCloneDbInfos(const std::string &dbName, std::vector<CloneDbInfo> &mediaDbInfo)
{
    std::string dbPath = OTHER_CLONE_DB_PATH + dbName;
    if (access(dbPath.c_str(), F_OK) != 0) {
        MEDIA_ERR_LOG("Init rdb not exists, dbName = %{public}s", dbName.c_str());
        return;
    }
    std::shared_ptr<NativeRdb::RdbStore> mediaRdb;
    int32_t initErr = BackupDatabaseUtils::InitDb(mediaRdb, dbName, dbPath, mediaAppName_, false);
    if (mediaRdb == nullptr) {
        MEDIA_ERR_LOG("Init rdb fail, dbName = %{public}s, err = %{public}d", dbName.c_str(), initErr);
        return;
    }

    std::string selectTotalCloneMediaNumber = "SELECT count(1) AS count FROM mediainfo";
    int32_t totalNumber = BackupDatabaseUtils::QueryInt(mediaRdb, selectTotalCloneMediaNumber, CUSTOM_COUNT);
    MEDIA_INFO_LOG("dbName = %{public}s, totalNumber = %{public}d", dbName.c_str(), totalNumber);
    for (int32_t offset = 0; offset < totalNumber; offset += QUERY_NUMBER) {
        HandleSelectBatch(mediaRdb, offset, mediaDbInfo);
    }
}

int32_t OthersCloneRestore::Init(const std::string &backupRetoreDir, const std::string &upgradeFilePath, bool isUpgrade)
{
    if (BaseRestore::Init() != E_OK) {
        MEDIA_ERR_LOG("GetBackupInfo init failed");
        return E_FAIL;
    }
    if (mediaLibraryRdb_ == nullptr) {
        MEDIA_ERR_LOG("GetBackupInfo Rdbstore is null");
        return E_FAIL;
    }
    int64_t startGetInfo = MediaFileUtils::UTCTimeMilliSeconds();
    GetCloneDbInfos(PHOTO_DB_NAME, photoDbInfo_);
    GetCloneDbInfos(VIDEO_DB_NAME, photoDbInfo_);
    int64_t startCurrent = MediaFileUtils::UTCTimeMilliSeconds();
    int32_t err = GetAllfilesInCurrentDir(backupRestoreDir_);
    if (err != E_OK) {
        MEDIA_ERR_LOG("get all files err %{public}d", err);
        return err;
    }
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("GetCloneDb cost %{public}ld, recursively getting all files cost %{public}ld, phonesize:%{public}d",
        (long)(startCurrent - startGetInfo), (long)(end - startCurrent), (int)photoInfos_.size());
    this->photoAlbumDao_.SetMediaLibraryRdb(this->mediaLibraryRdb_);
    MEDIA_INFO_LOG("Init end");
    return E_OK;
}

NativeRdb::ValuesBucket OthersCloneRestore::GetInsertValue(const FileInfo &fileInfo, const std::string &newPath,
    int32_t sourceType)
{
    NativeRdb::ValuesBucket values;
    values.PutString(MediaColumn::MEDIA_FILE_PATH, newPath);
    values.PutString(MediaColumn::MEDIA_TITLE, fileInfo.title);
    values.PutString(MediaColumn::MEDIA_NAME, fileInfo.displayName);
    // use owner_album_id to mark the album id which the photo is in.
    values.PutInt(PhotoColumn::PHOTO_OWNER_ALBUM_ID, fileInfo.ownerAlbumId);
    // only SOURCE album has package_name and owner_package.
    values.PutString(MediaColumn::MEDIA_PACKAGE_NAME, fileInfo.packageName);
    values.PutString(MediaColumn::MEDIA_OWNER_PACKAGE, fileInfo.bundleName);
    if (fileInfo.dateTaken != 0) {
        values.PutLong(MediaColumn::MEDIA_DATE_TAKEN, fileInfo.dateTaken);
        values.PutLong(MediaColumn::MEDIA_DATE_ADDED, fileInfo.dateTaken);
    }
    if (fileInfo.dateModified != 0) {
        values.PutLong(MediaColumn::MEDIA_DATE_MODIFIED, fileInfo.dateModified);
    }
    return values;
}

void OthersCloneRestore::SetFileInfosInCurrentDir(const std::string &file, struct stat &statInfo)
{
    FileInfo tmpInfo;
    tmpInfo.filePath = file;
    tmpInfo.displayName = ExtractFileName(file);
    tmpInfo.title = BackupFileUtils::GetFileTitle(tmpInfo.displayName);
    tmpInfo.fileType = MediaFileUtils::GetMediaType(tmpInfo.displayName);
    tmpInfo.fileSize = statInfo.st_size;
    tmpInfo.dateModified = MediaFileUtils::Timespec2Millisecond(statInfo.st_mtim);
    if (tmpInfo.fileType  == MediaType::MEDIA_TYPE_IMAGE || tmpInfo.fileType  == MediaType::MEDIA_TYPE_VIDEO) {
        UpDateFileModifiedTime(tmpInfo);
        photoInfos_.emplace_back(tmpInfo);
    } else {
        tmpInfo.fileType = MediaFileUtils::GetMediaTypeNotSupported(tmpInfo.displayName);
        if (tmpInfo.fileType  == MediaType::MEDIA_TYPE_IMAGE || tmpInfo.fileType  == MediaType::MEDIA_TYPE_VIDEO) {
            UpDateFileModifiedTime(tmpInfo);
            photoInfos_.emplace_back(tmpInfo);
            MEDIA_WARN_LOG("Not supported media %{public}s", BackupFileUtils::GarbleFilePath(file, sceneCode_).c_str());
        } else {
            MEDIA_WARN_LOG("Not supported file %{public}s", BackupFileUtils::GarbleFilePath(file, sceneCode_).c_str());
        }
    }
}

void OthersCloneRestore::UpDateFileModifiedTime(FileInfo &fileInfo)
{
    auto pathMatch = [displayName {fileInfo.displayName}](const auto &info) {
        return info.displayName == displayName;
    };
    CloneDbInfo info;
    if (fileInfo.fileType  == MediaType::MEDIA_TYPE_IMAGE || fileInfo.fileType  == MediaType::MEDIA_TYPE_VIDEO) {
        auto it = std::find_if(photoDbInfo_.begin(), photoDbInfo_.end(), pathMatch);
        if (it != photoDbInfo_.end()) {
            info.dateModified = it->dateModified;
            info.dateTaken = it->dateTaken;
        }
    } else {
        return;
    }
    if (info.dateModified < SECONDS_LEVEL_LIMIT) {
        info.dateModified = info.dateModified * static_cast<double>(MSEC_TO_SEC);
    }
    if (info.dateTaken < SECONDS_LEVEL_LIMIT) {
        info.dateTaken = info.dateTaken * static_cast<double>(MSEC_TO_SEC);
    }
    fileInfo.dateModified = static_cast<int64_t>(info.dateModified);
    fileInfo.dateTaken = static_cast<int64_t>(info.dateTaken);
    BackupFileUtils::ModifyFile(fileInfo.filePath, fileInfo.dateModified / MSEC_TO_SEC);
}

int32_t OthersCloneRestore::GetAllfilesInCurrentDir(const std::string &path)
{
    int err = E_OK;
    DIR *dirPath = nullptr;
    struct dirent *currentFile = nullptr;
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
        FREE_MEMORY_AND_SET_NULL(fName);
        MEDIA_ERR_LOG("Failed to opendir %{private}s, errno %{private}d", path.c_str(), errno);
        return ERR_NOT_ACCESSIBLE;
    }

    while ((currentFile = readdir(dirPath)) != nullptr) {
        if (!strcmp(currentFile->d_name, ".") || !strcmp(currentFile->d_name, "..")) {
            continue;
        }
        if (strncpy_s(fName + len, FILENAME_MAX - len, currentFile->d_name, FILENAME_MAX - len)) {
            MEDIA_ERR_LOG("Failed to copy file name %{private}s ", fName);
            continue;
        }
        if (lstat(fName, &statInfo) == -1) {
            MEDIA_ERR_LOG("Failed to get info of directory %{private}s ", fName);
            continue;
        }
        std::string currentPath = fName;
        if (S_ISDIR(statInfo.st_mode)) {
            (void)GetAllfilesInCurrentDir(currentPath);
        } else if (S_ISREG(statInfo.st_mode)) {
            SetFileInfosInCurrentDir(fName, statInfo);
        } else {
            MEDIA_INFO_LOG("Not directory or regular file, name is %{private}s", fName);
        }
    }
    closedir(dirPath);
    dirPath = nullptr;
    FREE_MEMORY_AND_SET_NULL(fName);
    return err;
}

void OthersCloneRestore::RestorePhoto()
{
    if (!photoInfos_.size()) {
        MEDIA_INFO_LOG("photo infos size zero");
        return;
    }
    std::vector<FileInfo> fileInfos;
    totalNumber_ += photoInfos_.size();
    RestoreAlbum(photoInfos_);
    unsigned long pageSize = 200;
    vector<FileInfo> insertInfos;
    for (auto &info : photoInfos_) {
        if (info.fileType != MediaType::MEDIA_TYPE_IMAGE && info.fileType != MediaType::MEDIA_TYPE_VIDEO) {
            continue;
        }
        UpdateAlbumInfo(info);
        insertInfos.emplace_back(info);
        if (insertInfos.size() >= pageSize) {
            InsertPhoto(insertInfos);
            insertInfos.clear();
        }
    }
    if (insertInfos.size()) {
        InsertPhoto(insertInfos);
    }
}

void OthersCloneRestore::InsertPhoto(std::vector<FileInfo> &fileInfos)
{
    int64_t start = MediaFileUtils::UTCTimeMilliSeconds();
    vector<NativeRdb::ValuesBucket> values = BaseRestore::GetInsertValues(sceneCode_, fileInfos, SourceType::PHOTOS);
    int64_t startInsert = MediaFileUtils::UTCTimeMilliSeconds();
    int64_t rowNum = 0;
    int32_t errCode = BatchInsertWithRetry(PhotoColumn::PHOTOS_TABLE, values, rowNum);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("BatchInsert fail err %{public}d", errCode);
        UpdateFailedFiles(fileInfos, RestoreError::INSERT_FAILED);
        return;
    }

    int64_t startMove = MediaFileUtils::UTCTimeMilliSeconds();
    migrateDatabaseNumber_ += rowNum;
    int32_t fileMoveCount = 0;
    int32_t videoFileMoveCount = 0;
    MoveMigrateFile(fileInfos, fileMoveCount, videoFileMoveCount, sceneCode_);
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("generate values cost %{public}ld, insert %{public}ld assets cost %{public}ld"
        ", and move %{public}ld files (%{public}ld + %{public}ld) cost %{public}ld.",
        (long)(startInsert - start), (long)rowNum, (long)(startMove - startInsert),
        (long)fileMoveCount, (long)(fileMoveCount - videoFileMoveCount),
        (long)videoFileMoveCount, (long)(end - startMove));
}

bool OthersCloneRestore::NeedBatchQueryPhotoForPortrait(const std::vector<FileInfo> &fileInfos,
    NeedQueryMap &needQueryMap)
{
    return true;
}

void OthersCloneRestore::RestoreAudio()
{
    MEDIA_INFO_LOG("restore audio");
}

void OthersCloneRestore::HandleRestData()
{
    MEDIA_INFO_LOG("Start to handle rest data in native.");
    RestoreThumbnail();
}

bool OthersCloneRestore::ParseResultSet(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &info,
    std::string dbName)
{
    return true;
}

bool OthersCloneRestore::ParseResultSetForAudio(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &info)
{
    return true;
}

void OthersCloneRestore::RestoreAlbum(std::vector<FileInfo> &fileInfos)
{
    std::vector<PhotoAlbumDao::PhotoAlbumRowData> albumInfos = this->photoAlbumDao_.GetPhotoAlbums();
    std::vector<PhotoAlbumRestore::GalleryAlbumRowData> galleryAlbumInfos;
    PhotoAlbumRestore photoAlbumRestore;
    if (sceneCode_ == I_PHONE_CLONE_RESTORE) {
        PhotoAlbumRestore::GalleryAlbumRowData galleryAlbum;
        galleryAlbum.albumName = clonePhoneName_;
        galleryAlbum.bundleName = clonePhoneName_;
        galleryAlbum.lPath = I_PHONE_LPATH + clonePhoneName_;
        galleryAlbum.priority = 1;
        galleryAlbumInfos.emplace_back(galleryAlbum);
    }
    std::vector<PhotoAlbumDao::PhotoAlbumRowData> albumInfosToRestore =
        photoAlbumRestore.GetAlbumsToRestore(albumInfos, galleryAlbumInfos);
    auto ret = photoAlbumDao_.RestoreAlbums(albumInfosToRestore);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Failed to RestoreAlbums : %{public}d", ret);
    }
}

void OthersCloneRestore::UpdateAlbumInfo(FileInfo &info)
{
    if (sceneCode_ == I_PHONE_CLONE_RESTORE) {
        PhotoAlbumDao::PhotoAlbumRowData albumInfo = photoAlbumDao_.GetPhotoAlbum(I_PHONE_LPATH + clonePhoneName_);
        info.lPath = I_PHONE_LPATH + clonePhoneName_;
        info.mediaAlbumId = albumInfo.albumId;
        info.ownerAlbumId = albumInfo.albumId;
        info.packageName = clonePhoneName_;
        info.bundleName = clonePhoneName_;
    }
}

void OthersCloneRestore::AnalyzeSource()
{
    MEDIA_INFO_LOG("analyze source later");
}

} // namespace Media
} // namespace OHOS
