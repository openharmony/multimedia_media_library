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
#include <regex>

#include "album_plugin_config.h"
#include "backup_database_utils.h"
#include "backup_file_utils.h"
#include "datashare_abs_result_set.h"
#include "directory_ex.h"
#include "ffrt.h"
#include "ffrt_inner.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "media_file_utils.h"
#include "media_file_uri.h"
#include "media_log.h"
#include "media_scanner.h"
#include "medialibrary_rdb_transaction.h"

namespace OHOS {
namespace Media {
const int PHONE_FIRST_NUMBER = 105;
const int PHONE_SECOND_NUMBER = 80;
const int PHONE_THIRD_NUMBER = 104;
const int PHONE_FOURTH_NUMBER = 111;
const int PHONE_FIFTH_NUMBER = 110;
const int PHONE_SIXTH_NUMBER = 101;
const int QUERY_NUMBER = 200;
const int STRONG_ASSOCIATION_ENABLE = 1;
constexpr int32_t MAX_CLONE_THREAD_NUM = 2;
constexpr int64_t SECONDS_LEVEL_LIMIT = 1e10;
const std::string I_PHONE_LPATH = "/Pictures/";
const std::string PHONE_TYPE = "type";
const std::string PHONE_DEVICE_TYPE = "deviceType";
const std::string PHONE_DETAIL = "detail";
const std::string PHOTO_DB_NAME = "photo_MediaInfo.db";
const std::string PHOTO_SD_MEDIA_INFO_DB_NAME = "photo_sd_MediaInfo.db";
const std::string VIDEO_DB_NAME = "video_MediaInfo.db";
const std::string VIDEO_SD_MEDIA_INFO_DB_NAME = "video_sd_MediaInfo.db";
const std::string OTHER_CLONE_FILE_ROOT_PATH = "/storage/media/local/files/.backup/restore";
const std::string LITE_CLONE_SD_FILE_PATH = "/storage/media/local/files/.backup/restore/storage/";
const std::string OTHER_CLONE_DB_PATH = "/storage/media/local/files/.backup/restore/storage/emulated/0/";
const std::string OTHER_CLONE_FILE_PATH = "/storage/media/local/files/.backup/restore/storage/emulated/";
const std::string OTHER_CLONE_DISPLAYNAME = "primaryStr";
const std::string OTHER_CLONE_DATA = "_data";
const std::string OTHER_CLONE_MODIFIED = "date_modified";
const std::string OTHER_CLONE_TAKEN = "datetaken";
const std::string OTHER_MUSIC_ROOT_PATH = "/storage/emulated/0/";

static constexpr uint32_t CHAR_ARRAY_LENGTH = 5;
static constexpr uint32_t ASCII_CHAR_LENGTH = 8;
static constexpr uint32_t DECODE_NAME_IDX = 4;
static constexpr uint32_t DECODE_SURFIX_IDX = 5;
static constexpr uint32_t DECODE_TIME_IDX = 3;

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
    ffrt_disable_worker_escape();
    MEDIA_INFO_LOG("Set ffrt_disable_worker_escape");
}

void OthersCloneRestore::CloneInfoPushBack(std::vector<CloneDbInfo> &pushInfos, std::vector<CloneDbInfo> &popInfos)
{
    std::lock_guard<std::mutex> guard(cloneMutex_);
    for (auto &info : popInfos) {
        pushInfos.push_back(info);
    }
}

void OthersCloneRestore::HandleSelectBatch(std::shared_ptr<NativeRdb::RdbStore> mediaRdb, int32_t offset,
    int32_t sceneCode, std::vector<CloneDbInfo> &mediaDbInfo)
{
    MEDIA_INFO_LOG("start handle clone batch, offset: %{public}d", offset);
    if (mediaRdb == nullptr) {
        MEDIA_ERR_LOG("rdb is nullptr, Maybe init failed.");
        return;
    }
    std::string queryExternalMayClonePhoto;
    if (sceneCode == I_PHONE_CLONE_RESTORE) {
        queryExternalMayClonePhoto = "SELECT primaryStr, date_modified, datetaken FROM mediainfo LIMIT " +
            std::to_string(offset) + ", " + std::to_string(QUERY_NUMBER);
    } else if (sceneCode == LITE_PHONE_CLONE_RESTORE) {
        queryExternalMayClonePhoto = "SELECT _data, date_modified, datetaken FROM mediainfo LIMIT " +
            std::to_string(offset) + ", " + std::to_string(QUERY_NUMBER);
    } else {
        queryExternalMayClonePhoto = "SELECT _data, date_modified, datetaken FROM mediainfo LIMIT " +
            std::to_string(offset) + ", " + std::to_string(QUERY_NUMBER);
    }
    auto resultSet = mediaRdb->QuerySql(queryExternalMayClonePhoto);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Query resultSql is null.");
        return;
    }
    std::vector<CloneDbInfo> infos;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        CloneDbInfo tmpDbInfo;
        if (sceneCode == I_PHONE_CLONE_RESTORE) {
            tmpDbInfo.displayName = GetStringVal(OTHER_CLONE_DISPLAYNAME, resultSet);
            tmpDbInfo.dateModified = GetDoubleVal(OTHER_CLONE_MODIFIED, resultSet);
            tmpDbInfo.dateTaken = GetDoubleVal(OTHER_CLONE_TAKEN, resultSet);
        } else if (sceneCode == LITE_PHONE_CLONE_RESTORE) {
            tmpDbInfo.data = GetStringVal(OTHER_CLONE_DATA, resultSet);
            tmpDbInfo.dateModified = static_cast<double>(GetInt64Val(OTHER_CLONE_MODIFIED, resultSet));
            tmpDbInfo.dateTaken = static_cast<double>(GetInt64Val(OTHER_CLONE_TAKEN, resultSet));
        } else {
            tmpDbInfo.data = GetStringVal(OTHER_CLONE_DATA, resultSet);
            tmpDbInfo.dateModified = static_cast<double>(GetInt64Val(OTHER_CLONE_MODIFIED, resultSet));
            tmpDbInfo.dateTaken = static_cast<double>(GetInt64Val(OTHER_CLONE_TAKEN, resultSet));
        }
        infos.push_back(tmpDbInfo);
    };
    CloneInfoPushBack(mediaDbInfo, infos);
}

void OthersCloneRestore::GetCloneDbInfos(const std::string &dbName, std::vector<CloneDbInfo> &mediaDbInfo)
{
    std::string dbPath = OTHER_CLONE_DB_PATH + dbName;
    if (dbName == PHOTO_SD_MEDIA_INFO_DB_NAME || dbName == VIDEO_SD_MEDIA_INFO_DB_NAME) {
        dbPath = OTHER_CLONE_FILE_ROOT_PATH + "/" + dbName;
    }
    if (access(dbPath.c_str(), F_OK) != 0) {
        MEDIA_ERR_LOG("Init rdb not exists, dbName = %{public}s", dbName.c_str());
        return;
    }
    std::shared_ptr<NativeRdb::RdbStore> mediaRdb;
    int32_t initErr = BackupDatabaseUtils::InitDb(mediaRdb, dbName, dbPath, mediaAppName_, false);
    CHECK_AND_RETURN_LOG(mediaRdb != nullptr,
        "Init rdb fail, dbName = %{public}s, err = %{public}d",
        dbName.c_str(), initErr);

    std::string selectTotalCloneMediaNumber = "SELECT count(1) AS count FROM mediainfo";
    int32_t totalNumber = BackupDatabaseUtils::QueryInt(mediaRdb, selectTotalCloneMediaNumber, CUSTOM_COUNT);
    MEDIA_INFO_LOG("dbName = %{public}s, totalNumber = %{public}d", dbName.c_str(), totalNumber);
    ffrt_set_cpu_worker_max_num(ffrt::qos_utility, MAX_CLONE_THREAD_NUM);
    for (int32_t offset = 0; offset < totalNumber; offset += QUERY_NUMBER) {
        ffrt::submit([this, mediaRdb, offset, &mediaDbInfo]() {
            HandleSelectBatch(mediaRdb, offset, sceneCode_, mediaDbInfo);
            }, { &offset }, {}, ffrt::task_attr().qos(static_cast<int32_t>(ffrt::qos_utility)));
    }
    ffrt::wait();
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
    GetCloneDbInfos(AUDIO_DB_NAME, audioDbInfo_);
    GetCloneDbInfos(PHOTO_DB_NAME, photoDbInfo_);
    GetCloneDbInfos(PHOTO_SD_MEDIA_INFO_DB_NAME, photoDbInfo_);
    GetCloneDbInfos(VIDEO_DB_NAME, photoDbInfo_);
    GetCloneDbInfos(VIDEO_SD_MEDIA_INFO_DB_NAME, photoDbInfo_);
    int64_t startCurrent = MediaFileUtils::UTCTimeMilliSeconds();
    int32_t err = GetAllfilesInCurrentDir(backupRestoreDir_);
    if (err != E_OK) {
        MEDIA_ERR_LOG("get all files err %{public}d", err);
        return err;
    }
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("GetCloneDb cost %{public}ld, recursively getting all files cost %{public}ld, phonesize:%{public}d, \
        audiosize:%{public}d", (long)(startCurrent - startGetInfo), (long)(end - startCurrent),
        (int)photoInfos_.size(), (int)audioInfos_.size());
    this->photoAlbumDao_.SetMediaLibraryRdb(this->mediaLibraryRdb_);
    this->photosRestore_.OnStart(this->mediaLibraryRdb_, nullptr);
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
    values.PutInt(PhotoColumn::PHOTO_STRONG_ASSOCIATION, fileInfo.strongAssociation);
    if (fileInfo.dateTaken != 0) {
        values.PutLong(MediaColumn::MEDIA_DATE_TAKEN, fileInfo.dateTaken);
        values.PutLong(MediaColumn::MEDIA_DATE_ADDED, fileInfo.dateTaken);
    }
    if (fileInfo.dateModified != 0) {
        values.PutLong(MediaColumn::MEDIA_DATE_MODIFIED, fileInfo.dateModified);
    }
    values.PutInt(MediaColumn::MEDIA_HIDDEN, fileInfo.hidden);
    values.PutLong(MediaColumn::MEDIA_DATE_TRASHED, fileInfo.dateTrashed);
    return values;
}

static std::string ParseSourcePathToPath(const std::string &sourcePath, const std::string &prefix)
{
    size_t startPos = sourcePath.find(prefix);
    std::string result = sourcePath;
    if (startPos != std::string::npos) {
        startPos += prefix.length();
        result = sourcePath.substr(startPos, sourcePath.size() - startPos);
    }
    return result;
}

static std::string Base32Decode(const std::string &input)
{
    std::string result;
    uint32_t val = 0;
    uint32_t valbits = 0;
    for (char c : input) {
        if (c >= 'A' && c <= 'Z') {
            val = (val << CHAR_ARRAY_LENGTH) + (c - 'A');
            valbits += CHAR_ARRAY_LENGTH;
        } else if (c >= '2' && c <= '7') {
            val = (val << CHAR_ARRAY_LENGTH) + (c - '2' + 26); // 26 : A-Z
            valbits += CHAR_ARRAY_LENGTH;
        }
        if (valbits >= ASCII_CHAR_LENGTH) {
            valbits -= ASCII_CHAR_LENGTH;
            result += static_cast<char>(val >> valbits);
            val &= (1 << valbits) - 1;
        }
    }
    return result;
}

static std::vector<std::string> GetSubStrings(const std::string &originalString, char delimiter)
{
    std::vector<std::string> substrings;
    size_t start = 0;
    size_t end = originalString.find(delimiter);

    while (end != std::string::npos) {
        substrings.push_back(originalString.substr(start, end - start));
        start = end + 1;
        end = originalString.find(delimiter, start);
    }

    substrings.push_back(originalString.substr(start));
    return substrings;
}

static void RecoverHiddenOrRecycleFile(std::string &currentPath, FileInfo &tmpInfo)
{
    size_t hiddenAlbumPos = currentPath.find("hiddenAlbum/bins/0");
    size_t recyclePos = currentPath.find("recycle/bins/0");
    bool recycleFlag = false;
    if (hiddenAlbumPos != std::string::npos) {
        tmpInfo.hidden = 1;
    } else if (recyclePos != std::string::npos) {
        recycleFlag = true;
    } else {
        MEDIA_INFO_LOG("currentPath %{public}s is normal", currentPath.c_str());
        return;
    }

    size_t lastSlashPos = currentPath.find_last_of('/');
    if (lastSlashPos == std::string::npos) {
        MEDIA_ERR_LOG("currentPath %{public}s is abnormal", currentPath.c_str());
        return;
    }
    std::string target = currentPath.substr(lastSlashPos + 1);
    std::vector<std::string> substrings = GetSubStrings(Base32Decode(target), '|');
    if (substrings.size() == 8) { // 8 : info num after decode
        std::string decodeFileName = substrings[DECODE_NAME_IDX] + substrings[DECODE_SURFIX_IDX];
        std::string newPath = currentPath.substr(0, lastSlashPos + 1) + decodeFileName;
        rename(currentPath.c_str(), newPath.c_str());
        currentPath = newPath;
    }
    if (recycleFlag) {
        tmpInfo.dateTrashed = std::stoll(substrings[DECODE_TIME_IDX], nullptr, 10); //10 : decimal
    }
}

void OthersCloneRestore::SetFileInfosInCurrentDir(const std::string &file, struct stat &statInfo)
{
    FileInfo tmpInfo;
    std::string tmpFile = file;

    RecoverHiddenOrRecycleFile(tmpFile, tmpInfo);
    tmpInfo.filePath = tmpFile;
    tmpInfo.displayName = ExtractFileName(tmpFile);
    tmpInfo.title = BackupFileUtils::GetFileTitle(tmpInfo.displayName);
    tmpInfo.fileType = MediaFileUtils::GetMediaType(tmpInfo.displayName);
    tmpInfo.fileSize = statInfo.st_size;
    tmpInfo.dateModified = MediaFileUtils::Timespec2Millisecond(statInfo.st_mtim);
    if (tmpInfo.fileType == MediaType::MEDIA_TYPE_IMAGE) {
        std::regex pattern(R"(.*_enhanced(\.[^.]+)$)");
        if (std::regex_match(file, pattern)) {
            MEDIA_INFO_LOG("%{private}s is an enhanced image!", file.c_str());
            tmpInfo.strongAssociation = STRONG_ASSOCIATION_ENABLE;
        }
    }
    if (tmpInfo.fileType  == MediaType::MEDIA_TYPE_IMAGE || tmpInfo.fileType  == MediaType::MEDIA_TYPE_VIDEO) {
        UpDateFileModifiedTime(tmpInfo);
        photoInfos_.emplace_back(tmpInfo);
    } else if (tmpInfo.fileType  == MediaType::MEDIA_TYPE_AUDIO) {
        UpDateFileModifiedTime(tmpInfo);
        tmpInfo.relativePath = ParseSourcePathToPath(tmpInfo.filePath, OTHER_MUSIC_ROOT_PATH);
        if (tmpInfo.relativePath == tmpInfo.filePath) {
            tmpInfo.relativePath = ParseSourcePathToPath(tmpInfo.filePath, OTHER_CLONE_FILE_ROOT_PATH);
        }
        audioInfos_.emplace_back(tmpInfo);
    } else {
        tmpInfo.fileType = MediaFileUtils::GetMediaTypeNotSupported(tmpInfo.displayName);
        if (tmpInfo.fileType  == MediaType::MEDIA_TYPE_IMAGE || tmpInfo.fileType  == MediaType::MEDIA_TYPE_VIDEO) {
            UpDateFileModifiedTime(tmpInfo);
            photoInfos_.emplace_back(tmpInfo);
            MEDIA_WARN_LOG("Not supported media %{public}s",
                BackupFileUtils::GarbleFilePath(tmpFile, sceneCode_).c_str());
        } else {
            MEDIA_WARN_LOG("Not supported file %{public}s",
                BackupFileUtils::GarbleFilePath(tmpFile, sceneCode_).c_str());
        }
    }
}

void OthersCloneRestore::UpDateFileModifiedTime(FileInfo &fileInfo)
{
    auto pathMatch = [displayName {fileInfo.displayName}, filePath {fileInfo.filePath},
        sceneCode {sceneCode_}](const auto &info) {
        if (sceneCode == I_PHONE_CLONE_RESTORE) {
            return info.displayName == displayName;
        } else {
            return info.data == ParseSourcePathToPath(filePath, OTHER_CLONE_FILE_ROOT_PATH);
        }
    };
    CloneDbInfo info;
    if (fileInfo.fileType == MediaType::MEDIA_TYPE_AUDIO) {
        auto it = std::find_if(audioDbInfo_.begin(), audioDbInfo_.end(), pathMatch);
        if (it != audioDbInfo_.end()) {
            info.dateModified = it->dateModified;
            info.dateTaken = it->dateTaken;
        } else {
            return;
        }
    } else if (fileInfo.fileType  == MediaType::MEDIA_TYPE_IMAGE || fileInfo.fileType  == MediaType::MEDIA_TYPE_VIDEO) {
        auto it = std::find_if(photoDbInfo_.begin(), photoDbInfo_.end(), pathMatch);
        if (it != photoDbInfo_.end()) {
            info.dateModified = it->dateModified;
            info.dateTaken = it->dateTaken;
        } else {
            auto it = std::find_if(audioDbInfo_.begin(), audioDbInfo_.end(), pathMatch);
            if (it != audioDbInfo_.end()) {
                MEDIA_WARN_LOG("find video in audio info map %{public}s", fileInfo.displayName.c_str());
                info.dateModified = it->dateModified;
                info.dateTaken = it->dateTaken;
            }
        }
    } else {
        MEDIA_WARN_LOG("Not supported file %{public}s", fileInfo.displayName.c_str());
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

void OthersCloneRestore::HandleInsertBatch(int32_t offset)
{
    int32_t totalNumber = std::min(static_cast<int32_t>(photoInfos_.size()),
        static_cast<int32_t>(offset + QUERY_NUMBER));
    vector<FileInfo> insertInfos;
    for (offset; offset < totalNumber; offset++) {
        FileInfo info = photoInfos_[offset];
        if (info.fileType != MediaType::MEDIA_TYPE_IMAGE && info.fileType != MediaType::MEDIA_TYPE_VIDEO) {
            MEDIA_WARN_LOG("photo info error : %{public}s", info.displayName.c_str());
            continue;
        }
        UpdateAlbumInfo(info);
        insertInfos.push_back(info);
    }
    InsertPhoto(insertInfos);
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
    int32_t totalNumber = static_cast<int32_t>(photoInfos_.size());
    ffrt_set_cpu_worker_max_num(ffrt::qos_utility, MAX_CLONE_THREAD_NUM);
    for (int32_t offset = 0; offset < totalNumber; offset += QUERY_NUMBER) {
        ffrt::submit([this, offset]() {
            HandleInsertBatch(offset);
            }, { &offset }, {}, ffrt::task_attr().qos(static_cast<int32_t>(ffrt::qos_utility)));
    }
    ffrt::wait();
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
    int64_t startUpdate = MediaFileUtils::UTCTimeMilliSeconds();
    UpdatePhotosByFileInfoMap(mediaLibraryRdb_, fileInfos);
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("generate values cost %{public}ld, insert %{public}ld assets cost %{public}ld"
        ", and move %{public}ld files (%{public}ld + %{public}ld) cost %{public}ld. update cost %{public}ld",
        (long)(startInsert - start), (long)rowNum, (long)(startMove - startInsert),
        (long)fileMoveCount, (long)(fileMoveCount - videoFileMoveCount),
        (long)videoFileMoveCount, (long)(startUpdate - startMove), (long)(end - startUpdate));
}

bool OthersCloneRestore::NeedBatchQueryPhotoForPortrait(const std::vector<FileInfo> &fileInfos,
    NeedQueryMap &needQueryMap)
{
    return true;
}

void OthersCloneRestore::RestoreAudio()
{
    MEDIA_INFO_LOG("restore audio");
    if (sceneCode_ == I_PHONE_CLONE_RESTORE) {
        MEDIA_INFO_LOG("No need move audio");
        return;
    }
    if (!audioInfos_.size()) {
        MEDIA_INFO_LOG("audio infos size zero");
        return;
    }
    audioTotalNumber_ += audioInfos_.size();
    int64_t start = MediaFileUtils::UTCTimeMilliSeconds();
    InsertAudio(sceneCode_, audioInfos_);
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("generate values cost %{public}ld, insert audio %{public}ld",
        (long)(end - start), (long)audioTotalNumber_);
}

void OthersCloneRestore::HandleRestData()
{
    MEDIA_INFO_LOG("Start to handle rest data in native.");
    RestoreThumbnail();
}

static std::string ParseSourcePathToLPath(int32_t sceneCode, const std::string &filePath)
{
    std::string lPath = filePath;
    std::string source = OTHER_CLONE_FILE_PATH;
    auto findPos = lPath.find(source);
    if (findPos != std::string::npos) {
        lPath.replace(lPath.find(source), source.length(), "");
    } else {
        MEDIA_WARN_LOG("find other clone path error path: %{public}s",
            BackupFileUtils::GarbleFilePath(filePath, sceneCode).c_str());
        source = LITE_CLONE_SD_FILE_PATH;
        findPos = lPath.find(source);
        if (findPos != std::string::npos) {
            lPath.replace(lPath.find(source), source.length(), "");
            std::size_t startPos = lPath.find_first_of(FILE_SEPARATOR);
            if (startPos != std::string::npos) {
                lPath = lPath.substr(startPos);
            }
        } else {
            source = OTHER_CLONE_FILE_ROOT_PATH;
            findPos = lPath.find(source);
            if (findPos != std::string::npos) {
                lPath.replace(lPath.find(source), source.length(), "");
            }
        }
    }
    std::size_t startPos = lPath.find_first_of(FILE_SEPARATOR);
    if (startPos != std::string::npos) {
        lPath = lPath.substr(startPos);
    }
    std::size_t pos = lPath.find_last_of(FILE_SEPARATOR);
    if (pos != std::string::npos) {
        lPath = lPath.substr(0, pos);
    } else {
        MEDIA_WARN_LOG("find error path is: %{public}s",
            BackupFileUtils::GarbleFilePath(filePath, sceneCode).c_str());
        lPath = FILE_SEPARATOR;
    }
    if (lPath.empty()) {
        MEDIA_WARN_LOG("find path is empty: %{public}s",
            BackupFileUtils::GarbleFilePath(filePath, sceneCode).c_str());
        lPath = FILE_SEPARATOR;
    }
    return lPath;
}

static void AddGalleryAlbum(std::vector<PhotoAlbumRestore::GalleryAlbumRowData> &galleryAlbumInfos,
    const std::string &lPath)
{
    auto pathMatch = [outerLPath {lPath}](const auto &galleryAlbumInfo) {
        return galleryAlbumInfo.lPath == outerLPath;
    };
    auto it = std::find_if(galleryAlbumInfos.begin(), galleryAlbumInfos.end(), pathMatch);
    if (it != galleryAlbumInfos.end()) {
        return;
    }

    PhotoAlbumRestore::GalleryAlbumRowData galleryAlbum;
    std::size_t pos = lPath.find_last_of(FILE_SEPARATOR);
    if (pos != std::string::npos) {
        galleryAlbum.albumName = lPath.substr(pos + 1);
    } else {
        galleryAlbum.albumName = lPath;
    }
    galleryAlbum.lPath = lPath;
    galleryAlbum.priority = 1;
    galleryAlbumInfos.emplace_back(galleryAlbum);
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
    if (sceneCode_ == I_PHONE_CLONE_RESTORE) {
        PhotoAlbumRestore::GalleryAlbumRowData galleryAlbum;
        galleryAlbum.albumName = clonePhoneName_;
        galleryAlbum.bundleName = clonePhoneName_;
        galleryAlbum.lPath = I_PHONE_LPATH + clonePhoneName_;
        galleryAlbum.priority = 1;
        galleryAlbumInfos.emplace_back(galleryAlbum);
    } else if (sceneCode_ == OTHERS_PHONE_CLONE_RESTORE || sceneCode_ == LITE_PHONE_CLONE_RESTORE) {
        for (auto &info : fileInfos) {
            info.lPath = ParseSourcePathToLPath(sceneCode_, info.filePath);
            AddGalleryAlbum(galleryAlbumInfos, info.lPath);
        }
    }
    std::vector<PhotoAlbumDao::PhotoAlbumRowData> albumInfosToRestore =
        photoAlbumRestore_.GetAlbumsToRestore(albumInfos, galleryAlbumInfos);
    auto ret =  photoAlbumDao_.RestoreAlbums(albumInfosToRestore);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Failed to RestoreAlbums : %{public}d", ret);
    }
}

bool OthersCloneRestore::HasSameFileForDualClone(FileInfo &fileInfo)
{
    PhotosDao::PhotosRowData rowData = this->photosRestore_.FindSameFile(fileInfo);
    int32_t fileId = rowData.fileId;
    std::string cloudPath = rowData.data;
    if (fileId <= 0 || cloudPath.empty()) {
        return false;
    }
    fileInfo.isNew = false;
    fileInfo.fileIdNew = fileId;
    fileInfo.cloudPath = cloudPath;
    bool isInCloud = rowData.cleanFlag == 1 && rowData.position == static_cast<int32_t>(PhotoPositionType::CLOUD);
    // If the file was in cloud previously, only require update flags.
    if (fileId > 0 && isInCloud) {
        fileInfo.updateMap["clean_flag"] = "0";
        fileInfo.updateMap["position"] = to_string(static_cast<int32_t>(PhotoPositionType::LOCAL_AND_CLOUD));
        return false;
    }
    fileInfo.needMove = false;
    return true;
}

static std::string ToLower(const std::string &str)
{
    std::string lowerStr;
    std::transform(
        str.begin(), str.end(), std::back_inserter(lowerStr), [](unsigned char c) { return std::tolower(c); });
    return lowerStr;
}

PhotoAlbumDao::PhotoAlbumRowData OthersCloneRestore::FindAlbumInfo(FileInfo &fileInfo)
{
    PhotoAlbumDao::PhotoAlbumRowData albumInfo;
    if (fileInfo.lPath.empty()) {
        MEDIA_ERR_LOG("others clone lPath is empty, path: %{public}s",
            BackupFileUtils::GarbleFilePath(fileInfo.filePath, sceneCode_).c_str());
        return albumInfo;
    }
    if (ToLower(fileInfo.lPath) == ToLower(AlbumPlugin::LPATH_SCREEN_SHOTS) &&
        fileInfo.fileType == MediaType::MEDIA_TYPE_VIDEO) {
        albumInfo = this->photoAlbumDao_.BuildAlbumInfoOfRecorders();
        albumInfo = this->photoAlbumDao_.GetOrCreatePhotoAlbum(albumInfo);
        MEDIA_INFO_LOG(
            "others clone: screenshots redirect to screenrecords, path: %{public}s",
            BackupFileUtils::GarbleFilePath(fileInfo.filePath, sceneCode_).c_str());
        fileInfo.lPath = AlbumPlugin::LPATH_SCREEN_RECORDS;
        return albumInfo;
    }
    albumInfo = this->photoAlbumDao_.GetPhotoAlbum(fileInfo.lPath);
    if (albumInfo.lPath.empty()) {
        MEDIA_ERR_LOG("others clone: albumInfo is empty, path: %{public}s",
            BackupFileUtils::GarbleFilePath(fileInfo.filePath, sceneCode_).c_str());
    }
    return albumInfo;
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
    } else if (sceneCode_ == OTHERS_PHONE_CLONE_RESTORE || sceneCode_ == LITE_PHONE_CLONE_RESTORE) {
        PhotoAlbumDao::PhotoAlbumRowData albumInfo = FindAlbumInfo(info);
        info.mediaAlbumId = albumInfo.albumId;
        info.ownerAlbumId = albumInfo.albumId;
    }
}

void OthersCloneRestore::AnalyzeSource()
{
    MEDIA_INFO_LOG("analyze source later");
}

} // namespace Media
} // namespace OHOS
