/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "photo_custom_restore_operation.h"

#include <algorithm>
#include <dlfcn.h>

#include "dfx_reporter.h"
#include "directory_ex.h"
#include "ffrt.h"
#include "ffrt_inner.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "media_file_uri.h"
#include "media_log.h"
#include "media_unique_number_column.h"
#include "medialibrary_asset_operations.h"
#include "medialibrary_bundle_manager.h"
#include "medialibrary_notify.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_type_const.h"
#include "medialibrary_db_const.h"
#include "metadata_extractor.h"
#include "mimetype_utils.h"
#include "photo_album_column.h"
#include "result_set_utils.h"
#include "scanner_utils.h"
#include "userfile_manager_types.h"

using namespace std;
namespace OHOS::Media {
std::shared_ptr<PhotoCustomRestoreOperation> PhotoCustomRestoreOperation::instance_ = nullptr;
std::mutex PhotoCustomRestoreOperation::objMutex_;

PhotoCustomRestoreOperation &PhotoCustomRestoreOperation::GetInstance()
{
    std::lock_guard<std::mutex> lock(PhotoCustomRestoreOperation::objMutex_);
    if (PhotoCustomRestoreOperation::instance_ == nullptr) {
        PhotoCustomRestoreOperation::instance_ = std::make_shared<PhotoCustomRestoreOperation>();
    }
    return *PhotoCustomRestoreOperation::instance_;
}

PhotoCustomRestoreOperation &PhotoCustomRestoreOperation::Start()
{
    if (this->isRunning_.exchange(true)) {
        MEDIA_INFO_LOG("Media_Operation: custom restore operation is running.");
        return *this;
    }
    while (!this->taskQueue_.empty()) {
        RestoreTaskInfo restoreTaskInfo = this->taskQueue_.front();
        if (IsCancelTask(restoreTaskInfo)) {
            CancelTaskFinish(restoreTaskInfo);
            continue;
        }
        DoCustomRestore(restoreTaskInfo);
        this->taskQueue_.pop();
    }

    cancelKeySet.clear();
    this->isRunning_.store(false);
    return *this;
}

void PhotoCustomRestoreOperation::CancelTask(RestoreTaskInfo restoreTaskInfo)
{
    MEDIA_INFO_LOG("cancel custom restore task. keyPath: %{public}s", restoreTaskInfo.keyPath.c_str());
    std::lock_guard<std::mutex> lock(g_cancelOprationLock_);
    cancelKeySet.insert(restoreTaskInfo.keyPath);
}

bool PhotoCustomRestoreOperation::IsCancelTask(RestoreTaskInfo &restoreTaskInfo)
{
    return cancelKeySet.count(restoreTaskInfo.keyPath) > 0;
}

void PhotoCustomRestoreOperation::CancelTaskFinish(RestoreTaskInfo &restoreTaskInfo)
{
    MEDIA_INFO_LOG("cancel custom restore task finish. keyPath: %{public}s", restoreTaskInfo.keyPath.c_str());
    SendNotifyMessage(restoreTaskInfo, NOTIFY_CANCEL, E_OK, 0);
    std::lock_guard<std::mutex> lock(g_cancelOprationLock_);
    cancelKeySet.erase(restoreTaskInfo.keyPath);
}

void PhotoCustomRestoreOperation::ApplyEfficiencyQuota(int32_t fileNum)
{
#ifdef EFFICIENCY_MANAGER_ENABLE
    int64_t quota = fileNum * BASE_EFFICIENCY_QUOTA / BASE_FILE_NUM;
    if (quota == 0) {
        MEDIA_WARN_LOG("quota is zero, skip apply efficiency quota.");
        return;
    }
    string module = BUNDLE_NAME;
    string reason = "Custom Restore";
    MEDIA_INFO_LOG("ApplyEfficiencyQuota. quota: %{public}" PRId64, quota);

    void *resourceQuotaMgrHandle_ = dlopen(ABNORMAL_MANAGER_LIB.c_str(), RTLD_NOW);
    if (!resourceQuotaMgrHandle_) {
        MEDIA_INFO_LOG("Not find resource_quota_manager lib.");
    }

    using HandleQuotaFunc = bool (*)(const std::string &, uint32_t, int64_t, const std::string &);
    auto handleQuotaFunc =
        reinterpret_cast<HandleQuotaFunc>(dlsym(resourceQuotaMgrHandle_, "ApplyAbnormalControlQuota"));
    if (!handleQuotaFunc) {
        MEDIA_ERR_LOG("Get handleQuotaFunc failed.");
        dlclose(resourceQuotaMgrHandle_);
        return;
    }
    if (!handleQuotaFunc(module, MODULE_POWER_OVERUSED, quota, reason)) {
        MEDIA_ERR_LOG("Do handleQuotaFunc failed.");
    }
    dlclose(resourceQuotaMgrHandle_);
#endif
}

PhotoCustomRestoreOperation &PhotoCustomRestoreOperation::AddTask(RestoreTaskInfo restoreTaskInfo)
{
    MEDIA_INFO_LOG("add custom restore task. keyPath: %{public}s", restoreTaskInfo.keyPath.c_str());
    this->taskQueue_.push(restoreTaskInfo);
    return *this;
}

void PhotoCustomRestoreOperation::DoCustomRestore(RestoreTaskInfo &restoreTaskInfo)
{
    ffrt_set_cpu_worker_max_num(ffrt::qos_utility, MAX_RESTORE_THREAD_NUM);

    vector<string> files;
    GetDirFiles(restoreTaskInfo.sourceDir, files);
    InitRestoreTask(restoreTaskInfo, files.size());

    bool isFirstRestoreSuccess = false;
    int32_t firstRestoreIndex = 0;
    for (size_t index = 0; index < files.size(); index++) {
        if (IsCancelTask(restoreTaskInfo)) {
            break;
        }
        if (index == 0 || !isFirstRestoreSuccess) {
            isFirstRestoreSuccess = HandleFirstRestoreFile(restoreTaskInfo, files, index, firstRestoreIndex);
            if (!isFirstRestoreSuccess && index == files.size() - 1) {
                break;
            }
            continue;
        }
        int32_t num1 = (index + 1) % MAX_RESTORE_FILE_NUM;
        int32_t num2 = (index + 1) / MAX_RESTORE_FILE_NUM;
        if (num1 == 0 || index == files.size() - 1) {
            int32_t fileNum = num1 == 0 && num2 > 0 ? MAX_RESTORE_FILE_NUM : num1;
            int32_t beginOffset = index - fileNum + 1;
            if (beginOffset <= firstRestoreIndex) {
                // not contain first restore file
                beginOffset = firstRestoreIndex + 1;
                fileNum = index - beginOffset + 1;
            }
            int32_t notifyType = index == files.size() - 1 ? NOTIFY_LAST : NOTIFY_PROGRESS;
            vector<string> subFiles(files.begin() + beginOffset, files.begin() + index + 1);
            ffrt::submit(
                [this, &restoreTaskInfo, notifyType, subFiles]() {
                    HandleBatchCustomRestore(restoreTaskInfo, notifyType, subFiles);
                },
                {},
                {},
                ffrt::task_attr().qos(static_cast<int32_t>(ffrt::qos_utility)));
        }
    }

    ffrt::wait();
    ReleaseCustomRestoreTask(restoreTaskInfo);
}

void PhotoCustomRestoreOperation::PhotoCustomRestoreOperation::ReleaseCustomRestoreTask(
    RestoreTaskInfo &restoreTaskInfo)
{
    photoCache.clear();
    if (!MediaFileUtils::DeleteDir(restoreTaskInfo.sourceDir)) {
        MEDIA_ERR_LOG("delete dir failed. dir:%{public}s", restoreTaskInfo.sourceDir.c_str());
    }
    ReportCustomRestoreTask(restoreTaskInfo);
    if (IsCancelTask(restoreTaskInfo)) {
        CancelTaskFinish(restoreTaskInfo);
    }
}

void PhotoCustomRestoreOperation::ReportCustomRestoreTask(RestoreTaskInfo &restoreTaskInfo)
{
    restoreTaskInfo.endTime = MediaFileUtils::UTCTimeSeconds();
    CustomRestoreDfxDataPoint point;
    point.customRestorePackageName = restoreTaskInfo.packageName;
    point.albumLPath = restoreTaskInfo.albumLpath;
    point.keyPath = restoreTaskInfo.keyPath;
    point.totalNum = restoreTaskInfo.totalNum;
    point.successNum = successNum;
    point.failedNum = failNum;
    point.sameNum = sameNum;
    if (IsCancelTask(restoreTaskInfo)) {
        point.cancelNum = point.totalNum - point.successNum - point.sameNum - point.failedNum;
    } else {
        point.cancelNum = 0;
        point.failedNum = point.totalNum - point.successNum - point.sameNum;
    }
    point.totalTime = restoreTaskInfo.endTime - restoreTaskInfo.beginTime;
    MEDIA_ERR_LOG("report custom restore finished. cost:%{public}" PRId64, point.totalTime);
    DfxReporter::ReportCustomRestoreFusion(point);
}

bool PhotoCustomRestoreOperation::HandleFirstRestoreFile(
    RestoreTaskInfo &restoreTaskInfo, vector<string> &files, size_t &index, int32_t &firstRestoreIndex)
{
    vector<string> subFiles(files.begin() + index, files.begin() + index + 1);
    int32_t errCode = HandleCustomRestore(restoreTaskInfo, subFiles, true);
    bool isFirstRestoreSuccess = errCode == E_OK;
    if (!isFirstRestoreSuccess && index == files.size() - 1) {
        MEDIA_ERR_LOG("first file restore failed. stop restore task.");
        SendNotifyMessage(restoreTaskInfo, NOTIFY_FIRST, errCode, 1);
    }
    if (isFirstRestoreSuccess) {
        MEDIA_ERR_LOG("first file restore success.");
        firstRestoreIndex = index;
        int notifyType = index = files.size() - 1 ? NOTIFY_FIRST : NOTIFY_LAST;
        SendNotifyMessage(restoreTaskInfo, notifyType, errCode, 1);
    }
    return isFirstRestoreSuccess;
}

void PhotoCustomRestoreOperation::HandleBatchCustomRestore(
    RestoreTaskInfo &restoreTaskInfo, int32_t notifyType, vector<string> subFiles)
{
    if (IsCancelTask(restoreTaskInfo)) {
        return;
    }
    int32_t fileNum = subFiles.size();
    int32_t errCode = HandleCustomRestore(restoreTaskInfo, subFiles, false);
    SendNotifyMessage(restoreTaskInfo, notifyType, errCode, fileNum);
}

void PhotoCustomRestoreOperation::InitRestoreTask(RestoreTaskInfo &restoreTaskInfo, int32_t fileNum)
{
    successNum.store(0);
    failNum.store(0);
    sameNum.store(0);
    photoCache.clear();
    restoreTaskInfo.uriType = RESTORE_URI_TYPE_PHOTO;
    restoreTaskInfo.totalNum = fileNum;
    restoreTaskInfo.beginTime = MediaFileUtils::UTCTimeSeconds();
    ApplyEfficiencyQuota(fileNum);
    QueryAlbumId(restoreTaskInfo);
}

int32_t PhotoCustomRestoreOperation::HandleCustomRestore(
    RestoreTaskInfo &restoreTaskInfo, vector<string> filePathVector, bool isFirst)
{
    MEDIA_INFO_LOG("HandleCustomRestore begin. size: %{public}d, isFirst: %{public}d",
        static_cast<int32_t>(filePathVector.size()), isFirst ? 1 : 0);
    UniqueNumber uniqueNumber;
    vector<FileInfo> restoreFiles = GetFileInfos(filePathVector, uniqueNumber);
    MEDIA_INFO_LOG("GetFileInfos finished");

    int32_t errCode = UpdateUniqueNumber(uniqueNumber);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("UpdateUniqueNumber failed. errCode: %{public}d", errCode);
        return errCode;
    }
    MEDIA_INFO_LOG("UpdateUniqueNumber success.");

    vector<FileInfo> destRestoreFiles = SetDestinationPath(restoreFiles, uniqueNumber);
    if (destRestoreFiles.size() == 0) {
        MEDIA_ERR_LOG("restore file number is zero.");
        return E_ERR;
    }
    MEDIA_INFO_LOG("SetDestinationPath finished");

    int32_t sameFileNum = 0;
    vector<FileInfo> insertRestoreFiles = BatchInsert(restoreTaskInfo, destRestoreFiles, sameFileNum);
    MEDIA_INFO_LOG("BatchInsert success.");
    RenameFiles(insertRestoreFiles);
    MEDIA_INFO_LOG("RenameFiles finished.");

    if (isFirst) {
        if (insertRestoreFiles.size() == 0) {
            return E_ERR;
        }
        if (UpdatePhotoAlbum(restoreTaskInfo, insertRestoreFiles[0]) != E_OK) {
            MEDIA_ERR_LOG("UpdatePhotoAlbum failed.");
            return errCode;
        }
    }

    successNum.fetch_add(insertRestoreFiles.size());
    failNum.fetch_add(filePathVector.size() - insertRestoreFiles.size() - sameFileNum);
    MEDIA_INFO_LOG("HandleCustomRestore success.");
    return E_OK;
}

int32_t PhotoCustomRestoreOperation::UpdatePhotoAlbum(RestoreTaskInfo &restoreTaskInfo, FileInfo fileInfo)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        return E_HAS_DB_ERROR;
    }

    const string querySql = "SELECT " + MediaColumn::MEDIA_ID + "," + PhotoColumn::PHOTO_OWNER_ALBUM_ID + " FROM " +
                            PhotoColumn::PHOTOS_TABLE + " WHERE data ='" + fileInfo.filePath + "';";
    MEDIA_INFO_LOG("UpdatePhotoAlbum querySql:%{public}s", querySql.c_str());
    auto resultSet = rdbStore->QuerySql(querySql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return E_HAS_DB_ERROR;
    }
    int32_t fileId = GetInt32Val(PhotoColumn::MEDIA_ID, resultSet);
    int32_t albumId = GetInt32Val(PhotoColumn::PHOTO_OWNER_ALBUM_ID, resultSet);
    if (restoreTaskInfo.albumId == 0) {
        const string updateSql = "UPDATE " + PhotoAlbumColumns::TABLE + " SET " + PhotoAlbumColumns::ALBUM_LPATH +
                                 "='" + restoreTaskInfo.albumLpath + "' WHERE " + PhotoAlbumColumns::ALBUM_ID + "='" +
                                 to_string(albumId) + "';";
        MEDIA_INFO_LOG("UpdatePhotoAlbum updateSql:%{public}s", updateSql.c_str());
        int32_t errCode = rdbStore->ExecuteSql(updateSql);
        if (errCode < 0) {
            MEDIA_ERR_LOG("execute update unique number failed, ret=%{public}d", errCode);
            return errCode;
        }
    }

    restoreTaskInfo.firstFileId = fileId;
    string extrUri = MediaFileUtils::GetExtraUri(fileInfo.displayName, fileInfo.filePath);
    restoreTaskInfo.firstFileUri = MediaFileUtils::GetUriByExtrConditions(
        ML_FILE_URI_PREFIX + MediaFileUri::GetMediaTypeUri(fileInfo.mediaType, MEDIA_API_VERSION_V10) + "/",
        to_string(fileId),
        extrUri);
    if (restoreTaskInfo.uriType == RESTORE_URI_TYPE_PHOTO) {
        restoreTaskInfo.uri = restoreTaskInfo.firstFileUri;
    } else {
        restoreTaskInfo.uri = PhotoAlbumColumns::ALBUM_URI_PREFIX + to_string(albumId);
        restoreTaskInfo.albumId = albumId;
    }

    MEDIA_INFO_LOG("uriType:%{public}d  uri:%{public}s", restoreTaskInfo.uriType, restoreTaskInfo.uri.c_str());

    return E_OK;
}

void PhotoCustomRestoreOperation::SendPhotoAlbumNotify(RestoreTaskInfo &restoreTaskInfo, int32_t notifyType)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    MediaLibraryRdbUtils::UpdateSystemAlbumInternal(rdbStore, {to_string(PhotoAlbumSubType::IMAGE)});
    MediaLibraryRdbUtils::UpdateSystemAlbumInternal(rdbStore, {to_string(PhotoAlbumSubType::VIDEO)});
    std::string uri = PhotoColumn::PHOTO_URI_PREFIX + to_string(restoreTaskInfo.firstFileId);
    MediaLibraryRdbUtils::UpdateSourceAlbumByUri(rdbStore, {uri});
    MEDIA_INFO_LOG("UpdateSourceAlbumByUri finished. uri:%{public}s", uri.c_str());

    auto watch = MediaLibraryNotify::GetInstance();
    if (notifyType == NOTIFY_FIRST) {
        watch->Notify(restoreTaskInfo.firstFileUri, NOTIFY_ADD);
    } else {
        watch->Notify(PhotoColumn::PHOTO_URI_PREFIX, NOTIFY_ADD);
    }
    MEDIA_INFO_LOG("PhotoAlbumNotify finished.");
}

InnerRestoreResult PhotoCustomRestoreOperation::GenerateCustomRestoreNotify(
    RestoreTaskInfo &restoreTaskInfo, int32_t notifyType)
{
    InnerRestoreResult restoreResult;
    restoreResult.errCode = 0;
    restoreResult.stage = (notifyType == NOTIFY_LAST || notifyType == NOTIFY_CANCEL) ? "finished" : "onRestore";
    restoreResult.uriType = restoreTaskInfo.uriType;
    restoreResult.uri = restoreTaskInfo.uri;
    restoreResult.totalNum = restoreTaskInfo.totalNum;
    if (restoreTaskInfo.totalNum == 0) {
        restoreResult.successNum = 0;
        restoreResult.failedNum = 0;
        restoreResult.sameNum = 0;
        restoreResult.progress = 0;
        return restoreResult;
    }
    restoreResult.successNum = successNum;
    restoreResult.sameNum = sameNum;
    if (notifyType == NOTIFY_LAST) {
        restoreResult.failedNum = restoreTaskInfo.totalNum - restoreResult.successNum - restoreResult.sameNum;
    } else {
        restoreResult.failedNum = failNum;
    }
    restoreResult.cancelNum = 0;
    if (notifyType == NOTIFY_CANCEL) {
        restoreResult.cancelNum =
            restoreResult.totalNum - restoreResult.successNum - restoreResult.sameNum - restoreResult.failedNum;
    }
    restoreResult.progress = PROGRESS_MULTI_NUM *
                             (restoreResult.successNum + restoreResult.failedNum + restoreResult.sameNum) /
                             restoreTaskInfo.totalNum;
    return restoreResult;
}

void PhotoCustomRestoreOperation::SendNotifyMessage(
    RestoreTaskInfo &restoreTaskInfo, int32_t notifyType, int32_t errCode, int32_t fileNum)
{
    MEDIA_INFO_LOG("SendNotifyMessage restore retCode:%{public}d fileNum:%{public}d", errCode, fileNum);
    // notify album
    if (errCode == E_OK && successNum > 0) {
        SendPhotoAlbumNotify(restoreTaskInfo, notifyType);
    }

    if (errCode != E_OK) {
        failNum.fetch_add(fileNum);
    }

    InnerRestoreResult restoreResult = GenerateCustomRestoreNotify(restoreTaskInfo, notifyType);
    if (notifyType == NOTIFY_FIRST && errCode != E_OK) {
        restoreResult.stage = "finished";
        restoreResult.errCode = 1;
        restoreResult.progress = 0;
    }
    MEDIA_INFO_LOG("CustomRestoreNotify stage:%{public}s errCode:%{public}d progress:%{public}d",
        restoreResult.stage.c_str(), restoreResult.errCode, restoreResult.progress);
    MEDIA_INFO_LOG(
        "CustomRestoreNotify totalNum:%{public}d successNum:%{public}d failedNum:%{public}d sameNum:%{public}d",
        restoreResult.totalNum, restoreResult.successNum, restoreResult.failedNum, restoreResult.sameNum);
    MEDIA_INFO_LOG(
        "CustomRestoreNotify uriType:%{public}d uri:%{public}s", restoreResult.uriType, restoreResult.uri.c_str());
    CustomRestoreNotify customRestoreNotify;
    customRestoreNotify.Notify(restoreTaskInfo.keyPath, restoreResult);
    MEDIA_INFO_LOG("CustomRestoreNotify finished.");
}

vector<FileInfo> PhotoCustomRestoreOperation::SetDestinationPath(
    vector<FileInfo> &restoreFiles, UniqueNumber &uniqueNumber)
{
    vector<FileInfo> newRestoreFiles;
    for (auto &fileInfo : restoreFiles) {
        string mediaDirPath;
        int32_t mediaType = fileInfo.mediaType;
        GetAssetRootDir(mediaType, mediaDirPath);
        if (mediaDirPath.empty()) {
            MEDIA_ERR_LOG("get asset root dir failed. mediaType: %{public}d", mediaType);
            continue;
        }

        int32_t fileId = 0;
        if (fileInfo.mediaType == MediaType::MEDIA_TYPE_IMAGE) {
            fileId = uniqueNumber.imageCurrentNumber++;
        } else if (fileInfo.mediaType == MediaType::MEDIA_TYPE_VIDEO) {
            fileId = uniqueNumber.videoCurrentNumber++;
        }

        int32_t bucketNum = 0;
        int32_t retCode = MediaFileUri::CreateAssetBucket(fileId, bucketNum);
        if (retCode != E_OK) {
            MEDIA_ERR_LOG("CreateAssetBucket failed. bucketNum: %{public}d", bucketNum);
            continue;
        }

        string realName;
        retCode = MediaFileUtils::CreateAssetRealName(fileId, fileInfo.mediaType, fileInfo.extension, realName);
        if (retCode != E_OK) {
            MEDIA_ERR_LOG("CreateAssetRealName failed. retCode: %{public}d", retCode);
            continue;
        }

        string dirPath = ROOT_MEDIA_DIR + mediaDirPath + to_string(bucketNum);
        if (!MediaFileUtils::IsFileExists(dirPath)) {
            if (!MediaFileUtils::CreateDirectory(dirPath)) {
                MEDIA_ERR_LOG("CreateDirectory failed. retCode: %{public}s", dirPath.c_str());
                continue;
            }
        }

        fileInfo.filePath = dirPath + "/" + realName;
        MEDIA_INFO_LOG("SetDestinationPath filePath: %{public}s", fileInfo.filePath.c_str());
        newRestoreFiles.push_back(fileInfo);
    }

    return newRestoreFiles;
}

void PhotoCustomRestoreOperation::GetAssetRootDir(int32_t mediaType, string &rootDirPath)
{
    map<int, string> rootDir = {
        {MEDIA_TYPE_FILE, DOCUMENT_BUCKET + SLASH_CHAR},
        {MEDIA_TYPE_VIDEO, PHOTO_BUCKET + SLASH_CHAR},
        {MEDIA_TYPE_IMAGE, PHOTO_BUCKET + SLASH_CHAR},
        {MEDIA_TYPE_AUDIO, AUDIO_BUCKET + SLASH_CHAR},
    };
    if (rootDir.count(mediaType) == 0) {
        rootDirPath = rootDir[MEDIA_TYPE_FILE];
    } else {
        rootDirPath = rootDir[mediaType];
    }
}

vector<FileInfo> PhotoCustomRestoreOperation::BatchInsert(
    RestoreTaskInfo &restoreTaskInfo, vector<FileInfo> &restoreFiles, int32_t &sameFileNum)
{
    vector<FileInfo> insertFiles;
    vector<NativeRdb::ValuesBucket> values;
    for (auto &fileInfo : restoreFiles) {
        NativeRdb::ValuesBucket value = GetInsertValue(restoreTaskInfo, fileInfo);
        if (!IsDuplication(restoreTaskInfo, fileInfo)) {
            values.push_back(value);
            insertFiles.push_back(fileInfo);
        }
    }
    sameFileNum = restoreFiles.size() - insertFiles.size();
    sameNum.fetch_add(sameFileNum);
    MEDIA_INFO_LOG("BatchInsert values size: %{public}d, sameNum:%{public}d",
        static_cast<int32_t>(values.size()), sameFileNum);
    if (values.size() == 0) {
        return insertFiles;
    }

    int64_t rowNum = 0;
    int32_t errCode = E_ERR;
    TransactionOperations trans{__func__};
    std::function<int(void)> func = [&]() -> int {
        errCode = trans.BatchInsert(rowNum, PhotoColumn::PHOTOS_TABLE, values);
        if (errCode != E_OK) {
            MEDIA_ERR_LOG("BatchInsert failed, errCode: %{public}d, rowNum: %{public}" PRId64, errCode, rowNum);
        }
        return errCode;
    };

    errCode = trans.RetryTrans(func, false);
    if (errCode != E_OK) {
        insertFiles.clear();
        MEDIA_ERR_LOG("RetryTrans: trans retry fail!, ret:%{public}d", errCode);
        return insertFiles;
    }
    MEDIA_INFO_LOG("BatchInsert success rowNum: %{public}" PRId64, rowNum);
    return insertFiles;
}

void PhotoCustomRestoreOperation::QueryAlbumId(RestoreTaskInfo &restoreTaskInfo)
{
    const string querySql = "SELECT " + PhotoAlbumColumns::ALBUM_ID + " FROM " + PhotoAlbumColumns::TABLE + " WHERE " +
                            PhotoAlbumColumns::ALBUM_LPATH + "='" + restoreTaskInfo.albumLpath + "';";
    MEDIA_ERR_LOG("QueryAlbumId querySql:%{public}s", querySql.c_str());
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        return;
    }
    auto resultSet = rdbStore->QuerySql(querySql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return;
    }
    int32_t albumId = GetInt32Val(PhotoAlbumColumns::ALBUM_ID, resultSet);
    if (albumId > 0) {
        restoreTaskInfo.albumId = albumId;
        MEDIA_ERR_LOG("QueryAlbumId albumId:%{public}d", albumId);
        InitPhotoCache(restoreTaskInfo);
    } else {
        MEDIA_INFO_LOG("album is not exits, skip check duplication.");
        restoreTaskInfo.isDeduplication = false;
    }
}

bool PhotoCustomRestoreOperation::IsDuplication(RestoreTaskInfo &restoreTaskInfo, FileInfo &fileInfo)
{
    if (!restoreTaskInfo.isDeduplication || restoreTaskInfo.albumId == 0) {
        return false;
    }
    int32_t mediaType = fileInfo.mediaType;
    if (restoreTaskInfo.hasPhotoCache) {
        string photoId = fileInfo.fileName + "_" + to_string(fileInfo.size) + "_" + to_string(mediaType) + "_" +
                         to_string(fileInfo.orientation);
        return photoCache.count(photoId) > 0;
    }
    const string querySql =
        "SELECT COUNT(1) as count FROM " + PhotoColumn::PHOTOS_TABLE + " WHERE " + PhotoColumn::PHOTO_OWNER_ALBUM_ID +
        "=" + to_string(restoreTaskInfo.albumId) + " AND " + MediaColumn::MEDIA_NAME + "='" + fileInfo.fileName +
        "' AND " + MediaColumn::MEDIA_SIZE + "=" + to_string(fileInfo.size) + " AND " + MediaColumn::MEDIA_TYPE + "=" +
        to_string(mediaType) + " AND " + PhotoColumn::PHOTO_ORIENTATION + "=" + to_string(fileInfo.orientation) + ";";
    MEDIA_ERR_LOG("IsDuplication querySql:%{public}s", querySql.c_str());
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        return false;
    }
    auto resultSet = rdbStore->QuerySql(querySql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return false;
    }
    int32_t count = GetInt32Val("count", resultSet);
    return count > 0;
}

int32_t PhotoCustomRestoreOperation::InitPhotoCache(RestoreTaskInfo &restoreTaskInfo)
{
    if (!restoreTaskInfo.isDeduplication || restoreTaskInfo.albumId == 0) {
        return E_OK;
    }
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        return E_HAS_DB_ERROR;
    }
    const string queryCountSql = "SELECT COUNT(1) as count FROM " + PhotoColumn::PHOTOS_TABLE + " WHERE " +
                                 PhotoColumn::PHOTO_OWNER_ALBUM_ID + "=" + to_string(restoreTaskInfo.albumId) + ";";
    MEDIA_ERR_LOG("InitPhotoCache queryCountSql:%{public}s", queryCountSql.c_str());
    auto resultSet = rdbStore->QuerySql(queryCountSql);
    if (resultSet == nullptr) {
        return E_HAS_DB_ERROR;
    }
    int32_t count = GetInt32Val("count", resultSet);
    if (count > MAX_PHOTO_CACHE_NUM) {
        MEDIA_WARN_LOG("album has more than %{public}d, skip create cache.", MAX_PHOTO_CACHE_NUM);
        return E_OK;
    }

    const string queryCacheSql = "SELECT " + MediaColumn::MEDIA_NAME + "," + MediaColumn::MEDIA_SIZE + "," +
                                 MediaColumn::MEDIA_TYPE + "," + PhotoColumn::PHOTO_ORIENTATION + " FROM " +
                                 PhotoColumn::PHOTOS_TABLE + " WHERE " + PhotoColumn::PHOTO_OWNER_ALBUM_ID + "=" +
                                 to_string(restoreTaskInfo.albumId) + ";";
    MEDIA_ERR_LOG("InitPhotoCache queryCacheSql:%{public}s", queryCacheSql.c_str());
    auto resultCacheSet = rdbStore->QuerySql(queryCacheSql);
    if (resultCacheSet == nullptr) {
        return E_HAS_DB_ERROR;
    }
    while (resultCacheSet->GoToNextRow() == NativeRdb::E_OK) {
        string displayName = GetStringVal(MediaColumn::MEDIA_NAME, resultCacheSet);
        int64_t mediaSize = GetInt64Val(MediaColumn::MEDIA_SIZE, resultCacheSet);
        int32_t mediaType = GetInt32Val(MediaColumn::MEDIA_TYPE, resultCacheSet);
        int32_t orientation = GetInt32Val(PhotoColumn::PHOTO_ORIENTATION, resultCacheSet);
        photoCache.insert(
            displayName + "_" + to_string(mediaSize) + "_" + to_string(mediaType) + "_" + to_string(orientation));
    }
    restoreTaskInfo.hasPhotoCache = true;
    MEDIA_ERR_LOG("InitPhotoCache success, num:%{public}d", static_cast<int32_t>(photoCache.size()));
    return E_OK;
}

int32_t PhotoCustomRestoreOperation::UpdateUniqueNumber(UniqueNumber &uniqueNumber)
{
    int32_t errCode = CreateAssetUniqueNumber(MediaType::MEDIA_TYPE_IMAGE, uniqueNumber);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("CreateAssetUniqueNumber IMAGE fail!, ret:%{public}d", errCode);
        return errCode;
    }
    MEDIA_INFO_LOG("imageTotalNumber: %{public}d imageCurrentNumber: %{public}d",
        uniqueNumber.imageTotalNumber, uniqueNumber.imageCurrentNumber);
    errCode = CreateAssetUniqueNumber(MediaType::MEDIA_TYPE_VIDEO, uniqueNumber);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("CreateAssetUniqueNumber VIDEO fail!, ret:%{public}d", errCode);
        return errCode;
    }
    MEDIA_INFO_LOG("videoTotalNumber: %{public}d videoCurrentNumber: %{public}d",
        uniqueNumber.videoTotalNumber, uniqueNumber.videoCurrentNumber);
    return E_OK;
}

int32_t PhotoCustomRestoreOperation::CreateAssetUniqueNumber(int32_t type, UniqueNumber &uniqueNumber)
{
    string typeString;
    int num = 0;
    if (type == MediaType::MEDIA_TYPE_IMAGE) {
        typeString += IMAGE_ASSET_TYPE;
        num = uniqueNumber.imageTotalNumber;
    }
    if (type == MediaType::MEDIA_TYPE_VIDEO) {
        typeString += VIDEO_ASSET_TYPE;
        num = uniqueNumber.videoTotalNumber;
    }
    if (num == 0) {
        return E_OK;
    }

    const string updateSql = "UPDATE " + ASSET_UNIQUE_NUMBER_TABLE + " SET " + UNIQUE_NUMBER + "=" + UNIQUE_NUMBER +
                             "+" + to_string(num) + " WHERE " + ASSET_MEDIA_TYPE + "='" + typeString + "';";
    const string querySql = "SELECT " + UNIQUE_NUMBER + " FROM " + ASSET_UNIQUE_NUMBER_TABLE + " WHERE " +
                            ASSET_MEDIA_TYPE + "='" + typeString + "';";

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        return E_HAS_DB_ERROR;
    }
    lock_guard<mutex> lock(g_uniqueNumberLock_);
    int32_t errCode = rdbStore->ExecuteSql(updateSql);
    if (errCode < 0) {
        MEDIA_ERR_LOG("execute update unique number failed, ret=%{public}d", errCode);
        return errCode;
    }

    auto resultSet = rdbStore->QuerySql(querySql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return E_HAS_DB_ERROR;
    }
    int32_t endUniqueNumber = GetInt32Val(UNIQUE_NUMBER, resultSet);
    int32_t startUniqueNumber = endUniqueNumber - num + 1;

    MEDIA_INFO_LOG("CreateAssetUniqueNumber updateSql: %{public}s  startUniqueNumber: %{public}d",
        updateSql.c_str(), startUniqueNumber);

    if (type == MediaType::MEDIA_TYPE_IMAGE) {
        uniqueNumber.imageCurrentNumber = startUniqueNumber;
    }
    if (type == MediaType::MEDIA_TYPE_VIDEO) {
        uniqueNumber.videoCurrentNumber = startUniqueNumber;
    }
    return E_OK;
}

NativeRdb::ValuesBucket PhotoCustomRestoreOperation::GetInsertValue(
    RestoreTaskInfo &restoreTaskInfo, FileInfo &fileInfo)
{
    NativeRdb::ValuesBucket value;
    value.PutString(MediaColumn::MEDIA_FILE_PATH, fileInfo.filePath);
    value.PutString(MediaColumn::MEDIA_TITLE, fileInfo.title);
    value.PutString(MediaColumn::MEDIA_NAME, fileInfo.displayName);
    value.PutString(MediaColumn::MEDIA_PACKAGE_NAME, restoreTaskInfo.packageName);
    value.PutString(MediaColumn::MEDIA_OWNER_PACKAGE, restoreTaskInfo.bundleName);
    value.PutString(MediaColumn::MEDIA_OWNER_APPID, restoreTaskInfo.appId);
    MEDIA_INFO_LOG("GetInsertValue filePath:%{public}s", fileInfo.filePath.c_str());
    MEDIA_INFO_LOG("GetInsertValue bundleName:%{public}s", restoreTaskInfo.bundleName.c_str());
    MEDIA_INFO_LOG("GetInsertValue packageName:%{public}s", restoreTaskInfo.packageName.c_str());

    std::unique_ptr<Metadata> data = make_unique<Metadata>();
    data->SetFilePath(fileInfo.originFilePath);
    data->SetFileName(fileInfo.fileName);
    data->SetFileMediaType(fileInfo.mediaType);
    FillMetadata(data);

    fileInfo.size = data->GetFileSize();
    fileInfo.orientation = data->GetOrientation();
    
    value.PutString(MediaColumn::MEDIA_FILE_PATH, data->GetFilePath());
    value.PutString(MediaColumn::MEDIA_MIME_TYPE, data->GetFileMimeType());
    value.PutInt(MediaColumn::MEDIA_TYPE, fileInfo.mediaType);
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
    value.PutInt(PhotoColumn::PHOTO_DYNAMIC_RANGE_TYPE, data->GetDynamicRangeType());

    return value;
}

vector<FileInfo> PhotoCustomRestoreOperation::GetFileInfos(vector<string> &filePathVector, UniqueNumber &uniqueNumber)
{
    vector<FileInfo> restoreFiles;
    for (auto &filePath : filePathVector) {
        FileInfo fileInfo;
        fileInfo.fileName = MediaFileUtils::GetFileName(filePath);
        fileInfo.displayName = fileInfo.fileName;
        fileInfo.originFilePath = filePath;
        fileInfo.extension = ScannerUtils::GetFileExtension(fileInfo.fileName);
        fileInfo.title = ScannerUtils::GetFileTitle(fileInfo.fileName);
        fileInfo.mediaType = MediaFileUtils::GetMediaType(fileInfo.fileName);
        if (fileInfo.mediaType == MediaType::MEDIA_TYPE_FILE) {
            fileInfo.mediaType = MediaFileUtils::GetMediaTypeNotSupported(fileInfo.fileName);
            if (fileInfo.mediaType == MediaType::MEDIA_TYPE_IMAGE ||
                fileInfo.mediaType == MediaType::MEDIA_TYPE_VIDEO) {
                MEDIA_WARN_LOG(
                    "single frame is not support This media type. fileName:%{public}s", fileInfo.fileName.c_str());
            }
        }
        if (fileInfo.mediaType == MediaType::MEDIA_TYPE_IMAGE) {
            uniqueNumber.imageTotalNumber++;
        } else if (fileInfo.mediaType == MediaType::MEDIA_TYPE_VIDEO) {
            uniqueNumber.videoTotalNumber++;
        } else {
            MEDIA_ERR_LOG(
                "This media type[%{public}s] is not image or video, skip restore.", fileInfo.extension.c_str());
            continue;
        }
        restoreFiles.push_back(fileInfo);
    }
    return restoreFiles;
}

int32_t PhotoCustomRestoreOperation::FillMetadata(std::unique_ptr<Metadata> &data)
{
    int32_t err = GetFileMetadata(data);
    if (err != E_OK) {
        MEDIA_ERR_LOG("failed to get file metadata");
        return err;
    }
    if (data->GetFileMediaType() == MEDIA_TYPE_IMAGE) {
        err = MetadataExtractor::ExtractImageMetadata(data);
    } else {
        err = MetadataExtractor::ExtractAVMetadata(data, Scene::AV_META_SCENE_CLONE);
        MEDIA_INFO_LOG("Extract av metadata end");
    }
    if (err != E_OK) {
        MEDIA_ERR_LOG("failed to extension data");
        return err;
    }
    return E_OK;
}

int32_t PhotoCustomRestoreOperation::GetFileMetadata(std::unique_ptr<Metadata> &data)
{
    struct stat statInfo {};
    if (stat(data->GetFilePath().c_str(), &statInfo) != 0) {
        MEDIA_ERR_LOG("stat syscall err %{public}d", errno);
        return E_FAIL;
    }
    data->SetFileSize(statInfo.st_size);
    auto dateModified = static_cast<int64_t>(MediaFileUtils::Timespec2Millisecond(statInfo.st_mtim));
    if (dateModified == 0) {
        dateModified = MediaFileUtils::UTCTimeMilliSeconds();
        MEDIA_WARN_LOG("Invalid dateModified from st_mtim, use current time instead: %{public}lld",
            static_cast<long long>(dateModified));
    }
    if (dateModified != 0 && data->GetFileDateModified() == 0) {
        data->SetFileDateModified(dateModified);
    }
    string extension = ScannerUtils::GetFileExtension(data->GetFileName());
    string mimeType = MimeTypeUtils::GetMimeTypeFromExtension(extension);
    data->SetFileExtension(extension);
    data->SetFileMimeType(mimeType);
    return E_OK;
}

void PhotoCustomRestoreOperation::RenameFiles(vector<FileInfo> &restoreFiles)
{
    for (auto &fileInfo : restoreFiles) {
        if (!MediaFileUtils::MoveFile(fileInfo.originFilePath, fileInfo.filePath)) {
            MEDIA_ERR_LOG("MoveFile failed. srcFile:%{public}s, destFile:%{public}s",
                fileInfo.originFilePath.c_str(),
                fileInfo.filePath.c_str());
        }
    }
}
}  // namespace OHOS::Media