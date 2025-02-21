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
#define MLOG_TAG "PhotoCustomRestoreOperation"

#include "photo_custom_restore_operation.h"

#include <dirent.h>
#include <dlfcn.h>
#include <thread>

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
#include "moving_photo_file_utils.h"
#include "photo_album_column.h"
#include "photo_file_utils.h"
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
        MEDIA_WARN_LOG("custom restore operation is running. skip start");
        return *this;
    }
    CleanTimeoutCustomRestoreTaskDir();
    while (!this->taskQueue_.empty()) {
        RestoreTaskInfo restoreTaskInfo = this->taskQueue_.front();
        if (IsCancelTask(restoreTaskInfo)) {
            CancelTaskFinish(restoreTaskInfo);
            this->taskQueue_.pop();
            continue;
        }
        DoCustomRestore(restoreTaskInfo);
        this->taskQueue_.pop();
    }
    {
        std::unique_lock<std::shared_mutex> lockGuard(cancelOprationLock_);
        cancelKeySet_.clear();
    }
    this->isRunning_.store(false);
    return *this;
}

void PhotoCustomRestoreOperation::CancelTask(RestoreTaskInfo restoreTaskInfo)
{
    MEDIA_INFO_LOG("cancel custom restore task. keyPath: %{public}s", restoreTaskInfo.keyPath.c_str());
    std::unique_lock<std::shared_mutex> lockGuard(cancelOprationLock_);
    cancelKeySet_.insert(restoreTaskInfo.keyPath);
}

bool PhotoCustomRestoreOperation::IsCancelTask(RestoreTaskInfo &restoreTaskInfo)
{
    std::shared_lock<std::shared_mutex> lockGuard(cancelOprationLock_);
    return cancelKeySet_.count(restoreTaskInfo.keyPath) > 0;
}

void PhotoCustomRestoreOperation::CancelTaskFinish(RestoreTaskInfo &restoreTaskInfo)
{
    UniqueNumber uniqueNumber;
    SendNotifyMessage(restoreTaskInfo, NOTIFY_CANCEL, E_OK, 0, uniqueNumber);
    std::unique_lock<std::shared_mutex> lockGuard(cancelOprationLock_);
    cancelKeySet_.erase(restoreTaskInfo.keyPath);
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
    MEDIA_DEBUG_LOG("ApplyEfficiencyQuota. quota: %{public}" PRId64, quota);
    void *resourceQuotaMgrHandle = dlopen(ABNORMAL_MANAGER_LIB.c_str(), RTLD_NOW);
    if (!resourceQuotaMgrHandle) {
        MEDIA_ERR_LOG("Not find resource_quota_manager lib.");
        return;
    }
    using HandleQuotaFunc = bool (*)(const std::string &, uint32_t, int64_t, const std::string &);
    auto handleQuotaFunc =
        reinterpret_cast<HandleQuotaFunc>(dlsym(resourceQuotaMgrHandle, "ApplyAbnormalControlQuota"));
    if (!handleQuotaFunc) {
        MEDIA_ERR_LOG("Not find ApplyAbnormalControlQuota func.");
        dlclose(resourceQuotaMgrHandle);
        return;
    }
    if (!handleQuotaFunc(module, MODULE_POWER_OVERUSED, quota, reason)) {
        MEDIA_ERR_LOG("Do handleQuotaFunc failed.");
    }
    dlclose(resourceQuotaMgrHandle);
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
    int32_t total = static_cast<int32_t>(files.size());
    int32_t lastIndex = total - 1;
    for (int32_t index = 0; index < total; index++) {
        if (IsCancelTask(restoreTaskInfo)) {
            break;
        }
        if (index == 0 || !isFirstRestoreSuccess) {
            isFirstRestoreSuccess = HandleFirstRestoreFile(restoreTaskInfo, files, index, firstRestoreIndex);
            if (!isFirstRestoreSuccess && index == lastIndex) {
                break;
            }
            continue;
        }
        // Remainder and multiple of MAX_RESTORE_FILE_NUM
        int32_t remainder = (index + 1) % MAX_RESTORE_FILE_NUM;
        int32_t multiples = (index + 1) / MAX_RESTORE_FILE_NUM;
        if (remainder == 0 || index == lastIndex) {
            int32_t fileNum = remainder == 0 && multiples > 0 ? MAX_RESTORE_FILE_NUM : remainder;
            int32_t beginOffset = index - fileNum + 1;
            if (beginOffset <= firstRestoreIndex) {
                // not contain first restore file
                beginOffset = firstRestoreIndex + 1;
                fileNum = index - beginOffset + 1;
            }
            int32_t notifyType = index == lastIndex ? NOTIFY_LAST : NOTIFY_PROGRESS;
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
    photoCache_.clear();
    if (!MediaFileUtils::DeleteDir(restoreTaskInfo.sourceDir)) {
        MEDIA_ERR_LOG("delete dir failed.");
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
    point.successNum = successNum_;
    point.failedNum = failNum_;
    point.sameNum = sameNum_;
    if (IsCancelTask(restoreTaskInfo)) {
        point.cancelNum = point.totalNum - point.successNum - point.sameNum - point.failedNum;
    } else {
        point.cancelNum = 0;
        point.failedNum = point.totalNum - point.successNum - point.sameNum;
    }
    point.totalTime = static_cast<uint64_t>(restoreTaskInfo.endTime - restoreTaskInfo.beginTime);
    MEDIA_INFO_LOG("report custom restore finished. cost:%{public}" PRId64, point.totalTime);
    DfxReporter::ReportCustomRestoreFusion(point);
}

bool PhotoCustomRestoreOperation::HandleFirstRestoreFile(
    RestoreTaskInfo &restoreTaskInfo, vector<string> &files, int32_t index, int32_t &firstRestoreIndex)
{
    vector<string> subFiles(files.begin() + index, files.begin() + index + 1);
    UniqueNumber uniqueNumber;
    int32_t errCode = HandleCustomRestore(restoreTaskInfo, subFiles, true, uniqueNumber);
    bool isFirstRestoreSuccess = errCode == E_OK;
    int32_t lastIndex = static_cast<int32_t>(files.size() - 1);
    if (!isFirstRestoreSuccess && index == lastIndex) {
        MEDIA_ERR_LOG("first file restore failed. stop restore task.");
        SendNotifyMessage(restoreTaskInfo, NOTIFY_FIRST, errCode, 1, uniqueNumber);
    }
    if (isFirstRestoreSuccess) {
        MEDIA_ERR_LOG("first file restore success.");
        firstRestoreIndex = index;
        int notifyType = index == lastIndex ? NOTIFY_LAST : NOTIFY_FIRST;
        SendNotifyMessage(restoreTaskInfo, notifyType, errCode, 1, uniqueNumber);
    }
    return isFirstRestoreSuccess;
}

void PhotoCustomRestoreOperation::HandleBatchCustomRestore(
    RestoreTaskInfo &restoreTaskInfo, int32_t notifyType, vector<string> subFiles)
{
    if (IsCancelTask(restoreTaskInfo)) {
        return;
    }
    int32_t fileNum = static_cast<int32_t>(subFiles.size());
    UniqueNumber uniqueNumber;
    int32_t errCode = HandleCustomRestore(restoreTaskInfo, subFiles, false, uniqueNumber);
    SendNotifyMessage(restoreTaskInfo, notifyType, errCode, fileNum, uniqueNumber);
}

void PhotoCustomRestoreOperation::InitRestoreTask(RestoreTaskInfo &restoreTaskInfo, int32_t fileNum)
{
    successNum_.store(0);
    failNum_.store(0);
    sameNum_.store(0);
    photoCache_.clear();
    restoreTaskInfo.uriType = RESTORE_URI_TYPE_PHOTO;
    restoreTaskInfo.totalNum = fileNum;
    restoreTaskInfo.beginTime = MediaFileUtils::UTCTimeSeconds();
    std::thread applyEfficiencyQuotaThread([this, fileNum] { ApplyEfficiencyQuota(fileNum); });
    applyEfficiencyQuotaThread.detach();
    QueryAlbumId(restoreTaskInfo);
    GetAlbumUriBySubType(PhotoAlbumSubType::IMAGE, restoreTaskInfo.imageAlbumUri);
    GetAlbumUriBySubType(PhotoAlbumSubType::VIDEO, restoreTaskInfo.videoAlbumUri);
}

int32_t PhotoCustomRestoreOperation::HandleCustomRestore(
    RestoreTaskInfo &restoreTaskInfo, vector<string> filePathVector, bool isFirst,
    UniqueNumber &uniqueNumber)
{
    MEDIA_DEBUG_LOG("HandleCustomRestore begin. size: %{public}d, isFirst: %{public}d",
        static_cast<int32_t>(filePathVector.size()), isFirst ? 1 : 0);
    vector<FileInfo> restoreFiles = GetFileInfos(filePathVector, uniqueNumber);
    MEDIA_DEBUG_LOG("GetFileInfos finished");
    int32_t errCode = UpdateUniqueNumber(uniqueNumber);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("UpdateUniqueNumber failed. errCode: %{public}d", errCode);
        return errCode;
    }
    MEDIA_DEBUG_LOG("UpdateUniqueNumber success.");
    vector<FileInfo> destRestoreFiles = SetDestinationPath(restoreFiles, uniqueNumber);
    if (destRestoreFiles.size() == 0) {
        MEDIA_ERR_LOG("restore file number is zero.");
        return E_ERR;
    }
    MEDIA_DEBUG_LOG("SetDestinationPath finished");
    int32_t sameFileNum = 0;
    vector<FileInfo> insertRestoreFiles = BatchInsert(restoreTaskInfo, destRestoreFiles, sameFileNum);
    MEDIA_DEBUG_LOG("BatchInsert success.");
    int32_t successFileNum = RenameFiles(insertRestoreFiles);
    MEDIA_DEBUG_LOG("RenameFiles finished.");
    if (isFirst) {
        if (successFileNum == 0) {
            return E_ERR;
        }
        if (UpdatePhotoAlbum(restoreTaskInfo, insertRestoreFiles[0]) != E_OK) {
            MEDIA_ERR_LOG("UpdatePhotoAlbum failed.");
            return errCode;
        }
    }
    int32_t totalFileNum = static_cast<int32_t>(filePathVector.size());
    successNum_.fetch_add(successFileNum);
    failNum_.fetch_add(totalFileNum - successFileNum - sameFileNum);
    MEDIA_DEBUG_LOG("HandleCustomRestore success.");
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
    auto resultSet = rdbStore->QuerySql(querySql);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("execute select unique number failed.");
        return E_HAS_DB_ERROR;
    }
    if (resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("execute GoToFirstRow err.");
        resultSet->Close();
        return E_HAS_DB_ERROR;
    }
    int32_t fileId = GetInt32Val(PhotoColumn::MEDIA_ID, resultSet);
    int32_t albumId = GetInt32Val(PhotoColumn::PHOTO_OWNER_ALBUM_ID, resultSet);
    resultSet->Close();
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
    }
    restoreTaskInfo.albumId = albumId;
    return E_OK;
}

void PhotoCustomRestoreOperation::SendPhotoAlbumNotify(RestoreTaskInfo &restoreTaskInfo, int32_t notifyType,
    const UniqueNumber &uniqueNumber)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniqueNumber.imageTotalNumber > 0) {
        MediaLibraryRdbUtils::UpdateSystemAlbumInternal(rdbStore, {to_string(PhotoAlbumSubType::IMAGE)});
    }
    if (uniqueNumber.videoTotalNumber > 0) {
        MediaLibraryRdbUtils::UpdateSystemAlbumInternal(rdbStore, {to_string(PhotoAlbumSubType::VIDEO)});
    }
    std::string uri = PhotoColumn::PHOTO_URI_PREFIX + to_string(restoreTaskInfo.firstFileId);
    MediaLibraryRdbUtils::UpdateSourceAlbumByUri(rdbStore, {uri});
    MEDIA_DEBUG_LOG("UpdateSourceAlbumByUri finished.");
    auto watch = MediaLibraryNotify::GetInstance();
    CHECK_AND_RETURN_LOG(watch != nullptr, "Can not get MediaLibraryNotify Instance");
    if (notifyType == NOTIFY_FIRST) {
        watch->Notify(restoreTaskInfo.firstFileUri, NOTIFY_ADD);
    } else {
        watch->Notify(PhotoColumn::PHOTO_URI_PREFIX, NOTIFY_ADD);
    }
    std::string albumUri =
        MediaFileUtils::GetUriByExtrConditions(PhotoAlbumColumns::ALBUM_URI_PREFIX, to_string(restoreTaskInfo.albumId));
    watch->Notify(albumUri, NotifyType::NOTIFY_UPDATE);
    if (uniqueNumber.imageTotalNumber > 0) {
        watch->Notify(restoreTaskInfo.imageAlbumUri, NotifyType::NOTIFY_UPDATE);
    }
    if (uniqueNumber.videoTotalNumber > 0) {
        watch->Notify(restoreTaskInfo.videoAlbumUri, NotifyType::NOTIFY_UPDATE);
    }
    MEDIA_DEBUG_LOG("PhotoAlbumNotify finished.");
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
    restoreResult.successNum = successNum_;
    restoreResult.sameNum = sameNum_;
    if (notifyType == NOTIFY_LAST) {
        restoreResult.failedNum = restoreTaskInfo.totalNum - restoreResult.successNum - restoreResult.sameNum;
    } else {
        restoreResult.failedNum = failNum_;
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
    RestoreTaskInfo &restoreTaskInfo, int32_t notifyType, int32_t errCode, int32_t fileNum,
    const UniqueNumber &uniqueNumber)
{
    // notify album
    if (errCode == E_OK && successNum_ > 0) {
        SendPhotoAlbumNotify(restoreTaskInfo, notifyType, uniqueNumber);
    }
    if (errCode != E_OK) {
        failNum_.fetch_add(fileNum);
    }
    InnerRestoreResult restoreResult = GenerateCustomRestoreNotify(restoreTaskInfo, notifyType);
    if (notifyType == NOTIFY_FIRST && errCode != E_OK) {
        restoreResult.stage = "finished";
        restoreResult.errCode = 1;
        restoreResult.progress = 0;
        restoreResult.uri = "";
    }
    MEDIA_DEBUG_LOG("CustomRestoreNotify stage:%{public}s errCode:%{public}d progress:%{public}d",
        restoreResult.stage.c_str(), restoreResult.errCode, restoreResult.progress);
    MEDIA_DEBUG_LOG(
        "CustomRestoreNotify totalNum:%{public}d successNum:%{public}d failedNum:%{public}d sameNum:%{public}d",
        restoreResult.totalNum, restoreResult.successNum, restoreResult.failedNum, restoreResult.sameNum);
    CustomRestoreNotify customRestoreNotify;
    customRestoreNotify.Notify(restoreTaskInfo.keyPath, restoreResult);
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
        fileInfo.fileId = fileId;
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
    sameFileNum = static_cast<int32_t>(restoreFiles.size() - insertFiles.size());
    sameNum_.fetch_add(sameFileNum);
    MEDIA_DEBUG_LOG("BatchInsert values size: %{public}d, sameNum:%{public}d",
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
    MEDIA_DEBUG_LOG("BatchInsert success rowNum: %{public}" PRId64, rowNum);
    return insertFiles;
}

void PhotoCustomRestoreOperation::QueryAlbumId(RestoreTaskInfo &restoreTaskInfo)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("QueryAlbumId: get rdb store fail!");
        return;
    }

    const string queryAlbumPathSql =
        "SELECT lpath from album_plugin WHERE (bundle_name = ? OR album_name = ?) AND priority = '1';";
    std::vector<NativeRdb::ValueObject> albumPathParams = {restoreTaskInfo.bundleName, restoreTaskInfo.packageName};
    auto albumPathResult = rdbStore->QuerySql(queryAlbumPathSql, albumPathParams);
    string lpath;
    if (albumPathResult == nullptr) {
        MEDIA_ERR_LOG("QueryAlbumId: query album_plugin failed!");
    } else if (albumPathResult->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_WARN_LOG("QueryAlbumId: album_plugin have no record!");
        albumPathResult->Close();
    } else {
        lpath = GetStringVal("lpath", albumPathResult);
        albumPathResult->Close();
    }
    if (lpath.empty()) {
        lpath = ALBUM_PATH_PREFIX + restoreTaskInfo.packageName;
    }
 
    const string querySql = "SELECT " + PhotoAlbumColumns::ALBUM_ID + " FROM " + PhotoAlbumColumns::TABLE + " WHERE " +
                            PhotoAlbumColumns::ALBUM_LPATH + " = ? ;";
    std::vector<NativeRdb::ValueObject> params = {lpath};
    auto resultSet = rdbStore->QuerySql(querySql, params);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("QueryAlbumId: query PhotoAlbum failed!");
        return;
    }
    if (resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_WARN_LOG("album is not exits, skip check duplication.");
        restoreTaskInfo.isDeduplication = false;
        resultSet->Close();
        return;
    }
    int32_t albumId = GetInt32Val(PhotoAlbumColumns::ALBUM_ID, resultSet);
    resultSet->Close();
    if (albumId > 0) {
        restoreTaskInfo.albumId = albumId;
        MEDIA_ERR_LOG("QueryAlbumId albumId:%{public}d", albumId);
        InitPhotoCache(restoreTaskInfo);
    }
}

int32_t PhotoCustomRestoreOperation::GetAlbumUriBySubType(int32_t subType, string &albumUri)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("GetAlbumUriBySubType: get rdb store fail!");
        return E_HAS_DB_ERROR;
    }
    const string querySql = "SELECT " + PhotoAlbumColumns::ALBUM_ID + " FROM " + PhotoAlbumColumns::TABLE + " WHERE " +
        PhotoAlbumColumns::ALBUM_SUBTYPE + " = ? ;";
    std::vector<NativeRdb::ValueObject> params = {subType};
    auto resultSet = rdbStore->QuerySql(querySql, params);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("GetAlbumUriBySubType: query PhotoAlbum failed! subType=%{public}d", subType);
        return E_HAS_DB_ERROR;
    }
    if (resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("GetAlbumUriBySubType first row empty.");
        resultSet->Close();
        return E_HAS_DB_ERROR;
    }
    int32_t albumId = GetInt32Val(PhotoAlbumColumns::ALBUM_ID, resultSet);
    resultSet->Close();
    albumUri = MediaFileUtils::GetUriByExtrConditions(PhotoAlbumColumns::ALBUM_URI_PREFIX, to_string(albumId));
    return E_OK;
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
        return photoCache_.count(photoId) > 0;
    }
    const string querySql =
        "SELECT COUNT(1) as count FROM " + PhotoColumn::PHOTOS_TABLE + " WHERE " + PhotoColumn::PHOTO_OWNER_ALBUM_ID +
        "=" + to_string(restoreTaskInfo.albumId) + " AND " + MediaColumn::MEDIA_NAME + "='" + fileInfo.fileName +
        "' AND " + MediaColumn::MEDIA_SIZE + "=" + to_string(fileInfo.size) + " AND " + MediaColumn::MEDIA_TYPE + "=" +
        to_string(mediaType) + " AND " + PhotoColumn::PHOTO_ORIENTATION + "=" + to_string(fileInfo.orientation) + ";";
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("IsDuplication: get rdb store fail!");
        return false;
    }
    auto resultSet = rdbStore->QuerySql(querySql);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("IsDuplication: query PhotoAlbum failed!");
        return false;
    }
    if (resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("IsDuplication first row empty.");
        resultSet->Close();
        return false;
    }
    int32_t count = GetInt32Val("count", resultSet);
    resultSet->Close();
    return count > 0;
}

int32_t PhotoCustomRestoreOperation::InitPhotoCache(RestoreTaskInfo &restoreTaskInfo)
{
    if (!restoreTaskInfo.isDeduplication || restoreTaskInfo.albumId == 0) {
        return E_OK;
    }
    MEDIA_INFO_LOG("InitPhotoCache begin, albumId: %{public}d", restoreTaskInfo.albumId);
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("InitPhotoCache: get rdb store fail!");
        return E_HAS_DB_ERROR;
    }
    const string queryCountSql = "SELECT COUNT(1) as count FROM " + PhotoColumn::PHOTOS_TABLE + " WHERE " +
                                 PhotoColumn::PHOTO_OWNER_ALBUM_ID + "=" + to_string(restoreTaskInfo.albumId) + ";";
    auto resultSet = rdbStore->QuerySql(queryCountSql);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("InitPhotoCache: get resultSet fail!");
        return E_HAS_DB_ERROR;
    }
    if (resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("InitPhotoCache first row empty.");
        resultSet->Close();
        return E_HAS_DB_ERROR;
    }
    int32_t count = GetInt32Val("count", resultSet);
    resultSet->Close();
    if (count > MAX_PHOTO_CACHE_NUM) {
        MEDIA_WARN_LOG("album has more than %{public}d, skip create cache.", MAX_PHOTO_CACHE_NUM);
        return E_OK;
    }
    const string queryCacheSql = "SELECT " + MediaColumn::MEDIA_NAME + "," + MediaColumn::MEDIA_SIZE + "," +
                                 MediaColumn::MEDIA_TYPE + "," + PhotoColumn::PHOTO_ORIENTATION + " FROM " +
                                 PhotoColumn::PHOTOS_TABLE + " WHERE " + PhotoColumn::PHOTO_OWNER_ALBUM_ID + "=" +
                                 to_string(restoreTaskInfo.albumId) + ";";
    auto resultCacheSet = rdbStore->QuerySql(queryCacheSql);
    if (resultCacheSet == nullptr) {
        return E_HAS_DB_ERROR;
    }
    while (resultCacheSet->GoToNextRow() == NativeRdb::E_OK) {
        string displayName = GetStringVal(MediaColumn::MEDIA_NAME, resultCacheSet);
        int64_t mediaSize = GetInt64Val(MediaColumn::MEDIA_SIZE, resultCacheSet);
        int32_t mediaType = GetInt32Val(MediaColumn::MEDIA_TYPE, resultCacheSet);
        int32_t orientation = GetInt32Val(PhotoColumn::PHOTO_ORIENTATION, resultCacheSet);
        photoCache_.insert(
            displayName + "_" + to_string(mediaSize) + "_" + to_string(mediaType) + "_" + to_string(orientation));
    }
    resultCacheSet->Close();
    restoreTaskInfo.hasPhotoCache = true;
    MEDIA_INFO_LOG("InitPhotoCache success, num:%{public}d", static_cast<int32_t>(photoCache_.size()));
    return E_OK;
}

int32_t PhotoCustomRestoreOperation::UpdateUniqueNumber(UniqueNumber &uniqueNumber)
{
    int32_t errCode = MediaLibraryAssetOperations::CreateAssetUniqueIds(
        MediaType::MEDIA_TYPE_IMAGE, uniqueNumber.imageTotalNumber, uniqueNumber.imageCurrentNumber);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("CreateAssetUniqueNumber IMAGE fail!, ret:%{public}d", errCode);
        return errCode;
    }
    MEDIA_DEBUG_LOG("imageTotalNumber: %{public}d imageCurrentNumber: %{public}d",
        uniqueNumber.imageTotalNumber, uniqueNumber.imageCurrentNumber);
    errCode = MediaLibraryAssetOperations::CreateAssetUniqueIds(
        MediaType::MEDIA_TYPE_VIDEO, uniqueNumber.videoTotalNumber, uniqueNumber.videoCurrentNumber);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("CreateAssetUniqueNumber VIDEO fail!, ret:%{public}d", errCode);
        return errCode;
    }
    MEDIA_DEBUG_LOG("videoTotalNumber: %{public}d videoCurrentNumber: %{public}d",
        uniqueNumber.videoTotalNumber, uniqueNumber.videoCurrentNumber);
    return E_OK;
}

static void InsertDateTaken(std::unique_ptr<Metadata> &metadata, NativeRdb::ValuesBucket &value)
{
    int64_t dateTaken = metadata->GetDateTaken();
    if (dateTaken != 0) {
        value.PutLong(MediaColumn::MEDIA_DATE_TAKEN, dateTaken);
        value.PutString(PhotoColumn::PHOTO_DATE_YEAR,
            MediaFileUtils::StrCreateTimeByMilliseconds(PhotoColumn::PHOTO_DATE_YEAR_FORMAT, dateTaken));
        value.PutString(PhotoColumn::PHOTO_DATE_MONTH,
            MediaFileUtils::StrCreateTimeByMilliseconds(PhotoColumn::PHOTO_DATE_MONTH_FORMAT, dateTaken));
        value.PutString(PhotoColumn::PHOTO_DATE_DAY,
            MediaFileUtils::StrCreateTimeByMilliseconds(PhotoColumn::PHOTO_DATE_DAY_FORMAT, dateTaken));
        return;
    }
    int64_t dateAdded = metadata->GetFileDateAdded();
    if (dateAdded == 0) {
        int64_t dateModified = metadata->GetFileDateModified();
        if (dateModified == 0) {
            dateTaken = MediaFileUtils::UTCTimeMilliSeconds();
        } else {
            dateTaken = dateModified;
        }
    } else {
        dateTaken = dateAdded;
    }
    value.PutLong(MediaColumn::MEDIA_DATE_TAKEN, dateTaken);
    value.PutString(PhotoColumn::PHOTO_DATE_YEAR,
        MediaFileUtils::StrCreateTimeByMilliseconds(PhotoColumn::PHOTO_DATE_YEAR_FORMAT, dateTaken));
    value.PutString(PhotoColumn::PHOTO_DATE_MONTH,
        MediaFileUtils::StrCreateTimeByMilliseconds(PhotoColumn::PHOTO_DATE_MONTH_FORMAT, dateTaken));
    value.PutString(PhotoColumn::PHOTO_DATE_DAY,
        MediaFileUtils::StrCreateTimeByMilliseconds(PhotoColumn::PHOTO_DATE_DAY_FORMAT, dateTaken));
}

NativeRdb::ValuesBucket PhotoCustomRestoreOperation::GetInsertValue(
    RestoreTaskInfo &restoreTaskInfo, FileInfo &fileInfo)
{
    NativeRdb::ValuesBucket value;
    value.PutString(MediaColumn::MEDIA_FILE_PATH, fileInfo.filePath);
    value.PutString(MediaColumn::MEDIA_TITLE, fileInfo.title);
    value.PutString(MediaColumn::MEDIA_NAME, fileInfo.displayName);
    int32_t subType = fileInfo.isLivePhoto ? static_cast<int32_t>(PhotoSubType::MOVING_PHOTO)
                                           : static_cast<int32_t>(PhotoSubType::DEFAULT);
    value.PutInt(PhotoColumn::PHOTO_SUBTYPE, subType);
    value.PutString(MediaColumn::MEDIA_PACKAGE_NAME, restoreTaskInfo.packageName);
    value.PutString(MediaColumn::MEDIA_OWNER_PACKAGE, restoreTaskInfo.bundleName);
    value.PutString(MediaColumn::MEDIA_OWNER_APPID, restoreTaskInfo.appId);
    std::unique_ptr<Metadata> data = make_unique<Metadata>();
    data->SetFilePath(fileInfo.originFilePath);
    data->SetFileName(fileInfo.fileName);
    data->SetFileMediaType(fileInfo.mediaType);
    FillMetadata(data);
    fileInfo.size = data->GetFileSize();
    fileInfo.orientation = data->GetOrientation();
    InsertDateTaken(data, value);
    value.PutLong(MediaColumn::MEDIA_DATE_ADDED, MediaFileUtils::UTCTimeMilliSeconds());
    value.PutInt(PhotoColumn::PHOTO_ORIENTATION, data->GetOrientation());
    value.PutString(MediaColumn::MEDIA_FILE_PATH, data->GetFilePath());
    value.PutString(MediaColumn::MEDIA_MIME_TYPE, data->GetFileMimeType());
    value.PutString(PhotoColumn::PHOTO_MEDIA_SUFFIX, data->GetFileExtension());
    value.PutInt(MediaColumn::MEDIA_TYPE, fileInfo.mediaType);
    value.PutString(MediaColumn::MEDIA_TITLE, data->GetFileTitle());
    value.PutLong(MediaColumn::MEDIA_SIZE, data->GetFileSize());
    value.PutLong(MediaColumn::MEDIA_DATE_MODIFIED, data->GetFileDateModified());
    value.PutInt(MediaColumn::MEDIA_DURATION, data->GetFileDuration());
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
    value.PutString(PhotoColumn::PHOTO_USER_COMMENT, data->GetUserComment());
    value.PutInt(PhotoColumn::PHOTO_QUALITY, 0);
    value.PutString(PhotoColumn::PHOTO_DETAIL_TIME, data->GetDetailTime());
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
        fileInfo.isLivePhoto = MovingPhotoFileUtils::IsLivePhoto(filePath);
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

static void UpdateCoverPosition(const string &filePath, int64_t coverPosition)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("UpdateCoverPosition: get rdb store fail!");
        return;
    }
    string updateSql = "UPDATE " + PhotoColumn::PHOTOS_TABLE + " SET " + PhotoColumn::PHOTO_COVER_POSITION +
        " = ? WHERE " + PhotoColumn::MEDIA_FILE_PATH + " = ?;";
    std::vector<NativeRdb::ValueObject> params = {coverPosition, filePath};
    int32_t errCode = rdbStore->ExecuteSql(updateSql, params);
    if (errCode < 0) {
        MEDIA_ERR_LOG("UpdateCoverPosition: execute update cover_position failed, ret = %{public}d", errCode);
    }
}

int32_t PhotoCustomRestoreOperation::RenameFiles(vector<FileInfo> &restoreFiles)
{
    int32_t renameNum = 0;
    for (auto &fileInfo : restoreFiles) {
        if (fileInfo.isLivePhoto) {
            if (MoveLivePhoto(fileInfo.originFilePath, fileInfo.filePath) != E_OK) {
                MEDIA_ERR_LOG("MoveFile failed. srcFile:%{public}s, destFile:%{public}s",
                    fileInfo.originFilePath.c_str(),
                    fileInfo.filePath.c_str());
                DeleteDatabaseRecord(fileInfo.filePath);
            } else {
                renameNum++;
            }
            continue;
        }
        if (!MediaFileUtils::MoveFile(fileInfo.originFilePath, fileInfo.filePath)) {
            MEDIA_ERR_LOG("MoveFile failed. srcFile:%{public}s, destFile:%{public}s",
                fileInfo.originFilePath.c_str(),
                fileInfo.filePath.c_str());
            DeleteDatabaseRecord(fileInfo.filePath);
        } else {
            renameNum++;
        }
    }
    return renameNum;
}

int32_t PhotoCustomRestoreOperation::MoveLivePhoto(const string &originFilePath, const string &filePath)
{
    string videoPath = MovingPhotoFileUtils::GetMovingPhotoVideoPath(filePath);
    string extraDataPath = MovingPhotoFileUtils::GetMovingPhotoExtraDataPath(filePath);
    string extraPathDir = MovingPhotoFileUtils::GetMovingPhotoExtraDataDir(filePath);
    if (!MediaFileUtils::IsFileExists(extraPathDir) && !MediaFileUtils::CreateDirectory(extraPathDir)) {
        MEDIA_WARN_LOG("Failed to create local extra data dir");
        return E_HAS_FS_ERROR;
    }
    int32_t ret = MovingPhotoFileUtils::ConvertToMovingPhoto(originFilePath, filePath, videoPath, extraDataPath);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("Failed to convert live photo, ret:%{public}d", ret);
        (void)MediaFileUtils::DeleteFile(filePath);
        (void)MediaFileUtils::DeleteFile(videoPath);
        (void)MediaFileUtils::DeleteDir(extraPathDir);
        return ret;
    }
    uint64_t coverPosition = 0;
    uint32_t version = 0;
    uint32_t frameIndex = 0;
    bool hasCinemagraphInfo = false;
    string absExtraDataPath;
    if (!PathToRealPath(extraDataPath, absExtraDataPath)) {
        MEDIA_WARN_LOG("file is not real path: %{private}s, errno: %{public}d", extraDataPath.c_str(), errno);
        UpdateCoverPosition(filePath, static_cast<int64_t>(coverPosition));
        return E_OK;
    }
    UniqueFd extraDataFd(open(absExtraDataPath.c_str(), O_RDONLY));
    (void)MovingPhotoFileUtils::GetVersionAndFrameNum(extraDataFd.Get(), version, frameIndex, hasCinemagraphInfo);
    (void)MovingPhotoFileUtils::GetCoverPosition(videoPath, frameIndex, coverPosition);
    UpdateCoverPosition(filePath, static_cast<int64_t>(coverPosition));
    return ret;
}

void PhotoCustomRestoreOperation::DeleteDatabaseRecord(const string &filePath)
{
    string deleteSql =
        "DELETE FROM " + PhotoColumn::PHOTOS_TABLE + " WHERE " + PhotoColumn::MEDIA_FILE_PATH + " = ?;";
    std::vector<NativeRdb::ValueObject> params = {filePath};
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        return;
    }
    int32_t ret = rdbStore->ExecuteSql(deleteSql, params);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("delete data from database failed, ret:%{public}d", ret);
        return;
    }
}

void PhotoCustomRestoreOperation::CleanTimeoutCustomRestoreTaskDir()
{
    MEDIA_INFO_LOG("CleanTimeoutCustomRestoreTaskDir");
    auto timestampNow = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    DIR* dir = opendir(CUSTOM_RESTORE_DIR.c_str());
    if (dir == nullptr) {
        MEDIA_ERR_LOG("failed open dir, errno: %{public}d.", errno);
        return;
    }
    struct dirent *ptr = nullptr;
    while ((ptr = readdir(dir)) != nullptr) {
        if (ptr->d_type != DT_DIR || strcmp(".", ptr->d_name) == 0
            || strcmp("..", ptr->d_name) == 0) {
            continue;
        }
        std::string fileStr = CUSTOM_RESTORE_DIR + "/" + ptr->d_name;
        struct stat statInfo {};
        if (stat(fileStr.c_str(), &statInfo) != 0) {
            MEDIA_ERR_LOG("stat syscall err");
            continue;
        }
        auto dateCreated = static_cast<int64_t>(MediaFileUtils::Timespec2Millisecond(statInfo.st_ctim));
        if ((timestampNow - dateCreated) < TIMEOUT_TASK_DIR_CLEAN_INTERVAL) {
            MEDIA_ERR_LOG("no timeout file");
            continue;
        }
        if (!MediaFileUtils::DeleteDir(fileStr)) {
            MEDIA_ERR_LOG("clean timeout task dir failed");
        }
    }
    closedir(dir);
}

}  // namespace OHOS::Media
