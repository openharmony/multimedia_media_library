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
#define MLOG_TAG "DfxManager"

#include <sstream>
#include "dfx_manager.h"

#include "dfx_cloud_manager.h"
#include "dfx_utils.h"
#include "ffrt.h"
#include "ffrt_inner.h"
#include "media_file_utils.h"
#include "media_file_uri.h"
#include "media_log.h"
#include "userfile_manager_types.h"
#include "medialibrary_bundle_manager.h"
#ifdef META_RECOVERY_SUPPORT
#include "medialibrary_meta_recovery.h"
#endif
#include "dfx_database_utils.h"
#include "vision_aesthetics_score_column.h"
#include "parameters.h"
#include "preferences.h"
#include "preferences_helper.h"
#include "hi_audit.h"
#include "medialibrary_errno.h"
#include "photo_storage_operation.h"
#include "medialibrary_unistore_manager.h"

using namespace std;

namespace OHOS {
namespace Media {

shared_ptr<DfxManager> DfxManager::dfxManagerInstance_{nullptr};
mutex DfxManager::instanceLock_;

struct QueryParams {
    MediaType mediaType;
    PhotoPositionType positionType;
};

shared_ptr<DfxManager> DfxManager::GetInstance()
{
    lock_guard<mutex> lockGuard(instanceLock_);
    if (dfxManagerInstance_ == nullptr) {
        dfxManagerInstance_ = make_shared<DfxManager>();
        if (dfxManagerInstance_ != nullptr) {
            dfxManagerInstance_->Init();
        }
    }
    return dfxManagerInstance_;
}

DfxManager::DfxManager() : isInitSuccess_(false),
    downloadMeta_(DOWNLOAD_META_LEN),
    uploadMeta_(UPLOAD_META_LEN),
    downloadThumb_(DOWNLOAD_THUMB_LEN),
    downloadLcd_(DOWNLOAD_LCD_LEN),
    uploadAlbum_(UPLOAD_ALBUM_LEN),
    downloadAlbum_(DOWNLOAD_ALBUM_LEN),
    updateDetails_(UPDATE_DETAILS_LEN),
    uploadMetaErr_(UPLOAD_META_ERR_LEN)
{
}

DfxManager::~DfxManager()
{
}

void DfxManager::Init()
{
    MEDIA_INFO_LOG("Init DfxManager");
    dfxCollector_ = make_shared<DfxCollector>();
    dfxAnalyzer_ = make_shared<DfxAnalyzer>();
    dfxReporter_ = make_shared<DfxReporter>();
    dfxWorker_ = DfxWorker::GetInstance();
    dfxWorker_->Init();
    isInitSuccess_ = true;
}

void DfxManager::HandleTimeOutOperation(std::string &bundleName, int32_t type, int32_t object, int32_t time)
{
    if (!isInitSuccess_) {
        MEDIA_WARN_LOG("DfxManager not init");
        return;
    }
    dfxReporter_->ReportTimeOutOperation(bundleName, type, object, time);
}

void DfxManager::HandleControllerServiceError(uint32_t operationCode, int32_t errorCode)
{
    if (!isInitSuccess_) {
        MEDIA_WARN_LOG("DfxManager not init");
        return;
    }
    dfxReporter_->ReportControllerService(operationCode, errorCode);
}

int32_t DfxManager::HandleHighMemoryThumbnail(std::string &path, int32_t mediaType, int32_t width,
    int32_t height)
{
    if (!isInitSuccess_) {
        MEDIA_WARN_LOG("DfxManager not init");
        return NOT_INIT;
    }
    string suffix = MediaFileUtils::GetExtensionFromPath(path);
    if (mediaType == MEDIA_TYPE_IMAGE) {
        return dfxReporter_->ReportHighMemoryImageThumbnail(path, suffix, width, height);
    } else {
        return dfxReporter_->ReportHighMemoryVideoThumbnail(path, suffix, width, height);
    }
}

void DfxManager::HandleThumbnailError(const std::string &path, int32_t method, int32_t errorCode)
{
    string safePath = DfxUtils::GetSafePath(path);
    MEDIA_ERR_LOG("Failed to %{public}d, path: %{public}s, err: %{public}d", method, safePath.c_str(), errorCode);
    if (!isInitSuccess_) {
        MEDIA_WARN_LOG("DfxManager not init");
        return;
    }
    dfxCollector_->CollectThumbnailError(safePath, method, errorCode);
}

void DfxManager::HandleThumbnailGeneration(const ThumbnailData::GenerateStats &stats)
{
    if (!isInitSuccess_) {
        MEDIA_WARN_LOG("DfxManager not init");
        return;
    }
    dfxReporter_->ReportThumbnailGeneration(stats);
}

void DfxManager::HandleCommonBehavior(string bundleName, int32_t type)
{
    if (!isInitSuccess_) {
        MEDIA_WARN_LOG("DfxManager not init");
        return;
    }
    dfxCollector_->AddCommonBahavior(bundleName, type);
}

static string GetDisplayName(const string &coverId, const std::map<std::string, std::string> &displayNames)
{
    auto it = std::find_if(displayNames.begin(), displayNames.end(),
        [&](const std::pair<std::string, std::string> &name) {
        return name.first == coverId;
    });
    string displayName = it == displayNames.end() ? "" : it->second;
    return DfxUtils::GetSafeDiaplayNameWhenChinese(displayName);
}

static string GetAlbumName(const string &coverId, const DeleteBehaviorData &deleteBehaviorData)
{
    auto itIds = std::find_if(deleteBehaviorData.ownerAlbumIds.begin(), deleteBehaviorData.ownerAlbumIds.end(),
        [&](const std::pair<std::string, std::string> &ownerAlbumId) {
            return ownerAlbumId.first == coverId;
        });
    if (itIds == deleteBehaviorData.ownerAlbumIds.end()) {
        return "";
    }
    string albumId = itIds->second;
    auto it = std::find_if(deleteBehaviorData.albumNames.begin(), deleteBehaviorData.albumNames.end(),
        [&](const std::pair<std::string, std::string> &albumName) {
            return albumName.first == albumId;
        });
    string albumName = it == deleteBehaviorData.albumNames.end() ? "" : it->second;
    return DfxUtils::GetSafeAlbumNameWhenChinese(albumName);
}

static void LogDelete(DfxData *data)
{
    if (data == nullptr) {
        return;
    }
    auto *taskData = static_cast<DeleteBehaviorTask *>(data);
    string id = taskData->id_;
    int32_t type = taskData->type_;
    int32_t size = taskData->size_;
    std::shared_ptr<DfxReporter> dfxReporter = taskData->dfxReporter_;
    MEDIA_INFO_LOG("id: %{public}s, type: %{public}d, size: %{public}d", id.c_str(), type, size);

    std::vector<std::string> uris = taskData->uris_;
    if (!uris.empty()) {
        for (auto& uri: uris) {
            string::size_type pos = uri.find_last_of('/');
            if (pos == string::npos) {
                continue;
            }
            string halfUri = uri.substr(0, pos);
            string::size_type pathPos = halfUri.find_last_of('/');
            if (pathPos == string::npos) {
                continue;
            }
            string coverId = MediaFileUri::GetPhotoId(uri);
            string displayName = GetDisplayName(coverId, taskData->deleteBehaviorData_.displayNames);
            string albumName = GetAlbumName(coverId, taskData->deleteBehaviorData_);
            AuditLog auditLog = { true, "USER BEHAVIOR", "DELETE", "io", 1, "running", "ok",
                id, type, size, (halfUri.substr(pathPos + 1)).c_str(), displayName, albumName };
            HiAudit::GetInstance().Write(auditLog);
            dfxReporter->ReportDeleteBehavior(id, type, halfUri.substr(pathPos + 1));
        }
    }
}

void DfxManager::HandleNoPermmison(int32_t type, int32_t object, int32_t error)
{
    MEDIA_INFO_LOG("permission deny: {%{public}d, %{public}d, %{public}d}", type, object, error);
}

void DfxManager::HandleDeleteBehavior(int32_t type, int32_t size, std::vector<std::string> &uris, string bundleName,
    const DeleteBehaviorData &deleteBehaviorData)
{
    if (bundleName == "") {
        bundleName = MediaLibraryBundleManager::GetInstance()->GetClientBundleName();
    }
    dfxCollector_->CollectDeleteBehavior(bundleName, type, size);
    if (dfxWorker_ == nullptr) {
        MEDIA_ERR_LOG("Can not get dfxWork_");
        return;
    }
    string id = bundleName == "" ? to_string(IPCSkeleton::GetCallingUid()) : bundleName;
    auto *taskData = new (nothrow) DeleteBehaviorTask(id, type, size, uris, dfxReporter_, deleteBehaviorData);
    if (taskData == nullptr) {
        MEDIA_ERR_LOG("Failed to new taskData");
        return;
    }
    auto deleteBehaviorTask = make_shared<DfxTask>(LogDelete, taskData);
    if (deleteBehaviorTask == nullptr) {
        MEDIA_ERR_LOG("Failed to create async task for deleteBehaviorTask.");
        return;
    }
    dfxWorker_->AddTask(deleteBehaviorTask);
}

static void HandlePhotoInfo(std::shared_ptr<DfxReporter>& dfxReporter)
{
    const std::vector<QueryParams> queryParamsList = {
        {MediaType::MEDIA_TYPE_IMAGE, PhotoPositionType::LOCAL},
        {MediaType::MEDIA_TYPE_VIDEO, PhotoPositionType::LOCAL},
        {MediaType::MEDIA_TYPE_IMAGE, PhotoPositionType::CLOUD},
        {MediaType::MEDIA_TYPE_VIDEO, PhotoPositionType::CLOUD},
        {MediaType::MEDIA_TYPE_IMAGE, PhotoPositionType::LOCAL_AND_CLOUD},
        {MediaType::MEDIA_TYPE_VIDEO, PhotoPositionType::LOCAL_AND_CLOUD}
    };

    PhotoStatistics stats = {};
    int32_t* countPtrs[] = {
        &stats.localImageCount,
        &stats.localVideoCount,
        &stats.cloudImageCount,
        &stats.cloudVideoCount,
        &stats.sharedImageCount,
        &stats.sharedVideoCount
    };

    for (size_t i = 0; i < queryParamsList.size(); i++) {
        const auto& params = queryParamsList[i];
        *countPtrs[i] = DfxDatabaseUtils::QueryFromPhotos(params.mediaType, static_cast<int32_t>(params.positionType));
    }

    MEDIA_INFO_LOG("localImageCount: %{public}d, localVideoCount: %{public}d, "
                   "cloudImageCount: %{public}d, cloudVideoCount: %{public}d, "
                   "sharedImageCount: %{public}d, sharedVideoCount: %{public}d",
                   stats.localImageCount, stats.localVideoCount,
                   stats.cloudImageCount, stats.cloudVideoCount,
                   stats.sharedImageCount, stats.sharedVideoCount);

    dfxReporter->ReportPhotoInfo(stats);
}

static void HandleAlbumInfoBySubtype(std::shared_ptr<DfxReporter> &dfxReporter, int32_t albumSubType)
{
    AlbumInfo albumInfo = DfxDatabaseUtils::QueryAlbumInfoBySubtype(albumSubType);
    string albumName = ALBUM_MAP.at(albumSubType);
    MEDIA_INFO_LOG("album %{public}s: {count:%{public}d, imageCount:%{public}d, videoCount:%{public}d, \
        isLocal:%{public}d}", albumName.c_str(), albumInfo.count, albumInfo.imageCount, albumInfo.videoCount,
        albumInfo.isLocal);
    dfxReporter->ReportAlbumInfo(albumName.c_str(), albumInfo.imageCount, albumInfo.videoCount, albumInfo.isLocal);
}

static void HandleAlbumInfo(std::shared_ptr<DfxReporter> &dfxReporter)
{
    HandleAlbumInfoBySubtype(dfxReporter, static_cast<int32_t>(PhotoAlbumSubType::IMAGE));
    HandleAlbumInfoBySubtype(dfxReporter, static_cast<int32_t>(PhotoAlbumSubType::VIDEO));
    HandleAlbumInfoBySubtype(dfxReporter, static_cast<int32_t>(PhotoAlbumSubType::FAVORITE));
    HandleAlbumInfoBySubtype(dfxReporter, static_cast<int32_t>(PhotoAlbumSubType::HIDDEN));
    HandleAlbumInfoBySubtype(dfxReporter, static_cast<int32_t>(PhotoAlbumSubType::TRASH));
}

static void HandleDirtyCloudPhoto(std::shared_ptr<DfxReporter> &dfxReporter)
{
    vector<PhotoInfo> photoInfoList = DfxDatabaseUtils::QueryDirtyCloudPhoto();
    if (photoInfoList.empty()) {
        return;
    }
    for (auto& photoInfo: photoInfoList) {
        dfxReporter->ReportDirtyCloudPhoto(photoInfo.data, photoInfo.dirty, photoInfo.cloudVersion);
    }
}

static void HandleLocalVersion(std::shared_ptr<DfxReporter> &dfxReporter)
{
    int32_t dbVersion = DfxDatabaseUtils::QueryDbVersion();
    dfxReporter->ReportCommonVersion(dbVersion);
    int32_t aestheticsVersion = DfxDatabaseUtils::QueryAnalysisVersion("tab_analysis_aesthetics_score",
        AESTHETICS_VERSION);
    dfxReporter->ReportAnalysisVersion("tab_analysis_aesthetics_score", aestheticsVersion);
}

void HandleAstcInfo(std::shared_ptr<DfxReporter>& dfxReporter)
{
    LcdAndAstcCount count = {};
    count.localAstcCount = DfxDatabaseUtils::QueryASTCThumb(true);
    count.cloudAstcCount = DfxDatabaseUtils::QueryASTCThumb(false);
    count.localLcdCount = DfxDatabaseUtils::QueryLCDThumb(true);
    count.cloudLcdCount = DfxDatabaseUtils::QueryLCDThumb(false);

    MEDIA_INFO_LOG("localLcdCount: %{public}d, localAstcCount: %{public}d, "
                   "cloudLcdCount: %{public}d, cloudAstcCount: %{public}d",
                   count.localLcdCount, count.localAstcCount,
                   count.cloudLcdCount, count.cloudAstcCount);

    dfxReporter->ReportAstcInfo(count);
}

static void HandleStatistic(DfxData *data)
{
    if (data == nullptr) {
        return;
    }
    auto *taskData = static_cast<StatisticData *>(data);
    std::shared_ptr<DfxReporter> dfxReporter = taskData->dfxReporter_;
    HandlePhotoInfo(dfxReporter);
    HandleAlbumInfo(dfxReporter);
    HandleDirtyCloudPhoto(dfxReporter);
    HandleLocalVersion(dfxReporter);
    HandleAstcInfo(dfxReporter);
#ifdef META_RECOVERY_SUPPORT
    MediaLibraryMetaRecovery::GetInstance().RecoveryStatistic();
#endif
}

static void CheckPhotoError(std::shared_ptr<DfxReporter>& dfxReporter)
{
    CHECK_AND_RETURN_INFO_LOG(dfxReporter != nullptr, "E_OK");
    auto photoCount = DfxDatabaseUtils::QueryPhotoErrorCount();
    CHECK_AND_RETURN_INFO_LOG(photoCount, "E_OK");
    MEDIA_ERR_LOG("DFX ReportPhotoError count is %{public}d", photoCount);
    PhotoErrorCount photoError = { {PhotoErrorType::PHOTO_MISS_TYPE}, {photoCount} };
    dfxReporter->ReportPhotoError(photoError);
}

static void HandleCheckTwoDayTask(DfxData *data)
{
    CHECK_AND_RETURN_LOG(data != nullptr, "Failed to get data for Handle Check Two Day Task!");
    auto *taskData = static_cast<StatisticData *>(data);
    std::shared_ptr<DfxReporter> dfxReporter = taskData->dfxReporter_;
    CHECK_AND_RETURN_LOG(dfxReporter != nullptr, "Failed to get dfxReporter for Handle Check Two Day Task!");
    CheckPhotoError(dfxReporter);
}

bool DfxManager::HandleHalfDayMissions()
{
    MEDIA_INFO_LOG("Begin HandleHalfDayMissions");
    if (!isInitSuccess_) {
        MEDIA_WARN_LOG("DfxManager not init");
        return false;
    }
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(DFX_COMMON_XML, errCode);
    if (!prefs) {
        MEDIA_ERR_LOG("get preferences error: %{public}d", errCode);
        return false;
    }
    int64_t lastReportTime = prefs->GetLong(LAST_HALF_DAY_REPORT_TIME, 0);
    if (dfxWorker_ == nullptr || (MediaFileUtils::UTCTimeSeconds() - lastReportTime <= HALF_DAY)) {
        MEDIA_INFO_LOG("last task was executed within half a day.");
        return false;
    }
    MEDIA_INFO_LOG("start handle statistic behavior");
    auto *taskData = new (nothrow) StatisticData(dfxReporter_);
    if (taskData == nullptr) {
        MEDIA_ERR_LOG("Failed to alloc async data for Handle Half Day Missions!");
        return false;
    }
    auto statisticTask = make_shared<DfxTask>(HandleStatistic, taskData);
    if (statisticTask == nullptr) {
        MEDIA_ERR_LOG("Failed to create statistic task.");
        delete taskData;
        return false;
    }
    dfxWorker_->AddTask(statisticTask);
    int64_t time = MediaFileUtils::UTCTimeSeconds();
    prefs->PutLong(LAST_HALF_DAY_REPORT_TIME, time);
    prefs->FlushSync();
    return true;
}

bool DfxManager::HandleTwoDayMissions()
{
    MEDIA_INFO_LOG("Begin HandleTwoDayMissions");
    CHECK_AND_RETURN_RET_LOG(isInitSuccess_, false, "DfxManager not init");
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(DFX_COMMON_XML, errCode);
    if (!prefs) {
        MEDIA_ERR_LOG("get preferences error: %{public}d", errCode);
        return false;
    }
    int64_t lastReportTime = prefs->GetLong(LAST_TWO_DAY_REPORT_TIME, 0);
    if (dfxWorker_ == nullptr || (MediaFileUtils::UTCTimeSeconds() - lastReportTime <= TWO_DAY)) {
        MEDIA_INFO_LOG("last task was executed within two day.");
        return false;
    }
    MEDIA_INFO_LOG("start handle statistic behavior");
    auto *taskData = new (nothrow) StatisticData(dfxReporter_);
    CHECK_AND_RETURN_RET_LOG(taskData != nullptr, false, "Failed to alloc async data for Handle Two Day Missions!");
    auto twoDayTask = make_shared<DfxTask>(HandleCheckTwoDayTask, taskData);
    if (twoDayTask == nullptr) {
        MEDIA_ERR_LOG("Failed to create dfx task.");
        delete taskData;
        return false;
    }
    dfxWorker_->AddTask(twoDayTask);
    int64_t time = MediaFileUtils::UTCTimeSeconds();
    prefs->PutLong(LAST_TWO_DAY_REPORT_TIME, time);
    prefs->FlushSync();
    return true;
}

void DfxManager::IsDirectoryExist(const string& dirName)
{
    struct stat statInfo {};
    if (stat(dirName.c_str(), &statInfo) == E_SUCCESS) {
        if (statInfo.st_mode & S_IFDIR) {
            return;
        }
        MEDIA_ERR_LOG("Not Is DIR, errno is %{public}d", errno);
        return;
    }
    MEDIA_ERR_LOG("Directory Not Exist, errno is %{public}d", errno);
    return;
}

void DfxManager::CheckStatus()
{
    const std::string CLOUD_FILE_PATH = "/storage/cloud/files";
    IsDirectoryExist(CLOUD_FILE_PATH);
}

void DfxManager::HandleFiveMinuteTask()
{
    if (!isInitSuccess_) {
        MEDIA_WARN_LOG("DfxManager not init");
        return;
    }
    std::unordered_map<string, CommonBehavior> commonBehavior = dfxCollector_->GetCommonBehavior();
    dfxAnalyzer_->FlushCommonBehavior(commonBehavior);
    HandleDeleteBehaviors();
    std::unordered_map<std::string, ThumbnailErrorInfo> result = dfxCollector_->GetThumbnailError();
    dfxAnalyzer_->FlushThumbnail(result);
    AdaptationToMovingPhotoInfo adaptationInfo = dfxCollector_->GetAdaptationToMovingPhotoInfo();
    dfxAnalyzer_->FlushAdaptationToMovingPhoto(adaptationInfo);
    CheckStatus();
}

void DfxManager::HandleDeleteBehaviors()
{
    std::unordered_map<string, int32_t> deleteAssetToTrash =
        dfxCollector_->GetDeleteBehavior(DfxType::TRASH_PHOTO);
    dfxAnalyzer_->FlushDeleteBehavior(deleteAssetToTrash, DfxType::TRASH_PHOTO);
    std::unordered_map<string, int32_t> deleteAssetFromDisk =
        dfxCollector_->GetDeleteBehavior(DfxType::ALBUM_DELETE_ASSETS);
    dfxAnalyzer_->FlushDeleteBehavior(deleteAssetToTrash, DfxType::ALBUM_DELETE_ASSETS);
    std::unordered_map<string, int32_t> removeAssets =
        dfxCollector_->GetDeleteBehavior(DfxType::ALBUM_REMOVE_PHOTOS);
    dfxAnalyzer_->FlushDeleteBehavior(removeAssets, DfxType::ALBUM_REMOVE_PHOTOS);
}

int64_t DfxManager::HandleMiddleReport()
{
    if (!isInitSuccess_) {
        MEDIA_WARN_LOG("DfxManager not init");
        return MediaFileUtils::UTCTimeSeconds();
    }
    dfxReporter_->ReportCommonBehavior();
    dfxReporter_->ReportDeleteStatistic();
    return MediaFileUtils::UTCTimeSeconds();
}

int64_t DfxManager::HandleOneDayReport()
{
    if (!isInitSuccess_) {
        MEDIA_WARN_LOG("DfxManager not init");
        return MediaFileUtils::UTCTimeSeconds();
    }
    dfxReporter_->ReportThumbnailError();
    dfxReporter_->ReportAdaptationToMovingPhoto();
    dfxReporter_->ReportPhotoRecordInfo();
    dfxReporter_->ReportOperationRecordInfo();
    return MediaFileUtils::UTCTimeSeconds();
}

void DfxManager::HandleAdaptationToMovingPhoto(const string &appName, bool adapted)
{
    if (!isInitSuccess_) {
        MEDIA_WARN_LOG("DfxManager not init");
        return;
    }
    dfxCollector_->CollectAdaptationToMovingPhotoInfo(appName, adapted);
}

static void GetPhotoAndPhotoExtSizes(QuerySizeAndResolution &queryInfo)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    bool conn = rdbStore == nullptr;
    CHECK_AND_RETURN_LOG(!conn, "rdbStore is null");

    int64_t cacheSize = PhotoStorageOperation().GetCacheSize();
    int64_t highlightSize = PhotoStorageOperation().GetHighlightSizeFromPreferences();

    TotalThumbnailSizeResult totalThumbnailSizeResult = {};
    PhotoStorageOperation().GetTotalThumbnailSize(rdbStore, totalThumbnailSizeResult);

    TotalEditdataSizeResult totalEditdataSizeRusult = {};
    PhotoStorageOperation().GetTotalEditdataSize(rdbStore, totalEditdataSizeRusult);

    int64_t totalExtSize = cacheSize + highlightSize + totalThumbnailSizeResult.totalThumbnailSize +
                           totalEditdataSizeRusult.totalEditdataSize;
    LocalPhotoSizeResult localPhotoSizeResult = {};
    PhotoStorageOperation().GetLocalPhotoSize(rdbStore, localPhotoSizeResult, totalExtSize);

    int64_t totalSize = localPhotoSizeResult.localImageSize + localPhotoSizeResult.localVideoSize + totalExtSize;

    queryInfo.cacheRomSize = std::to_string(cacheSize);
    queryInfo.highlightRomSize = std::to_string(highlightSize);
    queryInfo.ThumbnailRomSize = std::to_string(totalThumbnailSizeResult.totalThumbnailSize);
    queryInfo.EditdataRomSize = std::to_string(totalEditdataSizeRusult.totalEditdataSize);
    queryInfo.localImageRomSize = std::to_string(localPhotoSizeResult.localImageSize);
    queryInfo.localVideoRomSize = std::to_string(localPhotoSizeResult.localVideoSize);
    queryInfo.totalSize = std::to_string(totalSize);
    MEDIA_INFO_LOG("localImageRomSize: %{public}s, localVideoRomSize: %{public}s, totalThumbnailSize: %{public}s, "
                   "totalEditdataSize: %{public}s, cacheSize: %{public}s, highlightSize: %{public}s, "
                   "totalSize: %{public}s",
                   queryInfo.localImageRomSize.c_str(), queryInfo.localVideoRomSize.c_str(),
                   queryInfo.ThumbnailRomSize.c_str(), queryInfo.EditdataRomSize.c_str(),
                   queryInfo.cacheRomSize.c_str(), queryInfo.highlightRomSize.c_str(),
                   queryInfo.totalSize.c_str());
}

static void HandleGetSizeAndResolutionInfo(std::shared_ptr<DfxReporter>& dfxReporter)
{
    MEDIA_INFO_LOG("HandleGetSizeAndResolutionInfo start");
    CHECK_AND_RETURN_LOG(dfxReporter != nullptr, "Failed to get dfxReporter for HandleGetSizeAndResolutionInfo!");
    QuerySizeAndResolution queryInfo = {};
    bool bQueryInfo = DfxDatabaseUtils::GetSizeAndResolutionInfo(queryInfo);
    CHECK_AND_RETURN_LOG(bQueryInfo, "E_OK");
    std::string photoMimeType;
    DfxDatabaseUtils::GetPhotoMimeType(photoMimeType);
    GetPhotoAndPhotoExtSizes(queryInfo);
    dfxReporter->ReportPhotoSizeAndResolutionInfo(queryInfo, photoMimeType);
}

static void HandleCheckOneWeekDayTask(DfxData *data)
{
    CHECK_AND_RETURN_LOG(data != nullptr, "Failed to get data for Handle Check One Week Day Task!");
    auto *taskData = static_cast<StatisticData *>(data);
    std::shared_ptr<DfxReporter> dfxReporter = taskData->dfxReporter_;
    CHECK_AND_RETURN_LOG(dfxReporter != nullptr, "Failed to get dfxReporter for Handle Check One Week Day Task!");
    HandleGetSizeAndResolutionInfo(dfxReporter);
}

bool DfxManager::HandleOneWeekMissions()
{
    MEDIA_INFO_LOG("HandlePhotoInfo start");
    CHECK_AND_RETURN_RET_LOG(isInitSuccess_, false, "DfxManager not init");
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
    NativePreferences::PreferencesHelper::GetPreferences(DFX_COMMON_XML, errCode);
    if (!prefs) {
        MEDIA_ERR_LOG("get preferences error: %{public}d", errCode);
        return false;
    }
    int64_t lastReportTime = prefs->GetLong(LAST_WEEK_REPORT_TIME, 0);
    if (dfxWorker_ == nullptr || (MediaFileUtils::UTCTimeSeconds() - lastReportTime <= ONE_WEEK)) {
        MEDIA_INFO_LOG("last task was executed within a week.");
        return false;
    }
    MEDIA_INFO_LOG("start handle statistic behavior");
    auto *taskData = new (nothrow) StatisticData(dfxReporter_);
    CHECK_AND_RETURN_RET_LOG(taskData != nullptr, false, "Failed to alloc async data for Handle Week Day Missions!");
    auto oneWeekTask = make_shared<DfxTask>(HandleCheckOneWeekDayTask, taskData);
    if (oneWeekTask == nullptr) {
        MEDIA_ERR_LOG("Failed to create dfx task.");
        delete taskData;
        return false;
    }
    dfxWorker_->AddTask(oneWeekTask);
    int64_t time = MediaFileUtils::UTCTimeSeconds();
    prefs->PutLong(LAST_WEEK_REPORT_TIME, time);
    prefs->FlushSync();
    return true;
}

bool IsReported()
{
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(DFX_COMMON_XML, errCode);
    if (!prefs) {
        MEDIA_ERR_LOG("get dfx common preferences error: %{public}d", errCode);
        return false;
    }
    return prefs->GetBool(IS_REPORTED, false);
}

void SetReported(bool isReported)
{
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(DFX_COMMON_XML, errCode);
    if (!prefs) {
        MEDIA_ERR_LOG("get dfx common preferences error: %{public}d", errCode);
        return;
    }
    prefs->PutBool(IS_REPORTED, isReported);
}

CloudSyncDfxManager::~CloudSyncDfxManager()
{
    ShutDownTimer();
}

CloudSyncDfxManager& CloudSyncDfxManager::GetInstance()
{
    static CloudSyncDfxManager cloudSyncDfxManager;
    return cloudSyncDfxManager;
}

CloudSyncStatus GetCloudSyncStatus()
{
    return static_cast<CloudSyncStatus>(system::GetParameter(CLOUDSYNC_STATUS_KEY, "0").at(0) - '0');
}

CloudSyncDfxManager::CloudSyncDfxManager()
{
    InitSyncState();
    uint16_t newState = static_cast<uint16_t>(syncState_);
    stateProcessFuncs_[newState].Process(*this);
}

void CloudSyncDfxManager::InitSyncState()
{
    CloudSyncStatus cloudSyncStatus = GetCloudSyncStatus();
    switch (cloudSyncStatus) {
        case CloudSyncStatus::BEGIN:
        case CloudSyncStatus::SYNC_SWITCHED_OFF:
            syncState_ = SyncState::INIT_STATE;
            return;
        case CloudSyncStatus::FIRST_FIVE_HUNDRED:
        case CloudSyncStatus::TOTAL_DOWNLOAD:
            syncState_ = SyncState::START_STATE;
            return;
        case CloudSyncStatus::TOTAL_DOWNLOAD_FINISH:
            syncState_ = SyncState::END_STATE;
            return;
        default:
            return;
    }
}

bool InitState::StateSwitch(CloudSyncDfxManager& manager)
{
    CloudSyncStatus cloudSyncStatus = GetCloudSyncStatus();
    switch (cloudSyncStatus) {
        case CloudSyncStatus::FIRST_FIVE_HUNDRED:
        case CloudSyncStatus::TOTAL_DOWNLOAD:
            manager.syncState_ = SyncState::START_STATE;
            return true;
        case CloudSyncStatus::TOTAL_DOWNLOAD_FINISH:
            manager.syncState_ = SyncState::END_STATE;
            MEDIA_INFO_LOG("CloudSyncDfxManager new status:%{public}hu", manager.syncState_);
            return true;
        default:
            return false;
    }
}

void InitState::Process(CloudSyncDfxManager& manager)
{
    MEDIA_INFO_LOG("CloudSyncDfxManager new status:%{public}hu", manager.syncState_);
    manager.ResetStartTime();
    manager.ShutDownTimer();
    SetReported(false);
}

void CloudSyncDfxManager::RunDfx()
{
    uint16_t oldState = static_cast<uint16_t>(syncState_);
    if (stateProcessFuncs_[oldState].StateSwitch(*this)) {
        uint16_t newState = static_cast<uint16_t>(syncState_);
        stateProcessFuncs_[newState].Process(*this);
    }
}

bool StartState::StateSwitch(CloudSyncDfxManager& manager)
{
    CloudSyncStatus cloudSyncStatus = GetCloudSyncStatus();
    switch (cloudSyncStatus) {
        case CloudSyncStatus::BEGIN:
        case CloudSyncStatus::SYNC_SWITCHED_OFF:
            manager.syncState_ = SyncState::INIT_STATE;
            return true;
        case CloudSyncStatus::TOTAL_DOWNLOAD_FINISH:
            manager.syncState_ = SyncState::END_STATE;
            MEDIA_INFO_LOG("CloudSyncDfxManager new status:%{public}hu", manager.syncState_);
            return true;
        default:
            return false;
    }
}

void StartState::Process(CloudSyncDfxManager& manager)
{
    MEDIA_INFO_LOG("CloudSyncDfxManager new status:%{public}hu", manager.syncState_);
    manager.SetStartTime();
    manager.StartTimer();
    SetReported(false);
}

bool EndState::StateSwitch(CloudSyncDfxManager& manager)
{
    CloudSyncStatus cloudSyncStatus = GetCloudSyncStatus();
    switch (cloudSyncStatus) {
        case CloudSyncStatus::BEGIN:
        case CloudSyncStatus::SYNC_SWITCHED_OFF:
            manager.syncState_ = SyncState::INIT_STATE;
            return true;
        case CloudSyncStatus::TOTAL_DOWNLOAD_FINISH:
            return true;
        default:
            return false;
    }
}

void EndState::Process(CloudSyncDfxManager& manager)
{
    std::unique_lock<std::mutex> lock(manager.endStateMutex_);
    if (IsReported()) {
        manager.ShutDownTimer();
        return;
    }
    manager.SetStartTime();
    manager.StartTimer();
    int32_t downloadedThumb = 0;
    int32_t generatedThumb = 0;
    if (!DfxDatabaseUtils::QueryDownloadedAndGeneratedThumb(downloadedThumb, generatedThumb)) {
        if (downloadedThumb != generatedThumb) {
            return;
        }
        int32_t totalDownload = 0;
        DfxDatabaseUtils::QueryTotalCloudThumb(totalDownload);
        if (totalDownload != downloadedThumb) {
            return;
        }
        SetReported(true);
        manager.ShutDownTimer();
        DfxReporter::ReportCloudSyncThumbGenerationStatus(downloadedThumb, generatedThumb, totalDownload);
    }
}

void CloudSyncDfxManager::StartTimer()
{
    std::unique_lock<std::mutex> lock(timerMutex_);
    if (timerId_ != 0) {
        return;
    }
    if (timer_.Setup() != ERR_OK) {
        MEDIA_INFO_LOG("CloudSync Dfx Set Timer Failed");
        return;
    }
    Utils::Timer::TimerCallback timerCallback = [this]() {
        (void)this;
        if (IsReported()) {
            return;
        }
        int32_t generatedThumb = 0;
        int32_t downloadedThumb = 0;
        if (!DfxDatabaseUtils::QueryDownloadedAndGeneratedThumb(downloadedThumb, generatedThumb)) {
            int32_t totalDownload = 0;
            DfxDatabaseUtils::QueryTotalCloudThumb(totalDownload);
            if (downloadedThumb == generatedThumb && totalDownload == generatedThumb) {
                MEDIA_INFO_LOG("CloudSyncDfxManager Dfx report Thumb generation status, "
                    "download: %{public}d, generate: %{public}d", downloadedThumb, generatedThumb);
                SetReported(true);
            }
            DfxReporter::ReportCloudSyncThumbGenerationStatus(downloadedThumb, generatedThumb, totalDownload);
        }
    };
    timerId_ = timer_.Register(timerCallback, SIX_HOUR * TO_MILLION, false);
    MEDIA_INFO_LOG("CloudSyncDfxManager StartTimer id:%{public}d", timerId_);
}

void CloudSyncDfxManager::ShutDownTimer()
{
    std::unique_lock<std::mutex> lock(timerMutex_);
    if (timerId_ == 0) {
        return;
    }
    MEDIA_INFO_LOG("CloudSyncDfxManager ShutDownTimer id:%{public}d", timerId_);
    timer_.Unregister(timerId_);
    timerId_ = 0;
    timer_.Shutdown();
}

void CloudSyncDfxManager::ResetStartTime()
{
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(DFX_COMMON_XML, errCode);
    if (!prefs) {
        MEDIA_ERR_LOG("get dfx common preferences error: %{public}d", errCode);
        return;
    }
    prefs->PutLong(CLOUD_SYNC_START_TIME, 0);
    prefs->FlushSync();
}

void CloudSyncDfxManager::SetStartTime()
{
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(DFX_COMMON_XML, errCode);
    if (!prefs) {
        MEDIA_ERR_LOG("get dfx common preferences error: %{public}d", errCode);
        return;
    }
    int64_t time = prefs->GetLong(CLOUD_SYNC_START_TIME, 0);
    // if startTime exists, no need to reset startTime
    if (time != 0) {
        return;
    }
    time = MediaFileUtils::UTCTimeSeconds();
    prefs->PutLong(CLOUD_SYNC_START_TIME, time);
    prefs->FlushSync();
}

void DfxManager::ResetStatistic()
{
    for (auto &value : downloadMeta_) {
        value.store(0);
    }
    for (auto &value : uploadMeta_) {
        value.store(0);
    }
    for (auto &value : downloadThumb_) {
        value.store(0);
    }
    for (auto &value : downloadLcd_) {
        value.store(0);
    }
    for (auto &value : uploadAlbum_) {
        value.store(0);
    }
    for (auto &value : downloadAlbum_) {
        value.store(0);
    }
    for (auto &value : updateDetails_) {
        value.store(0);
    }
    for (auto &value : uploadMetaErr_) {
        value.store(0);
    }
}

void DfxManager::CopyStatistic(CloudSyncStat& stat)
{
    stat.downloadMeta.reserve(downloadMeta_.size());
    for (auto &value : downloadMeta_) {
        stat.downloadMeta.push_back(value.load());
    }
    stat.uploadMeta.reserve(uploadMeta_.size());
    for (auto &value : uploadMeta_) {
        stat.uploadMeta.push_back(value.load());
    }
    stat.downloadThumb.reserve(downloadThumb_.size());
    for (auto &value : downloadThumb_) {
        stat.downloadThumb.push_back(value.load());
    }
    stat.downloadLcd.reserve(downloadLcd_.size());
    for (auto &value : downloadLcd_) {
        stat.downloadLcd.push_back(value.load());
    }

    stat.uploadAlbum.reserve(uploadAlbum_.size());
    for (auto &value : uploadAlbum_) {
        stat.uploadAlbum.push_back(value.load());
    }
    stat.downloadAlbum.reserve(downloadAlbum_.size());
    for (auto &value : downloadAlbum_) {
        stat.downloadAlbum.push_back(value.load());
    }

    stat.updateDetails.reserve(updateDetails_.size());
    for (auto &value : updateDetails_) {
        stat.updateDetails.push_back(value.load());
    }
    stat.uploadMetaErr.reserve(uploadMetaErr_.size());
    for (auto &value : uploadMetaErr_) {
        stat.uploadMetaErr.push_back(value.load());
    }
}

void DfxManager::HandleSyncStart(const std::string& taskId, const int32_t syncReason)
{
    ResetStatistic();
    syncInfo_.startTime = static_cast<uint64_t>(MediaFileUtils::UTCTimeSeconds());
    syncInfo_.syncReason = syncReason;
    taskId_ = taskId;
}

void DfxManager::HandleUpdateMetaStat(uint32_t index, uint64_t diff, uint32_t syncType)
{
    if (index < DOWNLOAD_META_LEN) {
        downloadMeta_[index].fetch_add(diff);
    } else if (index - INDEX_UL_META_SUCCESS < UPLOAD_META_LEN) {
        uploadMeta_[index - INDEX_UL_META_SUCCESS].fetch_add(diff);
    } else {
        MEDIA_DEBUG_LOG("HandleUpdateMetaStat get a invalid index");
    }

    if (syncType > 0 && syncType < UPDATE_DETAILS_LEN &&
        (index == INDEX_UL_META_SUCCESS || index == INDEX_DL_META_SUCCESS)) {
        updateDetails_[syncType].fetch_add(diff);
    }
}

void DfxManager::HandleUpdateAttachmentStat(uint32_t index, uint64_t diff)
{
    if (index < DOWNLOAD_THUMB_LEN) {
        downloadThumb_[index].fetch_add(diff);
    } else if (index - INDEX_LCD_SUCCESS < DOWNLOAD_LCD_LEN) {
        downloadLcd_[index - INDEX_LCD_SUCCESS].fetch_add(diff);
    } else {
        MEDIA_DEBUG_LOG("HandleUpdateAttachmentStat get a invalid index");
    }
}

void DfxManager::HandleUpdateAlbumStat(uint32_t index, uint64_t diff)
{
    if (index < DOWNLOAD_ALBUM_LEN) {
        downloadAlbum_[index].fetch_add(diff);
    } else if (index - INDEX_UL_ALBUM_SUCCESS < UPLOAD_ALBUM_LEN) {
        uploadAlbum_[index - INDEX_UL_ALBUM_SUCCESS].fetch_add(diff);
    } else {
        MEDIA_DEBUG_LOG("HandleUpdateAlbumStat get a invalid index");
    }
}

void DfxManager::HandleUpdateUploadMetaStat(uint32_t index, uint64_t diff)
{
    if (index < UPLOAD_META_ERR_LEN) {
        uploadMetaErr_[index].fetch_add(diff);
    }
}

void DfxManager::HandleUpdateUploadDetailError(int32_t error)
{
    if (error == E_CLOUD_STORAGE_FULL) {
        uploadMetaErr_[INDEX_UL_META_ERR_STORAGE].fetch_add(1);
    }
}

static std::string VectorToString(const std::vector<uint64_t>& vec)
{
    std::ostringstream oss;
    for (size_t i = 0; i < vec.size(); ++i) {
        if (0 != i) {
            oss << " ";
        }
        oss << vec[i];
    }
    return oss.str();
}

void DfxManager::HandleSyncEnd(const int32_t stopReason)
{
    int64_t endTime = MediaFileUtils::UTCTimeSeconds();
    if (static_cast<uint64_t>(endTime) >= syncInfo_.startTime) {
        syncInfo_.duration = static_cast<uint64_t>(endTime) - syncInfo_.startTime;
    } else {
        syncInfo_.duration = 0;
    }
    syncInfo_.stopReason = stopReason;
    CloudSyncStat stat;
    CopyStatistic(stat);

    std::string syncInfo;
    for (auto &detail : stat.updateDetails) {
        if (detail > 0) {
            stat.updateDetails[0] = static_cast<uint64_t>(MediaFileUtils::UTCTimeSeconds());
            syncInfo = "[" + taskId_ + " " + std::to_string(syncInfo_.startTime) + " " +
            VectorToString(stat.updateDetails) + "]";
            break;
        }
    }

    DfxReporter::ReportSyncStat(taskId_, syncInfo_, stat, syncInfo);
}

void DfxManager::HandleReportSyncFault(const std::string& position, const SyncFaultEvent& event)
{
    DfxReporter::ReportSyncFault(taskId_, position, event);
}

int32_t DfxManager::Start(const std::string &taskExtra)
{
    MEDIA_INFO_LOG("Start begin");
    ffrt::submit([this]() {
        bool taskHalfDay = HandleHalfDayMissions();
        bool taskTwoDay = HandleTwoDayMissions();
        bool taskOneWeek = HandleOneWeekMissions();
        if (taskHalfDay || taskTwoDay || taskOneWeek) {
            if (!HandleReportTaskCompleteMissions()) {
                RemoveTaskName(taskName_);
                ReportTaskComplete(taskName_);
            }
        } else {
            RemoveTaskName(taskName_);
            ReportTaskComplete(taskName_);
        }
    });
    return E_OK;
}

int32_t DfxManager::Stop(const std::string &taskExtra)
{
    return E_OK;
}

static void HandleReportTaskCompleteTask(DfxData *data)
{
    MediaLibraryBaseBgProcessor::RemoveTaskName(DFX_HANDLE_HALF_DAY_MISSIONS);
    MediaLibraryBaseBgProcessor::ReportTaskComplete(DFX_HANDLE_HALF_DAY_MISSIONS);
}

bool DfxManager::HandleReportTaskCompleteMissions()
{
    if (!isInitSuccess_) {
        MEDIA_WARN_LOG("DfxManager not init");
        return false;
    }
    MEDIA_INFO_LOG("start handle statistic behavior");
    auto *taskData = new (nothrow) StatisticData(dfxReporter_);
    if (taskData == nullptr) {
        MEDIA_ERR_LOG("Failed to alloc async data for Handle Half Day Missions!");
        return false;
    }
    auto statisticTask = make_shared<DfxTask>(HandleReportTaskCompleteTask, taskData);
    if (statisticTask == nullptr) {
        MEDIA_ERR_LOG("Failed to create statistic task.");
        delete taskData;
        return false;
    }
    dfxWorker_->AddTask(statisticTask);
    return true;
}
} // namespace Media
} // namespace OHOS
