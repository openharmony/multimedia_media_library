/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#define MLOG_TAG "MedialibrarySubscribe"

#include "medialibrary_subscriber.h"

#include <memory>
#include "appexecfwk_errors.h"
#include "background_cloud_file_processor.h"
#include "background_task_mgr_helper.h"
#ifdef HAS_BATTERY_MANAGER_PART
#include "battery_srv_client.h"
#endif
#include "bundle_info.h"
#include "cloud_media_asset_manager.h"
#include "cloud_media_asset_types.h"
#include "cloud_sync_utils.h"
#include "cloud_upload_checker.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "common_event_utils.h"
#include "dfx_cloud_manager.h"

#include "want.h"
#include "post_event_utils.h"
#ifdef HAS_POWER_MANAGER_PART
#include "power_mgr_client.h"
#endif
#ifdef HAS_THERMAL_MANAGER_PART
#include "thermal_mgr_client.h"
#endif

#include "medialibrary_album_fusion_utils.h"
#include "medialibrary_bundle_manager.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_errno.h"
#include "medialibrary_inotify.h"
#include "medialibrary_restore.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "media_scanner_manager.h"
#include "application_context.h"
#include "ability_manager_client.h"
#include "resource_type.h"
#include "dfx_manager.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_rdb_utils.h"
#include "moving_photo_processor.h"
#include "permission_utils.h"
#include "thumbnail_generate_worker_manager.h"
#include "parameters.h"

#ifdef HAS_WIFI_MANAGER_PART
#include "wifi_device.h"
#endif
#include "power_efficiency_manager.h"
#include "photo_album_lpath_operation.h"
#include "enhancement_manager.h"

using namespace OHOS::AAFwk;

namespace OHOS {
namespace Media {
// The task can be performed when the battery level reaches the value
const int32_t PROPER_DEVICE_BATTERY_CAPACITY = 50;

// The task can be performed only when the temperature of the device is lower than the value
const int32_t PROPER_DEVICE_TEMPERATURE_LEVEL = 1;
const int32_t PROPER_DEVICE_TEMPERATURE_LEVEL_HOT = 3;

// WIFI should be available in this state
const int32_t WIFI_STATE_CONNECTED = 4;

const int32_t DELAY_TASK_TIME = 30000;
const int32_t COMMON_EVENT_KEY_GET_DEFAULT_PARAM = -1;
const int32_t MegaByte = 1024 * 1024;
const int32_t MAX_FILE_SIZE_MB = 200;
const std::string COMMON_EVENT_KEY_BATTERY_CAPACITY = "soc";
const std::string COMMON_EVENT_KEY_DEVICE_TEMPERATURE = "0";
const std::string KEY_HIVIEW_VERSION_TYPE = "const.logsystem.versiontype";

// The network should be available in this state
const int32_t NET_CONN_STATE_CONNECTED = 3;
// The net bearer type is in net_all_capabilities.h
const int32_t BEARER_CELLULAR = 0;
bool MedialibrarySubscriber::isCellularNetConnected_ = false;
bool MedialibrarySubscriber::isWifiConnected_ = false;
bool MedialibrarySubscriber::currentStatus_ = false;

const std::vector<std::string> MedialibrarySubscriber::events_ = {
    EventFwk::CommonEventSupport::COMMON_EVENT_CHARGING,
    EventFwk::CommonEventSupport::COMMON_EVENT_DISCHARGING,
    EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF,
    EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON,
    EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED,
    EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_CHANGED,
    EventFwk::CommonEventSupport::COMMON_EVENT_THERMAL_LEVEL_CHANGED,
    EventFwk::CommonEventSupport::COMMON_EVENT_WIFI_CONN_STATE,
    EventFwk::CommonEventSupport::COMMON_EVENT_CONNECTIVITY_CHANGE
};

const std::map<std::string, StatusEventType> BACKGROUND_OPERATION_STATUS_MAP = {
    {EventFwk::CommonEventSupport::COMMON_EVENT_CHARGING, StatusEventType::CHARGING},
    {EventFwk::CommonEventSupport::COMMON_EVENT_DISCHARGING, StatusEventType::DISCHARGING},
    {EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF, StatusEventType::SCREEN_OFF},
    {EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON, StatusEventType::SCREEN_ON},
    {EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_CHANGED, StatusEventType::BATTERY_CHANGED},
    {EventFwk::CommonEventSupport::COMMON_EVENT_THERMAL_LEVEL_CHANGED, StatusEventType::THERMAL_LEVEL_CHANGED},
};

MedialibrarySubscriber::MedialibrarySubscriber(const EventFwk::CommonEventSubscribeInfo &subscriberInfo)
    : EventFwk::CommonEventSubscriber(subscriberInfo)
{
#ifdef HAS_POWER_MANAGER_PART
    auto& powerMgrClient = PowerMgr::PowerMgrClient::GetInstance();
    isScreenOff_ = !powerMgrClient.IsScreenOn();
#endif
#ifdef HAS_BATTERY_MANAGER_PART
    auto& batteryClient = PowerMgr::BatterySrvClient::GetInstance();
    auto chargeState = batteryClient.GetChargingStatus();
    isCharging_ = (chargeState == PowerMgr::BatteryChargeState::CHARGE_STATE_ENABLE) ||
        (chargeState == PowerMgr::BatteryChargeState::CHARGE_STATE_FULL);
    isPowerSufficient_ = batteryClient.GetCapacity() >= PROPER_DEVICE_BATTERY_CAPACITY;
#endif
#ifdef HAS_THERMAL_MANAGER_PART
    auto& thermalMgrClient = PowerMgr::ThermalMgrClient::GetInstance();
    newTemperatureLevel_ = static_cast<int32_t>(thermalMgrClient.GetThermalLevel());
    isDeviceTemperatureProper_ = newTemperatureLevel_ <= PROPER_DEVICE_TEMPERATURE_LEVEL;
#endif
#ifdef HAS_WIFI_MANAGER_PART
    auto wifiDevicePtr = Wifi::WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
    if (wifiDevicePtr == nullptr) {
        MEDIA_ERR_LOG("MedialibrarySubscriber wifiDevicePtr is null");
    } else {
        ErrCode ret = wifiDevicePtr->IsConnected(isWifiConnected_);
        if (ret != Wifi::WIFI_OPT_SUCCESS) {
            MEDIA_ERR_LOG("MedialibrarySubscriber Get-IsConnected-fail: -%{public}d", ret);
        }
    }
#endif
    MEDIA_DEBUG_LOG("MedialibrarySubscriber current status:%{public}d, %{public}d, %{public}d, %{public}d, %{public}d",
        isScreenOff_, isCharging_, isPowerSufficient_, isDeviceTemperatureProper_, isWifiConnected_);
}

MedialibrarySubscriber::~MedialibrarySubscriber()
{
    EndBackgroundOperationThread();
}

bool MedialibrarySubscriber::Subscribe(void)
{
    EventFwk::MatchingSkills matchingSkills;
    for (auto event : events_) {
        matchingSkills.AddEvent(event);
    }
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    std::shared_ptr<MedialibrarySubscriber> subscriber = std::make_shared<MedialibrarySubscriber>(subscribeInfo);
    return EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber);
}

static bool IsBetaVersion()
{
    static const string versionType = system::GetParameter(KEY_HIVIEW_VERSION_TYPE, "unknown");
    static bool isBetaVersion = versionType.find("beta") != std::string::npos;
    return isBetaVersion;
}

static void UploadDBFile()
{
    int64_t begin = MediaFileUtils::UTCTimeMilliSeconds();
    static const std::string databaseDir = MEDIA_DB_DIR + "/rdb";
    static const std::vector<std::string> dbFileName = { "/media_library.db",
                                                         "/media_library.db-shm",
                                                         "/media_library.db-wal" };
    static const std::string destPath = "/data/storage/el2/log/logpack";
    int64_t totalFileSize = 0;
    for (auto &dbName : dbFileName) {
        string dbPath = databaseDir + dbName;
        struct stat statInfo {};
        if (stat(dbPath.c_str(), &statInfo) != 0) {
            continue;
        }
        totalFileSize += statInfo.st_size;
    }
    totalFileSize /= MegaByte; // Convert bytes to MB
    if (totalFileSize > MAX_FILE_SIZE_MB) {
        MEDIA_WARN_LOG("DB file over 200MB are not uploaded, totalFileSize is %{public}ld MB",
            static_cast<long>(totalFileSize));
        return ;
    }
    if (!MediaFileUtils::IsFileExists(destPath) && !MediaFileUtils::CreateDirectory(destPath)) {
        MEDIA_ERR_LOG("Create dir failed, dir=%{private}s", destPath.c_str());
        return ;
    }
    auto dataManager = MediaLibraryDataManager::GetInstance();
    if (dataManager == nullptr) {
        MEDIA_ERR_LOG("dataManager is nullptr");
        return;
    }
    dataManager->UploadDBFileInner();
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("Handle %{public}ld MB DBFile success, cost %{public}ld ms", static_cast<long>(totalFileSize),
        static_cast<long>(end - begin));
}

void MedialibrarySubscriber::CheckHalfDayMissions()
{
    if (isScreenOff_ && isCharging_) {
        if (IsBetaVersion()) {
            MEDIA_INFO_LOG("Version is BetaVersion, UploadDBFile");
            UploadDBFile();
        }
        DfxManager::GetInstance()->HandleHalfDayMissions();
        MediaLibraryRestore::GetInstance().CheckBackup();
    }
    if (!isScreenOff_ || !isCharging_) {
        MediaLibraryRestore::GetInstance().InterruptBackup();
    }
}

void MedialibrarySubscriber::UpdateCurrentStatus()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (deviceTemperatureLevel_ != newTemperatureLevel_) {
        deviceTemperatureLevel_ = newTemperatureLevel_;
        ThumbnailService::GetInstance()->NotifyTempStatusForReady(deviceTemperatureLevel_);
    }
    bool newStatus = isScreenOff_ && isCharging_ && isPowerSufficient_ && isDeviceTemperatureProper_;
    if (currentStatus_ == newStatus) {
        return;
    }

    MEDIA_INFO_LOG("update status current:%{public}d, new:%{public}d, %{public}d, %{public}d, %{public}d, %{public}d",
        currentStatus_, newStatus, isScreenOff_, isCharging_, isPowerSufficient_, isDeviceTemperatureProper_);
    PowerEfficiencyManager::SetSubscriberStatus(isCharging_, isScreenOff_);

    currentStatus_ = newStatus;
    ThumbnailService::GetInstance()->UpdateCurrentStatusForTask(newStatus);
    EndBackgroundOperationThread();
    if (currentStatus_) {
        isTaskWaiting_ = true;
        backgroundOperationThread_ = std::thread([this] { this->DoBackgroundOperation(); });
    } else {
        StopBackgroundOperation();
    }
}

void MedialibrarySubscriber::WalCheckPointAsync()
{
    if (!isScreenOff_ || !isCharging_) {
        return;
    }
    std::thread(MediaLibraryRdbStore::WalCheckPoint).detach();
}

void MedialibrarySubscriber::UpdateBackgroundOperationStatus(
    const AAFwk::Want &want, const StatusEventType statusEventType)
{
    switch (statusEventType) {
        case StatusEventType::SCREEN_OFF:
            isScreenOff_ = true;
            CheckHalfDayMissions();
            WalCheckPointAsync();
            break;
        case StatusEventType::SCREEN_ON:
            isScreenOff_ = false;
            CheckHalfDayMissions();
            break;
        case StatusEventType::CHARGING:
            isCharging_ = true;
            CheckHalfDayMissions();
            WalCheckPointAsync();
            break;
        case StatusEventType::DISCHARGING:
            isCharging_ = false;
            CheckHalfDayMissions();
            break;
        case StatusEventType::BATTERY_CHANGED:
            isPowerSufficient_ = want.GetIntParam(COMMON_EVENT_KEY_BATTERY_CAPACITY,
                COMMON_EVENT_KEY_GET_DEFAULT_PARAM) >= PROPER_DEVICE_BATTERY_CAPACITY;
            break;
        case StatusEventType::THERMAL_LEVEL_CHANGED: {
            newTemperatureLevel_ = want.GetIntParam(COMMON_EVENT_KEY_DEVICE_TEMPERATURE,
                COMMON_EVENT_KEY_GET_DEFAULT_PARAM);
            isDeviceTemperatureProper_ = newTemperatureLevel_ <= PROPER_DEVICE_TEMPERATURE_LEVEL;
            PowerEfficiencyManager::UpdateAlbumUpdateInterval(isDeviceTemperatureProper_);
            break;
        }
        default:
            MEDIA_WARN_LOG("StatusEventType:%{public}d is not invalid", statusEventType);
            return;
    }

    UpdateCurrentStatus();
    UpdateBackgroundTimer();
}

void MedialibrarySubscriber::UpdateCloudMediaAssetDownloadStatus(const AAFwk::Want &want,
    const StatusEventType statusEventType)
{
    if (statusEventType != StatusEventType::THERMAL_LEVEL_CHANGED) {
        return;
    }
    int32_t taskStatus = CloudMediaAssetManager::GetInstance().GetTaskStatus();
    int32_t downloadType = CloudMediaAssetManager::GetInstance().GetDownloadType();
    bool foregroundTemperature = want.GetIntParam(COMMON_EVENT_KEY_DEVICE_TEMPERATURE,
        COMMON_EVENT_KEY_GET_DEFAULT_PARAM) <= PROPER_DEVICE_TEMPERATURE_LEVEL_HOT;
    if (!foregroundTemperature && downloadType == static_cast<int32_t>(CloudMediaDownloadType::DOWNLOAD_FORCE)) {
        CloudMediaAssetManager::GetInstance().PauseDownloadCloudAsset(CloudMediaTaskPauseCause::TEMPERATURE_LIMIT);
        return;
    }
    if (foregroundTemperature && taskStatus == static_cast<int32_t>(CloudMediaAssetTaskStatus::PAUSED)) {
        CloudMediaAssetManager::GetInstance().RecoverDownloadCloudAsset(
            CloudMediaTaskRecoverCause::FOREGROUND_TEMPERATURE_PROPER);
    }
}

bool MedialibrarySubscriber::IsCellularNetConnected()
{
    return isCellularNetConnected_;
}

bool MedialibrarySubscriber::IsWifiConnected()
{
    return isWifiConnected_;
}

bool MedialibrarySubscriber::IsCurrentStatusOn()
{
    return currentStatus_;
}

void MedialibrarySubscriber::UpdateCloudMediaAssetDownloadTaskStatus()
{
    if (!isCellularNetConnected_) {
        MEDIA_INFO_LOG("CellularNet not connected.");
        int32_t taskStatus = CloudMediaAssetManager::GetInstance().GetTaskStatus();
        if (taskStatus == static_cast<int32_t>(CloudMediaAssetTaskStatus::PAUSED)) {
            CloudMediaAssetManager::GetInstance().PauseDownloadCloudAsset(CloudMediaTaskPauseCause::NETWORK_FLOW_LIMIT);
        }
        return;
    }
    if (CloudSyncUtils::IsUnlimitedTrafficStatusOn()) {
        CloudMediaAssetManager::GetInstance().RecoverDownloadCloudAsset(CloudMediaTaskRecoverCause::NETWORK_NORMAL);
    } else if (!isWifiConnected_) {
        CloudMediaAssetManager::GetInstance().PauseDownloadCloudAsset(CloudMediaTaskPauseCause::WIFI_UNAVAILABLE);
    }
}

void MedialibrarySubscriber::OnReceiveEvent(const EventFwk::CommonEventData &eventData)
{
    const AAFwk::Want &want = eventData.GetWant();
    std::string action = want.GetAction();
    if (action != EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_CHANGED) {
        MEDIA_INFO_LOG("OnReceiveEvent action:%{public}s.", action.c_str());
    }
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_WIFI_CONN_STATE) {
        isWifiConnected_ = eventData.GetCode() == WIFI_STATE_CONNECTED;
        UpdateBackgroundTimer();
        if (isWifiConnected_) {
            CloudMediaAssetManager::GetInstance().RecoverDownloadCloudAsset(CloudMediaTaskRecoverCause::NETWORK_NORMAL);
        }
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_CONNECTIVITY_CHANGE) {
        int netType = want.GetIntParam("NetType", -1);
        bool cellularNetConnected = eventData.GetCode() == NET_CONN_STATE_CONNECTED;
        isCellularNetConnected_ = netType == BEARER_CELLULAR ? cellularNetConnected : isCellularNetConnected_;
        UpdateCloudMediaAssetDownloadTaskStatus();
    } else if (BACKGROUND_OPERATION_STATUS_MAP.count(action) != 0) {
        UpdateBackgroundOperationStatus(want, BACKGROUND_OPERATION_STATUS_MAP.at(action));
        UpdateCloudMediaAssetDownloadStatus(want, BACKGROUND_OPERATION_STATUS_MAP.at(action));
    } else if (action.compare(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED) == 0) {
        string packageName = want.GetElement().GetBundleName();
        RevertPendingByPackage(packageName);
        MediaLibraryBundleManager::GetInstance()->Clear();
        PermissionUtils::ClearBundleInfoInCache();
    }

    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_WIFI_CONN_STATE ||
        action == EventFwk::CommonEventSupport::COMMON_EVENT_CONNECTIVITY_CHANGE) {
        EnhancementManager::GetInstance().HandleNetChange(isWifiConnected_, isCellularNetConnected_);
    }
}

int64_t MedialibrarySubscriber::GetNowTime()
{
    struct timespec t;
    constexpr int64_t SEC_TO_MSEC = 1e3;
    constexpr int64_t MSEC_TO_NSEC = 1e6;
    clock_gettime(CLOCK_REALTIME, &t);
    return t.tv_sec * SEC_TO_MSEC + t.tv_nsec / MSEC_TO_NSEC;
}

void MedialibrarySubscriber::Init()
{
    lockTime_ = GetNowTime();
    agingCount_ = 0;
}

void DeleteTemporaryPhotos()
{
    auto dataManager = MediaLibraryDataManager::GetInstance();
    if (dataManager == nullptr) {
        return;
    }

    string UriString = PAH_DISCARD_CAMERA_PHOTO;
    MediaFileUtils::UriAppendKeyValue(UriString, URI_PARAM_API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri uri(UriString);
    MediaLibraryCommand cmd(uri);
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(PhotoColumn::PHOTO_IS_TEMP, true);
    DataShare::DataSharePredicates predicates;

    // 24H之前的数据
    int64_t current = MediaFileUtils::UTCTimeMilliSeconds();
    int64_t timeBefore24Hours = current - 24 * 60 * 60 * 1000;
    string where = PhotoColumn::PHOTO_IS_TEMP + " = 1 AND (" + PhotoColumn::MEDIA_DATE_ADDED + " <= " +
        to_string(timeBefore24Hours) + " OR " + MediaColumn::MEDIA_ID + " NOT IN (SELECT " + MediaColumn::MEDIA_ID +
        " FROM (SELECT " + MediaColumn::MEDIA_ID + " FROM " + PhotoColumn::PHOTOS_TABLE + " WHERE " +
        PhotoColumn::PHOTO_IS_TEMP + " = 1 " + "ORDER BY " + MediaColumn::MEDIA_ID +
        " DESC LIMIT 50)) AND (select COUNT(1) from " + PhotoColumn::PHOTOS_TABLE +
        " where " + PhotoColumn::PHOTO_IS_TEMP + " = 1) > 100) ";
    predicates.SetWhereClause(where);

    auto changedRows = dataManager->Update(cmd, valuesBucket, predicates);
    if (changedRows < 0) {
        MEDIA_INFO_LOG("Failed to update property of asset, err: %{public}d", changedRows);
        return;
    }
    MEDIA_INFO_LOG("delete %{public}d temp files exceeding 24 hous or exceed maximum quantity.", changedRows);
}

void MedialibrarySubscriber::DoThumbnailOperation()
{
    auto dataManager = MediaLibraryDataManager::GetInstance();
    if (dataManager == nullptr) {
        return;
    }

    auto result = dataManager->GenerateThumbnailBackground();
    if (result != E_OK) {
        MEDIA_ERR_LOG("GenerateThumbnailBackground faild");
    }

    result = dataManager->UpgradeThumbnailBackground(isWifiConnected_);
    if (result != E_OK) {
        MEDIA_ERR_LOG("UpgradeThumbnailBackground faild");
    }

    result = dataManager->DoAging();
    if (result != E_OK) {
        MEDIA_ERR_LOG("DoAging faild");
    }

    shared_ptr<int> trashCountPtr = make_shared<int>();
    result = dataManager->DoTrashAging(trashCountPtr);
    if (result != E_OK) {
        MEDIA_ERR_LOG("DoTrashAging faild");
    }
    VariantMap map = {{KEY_COUNT, *trashCountPtr}};
    PostEventUtils::GetInstance().PostStatProcess(StatType::AGING_STAT, map);
}

static void QueryBurstNeedUpdate(AsyncTaskData *data)
{
    auto dataManager = MediaLibraryDataManager::GetInstance();
    if (dataManager == nullptr) {
        return;
    }

    int32_t result = dataManager->UpdateBurstFromGallery();
    if (result != E_OK) {
        MEDIA_ERR_LOG("UpdateBurstFromGallery faild");
    }
}

static int32_t DoUpdateBurstFromGallery()
{
    MEDIA_INFO_LOG("Begin DoUpdateBurstFromGallery");
    auto asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    if (asyncWorker == nullptr) {
        MEDIA_ERR_LOG("Failed to get async worker instance!");
        return E_FAIL;
    }
    shared_ptr<MediaLibraryAsyncTask> updateBurstTask =
        make_shared<MediaLibraryAsyncTask>(QueryBurstNeedUpdate, nullptr);
    if (updateBurstTask != nullptr) {
        asyncWorker->AddTask(updateBurstTask, false);
    } else {
        MEDIA_ERR_LOG("Failed to create async task for updateBurstTask!");
        return E_FAIL;
    }
    return E_SUCCESS;
}

static void UpdateDateTakenWhenZero(AsyncTaskData *data)
{
    auto dataManager = MediaLibraryDataManager::GetInstance();
    if (dataManager == nullptr) {
        MEDIA_ERR_LOG("Failed to MediaLibraryDataManager instance!");
        return;
    }

    int32_t result = dataManager->UpdateDateTakenWhenZero();
    if (result != E_OK) {
        MEDIA_ERR_LOG("UpdateDateTakenWhenZero faild, result = %{public}d", result);
    }
}

static int32_t DoUpdateDateTakenWhenZero()
{
    MEDIA_DEBUG_LOG("Begin DoUpdateDateTakenWhenZero");
    auto asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    if (asyncWorker == nullptr) {
        MEDIA_ERR_LOG("Failed to get async worker instance!");
        return E_FAIL;
    }
    shared_ptr<MediaLibraryAsyncTask> UpdateDateTakenWhenZeroTask =
        make_shared<MediaLibraryAsyncTask>(UpdateDateTakenWhenZero, nullptr);
    if (UpdateDateTakenWhenZeroTask != nullptr) {
        asyncWorker->AddTask(UpdateDateTakenWhenZeroTask, false);
    } else {
        MEDIA_ERR_LOG("Failed to create async task for UpdateDateTakenWhenZeroTask !");
        return E_FAIL;
    }
    return E_SUCCESS;
}

static void RecoverBackgroundDownloadCloudMediaAsset()
{
    if (!CloudMediaAssetManager::GetInstance().SetBgDownloadPermission(true)) {
        return;
    }
    int32_t ret = CloudMediaAssetManager::GetInstance().RecoverDownloadCloudAsset(
        CloudMediaTaskRecoverCause::BACKGROUND_TASK_AVAILABLE);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("RecoverDownloadCloudAsset faild");
    }
}

static void UpdateBurstCoverLevelFromGallery(AsyncTaskData *data)
{
    auto dataManager = MediaLibraryDataManager::GetInstance();
    if (dataManager == nullptr) {
        return;
    }

    int32_t result = dataManager->UpdateBurstCoverLevelFromGallery();
    if (result != E_OK) {
        MEDIA_ERR_LOG("UpdateBurstCoverLevelFromGallery faild");
    }
}

static int32_t DoUpdateBurstCoverLevelFromGallery()
{
    MEDIA_INFO_LOG("Begin DoUpdateBurstCoverLevelFromGallery");
    auto asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    if (asyncWorker == nullptr) {
        MEDIA_ERR_LOG("Failed to get async worker instance!");
        return E_FAIL;
    }
    shared_ptr<MediaLibraryAsyncTask> updateBurstCoverLevelTask =
        make_shared<MediaLibraryAsyncTask>(UpdateBurstCoverLevelFromGallery, nullptr);
    if (updateBurstCoverLevelTask != nullptr) {
        asyncWorker->AddTask(updateBurstCoverLevelTask, false);
    } else {
        MEDIA_ERR_LOG("Failed to create async task for updateBurstCoverLevelTask!");
        return E_FAIL;
    }
    return E_SUCCESS;
}

void MedialibrarySubscriber::DoBackgroundOperation()
{
    if (!IsDelayTaskTimeOut() || !currentStatus_) {
        MEDIA_INFO_LOG("The conditions for DoBackgroundOperation are not met, will return.");
        return;
    }

    // delete temporary photos
    DeleteTemporaryPhotos();

    BackgroundTaskMgr::EfficiencyResourceInfo resourceInfo = BackgroundTaskMgr::EfficiencyResourceInfo(
        BackgroundTaskMgr::ResourceType::CPU, true, 0, "apply", true, true);
    BackgroundTaskMgr::BackgroundTaskMgrHelper::ApplyEfficiencyResources(resourceInfo);
    Init();
    DoThumbnailOperation();
    // update burst from gallery
    int32_t ret = DoUpdateBurstFromGallery();
    if (ret != E_OK) {
        MEDIA_ERR_LOG("DoUpdateBurstFromGallery faild");
    }
    CloudUploadChecker::HandleNoOriginPhoto();
    ret = DoUpdateDateTakenWhenZero();
    if (ret != E_OK) {
        MEDIA_ERR_LOG("DoUpdateDateTakenWhenZero faild");
    }
    ret = DoUpdateBurstCoverLevelFromGallery();
    CHECK_AND_PRINT_LOG(ret == E_OK, "DoUpdateBurstCoverLevelFromGallery faild");
    RecoverBackgroundDownloadCloudMediaAsset();
    CloudMediaAssetManager::GetInstance().StartDeleteCloudMediaAssets();
    // compat old-version moving photo
    MovingPhotoProcessor::StartProcess();
    MediaLibraryAlbumFusionUtils::CleanInvalidCloudAlbumAndData();
    auto watch = MediaLibraryInotify::GetInstance();
    if (watch != nullptr) {
        watch->DoAging();
    }
}

static void PauseBackgroundDownloadCloudMedia()
{
    if (!CloudMediaAssetManager::GetInstance().SetBgDownloadPermission(false)) {
        return;
    }
    int32_t taskStatus = static_cast<int32_t>(CloudMediaAssetTaskStatus::DOWNLOADING);
    int32_t downloadType = static_cast<int32_t>(CloudMediaDownloadType::DOWNLOAD_GENTLE);
    if (CloudMediaAssetManager::GetInstance().GetTaskStatus() == taskStatus &&
        CloudMediaAssetManager::GetInstance().GetDownloadType() == downloadType) {
        CloudMediaAssetManager::GetInstance().PauseDownloadCloudAsset(
            CloudMediaTaskPauseCause::BACKGROUND_TASK_UNAVAILABLE);
    }
}

void MedialibrarySubscriber::StopBackgroundOperation()
{
    MovingPhotoProcessor::StopProcess();
    MediaLibraryDataManager::GetInstance()->InterruptBgworker();
    PhotoAlbumLPathOperation::GetInstance().Stop();
    PauseBackgroundDownloadCloudMedia();
    CloudMediaAssetManager::GetInstance().StopDeleteCloudMediaAssets();
}

#ifdef MEDIALIBRARY_MTP_ENABLE
void MedialibrarySubscriber::DoStartMtpService()
{
    AAFwk::Want want;
    want.SetElementName("com.ohos.medialibrary.medialibrarydata", "MtpService");
    auto abilityContext = AbilityRuntime::Context::GetApplicationContext();
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want, abilityContext->GetToken(),
        OHOS::AAFwk::DEFAULT_INVAL_VALUE);
    MEDIA_INFO_LOG("MedialibrarySubscriber::DoStartMtpService. End calling StartAbility. ret=%{public}d", err);
}
#endif

void MedialibrarySubscriber::RevertPendingByPackage(const std::string &bundleName)
{
    MediaLibraryDataManager::GetInstance()->RevertPendingByPackage(bundleName);
}

void MedialibrarySubscriber::UpdateBackgroundTimer()
{
    if (isCharging_ && isScreenOff_) {
        CloudSyncDfxManager::GetInstance().RunDfx();
    }

    ThumbnailGenerateWorkerManager::GetInstance().TryCloseThumbnailWorkerTimer();

    std::lock_guard<std::mutex> lock(mutex_);
    bool newStatus = isScreenOff_ && isCharging_ && isPowerSufficient_ &&
        isDeviceTemperatureProper_ && isWifiConnected_;
    if (timerStatus_ == newStatus) {
        return;
    }

    MEDIA_INFO_LOG("update timer status current:%{public}d, new:%{public}d, %{public}d, %{public}d, %{public}d, "
        "%{public}d, %{public}d",
        timerStatus_, newStatus, isScreenOff_, isCharging_, isPowerSufficient_, isDeviceTemperatureProper_,
        isWifiConnected_);

    timerStatus_ = newStatus;
    if (timerStatus_) {
        BackgroundCloudFileProcessor::StartTimer();
    } else {
        BackgroundCloudFileProcessor::StopTimer();
    }
}

bool MedialibrarySubscriber::IsDelayTaskTimeOut()
{
    std::unique_lock<std::mutex> lock(delayTaskLock_);
    return !delayTaskCv_.wait_for(lock, std::chrono::milliseconds(DELAY_TASK_TIME), [this]() {
        return !isTaskWaiting_;
    });
}

void MedialibrarySubscriber::EndBackgroundOperationThread()
{
    {
        std::unique_lock<std::mutex> lock(delayTaskLock_);
        isTaskWaiting_ = false;
    }
    delayTaskCv_.notify_all();
    if (!backgroundOperationThread_.joinable()) {
        return;
    }
    backgroundOperationThread_.join();
}
}  // namespace Media
}  // namespace OHOS
