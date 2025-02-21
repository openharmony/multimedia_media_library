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
#include "medialibrary_all_album_refresh_processor.h"
#include "medialibrary_bundle_manager.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_errno.h"
#include "medialibrary_inotify.h"
#ifdef META_RECOVERY_SUPPORT
#include "medialibrary_meta_recovery.h"
#endif
#include "medialibrary_restore.h"
#include "medialibrary_subscriber_database_utils.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "media_scanner_manager.h"
#include "application_context.h"
#include "ability_manager_client.h"
#include "resource_type.h"
#include "dfx_manager.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_type_const.h"
#include "moving_photo_processor.h"
#include "permission_utils.h"
#include "thumbnail_generate_worker_manager.h"
#include "userfilemgr_uri.h"
#include "common_timer_errors.h"
#include "parameters.h"
#ifdef HAS_WIFI_MANAGER_PART
#include "wifi_device.h"
#endif
#include "power_efficiency_manager.h"
#include "photo_album_lpath_operation.h"
#include "medialibrary_astc_stat.h"
#include "photo_mimetype_operation.h"
#include "photo_other_album_trans_operation.h"
#include "background_cloud_file_processor.h"
#include "enhancement_manager.h"

using namespace OHOS::AAFwk;

namespace OHOS {
namespace Media {
// The task can be performed when the battery level reaches the value
const int32_t PROPER_DEVICE_BATTERY_CAPACITY = 50;
const int32_t PROPER_DEVICE_BATTERY_CAPACITY_THUMBNAIL = 20;

const int TIME_START_RELEASE_TEMPERATURE_LIMIT = 1;
const int TIME_STOP_RELEASE_TEMPERATURE_LIMIT = 6;

// The task can be performed only when the temperature of the device is lower than the value
const int32_t PROPER_DEVICE_TEMPERATURE_LEVEL_37 = 1;
const int32_t PROPER_DEVICE_TEMPERATURE_LEVEL_40 = 2;
const int32_t PROPER_DEVICE_TEMPERATURE_LEVEL_43 = 3;

// WIFI should be available in this state
const int32_t WIFI_STATE_CONNECTED = 4;
const int32_t DELAY_TASK_TIME = 30000;
const int32_t COMMON_EVENT_KEY_GET_DEFAULT_PARAM = -1;
const int32_t MegaByte = 1024*1024;
const int32_t MAX_FILE_SIZE_MB = 10240;
const std::string COMMON_EVENT_KEY_BATTERY_CAPACITY = "soc";
const std::string COMMON_EVENT_KEY_DEVICE_TEMPERATURE = "0";

// The network should be available in this state
const int32_t NET_CONN_STATE_CONNECTED = 3;
// The net bearer type is in net_all_capabilities.h
const int32_t BEARER_CELLULAR = 0;
const int32_t THUMB_ASTC_ENOUGH = 20000;
bool MedialibrarySubscriber::isCellularNetConnected_ = false;
bool MedialibrarySubscriber::isWifiConnected_ = false;
bool MedialibrarySubscriber::currentStatus_ = false;
// BetaVersion will upload the DB, and the true uploadDBFlag indicates that uploading is enabled.
const std::string KEY_HIVIEW_VERSION_TYPE = "const.logsystem.versiontype";
std::atomic<bool> uploadDBFlag(true);

const std::vector<std::string> MedialibrarySubscriber::events_ = {
    EventFwk::CommonEventSupport::COMMON_EVENT_CHARGING,
    EventFwk::CommonEventSupport::COMMON_EVENT_DISCHARGING,
    EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF,
    EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON,
    EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED,
    EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_CHANGED,
    EventFwk::CommonEventSupport::COMMON_EVENT_THERMAL_LEVEL_CHANGED,
    EventFwk::CommonEventSupport::COMMON_EVENT_WIFI_CONN_STATE,
    EventFwk::CommonEventSupport::COMMON_EVENT_CONNECTIVITY_CHANGE,
    EventFwk::CommonEventSupport::COMMON_EVENT_TIME_TICK,
    EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGOUT
};

const std::map<std::string, StatusEventType> BACKGROUND_OPERATION_STATUS_MAP = {
    {EventFwk::CommonEventSupport::COMMON_EVENT_CHARGING, StatusEventType::CHARGING},
    {EventFwk::CommonEventSupport::COMMON_EVENT_DISCHARGING, StatusEventType::DISCHARGING},
    {EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF, StatusEventType::SCREEN_OFF},
    {EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON, StatusEventType::SCREEN_ON},
    {EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_CHANGED, StatusEventType::BATTERY_CHANGED},
    {EventFwk::CommonEventSupport::COMMON_EVENT_THERMAL_LEVEL_CHANGED, StatusEventType::THERMAL_LEVEL_CHANGED},
    {EventFwk::CommonEventSupport::COMMON_EVENT_TIME_TICK, StatusEventType::TIME_TICK},
};

bool GetNowLocalTime(std::tm &nowLocalTime)
{
    auto now = std::chrono::system_clock::now();
    std::time_t nowTime = std::chrono::system_clock::to_time_t(now);
    return localtime_r(&nowTime, &nowLocalTime) != nullptr;
}

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
    batteryCapacity_ = batteryClient.GetCapacity();
#endif
#ifdef HAS_THERMAL_MANAGER_PART
    auto& thermalMgrClient = PowerMgr::ThermalMgrClient::GetInstance();
    newTemperatureLevel_ = static_cast<int32_t>(thermalMgrClient.GetThermalLevel());
    isDeviceTemperatureProper_ = newTemperatureLevel_ <= PROPER_DEVICE_TEMPERATURE_LEVEL_37;
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
    MediaLibraryAllAlbumRefreshProcessor::GetInstance()->OnCurrentStatusChanged(
        isScreenOff_ && isCharging_ && batteryCapacity_ >= PROPER_DEVICE_BATTERY_CAPACITY
        && isDeviceTemperatureProper_);
    MEDIA_DEBUG_LOG("MedialibrarySubscriber current status:%{public}d, %{public}d, %{public}d, %{public}d, %{public}d",
        isScreenOff_, isCharging_, batteryCapacity_, newTemperatureLevel_, isWifiConnected_);
}

MedialibrarySubscriber::~MedialibrarySubscriber() = default;

bool MedialibrarySubscriber::Subscribe(void)
{
    EventFwk::MatchingSkills matchingSkills;
    for (auto event : events_) {
        matchingSkills.AddEvent(event);
    }

    MEDIA_INFO_LOG("Subscribe: add event.");
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
    uploadDBFlag.store(false);
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
        MEDIA_WARN_LOG("DB file over 10GB are not uploaded, totalFileSize is %{public}ld MB",
            static_cast<long>(totalFileSize));
        uploadDBFlag.store(true);
        return ;
    }
    if (!MediaFileUtils::IsFileExists(destPath) && !MediaFileUtils::CreateDirectory(destPath)) {
        MEDIA_ERR_LOG("Create dir failed, dir=%{private}s", destPath.c_str());
        uploadDBFlag.store(true);
        return ;
    }
    auto dataManager = MediaLibraryDataManager::GetInstance();
    if (dataManager == nullptr) {
        MEDIA_ERR_LOG("dataManager is nullptr");
        uploadDBFlag.store(true);
        return;
    }
    dataManager->UploadDBFileInner(totalFileSize);
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    MEDIA_INFO_LOG("Handle %{public}ld MB DBFile success, cost %{public}ld ms", (long)(totalFileSize),
        (long)(end - begin));
    uploadDBFlag.store(true);
}

void MedialibrarySubscriber::CheckHalfDayMissions()
{
    if (isScreenOff_ && isCharging_) {
        if (IsBetaVersion() && uploadDBFlag.load()) {
            MEDIA_INFO_LOG("Version is BetaVersion, UploadDBFile");
            UploadDBFile();
        }
        DfxManager::GetInstance()->HandleHalfDayMissions();
        MediaLibraryRestore::GetInstance().CheckBackup();
    }
    if (!isScreenOff_ || !isCharging_) {
        MediaLibraryRestore::GetInstance().InterruptBackup();
    }
#ifdef META_RECOVERY_SUPPORT
    MediaLibraryMetaRecovery::GetInstance().StatisticSave();
#endif
}

void MedialibrarySubscriber::UpdateCurrentStatus()
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::tm nowLocalTime;
    bool newStatus = false;
    bool isPowerSufficient = batteryCapacity_ >= PROPER_DEVICE_BATTERY_CAPACITY;
    if (GetNowLocalTime(nowLocalTime) && nowLocalTime.tm_hour >= TIME_START_RELEASE_TEMPERATURE_LIMIT &&
        nowLocalTime.tm_hour < TIME_STOP_RELEASE_TEMPERATURE_LIMIT) {
        newStatus = isScreenOff_ && isCharging_ && isPowerSufficient &&
            newTemperatureLevel_ <= PROPER_DEVICE_TEMPERATURE_LEVEL_43;
    } else {
        newStatus = isScreenOff_ && isCharging_ && isPowerSufficient &&
            newTemperatureLevel_ <= PROPER_DEVICE_TEMPERATURE_LEVEL_37;
    }

    if (currentStatus_ == newStatus) {
        return;
    }

    MEDIA_INFO_LOG("update status current:%{public}d, new:%{public}d, %{public}d, %{public}d, %{public}d, %{public}d",
        currentStatus_, newStatus, isScreenOff_, isCharging_, isPowerSufficient, newTemperatureLevel_);
    currentStatus_ = newStatus;
    backgroundDelayTask_.EndBackgroundOperationThread();
    if (currentStatus_) {
        backgroundDelayTask_.SetOperationThread([this] { this->DoBackgroundOperation(); });
    } else {
        StopBackgroundOperation();
    }
    MediaLibraryAllAlbumRefreshProcessor::GetInstance()->OnCurrentStatusChanged(currentStatus_);
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
            break;
        case StatusEventType::SCREEN_ON:
            isScreenOff_ = false;
            break;
        case StatusEventType::CHARGING:
            isCharging_ = true;
            break;
        case StatusEventType::DISCHARGING:
            isCharging_ = false;
            break;
        case StatusEventType::BATTERY_CHANGED:
            batteryCapacity_ = want.GetIntParam(COMMON_EVENT_KEY_BATTERY_CAPACITY,
                COMMON_EVENT_KEY_GET_DEFAULT_PARAM);
            break;
        case StatusEventType::THERMAL_LEVEL_CHANGED: {
            newTemperatureLevel_ = want.GetIntParam(COMMON_EVENT_KEY_DEVICE_TEMPERATURE,
                COMMON_EVENT_KEY_GET_DEFAULT_PARAM);
            isDeviceTemperatureProper_ = newTemperatureLevel_ <= PROPER_DEVICE_TEMPERATURE_LEVEL_37;
            break;
        }
        case StatusEventType::TIME_TICK:
            break;
        default:
            MEDIA_WARN_LOG("StatusEventType:%{public}d is not invalid", statusEventType);
            return;
    }

    UpdateCurrentStatus();
    UpdateThumbnailBgGenerationStatus();
    UpdateBackgroundTimer();
    DealWithEventsAfterUpdateStatus(statusEventType);
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
        COMMON_EVENT_KEY_GET_DEFAULT_PARAM) <= PROPER_DEVICE_TEMPERATURE_LEVEL_43;
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
    if (action != EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_CHANGED &&
        action != EventFwk::CommonEventSupport::COMMON_EVENT_TIME_TICK) {
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
        bool isNetConnected = eventData.GetCode() == NET_CONN_STATE_CONNECTED;
        MEDIA_INFO_LOG("netType: %{public}d, isConnected: %{public}d.", netType, static_cast<int32_t>(isNetConnected));
        isCellularNetConnected_ = netType == BEARER_CELLULAR ? isNetConnected : isCellularNetConnected_;
        UpdateCloudMediaAssetDownloadTaskStatus();
    } else if (BACKGROUND_OPERATION_STATUS_MAP.count(action) != 0) {
        UpdateBackgroundOperationStatus(want, BACKGROUND_OPERATION_STATUS_MAP.at(action));
        UpdateCloudMediaAssetDownloadStatus(want, BACKGROUND_OPERATION_STATUS_MAP.at(action));
    } else if (action.compare(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED) == 0) {
        string packageName = want.GetElement().GetBundleName();
        RevertPendingByPackage(packageName);
        MediaLibraryBundleManager::GetInstance()->Clear();
        PermissionUtils::ClearBundleInfoInCache();
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGOUT) {
        // when turn off gallery switch or quit account, clear the download lastest finished flag,
        // so we can download lastest images for the subsequent login new account
        BackgroundCloudFileProcessor::SetDownloadLatestFinished(false);
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
    CHECK_AND_RETURN_LOG(changedRows >= 0, "Failed to update property of asset, err: %{public}d", changedRows);
    MEDIA_INFO_LOG("delete %{public}d temp files exceeding 24 hous or exceed maximum quantity.", changedRows);
}

void MedialibrarySubscriber::DoAgingOperation()
{
    auto dataManager = MediaLibraryDataManager::GetInstance();
    CHECK_AND_RETURN_LOG(dataManager != nullptr, "dataManager is nullptr");

    int32_t result = dataManager->DoAging();
    CHECK_AND_PRINT_LOG(result == E_OK, "DoAging faild");

    shared_ptr<int> trashCountPtr = make_shared<int>();
    result = dataManager->DoTrashAging(trashCountPtr);
    CHECK_AND_PRINT_LOG(result == E_OK, "DoTrashAging faild");

    VariantMap map = {{KEY_COUNT, *trashCountPtr}};
    PostEventUtils::GetInstance().PostStatProcess(StatType::AGING_STAT, map);
}

static void QueryBurstNeedUpdate(AsyncTaskData *data)
{
    auto dataManager = MediaLibraryDataManager::GetInstance();
    CHECK_AND_RETURN_LOG(dataManager != nullptr,  "dataManager is nullptr");

    int32_t result = dataManager->UpdateBurstFromGallery();
    CHECK_AND_PRINT_LOG(result == E_OK, "UpdateBurstFromGallery faild");
}

static int32_t DoUpdateBurstFromGallery()
{
    MEDIA_INFO_LOG("Begin DoUpdateBurstFromGallery");
    auto asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    CHECK_AND_RETURN_RET_LOG(asyncWorker != nullptr, E_FAIL, "Failed to get async worker instance!");

    shared_ptr<MediaLibraryAsyncTask> updateBurstTask =
        make_shared<MediaLibraryAsyncTask>(QueryBurstNeedUpdate, nullptr);
    CHECK_AND_RETURN_RET_LOG(updateBurstTask != nullptr, E_FAIL,
        "Failed to create async task for updateBurstTask!");
    asyncWorker->AddTask(updateBurstTask, false);
    return E_SUCCESS;
}

static void RecoverBackgroundDownloadCloudMediaAsset()
{
    if (!CloudMediaAssetManager::GetInstance().SetBgDownloadPermission(true)) {
        return;
    }
    int32_t ret = CloudMediaAssetManager::GetInstance().RecoverDownloadCloudAsset(
        CloudMediaTaskRecoverCause::BACKGROUND_TASK_AVAILABLE);
    CHECK_AND_PRINT_LOG(ret == E_OK, "RecoverDownloadCloudAsset faild");
}

static void UpdateDateTakenWhenZero(AsyncTaskData *data)
{
    auto dataManager = MediaLibraryDataManager::GetInstance();
    CHECK_AND_RETURN_LOG(dataManager != nullptr, "Failed to MediaLibraryDataManager instance!");

    int32_t result = dataManager->UpdateDateTakenWhenZero();
    CHECK_AND_PRINT_LOG(result == E_OK, "UpdateDateTakenWhenZero faild, result = %{public}d", result);
}

static int32_t DoUpdateDateTakenWhenZero()
{
    MEDIA_DEBUG_LOG("Begin DoUpdateDateTakenWhenZero");
    auto asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    CHECK_AND_RETURN_RET_LOG(asyncWorker != nullptr, E_FAIL,
        "Failed to get async worker instance!");

    shared_ptr<MediaLibraryAsyncTask> UpdateDateTakenWhenZeroTask =
        make_shared<MediaLibraryAsyncTask>(UpdateDateTakenWhenZero, nullptr);
    CHECK_AND_RETURN_RET_LOG(UpdateDateTakenWhenZeroTask != nullptr, E_FAIL,
        "Failed to create async task for UpdateDateTakenWhenZeroTask !");
    asyncWorker->AddTask(UpdateDateTakenWhenZeroTask, false);
    return E_SUCCESS;
}

static void UpdateBurstCoverLevelFromGallery(AsyncTaskData *data)
{
    auto dataManager = MediaLibraryDataManager::GetInstance();
    CHECK_AND_RETURN_LOG(dataManager != nullptr, "dataManager is nullptr");

    int32_t result = dataManager->UpdateBurstCoverLevelFromGallery();
    CHECK_AND_PRINT_LOG(result == E_OK, "UpdateBurstCoverLevelFromGallery faild");
}

static int32_t DoUpdateBurstCoverLevelFromGallery()
{
    MEDIA_INFO_LOG("Begin DoUpdateBurstCoverLevelFromGallery");
    auto asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    CHECK_AND_RETURN_RET_LOG(asyncWorker != nullptr, E_FAIL,
        "Failed to get async worker instance!");

    shared_ptr<MediaLibraryAsyncTask> updateBurstCoverLevelTask =
        make_shared<MediaLibraryAsyncTask>(UpdateBurstCoverLevelFromGallery, nullptr);
    CHECK_AND_RETURN_RET_LOG(updateBurstCoverLevelTask != nullptr, E_FAIL,
        "Failed to create async task for updateBurstCoverLevelTask!");
    asyncWorker->AddTask(updateBurstCoverLevelTask, false);
    return E_SUCCESS;
}

void MedialibrarySubscriber::DoBackgroundOperation()
{
    bool cond = (!backgroundDelayTask_.IsDelayTaskTimeOut() || !currentStatus_);
    CHECK_AND_RETURN_LOG(!cond, "The conditions for DoBackgroundOperation are not met, will return.");
#ifdef META_RECOVERY_SUPPORT
    // check metadata recovery state
    MediaLibraryMetaRecovery::GetInstance().CheckRecoveryState();
#endif
    // delete temporary photos
    DeleteTemporaryPhotos();
    BackgroundTaskMgr::EfficiencyResourceInfo resourceInfo = BackgroundTaskMgr::EfficiencyResourceInfo(
        BackgroundTaskMgr::ResourceType::CPU, true, 0, "apply", true, true);
    BackgroundTaskMgr::BackgroundTaskMgrHelper::ApplyEfficiencyResources(resourceInfo);
    Init();
    DoAgingOperation();
    MediaLibraryRdbUtils::AnalyzePhotosData();
    // update burst from gallery
    int32_t ret = DoUpdateBurstFromGallery();
    CHECK_AND_PRINT_LOG(ret == E_OK, "DoUpdateBurstFromGallery faild");
    CloudUploadChecker::RepairNoOriginButLcd();
    CloudUploadChecker::HandleNoOriginPhoto();

    CloudUploadChecker::RepairNoDetailTime();
    // migration highlight info to new path
    if (MediaFileUtils::IsFileExists(ROOT_MEDIA_DIR + HIGHLIGHT_INFO_OLD)) {
        MEDIA_INFO_LOG("Migration highlight info to new path");
        bool retMigration = MediaFileUtils::CopyDirAndDelSrc(ROOT_MEDIA_DIR + HIGHLIGHT_INFO_OLD,
            ROOT_MEDIA_DIR + HIGHLIGHT_INFO_NEW);
        if (retMigration) {
            bool retDelete = MediaFileUtils::DeleteDir(ROOT_MEDIA_DIR + HIGHLIGHT_INFO_OLD);
            if (!retDelete) {
                MEDIA_ERR_LOG("Delete old highlight path fail");
            }
        }
    }
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
    PhotoMimetypeOperation::UpdateInvalidMimeType();
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
#ifdef META_RECOVERY_SUPPORT
    MediaLibraryMetaRecovery::GetInstance().InterruptRecovery();
#endif
    MovingPhotoProcessor::StopProcess();
    MediaLibraryDataManager::GetInstance()->InterruptBgworker();
    PauseBackgroundDownloadCloudMedia();
    PhotoAlbumLPathOperation::GetInstance().Stop();
    PhotoOtherAlbumTransOperation::GetInstance().Stop();
    CloudMediaAssetManager::GetInstance().StopDeleteCloudMediaAssets();
}

void MedialibrarySubscriber::UpdateThumbnailBgGenerationStatus()
{
    std::lock_guard<std::mutex> lock(mutex_);
    bool isPowerSufficientForThumbnail = batteryCapacity_ >= PROPER_DEVICE_BATTERY_CAPACITY_THUMBNAIL;
    bool newStatus = false;
    if (isCharging_) {
        newStatus = isScreenOff_ && isPowerSufficientForThumbnail &&
            newTemperatureLevel_ <= PROPER_DEVICE_TEMPERATURE_LEVEL_43;
    } else if (isScreenOff_ && newTemperatureLevel_ <= PROPER_DEVICE_TEMPERATURE_LEVEL_37 &&
        batteryCapacity_ >= PROPER_DEVICE_BATTERY_CAPACITY) {
        int32_t thumbAstcCount = 0;
        int32_t thumbTotalCount = 0;
        MedialibrarySubscriberDatabaseUtils::QueryThumbAstc(thumbAstcCount);
        MedialibrarySubscriberDatabaseUtils::QueryThumbTotal(thumbTotalCount);
        bool isThumbAstcEnough = thumbAstcCount > THUMB_ASTC_ENOUGH || thumbAstcCount == thumbTotalCount;
        newStatus = !isThumbAstcEnough;
        CHECK_AND_PRINT_LOG(isThumbAstcEnough,
            "ThumbnailBg generate status: isThumbAstcEnough:%{public}d,"
            " thumbAstcCount:%{public}d, thumbTotalCount:%{public}d",
            isThumbAstcEnough, thumbAstcCount, thumbTotalCount);
    }

    if (thumbnailBgGenerationStatus_ == newStatus) {
        return;
    }
    MEDIA_INFO_LOG("update status thumbnailBg:%{public}d, new:%{public}d, "
        "%{public}d, %{public}d, %{public}d, %{public}d",
        thumbnailBgGenerationStatus_, newStatus, isScreenOff_,
        isCharging_, batteryCapacity_, newTemperatureLevel_);
    thumbnailBgGenerationStatus_ = newStatus;

    thumbnailBgDelayTask_.EndBackgroundOperationThread();
    if (thumbnailBgGenerationStatus_) {
        thumbnailBgDelayTask_.SetOperationThread([this] { this->DoThumbnailBgOperation(); });
    } else {
        MediaLibraryAstcStat::GetInstance().GetInterruptInfo(isScreenOff_, isCharging_,
            isPowerSufficientForThumbnail,
            newTemperatureLevel_ <= PROPER_DEVICE_TEMPERATURE_LEVEL_40);
        StopThumbnailBgOperation();
    }
}

void MedialibrarySubscriber::DoThumbnailBgOperation()
{
    bool cond = (!thumbnailBgDelayTask_.IsDelayTaskTimeOut() || !thumbnailBgGenerationStatus_);
    CHECK_AND_RETURN_LOG(!cond, "The conditions for DoThumbnailBgOperation are not met, will return.");

    auto dataManager = MediaLibraryDataManager::GetInstance();
    CHECK_AND_RETURN_LOG(dataManager != nullptr, "dataManager is nullptr");

    auto result = dataManager->GenerateThumbnailBackground();
    CHECK_AND_PRINT_LOG(result == E_OK, "GenerateThumbnailBackground faild");

    result = dataManager->UpgradeThumbnailBackground(isWifiConnected_);
    CHECK_AND_PRINT_LOG(result == E_OK, "UpgradeThumbnailBackground faild");

    result = dataManager->GenerateHighlightThumbnailBackground();
    CHECK_AND_PRINT_LOG(result == E_OK, "GenerateHighlightThumbnailBackground failed %{public}d", result);
}

void MedialibrarySubscriber::StopThumbnailBgOperation()
{
    MediaLibraryDataManager::GetInstance()->InterruptThumbnailBgWorker();
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
    std::lock_guard<std::mutex> lock(mutex_);
    bool isPowerSufficient = batteryCapacity_ >= PROPER_DEVICE_BATTERY_CAPACITY;
    bool newStatus = isScreenOff_ && isCharging_ && isPowerSufficient &&
        isDeviceTemperatureProper_ && isWifiConnected_;
    if (timerStatus_ == newStatus) {
        return;
    }

    MEDIA_INFO_LOG("update timer status current:%{public}d, new:%{public}d, %{public}d, %{public}d, %{public}d, "
        "%{public}d, %{public}d",
        timerStatus_, newStatus, isScreenOff_, isCharging_, isPowerSufficient, isDeviceTemperatureProper_,
        isWifiConnected_);

    timerStatus_ = newStatus;
    if (timerStatus_) {
        BackgroundCloudFileProcessor::StartTimer();
    } else {
        BackgroundCloudFileProcessor::StopTimer();
    }
}

void MedialibrarySubscriber::DealWithEventsAfterUpdateStatus(const StatusEventType statusEventType)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (deviceTemperatureLevel_ != newTemperatureLevel_) {
        deviceTemperatureLevel_ = newTemperatureLevel_;
        ThumbnailService::GetInstance()->NotifyTempStatusForReady(deviceTemperatureLevel_);
    }

    CloudSyncDfxManager::GetInstance().RunDfx();
    ThumbnailService::GetInstance()->UpdateCurrentStatusForTask(thumbnailBgGenerationStatus_);
    ThumbnailGenerateWorkerManager::GetInstance().TryCloseThumbnailWorkerTimer();
    PowerEfficiencyManager::SetSubscriberStatus(isCharging_, isScreenOff_);

    if (statusEventType == StatusEventType::SCREEN_OFF || statusEventType == StatusEventType::CHARGING) {
        WalCheckPointAsync();
        CheckHalfDayMissions();
        return;
    }

    if (statusEventType == StatusEventType::SCREEN_ON || statusEventType == StatusEventType::DISCHARGING) {
        CheckHalfDayMissions();
        return;
    }

    if (statusEventType == StatusEventType::THERMAL_LEVEL_CHANGED) {
        MEDIA_INFO_LOG("Current temperature level is %{public}d", newTemperatureLevel_);
        PowerEfficiencyManager::UpdateAlbumUpdateInterval(isDeviceTemperatureProper_);
    }
}

bool MedialibrarySubscriber::DelayTask::IsDelayTaskTimeOut()
{
    std::unique_lock<std::mutex> lock(this->lock);
    return !cv.wait_for(lock, std::chrono::milliseconds(DELAY_TASK_TIME), [this]() {
        return !isTaskWaiting;
    });
}

void MedialibrarySubscriber::DelayTask::EndBackgroundOperationThread()
{
    {
        std::unique_lock<std::mutex> lock(this->lock);
        isTaskWaiting = false;
        MEDIA_INFO_LOG("DelayTask %{public}s EndBackgroundOperationThread", taskName.c_str());
    }
#ifdef META_RECOVERY_SUPPORT
    MediaLibraryMetaRecovery::GetInstance().InterruptRecovery();
#endif
    cv.notify_all();
    if (!operationThread.joinable()) {
        return;
    }
    operationThread.join();
}

void MedialibrarySubscriber::DelayTask::SetOperationThread(std::function<void()> operationTask)
{
    if (operationThread.joinable()) {
        operationThread.join();
    }
    {
        std::unique_lock<std::mutex> lock(this->lock);
        isTaskWaiting = true;
    }
    this->operationThread = std::thread(operationTask);
}

int32_t MedialibrarySubscriberDatabaseUtils::QueryThumbAstc(int32_t& thumbAstcCount)
{
    std::vector<std::string> columns = { "count(1) AS count" };
    std::string queryColumn = "count";
    NativeRdb::RdbPredicates astcPredicates(PhotoColumn::PHOTOS_TABLE);
    astcPredicates.GreaterThanOrEqualTo(PhotoColumn::PHOTO_THUMBNAIL_READY,
        static_cast<int32_t>(ThumbnailReady::GENERATE_THUMB_RETRY));
    int32_t errCode = QueryInt(astcPredicates, columns, queryColumn, thumbAstcCount);
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "Query thumbAstcCount fail: %{public}d", errCode);
    return E_OK;
}

int32_t MedialibrarySubscriberDatabaseUtils::QueryThumbTotal(int32_t& thumbTotalCount)
{
    std::vector<std::string> columns = { "count(1) AS count" };
    std::string queryColumn = "count";
    NativeRdb::RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    int32_t errCode = QueryInt(predicates, columns, queryColumn, thumbTotalCount);
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "Query thumbTotalCount fail: %{public}d", errCode);
    return E_OK;
}

int32_t MedialibrarySubscriberDatabaseUtils::QueryInt(const NativeRdb::AbsRdbPredicates &predicates,
    const std::vector<std::string> &columns, const std::string &queryColumn, int32_t &value)
{
    auto resultSet = MediaLibraryRdbStore::QueryWithFilter(predicates, columns);
    bool cond = (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK);
    CHECK_AND_RETURN_RET(!cond, E_DB_FAIL);
    value = GetInt32Val(queryColumn, resultSet);
    return E_OK;
}
}  // namespace Media
}  // namespace OHOS
