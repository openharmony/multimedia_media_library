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
#define MLOG_TAG "Subscribe"

#include "medialibrary_subscriber.h"

#include <memory>
#include "appexecfwk_errors.h"
#include "background_cloud_file_processor.h"
#include "background_task_mgr_helper.h"
#ifdef HAS_BATTERY_MANAGER_PART
#include "battery_srv_client.h"
#endif
#include "bundle_info.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "dfx_cloud_manager.h"

#include "want.h"
#include "post_event_utils.h"
#ifdef HAS_POWER_MANAGER_PART
#include "power_mgr_client.h"
#endif
#ifdef HAS_THERMAL_MANAGER_PART
#include "thermal_mgr_client.h"
#endif

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
#include "permission_utils.h"
#include "thumbnail_generate_worker_manager.h"

#ifdef HAS_WIFI_MANAGER_PART
#include "wifi_device.h"
#endif

using namespace OHOS::AAFwk;

namespace OHOS {
namespace Media {
// The task can be performed when the battery level reaches the value
const int32_t PROPER_DEVICE_BATTERY_CAPACITY = 50;

// The task can be performed only when the temperature of the device is lower than the value
// Level 0: The device temperature is lower than 35℃
// Level 1: The device temperature ranges from 35℃ to 37℃
const int32_t PROPER_DEVICE_TEMPERATURE_LEVEL = 1;

// WIFI should be available in this state
const int32_t WIFI_STATE_CONNECTED = 4;

const int32_t DELAY_TASK_TIME = 30000;
const int32_t COMMON_EVENT_KEY_GET_DEFAULT_PARAM = -1;
const std::string COMMON_EVENT_KEY_BATTERY_CAPACITY = "soc";
const std::string COMMON_EVENT_KEY_DEVICE_TEMPERATURE = "0";
const std::vector<std::string> MedialibrarySubscriber::events_ = {
    EventFwk::CommonEventSupport::COMMON_EVENT_CHARGING,
    EventFwk::CommonEventSupport::COMMON_EVENT_DISCHARGING,
    EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF,
    EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON,
    EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED,
    EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_CHANGED,
    EventFwk::CommonEventSupport::COMMON_EVENT_THERMAL_LEVEL_CHANGED,
    EventFwk::CommonEventSupport::COMMON_EVENT_WIFI_CONN_STATE
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
    isDeviceTemperatureProper_ = static_cast<int32_t>(
        thermalMgrClient.GetThermalLevel()) <= PROPER_DEVICE_TEMPERATURE_LEVEL;
#endif
#ifdef HAS_WIFI_MANAGER_PART
    auto wifiDevicePtr = Wifi::WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
    if (wifiDevicePtr == nullptr) {
        MEDIA_ERR_LOG("MedialibrarySubscriber wifiDevicePtr is null");
    } else {
        ErrCode ret = wifiDevicePtr->IsConnected(isWifiConn_);
        if (ret != Wifi::WIFI_OPT_SUCCESS) {
            MEDIA_ERR_LOG("MedialibrarySubscriber Get-IsConnected-fail: -%{public}d", ret);
        }
    }
#endif
    MEDIA_DEBUG_LOG("MedialibrarySubscriber current status:%{public}d, %{public}d, %{public}d, %{public}d, %{public}d",
        isScreenOff_, isCharging_, isPowerSufficient_, isDeviceTemperatureProper_, isWifiConn_);
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

void MedialibrarySubscriber::CheckHalfDayMissions()
{
    if (isScreenOff_ && isCharging_) {
        DfxManager::GetInstance()->HandleHalfDayMissions();
        MediaLibraryRestore::GetInstance().DoRdbHAModeSwitch();
    }
    if (!isScreenOff_ || !isCharging_) {
        MediaLibraryRestore::GetInstance().InterruptRdbHAModeSwitch();
    }
}

void MedialibrarySubscriber::UpdateCurrentStatus()
{
    std::lock_guard<std::mutex> lock(mutex_);
    bool newStatus = isScreenOff_ && isCharging_ && isPowerSufficient_ && isDeviceTemperatureProper_;
    if (currentStatus_ == newStatus) {
        return;
    }

    MEDIA_INFO_LOG("update status current:%{public}d, new:%{public}d, %{public}d, %{public}d, %{public}d, %{public}d",
        currentStatus_, newStatus, isScreenOff_, isCharging_, isPowerSufficient_, isDeviceTemperatureProper_);

    currentStatus_ = newStatus;
    EndBackgroundOperationThread();
    if (currentStatus_) {
        isTaskWaiting_ = true;
        backgroundOperationThread_ = std::thread([this] { this->DoBackgroundOperation(); });
    } else {
        StopBackgroundOperation();
    }
}

void MedialibrarySubscriber::UpdateBackgroundOperationStatus(
    const AAFwk::Want &want, const StatusEventType statusEventType)
{
    switch (statusEventType) {
        case StatusEventType::SCREEN_OFF:
            isScreenOff_ = true;
            CheckHalfDayMissions();
            break;
        case StatusEventType::SCREEN_ON:
            isScreenOff_ = false;
            CheckHalfDayMissions();
            break;
        case StatusEventType::CHARGING:
            isCharging_ = true;
            CheckHalfDayMissions();
            break;
        case StatusEventType::DISCHARGING:
            isCharging_ = false;
            CheckHalfDayMissions();
            break;
        case StatusEventType::BATTERY_CHANGED:
            isPowerSufficient_ = want.GetIntParam(COMMON_EVENT_KEY_BATTERY_CAPACITY,
                COMMON_EVENT_KEY_GET_DEFAULT_PARAM) >= PROPER_DEVICE_BATTERY_CAPACITY;
            ThumbnailGenerateWorkerManager::GetInstance().TryCloseThumbnailWorkerTimer();
            break;
        case StatusEventType::THERMAL_LEVEL_CHANGED:
            isDeviceTemperatureProper_ = want.GetIntParam(COMMON_EVENT_KEY_DEVICE_TEMPERATURE,
                COMMON_EVENT_KEY_GET_DEFAULT_PARAM) <= PROPER_DEVICE_TEMPERATURE_LEVEL;
            break;
        default:
            MEDIA_WARN_LOG("StatusEventType:%{public}d is not invalid", statusEventType);
            return;
    }

    UpdateCurrentStatus();
    UpdateBackgroundTimer();
}

void MedialibrarySubscriber::OnReceiveEvent(const EventFwk::CommonEventData &eventData)
{
    const AAFwk::Want &want = eventData.GetWant();
    std::string action = want.GetAction();
    MEDIA_DEBUG_LOG("OnReceiveEvent action:%{public}s.", action.c_str());
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_WIFI_CONN_STATE) {
        isWifiConn_ = eventData.GetCode() == WIFI_STATE_CONNECTED;
        UpdateBackgroundTimer();
    } else if (BACKGROUND_OPERATION_STATUS_MAP.count(action) != 0) {
        UpdateBackgroundOperationStatus(want, BACKGROUND_OPERATION_STATUS_MAP.at(action));
    } else if (action.compare(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED) == 0) {
        string packageName = want.GetElement().GetBundleName();
        RevertPendingByPackage(packageName);
        MediaLibraryBundleManager::GetInstance()->Clear();
        PermissionUtils::ClearBundleInfoInCache();
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
    
    if (isWifiConn_ && dataManager->CheckCloudThumbnailDownloadFinish() != E_OK) {
        MEDIA_INFO_LOG("CheckCloudThumbnailDownloadFinish failed");
        return;
    }

    auto result = dataManager->GenerateThumbnailBackground();
    if (result != E_OK) {
        MEDIA_ERR_LOG("GenerateThumbnailBackground faild");
    }

    result = dataManager->UpgradeThumbnailBackground(isWifiConn_);
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

    auto watch = MediaLibraryInotify::GetInstance();
    if (watch != nullptr) {
        watch->DoAging();
    }
}

void MedialibrarySubscriber::StopBackgroundOperation()
{
    MediaLibraryDataManager::GetInstance()->InterruptBgworker();
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
    std::lock_guard<std::mutex> lock(mutex_);
    bool newStatus = isScreenOff_ && isCharging_ && isPowerSufficient_ && isDeviceTemperatureProper_ && isWifiConn_;
    if (timerStatus_ == newStatus) {
        return;
    }

    MEDIA_INFO_LOG("update timer status current:%{public}d, new:%{public}d, %{public}d, %{public}d, %{public}d, "
        "%{public}d, %{public}d",
        timerStatus_, newStatus, isScreenOff_, isCharging_, isPowerSufficient_, isDeviceTemperatureProper_,
        isWifiConn_);

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
    isTaskWaiting_ = false;
    delayTaskCv_.notify_all();
    if (!backgroundOperationThread_.joinable()) {
        return;
    }
    backgroundOperationThread_.join();
}
}  // namespace Media
}  // namespace OHOS
