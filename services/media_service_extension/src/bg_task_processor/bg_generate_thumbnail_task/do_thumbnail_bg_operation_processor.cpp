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

#define MLOG_TAG "MediaBgTask_DoThumbnailBgOperationProcessor"

#include "do_thumbnail_bg_operation_processor.h"

#include "ffrt.h"
#include "ffrt_inner.h"
#include "media_log.h"
#include "medialibrary_astc_stat.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_errno.h"
#include "medialibrary_subscriber.h"
#include "medialibrary_unistore_manager.h"
#include "result_set.h"
#include "result_set_utils.h"
#include "rdb_predicates.h"
#include "rdb_utils.h"
#include "thumbnail_service.h"

#include <mutex>

namespace OHOS {
namespace Media {
static const int32_t QUERY_THUMB_TOTAL_EVERY_SIX_TIMES = 6;

constexpr int32_t POLLING_INTERVAL = 5 * 1000;  // 5 seconds
int32_t DoThumbnailBgOperationProcessor::pollingInterval_ = POLLING_INTERVAL;
const int32_t THUMB_ASTC_ENOUGH = 20000;

const int32_t PROPER_DEVICE_BATTERY_CAPACITY_THUMBNAIL = 20;
const int32_t PROPER_DEVICE_BATTERY_CAPACITY = 50;
const int32_t PROPER_DEVICE_TEMPERATURE_LEVEL_40 = 2;

std::recursive_mutex DoThumbnailBgOperationProcessor::mutex_;
Utils::Timer DoThumbnailBgOperationProcessor::timer_("do_thumbnail_bg_operation_processor");
int32_t DoThumbnailBgOperationProcessor::countTimer_ = 0;
uint32_t DoThumbnailBgOperationProcessor::startTimerId_ = -1;
bool DoThumbnailBgOperationProcessor::thumbnailBgGenerationStatus_ = false;
const std::string DoThumbnailBgOperationProcessor::taskName_ = DO_THUMBNAIL_BG_OPERATION;

int32_t DoThumbnailBgOperationProcessor::Start(const std::string &taskExtra)
{
    MEDIA_INFO_LOG("Start begin");
    ffrt::submit([this]() {
        thumbnailBgGenerationStatus_ = true;
        DoThumbnailBgOperation();
        StartTimer();
    });
    return E_OK;
}

int32_t DoThumbnailBgOperationProcessor::Stop(const std::string &taskExtra)
{
    ffrt::submit([this]() {
        bool isCharging = MedialibrarySubscriber::IsCharging();
        bool isScreenOff = MedialibrarySubscriber::IsScreenOff();
        int32_t newTemperatureLevel = MedialibrarySubscriber::GetNewTemperatureLevel();
        int32_t batteryCapacity = MedialibrarySubscriber::GetBatteryCapacity();
        bool isPowerSufficientForThumbnail = batteryCapacity >= PROPER_DEVICE_BATTERY_CAPACITY_THUMBNAIL;

        MediaLibraryAstcStat::GetInstance().GetInterruptInfo(isScreenOff, isCharging,
            isPowerSufficientForThumbnail, newTemperatureLevel <= PROPER_DEVICE_TEMPERATURE_LEVEL_40);
        StopThumbnailBgOperation();
        StopTimer(false);
    });
    return E_OK;
}

void DoThumbnailBgOperationProcessor::DoThumbnailBgOperation()
{
    auto dataManager = MediaLibraryDataManager::GetInstance();
    CHECK_AND_RETURN_LOG(dataManager != nullptr, "dataManager is nullptr");

    auto result = dataManager->GenerateThumbnailBackground();
    CHECK_AND_PRINT_LOG(result == E_OK, "GenerateThumbnailBackground faild");

    result = dataManager->RepairExifRotateBackground();
    CHECK_AND_PRINT_LOG(result == E_OK, "RepairExifRotateBackground faild");

    bool isWifiConnected = MedialibrarySubscriber::IsWifiConnected();
    result = dataManager->UpgradeThumbnailBackground(isWifiConnected);
    CHECK_AND_PRINT_LOG(result == E_OK, "UpgradeThumbnailBackground faild");

    result = dataManager->GenerateHighlightThumbnailBackground();
    CHECK_AND_PRINT_LOG(result == E_OK, "GenerateHighlightThumbnailBackground failed %{public}d", result);

    UpdateCurrentStatusForTask();
}

void DoThumbnailBgOperationProcessor::StopThumbnailBgOperation()
{
    auto dataManager = MediaLibraryDataManager::GetInstance();
    CHECK_AND_RETURN_LOG(dataManager != nullptr, "dataManager is nullptr");

    dataManager->InterruptThumbnailBgWorker();
}

void DoThumbnailBgOperationProcessor::UpdateCurrentStatusForTask()
{
    auto thumbnailService = ThumbnailService::GetInstance();
    CHECK_AND_RETURN_LOG(thumbnailService != nullptr, "dataManager is nullptr");

    thumbnailService->UpdateCurrentStatusForTask(thumbnailBgGenerationStatus_);
}

void DoThumbnailBgOperationProcessor::StartTimer()
{
    std::lock_guard<recursive_mutex> lock(mutex_);
    MEDIA_INFO_LOG("Turn on the thumbnail background operation timer");
    CHECK_AND_EXECUTE(startTimerId_ <= 0, timer_.Unregister(startTimerId_));
    uint32_t ret = timer_.Setup();
    CHECK_AND_PRINT_LOG(ret == E_OK, "Failed to start background download cloud files timer, err: %{public}d", ret);
    
    startTimerId_ = timer_.Register(TryStopThumbnailBgOperation, pollingInterval_);
}

void DoThumbnailBgOperationProcessor::StopTimer(bool needReport)
{
    std::lock_guard<recursive_mutex> lock(mutex_);
    if (needReport) {
        RemoveTaskName(taskName_);
        ReportTaskComplete(taskName_);
    }

    timer_.Unregister(startTimerId_);
    timer_.Shutdown();

    startTimerId_ = -1;
    countTimer_ = 0;

    thumbnailBgGenerationStatus_ = false;
    UpdateCurrentStatusForTask();
}

void DoThumbnailBgOperationProcessor::TryStopThumbnailBgOperation()
{
    countTimer_++;
    if (MediaLibraryAstcStat::GetInstance().IsBackupGroundTaskEmpty()) {
        std::thread([]() {
            StopTimer(true);
            MEDIA_INFO_LOG("success StopThumbnailBgOperation.");
        }).detach();
        return;
    }

    if (countTimer_ != QUERY_THUMB_TOTAL_EVERY_SIX_TIMES) {
        MEDIA_INFO_LOG("No need to query thumb total, countTimer_: %{public}d.", countTimer_);
        return;
    }
    countTimer_ = 0;
    bool isCharging = MedialibrarySubscriber::IsCharging();
    if (isCharging) {
        MEDIA_INFO_LOG("No need to query thumb total, isCharging: %{public}d.", isCharging);
        return;
    }
    UpdateThumbnailBgGenerationStatus(isCharging);
    UpdateCurrentStatusForTask();
}

void DoThumbnailBgOperationProcessor::UpdateThumbnailBgGenerationStatus(bool isCharging)
{
    bool isScreenOff = MedialibrarySubscriber::IsScreenOff();
    int32_t newTemperatureLevel = MedialibrarySubscriber::GetNewTemperatureLevel();
    int32_t batteryCapacity = MedialibrarySubscriber::GetBatteryCapacity();
    if (isScreenOff && newTemperatureLevel <= PROPER_DEVICE_TEMPERATURE_LEVEL_40 &&
        batteryCapacity >= PROPER_DEVICE_BATTERY_CAPACITY) {
        int32_t thumbAstcCount = 0;
        int32_t thumbTotalCount = 0;
        int32_t ret = QueryThumbAstc(thumbAstcCount);
        CHECK_AND_PRINT_LOG(ret == E_OK, "Query thumbAstcCount fail: %{public}d", ret);
    
        ret = QueryThumbTotal(thumbTotalCount);
        CHECK_AND_PRINT_LOG(ret == E_OK, "Query thumbTotalCount fail: %{public}d", ret);

        bool isThumbAstcEnough = thumbAstcCount > THUMB_ASTC_ENOUGH || thumbAstcCount == thumbTotalCount;
        thumbnailBgGenerationStatus_ = !isThumbAstcEnough;
        CHECK_AND_PRINT_LOG(isThumbAstcEnough,
            "ThumbnailBg status: isThumbAstcEnough:%{public}d, thumbAstcCount:%{public}d, thumbTotalCount:%{public}d",
            isThumbAstcEnough, thumbAstcCount, thumbTotalCount);
        
        if (isThumbAstcEnough) {
            bool isPowerSufficientForThumbnail = batteryCapacity >= PROPER_DEVICE_BATTERY_CAPACITY_THUMBNAIL;

            MediaLibraryAstcStat::GetInstance().GetInterruptInfo(isScreenOff, isCharging,
                isPowerSufficientForThumbnail, newTemperatureLevel <= PROPER_DEVICE_TEMPERATURE_LEVEL_40);
            StopThumbnailBgOperation();
            std::thread([]() {
                StopTimer(true);
            }).detach();
        }
    }
}

int32_t DoThumbnailBgOperationProcessor::QueryThumbAstc(int32_t &thumbAstcCount)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_ERR, "rdbStore is nullptr!");

    NativeRdb::AbsRdbPredicates queryPredicates(PhotoColumn::PHOTOS_TABLE);
    queryPredicates.GreaterThanOrEqualTo(PhotoColumn::PHOTO_THUMBNAIL_READY,
        static_cast<int32_t>(ThumbnailReady::GENERATE_THUMB_RETRY));
    const std::vector<std::string> columns = { "count(1) AS count" };
    const std::string queryColumn = "count";

    auto resultSet = rdbStore->Query(queryPredicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr && resultSet->GoToFirstRow() == NativeRdb::E_OK,
        E_DB_FAIL, "resultSet is null");

    thumbAstcCount = GetInt32Val(queryColumn, resultSet);
    return E_OK;
}

int32_t DoThumbnailBgOperationProcessor::QueryThumbTotal(int32_t &thumbTotalCount)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_ERR, "rdbStore is nullptr!");

    NativeRdb::RdbPredicates queryPredicates(PhotoColumn::PHOTOS_TABLE);
    const std::vector<std::string> columns = { "count(1) AS count" };
    const std::string queryColumn = "count";

    auto resultSet = rdbStore->Query(queryPredicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr && resultSet->GoToFirstRow() == NativeRdb::E_OK,
        E_DB_FAIL, "resultSet is null");

    thumbTotalCount = GetInt32Val(queryColumn, resultSet);
    return E_OK;
}

} // namespace Media
} // namespace OHOS
