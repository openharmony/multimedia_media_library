/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#define MLOG_TAG "Lcd_Aging"

#include "lcd_aging_manager.h"

#include <sys/stat.h>

#include "cloud_sync_manager.h"
#include "lcd_aging_task_priority_manager.h"
#include "lcd_aging_utils.h"
#include "lcd_aging_worker.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_astc_stat.h"
#include "medialibrary_errno.h"
#include "medialibrary_photo_operations.h"
#include "medialibrary_subscriber.h"
#include "medialibrary_tracer.h"
#include "photo_file_utils.h"
#include "preferences.h"
#include "preferences_helper.h"
#include "thumbnail_service.h"
#include "medialibrary_unistore_manager.h"

namespace OHOS::Media {
const std::string LCD_AGING_XML = "/data/storage/el2/base/preferences/lcd_aging.xml";
const std::string LAST_LCD_AGING_END_TIME = "last_lcd_aging_end_time";
constexpr int64_t BATCH_TASK_SIZE = 5000;
constexpr int32_t BATCH_AGING_SIZE = 200;
constexpr int32_t CYCLE_NUMBER = 50;
constexpr int32_t E_FINISH = 1;
constexpr int32_t E_PAUSE = 2;
constexpr int64_t ONE_DAY = 24 * 60 * 60;

LcdAgingManager& LcdAgingManager::GetInstance()
{
    static LcdAgingManager instance;
    return instance;
}

int32_t LcdAgingManager::ReadyAgingLcd()
{
    if (this->isInAgingPeriod_.load()) {
        MEDIA_INFO_LOG("continue to aging lcd");
        LcdAgingWorker::GetInstance().StartLcdAgingWorker();
        return E_OK;
    }

    CHECK_AND_RETURN_RET_LOG(this->IsAgingPeriodSatisfied(), E_ERR, "failed to check lcd aging period");
    CHECK_AND_RETURN_RET_LOG(this->IsAgingThresholdSatisfied(), E_ERR, "failed to check lcd aging threshold");
    this->hasAgingLcdNumber_ = 0;
    this->isInAgingPeriod_.store(true);
    LcdAgingWorker::GetInstance().StartLcdAgingWorker();
    return E_OK;
}

int32_t LcdAgingManager::BatchAgingLcdFileTask()
{
    std::lock_guard<std::mutex> lock(lcdOperationMutex_);
    CHECK_AND_RETURN_RET_LOG(this->IsLcdAgingStatusOn(), E_PAUSE, "current status is invalid");

    int64_t taskSize = -1;
    int32_t ret = this->GetNeedAgingLcdSize(taskSize);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, E_ERR, "Failed to GetNeedAgingLcdSize, ret: %{public}d", ret);
    CHECK_AND_RETURN_RET(taskSize > 0, FinishAgingTask());
    CHECK_AND_EXECUTE(taskSize <= BATCH_TASK_SIZE, taskSize = BATCH_TASK_SIZE);

    ret = E_ERR;
    int32_t cycleNumber = 0;
    const std::vector<BatchAgingLcdFileFunc> batchAgingFuncs = {
        &LcdAgingManager::BatchAgingLcdFileTrashed,
        &LcdAgingManager::BatchAgingLcdFileNotTrashed
    };

    bool hasTrashedData = true;
    while (taskSize > 0 && cycleNumber++ <= CYCLE_NUMBER) {
        CHECK_AND_RETURN_RET_LOG(this->IsLcdAgingStatusOn(), E_PAUSE, "current status is invalid");

        int32_t currentBatchSize = static_cast<int32_t>(taskSize > BATCH_AGING_SIZE ? BATCH_AGING_SIZE : taskSize);
        int64_t agingSuccessSize = 0;
        ret = E_NO_QUERY_DATA;

        for (size_t i = 0; i < batchAgingFuncs.size(); ++i) {
            bool isContinue = (i == 0 && !hasTrashedData);
            CHECK_AND_CONTINUE(!isContinue);

            ret = (this->*batchAgingFuncs[i])(currentBatchSize, agingSuccessSize);
            CHECK_AND_BREAK(ret == E_NO_QUERY_DATA);
            // when query no data with trashed, hasTrashedData = false
            if (i == 0) {
                hasTrashedData = false;
                MEDIA_INFO_LOG("No more trashed data to age, will try not trashed data next");
            }
        }
        CHECK_AND_PRINT_LOG(ret == E_OK, "failed to BatchAgingLcdFile, ret: %{public}d", ret);
        CHECK_AND_BREAK_INFO_LOG(ret != E_NO_QUERY_DATA, "break task cause of no query aging lcd data");

        taskSize -= agingSuccessSize;
        this->hasAgingLcdNumber_ += agingSuccessSize;
        MEDIA_INFO_LOG("batch aging lcdFile, currentBatchSize: %{public}d, agingSuccessSize: %{public}" PRId64
            ", hasAgingLcdNumber: %{public}" PRId64 ", taskSize: %{public}" PRId64 ", cycleNumber: %{public}d",
            currentBatchSize, agingSuccessSize, this->hasAgingLcdNumber_, taskSize, cycleNumber);
    }
    CHECK_AND_RETURN_RET(ret != E_NO_QUERY_DATA, FinishAgingTask());
    return E_OK;
}

int32_t LcdAgingManager::BatchAgingLcdFileTrashed(const int32_t size, int64_t &agingSuccessSize)
{
    MediaLibraryTracer tracer;
    tracer.Start("BatchAgingLcdFileTrashed");
    std::vector<PhotosPo> lcdAgingPoList;
    int32_t ret = this->lcdAgingDao_.QueryAgingLcdDataTrashed(size, this->notAgingFileIds_, lcdAgingPoList);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, E_NO_QUERY_DATA, "Failed to QueryAgingLcdDataTrashed, ret: %{public}d", ret);
    CHECK_AND_RETURN_RET_LOG(!lcdAgingPoList.empty(), E_NO_QUERY_DATA, "no aging lcd data (trashed)");
    ret = this->DoBatchAgingLcdFile(lcdAgingPoList, agingSuccessSize);
    CHECK_AND_PRINT_LOG(ret == E_OK, "Failed to DoBatchAgingLcdFile, ret: %{public}d", ret);
    return ret;
}

int32_t LcdAgingManager::BatchAgingLcdFileNotTrashed(const int32_t size, int64_t &agingSuccessSize)
{
    MediaLibraryTracer tracer;
    tracer.Start("BatchAgingLcdFileNotTrashed");
    std::vector<PhotosPo> lcdAgingPoList;
    int32_t ret = this->lcdAgingDao_.QueryAgingLcdDataNotTrashed(size, this->notAgingFileIds_, lcdAgingPoList);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, E_NO_QUERY_DATA,
        "Failed to QueryAgingLcdDataNotTrashed, ret: %{public}d", ret);
    CHECK_AND_RETURN_RET_LOG(!lcdAgingPoList.empty(), E_NO_QUERY_DATA, "no aging lcd data (not trashed)");
    ret = this->DoBatchAgingLcdFile(lcdAgingPoList, agingSuccessSize);
    CHECK_AND_PRINT_LOG(ret == E_OK, "Failed to DoBatchAgingLcdFile, ret: %{public}d", ret);
    return ret;
}

int32_t LcdAgingManager::DoBatchAgingLcdFile(const std::vector<PhotosPo> &lcdAgingPoList, int64_t &agingSuccessSize)
{
    MediaLibraryTracer tracer;
    tracer.Start("DoBatchAgingLcdFile");
    agingSuccessSize = 0;
    std::vector<LcdAgingFileInfo> agingFileInfos = this->GetLcdAgingFileInfo(lcdAgingPoList);
    CHECK_AND_RETURN_RET_LOG(!agingFileInfos.empty(), E_ERR, "agingFileInfos is empty");

    std::vector<std::string> fileIds = this->GetFileIdFromAgingFiles(agingFileInfos);
    int32_t ret = this->lcdAgingDao_.SetLcdNotDownloadStatus(fileIds);
    CHECK_AND_PRINT_LOG(ret == E_OK, "Failed to SetLcdNotDownloadStatus, ret: %{public}d", ret);
    ret = this->lcdAgingDao_.UpdateLcdFileSize(agingFileInfos);
    CHECK_AND_PRINT_LOG(ret == E_OK, "Failed to UpdateLcdFileSize, ret: %{public}d", ret);

    std::vector<DentryFileInfo> dentryFileInfos = LcdAgingUtils().ConvertAgingFileToDentryFile(agingFileInfos);
    std::vector<std::string> failCloudIds;
    MEDIA_INFO_LOG("Begin to BatchDentryFileInsert");
    ret = CloudSyncManager::GetInstance().BatchDentryFileInsert(dentryFileInfos, failCloudIds);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("Failed to insert dentry file, ret: %{public}d", ret);
        ret = this->lcdAgingDao_.RevertToLcdDownloadStatus(fileIds);
        CHECK_AND_PRINT_LOG(ret == E_OK, "Failed to RevertToLcdDownloadStatus, ret: %{public}d", ret);
        return E_ERR;
    }
    MEDIA_INFO_LOG("End to BatchDentryFileInsert");

    std::vector<std::string> failFileIds;
    this->DeleteLocalLcdFiles(agingFileInfos, failCloudIds, failFileIds);
    if (!failFileIds.empty()) {
        this->lcdAgingDao_.RevertToLcdDownloadStatus(failFileIds);
        this->notAgingFileIds_.insert(this->notAgingFileIds_.end(), failFileIds.begin(), failFileIds.end());
    }
    agingSuccessSize = static_cast<int64_t>(dentryFileInfos.size()) - static_cast<int64_t>(failCloudIds.size());
    return E_OK;
}

std::vector<std::string> LcdAgingManager::GetFileIdFromAgingFiles(const std::vector<LcdAgingFileInfo> &agingFileInfos)
{
    std::vector<std::string> fileIds;
    for (auto &agingFileInfo : agingFileInfos) {
        fileIds.emplace_back(std::to_string(agingFileInfo.fileId));
    }
    return fileIds;
}

void LcdAgingManager::DeleteLocalLcdFiles(const std::vector<LcdAgingFileInfo> &agingFileInfos,
    const std::vector<std::string> &failCloudIds, std::vector<std::string> &failFileIds)
{
    MediaLibraryTracer tracer;
    tracer.Start("DeleteLocalLcdFiles");
    for (auto &agingFileInfo : agingFileInfos) {
        if (std::find(failCloudIds.begin(), failCloudIds.end(), agingFileInfo.cloudId) != failCloudIds.end()) {
            failFileIds.emplace_back(std::to_string(agingFileInfo.fileId));
            MEDIA_ERR_LOG("Failed to insert dentry, cloudId: %{public}s, fileId: %{public}d",
                agingFileInfo.cloudId.c_str(), agingFileInfo.fileId);
            continue;
        }
        CHECK_AND_EXECUTE(!agingFileInfo.hasExThumbnail, this->DeleteLocalFile(agingFileInfo.localLcdExPath));
        this->DeleteLocalFile(agingFileInfo.localLcdPath);
        MediaLibraryPhotoOperations::StoreThumbnailSize(std::to_string(agingFileInfo.fileId), agingFileInfo.path);
    }
}

int32_t LcdAgingManager::DeleteLocalFile(const std::string &localPath)
{
    CHECK_AND_RETURN_RET_LOG(!localPath.empty(), E_ERR, "path is empty");
    if (!MediaFileUtils::IsFileExists(localPath)) {
        MEDIA_WARN_LOG("localPath not exist, path: %{public}s", localPath.c_str());
        return E_ERR;
    }
    if (!MediaFileUtils::DeleteFile(localPath)) {
        // 删除文件失败，兜底重试一次
        CHECK_AND_PRINT_LOG(MediaFileUtils::DeleteFile(localPath),
            "Failed to delete localPath, path: %{public}s", localPath.c_str());
        return E_ERR;
    }
    return E_OK;
}

int64_t LcdAgingManager::GetLastLcdAgingEndTime()
{
    int64_t lastLcdAgingEndTime = 0;
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(LCD_AGING_XML, errCode);
    CHECK_AND_RETURN_RET_LOG(prefs, lastLcdAgingEndTime, "Get preferences error: %{public}d", errCode);
    lastLcdAgingEndTime = prefs->GetLong(LAST_LCD_AGING_END_TIME, 0);
    return lastLcdAgingEndTime;
}

void LcdAgingManager::UpdateLastLcdAgingEndTime(const int64_t lastLcdAgingEndTime)
{
    int32_t errCode;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(LCD_AGING_XML, errCode);
    CHECK_AND_RETURN_LOG(prefs, "Get preferences error: %{public}d", errCode);
    prefs->PutLong(LAST_LCD_AGING_END_TIME, lastLcdAgingEndTime);
    prefs->FlushSync();
}

std::vector<LcdAgingFileInfo> LcdAgingManager::GetLcdAgingFileInfo(const std::vector<PhotosPo> &photos)
{
    MediaLibraryTracer tracer;
    tracer.Start("GetLcdAgingFileInfo");
    std::vector<LcdAgingFileInfo> agingFileList;
    for (const auto &photo : photos) {
        LcdAgingFileInfo agingFileInfo;
        CHECK_AND_CONTINUE_ERR_LOG(photo.data.has_value(),
            "photo.data is invalid, fileId: %{public}d", photo.fileId.value_or(0));
        agingFileInfo.fileId = photo.fileId.value_or(0);
        agingFileInfo.cloudId = photo.cloudId.value_or("");
        agingFileInfo.path = photo.data.value_or("");
        agingFileInfo.mediaType = photo.mediaType.value_or(0);
        agingFileInfo.orientation = photo.orientation.value_or(0);
        agingFileInfo.exifRotate = photo.exifRotate.value_or(0);
        agingFileInfo.thumbnailReady = photo.thumbnailReady.value_or(0);
        agingFileInfo.dateModified = photo.dateModified.value_or(0);
        agingFileInfo.hasExThumbnail = LcdAgingUtils().HasExThumbnail(agingFileInfo);
        agingFileInfo.localLcdPath = PhotoFileUtils::GetLocalLcdPath(agingFileInfo.path);
        agingFileInfo.localLcdExPath = agingFileInfo.hasExThumbnail ?
            PhotoFileUtils::GetLocalLcdExPath(agingFileInfo.path) : "";
        if (!this->CheckLocalLcd(agingFileInfo)) {
            this->notAgingFileIds_.emplace_back(std::to_string(photo.fileId.value_or(0)));
            continue;
        }
        CHECK_AND_EXECUTE(photo.lcdFileSize.value_or(0) > 0, agingFileInfo.needFixLcdFileSize = true);
        agingFileList.push_back(agingFileInfo);
    }
    return agingFileList;
}

bool LcdAgingManager::CheckLocalLcd(LcdAgingFileInfo &agingFileInfo)
{
    std::string localLcdPath = agingFileInfo.hasExThumbnail ? agingFileInfo.localLcdExPath : agingFileInfo.localLcdPath;
    MEDIA_DEBUG_LOG("CheckLocalLcd, path: %{public}s", localLcdPath.c_str());
    struct stat statInfo = { 0 };
    bool isValid = !localLcdPath.empty();
    isValid = isValid && (stat(localLcdPath.c_str(), &statInfo) == E_SUCCESS);
    CHECK_AND_RETURN_RET_LOG(isValid, false,
        "local lcd not exist, path: %{public}s", localLcdPath.c_str());
    agingFileInfo.lcdFileSize = statInfo.st_size;
    RegenerateAstcWithLocal(agingFileInfo);
    return true;
}

int32_t LcdAgingManager::RegenerateAstcWithLocal(const LcdAgingFileInfo &agingFileInfo)
{
    bool isValid = agingFileInfo.thumbnailReady == static_cast<int64_t>(ThumbnailReady::THUMB_NEED_REGENERATE_ASTC);
    CHECK_AND_RETURN_RET(isValid, E_ERR);
    std::string astcPath = GetThumbnailPath(agingFileInfo.path, THUMBNAIL_THUMB_ASTC_SUFFIX);
    CHECK_AND_RETURN_RET_LOG(!astcPath.empty(), E_ERR, "astcPath is empty, fileId: %{public}d", agingFileInfo.fileId);
    isValid = !MediaFileUtils::IsFileExists(astcPath);
    CHECK_AND_RETURN_RET(isValid, E_ERR);
    auto thumbnailService = ThumbnailService::GetInstance();
    CHECK_AND_RETURN_RET_LOG(thumbnailService != nullptr, E_ERR, "thumbnailService is null");
    MEDIA_INFO_LOG("begin to sync regenerate astc with local, fileId: %{public}d", agingFileInfo.fileId);
    return thumbnailService->SyncRegenerateAstcWithLocal(std::to_string(agingFileInfo.fileId));
}

int32_t LcdAgingManager::GetNeedAgingLcdSize(int64_t &taskSize)
{
    int64_t lcdThresholdNumber = -1;
    int32_t ret = LcdAgingUtils().GetScaleThresholdOfLcd(lcdThresholdNumber);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, E_ERR, "Failed to GetScaleThresholdOfLcd, ret: %{public}d", ret);

    int64_t lcdCurrentNumber = -1;
    ret = lcdAgingDao_.GetCurrentNumberOfLcd(lcdCurrentNumber);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, E_ERR, "Failed to GetCurrentNumberOfLcd, ret: %{public}d", ret);

    taskSize = lcdCurrentNumber - lcdThresholdNumber;
    CHECK_AND_PRINT_LOG(taskSize > 0,
        "no need aging lcd, lcdThresholdNumber: %{public}" PRId64 ", lcdCurrentNumber: %{public}" PRId64,
        lcdThresholdNumber, lcdCurrentNumber);
    return E_OK;
}

int32_t LcdAgingManager::FinishAgingTask()
{
    MEDIA_INFO_LOG("start FinishAgingTask");
    this->isInAgingPeriod_.store(false);
    this->UpdateLastLcdAgingEndTime(MediaFileUtils::UTCTimeSeconds());
    // 打点上报

    // 清理缓存
    this->hasAgingLcdNumber_ = 0;
    this->notAgingFileIds_.clear();
    MEDIA_INFO_LOG("end FinishAgingTask");
    return E_FINISH;
}

void LcdAgingManager::DelayLcdAgingTime()
{
    int64_t currentTime = MediaFileUtils::UTCTimeSeconds();
    this->UpdateLastLcdAgingEndTime(currentTime);
}

bool LcdAgingManager::IsLcdAgingStatusOn()
{
    bool isStatusOn = MedialibrarySubscriber::IsCurrentStatusOn() &&
        !LcdAgingTaskPriorityManager::GetInstance().HasHighPriorityTasks() &&
        MediaLibraryAstcStat::GetInstance().IsBackupGroundTaskEmpty();
    return isStatusOn;
}

void LcdAgingManager::ClearNotAgingFileIds()
{
    this->notAgingFileIds_.clear();
}

bool LcdAgingManager::IsAgingPeriodSatisfied()
{
    int64_t lastLcdAgingEndTime = this->GetLastLcdAgingEndTime();
    int64_t currentTime = MediaFileUtils::UTCTimeSeconds();
    if (lastLcdAgingEndTime < 0 || lastLcdAgingEndTime - currentTime > ONE_DAY) {
        MEDIA_ERR_LOG("invalid lastLcdAgingEndTime: %{public}" PRId64, lastLcdAgingEndTime);
        lastLcdAgingEndTime = lastLcdAgingEndTime < 0 ? 0 : currentTime;
        this->UpdateLastLcdAgingEndTime(lastLcdAgingEndTime);
    }
    bool isValid = (currentTime - lastLcdAgingEndTime) >= ONE_DAY;
    CHECK_AND_RETURN_RET_LOG(isValid, false,
        "lastLcdAgingEndTime: %{public}" PRId64 ", currentTime: %{public}" PRId64, lastLcdAgingEndTime, currentTime);
    MEDIA_INFO_LOG("aging period satisfied, lastLcdAgingEndTime: %{public}" PRId64, lastLcdAgingEndTime);
    return true;
}

bool LcdAgingManager::IsAgingThresholdSatisfied()
{
    int64_t maxLcdNumber = -1;
    int32_t ret = LcdAgingUtils().GetMaxThresholdOfLcd(maxLcdNumber);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, false, "Failed to GetMaxThresholdOfLcd, ret: %{public}d", ret);
    int64_t currentLcdNumber = -1;
    ret = this->lcdAgingDao_.GetCurrentNumberOfLcd(currentLcdNumber);
    CHECK_AND_RETURN_RET_LOG(ret == E_OK, false, "Failed to GetCurrentNumberOfLcd, ret: %{public}d", ret);
    bool isValid = currentLcdNumber > maxLcdNumber;
    CHECK_AND_RETURN_RET_LOG(isValid, false, "no need aging lcd, currentLcdNumber: %{public}" PRId64
        ", maxLcdNumber: %{public}" PRId64, currentLcdNumber, maxLcdNumber);
    MEDIA_INFO_LOG("aging threshold satisfied, currentLcdNumber: %{public}" PRId64 ", maxLcdNumber: %{public}" PRId64,
        currentLcdNumber, maxLcdNumber);
    return true;
}

int32_t LcdAgingManager::GenerateLcdWithLocal(const LcdAgingFileInfo &agingFileInfo)
{
    ThumbnailData thumbnailData = ConvertLcdAgingFileInfoToThumbnailData(agingFileInfo);
    auto createLcdBackgroundTask = [](std::shared_ptr<ThumbnailTaskData> &data) {
        CHECK_AND_RETURN_LOG(data != nullptr, "CreateLcd failed, data is null");
        auto &thumbnailData = data->thumbnailData_;
        thumbnailData.loaderOpts.loadingStates = SourceLoader::LOCAL_SOURCE_LOADING_STATES;
        IThumbnailHelper::CreateLcd(data);
    };
    thumbnailData.genThumbScene = GenThumbScene::NO_LCD_AND_GEN_IT_BACKGROUND;
    ThumbRdbOpt opts;
    opts.table = PhotoColumn::PHOTOS_TABLE;
    opts.store = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    opts.row = thumbnailData.id;
    IThumbnailHelper::AddThumbnailGenerateTask(createLcdBackgroundTask,
        opts, thumbnailData, ThumbnailTaskType::BACKGROUND, ThumbnailTaskPriority::LOW);
    return E_OK;
}

ThumbnailData LcdAgingManager::ConvertLcdAgingFileInfoToThumbnailData
    (const LcdAgingFileInfo &agingFileInfo)
{
    ThumbnailData thumbnailData;
    thumbnailData.id = std::to_string(agingFileInfo.fileId);
    thumbnailData.path = agingFileInfo.path;
    thumbnailData.mediaType = agingFileInfo.mediaType;
    thumbnailData.orientation = agingFileInfo.orientation;
    thumbnailData.exifRotate = agingFileInfo.exifRotate;
    thumbnailData.thumbnailReady = agingFileInfo.thumbnailReady;
    thumbnailData.dateModified = std::to_string(agingFileInfo.dateModified);
    thumbnailData.isLocalFile = true;
    return thumbnailData;
}

std::mutex& LcdAgingManager::GetLcdOperationMutex()
{
    return lcdOperationMutex_;
}
}  // namespace OHOS::Media