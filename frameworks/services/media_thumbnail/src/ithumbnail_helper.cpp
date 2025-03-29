/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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
#define MLOG_TAG "Thumbnail"

#include "ithumbnail_helper.h"

#include "ability_manager_client.h"
#include "background_task_mgr_helper.h"
#include "cloud_sync_helper.h"
#include "dfx_cloud_manager.h"
#include "dfx_utils.h"
#include "hitrace_meter.h"
#include "ipc_skeleton.h"
#include "media_column.h"
#include "medialibrary_errno.h"
#include "medialibrary_kvstore_manager.h"
#include "medialibrary_notify.h"
#include "medialibrary_photo_operations.h"
#include "medialibrary_type_const.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "post_event_utils.h"
#include "post_proc.h"
#include "result_set_utils.h"
#include "rdb_predicates.h"
#include "rdb_helper.h"
#include "single_kvstore.h"
#include "thumbnail_const.h"
#include "thumbnail_generate_worker_manager.h"
#include "thumbnail_image_framework_utils.h"
#include "thumbnail_source_loading.h"
#include "medialibrary_astc_stat.h"
using namespace std;
using namespace OHOS::DistributedKv;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {

void StoreThumbnailSize(const ThumbRdbOpt& opts, const ThumbnailData& data)
{
    std::string photoId = opts.row.empty() ? data.id : opts.row;
    std::string tmpPath = opts.path.empty() ? data.path : opts.path;
    if (tmpPath.find(ROOT_MEDIA_DIR + PHOTO_BUCKET) != string::npos) {
        MediaLibraryPhotoOperations::StoreThumbnailSize(photoId, tmpPath);
    }
}

void IThumbnailHelper::CloudSyncOnGenerationComplete(std::shared_ptr<ThumbnailTaskData> &data)
{
    CloudSyncHelper::GetInstance()->isThumbnailGenerationCompleted_ = true;
    CloudSyncHelper::GetInstance()->StartSync();
    MEDIA_INFO_LOG("CloudSyncOnGenerationComplete complete");
}

void IThumbnailHelper::CreateLcdAndThumbnail(std::shared_ptr<ThumbnailTaskData> &data)
{
    if (data == nullptr) {
        MEDIA_ERR_LOG("CreateLcdAndThumbnail failed, data is null");
        return;
    }
    WaitStatus status;
    bool isSuccess = DoCreateLcdAndThumbnail(data->opts_, data->thumbnailData_, status);
    if (status == WaitStatus::INSERT || status == WaitStatus::WAIT_CONTINUE) {
        if (isSuccess && !data->thumbnailData_.tracks.empty() && (data->thumbnailData_.trigger == "0")) {
            UpdateHighlightDbState(data->opts_, data->thumbnailData_);
        }
    }
    
    ThumbnailUtils::RecordCostTimeAndReport(data->thumbnailData_.stats);
}

void IThumbnailHelper::CreateLcd(std::shared_ptr<ThumbnailTaskData> &data)
{
    if (data == nullptr) {
        MEDIA_ERR_LOG("CreateLcd failed, data is null");
        return;
    }
    WaitStatus status;
    DoCreateLcd(data->opts_, data->thumbnailData_, status);
}

void IThumbnailHelper::CreateThumbnail(std::shared_ptr<ThumbnailTaskData> &data)
{
    if (data == nullptr) {
        MEDIA_ERR_LOG("CreateThumbnail failed, data is null");
        return;
    }
    WaitStatus status;
    bool isSuccess = DoCreateThumbnail(data->opts_, data->thumbnailData_, status);
    ThumbnailUtils::RecordCostTimeAndReport(data->thumbnailData_.stats);
}

void IThumbnailHelper::CreateAstc(std::shared_ptr<ThumbnailTaskData> &data)
{
    if (data == nullptr) {
        MEDIA_ERR_LOG("CreateAstc failed, data is null");
        return;
    }
    int64_t startTime = MediaFileUtils::UTCTimeMilliSeconds();
    bool isSuccess = DoCreateAstc(data->opts_, data->thumbnailData_);
    UpdateThumbnailState(data->opts_, data->thumbnailData_, isSuccess);
    MediaLibraryAstcStat::GetInstance().AddAstcInfo(startTime,
        data->thumbnailData_.stats.scene, AstcGenScene::NOCHARGING_SCREENOFF, data->thumbnailData_.id);
    ThumbnailUtils::RecordCostTimeAndReport(data->thumbnailData_.stats);
}

void IThumbnailHelper::CreateAstcEx(std::shared_ptr<ThumbnailTaskData> &data)
{
    if (data == nullptr) {
        MEDIA_ERR_LOG("CreateAstcEx failed, data is null");
        return;
    }
    WaitStatus status;
    bool isSuccess = DoCreateAstcEx(data->opts_, data->thumbnailData_, status);
    ThumbnailUtils::RecordCostTimeAndReport(data->thumbnailData_.stats);
}

void IThumbnailHelper::DeleteMonthAndYearAstc(std::shared_ptr<ThumbnailTaskData> &data)
{
    if (data == nullptr) {
        MEDIA_ERR_LOG("DeleteMonthAndYearAstc failed, data is null");
        return;
    }
    if (!ThumbnailUtils::DoDeleteMonthAndYearAstc(data->opts_)) {
        MEDIA_ERR_LOG("DeleteMonthAndYearAstc failed, key is %{public}s and %{public}s",
            data->opts_.row.c_str(), data->opts_.dateTaken.c_str());
    }
}

void IThumbnailHelper::UpdateAstcDateTaken(std::shared_ptr<ThumbnailTaskData> &data)
{
    if (data == nullptr) {
        MEDIA_ERR_LOG("UpdateAstcDateTaken failed, data is null");
        return;
    }
    if (!ThumbnailUtils::DoUpdateAstcDateTaken(data->opts_, data->thumbnailData_)) {
        MEDIA_ERR_LOG("UpdateAstcDateTaken failed, key is %{public}s and %{public}s",
            data->opts_.row.c_str(), data->thumbnailData_.dateTaken.c_str());
    }
}

void IThumbnailHelper::AddThumbnailGenerateTask(ThumbnailGenerateExecute executor, const ThumbnailTaskType &taskType,
    const ThumbnailTaskPriority &priority)
{
    std::shared_ptr<ThumbnailGenerateWorker> thumbnailWorker =
        ThumbnailGenerateWorkerManager::GetInstance().GetThumbnailWorker(taskType);
    if (thumbnailWorker == nullptr) {
        MEDIA_ERR_LOG("thumbnailWorker is null");
        return;
    }

    std::shared_ptr<ThumbnailTaskData> taskData = std::make_shared<ThumbnailTaskData>();
    std::shared_ptr<ThumbnailGenerateTask> task = std::make_shared<ThumbnailGenerateTask>(executor, taskData);
    thumbnailWorker->AddTask(task, priority);
}

void IThumbnailHelper::AddThumbnailGenerateTask(ThumbnailGenerateExecute executor, ThumbRdbOpt &opts,
    ThumbnailData &thumbData, const ThumbnailTaskType &taskType, const ThumbnailTaskPriority &priority,
    std::shared_ptr<ExecuteParamBuilder> param)
{
    std::shared_ptr<ThumbnailGenerateWorker> thumbnailWorker =
        ThumbnailGenerateWorkerManager::GetInstance().GetThumbnailWorker(taskType);
    if (thumbnailWorker == nullptr) {
        MEDIA_ERR_LOG("thumbnailWorker is null");
        return;
    }

    std::shared_ptr<ThumbnailTaskData> taskData = std::make_shared<ThumbnailTaskData>(opts, thumbData);
    std::shared_ptr<ThumbnailGenerateTask> task = std::make_shared<ThumbnailGenerateTask>(executor, taskData, param);
    thumbnailWorker->AddTask(task, priority);
}

void IThumbnailHelper::AddThumbnailGenBatchTask(ThumbnailGenerateExecute executor,
    ThumbRdbOpt &opts, ThumbnailData &thumbData, int32_t requestId)
{
    std::shared_ptr<ThumbnailGenerateWorker> thumbnailWorker =
        ThumbnailGenerateWorkerManager::GetInstance().GetThumbnailWorker(ThumbnailTaskType::FOREGROUND);
    if (thumbnailWorker == nullptr) {
        MEDIA_ERR_LOG("thumbnailWorker is null");
        return;
    }

    std::shared_ptr<ThumbnailTaskData> taskData = std::make_shared<ThumbnailTaskData>(opts, thumbData, requestId);
    std::shared_ptr<ThumbnailGenerateTask> task = std::make_shared<ThumbnailGenerateTask>(executor, taskData);
    thumbnailWorker->AddTask(task, ThumbnailTaskPriority::LOW);
}

ThumbnailWait::ThumbnailWait(bool release) : needRelease_(release)
{}

ThumbnailWait::~ThumbnailWait()
{
    if (needRelease_) {
        Notify();
    }
}

ThumbnailMap ThumbnailWait::thumbnailMap_;
std::shared_mutex ThumbnailWait::mutex_;

static bool WaitFor(const shared_ptr<ThumbnailSyncStatus> &thumbnailWait, int waitMs, unique_lock<mutex> &lck)
{
    bool ret = thumbnailWait->cond_.wait_for(lck, chrono::milliseconds(waitMs),
        [thumbnailWait]() { return thumbnailWait->isSyncComplete_; });
    if (!ret) {
        MEDIA_INFO_LOG("IThumbnailHelper::Wait wait for lock timeout");
    }
    return ret;
}

WaitStatus ThumbnailWait::InsertAndWait(const string &id, ThumbnailType type, const string &dateModified)
{
    id_ = id + ThumbnailUtils::GetThumbnailSuffix(type);
    dateModified_ = dateModified;
    unique_lock<shared_mutex> writeLck(mutex_);
    auto iter = thumbnailMap_.find(id_);
    if (iter != thumbnailMap_.end()) {
        auto thumbnailWait = iter->second;
        unique_lock<mutex> lck(thumbnailWait->mtx_);

        // As data Source has changed, allowing this insertion to proceed and update dateModified
        if (thumbnailWait->latestDateModified_ < dateModified) {
            MEDIA_INFO_LOG("DateModified changed, continue to generate thumbnail, id: %{public}s, last: %{public}s,"
                "new:  %{public}s", id_.c_str(), thumbnailWait->latestDateModified_.c_str(), dateModified.c_str());
            thumbnailWait->latestDateModified_ = dateModified;
            return WaitStatus::WAIT_CONTINUE;
        }

        writeLck.unlock();
        MEDIA_INFO_LOG("Waiting for thumbnail generation, id: %{public}s", id_.c_str());
        thumbnailWait->cond_.wait(lck, [weakPtr = weak_ptr(thumbnailWait)]() {
            if (auto sharedPtr = weakPtr.lock()) {
                return sharedPtr->isSyncComplete_;
            } else {
                return true;
            }
        });
        if (thumbnailWait->isCreateThumbnailSuccess_) {
            MEDIA_INFO_LOG("Thumbnail generated successfully");
            return WaitStatus::WAIT_SUCCESS;
        } else {
            MEDIA_ERR_LOG("Failed to generate thumbnail");
            return WaitStatus::WAIT_FAILED;
        }
    } else {
        shared_ptr<ThumbnailSyncStatus> thumbnailWait = make_shared<ThumbnailSyncStatus>();
        thumbnailWait->latestDateModified_ = dateModified;
        thumbnailMap_.insert(ThumbnailMap::value_type(id_, thumbnailWait));
        return WaitStatus::INSERT;
    }
}

WaitStatus CheckCloudReadResult(CloudLoadType cloudLoadType, CloudReadStatus status)
{
    switch (status) {
        case CloudReadStatus::FAIL:
            MEDIA_INFO_LOG("Fail to cloud read thumbnail, type: %{public}d", cloudLoadType);
            return WaitStatus::WAIT_FAILED;
            break;
        case CloudReadStatus::SUCCESS:
            MEDIA_INFO_LOG("Success to cloud read thumbnail, type: %{public}d", cloudLoadType);
            return WaitStatus::WAIT_SUCCESS;
            break;
        case CloudReadStatus::START:
            MEDIA_INFO_LOG("Continue to cloud read thumbnail, type: %{public}d", cloudLoadType);
            return WaitStatus::WAIT_CONTINUE;
            break;
        default:
            break;
    }
    return WaitStatus::WAIT_FAILED;
}

WaitStatus ThumbnailWait::CloudInsertAndWait(const string &id, CloudLoadType cloudLoadType)
{
    id_ = id + ".cloud";
    unique_lock<shared_mutex> writeLck(mutex_);
    auto iter = thumbnailMap_.find(id_);
    if (iter != thumbnailMap_.end()) {
        auto thumbnailWait = iter->second;
        unique_lock<mutex> lck(thumbnailWait->mtx_);
        writeLck.unlock();
        MEDIA_INFO_LOG("Waiting for thumbnail generation, id: %{public}s", id_.c_str());
        thumbnailWait->cond_.wait(lck, [weakPtr = weak_ptr(thumbnailWait)]() {
            if (auto sharedPtr = weakPtr.lock()) {
                return sharedPtr->isSyncComplete_;
            } else {
                return true;
            }
        });
        thumbnailWait->isSyncComplete_ = false;
        thumbnailWait->cloudLoadType_ = cloudLoadType;
        unique_lock<shared_mutex> evokeLck(mutex_);
        thumbnailMap_.emplace(ThumbnailMap::value_type(id_, thumbnailWait));
        evokeLck.unlock();

        if (cloudLoadType == CLOUD_DOWNLOAD) {
            MEDIA_INFO_LOG("Continue to generate thumbnail");
            return WaitStatus::WAIT_CONTINUE;
        }
        if (cloudLoadType == CLOUD_READ_THUMB) {
            return CheckCloudReadResult(cloudLoadType, thumbnailWait->CloudLoadThumbnailStatus_);
        }
        if (cloudLoadType == CLOUD_READ_LCD) {
            return CheckCloudReadResult(cloudLoadType, thumbnailWait->CloudLoadLcdStatus_);
        }
        MEDIA_INFO_LOG("Cloud generate thumbnail successfully");
        return WaitStatus::WAIT_SUCCESS;
    } else {
        shared_ptr<ThumbnailSyncStatus> thumbnailWait = make_shared<ThumbnailSyncStatus>();
        thumbnailWait->cloudLoadType_ = cloudLoadType;
        thumbnailMap_.insert(ThumbnailMap::value_type(id_, thumbnailWait));
        return WaitStatus::INSERT;
    }
}

bool ThumbnailWait::TrySaveCurrentPixelMap(ThumbnailData &data, ThumbnailType type)
{
    ThumbnailType idType = (type == ThumbnailType::LCD || type == ThumbnailType::LCD_EX) ?
        ThumbnailType::LCD : ThumbnailType::THUMB;
    id_ = data.id + ThumbnailUtils::GetThumbnailSuffix(idType);
    MEDIA_INFO_LOG("Save current pixelMap, path: %{public}s, type: %{public}d",
        DfxUtils::GetSafePath(data.path).c_str(), type);
    unique_lock<shared_mutex> writeLck(mutex_);
    auto iter = thumbnailMap_.find(id_);
    if (iter != thumbnailMap_.end()) {
        auto thumbnailWait = iter->second;
        unique_lock<mutex> lck(thumbnailWait->mtx_);
        writeLck.unlock();
        if (!thumbnailWait->CheckSavedFileMap(data.id, type, data.dateModified)) {
            MEDIA_ERR_LOG("TrySaveCurrentPixelMap cancelled, latest file exists, path: %{public}s",
                DfxUtils::GetSafePath(data.path).c_str());
            data.needUpdateDb = false;
            return false;
        }

        int err = ThumbnailUtils::TrySaveFile(data, type);
        if (err < 0) {
            MEDIA_ERR_LOG("TrySaveCurrentPixelMap failed: %{public}d, path: %{public}s", err,
                DfxUtils::GetSafePath(data.path).c_str());
            return false;
        }

        if (!thumbnailWait->UpdateSavedFileMap(data.id, type, data.dateModified)) {
            MEDIA_ERR_LOG("UpdateSavedFileMap failed while save pixelMap, path: %{public}s",
                DfxUtils::GetSafePath(data.path).c_str());
            return false;
        }
    } else {
        MEDIA_ERR_LOG("TrySaveCurrentPixelMap cancelled, corresponding task has finished, path: %{public}s",
            DfxUtils::GetSafePath(data.path).c_str());
        return false;
    }
    return true;
}

bool ThumbnailWait::TrySaveCurrentPicture(ThumbnailData &data, bool isSourceEx, const string &tempOutputPath)
{
    id_ = data.id + ThumbnailUtils::GetThumbnailSuffix(ThumbnailType::LCD);
    MEDIA_INFO_LOG("Save current picture, path: %{public}s", DfxUtils::GetSafePath(data.path).c_str());
    unique_lock<shared_mutex> writeLck(mutex_);
    auto iter = thumbnailMap_.find(id_);
    if (iter != thumbnailMap_.end()) {
        auto thumbnailWait = iter->second;
        unique_lock<mutex> lck(thumbnailWait->mtx_);
        writeLck.unlock();
        ThumbnailType lcdType = isSourceEx ? ThumbnailType::LCD_EX : ThumbnailType::LCD;
        if (!thumbnailWait->CheckSavedFileMap(data.id, lcdType, data.dateModified)) {
            MEDIA_ERR_LOG("TrySaveCurrentPicture cancelled, latest file exists, path: %{public}s",
                DfxUtils::GetSafePath(data.path).c_str());
            ThumbnailUtils::CancelAfterPacking(tempOutputPath);
            data.needUpdateDb = false;
            return false;
        }

        if (!ThumbnailUtils::SaveAfterPacking(data, isSourceEx, tempOutputPath)) {
            MEDIA_ERR_LOG("TrySaveCurrentPicture failed, path: %{public}s", DfxUtils::GetSafePath(data.path).c_str());
            return false;
        }

        if (!thumbnailWait->UpdateSavedFileMap(data.id, lcdType, data.dateModified)) {
            MEDIA_ERR_LOG("UpdateSavedFileMap failed while save picture, path: %{public}s",
                DfxUtils::GetSafePath(data.path).c_str());
            return false;
        }
    } else {
        MEDIA_ERR_LOG("TrySaveCurrentPicture cancelled, corresponding task has finished, path: %{public}s",
            DfxUtils::GetSafePath(data.path).c_str());
        ThumbnailUtils::CancelAfterPacking(tempOutputPath);
        return false;
    }
    return true;
}

void ThumbnailWait::CheckAndWait(const string &id, bool isLcd)
{
    id_ = id;

    if (isLcd) {
        id_ += THUMBNAIL_LCD_SUFFIX;
    } else {
        id_ += THUMBNAIL_THUMB_SUFFIX;
    }
    shared_lock<shared_mutex> readLck(mutex_);
    auto iter = thumbnailMap_.find(id_);
    if (iter != thumbnailMap_.end()) {
        auto thumbnailWait = iter->second;
        unique_lock<mutex> lck(thumbnailWait->mtx_);
        readLck.unlock();
        WaitFor(thumbnailWait, WAIT_FOR_MS, lck);
    }
}

void ThumbnailWait::UpdateThumbnailMap()
{
    unique_lock<shared_mutex> writeLck(mutex_);
    auto iter = thumbnailMap_.find(id_);
    if (iter != thumbnailMap_.end()) {
        auto thumbnailWait = iter->second;
        {
            unique_lock<mutex> lck(thumbnailWait->mtx_);
            writeLck.unlock();
            thumbnailWait->isCreateThumbnailSuccess_ = true;
            needRelease_ = thumbnailWait->latestDateModified_ == dateModified_;
        }
        if (!needRelease_) {
            MEDIA_INFO_LOG("Latest task has come, id: %{public}s", id_.c_str());
        }
    } else {
        MEDIA_ERR_LOG("Update ThumbnailMap failed, id: %{public}s", id_.c_str());
    }
}

void ThumbnailWait::UpdateCloudLoadThumbnailMap(CloudLoadType cloudLoadType, bool isLoadSuccess)
{
    unique_lock<shared_mutex> writeLck(mutex_);
    auto iter = thumbnailMap_.find(id_);
    if (iter != thumbnailMap_.end()) {
        auto thumbnailWait = iter->second;
        {
            unique_lock<mutex> lck(thumbnailWait->mtx_);
            writeLck.unlock();
            switch (cloudLoadType) {
                case CLOUD_READ_THUMB:
                    thumbnailWait->CloudLoadThumbnailStatus_ =
                        isLoadSuccess ? CloudReadStatus::SUCCESS : CloudReadStatus::FAIL;
                    break;
                case CLOUD_READ_LCD:
                    thumbnailWait->CloudLoadLcdStatus_ =
                        isLoadSuccess ? CloudReadStatus::SUCCESS : CloudReadStatus::FAIL;
                    break;
                case CLOUD_DOWNLOAD:
                    thumbnailWait->CloudLoadThumbnailStatus_ =
                        isLoadSuccess ? CloudReadStatus::SUCCESS : CloudReadStatus::FAIL;
                    thumbnailWait->CloudLoadLcdStatus_ =
                        isLoadSuccess ? CloudReadStatus::SUCCESS : CloudReadStatus::FAIL;
                    break;
                default:
                    break;
            }
        }
    } else {
        MEDIA_ERR_LOG("Update CloudLoadThumbnailMap failed, id: %{public}s", id_.c_str());
    }
}

void ThumbnailWait::Notify()
{
    unique_lock<shared_mutex> writeLck(mutex_);
    auto iter = thumbnailMap_.find(id_);
    if (iter != thumbnailMap_.end()) {
        auto thumbnailWait = iter->second;
        {
            unique_lock<mutex> lck(thumbnailWait->mtx_);
            if (!dateModified_.empty() && thumbnailWait->latestDateModified_ > dateModified_) {
                MEDIA_INFO_LOG("Latest task has come, no need to notify, id: %{public}s", id_.c_str());
                return;
            }
            thumbnailMap_.erase(iter);
            writeLck.unlock();
            thumbnailWait->isSyncComplete_ = true;
        }
        if (thumbnailWait->cloudLoadType_ == CloudLoadType::NONE) {
            thumbnailWait->cond_.notify_all();
        } else {
            thumbnailWait->cond_.notify_one();
        }
    }
}

bool ThumbnailSyncStatus::CheckSavedFileMap(const string &id, ThumbnailType type, const string &dateModified)
{
    std::string saveId = id + ThumbnailUtils::GetThumbnailSuffix(type);
    auto iter = latestSavedFileMap_.find(id);
    if (iter != latestSavedFileMap_.end() && (iter->second > dateModified)) {
        return false;
    }
    return true;
}

bool ThumbnailSyncStatus::UpdateSavedFileMap(const string &id, ThumbnailType type, const string &dateModified)
{
    std::string saveId = id + ThumbnailUtils::GetThumbnailSuffix(type);
    auto iter = latestSavedFileMap_.find(id);
    if (iter != latestSavedFileMap_.end()) {
        if (iter->second > dateModified) {
            return false;
        } else {
            iter->second = dateModified;
        }
    } else {
        latestSavedFileMap_.emplace(id, dateModified);
    }
    return true;
}

bool IThumbnailHelper::TryLoadSource(ThumbRdbOpt &opts, ThumbnailData &data)
{
    if (!data.source.IsEmptySource()) {
        return true;
    }

    if (data.loaderOpts.loadingStates.empty()) {
        MEDIA_ERR_LOG("try load source failed, the loading source states is empty.");
        return false;
    }

    if (!ThumbnailUtils::LoadSourceImage(data)) {
        if (opts.path.empty()) {
            MEDIA_ERR_LOG("LoadSourceImage faild, %{public}s", DfxUtils::GetSafePath(data.path).c_str());
            VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, E_THUMBNAIL_UNKNOWN},
                {KEY_OPT_FILE, data.path}, {KEY_OPT_TYPE, OptType::THUMB}};
            PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
            return false;
        } else {
            opts.path = "";
            ThumbnailUtils::GetThumbnailInfo(opts, data);
            if (access(data.path.c_str(), F_OK) == 0) {
                return true;
            }
            if (!ThumbnailUtils::LoadSourceImage(data)) {
                VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__},
                    {KEY_ERR_CODE, E_THUMBNAIL_UNKNOWN}, {KEY_OPT_FILE, data.path}, {KEY_OPT_TYPE, OptType::THUMB}};
                PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
                return false;
            }
        }
    }
    return true;
}

bool IThumbnailHelper::TrySavePixelMap(ThumbnailData &data, ThumbnailType type)
{
    if (!data.needCheckWaitStatus) {
        int err = ThumbnailUtils::TrySaveFile(data, type);
        if (err < 0) {
            MEDIA_ERR_LOG("No wait TrySavePixelMap failed: %{public}d, path: %{public}s", err,
                DfxUtils::GetSafePath(data.path).c_str());
            return false;
        }
        return true;
    }
    ThumbnailWait thumbnailWait(false);
    if (!thumbnailWait.TrySaveCurrentPixelMap(data, type)) {
        MEDIA_ERR_LOG("TrySavePixelMap failed, path: %{public}s", DfxUtils::GetSafePath(data.path).c_str());
        return false;
    }
    return true;
}

bool IThumbnailHelper::TrySavePicture(ThumbnailData &data, bool isSourceEx, const string &tempOutputPath)
{
    if (!data.needCheckWaitStatus) {
        if (!ThumbnailUtils::SaveAfterPacking(data, isSourceEx, tempOutputPath)) {
            MEDIA_ERR_LOG("No wait TrySavePicture failed, path: %{public}s", DfxUtils::GetSafePath(data.path).c_str());
            return false;
        }
        return true;
    }
    ThumbnailWait thumbnailWait(false);
    if (!thumbnailWait.TrySaveCurrentPicture(data, isSourceEx, tempOutputPath)) {
        MEDIA_ERR_LOG("TrySavePicture failed, path: %{public}s", DfxUtils::GetSafePath(data.path).c_str());
        return false;
    }
    return true;
}

bool IThumbnailHelper::DoCreateLcd(ThumbRdbOpt &opts, ThumbnailData &data, WaitStatus &ret)
{
    MEDIA_INFO_LOG("Start DoCreateLcd, id: %{public}s, path: %{public}s",
        data.id.c_str(), DfxUtils::GetSafePath(data.path).c_str());
    ThumbnailWait thumbnailWait(true);
    ret = thumbnailWait.InsertAndWait(data.id, ThumbnailType::LCD, data.dateModified);
    data.needCheckWaitStatus = true;
    if (ret != WaitStatus::INSERT && ret != WaitStatus::WAIT_CONTINUE) {
        return ret == WaitStatus::WAIT_SUCCESS;
    }

    if (!IsCreateLcdSuccess(opts, data)) {
        MEDIA_ERR_LOG("Fail to create lcd, path: %{public}s", DfxUtils::GetSafePath(opts.path).c_str());
        return false;
    }

    if (data.orientation != 0 && !IsCreateLcdExSuccess(opts, data)) {
        MEDIA_ERR_LOG("Fail to create lcdEx, path: %{public}s", DfxUtils::GetSafePath(opts.path).c_str());
    }
    thumbnailWait.UpdateThumbnailMap();
    data.needCheckWaitStatus = false;
    return true;
}

void UpdateLcdDbState(ThumbRdbOpt &opts, ThumbnailData &data)
{
    if (opts.table != PhotoColumn::PHOTOS_TABLE) {
        return;
    }
    if (data.isNeedStoreSize) {
        StoreThumbnailSize(opts, data);
    }
    data.isNeedStoreSize = true;
    int err = 0;
    if (!ThumbnailUtils::UpdateLcdInfo(opts, data, err)) {
        MEDIA_INFO_LOG("UpdateLcdInfo faild err : %{public}d", err);
    }
}

void IThumbnailHelper::UpdateHighlightDbState(ThumbRdbOpt &opts, ThumbnailData &data)
{
    if (opts.table != PhotoColumn::HIGHLIGHT_TABLE) {
        return;
    }
    int err = 0;
    if (!ThumbnailUtils::UpdateHighlightInfo(opts, data, err)) {
        MEDIA_ERR_LOG("UpdateHighlightInfo faild err : %{public}d", err);
    }
}

bool IThumbnailHelper::SaveLcdPictureSource(ThumbRdbOpt &opts, ThumbnailData &data, bool isSourceEx)
{
    shared_ptr<Picture> lcdSource = isSourceEx ? data.source.GetPictureEx() : data.source.GetPicture();
    if (lcdSource == nullptr) {
        MEDIA_ERR_LOG("SaveLcdPictureSource failed, lcdSource is null");
        return false;
    }
    if (lcdSource->GetMainPixel() == nullptr || lcdSource->GetGainmapPixelMap() == nullptr) {
        MEDIA_ERR_LOG("SaveLcdPictureSource failed, mainpixel exist: %{public}d, gainMap exist: %{public}d",
            lcdSource->GetMainPixel() == nullptr, lcdSource->GetGainmapPixelMap() == nullptr);
        return false;
    }
    bool shouldReverseSize = !isSourceEx && (data.orientation % FLAT_ANGLE != 0);
    int lcdDesiredWidth = shouldReverseSize ? data.lcdDesiredSize.height : data.lcdDesiredSize.width;
    int lcdDesiredHeight = shouldReverseSize ? data.lcdDesiredSize.width : data.lcdDesiredSize.height;
    std::shared_ptr<Picture> copySource;
    if (lcdDesiredWidth != lcdSource->GetMainPixel()->GetWidth()) {
        MEDIA_INFO_LOG("Copy and resize picture source for lcd desiredSize: %{public}s",
            DfxUtils::GetSafePath(data.path).c_str());
        copySource = ThumbnailImageFrameWorkUtils::CopyPictureSource(lcdSource);
        CHECK_AND_RETURN_RET_LOG(copySource != nullptr, false, "SaveLcdPictureSource failed, CopyPictureSource failed");
        if (lcdSource->GetMainPixel()->GetWidth() * lcdSource->GetMainPixel()->GetHeight() == 0) {
            MEDIA_ERR_LOG("SaveLcdPictureSource failed, invalid mainpixel size");
            return false;
        }
        float widthScale = (1.0f * lcdDesiredWidth) / lcdSource->GetMainPixel()->GetWidth();
        float heightScale = (1.0f * lcdDesiredHeight) / lcdSource->GetMainPixel()->GetHeight();
        lcdSource->GetMainPixel()->scale(widthScale, heightScale);
        lcdSource->GetGainmapPixelMap()->scale(widthScale, heightScale);
    }
    std::string tempOutputPath;
    if (!ThumbnailUtils::CompressPicture(data, isSourceEx, tempOutputPath)) {
        MEDIA_ERR_LOG("SaveLcdPictureSource failed, CompressPicture failed");
        return false;
    }
    if (!TrySavePicture(data, isSourceEx, tempOutputPath)) {
        MEDIA_ERR_LOG("SaveLcdPictureSource failed, save picture failed");
        return false;
    }
    if (copySource != nullptr) {
        lcdSource = copySource;
    }
    if (!isSourceEx) {
        UpdateLcdDbState(opts, data);
    }
    return true;
}

bool IThumbnailHelper::SaveLcdPixelMapSource(ThumbRdbOpt &opts, ThumbnailData &data, bool isSourceEx)
{
    shared_ptr<PixelMap> lcdSource = isSourceEx ? data.source.GetPixelMapEx() : data.source.GetPixelMap();
    if (lcdSource == nullptr) {
        MEDIA_ERR_LOG("SaveLcdPixelMapSource failed, lcdSource is null");
        return false;
    }
    int lcdDesiredWidth;
    int lcdDesiredHeight;
    if (isSourceEx) {
        lcdDesiredWidth = data.lcdDesiredSize.width;
        lcdDesiredHeight = data.lcdDesiredSize.height;
    } else {
        lcdDesiredWidth = data.orientation % FLAT_ANGLE == 0 ? data.lcdDesiredSize.width : data.lcdDesiredSize.height;
        lcdDesiredHeight = data.orientation % FLAT_ANGLE == 0 ? data.lcdDesiredSize.height : data.lcdDesiredSize.width;
    }
    if (lcdDesiredWidth != lcdSource->GetWidth()) {
        MEDIA_INFO_LOG("Copy and resize data source for lcd desiredSize: %{public}s",
            DfxUtils::GetSafePath(data.path).c_str());
        auto copySource = ThumbnailImageFrameWorkUtils::CopyPixelMapSource(lcdSource);
        lcdSource = std::move(copySource);
        CHECK_AND_RETURN_RET_LOG(lcdSource != nullptr, false, "LcdSource is nullptr");
        if (lcdSource->GetWidth() * lcdSource->GetHeight() == 0) {
            MEDIA_ERR_LOG("CompressImage failed, invalid lcdSource");
            return false;
        }
        float widthScale = (1.0f * lcdDesiredWidth) / lcdSource->GetWidth();
        float heightScale = (1.0f * lcdDesiredHeight) / lcdSource->GetHeight();
        lcdSource->scale(widthScale, heightScale);
    }
    if (!ThumbnailUtils::CompressImage(lcdSource, data.lcd, false, false, data.thumbnailQuality)) {
        MEDIA_ERR_LOG("CompressImage failed");
        return false;
    }

    if (!TrySavePixelMap(data, isSourceEx ? ThumbnailType::LCD_EX : ThumbnailType::LCD)) {
        MEDIA_ERR_LOG("SaveLcd PixelMap failed: %{public}s", DfxUtils::GetSafePath(data.path).c_str());
        return false;
    }

    data.lcd.clear();
    if (!isSourceEx) {
        UpdateLcdDbState(opts, data);
    }
    return true;
}

bool IThumbnailHelper::IsCreateLcdSuccess(ThumbRdbOpt &opts, ThumbnailData &data)
{
    data.loaderOpts.decodeInThumbSize = false;
    data.loaderOpts.isHdr = true;
    if (!TryLoadSource(opts, data)) {
        MEDIA_ERR_LOG("load source is nullptr path: %{public}s", DfxUtils::GetSafePath(opts.path).c_str());
        return false;
    }

    if (data.source.IsEmptySource()) {
        MEDIA_ERR_LOG("Fail to create lcd, source is nullptr");
        return false;
    }

    if (data.source.HasPictureSource()) {
        return SaveLcdPictureSource(opts, data, false);
    } else {
        return SaveLcdPixelMapSource(opts, data, false);
    }
}

bool IThumbnailHelper::NeedGenerateExFile(ThumbnailData &data)
{
    return data.isLocalFile || data.isRegenerateStage;
}

bool IThumbnailHelper::IsCreateLcdExSuccess(ThumbRdbOpt &opts, ThumbnailData &data)
{
    if (!NeedGenerateExFile(data)) {
        MEDIA_INFO_LOG("Create lcd when cloud loading, no need to create THM_EX, path: %{public}s, id: %{public}s",
            DfxUtils::GetSafePath(opts.path).c_str(), data.id.c_str());
        return false;
    }

    string fileName = GetThumbnailPath(data.path, THUMBNAIL_LCD_EX_SUFFIX);
    string dirName = MediaFileUtils::GetParentPath(fileName);
    if (!MediaFileUtils::CreateDirectory(dirName)) {
        MEDIA_ERR_LOG("Fail to create directory, fileName: %{public}s", DfxUtils::GetSafePath(fileName).c_str());
        return false;
    }
    
    if (data.source.IsEmptySource()) {
        MEDIA_ERR_LOG("Fail to create lcdEx, source is nullptr");
        return false;
    }

    if (data.source.HasPictureSource()) {
        return SaveLcdPictureSource(opts, data, true);
    } else {
        return SaveLcdPixelMapSource(opts, data, true);
    }
}

bool IThumbnailHelper::GenThumbnail(ThumbRdbOpt &opts, ThumbnailData &data, const ThumbnailType type)
{
    auto pixelMap = data.source.GetPixelMap();
    if (pixelMap == nullptr) {
        MEDIA_ERR_LOG("source is nullptr when generate type: %{public}s", TYPE_NAME_MAP.at(type).c_str());
        return false;
    }

    if (type == ThumbnailType::THUMB || type == ThumbnailType::THUMB_ASTC) {
        if (!ThumbnailUtils::CompressImage(pixelMap, type == ThumbnailType::THUMB ? data.thumbnail : data.thumbAstc,
            type == ThumbnailType::THUMB_ASTC)) {
            MEDIA_ERR_LOG("CompressImage faild id %{public}s", opts.row.c_str());
            VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, E_THUMBNAIL_UNKNOWN},
                {KEY_OPT_FILE, opts.path}, {KEY_OPT_TYPE, OptType::THUMB}};
            PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
            return false;
        }
    } else if (type == ThumbnailType::MTH_ASTC || type == ThumbnailType::YEAR_ASTC) {
        if (!ThumbnailUtils::CheckDateTaken(opts, data)) {
            MEDIA_ERR_LOG("CheckDateTaken failed in GenThumbnail");
            return false;
        }
        if (!GenMonthAndYearAstcData(data, type)) {
            MEDIA_ERR_LOG("GenMonthAndYearAstcData failed in GenThumbnail");
            return false;
        }
    } else {
        MEDIA_ERR_LOG("invalid thumbnail type: %{public}d", type);
        return false;
    }

    if (!TrySavePixelMap(data, type)) {
        MEDIA_ERR_LOG("SaveThumbnailData failed: %{public}s", DfxUtils::GetSafePath(opts.path).c_str());
        return false;
    }
    data.thumbnail.clear();
    return true;
}

bool IThumbnailHelper::GenThumbnailEx(ThumbRdbOpt &opts, ThumbnailData &data)
{
    if (!NeedGenerateExFile(data)) {
        MEDIA_INFO_LOG("Create thumb when cloud loading, no need to create THM_EX, path: %{public}s, id: %{public}s",
            DfxUtils::GetSafePath(opts.path).c_str(), data.id.c_str());
        return false;
    }
    
    string fileName = GetThumbnailPath(data.path, THUMBNAIL_THUMB_EX_SUFFIX);
    string dirName = MediaFileUtils::GetParentPath(fileName);
    if (!MediaFileUtils::CreateDirectory(dirName)) {
        MEDIA_ERR_LOG("Fail to create directory, fileName: %{public}s", DfxUtils::GetSafePath(fileName).c_str());
        return false;
    }

    auto pixelMapEx = data.source.GetPixelMapEx();
    if (pixelMapEx == nullptr) {
        MEDIA_ERR_LOG("sourceEx is nullptr when generate thumbnailEx, path: %{public}s",
            DfxUtils::GetSafePath(opts.path).c_str());
        return false;
    }

    if (!ThumbnailUtils::CompressImage(pixelMapEx, data.thumbnail, false)) {
        MEDIA_ERR_LOG("CompressImage failed id %{public}s", opts.row.c_str());
        return false;
    }

    if (!TrySavePixelMap(data, ThumbnailType::THUMB_EX)) {
        MEDIA_ERR_LOG("SaveThumbnailEx failed: %{public}s", DfxUtils::GetSafePath(opts.path).c_str());
        return false;
    }
    data.thumbnail.clear();
    return true;
}

bool IThumbnailHelper::GenMonthAndYearAstcData(ThumbnailData &data, const ThumbnailType type)
{
    Size size;
    if (type == ThumbnailType::MTH_ASTC) {
        size = {DEFAULT_MTH_SIZE, DEFAULT_MTH_SIZE };
    } else if (type == ThumbnailType::YEAR_ASTC) {
        size = {DEFAULT_YEAR_SIZE, DEFAULT_YEAR_SIZE };
    } else {
        MEDIA_ERR_LOG("invalid thumbnail type");
        return false;
    }
    ThumbnailUtils::GenTargetPixelmap(data, size);
    auto pixelMap = data.source.GetPixelMap();
#ifdef IMAGE_COLORSPACE_FLAG
    if (pixelMap->ApplyColorSpace(ColorManager::ColorSpaceName::DISPLAY_P3) != E_OK) {
        MEDIA_ERR_LOG("ApplyColorSpace to p3 failed");
    }
#endif
    if (!ThumbnailUtils::CompressImage(pixelMap,
        (type == ThumbnailType::MTH_ASTC) ? data.monthAstc : data.yearAstc, true)) {
        MEDIA_ERR_LOG("CompressImage to astc failed");
        return false;
    }
    return true;
}

// After all thumbnails are generated, the value of column "thumbnail_ready" in rdb needs to be updated,
// And if generate successfully, application should receive a notification at the same time.
bool IThumbnailHelper::UpdateThumbnailState(const ThumbRdbOpt &opts, ThumbnailData &data, const bool isSuccess)
{
    if (data.fileUri.empty()) {
        data.fileUri = MediaFileUtils::GetUriByExtrConditions(PhotoColumn::DEFAULT_PHOTO_URI + "/", data.id,
            MediaFileUtils::GetExtraUri(data.displayName, data.path));
    }
    return isSuccess ? UpdateSuccessState(opts, data) : UpdateFailState(opts, data);
}

// This method has to be called before updating rdb
static int32_t IsPhotoVisible(const ThumbRdbOpt &opts, const ThumbnailData &data)
{
    vector<string> columns = {
        PhotoColumn::PHOTO_THUMBNAIL_VISIBLE
    };
    if (data.id.empty() && opts.row.empty()) {
        MEDIA_ERR_LOG("SendThumbNotify thumb is empty");
        return 0;
    }
    string fileId = data.id.empty() ? opts.row : data.id;
    string strQueryCondition = MEDIA_DATA_DB_ID + " = " + fileId;
    RdbPredicates rdbPredicates(PhotoColumn::PHOTOS_TABLE);
    rdbPredicates.SetWhereClause(strQueryCondition);
    if (opts.store == nullptr) {
        MEDIA_ERR_LOG("SendThumbNotify opts.store is nullptr");
        return 0;
    }
    auto resultSet = opts.store->QueryByStep(rdbPredicates, columns);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("SendThumbNotify result is null");
        return 0;
    }
    auto ret = resultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("SendThumbNotify go to first row failed");
        return 0;
    }
    return GetInt32Val(PhotoColumn::PHOTO_THUMBNAIL_VISIBLE, resultSet);
}

std::string GetLocalOriginFilePath(const std::string &path)
{
    if (path.length() < ROOT_MEDIA_DIR.length()) {
        return "";
    }
    return LOCAL_MEDIA_PREFIX + path.substr(ROOT_MEDIA_DIR.length());
}

bool IThumbnailHelper::UpdateSuccessState(const ThumbRdbOpt &opts, const ThumbnailData &data)
{
    int thumbnailVisible = IsPhotoVisible(opts, data);
    int32_t err = UpdateThumbDbState(opts, data);
    if (err != E_OK) {
        MEDIA_ERR_LOG("update thumbnail_ready failed, err = %{public}d", err);
        return false;
    }

    if (data.isRegenerateStage) {
        string filePath = GetLocalOriginFilePath(data.path);
        bool shouldUpdateFDirty = access(filePath.c_str(), F_OK) == 0;
        ValuesBucket values;
        int changedRows;
        values.PutInt(PhotoColumn::PHOTO_DIRTY, shouldUpdateFDirty ?
            static_cast<int32_t>(DirtyType::TYPE_FDIRTY) : static_cast<int32_t>(DirtyType::TYPE_TDIRTY));
        MEDIA_ERR_LOG("update thumbnail_ready failed, err = %{public}d", err);
        int32_t err = opts.store->Update(changedRows, opts.table, values, MEDIA_DATA_DB_ID + " = ?",
            vector<string> { data.id });
        if (err != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Update Regenerate dirty status failed! %{public}d", err);
        }
    }

    auto watch = MediaLibraryNotify::GetInstance();
    if (watch == nullptr) {
        MEDIA_ERR_LOG("SendThumbNotify watch is nullptr");
        return false;
    }
    if (thumbnailVisible) {
        watch->Notify(data.fileUri, NotifyType::NOTIFY_THUMB_UPDATE);
    } else {
        watch->Notify(data.fileUri, NotifyType::NOTIFY_THUMB_ADD);
    }
    return true;
}

bool IThumbnailHelper::UpdateFailState(const ThumbRdbOpt &opts, const ThumbnailData &data)
{
    if (opts.store == nullptr) {
        MEDIA_ERR_LOG("opts.store is nullptr");
        return false;
    }
    ValuesBucket values;
    int changedRows;
    values.PutLong(PhotoColumn::PHOTO_THUMBNAIL_READY, static_cast<int64_t>(ThumbnailReady::GENERATE_THUMB_RETRY));
    values.PutLong(PhotoColumn::PHOTO_THUMBNAIL_VISIBLE, 1);
    int32_t err = opts.store->Update(changedRows, opts.table, values, MEDIA_DATA_DB_ID + " = ?",
        vector<string> { data.id });
    if (err != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("RdbStore Update failed! %{public}d", err);
        return false;
    }
    return true;
}

int32_t IThumbnailHelper::UpdateThumbDbState(const ThumbRdbOpt &opts, const ThumbnailData &data)
{
    ValuesBucket values;
    int changedRows;
    values.PutLong(PhotoColumn::PHOTO_THUMBNAIL_READY, MediaFileUtils::UTCTimeMilliSeconds());
    values.PutLong(PhotoColumn::PHOTO_THUMBNAIL_VISIBLE, 1);
    Size lcdSize;
    if (ThumbnailUtils::GetLocalThumbSize(data, ThumbnailType::LCD, lcdSize)) {
        ThumbnailUtils::SetThumbnailSizeValue(values, lcdSize, PhotoColumn::PHOTO_LCD_SIZE);
        values.PutLong(PhotoColumn::PHOTO_LCD_VISIT_TIME, static_cast<int64_t>(LcdReady::GENERATE_LCD_COMPLETED));
    }
    Size thumbSize;
    if (ThumbnailUtils::GetLocalThumbSize(data, ThumbnailType::THUMB, thumbSize)) {
        ThumbnailUtils::SetThumbnailSizeValue(values, thumbSize, PhotoColumn::PHOTO_THUMB_SIZE);
    }
    int32_t err = opts.store->Update(changedRows, opts.table, values, MEDIA_DATA_DB_ID + " = ?",
        vector<string> { data.id });
    StoreThumbnailSize(opts, data);
    if (err != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("RdbStore Update failed! %{public}d", err);
        return E_ERR;
    }
    return E_OK;
}

bool IThumbnailHelper::DoCreateThumbnail(ThumbRdbOpt &opts, ThumbnailData &data, WaitStatus &ret)
{
    MEDIA_INFO_LOG("Start DoCreateThumbnail, id: %{public}s, path: %{public}s",
        data.id.c_str(), DfxUtils::GetSafePath(data.path).c_str());
    int64_t startTime = MediaFileUtils::UTCTimeMilliSeconds();
    ThumbnailWait thumbnailWait(true);
    ret = thumbnailWait.InsertAndWait(data.id, ThumbnailType::THUMB, data.dateModified);
    data.needCheckWaitStatus = true;
    if (ret != WaitStatus::INSERT && ret != WaitStatus::WAIT_CONTINUE) {
        return ret == WaitStatus::WAIT_SUCCESS;
    }

    if (!IsCreateThumbnailSuccess(opts, data)) {
        MEDIA_ERR_LOG("Fail to create thumbnail, path: %{public}s", DfxUtils::GetSafePath(opts.path).c_str());
        if (data.needUpdateDb) {
            IThumbnailHelper::UpdateThumbnailState(opts, data, false);
        }
        return false;
    }

    if (data.orientation != 0 && !IsCreateThumbnailExSuccess(opts, data)) {
        MEDIA_ERR_LOG("Fail to create thumbnailEx, path: %{public}s", DfxUtils::GetSafePath(opts.path).c_str());
    }
    thumbnailWait.UpdateThumbnailMap();
    data.needCheckWaitStatus = false;
    MediaLibraryAstcStat::GetInstance().AddAstcInfo(startTime, data.stats.scene,
        AstcGenScene::SCREEN_ON, data.id);
    IThumbnailHelper::UpdateThumbnailState(opts, data, true);
    return true;
}

bool IThumbnailHelper::IsCreateThumbnailSuccess(ThumbRdbOpt &opts, ThumbnailData &data)
{
    data.loaderOpts.decodeInThumbSize = true;
    if (!TryLoadSource(opts, data)) {
        MEDIA_ERR_LOG("DoCreateThumbnail failed, try to load source failed, id: %{public}s", data.id.c_str());
        return false;
    }
    auto pixelMap = data.source.GetPixelMap();
    if (pixelMap != nullptr && pixelMap->IsHdr()) {
        uint32_t ret = pixelMap->ToSdr();
        if (ret != E_OK) {
            MEDIA_ERR_LOG("DoCreateThumbnail failed to transform to sdr, id: %{public}s.", data.id.c_str());
            return false;
        }
    }
    if (!GenThumbnail(opts, data, ThumbnailType::THUMB)) {
        return false;
    }
    if (opts.table == AudioColumn::AUDIOS_TABLE) {
        MEDIA_DEBUG_LOG("AUDIOS_TABLE, no need to create all thumbnail");
        return true;
    }

    if (ThumbnailUtils::IsSupportGenAstc() && !GenThumbnail(opts, data, ThumbnailType::THUMB_ASTC)) {
        return false;
    }

    if (!data.tracks.empty()) {
        MEDIA_INFO_LOG("generate highlight frame, no need to create month and year astc");
        return true;
    }

    // for some device that do not support KvStore, no need to generate the month and year astc.
    if (MediaLibraryKvStoreManager::GetInstance()
        .GetKvStore(KvStoreRoleType::OWNER, KvStoreValueType::MONTH_ASTC) == nullptr) {
        MEDIA_DEBUG_LOG("kvStore is nullptr, no need to create month and year astc");
        return true;
    }
    if (!GenThumbnail(opts, data, ThumbnailType::MTH_ASTC)) {
        return false;
    }
    if (!GenThumbnail(opts, data, ThumbnailType::YEAR_ASTC)) {
        return false;
    }
    return true;
}

bool IThumbnailHelper::IsCreateThumbnailExSuccess(ThumbRdbOpt &opts, ThumbnailData &data)
{
    if (!GenThumbnailEx(opts, data)) {
        MEDIA_ERR_LOG("Fail to create thumbnailEx, fileName: %{public}s", DfxUtils::GetSafePath(data.path).c_str());
        return false;
    }
    return true;
}

bool IThumbnailHelper::DoRotateThumbnail(ThumbRdbOpt &opts, ThumbnailData &data)
{
    auto pixelMap = data.source.GetPixelMap();
    if (pixelMap == nullptr) {
        MEDIA_ERR_LOG("source is nullptr when rotate thumbnail path: %{public}s",
            DfxUtils::GetSafePath(data.path).c_str());
        return false;
    }

    if (!ThumbnailUtils::CompressImage(pixelMap, data.thumbnail, false)) {
        MEDIA_ERR_LOG("CompressImage faild id %{public}s", data.id.c_str());
        return false;
    }

    if (!TrySavePixelMap(data, ThumbnailType::THUMB)) {
        MEDIA_ERR_LOG("DoRotateThumbnail failed: %{public}s", DfxUtils::GetSafePath(data.path).c_str());
        return false;
    }
    data.thumbnail.clear();
    return true;
}

static bool ScaleLcdToThumbnail(ThumbnailData &data)
{
    if (data.source.IsEmptySource()) {
        MEDIA_ERR_LOG("data source is empty when scaling from lcd to thumb");
        return false;
    }

    data.loaderOpts.decodeInThumbSize = true;
    if (data.source.HasPictureSource()) {
        MEDIA_INFO_LOG("Scale from picture source, path: %{public}s", DfxUtils::GetSafePath(data.path).c_str());
        auto mainPixelMap = data.source.GetPicture()->GetMainPixel();
        data.source.SetPixelMap(mainPixelMap);
    }
    if (!ThumbnailUtils::ScaleThumbnailFromSource(data, false)) {
        MEDIA_ERR_LOG("Fail to scale from LCD to THM, path: %{public}s", DfxUtils::GetSafePath(data.path).c_str());
        return false;
    }
    
    if (data.orientation != 0 && data.source.HasPictureSource()) {
        MEDIA_INFO_LOG("Scale from picture source, path: %{public}s", DfxUtils::GetSafePath(data.path).c_str());
        auto mainPixelMapEx = data.source.GetPictureEx()->GetMainPixel();
        data.source.SetPixelMapEx(mainPixelMapEx);
    }
    if (data.orientation != 0 && !ThumbnailUtils::ScaleThumbnailFromSource(data, true)) {
        MEDIA_ERR_LOG("Fail to scale from LCD_EX to THM_EX, path: %{public}s",
            DfxUtils::GetSafePath(data.path).c_str());
    }
    return true;
}

bool IThumbnailHelper::DoCreateLcdAndThumbnail(ThumbRdbOpt &opts, ThumbnailData &data, WaitStatus &ret)
{
    MEDIA_INFO_LOG("Start DoCreateLcdAndThumbnail, id: %{public}s, path: %{public}s",
        data.id.c_str(), DfxUtils::GetSafePath(data.path).c_str());
    data.isNeedStoreSize = false;
    DoCreateLcd(opts, data, ret);
    ScaleLcdToThumbnail(data);
    return DoCreateThumbnail(opts, data, ret);
}

std::string GetAvailableThumbnailSuffix(ThumbnailData &data)
{
    // Check whether the thumbnail data exist, firstly thumb then lcd, and return the corresponding suffix.
    // When there is no thumbnail data, return empty string.
    if (access(GetThumbnailPath(data.path, THUMBNAIL_THUMB_SUFFIX).c_str(), F_OK) == 0) {
        return THUMBNAIL_THUMB_SUFFIX;
    }
    if (access(GetThumbnailPath(data.path, THUMBNAIL_LCD_SUFFIX).c_str(), F_OK) == 0) {
        return THUMBNAIL_LCD_SUFFIX;
    }
    return "";
}

bool IThumbnailHelper::DoCreateAstc(ThumbRdbOpt &opts, ThumbnailData &data)
{
    MEDIA_INFO_LOG("Start DoCreateAstc, id: %{public}s, path: %{public}s",
        data.id.c_str(), DfxUtils::GetSafePath(data.path).c_str());
    data.loaderOpts.decodeInThumbSize = true;
    if (!TryLoadSource(opts, data)) {
        MEDIA_ERR_LOG("DoCreateAstc failed, try to load exist thumbnail failed, id: %{public}s", data.id.c_str());
        return false;
    }
    auto pixelMap = data.source.GetPixelMap();
    if (pixelMap != nullptr && pixelMap->IsHdr()) {
        uint32_t ret = pixelMap->ToSdr();
        if (ret != E_OK) {
            MEDIA_ERR_LOG("DoCreateAstc failed to transform to sdr, id: %{public}s.", data.id.c_str());
            return false;
        }
    }
    if (!GenThumbnail(opts, data, ThumbnailType::THUMB)) {
        MEDIA_ERR_LOG("DoCreateAstc GenThumbnail THUMB failed, id: %{public}s", data.id.c_str());
        return false;
    }
    if (!GenThumbnail(opts, data, ThumbnailType::THUMB_ASTC)) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__},
            {KEY_ERR_CODE, E_THUMBNAIL_UNKNOWN}, {KEY_OPT_FILE, opts.path}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        return false;
    }
    if (!GenThumbnail(opts, data, ThumbnailType::MTH_ASTC) || !GenThumbnail(opts, data, ThumbnailType::YEAR_ASTC)) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__},
            {KEY_ERR_CODE, E_THUMBNAIL_UNKNOWN}, {KEY_OPT_FILE, opts.path}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        return false;
    }
    return true;
}

bool IThumbnailHelper::DoCreateAstcMthAndYear(ThumbRdbOpt &opts, ThumbnailData &data)
{
    MEDIA_INFO_LOG("Start DoCreateAstcMthAndYear, id: %{public}s, path: %{public}s",
        data.id.c_str(), DfxUtils::GetSafePath(data.path).c_str());
    data.loaderOpts.decodeInThumbSize = true;
    data.loaderOpts.desiredType = ThumbnailType::MTH_ASTC;
    if (!TryLoadSource(opts, data)) {
        MEDIA_ERR_LOG("DoCreateAstcMthAndYear failed, try load source failed, id: %{public}s", data.id.c_str());
        return false;
    }
    auto pixelMap = data.source.GetPixelMap();
    if (pixelMap == nullptr) {
        MEDIA_ERR_LOG("DoCreateAstc failed, no available pixelMap, id: %{public}s.", data.id.c_str());
        return false;
    }
    if (!GenThumbnail(opts, data, ThumbnailType::MTH_ASTC) || !GenThumbnail(opts, data, ThumbnailType::YEAR_ASTC)) {
        MEDIA_ERR_LOG("DoCreateAstc failed, GenThumbnail failed, id: %{public}s.", data.id.c_str());
        return false;
    }
    return true;
}

bool GenerateRotatedThumbnail(ThumbRdbOpt &opts, ThumbnailData &data, ThumbnailType thumbType)
{
    WaitStatus status;
    if (thumbType == ThumbnailType::LCD && !IThumbnailHelper::DoCreateLcd(opts, data, status)) {
        MEDIA_ERR_LOG("Get lcd thumbnail pixelmap, rotate lcd failed: %{public}s",
            DfxUtils::GetSafePath(data.path).c_str());
        return false;
    }
    if (thumbType != ThumbnailType::LCD && !IThumbnailHelper::DoRotateThumbnail(opts, data)) {
        MEDIA_ERR_LOG("Get default thumbnail pixelmap, rotate thumbnail failed: %{public}s",
            DfxUtils::GetSafePath(data.path).c_str());
        return false;
    }
    return true;
}

unique_ptr<PixelMap> DecodeThumbnailFromFd(int32_t fd)
{
    SourceOptions opts;
    uint32_t err = 0;
    unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(fd, opts, err);
    if (imageSource == nullptr) {
        MEDIA_ERR_LOG("Decode thumbnail from fd failed, CreateImageSource err: %{public}d", err);
        return nullptr;
    }

    ImageInfo imageInfo;
    err = imageSource->GetImageInfo(0, imageInfo);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Decode thumbnail from fd failed, GetImageInfo err: %{public}d", err);
        return nullptr;
    }

    DecodeOptions decodeOpts;
    decodeOpts.desiredDynamicRange = DecodeDynamicRange::SDR;
    decodeOpts.desiredPixelFormat = PixelFormat::RGBA_8888;
    unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, err);
    if (pixelMap == nullptr) {
        MEDIA_ERR_LOG("Decode thumbnail from fd failed, CreatePixelMap err: %{public}d", err);
        return nullptr;
    }
    return pixelMap;
}

bool IThumbnailHelper::DoCreateAstcEx(ThumbRdbOpt &opts, ThumbnailData &data, WaitStatus &ret)
{
    ThumbnailWait thumbnailWait(true);
    ret = thumbnailWait.CloudInsertAndWait(data.id, CloudLoadType::CLOUD_DOWNLOAD);
    if (ret != WaitStatus::INSERT && ret != WaitStatus::WAIT_CONTINUE) {
        return ret == WaitStatus::WAIT_SUCCESS;
    }
    
    MEDIA_INFO_LOG("Start DoCreateAstcEx, id: %{public}s, path: %{public}s",
        data.id.c_str(), DfxUtils::GetSafePath(data.path).c_str());
    string fileName = GetThumbnailPath(data.path, THUMBNAIL_LCD_EX_SUFFIX);
    if (access(fileName.c_str(), F_OK) != 0) {
        MEDIA_ERR_LOG("No available file in THM_EX, path: %{public}s", DfxUtils::GetSafePath(data.path).c_str());
        return false;
    }

    if (!DoCreateLcd(opts, data, ret)) {
        MEDIA_ERR_LOG("Fail to create lcd, path: %{public}s", DfxUtils::GetSafePath(data.path).c_str());
        return false;
    }

    data.loaderOpts.decodeInThumbSize = true;
    if (data.source.HasPictureSource()) {
        MEDIA_INFO_LOG("Scale from picture source, path: %{public}s", DfxUtils::GetSafePath(data.path).c_str());
        auto mainPixelMap = data.source.GetPicture()->GetMainPixel();
        data.source.SetPixelMap(mainPixelMap);
    }
    if (!ThumbnailUtils::ScaleThumbnailFromSource(data, false)) {
        MEDIA_ERR_LOG("Fail to scale from LCD to THM, path: %{public}s", DfxUtils::GetSafePath(data.path).c_str());
        return false;
    }
    if (!DoCreateThumbnail(opts, data, ret)) {
        MEDIA_ERR_LOG("Fail to create thumbnail, path: %{public}s", DfxUtils::GetSafePath(data.path).c_str());
        return false;
    }

    thumbnailWait.UpdateCloudLoadThumbnailMap(CloudLoadType::CLOUD_DOWNLOAD, true);
    return true;
}

bool IThumbnailHelper::DoRotateThumbnailEx(ThumbRdbOpt &opts, ThumbnailData &data, int32_t fd, ThumbnailType thumbType)
{
    ThumbnailWait thumbnailWait(true);
    auto ret = thumbnailWait.CloudInsertAndWait(data.id, thumbType == ThumbnailType::LCD ?
        CloudLoadType::CLOUD_READ_LCD : CloudLoadType::CLOUD_READ_THUMB);
    if (ret != WaitStatus::INSERT && ret != WaitStatus::WAIT_CONTINUE) {
        close(fd);
        return ret == WaitStatus::WAIT_SUCCESS;
    }
    
    auto dataSourcePtr = DecodeThumbnailFromFd(fd);
    std::shared_ptr<PixelMap> dataSource = std::move(dataSourcePtr);
    if (dataSource == nullptr) {
        MEDIA_ERR_LOG("GetThumbnailPixelMap failed, dataSource is nullptr, path: %{public}s",
            DfxUtils::GetSafePath(data.path).c_str());
        close(fd);
        thumbnailWait.UpdateCloudLoadThumbnailMap(thumbType == ThumbnailType::LCD ?
            CloudLoadType::CLOUD_READ_LCD : CloudLoadType::CLOUD_READ_THUMB, false);
        return false;
    }
    close(fd);

    PostProc::RotateInRectangularSteps(*(dataSource.get()), static_cast<float>(data.orientation), true);
    data.source.SetPixelMap(dataSource);
    if (!GenerateRotatedThumbnail(opts, data, thumbType)) {
        MEDIA_ERR_LOG("GenerateRotatedThumbnail failed, path: %{public}s", DfxUtils::GetSafePath(data.path).c_str());
        thumbnailWait.UpdateCloudLoadThumbnailMap(thumbType == ThumbnailType::LCD ?
            CloudLoadType::CLOUD_READ_LCD : CloudLoadType::CLOUD_READ_THUMB, false);
        return false;
    }

    thumbnailWait.UpdateCloudLoadThumbnailMap(thumbType == ThumbnailType::LCD ?
        CloudLoadType::CLOUD_READ_LCD : CloudLoadType::CLOUD_READ_THUMB, true);
    return true;
}

bool IThumbnailHelper::IsPureCloudImage(ThumbRdbOpt &opts)
{
    vector<string> columns = {
        MEDIA_DATA_DB_ID,
        PhotoColumn::PHOTO_POSITION
    };
    if (opts.row.empty() || opts.table.empty()) {
        MEDIA_ERR_LOG("IsPureCloudImage opts.row is empty");
        return false;
    }
    string strQueryCondition = MEDIA_DATA_DB_ID + " = " + opts.row;
    RdbPredicates rdbPredicates(opts.table);
    rdbPredicates.SetWhereClause(strQueryCondition);
    if (opts.store == nullptr) {
        MEDIA_ERR_LOG("IsPureCloudImage opts.store is nullptr");
        return false;
    }
    auto resultSet = opts.store->QueryByStep(rdbPredicates, columns);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("IsPureCloudImage result set is null");
        return false;
    }
    auto ret = resultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("IsPureCloudImage go to first row failed");
        return false;
    }
    int photoPosition = GetInt32Val(PhotoColumn::PHOTO_POSITION, resultSet);

    // if current image is a pure cloud image, it's photo position column in database will be 2
    return photoPosition == 2;
}
} // namespace Media
} // namespace OHOS