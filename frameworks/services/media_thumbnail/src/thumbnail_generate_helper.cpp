/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "thumbnail_generate_helper.h"

#include <fcntl.h>

#include "acl.h"
#include "cloud_sync_helper.h"
#include "dfx_const.h"
#include "dfx_manager.h"
#include "dfx_timer.h"
#include "dfx_utils.h"
#include "ffrt.h"
#include "ffrt_inner.h"
#include "directory_ex.h"
#include "ithumbnail_helper.h"
#include "medialibrary_errno.h"
#include "medialibrary_kvstore_manager.h"
#include "medialibrary_photo_operations.h"
#include "medialibrary_type_const.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "thumbnail_const.h"
#include "thumbnail_generate_worker_manager.h"
#include "thumbnail_source_loading.h"
#include "thumbnail_utils.h"

using namespace std;
using namespace OHOS::DistributedKv;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
const int FFRT_MAX_RESTORE_ASTC_THREADS = 4;
const std::string SQL_REFRESH_THUMBNAIL_READY =
    " Update " + PhotoColumn::PHOTOS_TABLE + " SET " + PhotoColumn::PHOTO_THUMBNAIL_READY + " = 7 " +
    " WHERE " + PhotoColumn::PHOTO_THUMBNAIL_READY + " != 0; END;";

int32_t ThumbnailGenerateHelper::CreateThumbnailFileScaned(ThumbRdbOpt &opts, bool isSync)
{
    ThumbnailData thumbnailData;
    ThumbnailUtils::GetThumbnailInfo(opts, thumbnailData);
    thumbnailData.needResizeLcd = true;
    thumbnailData.loaderOpts.loadingStates = SourceLoader::LOCAL_SOURCE_LOADING_STATES;
    ThumbnailUtils::RecordStartGenerateStats(thumbnailData.stats, GenerateScene::LOCAL, LoadSourceType::LOCAL_PHOTO);
    if (ThumbnailUtils::DeleteThumbExDir(thumbnailData)) {
        MEDIA_ERR_LOG("Delete THM_EX directory, path: %{public}s, id: %{public}s",
            DfxUtils::GetSafePath(thumbnailData.path).c_str(), thumbnailData.id.c_str());
    }

    if (isSync) {
        WaitStatus status;
        bool isSuccess = IThumbnailHelper::DoCreateLcdAndThumbnail(opts, thumbnailData, status);
        if (status == WaitStatus::INSERT) {
            IThumbnailHelper::UpdateThumbnailState(opts, thumbnailData, isSuccess);
        }
        
        ThumbnailUtils::RecordCostTimeAndReport(thumbnailData.stats);
    } else {
        IThumbnailHelper::AddThumbnailGenerateTask(IThumbnailHelper::CreateLcdAndThumbnail,
            opts, thumbnailData, ThumbnailTaskType::FOREGROUND, ThumbnailTaskPriority::HIGH);
    }
    return E_OK;
}

int32_t ThumbnailGenerateHelper::CreateThumbnailBackground(ThumbRdbOpt &opts)
{
    if (opts.store == nullptr) {
        MEDIA_ERR_LOG("rdbStore is not init");
        return E_ERR;
    }
    CHECK_AND_RETURN_RET_LOG(ThumbnailUtils::CheckRemainSpaceMeetCondition(THUMBNAIL_FREE_SIZE_LIMIT_10),
        E_FREE_SIZE_NOT_ENOUGH, "Free size is not enough");

    vector<ThumbnailData> infos;
    int32_t err = GetNoThumbnailData(opts, infos);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to GetNoLThumbnailData %{private}d", err);
        return err;
    }

    if (infos.empty()) {
        MEDIA_DEBUG_LOG("No need generate thumbnail.");
        return E_OK;
    }
    auto createThumbnailBackgroundTask = [](std::shared_ptr<ThumbnailTaskData> &data) {
        CHECK_AND_RETURN_LOG(data != nullptr, "Data is null");
        auto &thumbnailData = data->thumbnailData_;
        CHECK_AND_RETURN_LOG(ThumbnailUtils::CheckRemainSpaceMeetCondition(THUMBNAIL_FREE_SIZE_LIMIT_10),
            "CreateThumbnailBackgroundTask free size is not enough, id:%{public}s, path:%{public}s",
            thumbnailData.id.c_str(), DfxUtils::GetSafePath(thumbnailData.path).c_str());
        IThumbnailHelper::CreateThumbnail(data);
    };

    for (uint32_t i = 0; i < infos.size(); i++) {
        opts.row = infos[i].id;
        infos[i].loaderOpts.loadingStates = infos[i].isLocalFile ? SourceLoader::LOCAL_SOURCE_LOADING_STATES :
            SourceLoader::CLOUD_SOURCE_LOADING_STATES;
        IThumbnailHelper::AddThumbnailGenerateTask(createThumbnailBackgroundTask,
            opts, infos[i], ThumbnailTaskType::BACKGROUND, ThumbnailTaskPriority::LOW);
    }

    return E_OK;
}

int32_t ThumbnailGenerateHelper::CreateAstcBackground(ThumbRdbOpt &opts)
{
    if (opts.store == nullptr) {
        MEDIA_ERR_LOG("rdbStore is not init");
        return E_ERR;
    }

    CheckMonthAndYearKvStoreValid(opts);
    CHECK_AND_RETURN_RET_LOG(ThumbnailUtils::CheckRemainSpaceMeetCondition(THUMBNAIL_FREE_SIZE_LIMIT_10),
        E_FREE_SIZE_NOT_ENOUGH, "Free size is not enough");
    vector<ThumbnailData> infos;
    int32_t err = GetNoAstcData(opts, infos);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to GetNoAstcData %{private}d", err);
        return err;
    }

    auto kvStore = MediaLibraryKvStoreManager::GetInstance()
        .GetKvStore(KvStoreRoleType::OWNER, KvStoreValueType::MONTH_ASTC);
    if (infos.empty() || kvStore == nullptr) {
        MEDIA_DEBUG_LOG("No need create Astc.");
        return E_OK;
    }

    auto createAstcBackgroundTask = [](std::shared_ptr<ThumbnailTaskData> &data) {
        CHECK_AND_RETURN_LOG(data != nullptr, "Data is null");
        auto &thumbnailData = data->thumbnailData_;
        CHECK_AND_RETURN_LOG(ThumbnailUtils::CheckRemainSpaceMeetCondition(THUMBNAIL_FREE_SIZE_LIMIT_10),
            "CreateAstcBackgroundTask free size is not enough, id:%{public}s, path:%{public}s",
            thumbnailData.id.c_str(), DfxUtils::GetSafePath(thumbnailData.path).c_str());
        if (thumbnailData.isLocalFile) {
            thumbnailData.loaderOpts.loadingStates = SourceLoader::LOCAL_SOURCE_LOADING_STATES;
            IThumbnailHelper::CreateThumbnail(data);
        } else {
            thumbnailData.loaderOpts.loadingStates = thumbnailData.orientation != 0 ?
                SourceLoader::CLOUD_LCD_SOURCE_LOADING_STATES : SourceLoader::CLOUD_SOURCE_LOADING_STATES;
            thumbnailData.orientation != 0 ? IThumbnailHelper::CreateAstcEx(data) : IThumbnailHelper::CreateAstc(data);
        }
    };

    MEDIA_INFO_LOG("no astc data size: %{public}d", static_cast<int>(infos.size()));
    for (uint32_t i = 0; i < infos.size(); i++) {
        opts.row = infos[i].id;
        ThumbnailUtils::RecordStartGenerateStats(infos[i].stats, GenerateScene::BACKGROUND,
            LoadSourceType::LOCAL_PHOTO);
        IThumbnailHelper::AddThumbnailGenerateTask(createAstcBackgroundTask,
            opts, infos[i], ThumbnailTaskType::BACKGROUND, ThumbnailTaskPriority::LOW);
    }
    return E_OK;
}

int32_t ThumbnailGenerateHelper::CreateAstcCloudDownload(ThumbRdbOpt &opts, bool isCloudInsertTaskPriorityHigh)
{
    ThumbnailData data;
    ThumbnailUtils::RecordStartGenerateStats(data.stats, GenerateScene::CLOUD, LoadSourceType::LOCAL_PHOTO);
    int err = 0;
    ThumbnailUtils::QueryThumbnailDataFromFileId(opts, opts.fileId, data, err);
    if (err != E_OK) {
        MEDIA_ERR_LOG("QueryThumbnailDataFromFileId failed, path: %{public}s",
            DfxUtils::GetSafePath(data.path).c_str());
        return err;
    }
    ValuesBucket values;
    Size lcdSize;
    if (data.mediaType == MEDIA_TYPE_VIDEO && ThumbnailUtils::GetLocalThumbSize(data, ThumbnailType::LCD, lcdSize)) {
        ThumbnailUtils::SetThumbnailSizeValue(values, lcdSize, PhotoColumn::PHOTO_LCD_SIZE);
        int changedRows;
        int32_t err = opts.store->Update(changedRows, opts.table, values, MEDIA_DATA_DB_ID + " = ?",
        vector<string> { data.id });
        if (err != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("RdbStore lcd size failed! %{public}d", err);
        }
    }

    data.loaderOpts.loadingStates = data.orientation != 0 ?
        SourceLoader::CLOUD_LCD_SOURCE_LOADING_STATES : SourceLoader::CLOUD_SOURCE_LOADING_STATES;
    if (isCloudInsertTaskPriorityHigh) {
        IThumbnailHelper::AddThumbnailGenerateTask(data.orientation != 0 ?
            IThumbnailHelper::CreateAstcEx : IThumbnailHelper::CreateAstc,
            opts, data, ThumbnailTaskType::FOREGROUND, ThumbnailTaskPriority::MID);
        return E_OK;
    }

    auto lowPriorityCreateAstcCloudDownloadTask = [](std::shared_ptr<ThumbnailTaskData> &data) {
        CHECK_AND_RETURN_LOG(data != nullptr, "Data is null");
        auto &thumbnailData = data->thumbnailData_;
        CHECK_AND_RETURN_LOG(ThumbnailUtils::CheckRemainSpaceMeetCondition(THUMBNAIL_FREE_SIZE_LIMIT_10),
            "LowPriorityCreateAstcCloudDownloadTask free size is not enough, id:%{public}s, path:%{public}s",
            thumbnailData.id.c_str(), DfxUtils::GetSafePath(thumbnailData.path).c_str());
        thumbnailData.orientation != 0 ? IThumbnailHelper::CreateAstcEx(data) : IThumbnailHelper::CreateAstc(data);
    };
    IThumbnailHelper::AddThumbnailGenerateTask(lowPriorityCreateAstcCloudDownloadTask,
        opts, data, ThumbnailTaskType::BACKGROUND, ThumbnailTaskPriority::LOW);
    return E_OK;
}

int32_t ThumbnailGenerateHelper::CreateLocalThumbnail(ThumbRdbOpt &opts)
{
    if (opts.store == nullptr) {
        MEDIA_ERR_LOG("rdbStore is not init");
        return E_ERR;
    }
    vector<ThumbnailData> infos;
    int32_t err = 0;
    if (!ThumbnailUtils::QueryLocalNoThumbnailInfos(opts, infos, err)) {
        MEDIA_ERR_LOG("Failed to QueryNoThumbnailInfos %{private}d", err);
        IThumbnailHelper::AddThumbnailGenerateTask(IThumbnailHelper::CloudSyncOnGenerationComplete,
            ThumbnailTaskType::BACKGROUND, ThumbnailTaskPriority::MID);
        return err;
    }
    if (infos.empty()) {
        IThumbnailHelper::AddThumbnailGenerateTask(IThumbnailHelper::CloudSyncOnGenerationComplete,
            ThumbnailTaskType::BACKGROUND, ThumbnailTaskPriority::MID);
        return E_OK;
    }
    std::shared_ptr<ExecuteParamBuilder> param = std::make_shared<ExecuteParamBuilder>();
    param->batteryLimit_ = LOCAL_GENERATION_BATTERY_CAPACITY;
    param->tempLimit_ = READY_TEMPERATURE_LEVEL;
    param->affinity_ = CpuAffinityType::CPU_IDX_6;
    MEDIA_INFO_LOG("CreateLocalThumbnail: %{public}d", static_cast<int>(infos.size()));
    for (uint32_t i = 0; i < infos.size(); i++) {
        opts.row = infos[i].id;
        infos[i].loaderOpts.loadingStates = SourceLoader::LOCAL_SOURCE_LOADING_STATES;
        if (infos[i].thumbnailReady == 0 && infos[i].lcdVisitTime == 0) {
            IThumbnailHelper::AddThumbnailGenerateTask(IThumbnailHelper::CreateLcdAndThumbnail,
                opts, infos[i], ThumbnailTaskType::BACKGROUND, ThumbnailTaskPriority::MID, param);
        } else if (infos[i].thumbnailReady == 0) {
            IThumbnailHelper::AddThumbnailGenerateTask(IThumbnailHelper::CreateThumbnail,
                opts, infos[i], ThumbnailTaskType::BACKGROUND, ThumbnailTaskPriority::MID, param);
        } else if (infos[i].lcdVisitTime == 0) {
            IThumbnailHelper::AddThumbnailGenerateTask(IThumbnailHelper::CreateLcd,
                opts, infos[i], ThumbnailTaskType::BACKGROUND, ThumbnailTaskPriority::MID, param);
        }
    }
    IThumbnailHelper::AddThumbnailGenerateTask(IThumbnailHelper::CloudSyncOnGenerationComplete,
        ThumbnailTaskType::BACKGROUND, ThumbnailTaskPriority::MID);
    return E_OK;
}

int32_t ThumbnailGenerateHelper::CreateAstcBatchOnDemand(
    ThumbRdbOpt &opts, NativeRdb::RdbPredicates &predicate, int32_t requestId)
{
    if (opts.store == nullptr) {
        MEDIA_ERR_LOG("rdbStore is not init");
        return E_ERR;
    }

    vector<ThumbnailData> infos;
    int32_t err = 0;
    if (!ThumbnailUtils::QueryNoAstcInfosOnDemand(opts, infos, predicate, err)) {
        MEDIA_ERR_LOG("Failed to QueryNoAstcInfos %{public}d", err);
        return err;
    }
    if (infos.empty()) {
        MEDIA_INFO_LOG("No need create Astc.");
        return E_THUMBNAIL_ASTC_ALL_EXIST;
    }

    MEDIA_INFO_LOG("no astc data size: %{public}d, requestId: %{public}d", static_cast<int>(infos.size()), requestId);
    for (auto& info : infos) {
        opts.row = info.id;
        ThumbnailUtils::RecordStartGenerateStats(info.stats, GenerateScene::FOREGROUND, LoadSourceType::LOCAL_PHOTO);
        if (info.isLocalFile) {
            info.loaderOpts.loadingStates = SourceLoader::LOCAL_SOURCE_LOADING_STATES;
            IThumbnailHelper::AddThumbnailGenBatchTask(IThumbnailHelper::CreateThumbnail, opts, info, requestId);
        } else {
            info.loaderOpts.loadingStates = info.mediaType == MEDIA_TYPE_VIDEO ?
                SourceLoader::ALL_SOURCE_LOADING_CLOUD_VIDEO_STATES : SourceLoader::ALL_SOURCE_LOADING_STATES;
            IThumbnailHelper::AddThumbnailGenBatchTask(info.orientation == 0 ?
                IThumbnailHelper::CreateAstc : IThumbnailHelper::CreateAstcEx, opts, info, requestId);
        }
    }
    return E_OK;
}

bool NeedGenerateLocalLcd(ThumbnailData &data)
{
    std::string lcdLocalPath = GetLocalThumbnailPath(data.path, THUMBNAIL_LCD_SUFFIX);
    size_t lcdSize = -1;

    // Local LCD exist, and its size is less than upload limit
    if (access(lcdLocalPath.c_str(), F_OK) == 0 && MediaFileUtils::GetFileSize(lcdLocalPath, lcdSize) &&
        lcdSize < LCD_UPLOAD_LIMIT_SIZE) {
        return false;
    }
    MEDIA_INFO_LOG("Local file Lcd need to be generate, size: %{public}d, path: %{public}s",
        static_cast<int>(lcdSize), DfxUtils::GetSafePath(data.path).c_str());
    return true;
}

int32_t ThumbnailGenerateHelper::CreateLcdBackground(ThumbRdbOpt &opts)
{
    if (opts.store == nullptr) {
        return E_ERR;
    }
    CHECK_AND_RETURN_RET_LOG(ThumbnailUtils::CheckRemainSpaceMeetCondition(THUMBNAIL_FREE_SIZE_LIMIT_10),
        E_FREE_SIZE_NOT_ENOUGH, "Free size is not enough");

    vector<ThumbnailData> infos;
    int32_t err = GetNoLcdData(opts, infos);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to GetNoLcdData %{private}d", err);
        return err;
    }
    if (infos.empty()) {
        MEDIA_DEBUG_LOG("No need create Lcd.");
        return E_THUMBNAIL_LCD_ALL_EXIST;
    }
    auto createLcdBackgroundTask = [](std::shared_ptr<ThumbnailTaskData> &data) {
        CHECK_AND_RETURN_LOG(data != nullptr, "CreateLcd failed, data is null");
        auto &thumbnailData = data->thumbnailData_;
        CHECK_AND_RETURN_LOG(ThumbnailUtils::CheckRemainSpaceMeetCondition(THUMBNAIL_FREE_SIZE_LIMIT_10),
            "CreateLcdBackgroundTask free size is not enough, id:%{public}s, path:%{public}s",
            thumbnailData.id.c_str(), DfxUtils::GetSafePath(thumbnailData.path).c_str());
        thumbnailData.loaderOpts.loadingStates = SourceLoader::LOCAL_SOURCE_LOADING_STATES;
        IThumbnailHelper::CreateLcd(data);
    };

    MEDIA_INFO_LOG("No lcd data size: %{public}d", static_cast<int>(infos.size()));
    for (uint32_t i = 0; i < infos.size(); i++) {
        opts.row = infos[i].id;

        // Check whether LCD exists or is over upload limit, if it does, just update the database
        if (!NeedGenerateLocalLcd(infos[i])) {
            MEDIA_INFO_LOG("Skip CreateLcdBackground, lcd exists: %{public}s",
                DfxUtils::GetSafePath(infos[i].path).c_str());
            ThumbnailUtils::UpdateLcdReadyStatus(opts, infos[i], err, LcdReady::GENERATE_LCD_COMPLETED);
            continue;
        }
        IThumbnailHelper::AddThumbnailGenerateTask(createLcdBackgroundTask,
            opts, infos[i], ThumbnailTaskType::BACKGROUND, ThumbnailTaskPriority::LOW);
    }
    return E_OK;
}

int32_t ThumbnailGenerateHelper::CheckLcdSizeAndUpdateStatus(ThumbRdbOpt &opts)
{
    if (opts.store == nullptr) {
        return E_ERR;
    }

    vector<ThumbnailData> infos;
    int32_t err = GetLocalNoLcdData(opts, infos);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to CheckLcdSizeAndUpdateStatus %{public}d", err);
        return err;
    }
    if (infos.empty()) {
        MEDIA_INFO_LOG("No need CheckLcdSizeAndUpdateStatus.");
        return E_THUMBNAIL_LCD_ALL_EXIST;
    }

    MEDIA_INFO_LOG("CheckLcdSizeAndUpdateStatus size: %{public}d", static_cast<int>(infos.size()));
    for (uint32_t i = 0; i < infos.size(); i++) {
        opts.row = infos[i].id;

        // Check whether LCD exists or is over upload limit, if it does, just update the database
        if (!NeedGenerateLocalLcd(infos[i])) {
            MEDIA_INFO_LOG("Check lcd size succeeded, lcd exists: %{public}s",
                DfxUtils::GetSafePath(infos[i].path).c_str());
            ThumbnailUtils::UpdateLcdReadyStatus(opts, infos[i], err, LcdReady::GENERATE_LCD_COMPLETED);
        }
    }
    return E_OK;
}

int32_t ThumbnailGenerateHelper::GetLcdCount(ThumbRdbOpt &opts, int &outLcdCount)
{
    int32_t err = E_ERR;
    if (!ThumbnailUtils::QueryLcdCount(opts, outLcdCount, err)) {
        MEDIA_ERR_LOG("Failed to QueryLcdCount %{private}d", err);
        return err;
    }
    return E_OK;
}

int32_t ThumbnailGenerateHelper::GetNoLcdData(ThumbRdbOpt &opts, vector<ThumbnailData> &outDatas)
{
    int32_t err = E_ERR;
    if (!ThumbnailUtils::QueryNoLcdInfos(opts, outDatas, err)) {
        MEDIA_ERR_LOG("Failed to QueryNoLcdInfos %{private}d", err);
        return err;
    }
    return E_OK;
}

int32_t ThumbnailGenerateHelper::GetLocalNoLcdData(ThumbRdbOpt &opts, vector<ThumbnailData> &outDatas)
{
    int32_t err = E_ERR;
    if (!ThumbnailUtils::QueryLocalNoLcdInfos(opts, outDatas, err)) {
        MEDIA_ERR_LOG("Failed to QueryLocalNoLcdInfos %{private}d", err);
        return err;
    }
    return E_OK;
}

int32_t ThumbnailGenerateHelper::GetNoThumbnailData(ThumbRdbOpt &opts, vector<ThumbnailData> &outDatas)
{
    int32_t err = E_ERR;
    if (!ThumbnailUtils::QueryNoThumbnailInfos(opts, outDatas, err)) {
        MEDIA_ERR_LOG("Failed to QueryNoThumbnailInfos %{private}d", err);
        return err;
    }
    return E_OK;
}

int32_t ThumbnailGenerateHelper::GetNoAstcData(ThumbRdbOpt &opts, vector<ThumbnailData> &outDatas)
{
    int32_t err = E_ERR;
    if (!ThumbnailUtils::QueryNoAstcInfos(opts, outDatas, err)) {
        MEDIA_ERR_LOG("Failed to QueryNoAstcInfos %{public}d", err);
        return err;
    }
    return E_OK;
}

int32_t ThumbnailGenerateHelper::GetNoHighlightData(ThumbRdbOpt &opts, vector<ThumbnailData> &outDatas)
{
    int32_t err = E_ERR;
    if (!ThumbnailUtils::QueryNoHighlightInfos(opts, outDatas, err)) {
        MEDIA_ERR_LOG("Failed to QueryNoHighlightInfos %{public}d", err);
        return err;
    }
    return E_OK;
}

int32_t ThumbnailGenerateHelper::GetNewThumbnailCount(ThumbRdbOpt &opts, const int64_t &time, int &count)
{
    int32_t err = E_ERR;
    if (!ThumbnailUtils::QueryNewThumbnailCount(opts, time, count, err)) {
        MEDIA_ERR_LOG("Failed to QueryNoThumbnailInfos %{private}d", err);
        return err;
    }
    return E_OK;
}

bool GenerateLocalThumbnail(ThumbRdbOpt &opts, ThumbnailData &data, ThumbnailType thumbType)
{
    data.loaderOpts.loadingStates = SourceLoader::LOCAL_SOURCE_LOADING_STATES;
    WaitStatus status;
    if (thumbType == ThumbnailType::LCD && !IThumbnailHelper::DoCreateLcd(opts, data, status)) {
        MEDIA_ERR_LOG("Get lcd thumbnail pixelmap, doCreateLcd failed: %{public}s",
            DfxUtils::GetSafePath(data.path).c_str());
        return false;
    }
    if (thumbType != ThumbnailType::LCD) {
        bool isSuccess = IThumbnailHelper::DoCreateThumbnail(opts, data, status);
        if (status == WaitStatus::INSERT) {
            IThumbnailHelper::UpdateThumbnailState(opts, data, isSuccess);
        }
        if (!isSuccess) {
            MEDIA_ERR_LOG("Get default thumbnail pixelmap, doCreateThumbnail failed: %{public}s",
                DfxUtils::GetSafePath(data.path).c_str());
            return false;
        }
    }
    return true;
}

bool GenerateKeyFrameLocalThumbnail(ThumbRdbOpt &opts, ThumbnailData &data, int32_t thumbType)
{
    data.loaderOpts.loadingStates = SourceLoader::LOCAL_SOURCE_LOADING_STATES;
    WaitStatus status;
    if (thumbType == KEY_FRAME_LCD && !IThumbnailHelper::DoCreateLcd(opts, data, status)) {
        MEDIA_ERR_LOG("Get key frame lcd thumbnail pixelmap, doCreateLcd failed: %{public}s",
            DfxUtils::GetSafePath(data.path).c_str());
        return false;
    }
    if (thumbType != KEY_FRAME_LCD) {
        bool isSuccess = IThumbnailHelper::DoCreateThumbnail(opts, data, status);
        if (!isSuccess) {
            MEDIA_ERR_LOG("Get default key frame thumbnail pixelmap, doCreateThumbnail failed: %{public}s",
                DfxUtils::GetSafePath(data.path).c_str());
            return false;
        }
    }
    return true;
}

int32_t ThumbnailGenerateHelper::GetAvailableFile(ThumbRdbOpt &opts, ThumbnailData &data, ThumbnailType thumbType,
    std::string &fileName)
{
    string thumbSuffix = GetThumbSuffix(thumbType);
    fileName = GetThumbnailPath(data.path, thumbSuffix);
    if (thumbType == ThumbnailType::THUMB_ASTC) {
        // Try to get jpeg thumbnail instead if there is no astc file
        if (access(fileName.c_str(), F_OK) == 0) {
            return E_OK;
        } else {
            fileName = GetThumbnailPath(data.path, GetThumbSuffix(ThumbnailType::THUMB));
        }
    }

    // No need to create thumbnails if corresponding file exists
    if (access(fileName.c_str(), F_OK) == 0) {
        MEDIA_INFO_LOG("File exists, path: %{public}s", DfxUtils::GetSafePath(fileName).c_str());
        return E_OK;
    }

    // Check if unrotated file exists
    string fileParentPath = MediaFileUtils::GetParentPath(fileName);
    string tempFileName = fileParentPath + "/THM_EX" + fileName.substr(fileParentPath.length());
    if (access(tempFileName.c_str(), F_OK) == 0) {
        fileName = tempFileName;
        data.isOpeningCloudFile = true;
        MEDIA_INFO_LOG("Unrotated file exists, path: %{public}s", DfxUtils::GetSafePath(fileName).c_str());
        return E_OK;
    }

    MEDIA_INFO_LOG("No available file, create thumbnail, path: %{public}s", DfxUtils::GetSafePath(fileName).c_str());
    if (!GenerateLocalThumbnail(opts, data, thumbType)) {
        MEDIA_ERR_LOG("GenerateLocalThumbnail failed, path: %{public}s", DfxUtils::GetSafePath(tempFileName).c_str());
        return E_THUMBNAIL_LOCAL_CREATE_FAIL;
    }
    if (!opts.path.empty()) {
        fileName = GetThumbnailPath(data.path, thumbSuffix);
    }
    return E_OK;
}

int32_t ThumbnailGenerateHelper::GetAvailableKeyFrameFile(ThumbRdbOpt &opts, ThumbnailData &data, int32_t thumbType,
    std::string &fileName)
{
    string thumbSuffix = GetKeyFrameThumbSuffix(thumbType);
    fileName = GetThumbnailPathHighlight(data.path, thumbSuffix, data.timeStamp);
    // No need to create keyFrame thumbnails if corresponding file exists
    if (access(fileName.c_str(), F_OK) == 0) {
        MEDIA_INFO_LOG("GetAvailableKeyFrameFile: file exists, path: %{public}s",
            DfxUtils::GetSafePath(fileName).c_str());
        return E_OK;
    }

    MEDIA_INFO_LOG("GetAvailableKeyFrameFile: no available file, create thumbnail, path: %{public}s",
        DfxUtils::GetSafePath(fileName).c_str());
    if (!GenerateKeyFrameLocalThumbnail(opts, data, thumbType)) {
        MEDIA_ERR_LOG("GenerateKeyFrameLocalThumbnail failed");
        return E_THUMBNAIL_LOCAL_CREATE_FAIL;
    }
    if (!opts.path.empty()) {
        fileName = GetThumbnailPathHighlight(data.path, thumbSuffix, data.timeStamp);
    }
    return E_OK;
}

bool IsLocalThumbnailAvailable(ThumbnailData &data, ThumbnailType thumbType)
{
    string tmpPath = "";
    switch (thumbType) {
        case ThumbnailType::THUMB:
        case ThumbnailType::THUMB_ASTC:
            tmpPath = GetLocalThumbnailPath(data.path, THUMBNAIL_THUMB_SUFFIX);
            break;
        case ThumbnailType::LCD:
            tmpPath =  GetLocalThumbnailPath(data.path, THUMBNAIL_LCD_SUFFIX);
            break;
        default:
            break;
    }
    return access(tmpPath.c_str(), F_OK) == 0;
}

bool IsLocalKeyFrameThumbnailAvailable(ThumbnailData &data, int32_t type)
{
    string tmpPath = "";
    switch (type) {
        case KEY_FRAME_THM:
        case KEY_FRAME_THM_ASTC:
            tmpPath = GetLocalKeyFrameThumbnailPath(data.path, THUMBNAIL_THUMB_SUFFIX, data.timeStamp);
            break;
        case KEY_FRAME_LCD:
            tmpPath = GetLocalKeyFrameThumbnailPath(data.path, THUMBNAIL_LCD_SUFFIX, data.timeStamp);
            break;
        default:
            break;
    }
    return access(tmpPath.c_str(), F_OK) == 0;
}

void UpdateStreamReadThumbDbStatus(ThumbRdbOpt& opts, ThumbnailData& data, ThumbnailType thumbType)
{
    ValuesBucket values;
    Size tmpSize;
    if (!ThumbnailUtils::GetLocalThumbSize(data, thumbType, tmpSize)) {
        return;
    }
    switch (thumbType) {
        case ThumbnailType::LCD:
            ThumbnailUtils::SetThumbnailSizeValue(values, tmpSize, PhotoColumn::PHOTO_LCD_SIZE);
            values.PutLong(PhotoColumn::PHOTO_LCD_VISIT_TIME, static_cast<int64_t>(LcdReady::GENERATE_LCD_COMPLETED));
            break;
        case ThumbnailType::THUMB:
        case ThumbnailType::THUMB_ASTC:
            ThumbnailUtils::SetThumbnailSizeValue(values, tmpSize, PhotoColumn::PHOTO_THUMB_SIZE);
            break;
        default:
            break;
    }
    int changedRows = 0;
    int32_t err = opts.store->Update(changedRows, opts.table, values, MEDIA_DATA_DB_ID + " = ?",
        vector<string> { data.id });
    if (err != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("UpdateStreamReadThumbDbStatus failed! %{public}d", err);
    }
}

void UpdateThumbStatus(ThumbRdbOpt &opts, ThumbnailType thumbType, ThumbnailData& thumbnailData, int& err,
    bool& isLocalThumbnailAvailable)
{
    if (!isLocalThumbnailAvailable) {
        UpdateStreamReadThumbDbStatus(opts, thumbnailData, thumbType);
    }
    if (thumbType == ThumbnailType::LCD && opts.table == PhotoColumn::PHOTOS_TABLE) {
        ThumbnailUtils::UpdateVisitTime(opts, thumbnailData, err);
    }
}

int32_t ThumbnailGenerateHelper::GetThumbnailPixelMap(ThumbRdbOpt &opts, ThumbnailType thumbType)
{
    ThumbnailWait thumbnailWait(false);
    thumbnailWait.CheckAndWait(opts.row, thumbType == ThumbnailType::LCD);
    ThumbnailData thumbnailData;
    ThumbnailUtils::GetThumbnailInfo(opts, thumbnailData);

    int err;
    ThumbnailUtils::QueryThumbnailDataFromFileId(opts, thumbnailData.id, thumbnailData, err);

    string fileName;
    err = GetAvailableFile(opts, thumbnailData, thumbType, fileName);
    if (err != E_OK) {
        MEDIA_ERR_LOG("GetAvailableFile failed, path: %{public}s", DfxUtils::GetSafePath(thumbnailData.path).c_str());
        return err;
    }
    bool isLocalThumbnailAvailable = IsLocalThumbnailAvailable(thumbnailData, thumbType);
    DfxTimer dfxTimer(thumbType == ThumbnailType::LCD ? DfxType::CLOUD_LCD_OPEN : DfxType::CLOUD_DEFAULT_OPEN,
        INVALID_DFX, thumbType == ThumbnailType::LCD ? CLOUD_LCD_TIME_OUT : CLOUD_DEFAULT_TIME_OUT, false);

    string absFilePath;
    if (!PathToRealPath(fileName, absFilePath)) {
        MEDIA_ERR_LOG("file is not real path, file path: %{public}s", DfxUtils::GetSafePath(fileName).c_str());
        return E_ERR;
    }

    auto fd = open(absFilePath.c_str(), O_RDONLY);
    dfxTimer.End();
    if (fd < 0) {
        DfxManager::GetInstance()->HandleThumbnailError(absFilePath,
            thumbType == ThumbnailType::LCD ? DfxType::CLOUD_LCD_OPEN : DfxType::CLOUD_DEFAULT_OPEN, -errno);
        return -errno;
    }
    if (thumbnailData.isOpeningCloudFile && thumbnailData.orientation != 0) {
        if (thumbnailData.mediaType == MEDIA_TYPE_VIDEO) {
            MEDIA_INFO_LOG("No need to rotate video file, path: %{public}s",
                DfxUtils::GetSafePath(thumbnailData.path).c_str());
            thumbnailData.orientation = 0;
        }
        IThumbnailHelper::DoRotateThumbnailEx(opts, thumbnailData, fd, thumbType);
        fileName = GetThumbnailPath(thumbnailData.path,
            thumbType == ThumbnailType::LCD ? THUMBNAIL_LCD_SUFFIX : THUMBNAIL_THUMB_SUFFIX);
        if (!PathToRealPath(fileName, absFilePath)) {
            MEDIA_ERR_LOG("file is not real path, file path: %{public}s", DfxUtils::GetSafePath(fileName).c_str());
            return E_ERR;
        }

        fd = open(absFilePath.c_str(), O_RDONLY);
        if (fd < 0) {
            MEDIA_ERR_LOG("Rotate thumb failed, path: %{public}s", DfxUtils::GetSafePath(thumbnailData.path).c_str());
            DfxManager::GetInstance()->HandleThumbnailError(absFilePath,
                thumbType == ThumbnailType::LCD ? DfxType::CLOUD_LCD_OPEN : DfxType::CLOUD_DEFAULT_OPEN, -errno);
            return -errno;
        }
    }
    UpdateThumbStatus(opts, thumbType, thumbnailData, err, isLocalThumbnailAvailable);
    return fd;
}

int32_t ThumbnailGenerateHelper::GetKeyFrameThumbnailPixelMap(ThumbRdbOpt &opts, int32_t &timeStamp, int32_t &type)
{
    ThumbnailWait thumbnailWait(false);
    thumbnailWait.CheckAndWait(opts.row, type == KEY_FRAME_LCD);
    vector<int> trackInfos;
    int32_t errTracks = E_ERR;
    if (!ThumbnailUtils::GetHighlightTracks(opts, trackInfos, errTracks)) {
        MEDIA_ERR_LOG("Failed to GetHighlightTracks %{public}d", errTracks);
        return errTracks;
    }
    if (find(trackInfos.begin(), trackInfos.end(), timeStamp) == trackInfos.end()) {
        timeStamp = 0;
        MEDIA_ERR_LOG("Not the frame of the highlight tracks, return the first frame");
    }

    ThumbnailData thumbnailData;
    thumbnailData.path = opts.path;
    thumbnailData.id = opts.row;
    thumbnailData.dateTaken = opts.dateTaken;
    thumbnailData.fileUri = opts.fileUri;
    thumbnailData.stats.uri = thumbnailData.fileUri;
    thumbnailData.timeStamp = std::to_string(timeStamp);
    thumbnailData.tracks = "tracks";

    string fileName;
    int err = GetAvailableKeyFrameFile(opts, thumbnailData, type, fileName);
    if (err != E_OK) {
        MEDIA_ERR_LOG("GetAvailableKeyFrameFile failed, path: %{public}s",
            DfxUtils::GetSafePath(thumbnailData.path).c_str());
        return err;
    }

    string absFilePath;
    if (!PathToRealPath(fileName, absFilePath)) {
        MEDIA_ERR_LOG("file is not real path, file path: %{public}s",
            DfxUtils::GetSafePath(fileName).c_str());
        return E_ERR;
    }

    auto fd = open(absFilePath.c_str(), O_RDONLY);
    if (fd < 0) {
        MEDIA_ERR_LOG("GetKeyFrameThumbnailPixelMap: open file failed path: %{public}s, errno:%{public}d",
            DfxUtils::GetSafePath(thumbnailData.path).c_str(), errno);
        return E_ERR;
    }
    return fd;
}

int32_t ThumbnailGenerateHelper::GenerateHighlightThumbnailBackground(ThumbRdbOpt &opts)
{
    if (opts.store == nullptr) {
        MEDIA_ERR_LOG("rdbStore is not init");
        return E_ERR;
    }

    vector<ThumbnailData> infos;
    int32_t err = GetNoHighlightData(opts, infos);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to GetNoHighlightData %{public}d", err);
        return err;
    }
    if (infos.empty()) {
        MEDIA_DEBUG_LOG("No need generate highlight thumbnail.");
        return E_OK;
    }

    for (uint32_t i = 0; i < infos.size(); i++) {
        opts.row = infos[i].id;
        infos[i].loaderOpts.loadingStates = SourceLoader::LOCAL_SOURCE_LOADING_STATES;
        IThumbnailHelper::AddThumbnailGenerateTask(IThumbnailHelper::CreateLcdAndThumbnail,
            opts, infos[i], ThumbnailTaskType::BACKGROUND, ThumbnailTaskPriority::LOW);
    }
    return E_OK;
}

int32_t ThumbnailGenerateHelper::TriggerHighlightThumbnail(ThumbRdbOpt &opts, std::string &id, std::string &tracks,
    std::string &trigger, std::string &genType)
{
    ThumbnailData data;
    data.id = id;
    data.tracks = tracks;
    data.trigger = trigger;

    int32_t err = E_ERR;
    if (!ThumbnailUtils::QueryHighlightTriggerPath(opts, data, err)) {
        MEDIA_ERR_LOG("Failed to QueryHighlightTriggerPath %{public}d", err);
        return err;
    }
    if (genType == MEDIA_DATA_DB_UPDATE_TYPE && ThumbnailUtils::DeleteBeginTimestampDir(data)) {
        MEDIA_INFO_LOG("Delete beginTimeStampDir success");
    }
    opts.row = data.id;
    data.loaderOpts.loadingStates = SourceLoader::LOCAL_SOURCE_LOADING_STATES;
    IThumbnailHelper::AddThumbnailGenerateTask(IThumbnailHelper::CreateLcdAndThumbnail,
        opts, data, ThumbnailTaskType::BACKGROUND, ThumbnailTaskPriority::LOW);
    return E_OK;
}

int32_t ThumbnailGenerateHelper::UpgradeThumbnailBackground(ThumbRdbOpt &opts, bool isWifiConnected)
{
    if (opts.store == nullptr) {
        MEDIA_ERR_LOG("rdbStore is not init");
        return E_ERR;
    }
    CHECK_AND_RETURN_RET_LOG(ThumbnailUtils::CheckRemainSpaceMeetCondition(THUMBNAIL_FREE_SIZE_LIMIT_10),
        E_FREE_SIZE_NOT_ENOUGH, "Free size is not enough");

    vector<ThumbnailData> infos;
    int32_t err = GetThumbnailDataNeedUpgrade(opts, infos, isWifiConnected);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to GetThumbnailDataNeedUpgrade %{public}d", err);
        return err;
    }
    if (infos.empty()) {
        MEDIA_DEBUG_LOG("No need upgrade thumbnail.");
        return E_OK;
    }
    MEDIA_INFO_LOG("Will upgrade %{public}zu photo thumbnails, wifi: %{public}d.", infos.size(), isWifiConnected);
    for (uint32_t i = 0; i < infos.size(); i++) {
        opts.row = infos[i].id;
        ThumbnailUtils::RecordStartGenerateStats(infos[i].stats, GenerateScene::UPGRADE, LoadSourceType::LOCAL_PHOTO);
        infos[i].loaderOpts.loadingStates = (infos[i].mediaType == MEDIA_TYPE_VIDEO) ?
            SourceLoader::UPGRADE_VIDEO_SOURCE_LOADING_STATES : SourceLoader::UPGRADE_SOURCE_LOADING_STATES;
        IThumbnailHelper::AddThumbnailGenerateTask(IThumbnailHelper::CreateLcdAndThumbnail,
            opts, infos[i], ThumbnailTaskType::BACKGROUND, ThumbnailTaskPriority::LOW);
    }
    return E_OK;
}

int32_t ThumbnailGenerateHelper::RestoreAstcDualFrame(ThumbRdbOpt &opts, const int32_t &restoreAstcCount)
{
    CHECK_AND_RETURN_RET_LOG(restoreAstcCount > 0, E_ERR, "RestoreAstcCount:%{public}d is invalid", restoreAstcCount);
    CHECK_AND_RETURN_RET_LOG(opts.store != nullptr, E_ERR, "RdbStore is not init");
    vector<ThumbnailData> infos;
    int32_t err = 0;
    if (!ThumbnailUtils::QueryNoAstcInfosRestored(opts, infos, err, restoreAstcCount)) {
        MEDIA_ERR_LOG("Failed to QueryNoAstcInfosRestored %{public}d", err);
        return err;
    }
    if (infos.empty()) {
        MEDIA_INFO_LOG("No photos need resotre astc.");
        return E_OK;
    }

    MEDIA_INFO_LOG("create astc for restored dual frame photos count:%{public}zu, restoreAstcCount:%{public}d",
        infos.size(), restoreAstcCount);

    for (auto &info : infos) {
        opts.row = info.id;
        info.loaderOpts.loadingStates = SourceLoader::LOCAL_SOURCE_LOADING_STATES;
        ThumbnailUtils::RecordStartGenerateStats(info.stats, GenerateScene::RESTORE, LoadSourceType::LOCAL_PHOTO);
        IThumbnailHelper::AddThumbnailGenerateTask(IThumbnailHelper::CreateThumbnail, opts, info,
            ThumbnailTaskType::FOREGROUND, ThumbnailTaskPriority::MID);
    }

    MEDIA_INFO_LOG("create astc for restored dual frame photos finished");
    return E_OK;
}

int32_t ThumbnailGenerateHelper::GetThumbnailDataNeedUpgrade(ThumbRdbOpt &opts, std::vector<ThumbnailData> &outDatas,
    bool isWifiConnected)
{
    int32_t err = E_ERR;
    if (!ThumbnailUtils::QueryUpgradeThumbnailInfos(opts, outDatas, isWifiConnected, err)) {
        MEDIA_ERR_LOG("Failed to QueryUpgradeThumbnailInfos %{public}d", err);
        return err;
    }
    return E_OK;
}

void ThumbnailGenerateHelper::CheckMonthAndYearKvStoreValid(ThumbRdbOpt &opts)
{
    bool isMonthKvStoreValid = MediaLibraryKvStoreManager::GetInstance().IsKvStoreValid(KvStoreValueType::MONTH_ASTC);
    bool isYearKvStoreValid = MediaLibraryKvStoreManager::GetInstance().IsKvStoreValid(KvStoreValueType::YEAR_ASTC);
    if (isMonthKvStoreValid && isYearKvStoreValid) {
        return;
    }

    if (opts.store == nullptr) {
        MEDIA_ERR_LOG("rdbStore is not init");
        return;
    }

    MEDIA_INFO_LOG("KvStore is invalid, start update rdb");
    if (opts.store->ExecuteSql(SQL_REFRESH_THUMBNAIL_READY) != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Update rdb failed");
        return;
    }
    MEDIA_INFO_LOG("Update rdb successfully");

    if (!isMonthKvStoreValid) {
        MediaLibraryKvStoreManager::GetInstance().RebuildInvalidKvStore(KvStoreValueType::MONTH_ASTC);
    }

    if (!isYearKvStoreValid) {
        MediaLibraryKvStoreManager::GetInstance().RebuildInvalidKvStore(KvStoreValueType::YEAR_ASTC);
    }

    Acl::AclSetDatabase();
    MEDIA_INFO_LOG("RebuildInvalidKvStore finish, isMonthKvStoreValid: %{public}d, isYearKvStoreValid: %{public}d",
        isMonthKvStoreValid, isYearKvStoreValid);
}
} // namespace Media
} // namespace OHOS
