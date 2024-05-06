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

#include "dfx_const.h"
#include "dfx_manager.h"
#include "dfx_timer.h"
#include "dfx_utils.h"
#include "ithumbnail_helper.h"
#include "medialibrary_errno.h"
#include "medialibrary_kvstore_manager.h"
#include "medialibrary_photo_operations.h"
#include "medialibrary_type_const.h"
#include "media_log.h"
#include "thumbnail_const.h"
#include "thumbnail_generate_worker_manager.h"

using namespace std;
using namespace OHOS::DistributedKv;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
int32_t ThumbnailGenerateHelper::CreateThumbnails(ThumbRdbOpt &opts, bool isSync)
{
    ThumbnailData thumbnailData;
    ThumbnailUtils::GetThumbnailInfo(opts, thumbnailData);
    thumbnailData.needResizeLcd = true;
    ThumbnailUtils::RecordStartGenerateStats(thumbnailData.stats, GenerateScene::LOCAL, LoadSourceType::LOCAL_PHOTO);
    if (isSync) {
        IThumbnailHelper::DoCreateThumbnails(opts, thumbnailData);
        ThumbnailUtils::RecordCostTimeAndReport(thumbnailData.stats);
        if (opts.path.find(ROOT_MEDIA_DIR + PHOTO_BUCKET) != string::npos) {
            MediaLibraryPhotoOperations::StoreThumbnailSize(opts.row, opts.path);
        }
    } else {
        IThumbnailHelper::AddThumbnailGenerateTask(IThumbnailHelper::CreateThumbnails,
            opts, thumbnailData, ThumbnailTaskType::FOREGROUND, ThumbnailTaskPriority::HIGH);
    }
    return E_OK;
}

int32_t ThumbnailGenerateHelper::CreateThumbnailBatch(ThumbRdbOpt &opts)
{
    if (opts.store == nullptr) {
        MEDIA_ERR_LOG("rdbStore is not init");
        return E_ERR;
    }

    vector<ThumbnailData> infos;
    int32_t err = GetNoThumbnailData(opts, infos);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to GetNoLcdData %{private}d", err);
        return err;
    }

    if (infos.empty()) {
        MEDIA_INFO_LOG("No need generate thumbnail.");
        return E_OK;
    }

    for (uint32_t i = 0; i < infos.size(); i++) {
        opts.row = infos[i].id;
        IThumbnailHelper::AddThumbnailGenerateTask(IThumbnailHelper::CreateThumbnail,
            opts, infos[i], ThumbnailTaskType::BACKGROUND, ThumbnailTaskPriority::LOW);
    }

    return E_OK;
}

int32_t ThumbnailGenerateHelper::CreateAstcBatch(ThumbRdbOpt &opts)
{
    if (opts.store == nullptr) {
        MEDIA_ERR_LOG("rdbStore is not init");
        return E_ERR;
    }

    vector<ThumbnailData> infos;
    int32_t err = GetNoAstcData(opts, infos);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to GetNoAstcData %{private}d", err);
        return err;
    }

    auto kvStore = MediaLibraryKvStoreManager::GetInstance()
        .GetKvStore(KvStoreRoleType::OWNER, KvStoreValueType::MONTH_ASTC);
    if (infos.empty() || kvStore == nullptr) {
        MEDIA_INFO_LOG("No need create Astc.");
        return E_OK;
    }

    MEDIA_INFO_LOG("no astc data size: %{public}d", static_cast<int>(infos.size()));
    for (uint32_t i = 0; i < infos.size(); i++) {
        opts.row = infos[i].id;
        ThumbnailUtils::RecordStartGenerateStats(infos[i].stats, GenerateScene::BACKGROUND,
            LoadSourceType::LOCAL_PHOTO);
        IThumbnailHelper::AddThumbnailGenerateTask(IThumbnailHelper::CreateAstc,
            opts, infos[i], ThumbnailTaskType::BACKGROUND, ThumbnailTaskPriority::LOW);
    }
    return E_OK;
}

int32_t ThumbnailGenerateHelper::CreateLcdBatch(ThumbRdbOpt &opts)
{
    if (opts.store == nullptr) {
        return E_ERR;
    }

    int lcdCount = 0;
    int32_t err = GetLcdCount(opts, lcdCount);
    if (err != E_OK) {
        MEDIA_ERR_LOG("GetLcdCount err %{private}d , lcdCount %{private}d", err, lcdCount);
        return err;
    }

    if (lcdCount >= THUMBNAIL_LCD_GENERATE_THRESHOLD) {
        MEDIA_INFO_LOG("Not need generate Lcd. lcdCount: %{lcdCount}d", lcdCount);
        return E_OK;
    }

    vector<ThumbnailData> infos;
    err = GetNoLcdData(opts, THUMBNAIL_LCD_GENERATE_THRESHOLD - lcdCount, infos);
    if ((err != E_OK) || infos.empty()) {
        MEDIA_ERR_LOG("Failed to GetNoLcdData %{private}d", err);
        return err;
    }

    for (uint32_t i = 0; i < infos.size(); i++) {
        opts.row = infos[i].id;
        IThumbnailHelper::AddThumbnailGenerateTask(IThumbnailHelper::CreateLcd,
            opts, infos[i], ThumbnailTaskType::BACKGROUND, ThumbnailTaskPriority::LOW);
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

int32_t ThumbnailGenerateHelper::GetNoLcdData(ThumbRdbOpt &opts, int lcdLimit, vector<ThumbnailData> &outDatas)
{
    int32_t err = E_ERR;
    if (!ThumbnailUtils::QueryNoLcdInfos(opts, lcdLimit, outDatas, err)) {
        MEDIA_ERR_LOG("Failed to QueryNoLcdInfos %{private}d", err);
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

int32_t ThumbnailGenerateHelper::GetNewThumbnailCount(ThumbRdbOpt &opts, const int64_t &time, int &count)
{
    int32_t err = E_ERR;
    if (!ThumbnailUtils::QueryNewThumbnailCount(opts, time, count, err)) {
        MEDIA_ERR_LOG("Failed to QueryNoThumbnailInfos %{private}d", err);
        return err;
    }
    return E_OK;
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
        return E_OK;
    }

    MEDIA_INFO_LOG("No available file, create thumbnail, path: %{public}s", fileName.c_str());
    if (thumbType == ThumbnailType::LCD && !IThumbnailHelper::DoCreateLcd(opts, data)) {
        MEDIA_ERR_LOG("Get lcd thumbnail pixelmap, doCreateLcd failed: %{public}s", fileName.c_str());
        return E_THUMBNAIL_LOCAL_CREATE_FAIL;
    } else if (!IThumbnailHelper::DoCreateThumbnail(opts, data)) {
        MEDIA_ERR_LOG("Get default thumbnail pixelmap, doCreateThumbnail failed: %{public}s", fileName.c_str());
        return E_THUMBNAIL_LOCAL_CREATE_FAIL;
    }
    if (!opts.path.empty()) {
        fileName = GetThumbnailPath(data.path, thumbSuffix);
    }
    return E_OK;
}

int32_t ThumbnailGenerateHelper::GetThumbnailPixelMap(ThumbRdbOpt &opts, ThumbnailType thumbType)
{
    ThumbnailWait thumbnailWait(false);
    thumbnailWait.CheckAndWait(opts.row, thumbType == ThumbnailType::LCD);
    ThumbnailData thumbnailData;
    ThumbnailUtils::GetThumbnailInfo(opts, thumbnailData);

    string fileName;
    int err = GetAvailableFile(opts, thumbnailData, thumbType, fileName);
    if (err != E_OK) {
        MEDIA_ERR_LOG("GetAvailableFile failed, path: %{public}s", DfxUtils::GetSafePath(thumbnailData.path).c_str());
        return err;
    }

    DfxTimer dfxTimer(thumbType == ThumbnailType::LCD ? DfxType::CLOUD_LCD_OPEN : DfxType::CLOUD_DEFAULT_OPEN,
        INVALID_DFX, thumbType == ThumbnailType::LCD ? CLOUD_LCD_TIME_OUT : CLOUD_DEFAULT_TIME_OUT, false);
    auto fd = open(fileName.c_str(), O_RDONLY);
    dfxTimer.End();
    if (fd < 0) {
        DfxManager::GetInstance()->HandleThumbnailError(fileName,
            thumbType == ThumbnailType::LCD ? DfxType::CLOUD_LCD_OPEN : DfxType::CLOUD_DEFAULT_OPEN, -errno);
        return -errno;
    }
    if (thumbType == ThumbnailType::LCD && opts.table == PhotoColumn::PHOTOS_TABLE) {
        ThumbnailUtils::UpdateVisitTime(opts, thumbnailData, err);
    }
    return fd;
}
} // namespace Media
} // namespace OHOS
