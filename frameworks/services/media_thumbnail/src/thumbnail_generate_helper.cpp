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

#include "ithumbnail_helper.h"
#include "medialibrary_errno.h"
#include "media_log.h"
#include "thumbnail_const.h"

using namespace std;
using namespace OHOS::DistributedKv;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
int32_t ThumbnailGenerateHelper::CreateThumbnailBatch(ThumbRdbOpt &opts)
{
    if (opts.store == nullptr) {
        MEDIA_ERR_LOG("rdbStore is not init");
        return E_ERR;
    }

    vector<ThumbnailRdbData> infos;
    int32_t err = GetNoThumbnailData(opts, infos);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to GetNoLcdData %{private}d", err);
        return err;
    }

    if (infos.empty()) {
        MEDIA_INFO_LOG("No need generate thumbnail.");
        return E_OK;
    }
    ThumbnailData data;
    for (uint32_t i = 0; i < infos.size(); i++) {
        opts.row = infos[i].id;
        ThumbnailUtils::ThumbnailDataCopy(data, infos[i]);
        IThumbnailHelper::AddAsyncTask(IThumbnailHelper::CreateThumbnail, opts, data, false);
    }

    return E_OK;
}

int32_t ThumbnailGenerateHelper::CreateLcdBatch(ThumbRdbOpt &opts)
{
    if (opts.store == nullptr) {
        MEDIA_ERR_LOG("rdbStore is not init");
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

    vector<ThumbnailRdbData> infos;
    err = GetNoLcdData(opts, THUMBNAIL_LCD_GENERATE_THRESHOLD - lcdCount, infos);
    if ((err != E_OK) || infos.empty()) {
        MEDIA_ERR_LOG("Failed to GetNoLcdData %{private}d", err);
        return err;
    }
    ThumbnailData data;
    for (uint32_t i = 0; i < infos.size(); i++) {
        opts.row = infos[i].id;
        ThumbnailUtils::ThumbnailDataCopy(data, infos[i]);
        IThumbnailHelper::AddAsyncTask(IThumbnailHelper::CreateLcd, opts, data, false);
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

int32_t ThumbnailGenerateHelper::GetNoLcdData(ThumbRdbOpt &opts, int lcdLimit, vector<ThumbnailRdbData> &outDatas)
{
    int32_t err = E_ERR;
    if (!ThumbnailUtils::QueryNoLcdInfos(opts, lcdLimit, outDatas, err)) {
        MEDIA_ERR_LOG("Failed to QueryNoLcdInfos %{private}d", err);
        return err;
    }
    return E_OK;
}

int32_t ThumbnailGenerateHelper::GetNoThumbnailData(ThumbRdbOpt &opts, vector<ThumbnailRdbData> &outDatas)
{
    int32_t err = E_ERR;
    if (!ThumbnailUtils::QueryNoThumbnailInfos(opts, outDatas, err)) {
        MEDIA_ERR_LOG("Failed to QueryNoThumbnailInfos %{private}d", err);
        return err;
    }
    return E_OK;
}
} // namespace Media
} // namespace OHOS
