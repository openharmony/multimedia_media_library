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

#include <fcntl.h>

#include "medialibrary_errno.h"
#include "media_log.h"
#include "thumbnail_const.h"
#include "thumbnail_utils.h"
#include "thumbnail_utils.h"

#include "lcd_thumbnail_helper.h"

using namespace std;
using namespace OHOS::DistributedKv;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
int32_t LcdThumbnailHelper::CreateThumbnail(ThumbRdbOpt &opts, bool isSync)
{
    ThumbnailData thumbnailData;
    if (IsPureCloudImage(opts)) {
        MEDIA_ERR_LOG("Lcd IsPureCloudImage fileId : %{pulic}s is pure cloud image", opts.row.c_str());
        return E_OK;
    }
    GetThumbnailInfo(opts, thumbnailData);

    string fileName = GetThumbnailPath(thumbnailData.path, THUMBNAIL_LCD_SUFFIX);
    if (access(fileName.c_str(), F_OK) == 0) {
        MEDIA_DEBUG_LOG("CreateThumbnail key is same, no need generate");
        return E_OK;
    }

    if (isSync) {
        DoCreateLcd(opts, thumbnailData, false);
    } else {
        IThumbnailHelper::AddAsyncTask(IThumbnailHelper::CreateLcd, opts, thumbnailData, true);
    }
    return E_OK;
}

int32_t LcdThumbnailHelper::GetThumbnailPixelMap(ThumbRdbOpt &opts, const Size &size, bool isAstc)
{
    int err;
    ThumbnailWait thumbnailWait(false);
    thumbnailWait.CheckAndWait(opts.row, true);
    ThumbnailData thumbnailData;
    GetThumbnailInfo(opts, thumbnailData);

    string fileName = GetThumbnailPath(thumbnailData.path, THUMBNAIL_LCD_SUFFIX);
    if (access(fileName.c_str(), F_OK) != 0) {
        MEDIA_ERR_LOG("get lcd thumbnail pixelmap, doCreateThumbnail %{public}s", fileName.c_str());
        if (!DoCreateLcd(opts, thumbnailData)) {
            return E_THUMBNAIL_LOCAL_CREATE_FAIL;
        }
        if (!opts.path.empty()) {
            fileName = GetThumbnailPath(thumbnailData.path, THUMBNAIL_LCD_SUFFIX);
        }
    }
    auto fd = open(fileName.c_str(), O_RDONLY);
    if (fd >= 0) {
        if (opts.table == PhotoColumn::PHOTOS_TABLE) {
            ThumbnailUtils::UpdateVisitTime(opts, thumbnailData, err);
        }
        return fd;
    }
    return -errno;
}
} // namespace Media
} // namespace OHOS
