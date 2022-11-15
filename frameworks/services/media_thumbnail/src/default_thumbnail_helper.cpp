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

#include "default_thumbnail_helper.h"
#include "medialibrary_errno.h"
#include "media_log.h"
#include "thumbnail_const.h"
#include "thumbnail_utils.h"

using namespace std;
using namespace OHOS::DistributedKv;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
int32_t DefaultThumbnailHelper::CreateThumbnail(ThumbRdbOpt &opts, bool isSync)
{
    int err = E_ERR;
    ThumbnailData thumbnailData;
    shared_ptr<AbsSharedResultSet> rdbSet = QueryThumbnailInfo(opts, thumbnailData, err);
    if (rdbSet == nullptr) {
        MEDIA_ERR_LOG("QueryThumbnailInfo Faild [ %{public}d ]", err);
        return err;
    }

    if (!thumbnailData.thumbnailKey.empty()) {
        ThumbnailData tmpData = thumbnailData;
        ThumbnailUtils::GenThumbnailKey(tmpData);
        if (tmpData.thumbnailKey == thumbnailData.thumbnailKey) {
            MEDIA_DEBUG_LOG("CreateThumbnail key is same, no need generate");
            return E_OK;
        }
    }
    if (isSync) {
        DoCreateThumbnail(opts, thumbnailData, true);
    } else {
        IThumbnailHelper::AddAsyncTask(IThumbnailHelper::CreateThumbnail, opts, thumbnailData, true);
    }
    return E_OK;
}

int32_t DefaultThumbnailHelper::GetThumbnailPixelMap(ThumbRdbOpt &opts,
    shared_ptr<DataShare::ResultSetBridge> &outResultSet)
{
    int err = E_ERR;
    ThumbnailWait thumbnailWait(false);
    thumbnailWait.CheckAndWait(opts.row, false);
    ThumbnailData thumbnailData;
    shared_ptr<AbsSharedResultSet> rdbSet = QueryThumbnailInfo(opts, thumbnailData, err);
    if (rdbSet == nullptr) {
        MEDIA_ERR_LOG("QueryThumbnailInfo Faild [ %{public}d ]", err);
        return err;
    }

    if (thumbnailData.thumbnailKey.empty()) {
        if (!opts.networkId.empty()) {
            auto remoteQuery = ThumbnailUtils::QueryRemoteThumbnail(opts, thumbnailData, err);
            if ((!remoteQuery || thumbnailData.thumbnailKey.empty()) &&
                !IThumbnailHelper::DoThumbnailSync(opts, thumbnailData)) {
                return E_THUMBNAIL_REMOTE_CREATE_FAIL;
            }
        } else if (!DoCreateThumbnail(opts, thumbnailData)) {
            MEDIA_ERR_LOG("DoCreateThumbnail Faild");
            return E_THUMBNAIL_LOCAL_CREATE_FAIL;
        }
    }

    if (!ThumbnailUtils::IsImageExist(thumbnailData.thumbnailKey, opts.networkId, opts.kvStore)) {
        MEDIA_ERR_LOG("image not exist in kvStore, key [%{public}s]", thumbnailData.thumbnailKey.c_str());
        if (!DoCreateThumbnail(opts, thumbnailData, true)) {
            return E_ERR;
        }
    }

    if (!ThumbnailUtils::GetKvResultSet(opts.kvStore, thumbnailData.thumbnailKey, opts.networkId, outResultSet)) {
        MEDIA_ERR_LOG("GetKvResultSet Faild");
        return E_ERR;
    }

    thumbnailData.lcdKey.clear();
    ThumbnailUtils::DoUpdateRemoteThumbnail(opts, thumbnailData, err);
    return E_OK;
}
} // namespace Media
} // namespace OHOS
