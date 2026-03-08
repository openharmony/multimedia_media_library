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

#define MLOG_TAG "Media_Cloud_Vo"

#include "get_download_asset_vo.h"

#include <sstream>

#include "media_itypes_utils.h"
#include "media_log.h"

namespace OHOS::Media::CloudSync {
bool GetDownloadAssetReqBody::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET_LOG(
        IPC::ITypeMediaUtil::Unmarshalling<std::string>(this->pathList, parcel), false, "pathList");
    CHECK_AND_RETURN_RET_LOG(
        IPC::ITypeMediaUtil::Unmarshalling<std::string>(this->fileKeyList, parcel), false, "fileKeyList");
    return true;
}

bool GetDownloadAssetReqBody::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET_LOG(IPC::ITypeMediaUtil::Marshalling<std::string>(this->pathList, parcel), false, "pathList");
    CHECK_AND_RETURN_RET_LOG(
        IPC::ITypeMediaUtil::Marshalling<std::string>(this->fileKeyList, parcel), false, "fileKeyList");
    return true;
}

std::string GetDownloadAssetReqBody::ToString() const
{
    std::stringstream ss;
    return ss.str();
}

bool GetDownloadAssetRespBody::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET_LOG(PhotosVo::Unmarshalling(this->photos, parcel), false, "photos");
    return true;
}

bool GetDownloadAssetRespBody::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET_LOG(PhotosVo::Marshalling(this->photos, parcel), false, "photos");
    return true;
}

std::string GetDownloadAssetRespBody::ToString() const
{
    std::stringstream ss;
    return ss.str();
}
}  // namespace OHOS::Media::CloudSync