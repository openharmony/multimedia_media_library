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

#include "photo_album_vo.h"

#include <sstream>

#include "media_itypes_utils.h"
#include "media_log.h"

namespace OHOS::Media::CloudSync {
bool PhotoAlbumVo::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET_LOG(parcel.ReadInt32(this->albumId), false, "albumId");
    CHECK_AND_RETURN_RET_LOG(parcel.ReadInt32(this->albumType), false, "albumType");
    CHECK_AND_RETURN_RET_LOG(parcel.ReadInt32(this->albumSubType), false, "albumSubType");
    CHECK_AND_RETURN_RET_LOG(parcel.ReadString(this->albumName), false, "albumName");
    CHECK_AND_RETURN_RET_LOG(parcel.ReadString(this->lPath), false, "lPath");
    CHECK_AND_RETURN_RET_LOG(parcel.ReadString(this->bundleName), false, "bundleName");
    CHECK_AND_RETURN_RET_LOG(parcel.ReadInt32(this->priority), false, "priority");
    return true;
}

bool PhotoAlbumVo::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInt32(this->albumId), false, "albumId");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInt32(this->albumType), false, "albumType");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInt32(this->albumSubType), false, "albumSubType");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(this->albumName), false, "albumName");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(this->lPath), false, "lPath");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteString(this->bundleName), false, "bundleName");
    CHECK_AND_RETURN_RET_LOG(parcel.WriteInt32(this->priority), false, "priority");
    return true;
}

std::string PhotoAlbumVo::ToString() const
{
    std::stringstream ss;
    ss << "{"
       << "\"albumId\": " << this->albumId << ", "
       << "\"albumType\": " << this->albumType << ", "
       << "\"albumSubType\": " << this->albumSubType << ", "
       << "\"lPath\": \"" << this->lPath << "\", "
       << "\"bundleName\": \"" << this->bundleName << "\", "
       << "\"priority\": " << this->priority << ""
       << "}";
    return ss.str();
}
}  // namespace OHOS::Media::CloudSync