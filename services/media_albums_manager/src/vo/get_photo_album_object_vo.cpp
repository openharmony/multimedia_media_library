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
 
#define MLOG_TAG "GetPhotoAlbumObjectVo"
 
#include "get_photo_album_object_vo.h"
 
#include <sstream>

#include "media_itypes_utils.h"
#include "media_log.h"
 
namespace OHOS::Media {
using namespace std;

bool GetPhotoAlbumObjectReqBody::Unmarshalling(MessageParcel &parcel)
{
    if (!DataShare::DataSharePredicates::Unmarshal(this->predicates, parcel)) {
        MEDIA_ERR_LOG("GetPhotoAlbumObjectReqBody unmarshal predicates failed");
        return false;
    }
    if (!IPC::ITypeMediaUtil::Unmarshalling(this->columns, parcel)) {
        MEDIA_ERR_LOG("GetPhotoAlbumObjectReqBody unmarshal columns failed");
        return false;
    }
    return true;
}
 
bool GetPhotoAlbumObjectReqBody::Marshalling(MessageParcel &parcel) const
{
    if (!DataShare::DataSharePredicates::Marshal(this->predicates, parcel)) {
        MEDIA_ERR_LOG("GetPhotoAlbumObjectReqBody marshal predicates failed");
        return false;
    }
    if (!IPC::ITypeMediaUtil::Marshalling(this->columns, parcel)) {
        MEDIA_ERR_LOG("GetPhotoAlbumObjectReqBody marshal columns failed");
        return false;
    }
    return true;
}

bool GetPhotoAlbumObjectRespBody::Unmarshalling(MessageParcel &parcel)
{
    this->resultSet = DataShare::DataShareResultSet::Unmarshal(parcel);
    if (this->resultSet == nullptr) {
        MEDIA_ERR_LOG("GetPhotoAlbumObjectRespBody ReadFromParcel failed");
        return false;
    }
    return true;
}
 
bool GetPhotoAlbumObjectRespBody::Marshalling(MessageParcel &parcel) const
{
    if (this->resultSet == nullptr || !DataShare::DataShareResultSet::Marshal(this->resultSet, parcel)) {
        MEDIA_ERR_LOG("GetPhotoAlbumObjectRespBody Marshalling failed");
        return false;
    }
    return true;
}
} // namespace OHOS::Media