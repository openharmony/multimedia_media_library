/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "get_photo_index_vo.h"

#include <sstream>
#include <string>
#include <vector>

#include "datashare_predicates.h"
#include "message_parcel.h"
#include "media_log.h"

namespace OHOS::Media {
bool GetPhotoIndexReqBody::Unmarshalling(MessageParcel &parcel)
{
    if (!DataShare::DataSharePredicates::Unmarshal(this->predicates, parcel)) {
        return false;
    }
    bool status = parcel.ReadBool(this->isAnalysisAlbum);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadString(this->photoId);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadString(this->albumId);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool GetPhotoIndexReqBody::Marshalling(MessageParcel &parcel) const
{
    if (!DataShare::DataSharePredicates::Marshal(this->predicates, parcel)) {
        return false;
    }
    bool status = parcel.WriteBool(this->isAnalysisAlbum);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteString(this->photoId);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteString(this->albumId);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}
}  // namespace OHOS::Media