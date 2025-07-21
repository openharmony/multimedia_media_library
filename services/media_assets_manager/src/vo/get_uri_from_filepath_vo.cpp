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

#include "get_uri_from_filepath_vo.h"

#include <sstream>
#include "media_log.h"
#include "itypes_util.h"

namespace OHOS::Media {

bool GetUriFromFilePathReqBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadString(this->tempPath);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool GetUriFromFilePathReqBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteString(this->tempPath);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}

bool GetUriFromFilePathRespBody::Unmarshalling(MessageParcel &parcel)
{
    this->resultSet = DataShare::DataShareResultSet::Unmarshal(parcel);
    bool cond = this->resultSet == nullptr;
    CHECK_AND_RETURN_RET_LOG(!cond, false, "ReadFromParcel failed");
    MEDIA_INFO_LOG("GetUriFromFilePathRespBody ReadFromParcel success");
    return true;
}

bool GetUriFromFilePathRespBody::Marshalling(MessageParcel &parcel) const
{
    bool cond = this->resultSet == nullptr || !DataShare::DataShareResultSet::Marshal(this->resultSet, parcel);
    CHECK_AND_RETURN_RET_LOG(!cond, false, "Marshalling failed");
    MEDIA_INFO_LOG("Marshalling success");
    return true;
}
};