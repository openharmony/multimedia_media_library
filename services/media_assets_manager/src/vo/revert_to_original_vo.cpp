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
 
#define MLOG_TAG "MediaRevertToOriginalVo"
 
#include "revert_to_original_vo.h"
 
#include <sstream>
 
#include "media_log.h"
 
namespace OHOS::Media {
using namespace std;
bool RevertToOriginalReqBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = parcel.ReadInt32(this->fileId);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.ReadString(this->fileUri);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}
 
bool RevertToOriginalReqBody::Marshalling(MessageParcel &parcel) const
{
    bool status = parcel.WriteInt32(this->fileId);
    CHECK_AND_RETURN_RET(status, status);
    status = parcel.WriteString(this->fileUri);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}
 
string RevertToOriginalReqBody::ToString() const
{
    std::stringstream ss;
    ss << "{"
        << "\"fileId\": \"" << std::to_string(this->fileId) << "\", "
        << "\"title\": " << this->fileUri
        << "}";
    return ss.str();
}
} // namespace OHOS::Media