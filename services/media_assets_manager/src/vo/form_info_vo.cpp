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
 
#define MLOG_TAG "MediaFormInfoVo"
 
#include "form_info_vo.h"
 
#include <sstream>
 
#include "itypes_util.h"
#include "media_log.h"
 
namespace OHOS::Media {
using namespace std;
bool FormInfoReqBody::Unmarshalling(MessageParcel &parcel)
{
    bool status = ITypesUtil::Unmarshalling(this->formIds, parcel);
    CHECK_AND_RETURN_RET(status, status);
    status = ITypesUtil::Unmarshalling(this->fileUris, parcel);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}
 
bool FormInfoReqBody::Marshalling(MessageParcel &parcel) const
{
    bool status = ITypesUtil::Marshalling<std::string>(this->formIds, parcel);
    CHECK_AND_RETURN_RET(status, status);
    status = ITypesUtil::Marshalling<std::string>(this->fileUris, parcel);
    CHECK_AND_RETURN_RET(status, status);
    return true;
}
 
string FormInfoReqBody::ToString() const
{
    std::stringstream ss;
    ss << "{";
    ss << "[";
    for (uint32_t i = 0; i < formIds.size(); i++) {
        ss << formIds[i];
        if (i != formIds.size() - 1) {
            ss << ",";
        }
    }
    ss << "], ";
    ss << "[";
    for (uint32_t i = 0; i < fileUris.size(); i++) {
        ss << fileUris[i];
        if (i != fileUris.size() - 1) {
            ss << ",";
        }
    }
    ss << "]"
        << "}";
    return ss.str();
}
} // namespace OHOS::Media