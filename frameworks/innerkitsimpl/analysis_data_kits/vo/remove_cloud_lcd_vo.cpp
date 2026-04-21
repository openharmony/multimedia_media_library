/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <sstream>

#include "remove_cloud_lcd_vo.h"
#include "media_log.h"
#include "media_itypes_utils.h"

namespace OHOS::Media {
bool RemoveCloudLcdReqBody::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET_LOG(IPC::ITypeMediaUtil::Marshalling(fileIds, parcel), false, "Failed to write fileIds");
    return true;
}

bool RemoveCloudLcdReqBody::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET_LOG(IPC::ITypeMediaUtil::Unmarshalling(fileIds, parcel), false, "Failed to read fileIds");
    return true;
}

std::string RemoveCloudLcdReqBody::ToString() const
{
    std::stringstream ss;
    ss << "RemoveCloudLcdReqBody{fileIds.size()=" << fileIds.size() << "}";
    return ss.str();
}
}  // namespace OHOS::Media