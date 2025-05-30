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

#ifndef OHOS_MEDIA_CLOUD_SYNC_MEDIA_OPERATE_RESULT_H
#define OHOS_MEDIA_CLOUD_SYNC_MEDIA_OPERATE_RESULT_H

#include <string>
#include <sstream>

namespace OHOS::Media::CloudSync {
#define EXPORT __attribute__ ((visibility ("default")))
class EXPORT MediaOperateResult {
public:
    std::string cloudId;
    int32_t errorCode;
    std::string errorMsg;

public:  // basic function
    std::string ToString() const
    {
        std::stringstream ss;
        ss << "{\"cloudId\": \"" << cloudId << "\", \"errorCode\": " << errorCode << "\", \"errorMsg\": \"" << errorMsg
           << "\"}";
        return ss.str();
    }
};
}  // namespace OHOS::Media::CloudSync
#endif  // OHOS_MEDIA_CLOUD_SYNC_MEDIA_OPERATE_RESULT_H