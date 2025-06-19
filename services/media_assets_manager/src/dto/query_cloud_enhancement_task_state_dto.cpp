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

#define MLOG_TAG "MediaQueryCloudEnhancementTaskStateDto"

#include "query_cloud_enhancement_task_state_dto.h"

#include <sstream>

namespace OHOS::Media {
using namespace std;
std::string QueryCloudEnhancementTaskStateDto::ToString() const
{
    std::stringstream ss;
    ss << "{"
       << "\"photoUri\": \"" << photoUri << "\","
       << "\"fileId\": \"" << to_string(fileId) << "\","
       << "\"photoId\": \"" << photoId << "\","
       << "\"ceAvailable\": \"" << to_string(ceAvailable) << "\","
       << "\"ceErrorCode\": \"" << to_string(ceErrorCode)
       << "}";
    return ss.str();
}
} // namespace OHOS::Media