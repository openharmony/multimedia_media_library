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

#define MLOG_TAG "MEDIA_CLOUD_DTO"

#include "check_file_data_dto.h"

#include <sstream>

namespace OHOS::Media::CloudSync {
std::string CheckFileDataDto::FileData::ToString() const
{
    std::stringstream ss;
    ss << "{"
       << "\"recordId\": \"" << this->recordId << "\", "
       << "\"isDelete\": " << this->isDelete << ", "
       << "\"version\": " << this->version << "\""
       << "}";
    return ss.str();
}

std::string CheckFileDataDto::ToString() const
{
    std::stringstream ss;
    ss << "{"
       << "\"fileDataList\": [";
    for (size_t i = 0; i < this->fileDataList.size(); i++) {
        ss << this->fileDataList[i].ToString();
        if (i != this->fileDataList.size() - 1) {
            ss << ", ";
        }
    }
    ss << "]"
       << "}";
    return ss.str();
}
}  // namespace OHOS::Media::CloudSync