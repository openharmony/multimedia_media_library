/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_CLOUD_SYNC_CLOUD_FILE_DATA_H
#define OHOS_MEDIA_CLOUD_SYNC_CLOUD_FILE_DATA_H

#include <string>
#include <sstream>

namespace OHOS::Media::CloudSync {
#define EXPORT __attribute__ ((visibility ("default")))
class EXPORT CloudFileData {
public:
    std::string fileName;  // 附件名称
    std::string filePath;  // 附件路径
    int64_t size;          // 附件大小

public:
    std::string ToString() const
    {
        std::stringstream ss;
        ss << "{\"fileName\": \"" << fileName << "\", \"filePath\": \"" << filePath << "\", \"size\": " << size << "}";
        return ss.str();
    }
};
}  // namespace OHOS::Media::CloudSync
#endif  // OHOS_MEDIA_CLOUD_SYNC_CLOUD_FILE_DATA_H