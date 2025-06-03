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

#ifndef OHOS_MEDIA_CLOUD_SYNC_CHECK_FILE_DATA_DTO_H
#define OHOS_MEDIA_CLOUD_SYNC_CHECK_FILE_DATA_DTO_H

#include <string>
#include <vector>
#include <sstream>
#include "cloud_media_define.h"

namespace OHOS::Media::CloudSync {
class EXPORT CheckFileDataDto {
public:
    class FileData {
    public:
        std::string recordId;  // 云端文件的唯一标识符
        bool isDelete;         // 文件是否被删除
        std::string version;   // 文件的版本号

    public:  // basic functions
        std::string ToString() const;
    };

public:
    std::vector<FileData> fileDataList;

public:  // basic functions
    std::string ToString() const;
};
}  // namespace OHOS::Media::CloudSync
#endif  // OHOS_MEDIA_CLOUD_SYNC_CHECK_FILE_DATA_DTO_H