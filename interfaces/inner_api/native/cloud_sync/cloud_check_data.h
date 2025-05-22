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

#ifndef OHOS_MEDIA_CLOUD_SYNC_CLOUD_CHECK_DATA_H
#define OHOS_MEDIA_CLOUD_SYNC_CLOUD_CHECK_DATA_H

#include <string>
#include <sstream>

#include "cloud_meta_data.h"

namespace OHOS::Media::CloudSync {
#define EXPORT __attribute__ ((visibility ("default")))
class EXPORT CloudCheckData : public CloudMetaData {
public:
    int64_t version;    // 本地记录云端版本
    int32_t position;   // 本地数据库记录文件位置
    int32_t thmStatus;  // 本地数据库记录缩略图下载状态
    int32_t syncStatus;
    int32_t dirtyType;

public:  // constructor & destructor
    virtual ~CloudCheckData() = default;

public:  // basic function
    virtual std::string ToString() const override
    {
        std::stringstream ss;
        ss << "{\"cloudId\": \"" << cloudId << "\", \"size\": " << size << ", \"path\": \"" << path << "\""
           << ", \"fileName\": \"" << fileName << "\", \"type\": " << type << ", \"modifiedTime\": " << modifiedTime
           << ",\"originalCloudId\": \"" << originalCloudId << "\",";
        ss << "\"version\": " << version << ", \"position\": " << position << ", \"thmStatus\": " << thmStatus
           << ", \"modifiedTime\": " << modifiedTime << ", \"dirtyType\": " << dirtyType << ", \"attachment\": {";
        bool first = true;
        for (const auto &item : attachment) {
            if (first) {
                first = false;
            } else {
                ss << ",";
            }
            ss << "\"" << item.first << "\":" << item.second.ToString();
            first = false;
        }
        ss << "}}";
        return ss.str();
    }
};
}  // namespace OHOS::Media::CloudSync
#endif  // OHOS_MEDIA_CLOUD_SYNC_CLOUD_CHECK_DATA_H