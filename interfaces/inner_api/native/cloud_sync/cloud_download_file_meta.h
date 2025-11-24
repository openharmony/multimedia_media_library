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

#ifndef OHOS_MEDIA_CLOUD_SYNC_CLOUD_DL_FILE_META_H
#define OHOS_MEDIA_CLOUD_SYNC_CLOUD_DL_FILE_META_H

#include "cloud_meta_data.h"

namespace OHOS::Media::CloudSync {
#define EXPORT __attribute__ ((visibility ("default")))

class EXPORT CloudDlFileMeta : public CloudMetaData {
public:
    int32_t hidden {0};      // 判断湖内外
    int64_t dateTrashed {0}; // 判断湖内外

public:
    virtual ~CloudDlFileMeta() = default;

    std::string ToString() const override
    {
        std::stringstream ss;
        std::string baseStr = CloudMetaData::ToString();
        if (!baseStr.empty() && baseStr.back() == '}') {
            baseStr.pop_back();
        }

        ss << baseStr
           << ",\"hidden\": " << hidden
           << ",\"dateTrashed\": " << dateTrashed
           << "}";

        return ss.str();
    }
};
} // namespace OHOS::Media::CloudSync

#endif // OHOS_MEDIA_CLOUD_SYNC_CLOUD_DL_FILE_META_H