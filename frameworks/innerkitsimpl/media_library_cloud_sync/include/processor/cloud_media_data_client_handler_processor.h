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

#ifndef OHOS_MEDIA_CLOUD_MEDIA_DATA_CLIENT_HANDLER_PROCESSOR_H
#define OHOS_MEDIA_CLOUD_MEDIA_DATA_CLIENT_HANDLER_PROCESSOR_H

#include <string>
#include <vector>

#include "cloud_meta_data.h"
#include "photos_vo.h"
#include "medialibrary_errno.h"

namespace OHOS::Media::CloudSync {
class CloudMediaDataClientHandlerProcessor {
public:
    std::vector<CloudMetaData> GetCloudNewData(const std::vector<PhotosVo> &newDatas);
    std::vector<CloudMetaData> GetCloudFdirtyData(const std::vector<PhotosVo> &fdirtyDatas);

public:
    template <class T>
    int32_t SplitVector(const std::vector<T> &input, size_t maxSize, std::vector<std::vector<T>> &result)
    {
        maxSize = maxSize > 0 ? maxSize : 1;
        size_t numSubVectors = (input.size() + maxSize - 1) / maxSize;
        for (size_t i = 0; i < numSubVectors; ++i) {
            size_t start = i * maxSize;
            size_t end = std::min(start + maxSize, input.size());
            std::vector<T> subVector(input.begin() + start, input.begin() + end);
            result.emplace_back(subVector);
        }
        return E_OK;
    }
};
}  // namespace OHOS::Media::CloudSync
#endif  // OHOS_MEDIA_CLOUD_MEDIA_DATA_CLIENT_HANDLER_PROCESSOR_H