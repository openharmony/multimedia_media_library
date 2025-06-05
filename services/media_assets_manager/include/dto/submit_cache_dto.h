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

#ifndef OHOS_MEDIA_ASSETS_MANAGER_SUBMIT_CACHE_DTO_H
#define OHOS_MEDIA_ASSETS_MANAGER_SUBMIT_CACHE_DTO_H

#include "submit_cache_vo.h"

namespace OHOS::Media {
class SubmitCacheDto {
public:
    bool isWriteGpsAdvanced;
    NativeRdb::ValuesBucket values;

    int32_t fileId{-1};
    std::string outUri;

public:
    static SubmitCacheDto Create(const SubmitCacheReqBody &req);
    SubmitCacheRspBody CreateRspBody();
};
}  // namespace OHOS::Media
#endif  // OHOS_MEDIA_ASSETS_MANAGER_SUBMIT_CACHE_DTO_H