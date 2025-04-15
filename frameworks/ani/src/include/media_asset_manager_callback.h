/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef MEDIA_ASSET_MANAGER_CALLBACK_H
#define MEDIA_ASSET_MANAGER_CALLBACK_H

#include "transcoder.h"

namespace OHOS {
namespace Media {
class MediaAssetManagerCallback : public TransCoderCallback {
public:
    MediaAssetManagerCallback() = default;
    ~MediaAssetManagerCallback() = default;
    void SetRequestId(std::string requestId);
protected:
    void OnError(int32_t errCode, const std::string &errorMsg) override;
    void OnInfo(int32_t type, int32_t extra) override;
    std::string requestId_;
};
} // namespace Media
} // namespace OHOS
#endif // MEDIA_ASSET_MANAGER_CALLBACK_H
