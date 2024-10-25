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

#ifndef FRAMEWORKS_SERVICES_MEDIA_CLOUD_ENHANCEMENT_INCLUDE_ENHANCEMENT_SERVICE_CALLBACK_H
#define FRAMEWORKS_SERVICES_MEDIA_CLOUD_ENHANCEMENT_INCLUDE_ENHANCEMENT_SERVICE_CALLBACK_H

#include <memory>
#include <string>

#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
#include "media_enhance_client.h"
#include "media_enhance_bundle.h"
#include "media_enhance_constants.h"
#include "cloud_enhancement_dfx_get_count.h"
#endif

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
struct CloudEnhancementFileInfo {
    int32_t fileId;
    std::string filePath;
    std::string displayName;
    int32_t subtype;
    int32_t hidden;
    CloudEnhancementFileInfo() : fileId(0), filePath(""), displayName(""),
        subtype(0), hidden(0) {}
    CloudEnhancementFileInfo(int32_t fileId, std::string filePath, std::string displayName,
        int32_t subtype, int32_t hidden) : fileId(fileId), filePath(filePath),
        displayName(displayName), subtype(subtype), hidden(hidden) {}
};

#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
class EnhancementServiceCallback : public MediaEnhance::MediaEnhanceResultCallback {
public:
    EXPORT EnhancementServiceCallback();
    EXPORT ~EnhancementServiceCallback();

    void OnSuccess(std::string taskId, MediaEnhance::MediaEnhanceBundle& bundle) override;
    void OnFailed(std::string taskId, MediaEnhance::MediaEnhanceBundle& bundle) override;
    void OnServiceReconnected() override;

private:
    EXPORT int32_t SaveCloudEnhancementPhoto(std::shared_ptr<CloudEnhancementFileInfo> info,
        const MediaEnhance::RawData &rawData);
    EXPORT int32_t CreateCloudEnhancementPhoto(int32_t sourceFileId,
        std::shared_ptr<CloudEnhancementFileInfo> info);
};
#endif
} // namespace Media
} // namespace OHOS
#endif  // FRAMEWORKS_SERVICES_MEDIA_CLOUD_ENHANCEMENT_INCLUDE_ENHANCEMENT_SERVICE_CALLBACK_H