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

#ifndef FRAMEWORKS_SERVICES_MEDIA_CLOUD_ENHANCEMENT_INCLUDE_ENHANCEMENT_SERVICE_ADAPTER_H
#define FRAMEWORKS_SERVICES_MEDIA_CLOUD_ENHANCEMENT_INCLUDE_ENHANCEMENT_SERVICE_ADAPTER_H

#include <string>
#include <map>
#include <memory>

#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
#include "media_enhance_client.h"
#include "media_enhance_bundle.h"
#include "media_enhance_constants.h"
#include "cloud_enhancement_dfx_get_count.h"
#endif

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))

#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
class EnhancementServiceAdapter : public RefBase {
#else
class EnhancementServiceAdapter {
#endif
public:
    EXPORT EnhancementServiceAdapter();
    EXPORT virtual ~EnhancementServiceAdapter();

#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
    EXPORT int32_t AddTask(const std::string &taskId, MediaEnhance::MediaEnhanceBundle &enhanceBundle);
    EXPORT int32_t RemoveTask(const std::string &taskId);
    EXPORT int32_t CancelTask(const std::string &taskId);
    EXPORT int32_t CancelAllTasks();
    EXPORT int32_t LoadEnhancementService();
    EXPORT int32_t GetPendingTasks(std::vector<std::string> &taskIdList);
#endif
    
private:
#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
    std::shared_ptr<MediaEnhance::MediaEnhanceClient> enhancementClient_;
#endif
};
} // namespace Media
} // namespace OHOS
#endif  // FRAMEWORKS_SERVICES_MEDIA_CLOUD_ENHANCEMENT_INCLUDE_ENHANCEMENT_SERVICE_ADAPTER_H