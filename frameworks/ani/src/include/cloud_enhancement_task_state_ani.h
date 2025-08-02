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

#ifndef FRAMEWORKS_ANI_SRC_INCLUDE_CLOUD_ENHANCEMENT_TASK_STATE_ANI_H
#define FRAMEWORKS_ANI_SRC_INCLUDE_CLOUD_ENHANCEMENT_TASK_STATE_ANI_H

#include <ani.h>
#include <memory>
#include "cloud_enhancement_ani.h"

namespace OHOS {
namespace Media {

class CloudEnhancementTaskStateAni {
public:
    CloudEnhancementTaskStateAni() = default;
    ~CloudEnhancementTaskStateAni() = default;
    static ani_object NewCloudEnhancementTaskStateAni(ani_env *env, unique_ptr<CloudEnhancementAniContext> &context);
    static ani_status Init(ani_env *env);

private:
    static ani_object Constructor(ani_env *env, ani_class cls,
        std::unique_ptr<CloudEnhancementTaskStateAni> &nativeHandle);
    static ani_status BindAniAttributes(ani_env *env, ani_class cls, ani_object object,
        unique_ptr<CloudEnhancementTaskStateAni> &nativeHandle);
    static CloudEnhancementTaskStateAni* Unwrap(ani_env *env, ani_object object);

    CloudEnhancementTaskStage GetCloudEnhancementTaskStage() const;
    void SetCloudEnhancementTaskStage(CloudEnhancementTaskStage cloudEnhancementTaskStage);

    static ani_int GetTransferredFileSize(ani_env *env, ani_object object);
    void SetTransferredFileSize(int32_t transferredFileSize);

    static ani_int GetTotalFileSize(ani_env *env, ani_object object);
    void SetTotalFileSize(int32_t totalFileSize);

    static ani_int GetExpectedDuration(ani_env *env, ani_object object);
    void SetExpectedDuration(int32_t expectedDuration);

    static ani_int GetStatusCode(ani_env *env, ani_object object);
    void SetStatusCode(int32_t statusCode);

    CloudEnhancementTaskStage cloudEnhancementTaskStage_ = CloudEnhancementTaskStage::TASK_STAGE_EXCEPTION;
    static const int32_t UNDEFINED = -1;
    int32_t transferredFileSize_ {UNDEFINED};
    int32_t totalFileSize_ {UNDEFINED};
    int32_t expectedDuration_ {UNDEFINED};
    int32_t statusCode_ {UNDEFINED};
};

} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_ANI_SRC_INCLUDE_CLOUD_ENHANCEMENT_TASK_STATE_ANI_H