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

#ifndef INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_CLOUD_MEDIA_ASSET_STATUS_ANI_H
#define INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_CLOUD_MEDIA_ASSET_STATUS_ANI_H

#include <ani.h>
#include <memory>
#include <string>

#include "cloud_media_asset_types.h"
#include "cloud_media_asset_manager_ani.h"

namespace OHOS {
namespace Media {
class CloudMediaAssetStatusAni {
public:
    CloudMediaAssetStatusAni() = default;
    ~CloudMediaAssetStatusAni() = default;
    static ani_object NewCloudMediaAssetStatusAni(
        ani_env *env, std::unique_ptr<CloudMediaAssetAsyncAniContext> &context);
    static ani_status Init(ani_env *env);

private:
    static ani_object Constructor(ani_env *env, ani_class cls,
        std::unique_ptr<CloudMediaAssetStatusAni> &nativeHandle);

    static CloudMediaAssetStatusAni* Unwrap(ani_env *env, ani_object aniObject);

    static ani_double CloudMediaAssetGetTaskStatus(ani_env *env, ani_object object);
    static ani_double CloudMediaAssetGetErrorCode(ani_env *env, ani_object object);
    static ani_string CloudMediaAssetGetTaskInfo(ani_env *env, ani_object object);

    CloudMediaAssetTaskStatus GetCloudMediaAssetTaskStatus() const;
    void SetCloudMediaAssetTaskStatus(CloudMediaAssetTaskStatus cloudMediaAssetTaskStatus);

    CloudMediaTaskPauseCause GetCloudMediaTaskPauseCause() const;
    void SetCloudMediaTaskPauseCause(CloudMediaTaskPauseCause cloudMediaTaskPauseCause);

    std::string GetTaskInfo() const;
    void SetTaskInfo(const std::string &taskInfo);

    static thread_local ani_ref constructor_;
    CloudMediaAssetTaskStatus cloudMediaAssetTaskStatus_ = CloudMediaAssetTaskStatus::IDLE;
    CloudMediaTaskPauseCause cloudMediaTaskPauseCause_ = CloudMediaTaskPauseCause::NO_PAUSE;
    std::string taskInfo_ = "";
    static const int32_t UNDEFINED = -1;
    static constexpr ani_string UNDEFINED_STR = nullptr;
};
} // namespace Media
} // namespace OHOS
#endif // INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_CLOUD_MEDIA_ASSET_STATUS_ANI_H