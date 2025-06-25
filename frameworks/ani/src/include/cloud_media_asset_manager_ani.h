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

#ifndef INTERFACES_KITS__MEDIALIBRARY_INCLUDE_CLOUD_MEDIA_ASSET_MANAGER_ANI_H
#define INTERFACES_KITS__MEDIALIBRARY_INCLUDE_CLOUD_MEDIA_ASSET_MANAGER_ANI_H

#include <string>
#include "ani_error.h"
#include "cloud_media_asset_types.h"
#include "datashare_helper.h"

namespace OHOS {
namespace Media {

class CloudMediaAssetManagerAni {
public:
    static ani_status Init(ani_env *env);
    static bool InitUserFileClient(ani_env *env, ani_object aniObject);
private:
    static ani_object Constructor(ani_env *env, ani_class clazz, ani_object context);
    static ani_object StartDownloadCloudMedia(ani_env *env, ani_object aniObject, ani_enum_item downloadType);
    static ani_object PauseDownloadCloudMedia(ani_env *env, ani_object aniObject);
    static ani_object CancelDownloadCloudMedia(ani_env *env, ani_object aniObject);
    static ani_object RetainCloudMediaAsset(ani_env *env, ani_object aniObject, ani_enum_item retainType);
    static ani_object GetCloudMediaAssetStatus(ani_env *env, ani_object aniObject);
};

struct CloudMediaAssetAsyncAniContext : public AniError {
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    int32_t cloudMediaDownloadType;
    int32_t cloudMediaRetainType;
    CloudMediaAssetTaskStatus cloudMediaAssetTaskStatus_;
    CloudMediaTaskPauseCause cloudMediaTaskPauseCause_;
    std::string taskInfo_;
};
} // namespace Media
} // namespace OHOS
#endif // INTERFACES_KITS__MEDIALIBRARY_INCLUDE_CLOUD_MEDIA_ASSET_MANAGER_NAPI_H