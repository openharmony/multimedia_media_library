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

#include "cloud_enhancement_ani.h"
#include "file_asset_ani.h"
#include "fetch_result_ani.h"
#include "media_album_change_request_ani.h"
#include "media_asset_change_request_ani.h"
#include "media_assets_change_request_ani.h"
#include "media_library_ani.h"
#include "medialibrary_ani_log.h"
#include "moving_photo_ani.h"
#include "photo_album_ani.h"
#include "photo_proxy_ani.h"

using namespace OHOS::Media;

namespace OHOS::Media::Ani {
ani_status GlobalFunctionInit(ani_env *env)
{
    const char *namespaceName = "L@ohos/file/photoAccessHelper/photoAccessHelper;";
    ani_namespace ns;
    if (ANI_OK != env->FindNamespace(namespaceName, &ns)) {
        ANI_ERR_LOG("Not found namespace: %{public}s", namespaceName);
        return ANI_ERROR;
    }

    std::array staticMethods = {
        ani_native_function {"getPhotoAccessHelper", nullptr, reinterpret_cast<void *>(MediaLibraryAni::Constructor)},
    };

    if (ANI_OK != env->Namespace_BindNativeFunctions(ns, staticMethods.data(), staticMethods.size())) {
        ANI_ERR_LOG("Cannot bind native methods to namespace: %{public}s", namespaceName);
        return ANI_ERROR;
    };

    ANI_INFO_LOG("GlobalFunctionInit ok");
    return ANI_OK;
}
} // namespace OHOS::Media::Ani

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    ANI_INFO_LOG("ANI_Constructor start");
    ani_env *env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        ANI_ERR_LOG("Unsupported %{public}d", ANI_VERSION_1);
        return ANI_ERROR;
    }

    CHECK_STATUS_RET(OHOS::Media::Ani::GlobalFunctionInit(env), "GlobalFunctionInit fail");
    CHECK_STATUS_RET(MediaLibraryAni::PhotoAccessHelperInit(env), "PhotoAccessHelperInit fail");
    CHECK_STATUS_RET(PhotoAlbumAni::PhotoAccessInit(env), "PhotoAccessInit fail");
    CHECK_STATUS_RET(FileAssetAni::FileAssetAniInit(env), "FileAssetAniInit fail");
    CHECK_STATUS_RET(FetchFileResultAni::FetchFileResultInit(env), "FetchFileResultInit fail");
    CHECK_STATUS_RET(MovingPhotoAni::MovingPhotoInit(env), "MovingPhotoInit fail");

    *result = ANI_VERSION_1;
    return ANI_OK;
}