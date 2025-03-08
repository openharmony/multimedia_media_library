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
#include "medialibrary_ani_log.h"
#include "moving_photo_ani.h"
#include "photo_access_helper_ani.h"
#include "photo_album_ani.h"
#include "photo_proxy_ani.h"

using namespace OHOS::Media;

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    ani_env *env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        ANI_ERR_LOG("Unsupported %{public}d", ANI_VERSION_1);
        return ANI_ERROR;
    }

    static const char *staticClassName = "L@ohos/file/photoAccessHelper/photoAccessHelper;";
    ani_class staticCls;
    if (ANI_OK != env->FindClass(staticClassName, &staticCls)) {
        ANI_ERR_LOG("Not found %{public}s", staticClassName);
        return ANI_ERROR;
    }

    std::array staticMethods = {
        ani_native_function {"getPhotoAccessHelper", nullptr,
            reinterpret_cast<void *>(PhotoAccessHelperAni::Constructor)},
    };

    if (ANI_OK != env->Class_BindNativeMethods(staticCls, staticMethods.data(), staticMethods.size())) {
        ANI_ERR_LOG("Cannot bind native methods to %{public}s", staticClassName);
        return ANI_ERROR;
    };

    CHECK_STATUS_RET(PhotoAccessHelperAni::PhotoAccessHelperInit(env), "PhotoAccessHelperInit fail");
    CHECK_STATUS_RET(PhotoAlbumAni::PhotoAccessInit(env), "PhotoAccessInit fail");
    CHECK_STATUS_RET(FileAssetAni::FileAssetAniInit(env), "FileAssetAniInit fail");
    CHECK_STATUS_RET(FetchFileResultAni::FetchFileResultInit(env), "FetchFileResultInit fail");
    CHECK_STATUS_RET(MovingPhotoAni::MovingPhotoInit(env), "MovingPhotoInit fail");

    *result = ANI_VERSION_1;
    return ANI_OK;
}