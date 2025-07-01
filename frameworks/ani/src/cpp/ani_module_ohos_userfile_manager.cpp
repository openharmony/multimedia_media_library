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

#include "media_library_ani.h"

using namespace OHOS::Media;

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    CHECK_COND_RET(vm != nullptr, ANI_ERROR, "vm is nullptr");
    ani_env *env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        ANI_ERR_LOG("Unsupported %{public}d", ANI_VERSION_1);
        return ANI_ERROR;
    }
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");

    static const char *staticNsName = "@ohos.filemanagement.userFileManager.userFileManager";
    ani_namespace staticNs;
    if (ANI_OK != env->FindNamespace(staticNsName, &staticNs)) {
        ANI_ERR_LOG("Not found %{public}s", staticNsName);
        return ANI_ERROR;
    }

    std::array staticMethods = {
        ani_native_function {"getUserFileMgr", nullptr,
            reinterpret_cast<void *>(MediaLibraryAni::GetUserFileMgr)},
    };

    if (ANI_OK != env->Namespace_BindNativeFunctions(staticNs, staticMethods.data(), staticMethods.size())) {
        ANI_ERR_LOG("Cannot bind native methods to %{public}s", staticNsName);
        return ANI_ERROR;
    }

    CHECK_STATUS_RET(MediaLibraryAni::UserFileMgrInit(env), "MediaLibraryAni::UserFileMgrInit fail");
    CHECK_STATUS_RET(FetchFileResultAni::UserFileMgrInit(env), "FetchFileResultAni::UserFileMgrInit fail");
    CHECK_STATUS_RET(FileAssetAni::UserFileMgrInit(env), "FileAssetAni::UserFileMgrInit fail");

    *result = ANI_VERSION_1;
    return ANI_OK;
}
