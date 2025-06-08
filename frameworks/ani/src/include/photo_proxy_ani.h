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

#ifndef FRAMEWORKS_ANI_SRC_INCLUDE_PHOTO_PROXY_ANI_H
#define FRAMEWORKS_ANI_SRC_INCLUDE_PHOTO_PROXY_ANI_H

#include <ani.h>
#include "photo_proxy.h"

namespace OHOS {
namespace Media {
class PhotoProxyAni {
public:
    PhotoProxyAni();
    ~PhotoProxyAni();

    static ani_status PhotoProxyAniInit(ani_env *env);

    sptr<PhotoProxy> photoProxy_;
    static thread_local sptr<PhotoProxy> sPhotoProxy_;
private:
    static ani_object PhotoProxyAniConstructor(ani_env *env, [[maybe_unused]] ani_class clazz);
    static void PhotoProxyAniDestructor(ani_env *env, void *nativeObject, void *finalize_hint);

    ani_env *env_;
    ani_ref wrapper_;
};
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_ANI_SRC_INCLUDE_PHOTO_PROXY_ANI_H