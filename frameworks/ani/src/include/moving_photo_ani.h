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

#ifndef FRAMEWORKS_ANI_SRC_INCLUDE_MOVING_PHOTO_ANI_H
#define FRAMEWORKS_ANI_SRC_INCLUDE_MOVING_PHOTO_ANI_H

#include <ani.h>
#include "ani_error.h"
#include "media_library_enum_ani.h"

namespace OHOS {
namespace Media {
class MovingPhotoAni {
public:
    static ani_status MovingPhotoInit(ani_env *env);
    static ani_object Constructor([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_class clazz,
        [[maybe_unused]] ani_object context);
    static MovingPhotoAni* Unwrap(ani_env *env, ani_object object);
    static void RequestContent1(ani_env *env, ani_object object, ani_string imageFileUri, ani_string videoFileUri);
    static void RequestContent2(ani_env *env, ani_object object, ani_enum_item resourceType, ani_string fileUri);
    static void RequestContent3(ani_env *env, ani_object object, ani_enum_item resourceType);
    static ani_string GetUri(ani_env *env, ani_object object);

private:
    std::string GetUriInner();
    std::string photoUri_;
};

} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_ANI_SRC_INCLUDE_MOVING_PHOTO_ANI_H