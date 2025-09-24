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

#ifndef FRAMEWORKS_ANI_SRC_INCLUDE_CLOUD_ENHANCEMENT_ANI_H
#define FRAMEWORKS_ANI_SRC_INCLUDE_CLOUD_ENHANCEMENT_ANI_H

#include <ani.h>

namespace OHOS {
namespace Media {
class CloudEnhancementAni {
public:
    static ani_status CloudEnhancementAniInit(ani_env *env);
    static ani_object Constructor(ani_env *env, ani_class clazz, ani_object context);
    static CloudEnhancementAni* Unwrap(ani_env *env, ani_object aniObject);
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_ANI_SRC_INCLUDE_CLOUD_ENHANCEMENT_ANI_H