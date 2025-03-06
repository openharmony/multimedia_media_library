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

#include "media_change_request_ani.h"
#include "userfile_client.h"
#include "photo_access_helper_ani.h"

namespace OHOS {
namespace Media {
MediaChangeRequestAni* MediaChangeRequestAni::Unwrap(ani_env *env, ani_object aniObject)
{
    ani_long nativeHandle;
    if (ANI_OK != env->Object_GetFieldByName_Long(aniObject, "nativeHandle", &nativeHandle)) {
        return nullptr;
    }
    return reinterpret_cast<MediaChangeRequestAni*>(nativeHandle);
}

bool MediaChangeRequestAni::InitUserFileClient(ani_env *env, ani_object object)
{
    if (UserFileClient::IsValid()) {
        return true;
    }

    std::unique_lock<std::mutex> helperLock(PhotoAccessHelperAni::sUserFileClientMutex_);
    if (!UserFileClient::IsValid()) {
        UserFileClient::Init(env, object);
    }
    helperLock.unlock();
    return UserFileClient::IsValid();
}
} // namespace Media
} // namespace OHOS