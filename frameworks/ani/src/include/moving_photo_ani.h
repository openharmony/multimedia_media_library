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

#include <string>
#include "ani_error.h"
#include "media_library_enum_ani.h"

namespace OHOS {
namespace Media {
struct MovingPhotoParam {
    std::string requestId;
    CompatibleMode compatibleMode;
};
struct MovingPhotoAsyncContext;

class MovingPhotoAni {
public:
    explicit MovingPhotoAni(const std::string& photoUri) : photoUri_(photoUri) {}
    ~MovingPhotoAni() = default;
    static ani_status Init(ani_env *env);
    static MovingPhotoAni* Unwrap(ani_env *env, ani_object object);
    static int32_t OpenReadOnlyFile(const std::string& uri, bool isReadImage);
    static int32_t OpenReadOnlyLivePhoto(const std::string& destLivePhotoUri);
    static int32_t OpenReadOnlyMetadata(const std::string& movingPhotoUri);
    static ani_object NewMovingPhotoAni(ani_env *env, const std::string& photoUri, SourceMode sourceMode,
        MovingPhotoParam movingPhotoParam,
        const std::function<void(int, int, std::string)> callbacks = [](int, int, std::string) {});
    static void SubRequestContent(int32_t fd, MovingPhotoAsyncContext* context);
    std::string GetUriInner();
    SourceMode GetSourceMode();
    static int32_t GetFdFromUri(const std::string &uri);
    void SetSourceMode(SourceMode sourceMode);
    std::string GetRequestId();
    void SetRequestId(const std::string &requestId);
    CompatibleMode GetCompatibleMode();
    void SetCompatibleMode(const CompatibleMode compatibleMode);
    void SetMovingPhotoCallback(const std::function<void(int, int, std::string)> callback);
    std::function<void(int, int, std::string)> GetMovingPhotoCallback();

private:
    static ani_object Constructor(ani_env *env, [[maybe_unused]] ani_class clazz, ani_string photoUriAni);

    static ani_object RequestContentByImageFileAndVideoFile(ani_env *env, ani_object object,
        ani_string imageFileUri, ani_string videoFileUri);
    static ani_object RequestContentByResourceTypeAndFile(ani_env *env, ani_object object,
        ani_enum_item resourceTypeAni, ani_string fileUri);
    static ani_object RequestContentByResourceType(ani_env *env, ani_object object,
        ani_enum_item resourceTypeAni);
    static ani_string GetUri(ani_env *env, ani_object object);

    std::string photoUri_;
    SourceMode sourceMode_ = SourceMode::EDITED_MODE;
    CompatibleMode compatibleMode_ = CompatibleMode::COMPATIBLE_FORMAT_MODE;
    std::string requestId_;
};

struct MovingPhotoAsyncContext : public AniError {
    enum RequestContentMode {
        WRITE_TO_SANDBOX,
        WRITE_TO_ARRAY_BUFFER,
        UNDEFINED,
    };

    std::string movingPhotoUri;
    SourceMode sourceMode;
    CompatibleMode compatibleMode;
    std::function<void(int, int, std::string)> callback;
    std::string requestId;
    ResourceType resourceType;
    std::string destImageUri;
    std::string destVideoUri;
    std::string destLivePhotoUri;
    std::string destMetadataUri;
    RequestContentMode requestContentMode = UNDEFINED;
    void* arrayBufferData = nullptr;
    size_t arrayBufferLength = 0;
};
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_ANI_SRC_INCLUDE_MOVING_PHOTO_ANI_H