/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MOVING_PHOTO_IMPL_H
#define MOVING_PHOTO_IMPL_H

#include <mutex>

#include "cj_common_ffi.h"
#include "photo_accesshelper_utils.h"

namespace OHOS {
namespace Media {
class FfiMovingPhotoImpl : public OHOS::FFI::FFIData {
    DECL_TYPE(FfiMovingPhotoImpl, OHOS::FFI::FFIData)
public:
    explicit FfiMovingPhotoImpl(const std::string& photoUri) : photoUri_(photoUri) {}
    FfiMovingPhotoImpl(const std::string& photoUri, SourceMode sourceMode);
    std::string GetUri();
    SourceMode GetSourceMode();
    void SetSourceMode(SourceMode sourceMode);
    void RequestContent(char* imageFileUri, char* videoFileUri, int32_t &errCode);
    void RequestContent(int32_t resourceType, char* fileUri, int32_t &errCode);
    CArrUI8 RequestContent(int32_t resourceType, int32_t &errCode);
    static int32_t OpenReadOnlyFile(const std::string& uri, bool isReadImage);
    static int32_t OpenReadOnlyLivePhoto(const std::string& destLivePhotoUri);
private:
    std::string photoUri_;
    SourceMode sourceMode_ = SourceMode::EDITED_MODE;
};
}
}
#endif