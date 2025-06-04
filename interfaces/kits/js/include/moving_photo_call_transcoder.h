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

#ifndef MEDIA_MOVING_PHOTO_CALL_TRANSCODE_H
#define MEDIA_MOVING_PHOTO_CALL_TRANSCODE_H

#include <string>
#include "napi/native_api.h"
#include "unique_fd.h"

namespace OHOS {
namespace Media {
struct MovingPhotoProgressHandler {
    napi_env env;
    napi_env mediaAssetEnv;
    napi_ref progressHandlerRef;
    UniqueFd srcFd;
    UniqueFd destFd;
    int64_t size;
    int64_t offset;
    int32_t extra;
    int32_t errCode;
    void *contextData;
    napi_threadsafe_function onProgressFunc;
    bool isComplete;
    std::function<void(napi_env, void*, int)> callbackFunc;
    MovingPhotoProgressHandler() : env(nullptr), mediaAssetEnv(nullptr), progressHandlerRef(nullptr),
        srcFd(-1), destFd(-1), size(0), offset(0), extra(0), errCode(0), contextData(nullptr),
        onProgressFunc(nullptr), isComplete(false) {}
};

class MovingPhotoCallTranscoder {
public:
    MovingPhotoCallTranscoder() = delete;
    ~MovingPhotoCallTranscoder() = delete;
    static bool DoTranscode(const std::shared_ptr<MovingPhotoProgressHandler> &MovingPhotoProgressHandler);
    static void OnProgress(napi_env env, napi_value cb, void *context, void *data);
};

} // namespace Media
} // namespace OHOS
#endif // MEDIA_MOVING_PHOTO_CALL_TRANSCODE_H
