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

#ifndef MOVING_PHOTO_CALL_TRANSCODER_H
#define MOVING_PHOTO_CALL_TRANSCODER_H

#include <string>
#include "ani.h"
#include "progress_handler.h"
#include "unique_fd.h"

namespace OHOS {
namespace Media {

class MovingPhotoCallTranscoder {
public:
    MovingPhotoCallTranscoder() = delete;
    ~MovingPhotoCallTranscoder() = delete;
    static bool DoTranscode(const std::shared_ptr<MovingPhotoProgressHandler> &mppHandler);
    static void OnProgress(ani_env *env, ProgressHandler *progressHandler);
};

} // namespace Media
} // namespace OHOS

#endif // MOVING_PHOTO_CALL_TRANSCODER_H
