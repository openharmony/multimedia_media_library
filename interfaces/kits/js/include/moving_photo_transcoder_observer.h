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

#ifndef MEDIA_MOVING_PHOTO_CALLBACK_H
#define MEDIA_MOVING_PHOTO_CALLBACK_H

#include <atomic>

#include "moving_photo_call_transcoder.h"
#include "napi/native_api.h"
#include "transcoder.h"

namespace OHOS {
namespace Media {
class MovingphotoTranscoderObserver : public TransCoderCallback {
public:
    MovingphotoTranscoderObserver() = default;
    ~MovingphotoTranscoderObserver() = default;
    void SetMovingPhotoProgress(const std::shared_ptr<MovingPhotoProgressHandler> &movingPhotoProgressHandler);
    void CallMovingProgressCallback(bool isComplete = false);
    void DoPrepareError();
    void setTransCoder(std::shared_ptr<TransCoder> transCoder)
    {
        transCoder_ = transCoder;
    }
protected:
    void OnError(int32_t errCode, const std::string &errorMsg) override;
    void OnInfo(int32_t type, int32_t extra) override;
private:
    void ErrorExcute();
    std::shared_ptr<MovingPhotoProgressHandler> movingPhotoProgressHandler_ { nullptr };
    std::shared_ptr<TransCoder> transCoder_ { nullptr };
    std::atomic_bool isPrepareError { false };
};
} // namespace Media
} // namespace OHOS
#endif // MEDIA_MOVING_PHOTO_CALLBACK_H
