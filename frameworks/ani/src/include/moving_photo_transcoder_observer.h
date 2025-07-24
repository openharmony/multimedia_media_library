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

#ifndef MOVING_PHOTO_TRANSCODER_OBSERVER_H
#define MOVING_PHOTO_TRANSCODER_OBSERVER_H

#include <atomic>

#include "moving_photo_call_transcoder.h"
#include "transcoder.h"

namespace OHOS {
namespace Media {

class MovingPhotoTranscoderObserver : public TransCoderCallback {
public:
    MovingPhotoTranscoderObserver() = default;
    ~MovingPhotoTranscoderObserver();
    void SetMovingPhotoProgressHandler(const std::shared_ptr<MovingPhotoProgressHandler> &mppHandler);
    void NotifyProcessInfo();
    void DoPrepareError();
    void setTransCoder(const std::shared_ptr<TransCoder> &transCoder)
    {
        transCoder_ = transCoder;
    }
protected:
    void OnError(int32_t errCode, const std::string &errorMsg) override;
    void OnInfo(int32_t type, int32_t extra) override;
private:
    std::shared_ptr<MovingPhotoProgressHandler> mppHandler_ { nullptr };
    std::shared_ptr<TransCoder> transCoder_ { nullptr };
    std::atomic_bool isPrepareError_ { false };
    int32_t process_ { -1 };
};
} // namespace Media
} // namespace OHOS

#endif // MOVING_PHOTO_TRANSCODER_OBSERVER_H
