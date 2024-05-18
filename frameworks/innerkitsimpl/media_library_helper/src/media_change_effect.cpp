/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "media_change_effect.h"
#ifdef IMAGE_EFFECT_SUPPORT
#include "plugin/common/any.h"
#include "image_effect_inner.h"
#endif
#include <memory>

using std::string;

namespace OHOS {
namespace Media {
 
#ifdef IMAGE_EFFECT_SUPPORT
int32_t ParseInt(Effect::ErrorCode input)
{
    return static_cast<int32_t>(input);
}
#endif

int32_t MediaChangeEffect::TakeEffect(const string &inputPath, const string &outputPath, string &editdata)
{
#ifdef IMAGE_EFFECT_SUPPORT
    Effect::ErrorCode ret = Effect::ErrorCode::ERR_UNKNOWN;
    std::shared_ptr<Effect::ImageEffect> imageEffect = Effect::ImageEffect::Restore(editdata);
    if (imageEffect == nullptr) {
        return ParseInt(ret);
    }
    ret = imageEffect->SetInputPath(inputPath);
    if (ret != Effect::ErrorCode::SUCCESS) {
        return ParseInt(ret);
    }
    ret = imageEffect->SetOutputPath(outputPath);
    if (ret != Effect::ErrorCode::SUCCESS) {
        return ParseInt(ret);
    }
    ret = imageEffect->Start();
    if (ret != Effect::ErrorCode::SUCCESS) {
        return ParseInt(ret);
    }
#endif
    return 0;
}
 
} // end of namespace
}