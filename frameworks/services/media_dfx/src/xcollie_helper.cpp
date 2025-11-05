/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "xcollie_helper.h"

#include "media_log.h"

#ifdef MEDIALIBRARY_FEATURE_HICOLLIE_ENABLE
#include "xcollie/xcollie.h"
#include "xcollie/xcollie_define.h"
#endif

namespace OHOS::Media {
static constexpr int32_t INVALID_ID = -1;
XCollieHelper::XCollieHelper(const std::string &name, uint32_t timeout, XCollieCallback func, void *arg, bool recovery)
{
#ifdef MEDIALIBRARY_FEATURE_HICOLLIE_ENABLE
    unsigned int flag = HiviewDFX::XCOLLIE_FLAG_LOG | HiviewDFX::XCOLLIE_FLAG_NOOP;
    if (recovery) {
        flag |= HiviewDFX::XCOLLIE_FLAG_RECOVERY;
    }
    xcollieId_ = HiviewDFX::XCollie::GetInstance().SetTimer(name, timeout, func, arg, flag);
#else
    LOGI("XCollie not supported");
    xcollieId_ = INVALID_ID;
#endif
}
XCollieHelper::~XCollieHelper()
{
#ifdef MEDIALIBRARY_FEATURE_HICOLLIE_ENABLE
    HiviewDFX::XCollie::GetInstance().CancelTimer(xcollieId_);
#endif
}
} // namespace OHOS::Media