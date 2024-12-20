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
#define MLOG_TAG "MtpGlobal"
#include "mtp_global.h"

namespace OHOS {
namespace Media {
bool MtpGlobal::isBlock_ = true;

bool MtpGlobal::IsBlocked()
{
    return isBlock_;
}

void MtpGlobal::ReleaseBlock()
{
    isBlock_ = false;
}

void MtpGlobal::ResetBlockStatus()
{
    isBlock_ = true;
}

} // namespace Media
} // namespace OHOS

