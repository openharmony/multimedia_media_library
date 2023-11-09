/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "medialibrary_xcollie_manager.h"

#include <cstdint>
#include <functional>

#include "media_log.h"
#ifdef MEDIALIBRARY_XCOLLIE_OPEN
#include "xcollie/xcollie.h"
#include "xcollie/xcollie_define.h"
#endif

namespace OHOS::Media {
using namespace std;
#ifdef MEDIALIBRARY_XCOLLIE_OPEN
constexpr int32_t INVALID_XCOLLIE_ID = HiviewDFX::INVALID_ID;
#else
constexpr int32_t INVALID_XCOLLIE_ID = -1;
#endif

MediaLibraryXCollieManager::MediaLibraryXCollieManager(const string &name, uint32_t timeout, bool recovery)
{
    xcollieId = SetXCollieTimer(name, timeout, recovery);
}

MediaLibraryXCollieManager::~MediaLibraryXCollieManager()
{
    if (!isCancel && xcollieId != INVALID_XCOLLIE_ID) {
        CancelXCollieTimer(xcollieId);
    }
}

void MediaLibraryXCollieManager::Cancel()
{
    if (!isCancel && xcollieId != INVALID_XCOLLIE_ID) {
        CancelXCollieTimer(xcollieId);
        isCancel = true;
    }
}

#ifdef MEDIALIBRARY_XCOLLIE_OPEN
static void XCollieTimeoutFunction(void *args)
{
    MEDIA_WARN_LOG("Warning, XCollie is timeout!!!");
}
#endif

int32_t MediaLibraryXCollieManager::SetXCollieTimer(const string &name, uint32_t timeout, bool recovery)
{
#ifdef MEDIALIBRARY_XCOLLIE_OPEN
    unsigned int flag = HiviewDFX::XCOLLIE_FLAG_NOOP | HiviewDFX::XCOLLIE_FLAG_LOG;
    if (recovery) {
        flag |= HiviewDFX::XCOLLIE_FLAG_RECOVERY;
    }
    return HiviewDFX::XCollie::GetInstance().SetTimer(name, timeout, XCollieTimeoutFunction, nullptr, flag);
#else
    MEDIA_DEBUG_LOG("XCollie not supported in MediaLibrary");
    return INVALID_XCOLLIE_ID;
#endif
}

void MediaLibraryXCollieManager::CancelXCollieTimer(int32_t id)
{
#ifdef MEDIALIBRARY_XCOLLIE_OPEN
    HiviewDFX::XCollie::GetInstance().CancelTimer(id);
#endif
}
}