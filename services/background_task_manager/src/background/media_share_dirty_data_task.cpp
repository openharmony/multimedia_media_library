/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#define MLOG_TAG "Media_Background"

#include "media_share_dirty_data_task.h"

#include "medialibrary_subscriber.h"
#ifdef MEDIALIBRARY_FEATURE_CUSTOM_RESTORE
#include "media_share_dirty_data_cleaner.h"
#endif

namespace OHOS::Media::Background {
bool MediaShareDirtyDataTask::Accept()
{
    return MedialibrarySubscriber::IsCurrentStatusOn();
}

void MediaShareDirtyDataTask::Execute()
{
    this->HandleDirtyData();
}

bool MediaShareDirtyDataTask::HandleDirtyData()
{
#ifdef MEDIALIBRARY_FEATURE_CUSTOM_RESTORE
    MediaShareDirtyDataCleaner::CheckDirtyData();
#endif
    return true;
}
} // namespace OHOS::Media::Background