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

#define MLOG_TAG "Media_Background"

#include "media_hidden_and_recycle_task.h"

#include "medialibrary_subscriber.h"
#include "cloud_media_dao_utils.h"
#include "media_log.h"
#include "medialibrary_errno.h"

namespace OHOS::Media::Background {
// LCOV_EXCL_START
bool MediaHiddenAndRecycleTask::Accept()
{
    return MedialibrarySubscriber::IsCurrentStatusOn();
}

void MediaHiddenAndRecycleTask::Execute()
{
    this->HandleMediaRecycle();
    this->HandleMediaHidden();
    return;
}

void MediaHiddenAndRecycleTask::HandleMediaHidden()
{
    int32_t count = 0;
    int32_t ret =
        CloudSync::CloudMediaDaoUtils::QueryCount(SQL_PHOTOS_TABLE_HIDDEN_RELATION_QUERY, COLUMN_NAME_COUNT, count);
    CHECK_AND_RETURN_LOG(ret == E_OK, "query hidden count failed, ret: %{public}d", ret);
    CHECK_AND_RETURN_INFO_LOG(count > 0, "hidden count is %{public}d, no need to handle", count);
    ret = CloudSync::CloudMediaDaoUtils::ExecuteSql(SQL_PHOTOS_TABLE_HIDDEN_RELATION_MAINTAIN);
    MEDIA_INFO_LOG("handle hidden count: %{public}d, ret: %{public}d", count, ret);
}

void MediaHiddenAndRecycleTask::HandleMediaRecycle()
{
    int32_t count = 0;
    int32_t ret =
        CloudSync::CloudMediaDaoUtils::QueryCount(SQL_PHOTOS_TABLE_RECYCLE_RELATION_QUERY, COLUMN_NAME_COUNT, count);
    CHECK_AND_RETURN_LOG(ret == E_OK, "query recycle count failed, ret: %{public}d", ret);
    CHECK_AND_RETURN_INFO_LOG(count > 0, "recycle count is %{public}d, no need to handle", count);
    ret = CloudSync::CloudMediaDaoUtils::ExecuteSql(SQL_PHOTOS_TABLE_RECYCLE_RELATION_MAINTAIN);
    MEDIA_INFO_LOG("handle recycle count: %{public}d, ret: %{public}d", count, ret);
}
// LCOV_EXCL_STOP
}  // namespace OHOS::Media::Background