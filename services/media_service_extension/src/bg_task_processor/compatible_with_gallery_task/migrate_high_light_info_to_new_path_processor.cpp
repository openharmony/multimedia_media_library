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

#define MLOG_TAG "MediaBgTask_MigrateHighLightInfoToNewPathProcessor"

#include "migrate_high_light_info_to_new_path_processor.h"

#include "ffrt.h"
#include "ffrt_inner.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_type_const.h"

namespace OHOS {
namespace Media {
int32_t MigrateHighLightInfoToNewPathProcessor::Start(const std::string &taskExtra)
{
    MEDIA_INFO_LOG("Start begin");
    ffrt::submit([this]() {
        DoMigrateHighLight();
        RemoveTaskName(taskName_);
        ReportTaskComplete(taskName_);
    });
    return E_OK;
}

int32_t MigrateHighLightInfoToNewPathProcessor::Stop(const std::string &taskExtra)
{
    return E_OK;
}

void MigrateHighLightInfoToNewPathProcessor::DoMigrateHighLight()
{
    // migration highlight info to new path
    if (!MediaFileUtils::IsFileExists(ROOT_MEDIA_DIR + HIGHLIGHT_INFO_OLD)) {
        MEDIA_WARN_LOG("Highlight old path not exists.");
        return;
    }
    MEDIA_INFO_LOG("Begin Migration highlight info to new path");
    bool retMigration = MediaFileUtils::CopyDirAndDelSrc(ROOT_MEDIA_DIR + HIGHLIGHT_INFO_OLD,
        ROOT_MEDIA_DIR + HIGHLIGHT_INFO_NEW);
    if (retMigration) {
        bool retDelete = MediaFileUtils::DeleteDir(ROOT_MEDIA_DIR + HIGHLIGHT_INFO_OLD);
        if (!retDelete) {
            MEDIA_ERR_LOG("Delete old highlight path fail");
        }
    }
    MEDIA_INFO_LOG("End Migration highlight info to new path");
}
} // namespace Media
} // namespace OHOS
