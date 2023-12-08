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

#define MLOG_TAG "MediaLibraryRestoreService"

#include "backup_restore_service.h"
#include "media_log.h"
#include "clone_restore.h"
#include "update_restore.h"

namespace OHOS {
namespace Media {
const int32_t UPDATE = 0;
const int32_t DUAL_FRAME_CLONE = 1;
BackupRestoreService &BackupRestoreService::GetInstance(void)
{
    static BackupRestoreService inst;
    return inst;
}

void BackupRestoreService::StartRestore(int32_t sceneCode, const std::string &galleryAppName,
    const std::string &mediaAppName, const std::string &cameraAppName)
{
    std::unique_ptr<BaseRestore> restoreService;
    if (sceneCode == UPDATE || sceneCode == DUAL_FRAME_CLONE) {
        restoreService = std::make_unique<UpdateRestore>(galleryAppName, mediaAppName, cameraAppName);
    } else {
        restoreService = std::make_unique<CloneRestore>();
    }
    if (restoreService == nullptr) {
        MEDIA_ERR_LOG("Create media restore service failed.");
        return;
    }
    restoreService->StartRestore(ORIGIN_PATH, UPDATE_FILE_DIR);
}
} // namespace Media
} // namespace OHOS
