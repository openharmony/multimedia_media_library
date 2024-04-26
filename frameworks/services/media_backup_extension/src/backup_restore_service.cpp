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
#include "upgrade_restore.h"

namespace OHOS {
namespace Media {
const int DUAL_FIRST_NUMBER = 65;
const int DUAL_SECOND_NUMBER = 110;
const int DUAL_THIRD_NUMBER = 100;
const int DUAL_FOURTH_NUMBER = 114;
const int DUAL_FIFTH_NUMBER = 111;
const int DUAL_SIXTH_NUMBER = 105;
const int DUAL_SEVENTH_NUMBER = 100;
BackupRestoreService &BackupRestoreService::GetInstance(void)
{
    static BackupRestoreService inst;
    return inst;
}

std::string GetDualDirName()
{
    int arr[] = { DUAL_FIRST_NUMBER, DUAL_SECOND_NUMBER, DUAL_THIRD_NUMBER, DUAL_FOURTH_NUMBER, DUAL_FIFTH_NUMBER,
        DUAL_SIXTH_NUMBER, DUAL_SEVENTH_NUMBER };
    int len = sizeof(arr) / sizeof(arr[0]);
    std::string dualDirName = "";
    for (int i = 0; i < len; i++) {
        dualDirName += char(arr[i]);
    }
    return dualDirName;
}

void BackupRestoreService::StartRestore(int32_t sceneCode, const std::string &galleryAppName,
    const std::string &mediaAppName)
{
    std::unique_ptr<BaseRestore> restoreService;
    MEDIA_INFO_LOG("Start restore service: %{public}d", sceneCode);
    if (sceneCode == UPGRADE_RESTORE_ID) {
        restoreService = std::make_unique<UpgradeRestore>(galleryAppName, mediaAppName,
            UPGRADE_RESTORE_ID, GetDualDirName());
    } else if (sceneCode == DUAL_FRAME_CLONE_RESTORE_ID) {
        restoreService = std::make_unique<UpgradeRestore>(galleryAppName, mediaAppName, DUAL_FRAME_CLONE_RESTORE_ID);
    } else {
        restoreService = std::make_unique<CloneRestore>();
    }
    if (restoreService == nullptr) {
        MEDIA_ERR_LOG("Create media restore service failed.");
        return;
    }
    restoreService->StartRestore(BACKUP_RESTORE_DIR, UPGRADE_FILE_DIR);
}
} // namespace Media
} // namespace OHOS
