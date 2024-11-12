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
#ifndef OHOS_MEDIA_BACKUP_UPGRADE_RESTORE_GALLERY_MEDIA_TASK_H
#define OHOS_MEDIA_BACKUP_UPGRADE_RESTORE_GALLERY_MEDIA_TASK_H

#include <string>
#include <vector>

#include "media_backup_report_data_type.h"

namespace OHOS::Media {
class UpgradeRestoreGalleryMediaTask {
private:
    struct BackupInfo {
        std::string backupInfo;
        std::string details;
        int duplicateCount;
        int failedCount;
        int successCount;
    };

    struct ResultInfo {
        std::string errorCode;
        std::string errorInfo;
        std::string type;
        std::vector<BackupInfo> infos;
    };

    struct ResultData {
        std::vector<ResultInfo> resultInfo;
    };

public:
    UpgradeRestoreGalleryMediaTask &SetSceneCode(int32_t sceneCode)
    {
        this->sceneCode_ = sceneCode;
        return *this;
    }
    UpgradeRestoreGalleryMediaTask &SetTaskId(const std::string &taskId)
    {
        this->taskId_ = taskId;
        return *this;
    }
    int32_t Report(const std::string &taskInfo);

private:
    ResultData ParseFromJsonStr(const std::string &jsonStr);
    std::vector<MediaRestoreResultInfo> Parse(const ResultData &resultData);
    std::string ToString(const ResultData &resultData);

private:
    int32_t sceneCode_;
    std::string taskId_;
};
}  // namespace OHOS::Media
#endif  // OHOS_MEDIA_BACKUP_UPGRADE_RESTORE_TASK_REPORT_H