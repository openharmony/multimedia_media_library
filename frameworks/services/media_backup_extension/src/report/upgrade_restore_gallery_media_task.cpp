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
#include "upgrade_restore_task_report.h"

#include <sstream>
#include <nlohmann/json.hpp>

#include "media_log.h"
#include "hisysevent.h"
#include "media_backup_report_data_type.h"
#include "upgrade_restore_gallery_media_task.h"
#include "json_utils.h"

namespace OHOS::Media {
static constexpr char MEDIA_LIBRARY[] = "MEDIALIBRARY";
int32_t UpgradeRestoreGalleryMediaTask::Report(const std::string &taskInfo)
{
    UpgradeRestoreGalleryMediaTask::ResultData resultData = this->ParseFromJsonStr(taskInfo);
    MEDIA_INFO_LOG("UpgradeRestoreGalleryMediaTask, resultData: %{public}s", this->ToString(resultData).c_str());
    for (const auto &eventInfo : this->Parse(resultData)) {
        int32_t ret = HiSysEventWrite(MEDIA_LIBRARY,
            "MEDIALIB_BACKUP_RESTORE_RESULT",
            HiviewDFX::HiSysEvent::EventType::STATISTIC,
            "SCENE_CODE",
            eventInfo.sceneCode,
            "TASK_ID",
            eventInfo.taskId,
            "ERROR_CODE",
            eventInfo.errorCode,
            "ERROR_INFO",
            eventInfo.errorInfo,
            "TYPE",
            eventInfo.type,
            "BACKUP_INFO",
            eventInfo.backupInfo,
            "DUPLICATE_COUNT",
            eventInfo.duplicateCount,
            "FAILED_COUNT",
            eventInfo.failedCount,
            "SUCCESS_COUNT",
            eventInfo.successCount);
        if (ret != 0) {
            MEDIA_ERR_LOG("UpgradeRestoreGalleryMediaTask error:%{public}d", ret);
        }
    }
    return 0;
}

UpgradeRestoreGalleryMediaTask::ResultData UpgradeRestoreGalleryMediaTask::ParseFromJsonStr(const std::string &jsonStr)
{
    JsonUtils jsonUtils;
    nlohmann::json jsonObj = jsonUtils.Parse(jsonStr);
    ResultData resultData;
    for (const auto &info : jsonUtils.GetArray(jsonObj, "resultInfo")) {
        ResultInfo resultInfo;
        resultInfo.errorCode = jsonUtils.GetString(info, "errorCode");
        resultInfo.errorInfo = jsonUtils.GetString(info, "errorInfo");
        resultInfo.type = jsonUtils.GetString(info, "type");
        for (const auto &backup : jsonUtils.GetArray(info, "infos")) {
            BackupInfo backupInfo;
            backupInfo.backupInfo = jsonUtils.GetString(backup, "backupInfo");
            backupInfo.duplicateCount = jsonUtils.GetInt(backup, "duplicateCount");
            backupInfo.failedCount = jsonUtils.GetInt(backup, "failedCount");
            backupInfo.successCount = jsonUtils.GetInt(backup, "successCount");
            resultInfo.infos.push_back(backupInfo);
        }
        resultData.resultInfo.push_back(resultInfo);
    }
    return resultData;
}

std::vector<MediaRestoreResultInfo> UpgradeRestoreGalleryMediaTask::Parse(
    const UpgradeRestoreGalleryMediaTask::ResultData &resultData)
{
    std::vector<MediaRestoreResultInfo> result;
    for (const auto &resultInfo : resultData.resultInfo) {
        for (const auto &backupInfo : resultInfo.infos) {
            MediaRestoreResultInfo eventInfo;
            eventInfo.sceneCode = this->sceneCode_;
            eventInfo.taskId = this->taskId_;
            eventInfo.errorCode = resultInfo.errorCode;
            eventInfo.errorInfo = resultInfo.errorInfo;
            eventInfo.type = resultInfo.type;
            eventInfo.backupInfo = backupInfo.backupInfo;
            eventInfo.duplicateCount = backupInfo.duplicateCount;
            eventInfo.failedCount = backupInfo.failedCount;
            eventInfo.successCount = backupInfo.successCount;
            result.emplace_back(eventInfo);
        }
    }
    return result;
}

std::string UpgradeRestoreGalleryMediaTask::ToString(const UpgradeRestoreGalleryMediaTask::ResultData &resultData)
{
    std::stringstream ss;
    for (const auto &resultInfo : resultData.resultInfo) {
        ss << "ErrorCode: " << resultInfo.errorCode << ", ";
        ss << "ErrorInfo: " << resultInfo.errorInfo << ", ";
        ss << "Type: " << resultInfo.type << ", ";
        for (const auto &backupInfo : resultInfo.infos) {
            ss << "BackupInfo: " << backupInfo.backupInfo << ", ";
            ss << "DuplicateCount: " << backupInfo.duplicateCount << ", ";
            ss << "FailedCount: " << backupInfo.failedCount << ", ";
            ss << "SuccessCount: " << backupInfo.successCount << ", ";
        }
    }
    return ss.str();
}
}  // namespace OHOS::Media