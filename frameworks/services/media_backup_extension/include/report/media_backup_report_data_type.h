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
#ifndef OHOS_MEDIA_BACKUP_REPORT_DATA_TYPE_H
#define OHOS_MEDIA_BACKUP_REPORT_DATA_TYPE_H

#include <string>

namespace OHOS::Media {
struct AlbumMediaStatisticInfo {
    int32_t sceneCode;
    std::string taskId;
    std::string albumName;
    int32_t totalCount;
    int32_t imageCount;
    int32_t videoCount;
    int32_t hiddenCount;
    int32_t trashedCount;
    int32_t cloudCount;
    int32_t favoriteCount;
    int32_t burstCoverCount;
    int32_t burstTotalCount;
};
struct MediaRestoreResultInfo {
    int32_t sceneCode;
    std::string taskId;
    std::string errorCode;
    std::string errorInfo;
    std::string type;
    std::string backupInfo;
    int duplicateCount;
    int failedCount;
    int successCount;
};
}  // namespace OHOS::Media
#endif  // OHOS_MEDIA_BACKUP_REPORT_DATA_TYPE_H