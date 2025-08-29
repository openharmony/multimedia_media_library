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

#ifndef OHOS_MEDIA_BACKGROUND_REPAIR_VIDEO_DIRTY_AND_QUALITY_TASK_H
#define OHOS_MEDIA_BACKGROUND_REPAIR_VIDEO_DIRTY_AND_QUALITY_TASK_H

#include <string>

#include "i_media_background_task.h"
#include "medialibrary_rdbstore.h"

namespace OHOS::Media::Background {
class RepairVideoDirtyAndQualityTask : public IMediaBackGroundTask {
public:
    virtual ~RepairVideoDirtyAndQualityTask() = default;

public:
    bool Accept() override;
    void Execute() override;

private:
    int32_t HandleRepairVideoDirtyAndQuality();
    int32_t UpdateVideoDirtyAndQuality(std::shared_ptr<MediaLibraryRdbStore> rdbStore,
        const std::vector<std::string> &fileIdVec);

private:
    const int32_t BATCH_QUERY_NUMBER = 200;
    const int32_t CAMERA_SUBTYPE = 5;
};
}  // namespace OHOS::Media::Background
#endif  // OHOS_MEDIA_BACKGROUND_MEDIA_HIDDEN_AND_RECYCLE_TASK_H