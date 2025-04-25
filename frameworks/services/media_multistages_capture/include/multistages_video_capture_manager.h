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

#ifndef FRAMEWORKS_SERVICES_MEDIA_MULTI_STAGES_CAPTURE_INCLUDE_MULTI_STAGES_VIDEO_CAPTURE_MANAGER_H
#define FRAMEWORKS_SERVICES_MEDIA_MULTI_STAGES_CAPTURE_INCLUDE_MULTI_STAGES_VIDEO_CAPTURE_MANAGER_H

#include <string>
#include <unordered_set>
#include <unordered_map>
#include <mutex>

#include "deferred_video_proc_adapter.h"
#include "medialibrary_type_const.h"
#include "medialibrary_command.h"
#include "result_set.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
class MultiStagesVideoCaptureManager {
public:
    EXPORT static MultiStagesVideoCaptureManager& GetInstance();
    bool Init();

    EXPORT void SyncWithDeferredVideoProcSession();
    EXPORT void SyncWithDeferredVideoProcSessionInternal();
    EXPORT void AddVideoInternal(const std::string &videoId, const std::string &filePath, bool isMovingPhoto = false);
    EXPORT void AddVideo(const std::string &videoId, const std::string &fileId, const std::string &filePath);
    EXPORT void RemoveVideo(const std::string &videoId, const bool restorable);
    EXPORT void RestoreVideo(const std::string &videoId);
private:
    MultiStagesVideoCaptureManager();
    ~MultiStagesVideoCaptureManager();

    std::shared_ptr<DeferredVideoProcessingAdapter> deferredProcSession_;
};
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_SERVICES_MEDIA_MULTI_STAGES_CAPTURE_INCLUDE_MULTI_STAGES_VIDEO_CAPTURE_MANAGER_H