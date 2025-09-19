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

#ifndef OHOS_MEDIA_VIDEO_3DGS_OPERATION_H
#define OHOS_MEDIA_VIDEO_3DGS_OPERATION_H

#include <string>
#include <vector>

#include "medialibrary_rdbstore.h"

namespace OHOS::Media {

struct CheckedVideoInfo {
    int32_t fileId;
    std::string path;
};

class Video3DgsOperation {
public:
    static void Update3DgsType();
    static void Stop();
    static int32_t QueryVideoCount(int32_t startFileId);
    static std::vector<CheckedVideoInfo> QueryVideoInfo(int32_t startFileId);
    static void HandleVideoInfos(const std::vector<CheckedVideoInfo> &photoInfos, int32_t &curFileId);
    static void UpdateVideoSubtype(const CheckedVideoInfo &photoInfo);

private:
    static std::atomic<bool> isContinue_;
};
}  // namespace OHOS::Media
#endif  // OHOS_MEDIA_VIDEO_3DGS_OPERATION_H