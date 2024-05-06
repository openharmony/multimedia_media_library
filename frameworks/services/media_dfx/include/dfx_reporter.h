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

#ifndef OHOS_MEDIA_DFX_REPORTER_H
#define OHOS_MEDIA_DFX_REPORTER_H

#include <string>

#include "thumbnail_data.h"

namespace OHOS {
namespace Media {
class DfxReporter {
public:
    DfxReporter();
    ~DfxReporter();

    void ReportTimeOutOperation(std::string &bundleName, int32_t type, int32_t object, int32_t time);
    int32_t ReportHighMemoryImageThumbnail(std::string &path, std::string &suffix, int32_t width, int32_t height);
    int32_t ReportHighMemoryVideoThumbnail(std::string &path, std::string &suffix, int32_t width, int32_t height);
    void ReportThumbnailError();
    void ReportCommonBehavior();
    void ReportDeleteStatistic();
    void ReportDeleteBehavior(std::string bundleName, int32_t type, std::string path);
    void ReportThumbnailGeneration(const ThumbnailData::GenerateStats &stats);
    void ReportPhotoInfo(int32_t localImageCount, int32_t localVideoCount, int32_t cloudImageCount,
        int32_t cloudVideCount);
    void ReportAlbumInfo(const std::string &albumName, int32_t albumImageCount, int32_t albumVideoCount,
        bool isLocal);
    void ReportDirtyCloudPhoto(const std::string &data, int32_t dirty, int32_t cloudVersion);
    void ReportCommonVersion();
    void ReportAnalysisVersion(const std::string &analysisName, int32_t version);
};
} // namespace Media
} // namespace OHOS

#endif  // OHOS_MEDIA_DFX_REPORTER_H