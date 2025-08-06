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

#ifndef OHOS_MEDIA_DFX_MOVING_PHOTO_H
#define OHOS_MEDIA_DFX_MOVING_PHOTO_H

#include <mutex>

#include "preferences.h"

namespace OHOS {
namespace Media {
struct MovingPhotoInfo {
    int32_t fileId{-1};
    std::string path;
    int32_t position{-1};
};

struct MovingPhotoStatistics {
    int32_t movingPhotoTotalCount{0};           // moving photo total count, not include graffiti
    int32_t dirtyMovingPhotoTotalCount{0};      // dirty moving photo total count, not include graffiti
    int32_t movingPhotoNotLocal{0};             // moving photo not local count, not include graffiti
    int32_t cameraAndNotEditAndNotCloud{0};     // camera and not edit and not cloud count, not include graffiti
    int32_t cameraAndEditAndNotCloud{0};        // camera and edit and not cloud count, not include graffiti
    int32_t cameraAndNotEditAndCloud{0};        // camera and not edit and cloud count, not include graffiti
    int32_t cameraAndEditAndCloud{0};           // camera and edit and cloud count, not include graffiti
    int32_t notCameraAndEditAndCloud{0};        // not camera and edit and cloud count, not include graffiti
    int32_t notCameraAndEditAndNotCloud{0};     // not camera and edit and not cloud count, not include graffiti
    int32_t notCameraAndNotEditAndCloud{0};     // not camera and not edit and cloud count, not include graffiti
    int32_t notCameraAndNotEditAndNotCloud{0};  // not camera and not edit and not cloud count, not include graffiti
};

class DfxMovingPhoto {
public:
    static int32_t AbnormalMovingPhotoStatistics();

private:
    static int32_t QueryMovingPhotoCount(const int32_t startFileId);
    static std::vector<MovingPhotoInfo> QueryMovingPhotos(const int32_t startFileId);
    static void StatisticsMovingPhotos(
        const std::vector<MovingPhotoInfo> &photoInfos, MovingPhotoStatistics &statistics, int32_t &curFileId);
    static void UpdateStatisticsFromXml(
        const std::shared_ptr<NativePreferences::Preferences> prefs, MovingPhotoStatistics &statistics);
    static void WriteStatisticsToXml(
        const std::shared_ptr<NativePreferences::Preferences> prefs, const MovingPhotoStatistics &statistics);
    static int32_t Report(const MovingPhotoStatistics &statistics);

private:
    static std::mutex mutex_;
    static bool statisticsFinished_;
};
}  // namespace Media
}  // namespace OHOS

#endif  // OHOS_MEDIA_DFX_MOVING_PHOTO_H