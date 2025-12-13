/*
 * Copyright (C) 2022-2025 Huawei Device Co., Ltd.
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
 
#ifndef OHOS_CAMERA_CHARATER_TYPES_H
#define OHOS_CAMERA_CHARATER_TYPES_H
 
#include <limits>
#include <string>
#include <tuple>
#include <vector>
 
namespace OHOS {
namespace Media {
enum class CameraCharacterType : int32_t {
    IMAGE_START = 0,
    IMAGE_YUV = 1,
    IMAGE_NON_YUV = 2,
    IMAGE_MOVING_PHOTO = 3,
    IMAGE_BURST = 4,
    IMAGE_END,      // the end of image
 
    VIDEO_START = 100,
    VIDEO = 101,
    VIDEO_MOVING_PHOTO = 102,
    VIDEO_CINEMATIC_PHOTO = 103,
    VIDEO_END,      // the end of video
};
 
enum class ObserverType : int32_t {
    UNDEFINED = 0,
    REQUEST_IMAGE,
    REQUEST_VIDEO,
    REQUEST_QUICK_IMAGE,
    OBSERVER_END,
};
 
enum class MultistagesCaptureNotifyType : int32_t {
    UNDEFINED = 0,
    ON_PROCESS_IMAGE_DONE,
    ON_ERROR_IMAGE,
    ON_PROCESS_VIDEO_DONE,
    ON_ERROR_VIDEO,
    YUV_READY,
    NOTIFY_END,
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_FILEMANAGEMENT_USERFILEMGR_TYPES_H