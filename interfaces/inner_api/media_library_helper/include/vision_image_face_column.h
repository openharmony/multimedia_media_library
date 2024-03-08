/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_SERVICES_MEDIA_MULTI_STAGES_CAPTURE_INCLUDE_VISION_IMAGE_FACE_COLUMN_H
#define FRAMEWORKS_SERVICES_MEDIA_MULTI_STAGES_CAPTURE_INCLUDE_VISION_IMAGE_FACE_COLUMN_H

#include "vision_column_comm.h"

namespace OHOS {
namespace Media {
const std::string FACE_ID = "face_id";
const std::string TAG_ID = "tag_id";
const std::string SCALE_X = "scale_x";
const std::string SCALE_Y = "scale_y";
const std::string SCALE_WIDTH = "scale_width";
const std::string SCALE_HEIGHT = "scale_height";
const std::string LANDMARKS = "landmarks";
const std::string PITCH = "pitch";
const std::string YAW = "yaw";
const std::string ROLL = "roll";
const std::string TOTAL_FACES = "total_faces";
const std::string FEATURES = "features";
const std::string IMAGE_FACE_VERSION = "face_version";
const std::string IMAGE_FEATURES_VERSION = "features_version";
} // namespace Media
} // namespace OHOS
#endif  // FRAMEWORKS_SERVICES_MEDIA_MULTI_STAGES_CAPTURE_INCLUDE_VISION_IMAGE_FACE_COLUMN_H