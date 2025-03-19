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

#ifndef CLOUD_MEDIA_ASSET_URI_H
#define CLOUD_MEDIA_ASSET_URI_H
#include "base_data_uri.h"

namespace OHOS {
namespace Media {
const std::string CLOUD_MEDIA_ASSET_OPERATE = "cloud_media_asset_operate";

const std::string CLOUD_MEDIA_ASSET_TASK_START_FORCE = "cloud_media_asset_task_start_force";
const std::string CLOUD_MEDIA_ASSET_TASK_START_GENTLE = "cloud_media_asset_task_start_gentle";
const std::string CLOUD_MEDIA_ASSET_TASK_PAUSE = "cloud_media_asset_task_pause";
const std::string CLOUD_MEDIA_ASSET_TASK_CANCEL = "cloud_media_asset_task_cancel";
const std::string CLOUD_MEDIA_ASSET_TASK_RETAIN_FORCE = "cloud_media_asset_task_retain_force";
const std::string CLOUD_MEDIA_ASSET_TASK_STATUS_QUERY = "cloud_media_asset_task_status_query";

const std::string CMAM_CLOUD_MEDIA_ASSET_TASK_START_FORCE = MEDIALIBRARY_DATA_URI + "/" + CLOUD_MEDIA_ASSET_OPERATE +
    "/" + CLOUD_MEDIA_ASSET_TASK_START_FORCE;
const std::string CMAM_CLOUD_MEDIA_ASSET_TASK_START_GENTLE = MEDIALIBRARY_DATA_URI + "/" + CLOUD_MEDIA_ASSET_OPERATE +
    "/" + CLOUD_MEDIA_ASSET_TASK_START_GENTLE;
const std::string CMAM_CLOUD_MEDIA_ASSET_TASK_PAUSE = MEDIALIBRARY_DATA_URI + "/" + CLOUD_MEDIA_ASSET_OPERATE + "/" +
    CLOUD_MEDIA_ASSET_TASK_PAUSE;
const std::string CMAM_CLOUD_MEDIA_ASSET_TASK_CANCEL = MEDIALIBRARY_DATA_URI + "/" + CLOUD_MEDIA_ASSET_OPERATE + "/" +
    CLOUD_MEDIA_ASSET_TASK_CANCEL;
const std::string CMAM_CLOUD_MEDIA_ASSET_TASK_RETAIN_FORCE = MEDIALIBRARY_DATA_URI + "/" + CLOUD_MEDIA_ASSET_OPERATE +
    "/" + CLOUD_MEDIA_ASSET_TASK_RETAIN_FORCE;
const std::string CMAM_CLOUD_MEDIA_ASSET_TASK_STATUS_QUERY = MEDIALIBRARY_DATA_URI + "/" + CLOUD_MEDIA_ASSET_OPERATE +
    "/" + CLOUD_MEDIA_ASSET_TASK_STATUS_QUERY;
} // namespace Media
} // namespace OHOS

#endif // CLOUD_MEDIA_ASSET_URI_H