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

#ifndef FRAMEWORKS_SERVICES_MEDIA_MULTI_STAGES_CAPTURE_INCLUDE_MEDIA_DEVICE_COLUMN_H
#define FRAMEWORKS_SERVICES_MEDIA_MULTI_STAGES_CAPTURE_INCLUDE_MEDIA_DEVICE_COLUMN_H

#include <string>

namespace OHOS {
namespace Media {
const std::string DEVICE_DB_ID = "id";
const std::string DEVICE_DB_UDID = "device_udid";
const std::string DEVICE_DB_NETWORK_ID = "network_id";
const std::string DEVICE_DB_NAME = "device_name";
const std::string DEVICE_DB_IP = "device_ip";
const std::string DEVICE_DB_SYNC_STATUS = "sync_status";
const std::string DEVICE_DB_PHOTO_SYNC_STATUS = "photo_table_sync_status";
const std::string DEVICE_DB_SELF_ID = "self_id";
const std::string DEVICE_DB_TYPE = "device_type";
const std::string DEVICE_DB_PREPATH = "pre_path";
const std::string DEVICE_DB_DATE_ADDED = "date_added";
const std::string DEVICE_DB_DATE_MODIFIED = "date_modified";
} // namespace Media
} // namespace OHOS
#endif  // FRAMEWORKS_SERVICES_MEDIA_MULTI_STAGES_CAPTURE_INCLUDE_MEDIA_DEVICE_COLUMN_H