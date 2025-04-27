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

#ifndef INTERFACES_INNERAPI_MEDIA_LIBRARY_HELPER_INCLUDE_PTP_MEDIALIBRARY_MANAGER_URI_H_
#define INTERFACES_INNERAPI_MEDIA_LIBRARY_HELPER_INCLUDE_PTP_MEDIALIBRARY_MANAGER_URI_H_

#include <string>

namespace OHOS {
namespace Media {
const std::string PTP_MEDIALIBRARY_DATA_URI = "datashare:///media";
const std::string PTP_OPERATION = "ptp_operation";
const std::string PTP_ALBUM_OPERATION = "ptp_album_operation";
const std::string URI_MTP_OPERATION = PTP_MEDIALIBRARY_DATA_URI + "/" + PTP_OPERATION;
const std::string OPRN_UPDATE_OWNER_ALBUM_ID = "update_owner_album_id";

} // namespace Media
} // namespace OHOS

#endif // INTERFACES_INNERAPI_MEDIA_LIBRARY_HELPER_INCLUDE_PTP_MEDIALIBRARY_MANAGER_URI_H_
