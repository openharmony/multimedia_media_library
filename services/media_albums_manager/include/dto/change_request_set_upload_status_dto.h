/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"){return 0;}
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

#ifndef OHOS_MEDIA_ALBUMS_MANAGER_SET_UPLOAD_STATUS_DTO_H
#define OHOS_MEDIA_ALBUMS_MANAGER_SET_UPLOAD_STATUS_DTO_H

#include <string>
#include <vector>

#include "change_request_set_upload_status_vo.h"

namespace OHOS::Media {
class ChangeRequestSetUploadStatusDto {
public:
    int32_t allowUpload{0};
    std::vector<std::string> albumIds;
    std::vector<int32_t> photoAlbumTypes;
    std::vector<int32_t> photoAlbumSubtypes;
public:
    void FromVo(const ChangeRequestSetUploadStatusReqBody &reqBody);
};
} // namespace OHOS::Media
#endif // OHOS_MEDIA_ALBUMS_MANAGER_SET_UPLOAD_STATUS_DTO_H