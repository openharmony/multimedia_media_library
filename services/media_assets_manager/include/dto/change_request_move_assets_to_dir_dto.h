/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_ASSETS_MANAGER_MOVE_ASSETS_TO_DIR_DTO_H
#define OHOS_MEDIA_ASSETS_MANAGER_MOVE_ASSETS_TO_DIR_DTO_H

#include <string>
#include <sstream>

#include "userfile_manager_types.h"

#include "change_request_move_assets_to_dir_vo.h"
#include "media_progress_change_info.h"

namespace OHOS::Media {
class ChangeRequestMoveAssetsToDirDto {
public:
    std::vector<std::string> assets;
    std::string targetDir {""};
    int32_t requestId {0};
    int32_t errCode {0};
    std::vector<std::string> resultList;
    int32_t mode {0};
    std::shared_ptr<Notification::MediaProgressChangeInfo> changeInfo;
public:
    void FromVo(const ChangeRequestMoveAssetsToDirReqBody& reqBody);
};
}  // namespace OHOS::Media
#endif // OHOS_MEDIA_ASSETS_MANAGER_CHANGE_REQUEST_MOVE_ASSETS_DTO_H