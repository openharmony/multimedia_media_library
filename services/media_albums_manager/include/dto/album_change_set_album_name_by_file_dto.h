/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_ASSETS_MANAGER_ALBUM_CHANGE_SET_ALBUM_NAME_BY_FILE_DTO_H
#define OHOS_MEDIA_ASSETS_MANAGER_ALBUM_CHANGE_SET_ALBUM_NAME_BY_FILE_DTO_H

#include <string>
#include <sstream>
#include "album_change_set_album_name_by_file_vo.h"

namespace OHOS::Media {
class AlbumChangeSetAlbumNameByFileDto {
public:
    int32_t albumId {};
    std::string albumName;
    int32_t albumType {};
    int32_t albumSubType {};

    void FromVo(const AlbumChangeSetAlbumNameByFileReqBody &reqBody);
};
} // namespace OHOS::Media
#endif // OHOS_MEDIA_ASSETS_MANAGER_ALBUM_CHANGE_SET_ALBUM_NAME_BY_FILE_DTO_H