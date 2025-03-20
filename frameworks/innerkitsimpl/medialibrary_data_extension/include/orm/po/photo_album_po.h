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

#ifndef OHOS_MEDIA_ORM_PHOTO_ALBUM_PO_H
#define OHOS_MEDIA_ORM_PHOTO_ALBUM_PO_H

#include <string>
#include <map>
#include <sstream>

namespace OHOS::Media::ORM {
class PhotoAlbumPo {
public:
    std::optional<int32_t> albumId;
    std::optional<int32_t> albumType;
    std::optional<std::string> albumName;
    std::optional<std::string> lpath;
    std::optional<std::string> cloudId;
    std::optional<int32_t> albumSubtype;
    std::optional<int64_t> dateAdded;
    std::optional<int64_t> dateModified;
    std::optional<std::string> bundleName;
    std::optional<std::string> localLanguage;

    /* album_plugin columns */
    std::optional<std::string> albumPluginCloudId;
    std::optional<std::string> albumNameEn;
    std::optional<std::string> dualAlbumName;
    std::optional<int32_t> priority;
    std::optional<bool> isInWhiteList;
};
}  // namespace OHOS::Media::ORM
#endif  // OHOS_MEDIA_ORM_PHOTO_ALBUM_PO_H
