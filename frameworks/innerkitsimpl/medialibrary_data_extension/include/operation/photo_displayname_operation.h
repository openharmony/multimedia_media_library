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

#ifndef OHOS_MEDIA_PHOTO_DISPLAYNAME_OPERATIOIN_H
#define OHOS_MEDIA_PHOTO_DISPLAYNAME_OPERATIOIN_H

#include <string>
#include <vector>

#include "result_set_utils.h"
#include "userfile_manager_types.h"
#include "media_column.h"
#include "media_log.h"
#include "photo_asset_info.h"
#include "medialibrary_rdbstore.h"

namespace OHOS::Media {
class PhotoDisplayNameOperation {
public:
    PhotoDisplayNameOperation &SetTargetPhotoInfo(const PhotoAssetInfo &photoAssetInfo);
    std::string FindDisplayName(const std::shared_ptr<MediaLibraryRdbStore> &rdbStore);

private:
    std::string FindDislayName(
        const std::shared_ptr<MediaLibraryRdbStore> &rdbStore, const PhotoAssetInfo &photoAssetInfo);
    bool IsDisplayNameExists(const std::shared_ptr<MediaLibraryRdbStore> rdbStore, const int32_t ownerAlbumId,
        const std::string &displayName);

private:
    PhotoAssetInfo photoAssetInfo_;
    const std::string SQL_PHOTOS_TABLE_QUERY_DISPLAY_NAME = "\
        SELECT \
            DISTINCT owner_album_id \
        FROM Photos \
        WHERE display_name = ?;";
};
}  // namespace OHOS::Media
#endif  // OHOS_MEDIA_PHOTO_DISPLAYNAME_OPERATIOIN_H