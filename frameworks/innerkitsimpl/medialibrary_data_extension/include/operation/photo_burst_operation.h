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

#ifndef OHOS_MEDIA_PHOTO_BURST_OPERATIOIN_H
#define OHOS_MEDIA_PHOTO_BURST_OPERATIOIN_H

#include <string>
#include <vector>

#include "medialibrary_rdbstore.h"
#include "rdb_store.h"

namespace OHOS::Media {
class PhotoBurstOperation {
private:
    struct PhotoAssetInfo {
        std::string displayName;
        int32_t subtype;
        int32_t ownerAlbumId;
        std::string burstGroupName;
    };

public:
    std::string FindBurstKey(const std::shared_ptr<MediaLibraryRdbStore> rdbStore,
        const std::shared_ptr<NativeRdb::ResultSet> &resultSet, const int32_t targetAlbumId,
        const std::string &uniqueDisplayName);

private:
    std::string FindBurstKey(const std::shared_ptr<MediaLibraryRdbStore> rdbStore,
        const PhotoAssetInfo &photoAssetInfo);
    std::string ToString(const PhotoAssetInfo &photoInfo);
    std::string ToString(const std::vector<NativeRdb::ValueObject> &values);
    std::string GenerateUuid();
    std::string FindBurstGroupName(const std::string &displayName);
    std::string QueryBurstKeyFromDB(const std::shared_ptr<MediaLibraryRdbStore> rdbStore,
        const PhotoAssetInfo &photoAssetInfo);

private:
    enum { UUID_STR_LENGTH = 37, DISPLAY_NAME_PREFIX_LENGTH = 20 };
    const std::string TITLE_KEY_WORDS_OF_BURST = "_BURST";
    std::string SQL_PHOTOS_TABLE_QUERY_BURST_KEY = "\
        SELECT \
            burst_key \
        FROM Photos \
        WHERE subtype = 4 AND \
            COALESCE(burst_key, '') <> '' AND \
            COALESCE(date_trashed, 0) = 0 AND \
            owner_album_id = ? AND \
            display_name LIKE ? \
        ORDER BY file_id \
        LIMIT 1;";
};
}  // namespace OHOS::Media
#endif  // OHOS_MEDIA_PHOTO_BURST_OPERATIOIN_H