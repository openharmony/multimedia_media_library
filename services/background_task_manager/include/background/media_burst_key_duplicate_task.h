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

#ifndef OHOS_MEDIA_BACKGROUND_MEDIA_BURST_KEY_DUPLICATE_TASK_H
#define OHOS_MEDIA_BACKGROUND_MEDIA_BURST_KEY_DUPLICATE_TASK_H

#include <vector>
#include <string>

#include "i_media_background_task.h"

namespace OHOS::Media::Background {
#define EXPORT __attribute__ ((visibility ("default")))

struct BurstKeyDuplicateInfo {
    int32_t ownerAlbumId;
    std::string burstKey;
};

using BurstKeyDuplicateList = std::vector<BurstKeyDuplicateInfo>;

class EXPORT MediaBurstKeyDuplicateTask : public IMediaBackGroundTask {
public:
    virtual ~MediaBurstKeyDuplicateTask() = default;

public:
    bool Accept() override;
    void Execute() override;

private:
    void HandleDuplicateBurstKey();
    BurstKeyDuplicateList FindDuplicateBurstKey();
    int32_t UpdateBurstKey(int32_t ownerAlbumId, const std::string &burstKey);

private:
    const std::string SQL_PHOTOS_TABLE_BURST_KEY_DUPLICATE_QUERY = "\
        WITH Album AS \
        ( \
            SELECT DISTINCT album_id \
            FROM PhotoAlbum \
            WHERE album_type IN (0, 2048) \
        ), BurstGroup AS \
        ( \
            SELECT owner_album_id, burst_key \
            FROM Photos \
            WHERE COALESCE(burst_key, '') <> '' AND \
                burst_cover_level = 1 AND \
                owner_album_id IN ALBUM \
            GROUP BY owner_album_id, burst_key \
        ), BurstDuplicate AS \
        ( \
            SELECT burst_key \
            FROM BurstGroup \
            GROUP BY burst_key \
            HAVING COUNT(1) > 1 \
        ) \
        SELECT \
            BurstGroup.owner_album_id, \
            BurstGroup.burst_key \
        FROM \
            BurstGroup INNER JOIN BurstDuplicate \
            ON BurstGroup.burst_key = BurstDuplicate.burst_key;";
    const std::string SQL_PHOTOS_TABLE_BURST_KEY_UPDATE = "\
        UPDATE Photos \
        SET burst_key = ?, meta_date_modified = strftime('%s000', 'now') \
        WHERE owner_album_id = ? AND \
            burst_key = ?;";
};

}  // namespace OHOS::Media::Background
#endif  // OHOS_MEDIA_BACKGROUND_MEDIA_BURST_KEY_DUPLICATE_TASK_H
