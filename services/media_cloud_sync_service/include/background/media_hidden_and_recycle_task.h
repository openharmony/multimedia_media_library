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

#ifndef OHOS_MEDIA_BACKGROUND_MEDIA_HIDDEN_AND_RECYCLE_TASK_H
#define OHOS_MEDIA_BACKGROUND_MEDIA_HIDDEN_AND_RECYCLE_TASK_H

#include <string>

#include "i_media_background_task.h"

namespace OHOS::Media::Background {
class MediaHiddenAndRecycleTask : public IMediaBackGroundTask {
public:
    virtual ~MediaHiddenAndRecycleTask() = default;

public:
    bool Accept() override;
    void Execute() override;

private:
    void HandleMediaHidden();
    void HandleMediaRecycle();

private:
    const std::string COLUMN_NAME_COUNT = "count";
    const std::string SQL_PHOTOS_TABLE_HIDDEN_RELATION_QUERY = "\
        SELECT count(1) AS count \
        FROM Photos \
        WHERE owner_album_id = \
            ( \
                SELECT album_id \
                FROM PhotoAlbum \
                WHERE LOWER(lpath) = LOWER('/Pictures/其它') \
                LIMIT 1 \
            ) AND \
            source_path NOT LIKE '/storage/emulated/0/Pictures/其它%' AND \
            hidden = 1 AND \
            date_trashed = 0;";
    const std::string SQL_PHOTOS_TABLE_HIDDEN_RELATION_MAINTAIN = "\
        UPDATE Photos \
        SET owner_album_id = -4 \
        WHERE owner_album_id = \
            ( \
                SELECT album_id \
                FROM PhotoAlbum \
                WHERE LOWER(lpath) = LOWER('/Pictures/其它') \
                LIMIT 1 \
            ) AND \
            source_path NOT LIKE '/storage/emulated/0/Pictures/其它%' AND \
            hidden = 1 AND \
            date_trashed = 0;";
    const std::string SQL_PHOTOS_TABLE_RECYCLE_RELATION_QUERY = "\
        SELECT count(1) AS count \
        FROM Photos \
        WHERE owner_album_id = \
            ( \
                SELECT album_id \
                FROM PhotoAlbum \
                WHERE LOWER(lpath) = LOWER('/Pictures/其它') \
                LIMIT 1 \
            ) AND \
            source_path NOT LIKE '/storage/emulated/0/Pictures/其它%' AND \
            date_trashed <> 0;";
    const std::string SQL_PHOTOS_TABLE_RECYCLE_RELATION_MAINTAIN = "\
        UPDATE Photos \
        SET owner_album_id = -3 \
        WHERE owner_album_id = \
            ( \
                SELECT album_id \
                FROM PhotoAlbum \
                WHERE LOWER(lpath) = LOWER('/Pictures/其它') \
                LIMIT 1 \
            ) AND \
            source_path NOT LIKE '/storage/emulated/0/Pictures/其它%' AND \
            date_trashed <> 0;";
};
}  // namespace OHOS::Media::Background
#endif  // OHOS_MEDIA_BACKGROUND_MEDIA_HIDDEN_AND_RECYCLE_TASK_H