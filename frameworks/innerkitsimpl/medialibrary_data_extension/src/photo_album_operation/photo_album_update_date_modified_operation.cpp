/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#define MLOG_TAG "PhotoAlbumUpdateDateModifiedOperation"

#include "photo_album_update_date_modified_operation.h"

#include "media_log.h"
#include "medialibrary_errno.h"
#include "result_set_utils.h"

namespace OHOS::Media {
const std::string SQL_QUERY_COUNT_ALBUM_DATE_NEED_FIX = "\
    SELECT COUNT(*) AS count FROM PhotoAlbum \
    WHERE album_type != 1024 AND \
        dirty != 4 AND \
        ( \
            COALESCE(date_modified, 0) = 0 OR \
            COALESCE(date_added, 0) = 0 \
        ) \
    ;";

const std::string SQL_UPDATE_ALBUM_DATE_NEED_FIX = "\
    UPDATE PhotoAlbum \
    SET date_modified = \
        CASE \
            WHEN COALESCE(date_modified, 0) = 0 THEN strftime('%s000', 'now') \
            ELSE date_modified \
        END, \
        date_added = \
        CASE \
            WHEN COALESCE(date_added, 0) = 0 THEN strftime('%s000', 'now') \
            ELSE date_added \
        END, \
        dirty = \
        CASE \
            WHEN COALESCE(cloud_id, '') != '' THEN 2 \
            ELSE dirty \
        END \
    WHERE album_type != 1024 AND \
        dirty != 4 AND \
        ( \
            COALESCE(date_modified, 0) = 0 OR \
            COALESCE(date_added, 0) = 0 \
        ) \
    ;";

bool PhotoAlbumUpdateDateModifiedOperation::CheckAlbumDateNeedFix(
    const std::shared_ptr<MediaLibraryRdbStore> &rdbStore)
{
    auto resultSet = rdbStore->QuerySql(SQL_QUERY_COUNT_ALBUM_DATE_NEED_FIX);
    bool cond = (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK);
    CHECK_AND_RETURN_RET_LOG(!cond, false, "Query count of album date need fix failed");

    if (GetInt32Val("count", resultSet) <= 0) {
        MEDIA_DEBUG_LOG("no album date need fix");
        return false;
    }

    MEDIA_INFO_LOG("album date need fix");
    return true;
}

void PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(
    const std::shared_ptr<MediaLibraryRdbStore> &rdbStore)
{
    int32_t errCode = rdbStore->ExecuteSql(SQL_UPDATE_ALBUM_DATE_NEED_FIX);
    CHECK_AND_RETURN_LOG(errCode == NativeRdb::E_OK,
        "Fix album date need fix failed, errCode:%{public}d", errCode);
    MEDIA_INFO_LOG("album date fix success");
}

int32_t PhotoAlbumUpdateDateModifiedOperation::UpdateAlbumDateNeedFix(NativeRdb::RdbStore &rdbStore)
{
    int32_t errCode = rdbStore.ExecuteSql(SQL_UPDATE_ALBUM_DATE_NEED_FIX);
    CHECK_AND_RETURN_RET_LOG(errCode == NativeRdb::E_OK, errCode,
        "Fix album date need fix failed, errCode:%{public}d", errCode);
    MEDIA_INFO_LOG("album date fix success");
    return NativeRdb::E_OK;
}

}  // namespace OHOS::Media