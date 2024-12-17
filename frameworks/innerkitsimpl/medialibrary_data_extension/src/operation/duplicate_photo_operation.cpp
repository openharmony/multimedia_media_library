/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define MLOG_TAG "DuplicatePhotoOperation"

#include "duplicate_photo_operation.h"

#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_tracer.h"
#include "medialibrary_unistore_manager.h"

namespace OHOS {
namespace Media {
std::once_flag DuplicatePhotoOperation::onceFlag_;

const std::string ASTERISK = "*";

const std::string SELECT_COLUMNS = "SELECT_COLUMNS";

const std::string IDX_DUPLICATE_ASSETS = "\
    CREATE INDEX \
    IF \
      NOT EXISTS idx_duplicate_assets ON Photos (title, size, orientation)";

const std::string SQL_QUERY_ALL_DUPLICATE_ASSETS = "\
    SELECT\
      SELECT_COLUMNS \
    FROM\
      Photos\
      INNER JOIN (\
      SELECT\
        title,\
        size,\
        orientation \
      FROM\
        Photos \
      WHERE\
        date_trashed = 0 \
        AND hidden = 0 \
        AND time_pending = 0 \
        AND is_temp = 0 \
        AND burst_cover_level = 1 \
        AND media_type = 1 \
      GROUP BY\
        title,\
        size,\
        orientation \
      HAVING\
        count(*) > 1 \
      ) AS IMG ON Photos.title = IMG.title \
      AND Photos.size = IMG.size \
      AND Photos.orientation = IMG.orientation \
    WHERE\
      date_trashed = 0 \
      AND hidden = 0 \
      AND time_pending = 0 \
      AND is_temp = 0 \
      AND burst_cover_level = 1 UNION\
    SELECT\
      SELECT_COLUMNS \
    FROM\
      Photos\
      INNER JOIN (\
      SELECT\
        title,\
        size \
      FROM\
        Photos \
      WHERE\
        date_trashed = 0 \
        AND hidden = 0 \
        AND time_pending = 0 \
        AND is_temp = 0 \
        AND burst_cover_level = 1 \
        AND media_type = 2 \
      GROUP BY\
        title,\
        size \
      HAVING\
        count(*) > 1 \
      ) AS VID ON Photos.title = VID.title \
      AND Photos.size = VID.size \
    WHERE\
      date_trashed = 0 \
      AND hidden = 0 \
      AND time_pending = 0 \
      AND is_temp = 0 \
      AND burst_cover_level = 1 \
    ORDER BY\
      Photos.title,\
      Photos.size,\
      Photos.orientation \
      LIMIT ? OFFSET ? ";

const std::string SQL_QUERY_ALL_DUPLICATE_ASSETS_COUNT = "\
    SELECT\
      count(*) \
    FROM\
      (\
      SELECT\
        file_id \
      FROM\
        Photos\
        INNER JOIN (\
        SELECT\
          title,\
          size,\
          orientation \
        FROM\
          Photos \
        WHERE\
          date_trashed = 0 \
          AND hidden = 0 \
          AND time_pending = 0 \
          AND is_temp = 0 \
          AND burst_cover_level = 1 \
          AND media_type = 1 \
        GROUP BY\
          title,\
          size,\
          orientation \
        HAVING\
          count(*) > 1 \
        ) AS IMG ON Photos.title = IMG.title \
        AND Photos.size = IMG.size \
        AND Photos.orientation = IMG.orientation \
      WHERE\
        date_trashed = 0 \
        AND hidden = 0 \
        AND time_pending = 0 \
        AND is_temp = 0 \
        AND burst_cover_level = 1 UNION\
      SELECT\
        file_id \
      FROM\
        Photos\
        INNER JOIN (\
        SELECT\
          title,\
          size \
        FROM\
          Photos \
        WHERE\
          date_trashed = 0 \
          AND hidden = 0 \
          AND time_pending = 0 \
          AND is_temp = 0 \
          AND burst_cover_level = 1 \
          AND media_type = 2 \
        GROUP BY\
          title,\
          size \
        HAVING\
          count(*) > 1 \
        ) AS VID ON Photos.title = VID.title \
        AND Photos.size = VID.size \
      WHERE\
        date_trashed = 0 \
        AND hidden = 0 \
        AND time_pending = 0 \
        AND is_temp = 0 \
        AND burst_cover_level = 1 \
      ) ";

const std::string SQL_QUERY_CAN_DEL_DUPLICATE_ASSETS = "\
    SELECT\
      SELECT_COLUMNS \
    FROM\
      (\
      SELECT\
        SELECT_COLUMNS,\
        ROW_NUMBER( ) OVER (\
          PARTITION BY title,\
          size,\
          orientation \
        ORDER BY\
        CASE\
            WHEN album_id != NULL THEN\
            0 ELSE 1 \
          END ASC,\
        CASE\
            WHEN lpath = '/DCIM/Camera' THEN\
            0 \
            WHEN lpath = '/Pictures/Screenshots' THEN\
            1 \
            WHEN lpath = '/Pictures/Screenrecords' THEN\
            2 \
            WHEN lpath = '/Pictures/WeiXin' THEN\
            3 \
            WHEN lpath IN ( '/Pictures/WeChat', '/tencent/MicroMsg/WeChat', '/Tencent/MicroMsg/WeiXin' ) THEN\
            4 ELSE 5 \
        END ASC \
        ) AS img_row_num \
      FROM\
        Photos\
        LEFT JOIN PhotoAlbum ON Photos.owner_album_id = PhotoAlbum.album_id \
      WHERE\
        date_trashed = 0 \
        AND hidden = 0 \
        AND time_pending = 0 \
        AND is_temp = 0 \
        AND burst_cover_level = 1 \
        AND media_type = 1 \
      ) \
    WHERE\
      img_row_num > 1 UNION\
    SELECT\
      SELECT_COLUMNS \
    FROM\
      (\
      SELECT\
        SELECT_COLUMNS,\
        ROW_NUMBER( ) OVER (\
          PARTITION BY title,\
          size \
        ORDER BY\
        CASE\
            WHEN album_id != NULL THEN\
            0 ELSE 1 \
          END ASC,\
        CASE\
            WHEN lpath = '/DCIM/Camera' THEN\
            0 \
            WHEN lpath = '/Pictures/Screenshots' THEN\
            1 \
            WHEN lpath = '/Pictures/Screenrecords' THEN\
            2 \
            WHEN lpath = '/Pictures/WeiXin' THEN\
            3 \
            WHEN lpath IN ( '/Pictures/WeChat', '/tencent/MicroMsg/WeChat', '/Tencent/MicroMsg/WeiXin' ) THEN\
            4 ELSE 5 \
        END ASC \
        ) AS vid_row_num \
      FROM\
        Photos\
        LEFT JOIN PhotoAlbum ON Photos.owner_album_id = PhotoAlbum.album_id \
      WHERE\
        date_trashed = 0 \
        AND hidden = 0 \
        AND time_pending = 0 \
        AND is_temp = 0 \
        AND burst_cover_level = 1 \
        AND media_type = 2 \
      ) \
    WHERE\
      vid_row_num > 1 \
    ORDER BY\
      title,\
      size,\
      orientation \
      LIMIT ? OFFSET ? ";

const std::string SQL_QUERY_CAN_DEL_DUPLICATE_ASSETS_COUNT = "\
    SELECT\
      count(*) \
    FROM\
      (\
      SELECT\
        file_id \
      FROM\
        (\
        SELECT\
          file_id,\
          ROW_NUMBER( ) OVER (\
            PARTITION BY title,\
            size,\
            orientation \
          ORDER BY\
          CASE\
              WHEN album_id != NULL THEN\
              0 ELSE 1 \
            END ASC,\
          CASE\
              WHEN lpath = '/DCIM/Camera' THEN\
              0 \
              WHEN lpath = '/Pictures/Screenshots' THEN\
              1 \
              WHEN lpath = '/Pictures/Screenrecords' THEN\
              2 \
              WHEN lpath = '/Pictures/WeiXin' THEN\
              3 \
              WHEN lpath IN ( '/Pictures/WeChat', '/tencent/MicroMsg/WeChat', '/Tencent/MicroMsg/WeiXin' ) THEN\
              4 ELSE 5 \
          END ASC \
          ) AS img_row_num \
        FROM\
          Photos\
          LEFT JOIN PhotoAlbum ON Photos.owner_album_id = PhotoAlbum.album_id \
        WHERE\
          date_trashed = 0 \
          AND hidden = 0 \
          AND time_pending = 0 \
          AND is_temp = 0 \
          AND burst_cover_level = 1 \
          AND media_type = 1 \
        ) \
      WHERE\
        img_row_num > 1 UNION\
      SELECT\
        file_id \
      FROM\
        (\
        SELECT\
          file_id,\
          ROW_NUMBER( ) OVER (\
            PARTITION BY title,\
            size \
          ORDER BY\
          CASE\
              WHEN album_id != NULL THEN\
              0 ELSE 1 \
            END ASC,\
          CASE\
              WHEN lpath = '/DCIM/Camera' THEN\
              0 \
              WHEN lpath = '/Pictures/Screenshots' THEN\
              1 \
              WHEN lpath = '/Pictures/Screenrecords' THEN\
              2 \
              WHEN lpath = '/Pictures/WeiXin' THEN\
              3 \
              WHEN lpath IN ( '/Pictures/WeChat', '/tencent/MicroMsg/WeChat', '/Tencent/MicroMsg/WeiXin' ) THEN\
              4 ELSE 5 \
          END ASC \
          ) AS vid_row_num \
        FROM\
          Photos\
          LEFT JOIN PhotoAlbum ON Photos.owner_album_id = PhotoAlbum.album_id \
        WHERE\
          date_trashed = 0 \
          AND hidden = 0 \
          AND time_pending = 0 \
          AND is_temp = 0 \
          AND burst_cover_level = 1 \
          AND media_type = 2 \
        ) \
      WHERE\
      vid_row_num > 1 \
      ) ";

std::string DuplicatePhotoOperation::GetSelectColumns(const std::unordered_set<std::string> &columns)
{
    if (columns.empty()) {
        return ASTERISK;
    }

    std::string selectColumns;
    bool first = true;
    for (const std::string &column : columns) {
        if (!first) {
            selectColumns += ", ";
        } else {
            first = false;
        }
        selectColumns += column;
    }

    return selectColumns;
}

std::shared_ptr<NativeRdb::ResultSet> DuplicatePhotoOperation::GetAllDuplicateAssets(
    const std::vector<std::string> &columns, const int offset, const int limit)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("GetAllDuplicateAssets failed, rdbStore is nullptr");
        return nullptr;
    }
    MediaLibraryTracer tracer;
    if (find(columns.begin(), columns.end(), MEDIA_COLUMN_COUNT) != columns.end()) {
        tracer.Start("QueryAllDuplicateAssets_count");
        std::call_once(onceFlag_, [&]() { rdbStore->ExecuteSql(IDX_DUPLICATE_ASSETS); });
        return rdbStore->QueryByStep(SQL_QUERY_ALL_DUPLICATE_ASSETS_COUNT);
    }

    tracer.Start("QueryAllDuplicateAssets_records");
    std::unordered_set<std::string> columnSet{ "Photos.file_id", "Photos.title", "Photos.size", "Photos.orientation" };
    for (const auto &column : columns) {
        if (MediaFileUtils::StartsWith(column, "Photos.")) {
            columnSet.insert(column);
        } else {
            columnSet.insert("Photos." + column);
        }
    }

    std::string selectColumns = GetSelectColumns(columnSet);
    std::string sql = SQL_QUERY_ALL_DUPLICATE_ASSETS;
    MediaFileUtils::ReplaceAll(sql, SELECT_COLUMNS, selectColumns);

    const std::vector<NativeRdb::ValueObject> bindArgs{ NativeRdb::ValueObject(limit), NativeRdb::ValueObject(offset) };
    return rdbStore->QueryByStep(sql, bindArgs);
}

std::shared_ptr<NativeRdb::ResultSet> DuplicatePhotoOperation::GetCanDelDuplicateAssets(
    const std::vector<std::string> &columns, const int offset, const int limit)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("GetAllDuplicateAssets failed, rdbStore is nullptr");
        return nullptr;
    }
    MediaLibraryTracer tracer;
    if (find(columns.begin(), columns.end(), MEDIA_COLUMN_COUNT) != columns.end()) {
        tracer.Start("QueryCanDelDuplicateAssets_count");
        return rdbStore->QueryByStep(SQL_QUERY_CAN_DEL_DUPLICATE_ASSETS_COUNT);
    }

    tracer.Start("QueryCanDelDuplicateAssets_records");
    std::unordered_set<std::string> columnSet{ "file_id", "title", "size", "orientation" };
    columnSet.insert(columns.begin(), columns.end());

    std::string selectColumns = GetSelectColumns(columnSet);
    std::string sql = SQL_QUERY_CAN_DEL_DUPLICATE_ASSETS;
    MediaFileUtils::ReplaceAll(sql, SELECT_COLUMNS, selectColumns);

    const std::vector<NativeRdb::ValueObject> bindArgs{ NativeRdb::ValueObject(limit), NativeRdb::ValueObject(offset) };
    return rdbStore->QueryByStep(sql, bindArgs);
}
} // namespace Media
} // namespace OHOS
