/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "medialibrary_trigger_test_utils.h"
#include "media_log.h"

using namespace OHOS::Media::AccurateRefresh;

namespace OHOS {
namespace Media {

static std::shared_ptr<MediaLibraryRdbStore> g_rdbStore = nullptr;

static const std::string CREATE_ALBUM_PLUGIN_TABLE = "\
    CREATE TABLE IF NOT EXISTS album_plugin \
    ( \
        lpath TEXT, \
        album_name TEXT, \
        album_name_en TEXT, \
        bundle_name TEXT, \
        cloud_id TEXT, \
        dual_album_name TEXT, \
        priority INT \
    );";

const static int32_t IMAGE_ALBUM_ID = 1;
const static std::string IMAGE_ALBUM_LPATH = "IMAGE_lpath";
const static int32_t IMAGE_ALBUM_IMAGE_COUNT = 1;
const static int32_t IMAGE_ALBUM_VIDEO_COUNT = 2;
const static std::string IMAGE_ALBUM_NAME = "IMAGE_albumName";
const static std::string IMAGE_ALBUM_URI = PhotoAlbumColumns::ALBUM_URI_PREFIX + std::to_string(IMAGE_ALBUM_ID);
const static int32_t IMAGE_ALBUM_COUNT = 3;
const static std::string IMAGE_ALBUM_COVER_URI = "file://media/Photo/13/VID_1750489859_000/1111.mp4";
const static int32_t IMAGE_ALBUM_HIDDEN_COUNT = 4;
const static std::string IMAGE_ALBUM_HIDDEN_COVER_URI = "file://media/Photo/14/VID_1750489859_000/1111.mp4";
const static int64_t IMAGE_ALBUM_COVER_DATE_TIME = 555555;
const static int64_t IMAGE_ALBUM_HIDDEN_COVER_DATE_TIME = 555555;

static NativeRdb::ValuesBucket GetPhotoAlbumInsertValue(
    const AlbumChangeInfo &albumInfo)
{
    NativeRdb::ValuesBucket value;
    value.PutInt(PhotoAlbumColumns::ALBUM_TYPE, albumInfo.albumType_);
    value.PutInt(PhotoAlbumColumns::ALBUM_SUBTYPE, albumInfo.albumSubType_);
    value.PutInt(PhotoAlbumColumns::ALBUM_IMAGE_COUNT, albumInfo.imageCount_);
    value.PutInt(PhotoAlbumColumns::ALBUM_VIDEO_COUNT, albumInfo.videoCount_);
    value.PutString(PhotoAlbumColumns::ALBUM_COVER_URI, albumInfo.coverUri_);
    value.PutInt(PhotoAlbumColumns::HIDDEN_COUNT, albumInfo.hiddenCount_);
    value.PutString(PhotoAlbumColumns::HIDDEN_COVER, albumInfo.hiddenCoverUri_);
    value.PutLong(PhotoAlbumColumns::COVER_DATE_TIME, albumInfo.coverDateTime_);
    value.PutLong(PhotoAlbumColumns::HIDDEN_COVER_DATE_TIME, albumInfo.hiddenCoverDateTime_);
    value.PutInt(PhotoAlbumColumns::ALBUM_DIRTY, albumInfo.dirty_);
    value.PutString(PhotoAlbumColumns::ALBUM_NAME, albumInfo.albumName_);
    value.PutString(PhotoAlbumColumns::ALBUM_LPATH, albumInfo.lpath_);
    return value;
}

const AlbumChangeInfo MediaLibraryTriggerTestUtils::SOURCE_ALBUM_INFO = {
    IMAGE_ALBUM_ID, IMAGE_ALBUM_LPATH, IMAGE_ALBUM_IMAGE_COUNT, IMAGE_ALBUM_VIDEO_COUNT,
    PhotoAlbumType::SOURCE, PhotoAlbumSubType::SOURCE_GENERIC, IMAGE_ALBUM_NAME, IMAGE_ALBUM_URI,
    IMAGE_ALBUM_COUNT, IMAGE_ALBUM_COVER_URI, IMAGE_ALBUM_HIDDEN_COUNT, IMAGE_ALBUM_HIDDEN_COVER_URI,
    false, false, IMAGE_ALBUM_COVER_DATE_TIME, IMAGE_ALBUM_HIDDEN_COVER_DATE_TIME,
    static_cast<int32_t>(DirtyType::TYPE_NEW)
};

void MediaLibraryTriggerTestUtils::SetRdbStore(std::shared_ptr<MediaLibraryRdbStore> rdbStore)
{
    g_rdbStore = rdbStore;
}

void MediaLibraryTriggerTestUtils::SetTables()
{
    std::vector<std::string> createTableSqlList = {
        PhotoColumn::CREATE_PHOTO_TABLE,
        PhotoAlbumColumns::CREATE_TABLE,
        CREATE_ALBUM_PLUGIN_TABLE
    };
    for (auto &createTableSql : createTableSqlList) {
        if (g_rdbStore == nullptr) {
            MEDIA_ERR_LOG("can not get g_rdbstore");
            return;
        }
        int32_t ret = g_rdbStore->ExecuteSql(createTableSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Execute sql %{public}s failed", createTableSql.c_str());
            return;
        }
        MEDIA_INFO_LOG("Execute sql %{public}s success", createTableSql.c_str());
    }
    MEDIA_INFO_LOG("SetTables");
}

void MediaLibraryTriggerTestUtils::ClearTables()
{
    vector<string> dropTableList = {
        PhotoAlbumColumns::TABLE,
        PhotoColumn::PHOTOS_TABLE,
        ALBUM_PLUGIN_TABLE
    };
    for (auto &dropTable : dropTableList) {
        string dropSql = "DROP TABLE IF EXISTS " + dropTable + ";";
        int32_t ret = g_rdbStore->ExecuteSql(dropSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Drop %{public}s table failed", dropTable.c_str());
            return;
        }
        MEDIA_INFO_LOG("Drop %{public}s table success", dropTable.c_str());
    }
}


void MediaLibraryTriggerTestUtils::PrepareData()
{
    std::vector<NativeRdb::ValuesBucket> values;
    values.push_back(GetPhotoAlbumInsertValue(SOURCE_ALBUM_INFO));

    int64_t insertNums = 0;
    auto ret = g_rdbStore->BatchInsert(insertNums, PhotoAlbumColumns::TABLE, values);
    MEDIA_INFO_LOG("ret: %{public}d, insert values: %{public}" PRId64, ret, insertNums);
}

void MediaLibraryTriggerTestUtils::RemoveData()
{
    MEDIA_INFO_LOG("RemoveData start");
    NativeRdb::RdbPredicates alumPredicates(PhotoAlbumColumns::TABLE);
    
    int deleteRows = 0;
    g_rdbStore->Delete(deleteRows, alumPredicates);
    MEDIA_INFO_LOG("delete album: %{public}d", deleteRows);

    NativeRdb::RdbPredicates photosPredicates(PhotoColumn::PHOTOS_TABLE);
    g_rdbStore->Delete(deleteRows, photosPredicates);
    MEDIA_INFO_LOG("delete Photos: %{public}d", deleteRows);

    NativeRdb::RdbPredicates albumPluginPredicates(ALBUM_PLUGIN_TABLE);
    g_rdbStore->Delete(deleteRows, albumPluginPredicates);
    MEDIA_INFO_LOG("delete album_plugin: %{public}d", deleteRows);
    MEDIA_INFO_LOG("RemoveData end");
}
} // namespace Media
} // namespace OHOS