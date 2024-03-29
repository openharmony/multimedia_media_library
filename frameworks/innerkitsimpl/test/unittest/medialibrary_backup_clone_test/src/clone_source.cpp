/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include <utility>

#include "clone_source.h"
#include "medialibrary_unistore.h"
#include "media_column.h"
#include "media_log.h"
#include "photo_album_column.h"
#include "photo_map_column.h"
#include "vision_column.h"
#include "vision_db_sqls.h"

using namespace std;

namespace OHOS {
namespace Media {
enum InsertType {
    PHOTOS = 0,
    PHOTO_ALBUM,
    PHOTO_MAP,
    ANALYSIS_ALBUM,
    ANALYSIS_PHOTO_MAP,
};
const unordered_map<string, string> TABLE_CREATE_MAP = {
    { PhotoColumn::PHOTOS_TABLE, PhotoColumn::CREATE_PHOTO_TABLE },
    { PhotoAlbumColumns::TABLE, PhotoAlbumColumns::CREATE_TABLE },
    { PhotoMap::TABLE, PhotoMap::CREATE_TABLE },
    { ANALYSIS_ALBUM_TABLE, CREATE_ANALYSIS_ALBUM_FOR_ONCREATE },
    { ANALYSIS_PHOTO_MAP_TABLE, CREATE_ANALYSIS_ALBUM_MAP },
};
const unordered_map<string, InsertType> TABLE_INSERT_TYPE_MAP = {
    { PhotoColumn::PHOTOS_TABLE, InsertType::PHOTOS },
    { PhotoAlbumColumns::TABLE, InsertType::PHOTO_ALBUM },
    { PhotoMap::TABLE, InsertType::PHOTO_MAP },
    { ANALYSIS_ALBUM_TABLE, InsertType::ANALYSIS_ALBUM },
    { ANALYSIS_PHOTO_MAP_TABLE, InsertType::ANALYSIS_PHOTO_MAP },
};
const string VALUES_BEGIN = " VALUES (";
const string VALUES_END = ") ";
const string INSERT_PHOTO = "INSERT INTO " + PhotoColumn::PHOTOS_TABLE + "(" + MediaColumn::MEDIA_ID + ", " +
    MediaColumn::MEDIA_FILE_PATH + ", " + MediaColumn::MEDIA_SIZE + ", " + MediaColumn::MEDIA_TITLE + ", " +
    MediaColumn::MEDIA_NAME + ", " + MediaColumn::MEDIA_TYPE + ", " + MediaColumn::MEDIA_OWNER_PACKAGE + ", " +
    MediaColumn::MEDIA_PACKAGE_NAME + ", " + MediaColumn::MEDIA_DATE_ADDED + ", "  +
    MediaColumn::MEDIA_DATE_MODIFIED + ", " + MediaColumn::MEDIA_DATE_TAKEN + ", " +
    MediaColumn::MEDIA_DURATION + ", " + MediaColumn::MEDIA_IS_FAV + ", " + MediaColumn::MEDIA_DATE_TRASHED + ", " +
    MediaColumn::MEDIA_HIDDEN + ", " + PhotoColumn::PHOTO_HEIGHT + ", " + PhotoColumn::PHOTO_WIDTH + ", " +
    PhotoColumn::PHOTO_EDIT_TIME + ", " + PhotoColumn::PHOTO_SHOOTING_MODE + ")";
const string INSERT_PHOTO_ALBUM = "INSERT INTO " + PhotoAlbumColumns::TABLE + "(" + PhotoAlbumColumns::ALBUM_ID + ", " +
    PhotoAlbumColumns::ALBUM_TYPE + ", " + PhotoAlbumColumns::ALBUM_SUBTYPE + ", " +
    PhotoAlbumColumns::ALBUM_NAME + ", " + PhotoAlbumColumns::ALBUM_DATE_MODIFIED + ", " +
    PhotoAlbumColumns::ALBUM_BUNDLE_NAME + ")";
const string INSERT_PHOTO_MAP = "INSERT INTO " + PhotoMap::TABLE + "(" + PhotoMap::ALBUM_ID + ", " +
    PhotoMap::ASSET_ID + ")";
const string INSERT_ANALYSIS_ALBUM = "INSERT INTO " + ANALYSIS_ALBUM_TABLE + "(" + PhotoAlbumColumns::ALBUM_ID + ", " +
    PhotoAlbumColumns::ALBUM_TYPE + ", " + PhotoAlbumColumns::ALBUM_SUBTYPE + ", " +
    PhotoAlbumColumns::ALBUM_NAME + ") ";
const string INSERT_ANALYSIS_PHOTO_MAP = "INSERT INTO " + ANALYSIS_PHOTO_MAP_TABLE + "(" + PhotoMap::ALBUM_ID + ", " +
    PhotoMap::ASSET_ID + ")";

int32_t CloneOpenCall::OnCreate(NativeRdb::RdbStore &store)
{
    for (const auto &createSql : createSqls_) {
        int32_t errCode = store.ExecuteSql(createSql);
        if (errCode != NativeRdb::E_OK) {
            MEDIA_INFO_LOG("Execute %{public}s failed: %{public}d", createSql.c_str(), errCode);
            return errCode;
        }
    }
    return NativeRdb::E_OK;
}

int32_t CloneOpenCall::OnUpgrade(NativeRdb::RdbStore &store, int oldVersion, int newVersion)
{
    return 0;
}

void CloneOpenCall::Init(const vector<string> &tableList)
{
    for (const auto &tableName : tableList) {
        if (TABLE_CREATE_MAP.count(tableName) == 0) {
            MEDIA_INFO_LOG("Find value failed: %{public}s, skip", tableName.c_str());
            continue;
        }
        string createSql = TABLE_CREATE_MAP.at(tableName);
        createSqls_.push_back(createSql);
    }
}

void CloneSource::Init(const string &dbPath, const vector<string> &tableList)
{
    NativeRdb::RdbStoreConfig config(dbPath);
    CloneOpenCall helper;
    helper.Init(tableList);
    int errCode = 0;
    shared_ptr<NativeRdb::RdbStore> store = NativeRdb::RdbHelper::GetRdbStore(config, 1, helper, errCode);
    cloneStorePtr_ = store;
    Insert(tableList);
}

void CloneSource::Insert(const vector<string> &tableList)
{
    for (const auto &tableName : tableList) {
        if (TABLE_INSERT_TYPE_MAP.count(tableName) == 0) {
            MEDIA_INFO_LOG("Find value failed: %{public}s, skip", tableName.c_str());
            continue;
        }
        InsertType insertType = TABLE_INSERT_TYPE_MAP.at(tableName);
        InsertByType(insertType);
    }
}

void CloneSource::InsertByType(int32_t insertType)
{
    switch (insertType) {
        case InsertType::PHOTOS: {
            InsertPhoto();
            break;
        }
        case InsertType::PHOTO_ALBUM: {
            InsertPhotoAlbum();
            break;
        }
        case InsertType::PHOTO_MAP: {
            InsertPhotoMap();
            break;
        }
        case InsertType::ANALYSIS_ALBUM: {
            InsertAnalysisAlbum();
            break;
        }
        case InsertType::ANALYSIS_PHOTO_MAP: {
            InsertAnalysisPhotoMap();
            break;
        }
        default:
            MEDIA_INFO_LOG("Invalid insert type");
    }
}

void CloneSource::InsertPhoto()
{
    // file_id,
    // data, size, title, display_name, media_type,
    // owner_package, package_name, date_added, date_modified, date_taken, duration, is_favorite, date_trashed, hidden
    // height, width, edit_time, shooting_mode
    cloneStorePtr_->ExecuteSql(INSERT_PHOTO + VALUES_BEGIN + "1, " +
        "'/storage/cloud/files/Photo/16/IMG_1501924305_000.jpg', 175258, 'cam_pic', 'cam_pic.jpg', 1, " +
        "'com.ohos.camera', '相机', 1501924205218, 1501924205423, 1501924205, 0, 0, 0, 0, " +
        "1280, 960, 0, '1'" + VALUES_END); // cam, pic, shootingmode = 1
    cloneStorePtr_->ExecuteSql(INSERT_PHOTO + VALUES_BEGIN + "2, " +
        "'/storage/cloud/files/Photo/1/IMG_1501924307_001.jpg', 175397, 'cam_pic_del', 'cam_pic_del.jpg', 1, " +
        "'com.ohos.camera', '相机', 1501924207184, 1501924207286, 1501924207, 0, 0, 1501924271267, 0, " +
        "1280, 960, 0, ''" + VALUES_END); // cam, pic, trashed
    cloneStorePtr_->ExecuteSql(INSERT_PHOTO + VALUES_BEGIN + "3, " +
        "'/storage/cloud/files/Photo/16/VID_1501924310_000.mp4', 167055, 'cam_vid_fav', 'cam_vid_fav.mp4', 2, " +
        "'com.ohos.camera', '相机', 1501924210677, 1501924216550, 1501924210, 5450, 1, 0, 0, " +
        "480, 640, 0, ''" + VALUES_END); // cam, vid, favorite
    cloneStorePtr_->ExecuteSql(INSERT_PHOTO + VALUES_BEGIN + "4, " +
        "'/storage/cloud/files/Photo/2/IMG_1501924331_002.jpg', 505571, 'scr_pic_hid', 'scr_pic_hid.jpg', 1, " +
        "'com.ohos.screenshot', '截图', 1501924231249, 1501924231286, 1501924231, 0, 0, 0, 1, " +
        "1280, 720, 0, ''" + VALUES_END); // screenshot, pic, hidden
    cloneStorePtr_->ExecuteSql(INSERT_PHOTO + VALUES_BEGIN + "5, " +
        "'/storage/cloud/files/Photo/4/IMG_1501924357_004.jpg', 85975, 'scr_pic_edit', 'scr_pic_edit.jpg', 1, " +
        "'com.ohos.screenshot', '截图', 1501924257174, 1501924257583, 1501924257, 0, 0, 0, 0, " +
        "592, 720, 1501935124, ''" + VALUES_END); // screenshot, pic, edit
}

void CloneSource::InsertPhotoAlbum()
{
    // album_id, album_type, album_subtype, album_name, date_modified, bundle_name
    cloneStorePtr_->ExecuteSql(INSERT_PHOTO_ALBUM + VALUES_BEGIN + "8, 2048, 2049, '相机', 0, 'com.ohos.camera'" +
        VALUES_END);
    cloneStorePtr_->ExecuteSql(INSERT_PHOTO_ALBUM + VALUES_BEGIN + "9, 2048, 2049, '截图', 0, 'com.ohos.screenshot'" +
        VALUES_END);
    cloneStorePtr_->ExecuteSql(INSERT_PHOTO_ALBUM + VALUES_BEGIN + "11, 0, 1, '新建相册1', 1711540817842, NULL" +
        VALUES_END);
}

void CloneSource::InsertPhotoMap()
{
    // map_album, map_asset
    cloneStorePtr_->ExecuteSql(INSERT_PHOTO_MAP + VALUES_BEGIN + "8, 1" + VALUES_END);
    cloneStorePtr_->ExecuteSql(INSERT_PHOTO_MAP + VALUES_BEGIN + "8, 2" + VALUES_END);
    cloneStorePtr_->ExecuteSql(INSERT_PHOTO_MAP + VALUES_BEGIN + "8, 3" + VALUES_END);
    cloneStorePtr_->ExecuteSql(INSERT_PHOTO_MAP + VALUES_BEGIN + "9, 4" + VALUES_END);
    cloneStorePtr_->ExecuteSql(INSERT_PHOTO_MAP + VALUES_BEGIN + "9, 5" + VALUES_END);
    cloneStorePtr_->ExecuteSql(INSERT_PHOTO_MAP + VALUES_BEGIN + "11, 1" + VALUES_END);
    cloneStorePtr_->ExecuteSql(INSERT_PHOTO_MAP + VALUES_BEGIN + "11, 4" + VALUES_END);
}

void CloneSource::InsertAnalysisAlbum()
{
    // album_id, album_type, album_subtype, album_name
    cloneStorePtr_->ExecuteSql(INSERT_ANALYSIS_ALBUM + VALUES_BEGIN + "1, 4096, 4101, '1'" + VALUES_END);
}

void CloneSource::InsertAnalysisPhotoMap()
{
    // map_album, map_asset
    cloneStorePtr_->ExecuteSql(INSERT_ANALYSIS_PHOTO_MAP + VALUES_BEGIN + "1, 1" + VALUES_END);
}
} // namespace Media
} // namespace OHOS