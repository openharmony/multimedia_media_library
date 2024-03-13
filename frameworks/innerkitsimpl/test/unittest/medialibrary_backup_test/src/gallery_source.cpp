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

#include "gallery_source.h"

namespace OHOS {
namespace Media {
const string GalleryOpenCall::CREATE_GALLERY_MEDIA = string("CREATE TABLE IF NOT EXISTS gallery_media ") +
    " (id INTEGER PRIMARY KEY AUTOINCREMENT, local_media_id INTEGER, _data TEXT COLLATE NOCASE," +
    "_size INTEGER,  date_added INTEGER, date_modified INTEGER, title TEXT, description TEXT, _display_name TEXT, " +
    "orientation INTEGER, bucket_id TEXT, duration INTEGER, media_type INTEGER, storage_id INTEGER, width INTEGER, " +
    "height INTEGER, is_hw_favorite INTEGER,  relative_bucket_id TEXT, showDateToken INTEGER, recycleFlag INTEGER, " +
    "recycledTime INTEGER);";

const string GalleryOpenCall::CREATE_GARBAGE_ALBUM = string("CREATE TABLE IF NOT EXISTS garbage_album") +
    "(app_name TEXT, cache_dir TEXT, nick_name TEXT, nick_dir TEXT, type INTEGER, relative_bucket_id TEXT);";

int GalleryOpenCall::OnCreate(NativeRdb::RdbStore &store)
{
    store.ExecuteSql(CREATE_GALLERY_MEDIA);
    return store.ExecuteSql(CREATE_GARBAGE_ALBUM);
}

int GalleryOpenCall::OnUpgrade(NativeRdb::RdbStore &store, int oldVersion, int newVersion)
{
    return 0;
}

void GallerySource::Init(const string &dbPath)
{
    NativeRdb::RdbStoreConfig config(dbPath);
    GalleryOpenCall helper;
    int errCode = 0;
    shared_ptr<NativeRdb::RdbStore> store = NativeRdb::RdbHelper::GetRdbStore(config, 1, helper, errCode);
    galleryStorePtr_ = store;
    InitGalleryMediaOne();
    InitGalleryMediaTwo();
    InitGalleryMediaThree();
    InitGarbageAlbum();
}

void GallerySource::InitGalleryMediaOne()
{
    galleryStorePtr_->ExecuteSql(string("INSERT INTO gallery_media VALUES(1, 1, ") +
        "'/storage/emulated/0//BaiduMap/cache/fake_baidu.jpg', 2160867, 1706950419, 1546937461," +
        "'fake_baidu', NULL, 'fake_baidu.jpg', 0, 2080527857, 0, 1, 65537, 3968, 2976, NULL, " +
        "-1492241466, 1495954569032, 0, 0)");
    galleryStorePtr_->ExecuteSql(string("INSERT INTO gallery_media VALUES(2, 16, ") +
        "'/storage/emulated/0/DCIM/Camera/camera_sync.jpg', 2808831, 1706950426, 1546937461," +
        "'camera_sync', NULL, 'camera_sync.jpg', 0, -1739773001, 0, 1, 65537, 3968, 2976, NULL, " +
        "2064266562, 1496025408734, 0, 0)");
    galleryStorePtr_->ExecuteSql(string("INSERT INTO gallery_media VALUES(3, 2, ") +
        "'/storage/emulated/0/Pictures/album1/album1.jpg', 3091817, 1706950426, 1546937461," +
        "'album1', NULL, 'album1.jpg', 0, -1266858078, 0, 1, 65537, 3968, 2976, NULL, " +
        "1999934381, 1495970415377, 0, 0)");
    galleryStorePtr_->ExecuteSql(string("INSERT INTO gallery_media VALUES(4, 3, ") +
        "'/storage/emulated/0/Pictures/album2/album2.jpg', 3621508, 1706950426, 1546937461," +
        "'album2', NULL, 'album2.jpg', 0, -1266858077, 0, 1, 65537, 3968, 2976, NULL, " +
        "1999934382, 1495973952757, 0, 0)");
    galleryStorePtr_->ExecuteSql(string("INSERT INTO gallery_media VALUES(5, 4, ") +
        "'/storage/emulated/0/Pictures/favorite.jpg', 7440437, 1706950426, 1546937461," +
        "'favorite', NULL, 'favorite.jpg', 0, -1617409521, 0, 1, 65537, 5120, 3840, 1, " +
        "218866788, 1495957457427, 0, 0)");
    galleryStorePtr_->ExecuteSql(string("INSERT INTO gallery_media VALUES(6, -4, ") +
        "'/storage/emulated/0/Pictures/hiddenAlbum/bins/0/" +
        "GF6DA7BRGAYXYMJXGA3DSNJQGQ4TEMBTGF6GQ2LEMRSW47BONJYGO7DJNVQWOZJPNJYGKZ34NZ2WY3A', 2716337, 1706950426, " +
        "1546937461, 'hidden', NULL, 'hidden.jpg', 0, -1617409521, 0, 1, 65537, 3968, 2976, NULL, " +
        "659449306, 1495961420646, 0, 0)");
    galleryStorePtr_->ExecuteSql(string("INSERT INTO gallery_media VALUES(7, 5, ") +
        "'/storage/emulated/0/Pictures/no_exif.png', 234265, 1706950426, 1541215543," +
        "'no_exif', NULL, 'no_exif.png', 0, -1617409521, 0, 1, 65537, 1024, 768, NULL, " +
        "218866788, 1541215543000, 0, 0)");
    galleryStorePtr_->ExecuteSql(string("INSERT INTO gallery_media VALUES(8, 6, ") +
        "'/storage/emulated/0/Pictures/orientation.jpg', 2781577, 1706950426, 1706950486," +
        "'orientation', NULL, 'orientation.jpg', 270, -1617409521, 0, 1, 65537, 3264, 2448, NULL, " +
        "218866788, 1495962070277, 0, 0)");
    galleryStorePtr_->ExecuteSql(string("INSERT INTO gallery_media VALUES(9, 0, ") +
        "'/storage/emulated/0/Pictures/.Gallery2/recycle/bins/0/\
        GF6DA7BRGA2HYMJXGA3DSNJQGQ4DENJXGN6HI4TBONUGKZD4FZVHAZ34NFWWCZ3FF5VHAZLHPRXHK3DM', 2454477, 1706950426, " +
        "1546937461, 'trashed', NULL, 'trashed.jpg', 0, -1617409521, 0, 1, 65537, 3968, 2976, NULL, " +
        "218866788, 1495959683996, 2, 1706950482573)");
}

void GallerySource::InitGalleryMediaTwo()
{
    galleryStorePtr_->ExecuteSql(string("INSERT INTO gallery_media VALUES(10, 7, ") +
        "'/storage/emulated/0/Pictures/user_common.jpg', 4330676, 1706950426, 1706950476," +
        "'user_common', 'user_comment', 'user_common.jpg', 0, -1617409521, 0, 1, 65537, 3968, 2976, NULL, " +
        "218866788, 1495962762035, 0, 0)");
    galleryStorePtr_->ExecuteSql(string("INSERT INTO gallery_media VALUES(11, -3, ") +
        "'/storage/emulated/0/Pictures/clone.jpg', 5431183, 1706950426, 1546937461," +
        "'clone', NULL, 'clone.jpg', 0, -1617409521, 0, 1, 65537, 5120, 3840, NULL, " +
        "218866788, 1496056464221, 0, 0)");
    galleryStorePtr_->ExecuteSql(string("INSERT INTO gallery_media VALUES(15, 13, ") +
        "'/storage/emulated/0/DCIM/Sgame/fake_game.jpg', 3871481, 1706950426, 1546937461," +
        "'fake_game', NULL, 'fake_game.jpg', 0, -1288103917, 0, 1, 65537, 3968, 2976, NULL, " +
        "-1858129624, 1495970384215, 0, 0)");
    galleryStorePtr_->ExecuteSql(string("INSERT INTO gallery_media VALUES(16, 14, ") +
        "'/storage/emulated/0/CTRIP/avatar/fake_garbage_ctrip.jpg', 3184187, 1706950426, 1546937461," +
        "'fake_garbage_ctrip', NULL, 'fake_garbage_ctrip.jpg', 0, 876554266, 0, 1, 65537, 3968, 2976, NULL, " +
        "-1457303569, 1495969289098, 0, 0)");
    galleryStorePtr_->ExecuteSql(string("INSERT INTO gallery_media VALUES(17, 15, ") +
        "'/storage/emulated/0/tencent/MicroMsg/WeiXin/fake_wechat.jpg', 2419880, 1706950426, 1432973383," +
        "'fake_wechat', NULL, 'fake_wechat.jpg', 0, -924335728, 0, 1, 65537, 3968, 2976, NULL, " +
        "-1803300197, 1432973383179, 0, 0)");
    galleryStorePtr_->ExecuteSql(string("INSERT INTO gallery_media VALUES(12, 9, ") +
        "'/storage/emulated/0/Movies/common.mp4', 192844, 1706950426, 1698033985," +
        "'common', NULL, 'common.mp4', 0, -1730634595, 6042, 3, 65537, 320, 240, NULL, " +
        "1989707826, 1240601085000, 0, 0)");
    galleryStorePtr_->ExecuteSql(string("INSERT INTO gallery_media VALUES(13, 10, ") +
        "'/storage/emulated/0/Movies/4K.mp4', 26162975, 1706950426, 1703905398," +
        "'4K', NULL, '4K.mp4', 0, -1730634595, 5099, 3, 65537, 3840, 2160, NULL, " +
        "1989707826, 1703905326000, 0, 0)");
    galleryStorePtr_->ExecuteSql(string("INSERT INTO gallery_media VALUES(14, 11, ") +
        "'/storage/emulated/0/Movies/1080p.mp4', 6626209, 1706950426, 1703905397," +
        "'1080p', NULL, '1080p.mp4', 0, -1730634595, 4551, 3, 65537, 1920, 1080, NULL, " +
        "1989707826, 1703905305000, 0, 0)");
}

void GallerySource::InitGalleryMediaThree()
{
    galleryStorePtr_->ExecuteSql(string("INSERT INTO gallery_media VALUES(18, 16, ") +
        "'/storage/emulated/0/A/media/Rocket/test/a_media_normal_video.mp4', 10865209, 1708600079, 1708600079," +
        "'a_media_normal_video', 'NULL', 'a_media_normal_video.mp4', 0, -1122816831, 52221, 3, 65537, 352, 640, " +
        "NULL, 1264692236, 1708600079000, 0, 0)");
    galleryStorePtr_->ExecuteSql(string("INSERT INTO gallery_media VALUES(19, 17, ") +
        "'/storage/emulated/0/A/media/Rocket/test/a_media_favorite.mp4', 10865209, 1708600079, 1708600079," +
        "'a_media_favorite', 'NULL', 'a_media_favorite.mp4', 0, -1122816831, 52221, 3, 65537, 352, 640, 1, " +
        "1264692236, 1708600079000, 0, 0)");
    galleryStorePtr_->ExecuteSql(string("INSERT INTO gallery_media VALUES(20, 18, ") +
        "'/storage/emulated/0/A/media/Baidu/a_media_favorite_baidu.mp4', 10865209, 1708600079, 1708600079," +
        "'a_media_favorite_baidu', 'NULL', 'a_media_favorite_baidu.mp4', 0, -1122816831, 52221, 3, 65537, 352, 640," +
        "1, 1264692236, 1708600079000, 0, 0)");
    galleryStorePtr_->ExecuteSql(string("INSERT INTO gallery_media VALUES(21, 19, ") +
        "'/storage/emulated/0/A/media/Baidu/a_media_normal_image.jpg', 418436, 1708602162000, 1708602162," +
        "'a_media_normal_image', 'NULL', 'a_media_normal_image.jpg', 0, -1960413976, 0, 1, 65537, 2000, 3556, NULL, " +
        "1264692236, 1708602162000, 0, 0)");
}

void GallerySource::InitGarbageAlbum()
{
    galleryStorePtr_->ExecuteSql(string("INSERT INTO garbage_album VALUES('baidu', '/BaiduMap/cache', ") +
        "null, null, 1, 1151084355);");
    galleryStorePtr_->ExecuteSql(string("INSERT INTO garbage_album VALUES('ctrip', '/CTRIP/avatar', ") +
        "null, null, 1, -1457303569);");
    galleryStorePtr_->ExecuteSql(string("INSERT INTO garbage_album VALUES(null, null, 'wechat', ") +
        "'/tencent/MicroMsg/WeiXin', 0, null);");
    galleryStorePtr_->ExecuteSql(string("INSERT INTO garbage_album VALUES(null, null, 'sgame', ") +
        "'/DCIM/Sgame', 0, null);");
}
} // namespace Media
} // namespace OHOS