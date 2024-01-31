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
    " _display_name TEXT, description TEXT, is_hw_favorite INTEGER, _size INTEGER, recycledTime INTEGER," +
    " duration INTEGER, media_type INTEGER, showDateToken INTEGER, date_modified INTEGER, height INTEGER, " +
    " width INTEGER, title TEXT, orientation INTEGER, storage_id INTEGER, relative_bucket_id TEXT, " +
    " bucket_id TEXT, recycleFlag INTEGER);";

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
    InitGalleryMedia();
    InitGarbageAlbum();
}

void GallerySource::InitGalleryMedia()
{
    galleryStorePtr_->ExecuteSql(string("INSERT INTO gallery_media VALUES(1, 1, ") +
        "'/storage/emulated/0/tencent/MicroMsg/WeiXin/fake_wechat.jpg', 'fake_wechat.jpg', 'fake_wechat', " +
        " null, 2419880, 0, 0, 1, 1432973383179, 1432973383, 2976, 3968, 'fake_wechat', 0, 65537, -1803300197, "
        " -924335728, 0)");
    galleryStorePtr_->ExecuteSql(string("INSERT INTO gallery_media VALUES(2, 2, ") +
        "'/storage/emulated/0/Pictures/favorite.jpg', 'favorite.jpg', 'favorite', 1, 7440437, 0, 0, 1, " +
        "1495957457427, 15464937461, 3840, 5120, 'favorite', 0, 65537, 218866788, -1617409521, 0)");
    galleryStorePtr_->ExecuteSql(string("INSERT INTO gallery_media VALUES(3, -4, ") +
        "'/storage/emulated/0/Pictures/hiddenAlbum/bins/0/xxx','hidden.jpg', 'hidden', null, 2716337, 0, 0, 1, " +
        "1495961420646, 1546937461, 2976, 3968, 'hidden', 0, 65537, 218866788, 1385117028, null)");
    galleryStorePtr_->ExecuteSql(string("INSERT INTO gallery_media VALUES(4, 4, ") +
        "'/storage/emulated/0/Pictures/.Gallery2/recycle/bins/0/xx', 'trashed.jpg', 'trashed', null, 2454477, " +
        "1698397634260, 0, 1, 1495959683996, 1546937461, 2976, 3968, 'trashed', 0, 65537, 218866788, -1739773001, 2)");
    galleryStorePtr_->ExecuteSql(string("INSERT INTO gallery_media VALUES(5, 5, ") +
        "'/storage/emulated/0/Pictures/orientation.jpg', 'orientation.jpg', 'orientation', null, 2781577, 0, 0," +
        " 1, 1495962070277, 1698397638, 2448, 3264, 'orientation', 270, 65537, 218866788, -1617409521, 0)");
    galleryStorePtr_->ExecuteSql(string("INSERT INTO gallery_media VALUES(6, 6, ") +
        "'/storage/emulated/0/BaiduMap/cache/fake_garbage_baidu.jpg', 'fake_garbage_baidu.jpg', " +
        "'fake_garbage_baidu', null, 2160867, 0, 0, 1, 1495954569032, 1546937461, 2976, 3968, " +
        "'fake_garbage_baidu', 0, 65537, 1151084355, -1617409521, 0)");
    galleryStorePtr_->ExecuteSql(string("INSERT INTO gallery_media VALUES(7, 7, ") +
        "'/storage/emulated/0/Pictures/zero_size.jpg', 'zero_size.jpg', 'zero_size', null, 0, 0, 0," +
        " 1, 1495962070277, 1698397638, 2448, 3264, 'zero_size', 0, 65537, 218866788, -1617409521, 0)");
    galleryStorePtr_->ExecuteSql(string("INSERT INTO gallery_media VALUES(8, 8, ") +
        "'/storage/emulated/0/Pictures/Screenshots/SVID_screen_video.mp4', 'SVID_screen_video.mp4', "+
        "'SVID_screen_video', null, 94270, 0, 3508, 3, 1476702882, 1698397638, 1280, 606, 'SVID_screen_video', " +
        "0, 65537, 218866788, 1028075469, 0)");
}

void GallerySource::InitGarbageAlbum()
{
    galleryStorePtr_->ExecuteSql(string("INSERT INTO garbage_album VALUES('baidu', '/BaiduMap/cache', ") +
        "null, null, 1, 1151084355);");
    galleryStorePtr_->ExecuteSql(string("INSERT INTO garbage_album VALUES('ctrip', '/CTRIP/avatar', ") +
        "null, null, 1, -1457303569);");
    galleryStorePtr_->ExecuteSql(string("INSERT INTO garbage_album VALUES(null, null, 'wechat', ") +
        "'/tencent/MicroMsg/WeiXin', 0, null);");
}
} // namespace Media
} // namespace OHOS