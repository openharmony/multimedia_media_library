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

#include "external_source.h"

namespace OHOS {
namespace Media {
// create external files
const string ExternalOpenCall::CREATE_EXTERNAL_FILES = string("CREATE TABLE IF NOT EXISTS files ") +
    "(_id INTEGER PRIMARY KEY AUTOINCREMENT, _data TEXT COLLATE NOCASE, _display_name TEXT, is_favorite INTEGER, " +
    "_size INTEGER, duration INTEGER, media_type INTEGER, date_modified INTEGER, height INTEGER, width INTEGER, " +
    "title TEXT, orientation INTEGER, date_added INTEGER, bucket_id TEXT, is_pending INTEGER, " +
    "owner_package_name TEXT);";

int ExternalOpenCall::OnCreate(NativeRdb::RdbStore &store)
{
    return store.ExecuteSql(CREATE_EXTERNAL_FILES);
}

int ExternalOpenCall::OnUpgrade(NativeRdb::RdbStore &store, int oldVersion, int newVersion)
{
    return 0;
}

void ExternalSource::Init(const string &dbPath)
{
    NativeRdb::RdbStoreConfig config(dbPath);
    ExternalOpenCall helper;
    int errCode = 0;
    shared_ptr<NativeRdb::RdbStore> store = NativeRdb::RdbHelper::GetRdbStore(config, 1, helper, errCode);
    externalStorePtr_ = store;
    store->ExecuteSql(string("INSERT INTO files VALUES(7, '/storage/emulated/0/DCIM/Camera/fake_camera.jpg', ") +
        "'fake_camera.jpg', 0, 2808831, null, 1, 1546937461, 2976, 3968, 'fake_camera.jpg', 0, 1699781505, " +
        "-1739773001, 0, 'camera')");
    store->ExecuteSql(string("INSERT INTO files VALUES(8, '/storage/emulated/0/CTRIP/avatar/not_sync_invalid.jpg', ") +
        "'not_sync_invalid.jpg', 0, 27657543, null, 1, 1546937461, 2448, 3264, 'not_sync_invalid.jpg', 0, " +
        "1699781529, 876554266, 0, 'ctrip')");
    store->ExecuteSql(string("INSERT INTO files VALUES(9, ") +
        "'/storage/emulated/0/MicroMsg/WeiXin/not_sync_valid.jpg', 'not_sync_valid.jpg', 0, 3503265, null, 1, " +
        "1546937461, 2976, 3968, 'not_sync_valid.jpg', 0, 1699781529, -924335728, 0, 'weixin')");
    store->ExecuteSql(string("INSERT INTO files VALUES(10, ") +
        "'/storage/emulated/0/DCIM/Camera/not_sync_pending_camera.jpg', 'not_sync_pending_camera.jpg', 0, 3503265, " +
        "null, 1, 1546937461, 2976, 3968, 'not_sync_pending_camera.jpg', 0, 1699781529, -1739773001, 1, 'camera')");
    store->ExecuteSql(string("INSERT INTO files VALUES(11, ") +
        "'/storage/emulated/0/MicroMsg/WeiXin/not_sync_pending_others.jpg', 'not_sync_pending_others.jpg', 0, " +
        "3503265, null, 1, 1546937461, 2976, 3968, 'not_sync_pending_others.jpg', 0, 1699781529, -924335728, 1, " +
        "'others')");
}
} // namespace Media
} // namespace OHOS