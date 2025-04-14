/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "medialibraryrestore_fuzzer.h"

#include <cstdint>
#include <string>
#include <pixel_map.h>

#include "medialibrary_restore.h"
#define private public
#include "medialibrary_rdbstore.h"
#undef private
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "media_file_utils.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "rdb_store_config.h"
#include "album_plugin_table_event_handler.h"

namespace OHOS {
using namespace std;

constexpr int RDB_VERSION = 1;
constexpr int32_t SLEEP_1 = 1;
constexpr int32_t SLEEP_2 = 2;
const std::string TEST_BACKUP_FOLDER = "/data/test/media_library_restore/rdb";
const std::string TEST_BACKUP_FILE = TEST_BACKUP_FOLDER + "/media_library";
const std::string SLAVE_DB = "_slave";
const std::string EXT_DB = ".db";
const std::string EXT_DB_WAL = ".db-wal";
const std::string DB_PATH = TEST_BACKUP_FILE + EXT_DB;
const std::string SELECT_SQL = "SELECT album_subtype FROM PhotoAlbum WHERE album_type = 0";
const std::string INSERT_SQL = std::string("INSERT INTO PhotoAlbum")
    .append("(album_type, album_subtype, album_name, cover_uri, cloud_id, relative_path) VALUES ")
    .append("(0, 1, 'test101010101010101010101010',")
    .append("'file://media/Photo/2/IMG_1501932657_001/IMG_201785_192917.jpg',")
    .append("'file://media/Photo/2/IMG_1501932657_001/IMG_201785_192917.jpg',")
    .append("'file://media/Photo/2/IMG_1501932657_001/IMG_201785_192917.jpg'")
    .append(");");
const std::string UPDATE_SQL = std::string("UPDATE PhotoAlbum set album_subtype = 2")
    .append(" where album_type = 0 and album_subtype = 1");
const std::string INCREASE_SQL = std::string("INSERT INTO PhotoAlbum")
    .append(" (album_type, album_subtype, album_name, cover_uri, cloud_id, relative_path)")
    .append(" select album_type, album_subtype, album_name, cover_uri, cloud_id, relative_path from PhotoAlbum");
const std::string CREATE_PHOTOS_ALBUM = std::string("CREATE TABLE IF NOT EXISTS PhotoAlbum ")
    .append("(album_id INTEGER PRIMARY KEY AUTOINCREMENT, album_type INT, ")
    .append("album_subtype INT, album_name TEXT COLLATE NOCASE, cover_uri TEXT, ")
    .append("count INT DEFAULT 0, date_modified BIGINT DEFAULT 0, dirty INT DEFAULT 1, ")
    .append("cloud_id TEXT, ")
    .append("relative_path TEXT, contains_hidden INT DEFAULT 0, hidden_count INT DEFAULT 0)");

static inline string FuzzString(const uint8_t *data, size_t size)
{
    return {reinterpret_cast<const char*>(data), size};
}

int Media::FuzzRestoreDataCallback::OnCreate(NativeRdb::RdbStore &store)
{
    int errCode = store.ExecuteSql(CREATE_PHOTOS_ALBUM);
    return errCode;
}

int Media::FuzzRestoreDataCallback::OnUpgrade(NativeRdb::RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

int CorruptDb(bool isSlave)
{
    std::string ext = "";
    if (isSlave) {
        ext = SLAVE_DB;
    }
    std::string filePath = TEST_BACKUP_FILE + ext + EXT_DB;
    std::string cmd = std::string("dd if=/dev/zero of=").append(filePath)
        .append(" bs=4k seek=0 conv=notrunc count=1");
    int ret = std::system(cmd.c_str());
    if (!isSlave) {
        cmd = std::string("dd if=/dev/zero of=").append(filePath).append(" bs=4k seek=1 conv=notrunc count=1");
        ret = std::system(cmd.c_str());
        cmd = std::string("dd if=/dev/zero of=").append(filePath).append(" bs=4k seek=3 conv=notrunc count=1");
        ret = std::system(cmd.c_str());
    }

    filePath = TEST_BACKUP_FILE + ext + EXT_DB_WAL;
    if (!isSlave) {
        cmd = std::string("dd if=/dev/zero of=").append(filePath).append(" bs=4k seek=5 conv=notrunc count=1");
        ret = std::system(cmd.c_str());
    }
    return ret;
}

void WaitForBackup()
{
    while (Media::MediaLibraryRestore::GetInstance().IsBackuping()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_2));
    }
}

const NativeRdb::RdbStoreConfig GetConfig()
{
    NativeRdb::RdbStoreConfig config(DB_PATH);
    config.SetHaMode(NativeRdb::HAMode::MANUAL_TRIGGER);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S3);
    config.SetAllowRebuild(true);
    return config;
}

static void MediaLibraryRestoreTest(const uint8_t *data, size_t size)
{
    auto config = GetConfig();
    Media::FuzzRestoreDataCallback callBack;
    int errCode = 0;
    auto rdb = NativeRdb::RdbHelper::GetRdbStore(config, RDB_VERSION, callBack, errCode);
    if (rdb == nullptr) {
        return;
    }
    errCode = rdb->ExecuteSql(INCREASE_SQL);
    std::string testSql = FuzzString(data, size);
    errCode = rdb->ExecuteSql(testSql);
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_1));
    rdb->IsSlaveDiffFromMaster();

    int32_t ret = Media::MediaLibraryUnitTestUtils::InitUnistore(config, RDB_VERSION, callBack);
    if (ret != Media::E_OK) {
        return;
    }
    Media::MediaLibraryRestore::GetInstance().CheckBackup();
    Media::MediaLibraryRestore::GetInstance().IsBackuping();
    WaitForBackup();
    rdb->IsSlaveDiffFromMaster();

    errCode = CorruptDb(false);
    errCode = rdb->ExecuteSql(SELECT_SQL);
    Media::MediaLibraryRestore::GetInstance().CheckRestore(errCode);
    Media::MediaLibraryRestore::GetInstance().IsRestoring();
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_1));
    Media::MediaLibraryRestore::GetInstance().InterruptBackup();

    Media::MediaLibraryUnitTestUtils::StopUnistore();
    NativeRdb::RdbHelper::DeleteRdbStore(config);
}

static void AlbumPluginFuzzerTest(const uint8_t *data, size_t size)
{
    auto config = GetConfig();
    Media::FuzzRestoreDataCallback callBack;
    int errCode = 0;
    auto rdb = NativeRdb::RdbHelper::GetRdbStore(config, RDB_VERSION, callBack, errCode);
        if (rdb == nullptr) {
        return;
    }
    errCode = rdb->ExecuteSql(INCREASE_SQL);
    std::string testSql = FuzzString(data, size);
    errCode = rdb->ExecuteSql(testSql);
    Media::AlbumPluginTableEventHandler albumPluginTableEventHandler;
    albumPluginTableEventHandler.OnCreate(*rdb);
    albumPluginTableEventHandler.OnUpgrade(*rdb, 0, 0);
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::MediaLibraryRestoreTest(data, size);
    OHOS::AlbumPluginFuzzerTest(data, size);
    return 0;
}