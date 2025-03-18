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

#define MLOG_TAG "TabOldPhotosRestoreTest"

#include "tab_old_photos_restore_test.h"

#include <string>

#define private public
#define protected public
#include "medialibrary_unittest_utils.h"
#include "tab_old_photos_restore.h"
#undef protected
#undef private

using namespace testing::ext;

namespace OHOS::Media {
const int32_t TEST_NEW_FILE_ID = 1;
const int32_t TEST_OLD_LOCAL_MEDIA_ID = 10;
const std::string TEST_NEW_DATA = "/storage/cloud/files/Photo/16/IMG_1501924305_000.jpg";
const std::string TEST_OLD_DATA = "/storage/emulated/0/Pictures/test.jpg";

static std::shared_ptr<MediaLibraryRdbStore> g_rdbStore;

void ExecuteSql(shared_ptr<NativeRdb::RdbStore> store, const std::string &sql,
    const std::vector<NativeRdb::ValueObject> &bindArgs = {})
{
    int32_t errCode = store->ExecuteSql(sql, bindArgs);
    if (errCode == NativeRdb::E_OK) {
        return;
    }
    MEDIA_ERR_LOG("Execute %{public}s failed: %{public}d", sql.c_str(), errCode);
}

void ExecuteSqls(shared_ptr<NativeRdb::RdbStore> store, const std::vector<std::string> &sqls)
{
    for (const auto &sql : sqls) {
        ExecuteSql(store, sql);
    }
}

void InsertPhoto()
{
    const std::vector<std::string> INSERT_SQL = {
        "INSERT INTO Photos (file_id, data) VALUES (?, ?)";
    };
    const std::vector<NativeRdb::ValueObject> BIND_ARGS = { TEST_NEW_FILE_ID, TEST_NEW_DATA };
    ExecuteSql(g_rdbStore->GetRaw(), INSERT_SQL);
}

void ClearData()
{
    const std::vector<std::string> CLEAR_SQLS = {
        "DELETE FROM Photos",
        "DELETE FROM tab_old_photos",
    };
    ExecuteSqls(g_rdbStore->GetRaw(), CLEAR_SQLS);
}

void TabOldPhotosRestoreTest::SetUpTestCase()
{
    MEDIA_INFO_LOG("SetUpTestCase");
    MEDIA_INFO_LOG("Start Init");
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ASSERT_NE(g_rdbStore, nullptr);
    MEDIA_INFO_LOG("Start InsertPhoto");
    InsertPhoto();
}

void TabOldPhotosRestoreTest::TearDownTestCase()
{
    MEDIA_INFO_LOG("TearDownTestCase");
    ClearData();
}

// SetUp:Execute before each test case
void TabOldPhotosRestoreTest::SetUp() {}

void TabOldPhotosRestoreTest::TearDown() {}

HWTEST_F(TabOldPhotosRestoreTest, tab_old_photos_restore_empty_ptr_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start tab_old_photos_restore_empty_ptr_test_001");
    TabOldPhotosRestore tabOldPhotosRestore;
    std::shared_ptr<NativeRdb::RdbStore> rdbStorePtr;
    std::vector<FileInfo> fileInfos;
    int32_t ret = tabOldPhotosRestore.Restore(rdbStorePtr, fileInfos);
    EXPECT_EQ(ret, NativeRdb::E_DB_NOT_EXIST);
    MEDIA_INFO_LOG("End tab_old_photos_restore_empty_ptr_test_001");
}

HWTEST_F(TabOldPhotosRestoreTest, tab_old_photos_restore_empty_fileInfos_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start tab_old_photos_restore_empty_fileInfos_test_001");
    TabOldPhotosRestore tabOldPhotosRestore;
    std::vector<FileInfo> fileInfos;
    int32_t ret = tabOldPhotosRestore.Restore(g_rdbStore->GetRaw(), fileInfos);
    EXPECT_EQ(ret, NativeRdb::E_ERROR);
    MEDIA_INFO_LOG("End tab_old_photos_restore_empty_fileInfos_test_001");
}

HWTEST_F(TabOldPhotosRestoreTest, tab_old_photos_restore_normal_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start tab_old_photos_restore_normal_test_001");
    TabOldPhotosRestore tabOldPhotosRestore;
    FileInfo fileInfo;
    fileInfo.localMediaId = TEST_OLD_LOCAL_MEDIA_ID;
    fileInfo.oldPath = TEST_OLD_DATA;
    fileInfo.cloudPath = TEST_NEW_DATA;
    
    std::vector<FileInfo> fileInfos = { fileInfo };
    int32_t ret = tabOldPhotosRestore.Restore(g_rdbStore->GetRaw(), fileInfos);
    EXPECT_EQ(ret, NativeRdb::E_OK);
    MEDIA_INFO_LOG("End tab_old_photos_restore_normal_test_001");
}
}  // namespace OHOS::Media