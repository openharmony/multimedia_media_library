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

#include "medialibrary_kvstore_manager_test.h"
#include "medialibrary_kvstore_manager.h"
#include "medialibrary_mocksinglekvstore.h"
#include "medialibrary_errno.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {

void MediaLibraryKvstoreManagerTest::SetUpTestCase(void) {}
void MediaLibraryKvstoreManagerTest::TearDownTestCase(void) {}
void MediaLibraryKvstoreManagerTest::SetUp(void) {}
void MediaLibraryKvstoreManagerTest::TearDown(void) {}

/*
 * Feature : MediaLibraryKvstoreManagerTest
 * Function : CloseAllKvStore
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaLibraryKvstoreManagerTest, MediaLibraryKvstoreManager_Test_001, TestSize.Level1)
{
    shared_ptr<MediaLibraryKvStore> mediaLibraryKvStore = make_shared<MediaLibraryKvStore>();
    ASSERT_NE(mediaLibraryKvStore, nullptr);
    KvStoreValueType valueType = KvStoreValueType::MONTH_ASTC;
    MediaLibraryKvStoreManager::GetInstance().kvStoreMap_.Insert(valueType, mediaLibraryKvStore);
    MediaLibraryKvStoreManager::GetInstance().CloseAllKvStore();
    MediaLibraryKvStoreManager::GetInstance().kvStoreMap_.Clear();
    MediaLibraryKvStoreManager::GetInstance().CloseAllKvStore();

    bool res = MediaLibraryKvStoreManager::GetInstance().CloseKvStore(valueType);
    EXPECT_FALSE(res);

    mediaLibraryKvStore->kvStorePtr_ = nullptr;
    res = MediaLibraryKvStoreManager::GetInstance().CloseKvStore(valueType);
    EXPECT_FALSE(res);
    
    mediaLibraryKvStore = nullptr;
    MediaLibraryKvStoreManager::GetInstance().kvStoreMap_.Insert(valueType, mediaLibraryKvStore);
    res = MediaLibraryKvStoreManager::GetInstance().CloseKvStore(valueType);
    EXPECT_FALSE(res);
}

/*
 * Feature : MediaLibraryKvstoreManagerTest
 * Function : InitMonthAndYearKvStore
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaLibraryKvstoreManagerTest, MediaLibraryKvstoreManager_Test_002, TestSize.Level1)
{
    KvStoreRoleType roleType = KvStoreRoleType::VISITOR;
    bool res = MediaLibraryKvStoreManager::GetInstance().InitMonthAndYearKvStore(roleType);
    EXPECT_FALSE(res);
}

/*
 * Feature : MediaLibraryKvstoreManagerTest
 * Function : InitKvStore
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : InitKvStore with OWNER role
 */
HWTEST_F(MediaLibraryKvstoreManagerTest, MediaLibraryKvstoreManager_Test_003, TestSize.Level1)
{
    KvStoreRoleType roleType = KvStoreRoleType::OWNER;
    KvStoreValueType valueType = KvStoreValueType::MONTH_ASTC;
    shared_ptr<MediaLibraryKvStore> kvStore =
        MediaLibraryKvStoreManager::GetInstance().InitKvStore(roleType, valueType);
    EXPECT_NE(kvStore, nullptr);
    MediaLibraryKvStoreManager::GetInstance().kvStoreMap_.Clear();
}

/*
 * Feature : MediaLibraryKvstoreManagerTest
 * Function : InitKvStore
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : InitKvStore with VISITOR role
 */
HWTEST_F(MediaLibraryKvstoreManagerTest, MediaLibraryKvstoreManager_Test_004, TestSize.Level1)
{
    KvStoreRoleType roleType = KvStoreRoleType::VISITOR;
    KvStoreValueType valueType = KvStoreValueType::MONTH_ASTC;
    shared_ptr<MediaLibraryKvStore> kvStore =
        MediaLibraryKvStoreManager::GetInstance().InitKvStore(roleType, valueType);
    EXPECT_NE(kvStore, nullptr);
    MediaLibraryKvStoreManager::GetInstance().kvStoreMap_.Clear();
}

/*
 * Feature : MediaLibraryKvstoreManagerTest
 * Function : GetKvStore
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : GetKvStore with existing store
 */
HWTEST_F(MediaLibraryKvstoreManagerTest, MediaLibraryKvstoreManager_Test_005, TestSize.Level1)
{
    KvStoreRoleType roleType = KvStoreRoleType::OWNER;
    KvStoreValueType valueType = KvStoreValueType::MONTH_ASTC;
    shared_ptr<MediaLibraryKvStore> kvStore =
        MediaLibraryKvStoreManager::GetInstance().InitKvStore(roleType, valueType);
    EXPECT_NE(kvStore, nullptr);
    shared_ptr<MediaLibraryKvStore> kvStore2 =
        MediaLibraryKvStoreManager::GetInstance().GetKvStore(roleType, valueType);
    EXPECT_NE(kvStore2, nullptr);
    MediaLibraryKvStoreManager::GetInstance().kvStoreMap_.Clear();
}

/*
 * Feature : MediaLibraryKvstoreManagerTest
 * Function : TryCloseAllKvStore
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : TryCloseAllKvStore with idle time
 */
HWTEST_F(MediaLibraryKvstoreManagerTest, MediaLibraryKvstoreManager_Test_006, TestSize.Level1)
{
    shared_ptr<MediaLibraryKvStore> mediaLibraryKvStore = make_shared<MediaLibraryKvStore>();
    ASSERT_NE(mediaLibraryKvStore, nullptr);
    KvStoreValueType valueType = KvStoreValueType::MONTH_ASTC;
    MediaLibraryKvStoreManager::GetInstance().kvStoreMap_.Insert(valueType, mediaLibraryKvStore);
    MediaLibraryKvStoreManager::GetInstance().TryCloseAllKvStore();
    MediaLibraryKvStoreManager::GetInstance().kvStoreMap_.Clear();
}

/*
 * Feature : MediaLibraryKvstoreManagerTest
 * Function : CloseKvStore
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : CloseKvStore with valid ptr
 */
HWTEST_F(MediaLibraryKvstoreManagerTest, MediaLibraryKvstoreManager_Test_007, TestSize.Level1)
{
    shared_ptr<MediaLibraryKvStore> mediaLibraryKvStore = make_shared<MediaLibraryKvStore>();
    ASSERT_NE(mediaLibraryKvStore, nullptr);
    mediaLibraryKvStore->kvStorePtr_ = make_shared<MockSingleKvStore>();
    KvStoreValueType valueType = KvStoreValueType::MONTH_ASTC;
    MediaLibraryKvStoreManager::GetInstance().kvStoreMap_.Insert(valueType, mediaLibraryKvStore);
    bool res = MediaLibraryKvStoreManager::GetInstance().CloseKvStore(valueType);
    EXPECT_TRUE(res);
}

/*
 * Feature : MediaLibraryKvstoreManagerTest
 * Function : IsKvStoreValid
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : IsKvStoreValid with valid store
 */
HWTEST_F(MediaLibraryKvstoreManagerTest, MediaLibraryKvstoreManager_Test_008, TestSize.Level1)
{
    KvStoreValueType valueType = KvStoreValueType::MONTH_ASTC;
    bool res = MediaLibraryKvStoreManager::GetInstance().IsKvStoreValid(valueType);
    EXPECT_TRUE(res);
}

/*
 * Feature : MediaLibraryKvstoreManagerTest
 * Function : RebuildInvalidKvStore
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : RebuildInvalidKvStore
 */
HWTEST_F(MediaLibraryKvstoreManagerTest, MediaLibraryKvstoreManager_Test_009, TestSize.Level1)
{
    KvStoreValueType valueType = KvStoreValueType::MONTH_ASTC;
    int32_t res = MediaLibraryKvStoreManager::GetInstance().RebuildInvalidKvStore(valueType);
    EXPECT_EQ(res, E_OK);
}

/*
 * Feature : MediaLibraryKvstoreManagerTest
 * Function : GetSingleKvStore
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : GetSingleKvStore with OWNER role
 */
HWTEST_F(MediaLibraryKvstoreManagerTest, MediaLibraryKvstoreManager_Test_010, TestSize.Level1)
{
    KvStoreRoleType roleType = KvStoreRoleType::OWNER;
    string storeId = "test_store";
    string baseDir = "/data/test";
    shared_ptr<MediaLibraryKvStore> kvStore =
        MediaLibraryKvStoreManager::GetInstance().GetSingleKvStore(roleType, storeId, baseDir);
    EXPECT_NE(kvStore, nullptr);
}

/*
 * Feature : MediaLibraryKvstoreManagerTest
 * Function : CloneKvStore
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : CloneKvStore
 */
HWTEST_F(MediaLibraryKvstoreManagerTest, MediaLibraryKvstoreManager_Test_011, TestSize.Level1)
{
    string oldKvStoreId = "old_store";
    string oldBaseDir = "/data/test/old";
    string newKvStoreId = "new_store";
    string newBaseDir = "/data/test/new";
    int32_t res =
        MediaLibraryKvStoreManager::GetInstance().CloneKvStore(oldKvStoreId, oldBaseDir, newKvStoreId, newBaseDir);
    EXPECT_EQ(res, E_OK);
}
} // namespace Media
} // namespace OHOS