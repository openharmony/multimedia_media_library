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

#include "medialibrary_thumbnail_kvstore_test.h"

#include "medialibrary_kvstore.h"
#include "medialibrary_errno.h"

using namespace testing::ext;

namespace OHOS {
namespace Media {
const std::string TEST_PATH = "/data/test";
const std::string FIRST_KEY = "000001";
const std::string SECOND_KEY = "000002";
const std::string THIRD_KEY = "000003";
const std::string FORTH_KEY = "000004";
std::shared_ptr<MediaLibraryKvStore> kvStorePtr = nullptr;

void MediaLibraryThumbnailKvStoreTest::SetUpTestCase(void)
{
    kvStorePtr = std::make_shared<MediaLibraryKvStore>();
    int errCode = kvStorePtr->Init(KvStoreRoleType::OWNER, KvStoreValueType::MONTH_ASTC, TEST_PATH);
    if (errCode != E_OK) {
        kvStorePtr = nullptr;
        return;
    }

    std::vector<uint8_t> value;
    value.assign(FIRST_KEY.begin(), FIRST_KEY.end());
    errCode = kvStorePtr->Insert(FIRST_KEY, value);
    value.clear();
    EXPECT_EQ(errCode, E_OK);

    value.assign(SECOND_KEY.begin(), SECOND_KEY.end());
    errCode = kvStorePtr->Insert(SECOND_KEY, value);
    value.clear();
    EXPECT_EQ(errCode, E_OK);

    value.assign(THIRD_KEY.begin(), THIRD_KEY.end());
    errCode = kvStorePtr->Insert(THIRD_KEY, value);
    value.clear();
    EXPECT_EQ(errCode, E_OK);
}

void MediaLibraryThumbnailKvStoreTest::TearDownTestCase(void)
{
    if (kvStorePtr == nullptr) {
        return;
    }
    kvStorePtr->Close();
}

void MediaLibraryThumbnailKvStoreTest::SetUp(void) {}

void MediaLibraryThumbnailKvStoreTest::TearDown(void) {}

HWTEST_F(MediaLibraryThumbnailKvStoreTest, MediaLibrary_KvStore_Insert_test_001, TestSize.Level0)
{
    if (kvStorePtr == nullptr) {
        exit(1);
    }
    std::vector<uint8_t> value;
    value.assign(FORTH_KEY.begin(), FORTH_KEY.end());
    int errCode = kvStorePtr->Insert(FORTH_KEY, value);
    value.clear();
    EXPECT_EQ(errCode, E_OK);
}

HWTEST_F(MediaLibraryThumbnailKvStoreTest, MediaLibrary_KvStore_Delete_test_002, TestSize.Level0)
{
    if (kvStorePtr == nullptr) {
        exit(1);
    }
    int errCode = kvStorePtr->Delete(FIRST_KEY);
    EXPECT_EQ(errCode, E_OK);
}

HWTEST_F(MediaLibraryThumbnailKvStoreTest, MediaLibrary_KvStore_Query_test_003, TestSize.Level0)
{
    if (kvStorePtr == nullptr) {
        exit(1);
    }
    std::vector<uint8_t> value;
    int errCode = kvStorePtr->Query(FIRST_KEY, value);
    EXPECT_NE(errCode, E_OK);

    errCode = kvStorePtr->Query(SECOND_KEY, value);
    EXPECT_EQ(errCode, E_OK);
}

HWTEST_F(MediaLibraryThumbnailKvStoreTest, MediaLibrary_KvStore_BatchQuery_test_004, TestSize.Level0)
{
    if (kvStorePtr == nullptr) {
        exit(1);
    }
    std::vector<std::string> uriBatch;
    std::vector<std::vector<uint8_t>> dataBatch;
    uriBatch.push_back(FORTH_KEY);
    uriBatch.push_back(THIRD_KEY);
    uriBatch.push_back(SECOND_KEY);
    uriBatch.push_back(FIRST_KEY);
    int errCode = kvStorePtr->BatchQuery(uriBatch, dataBatch);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_EQ(dataBatch.size(), 3);
    dataBatch.clear();

    std::vector<uint8_t> value;
    value.assign(FIRST_KEY.begin(), FIRST_KEY.end());
    errCode = kvStorePtr->Insert(FIRST_KEY, value);
    value.clear();
    EXPECT_EQ(errCode, E_OK);

    errCode = kvStorePtr->BatchQuery(uriBatch, dataBatch);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_EQ(dataBatch.size(), 4);
    dataBatch.clear();

    errCode = kvStorePtr->Delete(SECOND_KEY);
    EXPECT_EQ(errCode, E_OK);
    errCode = kvStorePtr->Delete(THIRD_KEY);
    EXPECT_EQ(errCode, E_OK);

    errCode = kvStorePtr->BatchQuery(uriBatch, dataBatch);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_EQ(dataBatch.size(), 2);
    dataBatch.clear();
}
} // namespace Media
} // namespace OHOS