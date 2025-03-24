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
#include <thread>
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
const std::string TEST_MONTH_STOREID = "test_month";

std::shared_ptr<MediaLibraryKvStore> kvStorePtr_ = nullptr;
static constexpr int32_t SLEEP_FIVE_SECONDS = 5;

void RestoreTestKvStore()
{
    kvStorePtr_ = std::make_shared<MediaLibraryKvStore>();
    int errCode = kvStorePtr_->Init(KvStoreRoleType::OWNER, KvStoreValueType::MONTH_ASTC, TEST_PATH);
    if (errCode != E_OK) {
        kvStorePtr_ = nullptr;
        return;
    }

    std::vector<uint8_t> value;
    value.assign(FIRST_KEY.begin(), FIRST_KEY.end());
    errCode = kvStorePtr_->Insert(FIRST_KEY, value);
    value.clear();
    EXPECT_EQ(errCode, E_OK);

    value.assign(SECOND_KEY.begin(), SECOND_KEY.end());
    errCode = kvStorePtr_->Insert(SECOND_KEY, value);
    value.clear();
    EXPECT_EQ(errCode, E_OK);

    value.assign(THIRD_KEY.begin(), THIRD_KEY.end());
    errCode = kvStorePtr_->Insert(THIRD_KEY, value);
    value.clear();
    EXPECT_EQ(errCode, E_OK);
}

void MediaLibraryThumbnailKvStoreTest::SetUpTestCase(void)
{
    RestoreTestKvStore();
}

void MediaLibraryThumbnailKvStoreTest::TearDownTestCase(void)
{
    if (kvStorePtr_ == nullptr) {
        return;
    }
    kvStorePtr_->Close();
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
}

void MediaLibraryThumbnailKvStoreTest::SetUp(void) {}

void MediaLibraryThumbnailKvStoreTest::TearDown(void) {}

HWTEST_F(MediaLibraryThumbnailKvStoreTest, MediaLibrary_KvStore_Insert_test_001, TestSize.Level0)
{
    EXPECT_NE(kvStorePtr_, nullptr);
    std::vector<uint8_t> value;
    value.assign(FORTH_KEY.begin(), FORTH_KEY.end());
    int errCode = kvStorePtr_->Insert(FORTH_KEY, value);
    value.clear();
    EXPECT_EQ(errCode, E_OK);
}

HWTEST_F(MediaLibraryThumbnailKvStoreTest, MediaLibrary_KvStore_Delete_test_002, TestSize.Level0)
{
    EXPECT_NE(kvStorePtr_, nullptr);
    int errCode = kvStorePtr_->Delete(FIRST_KEY);
    EXPECT_EQ(errCode, E_OK);
}

HWTEST_F(MediaLibraryThumbnailKvStoreTest, MediaLibrary_KvStore_Query_test_003, TestSize.Level0)
{
    EXPECT_NE(kvStorePtr_, nullptr);
    std::vector<uint8_t> value;
    int errCode = kvStorePtr_->Query(FIRST_KEY, value);
    EXPECT_NE(errCode, E_OK);

    errCode = kvStorePtr_->Query(SECOND_KEY, value);
    EXPECT_EQ(errCode, E_OK);
}

HWTEST_F(MediaLibraryThumbnailKvStoreTest, MediaLibrary_KvStore_BatchQuery_test_004, TestSize.Level0)
{
    EXPECT_NE(kvStorePtr_, nullptr);
    std::vector<std::string> uriBatch;
    std::vector<std::vector<uint8_t>> dataBatch;
    uriBatch.push_back(FORTH_KEY);
    uriBatch.push_back(THIRD_KEY);
    uriBatch.push_back(SECOND_KEY);
    uriBatch.push_back(FIRST_KEY);
    int errCode = kvStorePtr_->BatchQuery(uriBatch, dataBatch);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_EQ(dataBatch.size(), 4);
    dataBatch.clear();

    std::vector<uint8_t> value;
    value.assign(FIRST_KEY.begin(), FIRST_KEY.end());
    errCode = kvStorePtr_->Insert(FIRST_KEY, value);
    value.clear();
    EXPECT_EQ(errCode, E_OK);

    errCode = kvStorePtr_->BatchQuery(uriBatch, dataBatch);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_EQ(dataBatch.size(), 4);
    dataBatch.clear();

    errCode = kvStorePtr_->Delete(SECOND_KEY);
    EXPECT_EQ(errCode, E_OK);
    errCode = kvStorePtr_->Delete(THIRD_KEY);
    EXPECT_EQ(errCode, E_OK);

    errCode = kvStorePtr_->BatchQuery(uriBatch, dataBatch);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_EQ(dataBatch.size(), 4);
    dataBatch.clear();
}

HWTEST_F(MediaLibraryThumbnailKvStoreTest, MediaLibrary_KvStore_RebuildKvStore_test_005, TestSize.Level0)
{
    EXPECT_NE(kvStorePtr_, nullptr);
    auto monthKvStorePtr = std::make_shared<MediaLibraryKvStore>();
    int errCode = monthKvStorePtr->Init(KvStoreRoleType::OWNER, KvStoreValueType::MONTH_ASTC, TEST_PATH);
    EXPECT_EQ(errCode, E_OK);
    errCode = monthKvStorePtr->RebuildKvStore(KvStoreValueType::MONTH_ASTC, TEST_PATH);
    EXPECT_EQ(errCode, E_OK);

    auto yearKvStorePtr = std::make_shared<MediaLibraryKvStore>();
    errCode = yearKvStorePtr->Init(KvStoreRoleType::OWNER, KvStoreValueType::YEAR_ASTC, TEST_PATH);
    EXPECT_EQ(errCode, E_OK);
    errCode = yearKvStorePtr->RebuildKvStore(KvStoreValueType::YEAR_ASTC, TEST_PATH);
    EXPECT_EQ(errCode, E_OK);

    errCode = kvStorePtr_->RebuildKvStore(KvStoreValueType::MONTH_ASTC_OLD_VERSION, TEST_PATH);
    EXPECT_EQ(errCode, E_ERR);
    RestoreTestKvStore();
}

HWTEST_F(MediaLibraryThumbnailKvStoreTest, MediaLibrary_KvStore_BatchInsert_test_006, TestSize.Level0)
{
    EXPECT_NE(kvStorePtr_, nullptr);
    std::vector<DistributedKv::Entry> entries;
    DistributedKv::Entry entry;
    entry.key = FIRST_KEY;
    std::vector<uint8_t> value;
    value.assign(FIRST_KEY.begin(), FIRST_KEY.end());
    entry.value = value;
    auto singleKvStore = std::make_shared<MediaLibraryKvStore>();
    int32_t errCode = singleKvStore->BatchInsert(entries);
    EXPECT_NE(errCode, E_OK);
    errCode = kvStorePtr_->BatchInsert(entries);
    EXPECT_NE(errCode, E_OK);
    entries.emplace_back(std::move(entry));
    errCode = kvStorePtr_->BatchInsert(entries);
    EXPECT_EQ(errCode, E_OK);
}

HWTEST_F(MediaLibraryThumbnailKvStoreTest, MediaLibrary_KvStore_InitSingleKvstore_test_007, TestSize.Level0)
{
    EXPECT_NE(kvStorePtr_, nullptr);
    auto singleOwnerKvStore = std::make_shared<MediaLibraryKvStore>();
    int32_t errCode = singleOwnerKvStore->InitSingleKvstore(KvStoreRoleType::OWNER, TEST_MONTH_STOREID, TEST_PATH);
    EXPECT_EQ(errCode, E_OK);
    auto singleVisitorKvStore = std::make_shared<MediaLibraryKvStore>();
    errCode = singleVisitorKvStore->InitSingleKvstore(KvStoreRoleType::VISITOR, TEST_MONTH_STOREID, TEST_PATH);
    EXPECT_EQ(errCode, E_OK);
}

HWTEST_F(MediaLibraryThumbnailKvStoreTest, MediaLibrary_KvStore_PutAllValueToNewKvStore_test_008, TestSize.Level0)
{
    EXPECT_NE(kvStorePtr_, nullptr);
    auto singleKvStore = std::make_shared<MediaLibraryKvStore>();
    int32_t errCode = singleKvStore->PutAllValueToNewKvStore(kvStorePtr_);
    EXPECT_NE(errCode, E_OK);
    errCode = singleKvStore->InitSingleKvstore(KvStoreRoleType::OWNER, TEST_MONTH_STOREID, TEST_PATH);
    EXPECT_EQ(errCode, E_OK);
    errCode = kvStorePtr_->PutAllValueToNewKvStore(singleKvStore);
    EXPECT_EQ(errCode, E_OK);
}
} // namespace Media
} // namespace OHOS