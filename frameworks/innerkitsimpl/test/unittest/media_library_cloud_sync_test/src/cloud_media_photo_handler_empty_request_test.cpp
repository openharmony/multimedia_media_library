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
#include "cloud_media_photo_handler_empty_request_test.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <utime.h>
#include <fstream>
#include "i_cloud_media_data_handler.h"
#include "cloud_media_data_handler.h"
#include "medialibrary_errno.h"

using namespace testing::ext;
using namespace testing::internal;
namespace OHOS::Media::CloudSync {

void CloudMediaPhotoHandlerEmptyRequestTest::SetUpTestCase(void)
{
    GTEST_LOG_(INFO) << "CloudMediaPhotoHandlerEmptyRequestTest SetUpTestCase";
}

void CloudMediaPhotoHandlerEmptyRequestTest::TearDownTestCase(void)
{
    GTEST_LOG_(INFO) << "CloudMediaPhotoHandlerEmptyRequestTest TearDownTestCase";
}

// SetUp:Execute before each test case
void CloudMediaPhotoHandlerEmptyRequestTest::SetUp()
{
    GTEST_LOG_(INFO) << "CloudMediaPhotoHandlerEmptyRequestTest SetUp";
}

void CloudMediaPhotoHandlerEmptyRequestTest::TearDown(void)
{
    GTEST_LOG_(INFO) << "CloudMediaPhotoHandlerEmptyRequestTest TearDown";
}

HWTEST_F(CloudMediaPhotoHandlerEmptyRequestTest, OnCopyRecords_EMPTY, TestSize.Level1)
{
    std::map<std::string, MDKRecordOperResult> map;
    std::string tableName = "Photos";
    int32_t cloudType = 0;
    int32_t userId = 100;
    int32_t failSize = 0;
    int32_t ret;
    std::shared_ptr<CloudMediaDataHandler> dataHandler =
        std::make_shared<CloudMediaDataHandler>(tableName, cloudType, userId);

    ret = dataHandler->OnCopyRecords(map, failSize);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(0, failSize);
}

HWTEST_F(CloudMediaPhotoHandlerEmptyRequestTest, OnFetchRecords_EMPTY, TestSize.Level1)
{
    std::string tableName = "Photos";
    int32_t cloudType = 0;
    int32_t userId = 100;
    int32_t ret;
    std::shared_ptr<CloudMediaDataHandler> dataHandler =
        std::make_shared<CloudMediaDataHandler>(tableName, cloudType, userId);

    std::vector<MDKRecord> records;
    std::vector<CloudMetaData> newData;
    std::vector<CloudMetaData> fdirtyData;
    std::vector<std::string> failedRecords;
    std::vector<int32_t> stats;

    ret = dataHandler->OnFetchRecords(records, newData, fdirtyData, failedRecords, stats);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaPhotoHandlerEmptyRequestTest, OnDentryFileInsert_EMPTY, TestSize.Level1)
{
    std::string tableName = "Photos";
    int32_t cloudType = 0;
    int32_t userId = 100;
    int32_t ret;
    std::shared_ptr<CloudMediaDataHandler> dataHandler =
        std::make_shared<CloudMediaDataHandler>(tableName, cloudType, userId);

    std::vector<MDKRecord> records;
    std::vector<std::string> failedRecords;

    ret = dataHandler->OnDentryFileInsert(records, failedRecords);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaPhotoHandlerEmptyRequestTest, GetCheckRecords_EMPTY, TestSize.Level1)
{
    std::string tableName = "Photos";
    int32_t cloudType = 0;
    int32_t userId = 100;
    int32_t ret;
    std::shared_ptr<CloudMediaDataHandler> dataHandler =
        std::make_shared<CloudMediaDataHandler>(tableName, cloudType, userId);

    std::vector<std::string> cloudIds;
    std::unordered_map<std::string, CloudCheckData> checkRecords;

    ret = dataHandler->GetCheckRecords(cloudIds, checkRecords);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaPhotoHandlerEmptyRequestTest, OnCreateRecords_EMPTY, TestSize.Level1)
{
    std::string tableName = "Photos";
    int32_t cloudType = 0;
    int32_t userId = 100;
    int32_t ret;
    std::shared_ptr<CloudMediaDataHandler> dataHandler =
        std::make_shared<CloudMediaDataHandler>(tableName, cloudType, userId);

    std::map<std::string, MDKRecordOperResult> map;
    int32_t failSize = 0;

    ret = dataHandler->OnCreateRecords(map, failSize);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(0, failSize);
}

HWTEST_F(CloudMediaPhotoHandlerEmptyRequestTest, OnMdirtyRecords_EMPTY, TestSize.Level1)
{
    std::string tableName = "Photos";
    int32_t cloudType = 0;
    int32_t userId = 100;
    int32_t ret;
    std::shared_ptr<CloudMediaDataHandler> dataHandler =
        std::make_shared<CloudMediaDataHandler>(tableName, cloudType, userId);

    std::map<std::string, MDKRecordOperResult> map;
    int32_t failSize = 0;

    ret = dataHandler->OnMdirtyRecords(map, failSize);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(0, failSize);
}

HWTEST_F(CloudMediaPhotoHandlerEmptyRequestTest, OnFdirtyRecords_EMPTY, TestSize.Level1)
{
    std::string tableName = "Photos";
    int32_t cloudType = 0;
    int32_t userId = 100;
    int32_t ret;
    std::shared_ptr<CloudMediaDataHandler> dataHandler =
        std::make_shared<CloudMediaDataHandler>(tableName, cloudType, userId);

    std::map<std::string, MDKRecordOperResult> map;
    int32_t failSize = 0;

    ret = dataHandler->OnFdirtyRecords(map, failSize);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(0, failSize);
}

HWTEST_F(CloudMediaPhotoHandlerEmptyRequestTest, OnDeleteRecords_EMPTY, TestSize.Level1)
{
    std::string tableName = "Photos";
    int32_t cloudType = 0;
    int32_t userId = 100;
    int32_t ret;
    std::shared_ptr<CloudMediaDataHandler> dataHandler =
        std::make_shared<CloudMediaDataHandler>(tableName, cloudType, userId);

    std::map<std::string, MDKRecordOperResult> map;
    int32_t failSize = 0;

    ret = dataHandler->OnDeleteRecords(map, failSize);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(0, failSize);
}
}  // namespace OHOS::Media::CloudSync