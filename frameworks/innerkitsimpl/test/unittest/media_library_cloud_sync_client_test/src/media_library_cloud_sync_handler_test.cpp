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

#define MLOG_TAG "MediaCloudSync"

#include "media_library_cloud_sync_handler_test.h"

#include <memory>
#include "media_log.h"
#include "medialibrary_errno.h"

#include "json_helper.h"
#include "cloud_media_album_handler.h"
#include "cloud_media_photo_handler.h"
#include "cloud_media_data_client_handler.h"

using namespace testing::ext;

namespace OHOS::Media::CloudSync {

void CloudMediaHandlerClientTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("start CloudMediaHandlerClientTest::SetUpTestCase");
}

void CloudMediaHandlerClientTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("start CloudMediaHandlerClientTest::TearDownTestCase");
}

void CloudMediaHandlerClientTest::SetUp()
{
    MEDIA_INFO_LOG("setup");
}

void CloudMediaHandlerClientTest::TearDown() {}

HWTEST_F(CloudMediaHandlerClientTest, GetAlbumRecordsIllegalSize_Test, TestSize.Level1)
{
    int32_t failSize = 0;
    std::vector<int32_t> stats;
    std::vector<MDKRecord> records;
    std::vector<CloudMetaData> newData;
    std::vector<std::string> failedRecords;
    std::map<std::string, MDKRecordOperResult> map;
    std::unordered_map<std::string, CloudCheckData> checkRecords;

    auto handler = std::make_shared<CloudMediaAlbumHandler>();
    ASSERT_TRUE(handler);

    handler->OnStartSync();
    handler->OnCompleteSync();
    handler->OnCompletePush();
    handler->OnCompleteCheck();
    handler->OnDentryFileInsert(records, failedRecords);
    handler->GetRetryRecords(failedRecords);
    handler->GetCheckRecords(failedRecords, checkRecords);

    int32_t ret = handler->OnCopyRecords(map, failSize);
    ret = handler->OnDeleteRecords(map, failSize);
    EXPECT_EQ(ret, E_OK);

    MDKRecord record;
    ret = handler->OnFetchRecords(records, newData, newData, failedRecords, stats);
    EXPECT_EQ(ret, E_ERR);
    records.emplace_back(record);
    handler->OnFetchRecords(records, newData, newData, failedRecords, stats);
}

HWTEST_F(CloudMediaHandlerClientTest, OnCreateRecords_EmptyMaps, TestSize.Level1)
{
    int32_t failSize = 0;
    std::map<std::string, MDKRecordOperResult> map;
    auto handler = std::make_shared<CloudMediaAlbumHandler>();
    ASSERT_TRUE(handler);

    int32_t ret = handler->OnCreateRecords(map, failSize);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaHandlerClientTest, JsonHelper_NoJsonObj_Test, TestSize.Level1)
{
    Json::Value data = Json::nullValue;
    string key;
    EXPECT_EQ(JsonHelper::GetStringFromJson(data, key, "test"), "test");
    EXPECT_EQ(JsonHelper::GetIntFromJson(data, key, 1), 1);
    EXPECT_EQ(JsonHelper::GetUIntFromJson(data, key, 2), 2);
    EXPECT_EQ(JsonHelper::GetBoolFromJson(data, key, true), true);
    EXPECT_EQ(JsonHelper::GetUInt64FromJson(data, key, 121), 121);
    EXPECT_EQ(JsonHelper::GetInt64FromJson(data, key, 12), 12);
    EXPECT_EQ(JsonHelper::GetInt64FromJson(data, key), 0);
    JsonHelper::GetDoubleFromJson(data, key);
}

HWTEST_F(CloudMediaHandlerClientTest, CloudMediaPhotoHandler_Test, TestSize.Level1)
{
    auto handler = std::make_shared<CloudMediaPhotoHandler>();
    ASSERT_TRUE(handler);
    handler->OnCompleteCheck();
    handler->OnCompleteSync();
    handler->OnStartSync();
    handler->SetTraceId("00001");
    auto result = handler->GetTraceId();
    EXPECT_EQ(result, "00001");
}
}