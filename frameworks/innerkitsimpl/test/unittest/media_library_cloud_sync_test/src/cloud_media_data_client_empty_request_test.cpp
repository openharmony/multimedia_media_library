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
#include "cloud_media_data_client_empty_request_test.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <utime.h>
#include <fstream>
#include "cloud_media_data_client.h"
#include "medialibrary_errno.h"

using namespace testing::ext;
using namespace testing::internal;
namespace OHOS::Media::CloudSync {

void CloudMediaDataClientEmptyRequestTest::SetUpTestCase(void)
{
    GTEST_LOG_(INFO) << "CloudMediaDataClientEmptyRequestTest SetUpTestCase";
}

void CloudMediaDataClientEmptyRequestTest::TearDownTestCase(void)
{
    GTEST_LOG_(INFO) << "CloudMediaDataClientEmptyRequestTest TearDownTestCase";
}

// SetUp:Execute before each test case
void CloudMediaDataClientEmptyRequestTest::SetUp()
{
    GTEST_LOG_(INFO) << "CloudMediaDataClientEmptyRequestTest SetUp";
}

void CloudMediaDataClientEmptyRequestTest::TearDown(void)
{
    GTEST_LOG_(INFO) << "CloudMediaDataClientEmptyRequestTest TearDown";
}

HWTEST_F(CloudMediaDataClientEmptyRequestTest, OnDownloadAsset_EMPTY, TestSize.Level1)
{
    std::vector<std::string> cloudIds;
    CloudMediaDataClient cloudMediaDataClient(100);
    std::vector<MediaOperateResult> result;
    int32_t ret = cloudMediaDataClient.OnDownloadAsset(cloudIds, result);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaDataClientEmptyRequestTest, UpdatePosition_EMPTY, TestSize.Level1)
{
    std::vector<std::string> cloudIds;
    CloudMediaDataClient cloudMediaDataClient(100);
    int32_t position = 0;
    int32_t ret = cloudMediaDataClient.UpdatePosition(cloudIds, position);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaDataClientEmptyRequestTest, GetDownloadAsset_EMPTY, TestSize.Level1)
{
    std::vector<std::string> cloudIds;
    CloudMediaDataClient cloudMediaDataClient(100);
    std::vector<CloudMetaData> cloudMetaDataVec;
    int32_t ret = cloudMediaDataClient.GetDownloadAsset(cloudIds, cloudMetaDataVec);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaDataClientEmptyRequestTest, GetDownloadThmsByUri_EMPTY, TestSize.Level1)
{
    std::vector<std::string> cloudIds;
    CloudMediaDataClient cloudMediaDataClient(100);
    int32_t type = 0;
    std::vector<CloudMetaData> metaData;
    int32_t ret = cloudMediaDataClient.GetDownloadThmsByUri(cloudIds, type, metaData);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaDataClientEmptyRequestTest, OnDownloadThms_EMPTY, TestSize.Level1)
{
    CloudMediaDataClient cloudMediaDataClient(100);
    std::unordered_map<std::string, int32_t> resMap;
    int32_t failSize = 0;
    int32_t ret = cloudMediaDataClient.OnDownloadThms(resMap, failSize);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaDataClientEmptyRequestTest, UpdateLocalFileDirty_EMPTY, TestSize.Level1)
{
    CloudMediaDataClient cloudMediaDataClient(100);
    std::vector<MDKRecord> records;
    int32_t ret = cloudMediaDataClient.UpdateLocalFileDirty(records);
    EXPECT_EQ(ret, E_OK);
}
}  // namespace OHOS::Media::CloudSync