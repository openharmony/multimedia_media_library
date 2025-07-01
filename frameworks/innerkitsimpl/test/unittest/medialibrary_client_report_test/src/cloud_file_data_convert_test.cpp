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

#include "cloud_file_data_convert_test.h"
#include "cloud_file_data_convert.h"
#include "media_log.h"

using namespace testing::ext;

namespace OHOS::Media::CloudSync {
void CloudFileDataConvertTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
}

void CloudFileDataConvertTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase");
}

// SetUp:Execute before each test case
void CloudFileDataConvertTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void CloudFileDataConvertTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

HWTEST_F(CloudFileDataConvertTest, GetFileSize_Report, TestSize.Level0)
{
    CloudFileDataConvert convertor(CloudOperationType::FILE_CREATE, 0);
    std::string path = "";
    std::string thumbSuffix = "";
    int64_t fileSize;
    const int32_t ERR = 12002;

    EXPECT_EQ(convertor.GetFileSize(path, thumbSuffix, fileSize), ERR);
}
}  // namespace OHOS::Media::CloudSync