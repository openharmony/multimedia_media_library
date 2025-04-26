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

#define MLOG_TAG "PhotosDataHandlerTest"

#define private public
#define protected public
#include "photos_data_handler.h"
#undef private
#undef protected

#include "photos_data_handler_test.h"
#include <string>
#include "media_log.h"
#include "userfile_manager_types.h"

using namespace testing::ext;

namespace OHOS::Media {
static constexpr int32_t SLEEP_FIVE_SECONDS = 5;

void PhotosDataHandlerTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
}

void PhotosDataHandlerTest::TearDownTestCase(void)
{
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
    MEDIA_INFO_LOG("TearDownTestCase");
}

void PhotosDataHandlerTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void PhotosDataHandlerTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

HWTEST_F(PhotosDataHandlerTest, CleanDirtyFiles_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("CleanDirtyFiles_Test start");
    int32_t offset = 0;
    std::vector<PhotosDao::PhotosRowData> dirtyFiles = PhotosDataHandler().photosDao_.GetDirtyFiles(offset);
    int32_t count = PhotosDataHandler().CleanDirtyFiles(dirtyFiles);
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("CleanDirtyFiles_Test end");
}
}  // namespace OHOS::Media