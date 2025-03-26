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

#define MLOG_TAG "PhotoAlbumCloneTest"

#define private public
#define protected public
#include "photo_album_clone.h"
#undef private
#undef protected

#include "photo_album_clone_test.h"
#include <string>
#include "media_log.h"
#include "userfile_manager_types.h"

using namespace testing::ext;

namespace OHOS::Media {
static constexpr int32_t SLEEP_FIVE_SECONDS = 5;

void PhotoAlbumCloneTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
}

void PhotoAlbumCloneTest::TearDownTestCase(void)
{
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
    MEDIA_INFO_LOG("TearDownTestCase");
}

void PhotoAlbumCloneTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void PhotoAlbumCloneTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

HWTEST_F(PhotoAlbumCloneTest, GetPhotoAlbumCountInOriginalDb_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetPhotoAlbumCountInOriginalDb_Test start");
    auto count = PhotoAlbumClone().GetPhotoAlbumCountInOriginalDb();
    EXPECT_EQ(count, 0);
    MEDIA_INFO_LOG("GetPhotoAlbumCountInOriginalDb_Test end");
}

HWTEST_F(PhotoAlbumCloneTest, GetPhotoAlbumInOriginalDb_Test, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetPhotoAlbumInOriginalDb_Test start");
    int32_t offset = 0;
    int32_t count = 200;
    auto resultSet = PhotoAlbumClone().GetPhotoAlbumInOriginalDb(offset, count);
    EXPECT_EQ(resultSet, nullptr);
    MEDIA_INFO_LOG("GetPhotoAlbumInOriginalDb_Test end");
}
}  // namespace OHOS::Media