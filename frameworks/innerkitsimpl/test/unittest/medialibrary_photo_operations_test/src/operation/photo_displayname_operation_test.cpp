/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#define MLOG_TAG "PhotoDisplayNameOperationTest"

#include "photo_displayname_operation_test.h"

#include <string>

#include "photo_displayname_operation.h"
#include "display_name_info.h"
#include "media_log.h"
#include "userfile_manager_types.h"

using namespace testing::ext;

namespace OHOS::Media {
void PhotoDisplayNameOperationTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
}

void PhotoDisplayNameOperationTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase");
}

void PhotoDisplayNameOperationTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void PhotoDisplayNameOperationTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

HWTEST_F(PhotoDisplayNameOperationTest, rdbstore_nullptr, TestSize.Level1)
{
    PhotoAssetInfo photoAssetInfo;
    // Pattern: IMG_3025.jpg
    const std::string title = "IMG_3025";
    const std::string extension = ".jpg";
    photoAssetInfo.displayName = title + extension;
    photoAssetInfo.subtype = static_cast<int32_t>(PhotoSubType::DEFAULT);
    photoAssetInfo.ownerAlbumId = 0;
    std::shared_ptr<MediaLibraryRdbStore> rdbStore = nullptr;
    std::string displayName = PhotoDisplayNameOperation().SetTargetPhotoInfo(photoAssetInfo).FindDisplayName(rdbStore);
    EXPECT_EQ(displayName, photoAssetInfo.displayName);
}
}  // namespace OHOS::Media