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

#define MLOG_TAG "PhotoAssetCopyOperationTest"

#include "photo_asset_copy_operation_test.h"

#include <string>

#include "media_log.h"
#include "userfile_manager_types.h"
#include "photo_asset_copy_operation.h"

using namespace testing::ext;

namespace OHOS::Media {
void PhotoAssetCopyOperationTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
}

void PhotoAssetCopyOperationTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase");
}

void PhotoAssetCopyOperationTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void PhotoAssetCopyOperationTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

HWTEST_F(PhotoAssetCopyOperationTest, subtype_is_not_burst, TestSize.Level1)
{
    PhotoAssetInfo photoAssetInfo;
    // Pattern: IMG_3025.jpg
    const std::string title = "IMG_3025";
    const std::string extension = ".jpg";
    std::string displayName = title + extension;
    int32_t ownerAlbumId = 0;
    std::shared_ptr<MediaLibraryRdbStore> rdbStore = nullptr;
    std::shared_ptr<NativeRdb::ResultSet> resultSet = nullptr;
    NativeRdb::ValuesBucket values;
    PhotoAssetCopyOperation()
        .SetTargetPhotoInfo(resultSet)
        .SetTargetAlbumId(ownerAlbumId)
        .SetDisplayName(displayName)
        .CopyPhotoAsset(rdbStore, values);
    EXPECT_TRUE(true);
}
}  // namespace OHOS::Media