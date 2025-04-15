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

#define MLOG_TAG "PhotoBurstOperationTest"

#include "photo_burst_operation_test.h"

#include <string>

#include "photo_burst_operation.h"
#include "display_name_info.h"
#include "media_log.h"
#include "userfile_manager_types.h"

using namespace testing::ext;

namespace OHOS::Media {
void PhotoBurstOperationTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
}

void PhotoBurstOperationTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase");
}

void PhotoBurstOperationTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void PhotoBurstOperationTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

HWTEST_F(PhotoBurstOperationTest, subtype_is_not_burst, TestSize.Level1)
{
    PhotoAssetInfo photoAssetInfo;
    // Pattern: IMG_3025.jpg
    const std::string title = "IMG_3025";
    const std::string extension = ".jpg";
    photoAssetInfo.displayName = title + extension;
    photoAssetInfo.subtype = static_cast<int32_t>(PhotoSubType::DEFAULT);
    photoAssetInfo.ownerAlbumId = 0;
    std::shared_ptr<MediaLibraryRdbStore> rdbStore = nullptr;
    std::string burstKey = PhotoBurstOperation().SetTargetPhotoInfo(photoAssetInfo).FindBurstKey(rdbStore);
    EXPECT_TRUE(burstKey.empty());
}

HWTEST_F(PhotoBurstOperationTest, rdbstore_nullptr, TestSize.Level1)
{
    PhotoAssetInfo photoAssetInfo;
    // Pattern: IMG_20240222_135017_BURST004.jpg
    const std::string prefix = "IMG_";
    const int32_t yearMonthDay = 20240222;
    const int32_t hourMinuteSecond = 135017;
    const std::string suffix = "_BURST004.jpg";
    photoAssetInfo.displayName =
        prefix + std::to_string(yearMonthDay) + "_" + std::to_string(hourMinuteSecond) + suffix;
    photoAssetInfo.subtype = static_cast<int32_t>(PhotoSubType::BURST);
    photoAssetInfo.ownerAlbumId = 0;
    std::shared_ptr<MediaLibraryRdbStore> rdbStore = nullptr;
    std::string burstKey = PhotoBurstOperation().SetTargetPhotoInfo(photoAssetInfo).FindBurstKey(rdbStore);
    EXPECT_TRUE(burstKey.empty());
}
}  // namespace OHOS::Media