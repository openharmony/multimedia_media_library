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

#define MLOG_TAG "PhotoAlbumCopyMetaDataOperationTest"

#include "photo_album_copy_meta_data_operation_test.h"

#include <string>
#include <vector>

#include "photo_album_copy_meta_data_operation.h"
#include "media_log.h"

using namespace testing::ext;

namespace OHOS::Media {
void PhotoAlbumCopyMetaDataOperationTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
}

void PhotoAlbumCopyMetaDataOperationTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase");
}

void PhotoAlbumCopyMetaDataOperationTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void PhotoAlbumCopyMetaDataOperationTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

HWTEST_F(PhotoAlbumCopyMetaDataOperationTest, CopyAlbumMetaData_Test, TestSize.Level0)
{
    NativeRdb::ValuesBucket values;
    int32_t newAlbumId = PhotoAlbumCopyMetaDataOperation()
                                .SetRdbStore(nullptr)
                                .CopyAlbumMetaData(values);
    EXPECT_EQ(newAlbumId, -1);
}
} // namespace OHOS::Media