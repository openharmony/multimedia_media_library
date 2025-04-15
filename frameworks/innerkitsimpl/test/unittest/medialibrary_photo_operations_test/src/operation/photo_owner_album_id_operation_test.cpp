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

#define MLOG_TAG "PhotoOwnerAlbumIdOperationTest"

#include "photo_owner_album_id_operation_test.h"

#include <string>

#include "media_log.h"
#include "photo_owner_album_id_operation.h"

using namespace testing::ext;

namespace OHOS::Media {
void PhotoOwnerAlbumIdOperationTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
}

void PhotoOwnerAlbumIdOperationTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase");
}

void PhotoOwnerAlbumIdOperationTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void PhotoOwnerAlbumIdOperationTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

HWTEST_F(PhotoOwnerAlbumIdOperationTest, FixPhotoRelation_NULL_RDB_Test, TestSize.Level1)
{
    std::vector<std::string> fileIds = {"1", "2", "3"};
    std::shared_ptr<MediaLibraryRdbStore> uniStore = nullptr;
    int32_t ret = PhotoOwnerAlbumIdOperation().SetRdbStore(uniStore).SetFileIds(fileIds).FixPhotoRelation();
    EXPECT_EQ(ret, E_ERR);
}
}  // namespace OHOS::Media