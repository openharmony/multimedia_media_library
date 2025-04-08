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

#define MLOG_TAG "PhotoAlbumLPathOperationTest"

#include "photo_album_lpath_operation_test.h"

#include <string>
#include <vector>

#include "photo_album_lpath_operation.h"
#include "media_log.h"

using namespace testing::ext;

namespace OHOS::Media {
void PhotoAlbumLPathOperationTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
}

void PhotoAlbumLPathOperationTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase");
}

void PhotoAlbumLPathOperationTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void PhotoAlbumLPathOperationTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

HWTEST_F(PhotoAlbumLPathOperationTest, CleanInvalidPhotoAlbums_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CleanInvalidPhotoAlbums_Test_001");
    int32_t affectedCount = PhotoAlbumLPathOperation::GetInstance()
                                .SetRdbStore(nullptr)
                                .Start()
                                .CleanInvalidPhotoAlbums()
                                .GetAlbumAffectedCount();
    EXPECT_EQ(affectedCount, 0);
}

HWTEST_F(PhotoAlbumLPathOperationTest, CleanInvalidPhotoAlbums_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CleanInvalidPhotoAlbums_Test_002");
    PhotoAlbumLPathOperation::GetInstance()
        .SetRdbStore(nullptr)
        .Start()
        .Stop();
    int32_t affectedCount = PhotoAlbumLPathOperation::GetInstance()
                                .CleanInvalidPhotoAlbums()
                                .GetAlbumAffectedCount();
    EXPECT_EQ(affectedCount, 0);
}

HWTEST_F(PhotoAlbumLPathOperationTest, CleanDuplicatePhotoAlbums_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CleanDuplicatePhotoAlbums_Test_001");
    int32_t affectedCount = PhotoAlbumLPathOperation::GetInstance()
                                .SetRdbStore(nullptr)
                                .Start()
                                .CleanDuplicatePhotoAlbums()
                                .GetAlbumAffectedCount();
    EXPECT_EQ(affectedCount, 0);
}

HWTEST_F(PhotoAlbumLPathOperationTest, CleanDuplicatePhotoAlbums_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CleanDuplicatePhotoAlbums_Test_002");
    PhotoAlbumLPathOperation::GetInstance()
        .SetRdbStore(nullptr)
        .Start()
        .Stop();
    int32_t affectedCount = PhotoAlbumLPathOperation::GetInstance()
                                .CleanDuplicatePhotoAlbums()
                                .GetAlbumAffectedCount();
    EXPECT_EQ(affectedCount, 0);
}

HWTEST_F(PhotoAlbumLPathOperationTest, CleanEmptylPathPhotoAlbums_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CleanEmptylPathPhotoAlbums_Test_001");
    int32_t affectedCount = PhotoAlbumLPathOperation::GetInstance()
                                .SetRdbStore(nullptr)
                                .Start()
                                .CleanEmptylPathPhotoAlbums()
                                .GetAlbumAffectedCount();
    EXPECT_EQ(affectedCount, 0);
}

HWTEST_F(PhotoAlbumLPathOperationTest, CleanEmptylPathPhotoAlbums_Test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start CleanEmptylPathPhotoAlbums_Test_002");
    PhotoAlbumLPathOperation::GetInstance()
        .SetRdbStore(nullptr)
        .Start()
        .Stop();
    int32_t affectedCount = PhotoAlbumLPathOperation::GetInstance()
                                .CleanEmptylPathPhotoAlbums()
                                .GetAlbumAffectedCount();
    EXPECT_EQ(affectedCount, 0);
}

HWTEST_F(PhotoAlbumLPathOperationTest, Get_Invalid_PhotoAlbums_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Get_Invalid_PhotoAlbums_Test_001");
    shared_ptr<PhotoAlbumLPathOperation> ptr = std::make_shared<PhotoAlbumLPathOperation>();
    ASSERT_NE(ptr, nullptr);
    std::vector<PhotoAlbumInfoPo> test;
    test = ptr->GetInvalidPhotoAlbums();
    EXPECT_EQ(test.empty(), true);
    MEDIA_INFO_LOG("Get_Invalid_PhotoAlbums_Test_001 End");
}

HWTEST_F(PhotoAlbumLPathOperationTest, Clean_Duplicate_Photo_Album_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Clean_Duplicate_Photo_Albums_Test_001");
    shared_ptr<PhotoAlbumLPathOperation> ptr = std::make_shared<PhotoAlbumLPathOperation>();
    PhotoAlbumInfoPo mainAlbumInfo;
    int32_t ret;
    mainAlbumInfo.albumId = 10;
    mainAlbumInfo.albumName = "test.jpg";
    mainAlbumInfo.lPath = "/ment/test/test.jpg";
    ASSERT_NE(ptr, nullptr);
    ptr->isContinue_.store(false);
    ret = ptr->CleanDuplicatePhotoAlbum(mainAlbumInfo);
    EXPECT_NE(ret, -1);
    MEDIA_INFO_LOG("Clean_Duplicate_Photo_Albums_Test_001 End");
}

HWTEST_F(PhotoAlbumLPathOperationTest, Clean_Emptyl_Path_Photo_Album_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Clean_Emptyl_Path_Photo_Album_Test_001");
    shared_ptr<PhotoAlbumLPathOperation> ptr = std::make_shared<PhotoAlbumLPathOperation>();
    PhotoAlbumInfoPo mainAlbumInfo;
    int32_t ret;
    ASSERT_NE(ptr, nullptr);
    ptr->isContinue_.store(false);
    ret = ptr->CleanEmptylPathPhotoAlbum(mainAlbumInfo);
    EXPECT_NE(ret, -1);
    MEDIA_INFO_LOG("Clean_Emptyl_Path_Photo_Album_Test_001 End");
}

HWTEST_F(PhotoAlbumLPathOperationTest, Palot_To_String_Test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("Start Clean_Emptyl_Path_Photo_Album_Test_001");
    shared_ptr<PhotoAlbumLPathOperation> ptr = std::make_shared<PhotoAlbumLPathOperation>();
    std::string ret;
    std::vector<NativeRdb::ValueObject> values = { 1, 2, 3, 10 };
    ASSERT_NE(ptr, nullptr);
    ret = ptr->ToString(values);
    EXPECT_NE(ret, "");
    MEDIA_INFO_LOG("Clean_Emptyl_Path_Photo_Album_Test_001 End");
}
}  // namespace OHOS::Media