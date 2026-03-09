/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "cloud_media_photos_rename_service_test.h"

#include "media_log.h"
#include "medialibrary_errno.h"
#include "photo_album_column.h"
#include "media_file_utils.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_rdbstore.h"
#include "photos_po.h"
#include "photos_dto.h"
#include "asset_accurate_refresh.h"
#include "photo_asset_info.h"
#include "cloud_media_photos_rename_service.h"

using namespace std;
using namespace testing::ext;

namespace OHOS::Media::CloudSync {

static shared_ptr<MediaLibraryRdbStore> g_rdbStore;

void CloudMediaPhotosRenameServiceTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "SetUpTestCase";
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    ASSERT_NE(g_rdbStore, nullptr);
}

void CloudMediaPhotosRenameServiceTest::TearDownTestCase()
{
    GTEST_LOG_(INFO) << "TearDownTestCase";
    g_rdbStore = nullptr;
    MediaLibraryDataManager::GetInstance()->ClearMediaLibraryMgr();
}

void CloudMediaPhotosRenameServiceTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void CloudMediaPhotosRenameServiceTest::TearDown()
{
    MEDIA_INFO_LOG("TearDown");
}

HWTEST_F(CloudMediaPhotosRenameServiceTest, FindTitleAndSuffix_NoSuffix_Test_001, TestSize.Level1)
{
    // 用例说明：测试 FindTitleAndSuffix 方法，输入没有后缀的文件名
    CloudMediaPhotosRenameService service;
    std::string displayName = "IMG_3025";
    std::string title;
    std::string suffix;

    int32_t ret = service.FindTitleAndSuffix(displayName, title, suffix);

    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(title, displayName);
    EXPECT_EQ(suffix, "");
}

HWTEST_F(CloudMediaPhotosRenameServiceTest, FindTitleAndSuffix_WithSuffix_Test_001, TestSize.Level1)
{
    // 用例说明：测试 FindTitleAndSuffix 方法，输入有后缀的文件名
    CloudMediaPhotosRenameService service;
    std::string displayName = "IMG_3025.jpg";
    std::string title;
    std::string suffix;

    int32_t ret = service.FindTitleAndSuffix(displayName, title, suffix);

    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(title, "IMG_3025");
    EXPECT_EQ(suffix, ".jpg");
}

HWTEST_F(CloudMediaPhotosRenameServiceTest, FindTitleAndSuffix_MultipleDots_Test_001, TestSize.Level1)
{
    // 用例说明：测试 FindTitleAndSuffix 方法，输入包含多个点的文件名
    CloudMediaPhotosRenameService service;
    std::string displayName = "IMG.3025.test.jpg";
    std::string title;
    std::string suffix;

    int32_t ret = service.FindTitleAndSuffix(displayName, title, suffix);

    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(title, "IMG.3025.test");
    EXPECT_EQ(suffix, ".jpg");
}

HWTEST_F(CloudMediaPhotosRenameServiceTest, FindTitleAndSuffix_EmptyString_Test_001, TestSize.Level1)
{
    // 用例说明：测试 FindTitleAndSuffix 方法，输入空字符串
    CloudMediaPhotosRenameService service;
    std::string displayName = "";
    std::string title;
    std::string suffix;

    int32_t ret = service.FindTitleAndSuffix(displayName, title, suffix);

    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(title, "");
    EXPECT_EQ(suffix, "");
}

HWTEST_F(CloudMediaPhotosRenameServiceTest, FindTitleAndSuffix_OnlyDot_Test_001, TestSize.Level1)
{
    // 用例说明：测试 FindTitleAndSuffix 方法，输入只有点的文件名
    CloudMediaPhotosRenameService service;
    std::string displayName = ".";
    std::string title;
    std::string suffix;

    int32_t ret = service.FindTitleAndSuffix(displayName, title, suffix);

    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(title, "");
    EXPECT_EQ(suffix, ".");
}

HWTEST_F(CloudMediaPhotosRenameServiceTest, FindNextDisplayName_Normal_Test_001, TestSize.Level1)
{
    // 用例说明：测试 FindNextDisplayName 方法，正常情况
    CloudMediaPhotosRenameService service;
    PhotosPo photoInfo;
    photoInfo.fileId = 1;
    photoInfo.displayName = "IMG_3025.jpg";
    photoInfo.ownerAlbumId = 0;
    photoInfo.subtype = static_cast<int32_t>(PhotoSubType::DEFAULT);
    std::string nextDisplayName;

    int32_t ret = service.FindNextDisplayName(photoInfo, nextDisplayName);

    EXPECT_EQ(ret, E_OK);
    EXPECT_FALSE(nextDisplayName.empty());
}

HWTEST_F(CloudMediaPhotosRenameServiceTest, FindNextStoragePath_EmptyStoragePath_Test_001, TestSize.Level1)
{
    // 用例说明：测试 FindNextStoragePath 方法，storagePath 为空
    CloudMediaPhotosRenameService service;
    PhotosPo photoInfo;
    photoInfo.storagePath = "";
    std::string nextDisplayName = "IMG_3025.jpg";
    std::string nextStoragePath;

    int32_t ret = service.FindNextStoragePath(photoInfo, nextDisplayName, nextStoragePath);

    EXPECT_EQ(ret, E_DATA);
}

HWTEST_F(CloudMediaPhotosRenameServiceTest, FindNextStoragePath_EmptyNextDisplayName_Test_001, TestSize.Level1)
{
    // 用例说明：测试 FindNextStoragePath 方法，nextDisplayName 为空
    CloudMediaPhotosRenameService service;
    PhotosPo photoInfo;
    photoInfo.storagePath = "/storage/cloud/files/IMG_3025.jpg";
    std::string nextDisplayName = "";
    std::string nextStoragePath;

    int32_t ret = service.FindNextStoragePath(photoInfo, nextDisplayName, nextStoragePath);

    EXPECT_EQ(ret, E_DATA);
}

HWTEST_F(CloudMediaPhotosRenameServiceTest, FindNextStoragePath_NoSlash_Test_001, TestSize.Level1)
{
    // 用例说明：测试 FindNextStoragePath 方法，storagePath 没有斜杠
    CloudMediaPhotosRenameService service;
    PhotosPo photoInfo;
    photoInfo.storagePath = "IMG_3025.jpg";
    std::string nextDisplayName = "IMG_3026.jpg";
    std::string nextStoragePath;

    int32_t ret = service.FindNextStoragePath(photoInfo, nextDisplayName, nextStoragePath);

    EXPECT_EQ(ret, E_DATA);
}

HWTEST_F(CloudMediaPhotosRenameServiceTest, FindNextStoragePath_RenameFailed_Test_001, TestSize.Level1)
{
    // 用例说明：测试 FindNextStoragePath 方法，rename 系统调用失败
    CloudMediaPhotosRenameService service;
    PhotosPo photoInfo;
    photoInfo.storagePath = "/storage/cloud/files/nonexistent.jpg";
    std::string nextDisplayName = "IMG_3026.jpg";
    std::string nextStoragePath;

    int32_t ret = service.FindNextStoragePath(photoInfo, nextDisplayName, nextStoragePath);

    EXPECT_EQ(ret, E_DATA);
}

HWTEST_F(CloudMediaPhotosRenameServiceTest, RenameAsset_EmptyNextDisplayName_Test_001, TestSize.Level1)
{
    // 用例说明：测试 RenameAsset 方法，nextDisplayName 为空
    CloudMediaPhotosRenameService service;
    PhotosPo photoInfo;
    photoInfo.fileId = 1;
    std::string nextDisplayName = "";
    auto photoRefresh = make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = service.RenameAsset(photoInfo, nextDisplayName, photoRefresh);

    EXPECT_EQ(ret, E_DATA);
}

HWTEST_F(CloudMediaPhotosRenameServiceTest, RenameAsset_EmptyTitle_Test_001, TestSize.Level1)
{
    // 用例说明：测试 RenameAsset 方法，nextTitle 为空
    CloudMediaPhotosRenameService service;
    PhotosPo photoInfo;
    photoInfo.fileId = 1;
    std::string nextDisplayName = "IMG_3025";
    auto photoRefresh = make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = service.RenameAsset(photoInfo, nextDisplayName, photoRefresh);

    EXPECT_EQ(ret, E_DATA);
}

HWTEST_F(CloudMediaPhotosRenameServiceTest, RenameAsset_NullPhotoRefresh_Test_001, TestSize.Level1)
{
    // 用例说明：测试 RenameAsset 方法，photoRefresh 为空
    CloudMediaPhotosRenameService service;
    PhotosPo photoInfo;
    photoInfo.fileId = 1;
    std::string nextDisplayName = "IMG_3025.jpg";
    std::shared_ptr<AccurateRefresh::AssetAccurateRefresh> photoRefresh = nullptr;

    int32_t ret = service.RenameAsset(photoInfo, nextDisplayName, photoRefresh);

    EXPECT_EQ(ret, E_RDB_STORE_NULL);
}

HWTEST_F(CloudMediaPhotosRenameServiceTest, HandleSameNameRename_NoLocalInfo_Test_001, TestSize.Level1)
{
    // 用例说明：测试 HandleSameNameRename 方法，localInfoOp 无值
    CloudMediaPhotosRenameService service;
    PhotosDto photo;
    photo.localInfoOp = std::nullopt;
    auto photoRefresh = make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = service.HandleSameNameRename(photo, photoRefresh);

    EXPECT_EQ(ret, E_DATA);
}

HWTEST_F(CloudMediaPhotosRenameServiceTest, HandleSameNameRename_FindNextDisplayNameFailed_Test_001, TestSize.Level1)
{
    // 用例说明：测试 HandleSameNameRename 方法，FindNextDisplayName 失败
    CloudMediaPhotosRenameService service;
    PhotosDto photo;
    PhotosPo photoInfo;
    photoInfo.fileId = 0;
    photoInfo.displayName = "";
    photoInfo.ownerAlbumId = 0;
    photoInfo.subtype = 0;
    photo.localInfoOp = photoInfo;
    auto photoRefresh = make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = service.HandleSameNameRename(photo, photoRefresh);

    EXPECT_NE(ret, E_OK);
}

HWTEST_F(CloudMediaPhotosRenameServiceTest, RenameAsset_WithStoragePath_Test_001, TestSize.Level1)
{
    // 用例说明：测试 RenameAsset 方法，FindNextStoragePath 成功且返回非空路径
    CloudMediaPhotosRenameService service;
    PhotosPo photoInfo;
    photoInfo.fileId = 99999;
    photoInfo.storagePath = "/storage/cloud/files/test_old.jpg";
    std::string nextDisplayName = "test_new.jpg";
    auto photoRefresh = make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = service.RenameAsset(photoInfo, nextDisplayName, photoRefresh);

    EXPECT_NE(ret, E_OK);
}

HWTEST_F(CloudMediaPhotosRenameServiceTest, RenameAsset_WithoutStoragePath_Test_001, TestSize.Level1)
{
    // 用例说明：测试 RenameAsset 方法，FindNextStoragePath 返回空路径
    CloudMediaPhotosRenameService service;
    PhotosPo photoInfo;
    photoInfo.fileId = 99999;
    std::string nextDisplayName = "IMG_3025.jpg";
    auto photoRefresh = make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = service.RenameAsset(photoInfo, nextDisplayName, photoRefresh);

    EXPECT_NE(ret, E_OK);
}

HWTEST_F(CloudMediaPhotosRenameServiceTest, HandleSameNameRename_SuccessPath_Test_001, TestSize.Level1)
{
    // 用例说明：测试 HandleSameNameRename 方法，完整成功路径
    CloudMediaPhotosRenameService service;
    PhotosDto photo;
    PhotosPo photoInfo;
    photoInfo.fileId = 99999;
    photoInfo.displayName = "IMG_3025.jpg";
    photoInfo.ownerAlbumId = 0;
    photoInfo.subtype = static_cast<int32_t>(PhotoSubType::DEFAULT);
    photo.localInfoOp = photoInfo;
    auto photoRefresh = make_shared<AccurateRefresh::AssetAccurateRefresh>();

    int32_t ret = service.HandleSameNameRename(photo, photoRefresh);

    EXPECT_NE(ret, E_OK);
}
}  // namespace OHOS::Media::CloudSync
