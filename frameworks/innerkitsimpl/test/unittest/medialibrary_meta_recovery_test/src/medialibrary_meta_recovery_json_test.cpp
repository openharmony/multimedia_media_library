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

#include <gtest/gtest.h>
#include <set>
#include <string>

#include "get_self_permissions.h"
#include "medialibrary_errno.h"
#define private public
#include "medialibrary_meta_recovery.h"
#undef private
#include "medialibrary_meta_recovery_test_utils.h"
#include "medialibrary_unittest_utils.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
static constexpr int32_t SLEEP_FIVE_SECONDS = 5;

class MedialibraryMetaRecoveryJsonTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void MedialibraryMetaRecoveryJsonTest::SetUpTestCase(void)
{
    MediaLibraryUnitTestUtils::Init();
    std::vector<std::string> perms = {
        "ohos.permissions.MEDIA_LOCATION",
        "ohos.permissions.GET_BUNDLE_INFO_PRIVILEGED",
    };
    uint64_t tokenId = 0;
    PermissionUtilsUnitTest::SetAccessTokenPermission("MedialibraryMetaRecoveryJsonTest", perms, tokenId);
    ASSERT_TRUE(tokenId != 0);
}

void MedialibraryMetaRecoveryJsonTest::TearDownTestCase(void)
{
    MediaLibraryUnitTestUtils::CleanTestFiles();
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
}

void MedialibraryMetaRecoveryJsonTest::SetUp() {}
void MedialibraryMetaRecoveryJsonTest::TearDown() {}

HWTEST_F(MedialibraryMetaRecoveryJsonTest, MedialibraryMetaRecoveryJsonTest_00, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "MedialibraryMetaRecoveryJsonTest_00 begin";

    const std::string originPath = "/data/local/tmp/test_file.jpg";
    const std::string filePath = "/data/local/tmp/test_file.jpg.json";
    int32_t ret = E_OK;
    FileAsset fileAsset1;
    FileAsset fileAsset2;
    MediaLibraryMetaRecovery &recoveryJsonManager = MediaLibraryMetaRecovery::GetInstance();

    EXPECT_TRUE(CreateFile(originPath));
    InitFileAsset(fileAsset1);
    fileAsset1.SetFilePath(originPath);

    ret = recoveryJsonManager.WriteMetadataToFile(filePath, fileAsset1);
    EXPECT_EQ(ret, E_OK);
    ret = recoveryJsonManager.ReadMetadataFromFile(filePath, fileAsset2);
    EXPECT_EQ(ret, E_OK);

    EXPECT_TRUE(CompareFileAsset(fileAsset1, fileAsset2));
    EXPECT_EQ(remove(originPath.c_str()), 0);
    EXPECT_EQ(remove(filePath.c_str()), 0);
    GTEST_LOG_(INFO) << "MedialibraryMetaRecoveryJsonTest_00 ok";
}

HWTEST_F(MedialibraryMetaRecoveryJsonTest, MedialibraryMetaRecoveryJsonTest_01, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "MedialibraryMetaRecoveryJsonTest_01 begin";

    int32_t ret = E_OK;
    const int32_t n = 2;
    const std::string filePath = "/data/local/tmp/album.json";
    std::vector<std::shared_ptr<PhotoAlbum>> vecPhotoAlbum1;
    std::vector<std::shared_ptr<PhotoAlbum>> vecPhotoAlbum2;
    MediaLibraryMetaRecovery &recoveryJsonManager = MediaLibraryMetaRecovery::GetInstance();

    InitPhotoAlbum(vecPhotoAlbum1, n);
    EXPECT_EQ(vecPhotoAlbum1.size(), n);

    ret = recoveryJsonManager.WritePhotoAlbumToFile(filePath, vecPhotoAlbum1);
    EXPECT_EQ(ret, E_OK);
    ret = recoveryJsonManager.ReadPhotoAlbumFromFile(filePath, vecPhotoAlbum2);
    EXPECT_EQ(ret, E_OK);

    bool isOk = ComparePhotoAlbum(vecPhotoAlbum1, vecPhotoAlbum2);
    EXPECT_TRUE(isOk);

    EXPECT_EQ(remove(filePath.c_str()), 0);
    GTEST_LOG_(INFO) << "MedialibraryMetaRecoveryJsonTest_01 ok";
}

static void InsertMetaStatusData(const std::string &key, int32_t val, std::set<int32_t> &status)
{
    int32_t ret = MediaLibraryMetaRecovery::GetInstance().WriteMetaStatusToFile(key, val);
    status.emplace(std::stoi(key));
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MedialibraryMetaRecoveryJsonTest, MedialibraryMetaRecoveryJsonTest_02, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "MedialibraryMetaRecoveryJsonTest_02 begin";
    const std::string metaStatusPath = "/storage/cloud/files/.meta/status.json";
    std::string key1 = "1";
    std::string key2 = "2";
    std::string key3 = "3";
    std::string key4 = "4";
    std::string key5 = "5";
    std::string key6 = "6";
    int32_t val1 = 1;
    int32_t val2 = 2;
    int32_t val3 = 3;
    int32_t val4 = 4;
    int32_t val5 = 5;
    int32_t val6 = 6;
    std::set<int32_t> status;
    std::set<int32_t> readStatus;
    int32_t ret = E_OK;

    InsertMetaStatusData(key1, val1, status);
    InsertMetaStatusData(key2, val2, status);
    InsertMetaStatusData(key3, val3, status);
    InsertMetaStatusData(key4, val4, status);
    InsertMetaStatusData(key5, val5, status);

    ret = MediaLibraryMetaRecovery::GetInstance().ReadMetaStatusFromFile(readStatus);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(readStatus, status);

    int32_t sum = MediaLibraryMetaRecovery::GetInstance().ReadMetaRecoveryCountFromFile();
    EXPECT_EQ(sum, val1 + val2 + val3 + val4 + val5);

    val1 = 10;
    val2 = 20;
    val3 = 30;
    val4 = 40;
    val5 = 50;
    InsertMetaStatusData(key1, val1, status);
    InsertMetaStatusData(key2, val2, status);
    InsertMetaStatusData(key3, val3, status);
    InsertMetaStatusData(key4, val4, status);
    InsertMetaStatusData(key5, val5, status);
    InsertMetaStatusData(key6, val6, status);

    readStatus.clear();
    ret = MediaLibraryMetaRecovery::GetInstance().ReadMetaStatusFromFile(readStatus);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(readStatus, status);

    sum = MediaLibraryMetaRecovery::GetInstance().ReadMetaRecoveryCountFromFile();
    EXPECT_EQ(sum, val1 + val2 + val3 + val4 + val5 + val6);

    EXPECT_EQ(remove(metaStatusPath.c_str()), 0);
    GTEST_LOG_(INFO) << "MedialibraryMetaRecoveryJsonTest_02 ok";
}
}  // namespace Media
}  // namespace OHOS