/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "recycle_directory_test.h"
#include "get_self_permissions.h"
#include <unistd.h>
#include "datashare_helper.h"
#include "iservice_registry.h"
#include "medialibrary_db_const.h"
#include "media_log.h"
#include "media_thumbnail_helper.h"
#include "scanner_utils.h"
#include "result_set_utils.h"
#include "media_library_manager.h"
using namespace std;
using namespace OHOS::NativeRdb;
using namespace testing::ext;

namespace OHOS {
namespace Media {
static const int UID = 5003;
static const int STRASH_ALBUM_ID = 2;
static const int SLEEP5 = 5;
void RecycleDirectory::SetUpTestCase() {
    MEDIA_INFO_LOG("RecycleDirectory::SetUpTestCase:: invoked");
    vector<string> perms;
    perms.push_back("ohos.permission.READ_MEDIA");
    perms.push_back("ohos.permission.WRITE_MEDIA");
    perms.push_back("ohos.permission.FILE_ACCESS_MANAGER");
    const string processName = "MediaDataShareUnitTest";
    uint64_t tokenId = 0;
    PermissionUtilsUnitTest::SetAccessTokenPermission(processName, perms, tokenId);
    EXPECT_TRUE(tokenId != 0);
    sleep(SLEEP5);
    MEDIA_INFO_LOG("RecycleDirectory::SetUpTestCase:: Finish");
}
void RecycleDirectory::TearDownTestCase() {}
void RecycleDirectory::SetUp() {}
void RecycleDirectory::TearDown(void) {}

std::shared_ptr<DataShare::DataShareHelper> sDataShareHelper_ = nullptr;
void CreateDataAHelper(int32_t systemAbilityId)
{
    MEDIA_INFO_LOG("CreateDataAHelper::CreateDataAHelper");
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        MEDIA_ERR_LOG("CreateDataAHelper:: Get system ability mgr failed.");
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    if (remoteObj == nullptr) {
        MEDIA_ERR_LOG("CreateDataAHelper:: GetSystemAbility Service Failed.");
    }
    if (sDataShareHelper_ == nullptr) {
        const sptr<IRemoteObject> &token = remoteObj;
        sDataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    }
}

std::shared_ptr<DataShare::DataShareHelper> GetDataShareHelper()
{
    if (sDataShareHelper_ == nullptr) {
        CreateDataAHelper(UID);
    }
    if (sDataShareHelper_ == nullptr) {
        MEDIA_ERR_LOG("GetDataShareHelper ::sDataShareHelper_ is nullptr");
    }
    return sDataShareHelper_;
}

int32_t GetAlbumId(std::string relativePath)
{
    MEDIA_INFO_LOG("GetAlbumId:: start");
    std::shared_ptr<DataShare::DataShareHelper> helper = GetDataShareHelper();
    DataShare::DataSharePredicates sharePredicates;
    
    sharePredicates.SetWhereClause(" data = ? ");
    sharePredicates.SetWhereArgs({"/storage/media/local/files/" + relativePath});

    vector<string> columns;
    string queryUri = MEDIALIBRARY_DATA_URI + "/" + MEDIA_ALBUMOPRN_QUERYALBUM;

    Uri uri(queryUri);
    shared_ptr<DataShare::DataShareResultSet> resultSet = helper->Query(
        uri, sharePredicates, columns);

    int32_t albumId = -1;
    if (resultSet == nullptr) {
        MEDIA_INFO_LOG("GetMediaResultData resultSet is nullptr");
        EXPECT_EQ(false, true);
        return albumId;
    }
    if (resultSet->GoToFirstRow() == NativeRdb::E_OK) {
        int index;
        int integerVal;
        resultSet->GetColumnIndex(MEDIA_DATA_DB_BUCKET_ID, index);
        resultSet->GetInt(index, integerVal);
        albumId = integerVal;
    }
    if (albumId < 0) {
        EXPECT_EQ(false, true);
    }
    return albumId;
}

int32_t CreateFile(std::string relativePath, std::string displayName)
{
    std::shared_ptr<DataShare::DataShareHelper> helper = GetDataShareHelper();
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" +
		Media::MEDIA_FILEOPRN_CREATEASSET);
    DataShareValuesBucket valuesBucket;
    
    MediaType mediaType = MEDIA_TYPE_IMAGE;
    valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    valuesBucket.Put(MEDIA_DATA_DB_NAME, displayName);
    valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    return helper->Insert(createAssetUri, valuesBucket);
}

int32_t CreateAlbum(std::string relativePath)
{
    std::shared_ptr<DataShare::DataShareHelper> helper = GetDataShareHelper();
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAssetUri(abilityUri + "/" + Media::MEDIA_DIROPRN + "/" +
		Media::MEDIA_DIROPRN_FMS_CREATEDIR);
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    return helper->Insert(createAssetUri, valuesBucket);
}

void AddSmartAlbum(int32_t id)
{
    std::shared_ptr<DataShare::DataShareHelper> helper = GetDataShareHelper();
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(SMARTALBUMMAP_DB_ALBUM_ID, STRASH_ALBUM_ID);
    valuesBucket.Put(SMARTALBUMMAP_DB_CHILD_ASSET_ID, id);
    Uri AddAsseturi(MEDIALIBRARY_DATA_URI + "/"
    + MEDIA_SMARTALBUMMAPOPRN + "/" + MEDIA_SMARTALBUMMAPOPRN_ADDSMARTALBUM);
    helper->Insert(AddAsseturi, valuesBucket);
}

int32_t RemoveSmartAlbum(int32_t id)
{
    std::shared_ptr<DataShare::DataShareHelper> helper = GetDataShareHelper();
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(SMARTALBUMMAP_DB_ALBUM_ID, STRASH_ALBUM_ID);
    valuesBucket.Put(SMARTALBUMMAP_DB_CHILD_ASSET_ID, id);
    Uri RemoveAsseturi(MEDIALIBRARY_DATA_URI + "/" + MEDIA_SMARTALBUMMAPOPRN +
		"/" + MEDIA_SMARTALBUMMAPOPRN_REMOVESMARTALBUM);
    return helper->Insert(RemoveAsseturi, valuesBucket);
}

/**
 * @tc.number    : delete_directory_001
 * @tc.name      : FMS create_delete_directory
 * @tc.desc      : 1. create file Pictures/test001/gtest_001.jpg
 *                 2. push albumId into the recycle
 *                 3. pop albumId out of the recycle
 */
HWTEST_F(RecycleDirectory, recycle_directory_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("recycle_directory_001::Start");
    int32_t fileId = CreateFile("Pictures/test001/", "gtest_001.jpg");
    MEDIA_INFO_LOG("recycle_directory_001 fileId::%d\n", fileId);
    int32_t albumId = GetAlbumId("Pictures/test001");
    AddSmartAlbum(albumId);
    int32_t changedRows = RemoveSmartAlbum(albumId);
    EXPECT_NE((changedRows < 0), true);
    MEDIA_INFO_LOG("recycle_directory_001::End");
}

/**
 * @tc.number    : recycle_directory_002
 * @tc.name      : recycle_directory
 * @tc.desc      : 1. create file Pictures/test002/test002/gtest_002.jpg
 *                 2. push albumId into the recycle
 *                 3. pop albumId out of the recycle
 */
HWTEST_F(RecycleDirectory, recycle_directory_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("recycle_directory_002::Start");
    int32_t fileId_01 = CreateFile("Pictures/test002/", "gtest_002.jpg");
    MEDIA_INFO_LOG("recycle_directory_002 fileId_01::%d\n", fileId_01);
    int32_t fileId_02 = CreateFile("Pictures/test002/test002/", "gtest_002.jpg");
    MEDIA_INFO_LOG("recycle_directory_002 fileId_02::%d\n", fileId_02);
    int32_t albumId = GetAlbumId("Pictures/test002");
    MEDIA_INFO_LOG("recycle_directory_002 albumId::%d\n", albumId);
    AddSmartAlbum(albumId);
    int32_t changedRows = RemoveSmartAlbum(albumId);
    EXPECT_NE((changedRows < 0), true);
    MEDIA_INFO_LOG("recycle_directory_002::End");
}

/**
 * @tc.number    : recycle_directory_003
 * @tc.name      : recycle_directory
 * @tc.desc      : 1. create file Pictures/test003/gtest_003.jpg
 *                 2. push file into the recycle
 *                 3. push albumId into the recycle
 *                 4. pop file out of the recycle
 */
HWTEST_F(RecycleDirectory, recycle_directory_003, TestSize.Level0)
{
    int32_t fileId = CreateFile("Pictures/test003/", "gtest_003.jpg");
    MEDIA_INFO_LOG("recycle_directory_003 fileId::%d\n", fileId);
    int32_t albumId = GetAlbumId("Pictures/test003");
    MEDIA_INFO_LOG("recycle_directory_003 albumId::%d\n", albumId);
    AddSmartAlbum(fileId);
    AddSmartAlbum(albumId);
    int32_t changedRows = RemoveSmartAlbum(fileId);
    EXPECT_NE((changedRows < 0), true);
    MEDIA_INFO_LOG("recycle_directory_003::End");
}

/**
 * @tc.number    : recycle_directory_004
 * @tc.name      : recycle_directory
 * @tc.desc      : 1. create file Pictures/test004/gtest_004.jpg
 *                 2. push file into the recycle
 *                 3. push albumId into the recycle
 *                 4. pop file out of the recycle
 *                 5. pop albumId out of the recycle
 */
HWTEST_F(RecycleDirectory, recycle_directory_004, TestSize.Level0)
{
    int32_t fileId = CreateFile("Pictures/test004/", "gtest_004.jpg");
    MEDIA_INFO_LOG("recycle_directory_004 fileId::%d\n", fileId);
    int32_t albumId = GetAlbumId("Pictures/test004");
    MEDIA_INFO_LOG("recycle_directory_004 albumId::%d\n", albumId);
    AddSmartAlbum(fileId);
    AddSmartAlbum(albumId);
    int32_t changedRows1 = RemoveSmartAlbum(fileId);
    int32_t changedRows2 = RemoveSmartAlbum(albumId);
    EXPECT_NE((changedRows1 < 0), true);
    EXPECT_NE((changedRows2 < 0), true);
    MEDIA_INFO_LOG("recycle_directory_004::End");
}
/**
 * @tc.number    : recycle_directory_005
 * @tc.name      : recycle_directory
 * @tc.desc      : 1. create file Pictures/test005/gtest_005.jpg
 *                 2. push albumId into the recycle
 *                 3. create file Pictures/test005/
 *                 4. pop albumId out of the recycle
 */
HWTEST_F(RecycleDirectory, recycle_directory_005, TestSize.Level0)
{
    int32_t fileId = CreateFile("Pictures/test005/", "gtest_005.jpg");
    MEDIA_INFO_LOG("recycle_directory_005 fileId::%d\n", fileId);
    int32_t albumId = GetAlbumId("Pictures/test005");
    MEDIA_INFO_LOG("recycle_directory_005 albumId::%d\n", albumId);
    AddSmartAlbum(albumId);
    int32_t albumIdSame = CreateAlbum("Pictures/test005/");
    MEDIA_INFO_LOG("recycle_directory_005 albumIdSame::%d\n", albumIdSame);
    int32_t changedRows = RemoveSmartAlbum(albumId);
    EXPECT_NE((changedRows < 0), true);
    MEDIA_INFO_LOG("recycle_directory_005::End");
}
/**
 * @tc.number    : recycle_directory_006
 * @tc.name      : recycle_directory
 * @tc.desc      : 1. create file Pictures/test006/gtest_006.jpg
 *                 2. push albumId into the recycle
 *                 3. create album Pictures/test006/
 *                 4. create album Pictures/test006_recycle/
 *                 5. pop albumId out of the recycle
 */
HWTEST_F(RecycleDirectory, recycle_directory_006, TestSize.Level0)
{
    int32_t fileId = CreateFile("Pictures/test006/", "gtest_006.jpg");
    MEDIA_INFO_LOG("fileId::%d\n", fileId);
    int32_t albumId = GetAlbumId("Pictures/test006");
    MEDIA_INFO_LOG("recycle_directory_006 albumId::%d\n", albumId);
    AddSmartAlbum(albumId);
    int32_t albumIdSame = CreateAlbum("Pictures/test006/");
    MEDIA_INFO_LOG("recycle_directory_006 albumIdSame::%d\n", albumIdSame);
    int32_t albumIdSameRecycle = CreateAlbum("Pictures/test006_recycle/");
    MEDIA_INFO_LOG("recycle_directory_006 albumIdSameRecycle::%d\n", albumIdSameRecycle);
    int32_t changedRows = RemoveSmartAlbum(albumId);
    EXPECT_NE((changedRows < 0), true);
    MEDIA_INFO_LOG("recycle_directory_006::End");
}
/**
 * @tc.number    : recycle_directory_007
 * @tc.name      : recycle_directory
 * @tc.desc      : 1. create file Pictures/test007/gtest_007.jpg
 *                 2. push albumId into the recycle
 *                 3. create file Pictures/test007/gtest_007.jpg
 *                 4. pop albumId out of the recycle
 */
HWTEST_F(RecycleDirectory, recycle_directory_007, TestSize.Level0)
{
    int32_t fileId = CreateFile("Pictures/test007/", "gtest_007.jpg");
    MEDIA_INFO_LOG("recycle_directory_007 fileId::%d\n", fileId);
    int32_t albumId = GetAlbumId("Pictures/test007");
    MEDIA_INFO_LOG("recycle_directory_007 albumId::%d\n", albumId);
    AddSmartAlbum(albumId);

    int32_t fileIdSame = CreateFile("Pictures/test007/", "gtest_007.jpg");
    MEDIA_INFO_LOG("recycle_directory_007 fileIdSame::%d\n", fileIdSame);
    int32_t albumIdSame = GetAlbumId("Pictures/test007");
    MEDIA_INFO_LOG("recycle_directory_007 albumIdSame::%d\n", albumIdSame);
    int32_t changedRows2 = RemoveSmartAlbum(albumId);
    MEDIA_INFO_LOG("recycle_directory_007 changedRows2::%d\n", changedRows2);
    EXPECT_NE((changedRows2 < 0), true);
    MEDIA_INFO_LOG("recycle_directory_007::End");
}
/**
 * @tc.number    : recycle_directory_008
 * @tc.name      : recycle_directory
 * @tc.desc      : 1. create file Pictures/test008/gtest_008.jpg
 *                 2. push albumId into the recycle
 *                 3. pop albumId out of the recycle
 *                 4. push albumId into the recycle
 *                 5. pop albumId out of the recycle
 */
HWTEST_F(RecycleDirectory, recycle_directory_008, TestSize.Level0)
{
    int32_t fileId = CreateFile("Pictures/test008/", "gtest_008.jpg");
    MEDIA_INFO_LOG("recycle_directory_008 fileId::%d\n", fileId);
    int32_t albumId = GetAlbumId("Pictures/test008");
    MEDIA_INFO_LOG("recycle_directory_007 albumId::%d\n", albumId);
    AddSmartAlbum(albumId);
    int32_t changedRows1 = RemoveSmartAlbum(albumId);
    MEDIA_INFO_LOG("recycle_directory_008 changedRows1::%d\n", changedRows1);
    AddSmartAlbum(albumId);
    int32_t changedRows2 = RemoveSmartAlbum(albumId);
    EXPECT_NE((changedRows2 < 0), true);
    MEDIA_INFO_LOG("recycle_directory_008::End");
}
/**
 * @tc.number    : recycle_directory_009
 * @tc.name      : recycle_directory
 * @tc.desc      : 1. create file Pictures/test009/gtest_009.jpg
 *                 2. push fileId into the recycle
 *                 3. push album into the recycle
 *                 4. pop fileId out of the recycle
 *                 5. push file into the recycle
 *                 6. pop file out of the recycle
 */
HWTEST_F(RecycleDirectory, recycle_directory_009, TestSize.Level0)
{
    int32_t fileId = CreateFile("Pictures/test009/", "gtest_009.jpg");
    MEDIA_INFO_LOG("recycle_directory_009fileId::%d\n", fileId);
    int32_t albumId = GetAlbumId("Pictures/test009");
    MEDIA_INFO_LOG("recycle_directory_009 albumId::%d\n", albumId);
    AddSmartAlbum(fileId);
    AddSmartAlbum(albumId);

    int32_t changedRows1 = RemoveSmartAlbum(fileId);
    MEDIA_INFO_LOG("recycle_directory_009changedRows1::%d\n", changedRows1);
    AddSmartAlbum(fileId);

    int32_t changedRows2 = RemoveSmartAlbum(fileId);

    EXPECT_NE((changedRows2 < 0), true);
    MEDIA_INFO_LOG("recycle_directory_009::End");
}
/**
 * @tc.number    : recycle_directory_010
 * @tc.name      : recycle_directory
 * @tc.desc      : 1. create file Pictures/test010/gtest_010.jpg
 *                 2. push fileId into the recycle
 *                 3. push album into the recycle
 *                 4. pop fileId out of the recycle
 *                 5. push file into the recycle
 *                 6. pop file out of the recycle
 *                 7. pop album out of the recycle
 */
HWTEST_F(RecycleDirectory, recycle_directory_010, TestSize.Level0)
{
    int32_t fileId = CreateFile("Pictures/test010/", "gtest_010.jpg");
    MEDIA_INFO_LOG("recycle_directory_010 fileId::%d\n", fileId);
    int32_t albumId = GetAlbumId("Pictures/test010");
    MEDIA_INFO_LOG("recycle_directory_010 albumId::%d\n", albumId);
    AddSmartAlbum(fileId);
    AddSmartAlbum(albumId);

    int32_t changedRows = RemoveSmartAlbum(fileId);
    MEDIA_INFO_LOG("recycle_directory_010 changedRows::%d\n", changedRows);
    AddSmartAlbum(fileId);

    int32_t changedRows1 = RemoveSmartAlbum(fileId);
    MEDIA_INFO_LOG("recycle_directory_010 changedRows1::%d\n", changedRows1);
    int32_t changedRows2 = RemoveSmartAlbum(albumId);
    EXPECT_NE((changedRows2 < 0), true);
    MEDIA_INFO_LOG("recycle_directory_010::End");
}
/**
 * @tc.number    : recycle_directory_011
 * @tc.name      : recycle_directory
 * @tc.desc      : 1. create file Pictures/test011/01.jpg
 *                 2. create file Pictures/test011/01/01.jpg
 *                 3. push Pictures/test011/01 into the recycle
 *                 4. push Pictures/test011 into the recycle
 *                 5. pop Pictures/test011/01 out of the recycle
 *                 6. pop Pictures/test011 out of the recycle
 */
HWTEST_F(RecycleDirectory, recycle_directory_011, TestSize.Level0)
{
    int32_t fileId = CreateFile("Pictures/test011/", "gtest011.jpg");
    MEDIA_INFO_LOG("recycle_directory_011 fileId::%d\n", fileId);
    int32_t fileId_01 = CreateFile("Pictures/test011/01/", "01.jpg");
    MEDIA_INFO_LOG("recycle_directory_011 fileId_01::%d\n", fileId_01);
    int32_t albumId_01 = GetAlbumId("Pictures/test011/01");
    MEDIA_INFO_LOG("recycle_directory_011 albumId_01::%d\n", albumId_01);
    AddSmartAlbum(albumId_01);

    int32_t albumId = GetAlbumId("Pictures/test011");
    MEDIA_INFO_LOG("recycle_directory_011 albumId::%d\n", albumId);
    AddSmartAlbum(albumId);

    int32_t changedRows1 = RemoveSmartAlbum(albumId_01);
    MEDIA_INFO_LOG("recycle_directory_011 changedRows1::%d\n", changedRows1);
    int32_t changedRows2 = RemoveSmartAlbum(albumId);
    MEDIA_INFO_LOG("recycle_directory_011 changedRows2::%d\n", changedRows2);
    EXPECT_NE((changedRows2 < 0), true);
    MEDIA_INFO_LOG("recycle_directory_011::End");
}

} // namespace Media
} // namespace OHOS
