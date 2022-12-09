/**
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "create_delete_directory_test.h"
#include "get_self_permissions.h"
#include "hilog/log.h"
#include "media_log.h"
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <string>
using namespace std;
using namespace testing::ext;
namespace OHOS {
namespace Media {

void CreateFile(std::string baseURI, std::string targetPath, std::string newName,
    unsigned char fileContent[], int len);
int32_t CreateDir(std::string relativePath);
static const int SLEEP5 = 5;
unsigned char g_fileContentJpg[] = {
    0x49, 0x44, 0x33, 0x03, 0x20, 0x20, 0x20, 0x0c, 0x24, 0x5d, 0x54, 0x45, 0x4e, 0x43, 0x20, 0x20, 0x20, 0x0b,
    0x20, 0x20, 0x20, 0x50
};

void CreateDeleteDirectory::SetUpTestCase()
{
    MEDIA_INFO_LOG("CreateDeleteDirectory::SetUpTestCase:: invoked");
    vector<string> perms;
    perms.push_back("ohos.permission.READ_MEDIA");
    perms.push_back("ohos.permission.WRITE_MEDIA");
    perms.push_back("ohos.permission.FILE_ACCESS_MANAGER");
    const string processName = "MediaDataShareUnitTest";
    uint64_t tokenId = 0;
    PermissionUtilsUnitTest::SetAccessTokenPermission(processName, perms, tokenId);
    EXPECT_TRUE(tokenId != 0);
    // create base file
    CreateFile(MEDIALIBRARY_IMAGE_URI, "Pictures/", "01.jpg",
        g_fileContentJpg, sizeof(g_fileContentJpg));
    CreateFile(MEDIALIBRARY_IMAGE_URI, "Pictures/testDelete", "01.jpg",
        g_fileContentJpg, sizeof(g_fileContentJpg));
    CreateFile(MEDIALIBRARY_IMAGE_URI, "Pictures/testDelete/levelOne", "01.jpg",
        g_fileContentJpg, sizeof(g_fileContentJpg));
    CreateFile(MEDIALIBRARY_IMAGE_URI, "Pictures/testDelete/levelOne/levelTwo", "01.jpg",
        g_fileContentJpg, sizeof(g_fileContentJpg));
    CreateFile(MEDIALIBRARY_IMAGE_URI, "Pictures/testDelete/levelOne/levelTwo/levelThree", "01.jpg",
        g_fileContentJpg, sizeof(g_fileContentJpg));
    sleep(SLEEP5);
    
    MEDIA_INFO_LOG("CreateDeleteDirectory::SetUpTestCase:: Finish");
}
void CreateDeleteDirectory::TearDownTestCase() {}
void CreateDeleteDirectory::SetUp() {}
void CreateDeleteDirectory::TearDown(void) {}
static const int UID = 5003;
std::shared_ptr<DataShare::DataShareHelper> sDataShareHelper_ = nullptr;
MediaLibraryManager* mediaLibraryManager = MediaLibraryManager::GetMediaLibraryManager();
static const int32_t MEDIA_DELETE_ROOT_DIR_ERROR = -2010;

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
    mediaLibraryManager->InitMediaLibraryManager(remoteObj);
    MEDIA_INFO_LOG("CreateDataAHelper:: InitMediaLibraryManager success~!");
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
    MEDIA_INFO_LOG("getAlbumId:: start");
    std::shared_ptr<DataShare::DataShareHelper> helper = GetDataShareHelper();
    DataShare::DataSharePredicates sharePredicates;
    
    sharePredicates.SetWhereClause(" data = ? ");
    sharePredicates.SetWhereArgs({"/storage/media/local/files/" + relativePath});

    vector<string> columns;
    string queryUri = MEDIALIBRARY_DATA_URI;
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
        resultSet->GetColumnIndex(MEDIA_DATA_DB_ID, index);
        resultSet->GetInt(index, integerVal);
        albumId = integerVal;
    }
    MEDIA_INFO_LOG("getAlbumId::albumId :%d\n", albumId);
    if (albumId < 0) {
        EXPECT_EQ(false, true);
    }
    return albumId;
}

void CreateFile(std::string baseURI, std::string targetPath, std::string newName,
    unsigned char fileContent[], int len)
{
    MEDIA_INFO_LOG("CreateFile:: start Create file: %s", newName.c_str());
    std::shared_ptr<DataShare::DataShareHelper> helper = GetDataShareHelper();

    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CREATEASSET);
    DataShareValuesBucket valuesBucket;
    MediaType mediaType = MEDIA_TYPE_IMAGE;
    valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    valuesBucket.Put(MEDIA_DATA_DB_NAME, newName);
    valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, targetPath);

    int32_t index = helper->Insert(createAssetUri, valuesBucket);
    string destUri = baseURI + "/" + std::to_string(index);
    Uri openFileUriDest(destUri);
    int32_t destFd = helper->OpenFile(openFileUriDest, MEDIA_FILEMODE_READWRITE);
    EXPECT_NE(destFd <= 0, true);

    int32_t resWrite = write(destFd, fileContent, len);
    if (resWrite == -1) {
        EXPECT_EQ(false, true);
    }

    mediaLibraryManager->CloseAsset(destUri, destFd);
    MEDIA_INFO_LOG("CreateFile:: end Create file: %s", newName.c_str());
}

int32_t CreateDir(std::string relativePath)
{
    std::shared_ptr<DataShare::DataShareHelper> helper = GetDataShareHelper();
    Uri createAssetUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_DIROPRN + "/" +
		MEDIA_DIROPRN_FMS_CREATEDIR);
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    return helper->Insert(createAssetUri, valuesBucket);
}

int32_t DeleteDir(std::string relativePath)
{
    std::shared_ptr<DataShare::DataShareHelper> helper = GetDataShareHelper();
    DataShareValuesBucket deleteValuesBucket;
    Uri deleteDirUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_DIROPRN + "/" +
                MEDIA_DIROPRN_FMS_DELETEDIR);
    deleteValuesBucket.Put(MEDIA_DATA_DB_URI, relativePath);
    return helper->Insert(deleteDirUri, deleteValuesBucket);
}

int32_t TrashDir(std::string testNum)
{
    std::shared_ptr<DataShare::DataShareHelper> helper = GetDataShareHelper();
    DataShareValuesBucket valuesBucket;
    Uri createAssetUri(Media::MEDIALIBRARY_DATA_URI + "/" + Media::MEDIA_FILEOPRN + "/" +
                Media::MEDIA_FILEOPRN_CREATEASSET);
    valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, MEDIA_TYPE_IMAGE);
    std::string nameExtension(".jpg");
    std::string name = testNum + nameExtension;
    valuesBucket.Put(MEDIA_DATA_DB_NAME, name);
    std::string relativePathPart1("Pictures/");
    std::string relativePathPart3("/");
    std::string relativePath = relativePathPart1 + testNum;
    relativePath.append(relativePathPart3);
    valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    helper->Insert(createAssetUri, valuesBucket);

    Uri createAssetUri1(Media::MEDIALIBRARY_DATA_URI + "/" + Media::MEDIA_DIROPRN + "/" +
                Media::MEDIA_DIROPRN_FMS_TRASHDIR);
    relativePath.pop_back();
    int32_t albumId = GetAlbumId(relativePath);
    MEDIA_INFO_LOG("albumId::%d\n", albumId);
    DataShareValuesBucket valuesBucket1;
    valuesBucket1.Put(MEDIA_DATA_DB_ID, albumId);
    return helper->Insert(createAssetUri1, valuesBucket1);
}

/**
 * @tc.number    : directory_test_001
 * @tc.name      : directory_test_001
 * @tc.desc      : 1. create directory: Pictures/test001/
 *                 2. delete directory: Pictures/testDelete
 */
HWTEST_F(CreateDeleteDirectory, directory_test_001, TestSize.Level0)
{
    int32_t createRes = CreateDir("Pictures/test001/");
    MEDIA_INFO_LOG("directory_test_001 createRes::%d\n", createRes);
    int32_t albumId = GetAlbumId("Pictures/testDelete");
    MEDIA_INFO_LOG("directory_test_001 albumId::%d\n", albumId);
    std::string uri = "datashare:///media/file/" + std::to_string(albumId);
    int32_t deleteRes = DeleteDir(uri);
    MEDIA_INFO_LOG("directory_test_001 deleteRes::%d\n", deleteRes);
    EXPECT_NE((createRes < 0) && (deleteRes < 0), true);
    MEDIA_INFO_LOG("directory_test_001::End");
}
/**
 * @tc.number    : directory_test_002
 * @tc.name      : directory_test_002
 * @tc.desc      : 1. get directory :Pictures
 *                 2. delete directory: Pictures
 */
HWTEST_F(CreateDeleteDirectory, directory_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("directory_test_002::Start");
    int32_t albumId = GetAlbumId("Pictures");
    MEDIA_INFO_LOG("directory_test_002 albumId::%d\n", albumId);
    std::string uri = "datashare:///media/file/" + std::to_string(albumId);
    int32_t resFirst = DeleteDir(uri);
    MEDIA_INFO_LOG("directory_test_002 resFirst::%d\n", resFirst);
    EXPECT_EQ((resFirst == MEDIA_DELETE_ROOT_DIR_ERROR), true);
    MEDIA_INFO_LOG("directory_test_002::End");
}
/**
 * @tc.number    : directory_test_003
 * @tc.name      : directory_test_003
 * @tc.desc      : 1. get directory :Videos
 *                 2. delete directory: Videos
 */
HWTEST_F(CreateDeleteDirectory, directory_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("directory_test_003::Start");
    int32_t albumId = GetAlbumId("Videos");
    MEDIA_INFO_LOG("directory_test_003 albumId::%d\n", albumId);
    std::string uri = "datashare:///media/file/" + std::to_string(albumId);
    int32_t resFirst = DeleteDir(uri);
    MEDIA_INFO_LOG("directory_test_003 resfirst::%d\n", resFirst);
    EXPECT_EQ((resFirst == MEDIA_DELETE_ROOT_DIR_ERROR), true);
    MEDIA_INFO_LOG("directory_test_003::End");
}
/**
 * @tc.number    : directory_test_004
 * @tc.name      : directory_test_004
 * @tc.desc      : 1. get directory :Audios
 *                 2. delete directory: Audios
 */
HWTEST_F(CreateDeleteDirectory, directory_test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("directory_test_004::Start");
    int32_t albumId = GetAlbumId("Audios");
    MEDIA_INFO_LOG("directory_test_004 albumId::%d\n", albumId);
    std::string uri = "datashare:///media/file/" + std::to_string(albumId);
    int32_t resFirst = DeleteDir(uri);
    MEDIA_INFO_LOG("directory_test_004 resfirst::%d\n", resFirst);
    EXPECT_EQ((resFirst == MEDIA_DELETE_ROOT_DIR_ERROR), true);
    MEDIA_INFO_LOG("directory_test_004::End");
}
/**
 * @tc.number    : directory_test_005
 * @tc.name      : directory_test_005
 * @tc.desc      : 1. get directory :Documents
 *                 2. delete directory: Documents
 */
HWTEST_F(CreateDeleteDirectory, directory_test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("directory_test_005::Start");
    int32_t albumId = GetAlbumId("Documents");
    MEDIA_INFO_LOG("directory_test_005 albumId::%d\n", albumId);
    std::string uri = "datashare:///media/file/" + std::to_string(albumId);
    int32_t resFirst = DeleteDir(uri);
    MEDIA_INFO_LOG("directory_test_005 resfirst::%d\n", resFirst);
    EXPECT_EQ((resFirst == MEDIA_DELETE_ROOT_DIR_ERROR), true);
    MEDIA_INFO_LOG("directory_test_005::End");
}
/**
 * @tc.number    : directory_test_006
 * @tc.name      : directory_test_006
 * @tc.desc      : 1. get directory :Download
 *                 2. delete directory: Download
 */
HWTEST_F(CreateDeleteDirectory, directory_test_006, TestSize.Level0)
{
    MEDIA_INFO_LOG("directory_test_006::Start");
    int32_t albumId = GetAlbumId("Download");
    MEDIA_INFO_LOG("directory_test_006 albumId::%d\n", albumId);
    std::string uri = "datashare:///media/file/" + std::to_string(albumId);
    int32_t resFirst = DeleteDir(uri);
    MEDIA_INFO_LOG("directory_test_006 resfirst::%d\n", resFirst);
    EXPECT_EQ((resFirst == MEDIA_DELETE_ROOT_DIR_ERROR), true);
    MEDIA_INFO_LOG("directory_test_006::End");
}
/**
 * @tc.number    : directory_test_007
 * @tc.name      : directory_test_007
 * @tc.desc      : 1. create directory: Pictures/test007/
 *                 2. create directory: Pictures/test007/ fail
 *                 3. delete directory: Pictures/test007/
 */
HWTEST_F(CreateDeleteDirectory, directory_test_007, TestSize.Level0)
{
    MEDIA_INFO_LOG("directory_test_007::Start");
    int32_t resFirst = CreateDir("Pictures/test007/");
    MEDIA_INFO_LOG("directory_test_007 resFirst::%d\n", resFirst);
    int32_t resSecond = CreateDir("Pictures/test007/");
    MEDIA_INFO_LOG("directory_test_007 resSecond::%d\n", resSecond);
    EXPECT_EQ((resFirst >= 0) && (resSecond < 0), true);
    //clean
    int32_t albumId = GetAlbumId("Pictures/test007");
    MEDIA_INFO_LOG("directory_test_007 albumId::%d\n", albumId);
    std::string uri = "datashare:///media/file/" + std::to_string(albumId);
    int32_t resDelete = DeleteDir(uri);
    MEDIA_INFO_LOG("directory_test_007 resDelete :%d\n", resDelete);
    MEDIA_INFO_LOG("directory_test_007::End");
}
/**
 * @tc.number    : directory_test_008
 * @tc.name      : directory_test_008
 * @tc.desc      : 1. create directory: Pictures/test008
 *                 2. delete directory :Pictures/test008
 *                 3. delete directory: Pictures/test008
 */
HWTEST_F(CreateDeleteDirectory, directory_test_008, TestSize.Level0)
{
    MEDIA_INFO_LOG("directory_test_008::Start");
    int32_t resCreate = CreateDir("Pictures/test008/");
    MEDIA_INFO_LOG("directory_test_008 resCreate::%d\n", resCreate);
    int32_t albumId = GetAlbumId("Pictures/test008");
    MEDIA_INFO_LOG("directory_test_008 albumId::%d\n", albumId);
    std::string uri = "datashare:///media/file/" + std::to_string(albumId);
    int32_t resFirst = DeleteDir(uri);
    MEDIA_INFO_LOG("directory_test_008 resFirst::%d\n", resFirst);
    int32_t resSecond = DeleteDir(uri);
    MEDIA_INFO_LOG("directory_test_008 resSecond::%d\n", resSecond);
    EXPECT_EQ((resFirst >= 0) && (resSecond < 0), true);
    MEDIA_INFO_LOG("directory_test_008::End");
}
/**
 * @tc.number    : directory_test_009
 * @tc.name      : directory_test_009
 * @tc.desc      : 1. create directory: Videos/test009/
 *                 2. create directory: Videos/test009/
 *                 3. delete directory: Videos/test009/
 */
HWTEST_F(CreateDeleteDirectory, directory_test_009, TestSize.Level0)
{
    MEDIA_INFO_LOG("directory_test_009::Start");
    int32_t resFirst = CreateDir("Videos/test009/");
    MEDIA_INFO_LOG("directory_test_009 resFirst::%d\n", resFirst);
    int32_t resSecond = CreateDir("Videos/test009/");
    MEDIA_INFO_LOG("directory_test_009 resSecond::%d\n", resSecond);
    EXPECT_EQ((resFirst >= 0) && (resSecond < 0), true);
    //clean
    int32_t albumId = GetAlbumId("Videos/test009");
    MEDIA_INFO_LOG("directory_test_009 albumId::%d\n", albumId);
    std::string uri = "datashare:///media/file/" + std::to_string(albumId);
    int32_t resDelete = DeleteDir(uri);
    MEDIA_INFO_LOG("directory_test_009 resDelete :%d\n", resDelete);
    MEDIA_INFO_LOG("directory_test_009::End");
}
/**
 * @tc.number    : directory_test_010
 * @tc.name      : directory_test_010
 * @tc.desc      : 1. create directory: Videos/test010
 *                 2. delete directory :Videos/test010
 *                 3. delete directory: Videos/test010
 */
HWTEST_F(CreateDeleteDirectory, directory_test_010, TestSize.Level0)
{
    MEDIA_INFO_LOG("directory_test_010::Start");
    int32_t resCreate = CreateDir("Videos/test010/");
    MEDIA_INFO_LOG("directory_test_010 resCreate::%d\n", resCreate);
    int32_t albumId = GetAlbumId("Videos/test010");
    MEDIA_INFO_LOG("directory_test_010 albumId::%d\n", albumId);
    std::string uri = "datashare:///media/file/" + std::to_string(albumId);
    int32_t resFirst = DeleteDir(uri);
    MEDIA_INFO_LOG("directory_test_010 resFirst::%d\n", resFirst);
    int32_t resSecond = DeleteDir(uri);
    MEDIA_INFO_LOG("directory_test_010 resSecond::%d\n", resSecond);
    EXPECT_EQ((resFirst >= 0) && (resSecond < 0), true);
    MEDIA_INFO_LOG("directory_test_010::End");
}
/**
 * @tc.number    : directory_test_011
 * @tc.name      : directory_test_011
 * @tc.desc      : 1. create directory: Audios/test011/
 *                 2. create directory: Audios/test011/
 *                 3. delete directory: Audios/test011/
 */
HWTEST_F(CreateDeleteDirectory, directory_test_011, TestSize.Level0)
{
    MEDIA_INFO_LOG("directory_test_011::Start");
    int32_t resFirst = CreateDir("Audios/test011/");
    MEDIA_INFO_LOG("directory_test_011 resFirst::%d\n", resFirst);
    int32_t resSecond = CreateDir("Audios/test011/");
    MEDIA_INFO_LOG("directory_test_011 resSecond::%d\n", resSecond);
    EXPECT_EQ((resFirst >= 0) && (resSecond < 0), true);
    //clean
    int32_t albumId = GetAlbumId("Audios/test011");
    MEDIA_INFO_LOG("directory_test_011 albumId::%d\n", albumId);
    std::string uri = "datashare:///media/file/" + std::to_string(albumId);
    int32_t resDelete = DeleteDir(uri);
    MEDIA_INFO_LOG("directory_test_011 resDelete :%d\n", resDelete);
    MEDIA_INFO_LOG("directory_test_011::End");
}
/**
 * @tc.number    : directory_test_012
 * @tc.name      : directory_test_012
 * @tc.desc      : 1. create directory: Audios/test012
 *                 2. delete directory :Audios/test012
 *                 3. delete directory: Audios/test012
 */
HWTEST_F(CreateDeleteDirectory, directory_test_012, TestSize.Level0)
{
    MEDIA_INFO_LOG("directory_test_012::Start");
    int32_t resCreate = CreateDir("Audios/test012/");
    MEDIA_INFO_LOG("directory_test_012 resCreate::%d\n", resCreate);
    int32_t albumId = GetAlbumId("Audios/test012");
    MEDIA_INFO_LOG("directory_test_012 albumId::%d\n", albumId);
    std::string uri = "datashare:///media/file/" + std::to_string(albumId);
    int32_t resFirst = DeleteDir(uri);
    MEDIA_INFO_LOG("directory_test_012 resFirst::%d\n", resFirst);
    int32_t resSecond = DeleteDir(uri);
    MEDIA_INFO_LOG("directory_test_012 resSecond::%d\n", resSecond);
    EXPECT_EQ((resFirst >= 0) && (resSecond < 0), true);
    MEDIA_INFO_LOG("directory_test_012::End");
}
/**
 * @tc.number    : directory_test_013
 * @tc.name      : directory_test_013
 * @tc.desc      : 1. create directory: Documents/test013/
 *                 2. create directory: Documents/test013/
 *                 3. delete directory: Documents/test013/
 */
HWTEST_F(CreateDeleteDirectory, directory_test_013, TestSize.Level0)
{
    MEDIA_INFO_LOG("directory_test_013::Start");
    int32_t resFirst = CreateDir("Documents/test013/");
    MEDIA_INFO_LOG("directory_test_013 resFirst::%d\n", resFirst);
    int32_t resSecond = CreateDir("Documents/test013/");
    MEDIA_INFO_LOG("directory_test_013 resSecond::%d\n", resSecond);
    EXPECT_EQ((resFirst >= 0) && (resSecond < 0), true);
    //clean
    int32_t albumId = GetAlbumId("Documents/test013");
    MEDIA_INFO_LOG("directory_test_013 albumId::%d\n", albumId);
    std::string uri = "datashare:///media/file/" + std::to_string(albumId);
    int32_t resDelete = DeleteDir(uri);
    MEDIA_INFO_LOG("directory_test_013 resDelete :%d\n", resDelete);
    MEDIA_INFO_LOG("directory_test_013::End");
}
/**
 * @tc.number    : directory_test_014
 * @tc.name      : directory_test_014
 * @tc.desc      : 1. create directory: Documents/test014
 *                 2. delete directory :Documents/test014
 *                 3. delete directory: Documents/test014
 */
HWTEST_F(CreateDeleteDirectory, directory_test_014, TestSize.Level0)
{
    MEDIA_INFO_LOG("directory_test_014::Start");
    int32_t resCreate = CreateDir("Documents/test014/");
    MEDIA_INFO_LOG("directory_test_014 resCreate::%d\n", resCreate);
    int32_t albumId = GetAlbumId("Documents/test014");
    MEDIA_INFO_LOG("directory_test_014 albumId::%d\n", albumId);
    std::string uri = "datashare:///media/file/" + std::to_string(albumId);
    int32_t resFirst = DeleteDir(uri);
    MEDIA_INFO_LOG("directory_test_014 resFirst::%d\n", resFirst);
    int32_t resSecond = DeleteDir(uri);
    MEDIA_INFO_LOG("directory_test_014 resSecond::%d\n", resSecond);
    EXPECT_EQ((resFirst >= 0) && (resSecond < 0), true);
    MEDIA_INFO_LOG("directory_test_014::End");
}
/**
 * @tc.number    : directory_test_015
 * @tc.name      : directory_test_015
 * @tc.desc      : 1. create directory: Download/test015/
 *                 2. create directory: Download/test015/
 *                 3. delete directory: Download/test015/
 */
HWTEST_F(CreateDeleteDirectory, directory_test_015, TestSize.Level0)
{
    MEDIA_INFO_LOG("directory_test_015::Start");
    int32_t resFirst = CreateDir("Download/test015/");
    MEDIA_INFO_LOG("directory_test_015 resFirst::%d\n", resFirst);
    int32_t resSecond = CreateDir("Download/test015/");
    MEDIA_INFO_LOG("directory_test_015 resSecond::%d\n", resSecond);
    EXPECT_EQ((resFirst >= 0) && (resSecond < 0), true);
    //clean
    int32_t albumId = GetAlbumId("Download/test015");
    MEDIA_INFO_LOG("directory_test_015 albumId::%d\n", albumId);
    std::string uri = "datashare:///media/file/" + std::to_string(albumId);
    int32_t resDelete = DeleteDir(uri);
    MEDIA_INFO_LOG("directory_test_015 resDelete :%d\n", resDelete);
    MEDIA_INFO_LOG("directory_test_015::End");
}
/**
 * @tc.number    : directory_test_016
 * @tc.name      : directory_test_016
 * @tc.desc      : 1. create directory: Download/test016
 *                 2. delete directory :Download/test016
 *                 3. delete directory: Download/test016
 */
HWTEST_F(CreateDeleteDirectory, directory_test_016, TestSize.Level0)
{
    MEDIA_INFO_LOG("directory_test_016::Start");
    int32_t resCreate = CreateDir("Download/test016/");
    MEDIA_INFO_LOG("directory_test_016 resCreate::%d\n", resCreate);
    int32_t albumId = GetAlbumId("Download/test016");
    MEDIA_INFO_LOG("directory_test_016 albumId::%d\n", albumId);
    std::string uri = "datashare:///media/file/" + std::to_string(albumId);
    int32_t resFirst = DeleteDir(uri);
    MEDIA_INFO_LOG("directory_test_016 resFirst::%d\n", resFirst);
    int32_t resSecond = DeleteDir(uri);
    MEDIA_INFO_LOG("directory_test_016 resSecond::%d\n", resSecond);
    EXPECT_EQ((resFirst >= 0) && (resSecond < 0), true);
    MEDIA_INFO_LOG("directory_test_016::End");
}
/**
 * @tc.number    : directory_test_017
 * @tc.name      : directory_test_017
 * @tc.desc      : 1. create directory parameter is ""
 */
HWTEST_F(CreateDeleteDirectory, directory_test_017, TestSize.Level0)
{
    MEDIA_INFO_LOG("directory_test_017::Start");
    int32_t createRes = CreateDir("");
    MEDIA_INFO_LOG("directory_test_017 createRes :%d\n", createRes);
    EXPECT_EQ((createRes < 0), true);
    MEDIA_INFO_LOG("directory_test_017::End");
}
/**
 * @tc.number    : directory_test_018
 * @tc.name      : directory_test_018
 * @tc.desc      : 1. create directory parameter illegal : test_018
 */
HWTEST_F(CreateDeleteDirectory, directory_test_018, TestSize.Level0)
{
    MEDIA_INFO_LOG("directory_test_018::Start");
    int32_t createRes = CreateDir("test_018");
    MEDIA_INFO_LOG("directory_test_018 createRes :%d\n", createRes);
    EXPECT_EQ((createRes < 0), true);
    MEDIA_INFO_LOG("directory_test_018::End");
}
/**
 * @tc.number    : directory_test_019
 * @tc.name      : directory_test_019
 * @tc.desc      : 1. delete directory parameter dose not exist
 */
HWTEST_F(CreateDeleteDirectory, directory_test_019, TestSize.Level0)
{
    MEDIA_INFO_LOG("directory_test_019::Start");
    int32_t deleteRes = DeleteDir("not_exist");
    MEDIA_INFO_LOG("directory_test_019 deleteRes :%d\n", deleteRes);
    EXPECT_EQ((deleteRes < 0), true);
    MEDIA_INFO_LOG("directory_test_019::End");
}
/**
 * @tc.number    : directory_test_020
 * @tc.name      : directory_test_020
 * @tc.desc      : 1. dir trash
 */
HWTEST_F(CreateDeleteDirectory, directory_test_020, TestSize.Level0)
{
    MEDIA_INFO_LOG("directory_test_020::Start");
    int32_t trashRes = TrashDir("directory_test_020");
    MEDIA_INFO_LOG("directory_test_020 trashRes :%d\n", trashRes);
    EXPECT_NE((trashRes < 0), true);
    MEDIA_INFO_LOG("directory_test_020::End");
}
} // namespace Media
} // namespace OHOS