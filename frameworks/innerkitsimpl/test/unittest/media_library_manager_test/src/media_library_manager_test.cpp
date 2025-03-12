/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include <fstream>
#include <iostream>

#include "media_library_manager_test.h"
#include "datashare_helper.h"
#include "fetch_result.h"
#include "file_asset.h"
#include "get_self_permissions.h"
#include "hilog/log.h"
#include "iservice_registry.h"
#include "media_app_uri_permission_column.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "media_file_utils.h"
#include "media_library_extend_manager.h"
#include "media_library_manager.h"
#include "media_log.h"
#include "media_volume.h"
#include "photo_proxy_test.h"
#include "result_set_utils.h"
#include "scanner_utils.h"
#include "system_ability_definition.h"
#include "thumbnail_const.h"
#include "userfilemgr_uri.h"

using namespace std;
using namespace OHOS;
using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::AppExecFwk;

/**
 * @FileName MediaLibraryManagerTest
 * @Desc Media library manager native function test
 *
 */
namespace OHOS {
namespace Media {
const string API_VERSION = "api_version";
std::shared_ptr<DataShare::DataShareHelper> sDataShareHelper_ = nullptr;
std::unique_ptr<FileAsset> GetFile(int mediaTypeId);
static constexpr int32_t SLEEP_FIVE_SECONDS = 5;
void ClearFile();
void ClearAllFile();
void CreateDataHelper(int32_t systemAbilityId);

constexpr int STORAGE_MANAGER_MANAGER_ID = 5003;
int g_albumMediaType = MEDIA_TYPE_ALBUM;
int64_t g_oneImageSize = 0;
const int CLEAN_TIME = 1;
const int SCAN_WAIT_TIME = 10;
constexpr int32_t OWNER_PRIVIEDGE = 4;
constexpr int32_t TYPE_PHOTOS = 1;
constexpr int32_t TYPE_AUDIOS = 2;
constexpr int32_t MAX_PERMISSION_INDEX = 2;
constexpr int32_t URI_SIZE = 101;
uint64_t tokenId = 0;
int32_t txtIndex = 0;
int32_t audioIndex = 0;
int32_t randomNumber = 0;

static const unsigned char FILE_CONTENT_TXT[] = {
    0x49, 0x44, 0x33, 0x03, 0x20, 0x20, 0x20, 0x0c, 0x24
};

static const unsigned char FILE_CONTENT_JPG[] = {
    0x49, 0x44, 0x33, 0x03, 0x20, 0x20, 0x20, 0x0c, 0x24, 0x5d, 0x54, 0x45, 0x4e, 0x43, 0x20, 0x20, 0x20, 0x0b,
    0x20, 0x20, 0x20,
};

static const unsigned char FILE_CONTENT_MP3[] = {
    0x49, 0x44, 0x33, 0x03, 0x20, 0x20, 0x20, 0x0c, 0x24, 0x5d, 0x54, 0x45, 0x4e, 0x43, 0x20, 0x20, 0x20, 0x0b, 0x20,
    0x20, 0x20, 0x50, 0x72, 0x6f, 0x20, 0x54, 0x6f, 0x6f, 0x6c, 0x73, 0x20, 0x54, 0x58, 0x58, 0x58, 0x20, 0x20, 0x20,
    0x27, 0x20, 0x20, 0x20, 0x6f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x61, 0x74, 0x6f, 0x72, 0x5f, 0x72, 0x65, 0x66, 0x65,
    0x72, 0x65, 0x6e, 0x63, 0x65, 0x20, 0x21, 0x46, 0x6c, 0x4c, 0x55, 0x6b, 0x6e, 0x45, 0x6d, 0x52, 0x62, 0x61, 0x61,
    0x61, 0x47, 0x6b, 0x20, 0x54, 0x59, 0x45, 0x52, 0x20, 0x20, 0x20, 0x06, 0x20, 0x20, 0x20, 0x32, 0x30, 0x31, 0x35,
    0x20, 0x54, 0x44, 0x41, 0x54, 0x20, 0x20, 0x20, 0x06, 0x20, 0x20, 0x20, 0x32, 0x33, 0x31, 0x31, 0x20, 0x54, 0x58,
    0x58, 0x58, 0x20, 0x20, 0x20, 0x17, 0x20, 0x20, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x5f, 0x72, 0x65, 0x66, 0x65, 0x72,
    0x65, 0x6e, 0x63, 0x65, 0x20, 0x31, 0x36, 0x36, 0x31, 0x31, 0x39, 0x20, 0x54, 0x43, 0x4f, 0x4d, 0x20, 0x20, 0x20,
    0x09, 0x20, 0x20, 0x01, 0xff, 0xfe, 0x4b, 0x6d, 0xd5, 0x8b, 0x20, 0x20, 0x54, 0x50, 0x45, 0x31, 0x20, 0x20, 0x20,
    0x0f, 0x20, 0x20, 0x01, 0xff, 0xfe, 0x43, 0x51, 0x70, 0x65, 0x6e, 0x63, 0x4b, 0x6d, 0xd5, 0x8b, 0x20, 0x20, 0x54,
    0x41, 0x4c, 0x42, 0x20, 0x20, 0x20, 0x07, 0x20, 0x20, 0x20, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x20, 0x54, 0x49, 0x54,
    0x32, 0x20, 0x20, 0x20, 0x06, 0x20, 0x20, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x54, 0x50, 0x45, 0x32, 0x20, 0x20,
    0x20, 0x0c, 0x20, 0x20, 0x20, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x5f, 0x74, 0x65, 0x73, 0x74, 0x20, 0x54, 0x58, 0x58,
    0x58, 0x20, 0x20, 0x20, 0x0e, 0x20, 0x20, 0x20, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x20, 0x6d, 0x65, 0x64, 0x69,
    0x61, 0x20, 0x54, 0x43, 0x4f, 0x4e, 0x20, 0x20, 0x20, 0x09, 0x20, 0x20, 0x20, 0x4c, 0x79, 0x72, 0x69, 0x63, 0x61,
    0x6c, 0x20, 0x54, 0x53, 0x53, 0x45, 0x20, 0x20, 0x20, 0x0f, 0x20, 0x20, 0x20, 0x4c, 0x61
};

static const unsigned char FILE_CONTENT_MP4[] = {
    0x20, 0x20, 0x20, 0x20, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6f, 0x6d, 0x20, 0x20, 0x02, 0x20, 0x69, 0x73, 0x6f,
    0x6d, 0x69, 0x73, 0x6f, 0x32, 0x61, 0x76, 0x63, 0x31, 0x6d, 0x70, 0x34, 0x31, 0x20, 0x20, 0x20, 0x08, 0x66, 0x72,
    0x65, 0x65, 0x20, 0x49, 0xdd, 0x01, 0x6d, 0x64, 0x61, 0x74, 0x20, 0x20, 0x02, 0xa0, 0x06, 0x05, 0xff, 0xff, 0x9c,
};

MediaLibraryManager* mediaLibraryManager = MediaLibraryManager::GetMediaLibraryManager();
MediaLibraryExtendManager* mediaLibraryExtendManager = MediaLibraryExtendManager::GetMediaLibraryExtendManager();

void MediaLibraryManagerTest::SetUpTestCase(void)
{
    vector<string> perms;
    perms.push_back("ohos.permission.READ_IMAGEVIDEO");
    perms.push_back("ohos.permission.WRITE_IMAGEVIDEO");
    perms.push_back("ohos.permission.MEDIA_LOCATION");
    perms.push_back("ohos.permission.GET_BUNDLE_INFO_PRIVILEGED");
    uint64_t tokenId = 0;
    PermissionUtilsUnitTest::SetAccessTokenPermission("MediaLibraryManagerTest", perms, tokenId);
    ASSERT_TRUE(tokenId != 0);

    MEDIA_INFO_LOG("MediaLibraryManagerTest::SetUpTestCase:: invoked");
    CreateDataHelper(STORAGE_MANAGER_MANAGER_ID);
    if (sDataShareHelper_ == nullptr) {
        EXPECT_NE(sDataShareHelper_, nullptr);
        return;
    }
    
    // make sure board is empty
    ClearAllFile();

    Uri scanUri(URI_SCANNER);
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_FILE_PATH, ROOT_MEDIA_DIR);
    sDataShareHelper_->Insert(scanUri, valuesBucket);
    sleep(SCAN_WAIT_TIME);
    mediaLibraryExtendManager->InitMediaLibraryExtendManager();

    MEDIA_INFO_LOG("MediaLibraryManagerTest::SetUpTestCase:: Finish");
}

void MediaLibraryManagerTest::TearDownTestCase(void)
{
    MEDIA_ERR_LOG("TearDownTestCase start");
    if (sDataShareHelper_ != nullptr) {
        sDataShareHelper_->Release();
    }
    sleep(CLEAN_TIME);
    ClearAllFile();
    MEDIA_INFO_LOG("TearDownTestCase end");
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
}
// SetUp:Execute before each test case
void MediaLibraryManagerTest::SetUp(void)
{
    vector<string> perms;
    perms.push_back("ohos.permission.READ_IMAGEVIDEO");
    perms.push_back("ohos.permission.WRITE_IMAGEVIDEO");
    perms.push_back("ohos.permission.READ_AUDIO");
    perms.push_back("ohos.permission.WRITE_AUDIO");
    perms.push_back("ohos.permission.READ_MEDIA");
    perms.push_back("ohos.permission.WRITE_MEDIA");
    perms.push_back("ohos.permission.MEDIA_LOCATION");
    perms.push_back("ohos.permission.GET_BUNDLE_INFO_PRIVILEGED");
    PermissionUtilsUnitTest::SetAccessTokenPermission("MediaLibraryManagerTest", perms, tokenId);
    system("rm -rf /storage/cloud/100/files/Photo/*");
}

void MediaLibraryManagerTest::TearDown(void) {}

void CreateDataHelper(int32_t systemAbilityId)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        MEDIA_ERR_LOG("Get system ability mgr failed.");
        return;
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    if (remoteObj == nullptr) {
        MEDIA_ERR_LOG("GetSystemAbility Service Failed.");
        return;
    }
    mediaLibraryManager->InitMediaLibraryManager(remoteObj);
    MEDIA_INFO_LOG("InitMediaLibraryManager success!");

    if (sDataShareHelper_ == nullptr) {
        const sptr<IRemoteObject> &token = remoteObj;
        sDataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    }
    mediaLibraryManager->InitMediaLibraryManager(remoteObj);
}

void ClearAllFile()
{
    system("rm -rf /storage/media/100/local/files/.thumbs/*");
    system("rm -rf /storage/cloud/100/files/Audio/*");
    system("rm -rf /storage/cloud/100/files/Audios/*");
    system("rm -rf /storage/cloud/100/files/Camera/*");
    system("rm -rf /storage/cloud/100/files/Docs/Documents/*");
    system("rm -rf /storage/cloud/100/files/Photo/*");
    system("rm -rf /storage/cloud/100/files/Pictures/*");
    system("rm -rf /storage/cloud/100/files/Docs/Download/*");
    system("rm -rf /storage/cloud/100/files/Docs/.*");
    system("rm -rf /storage/cloud/100/files/Videos/*");
    system("rm -rf /storage/cloud/100/files/.*");
    system("rm -rf /data/app/el2/100/database/com.ohos.medialibrary.medialibrarydata/*");
    system("kill -9 `pidof com.ohos.medialibrary.medialibrarydata`");
    system("scanner");
}

void DeleteFile(std::string fileUri)
{
    if (sDataShareHelper_ == nullptr) {
        return;
    }
    Uri deleteAssetUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(MEDIA_DATA_DB_ID, MediaFileUtils::GetIdFromUri(fileUri));
    int retVal = sDataShareHelper_->Delete(deleteAssetUri, predicates);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test DeleteFile::uri :%{private}s", deleteAssetUri.ToString().c_str());
    EXPECT_NE(retVal, E_ERR);
}

void ClearFile()
{
    if (sDataShareHelper_ == nullptr) {
        return;
    }
    vector<string> columns;
    DataSharePredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> " + to_string(g_albumMediaType);
    predicates.SetWhereClause(prefix);
    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<DataShareResultSet> resultSet = nullptr;
    resultSet = sDataShareHelper_->Query(queryFileUri, predicates, columns);
    EXPECT_NE((resultSet == nullptr), true);

    unique_ptr<FetchResult<FileAsset>> fetchFileResult = make_unique<FetchResult<FileAsset>>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() < 0), true);
    unique_ptr<FileAsset> fileAsset = fetchFileResult->GetFirstObject();
    while (fileAsset != nullptr) {
        DeleteFile(fileAsset->GetUri());
        fileAsset = fetchFileResult->GetNextObject();
    }
}

static string CreateFile(std::string baseURI, std::string targetPath, std::string newName, MediaType mediaType,
    const unsigned char fileContent[])
{
    bool audioFlag = false;
    MEDIA_INFO_LOG("CreateFile:: start Create file: %s", newName.c_str());
    if (sDataShareHelper_ == nullptr) {
        return "";
    }
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    if (MediaFileUtils::StartsWith(targetPath, "Audios/")) {
        audioFlag = true;
        abilityUri += Media::MEDIA_AUDIOOPRN + "/" + Media::MEDIA_FILEOPRN_CREATEASSET;
    } else {
        abilityUri += Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CREATEASSET;
    }
    Uri createAssetUri(abilityUri);
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    valuesBucket.Put(MEDIA_DATA_DB_NAME, newName);
    valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, targetPath);
    int32_t index = sDataShareHelper_->Insert(createAssetUri, valuesBucket);

    int64_t virtualIndex = MediaFileUtils::GetVirtualIdByType(index, mediaType);
    string destUri = baseURI + "/" + std::to_string(virtualIndex);
    string getUri = baseURI + "/" + std::to_string(index);

    Uri openFileUriDest(destUri);
    int32_t destFd = sDataShareHelper_->OpenFile(openFileUriDest, MEDIA_FILEMODE_READWRITE);
    EXPECT_NE(destFd <= 0, true);
    int len;
    if (audioFlag == true) {
        len = sizeof(FILE_CONTENT_MP3);
    } else {
        len = sizeof(FILE_CONTENT_TXT);
    }
    int32_t resWrite = write(destFd, fileContent, len);
    if (resWrite == -1) {
        EXPECT_EQ(false, true);
    }
    mediaLibraryManager->CloseAsset(destUri, destFd);
    MEDIA_INFO_LOG("CreateFile:: end Create file: %s", newName.c_str());
    return getUri;
}

static string CreatePhotoAsset(string displayName)
{
    int32_t resWrite = -1;
    auto uri = mediaLibraryManager->CreateAsset(displayName);
    int32_t destFd = mediaLibraryManager->OpenAsset(uri, MEDIA_FILEMODE_READWRITE);
    EXPECT_NE(destFd <= 0, true);
    if (displayName.find(".jpg") != std::string::npos) {
        resWrite = write(destFd, FILE_CONTENT_JPG, sizeof(FILE_CONTENT_JPG));
    } else if (displayName.find(".mp4") != std::string::npos) {
        resWrite = write(destFd, FILE_CONTENT_MP4, sizeof(FILE_CONTENT_MP4));
    }
    if (resWrite == -1) {
        EXPECT_EQ(false, true);
    }
    return uri;
}

static void DeletAssetInDb(const string uri, int32_t uriType)
{
    string deleteUri;
    if (sDataShareHelper_ == nullptr) {
        return;
    }
    if (uriType == TYPE_PHOTOS) {
        deleteUri = MEDIALIBRARY_DATA_URI + "/" + MEDIA_PHOTOOPRN + "/" + MEDIA_FILEOPRN_DELETEASSET;
    } else if (uriType == TYPE_AUDIOS) {
        deleteUri = MEDIALIBRARY_DATA_URI + "/" + MEDIA_AUDIOOPRN + "/" + MEDIA_FILEOPRN_DELETEASSET;
    }
    Uri deleteAssetUri(deleteUri);
    DataSharePredicates predicates;
    predicates.EqualTo(MEDIA_DATA_DB_ID, MediaFileUtils::GetIdFromUri(uri));
    int retVal = sDataShareHelper_->Delete(deleteAssetUri, predicates);
    EXPECT_NE(retVal, E_ERR);
    MEDIA_INFO_LOG("DeleteAsset succeed!");
}

static void QueryUriPermissionTokenIdResult(int srcTokenId, int targetTokenId, vector<string> inColumn,
    int32_t mediaType, std::shared_ptr<DataShareResultSet>  &queryResult)
{
    DataSharePredicates predicates;
    vector<string> columns;
    DatashareBusinessError error;
    predicates.In(AppUriPermissionColumn::FILE_ID, inColumn);
    predicates.And()->EqualTo(AppUriPermissionColumn::SOURCE_TOKENID, srcTokenId);
    predicates.And()->EqualTo(AppUriPermissionColumn::TARGET_TOKENID, targetTokenId);
    predicates.And()->EqualTo(AppUriPermissionColumn::URI_TYPE, to_string(mediaType));
    predicates.OrderByAsc(AppUriPermissionColumn::FILE_ID);
    Uri queryUri(MEDIALIBRARY_GRANT_URIPERM_URI);
    ASSERT_NE(sDataShareHelper_, nullptr);
    queryResult = sDataShareHelper_->Query(queryUri, predicates, columns, &error);
    ASSERT_NE(queryResult, nullptr);
}

static string CreateOwnerPrivliegeAssets(uint32_t srcTokenId, uint32_t targetTokenId)
{
    string photoUri = CreatePhotoAsset("test.jpg");
    Uri insertUri(MEDIALIBRARY_GRANT_URIPERM_URI);
    string fileId = MediaFileUtils::GetIdFromUri(photoUri);
    DataShareValuesBucket ValuesBucket;

    ValuesBucket.Put(AppUriPermissionColumn::FILE_ID, static_cast<int32_t>(std::stoi(fileId)));
    ValuesBucket.Put(AppUriPermissionColumn::SOURCE_TOKENID, (int64_t)srcTokenId);
    ValuesBucket.Put(AppUriPermissionColumn::TARGET_TOKENID, (int64_t)targetTokenId);
    ValuesBucket.Put(AppUriPermissionColumn::PERMISSION_TYPE, OWNER_PRIVIEDGE);
    ValuesBucket.Put(AppUriPermissionColumn::URI_TYPE, TYPE_PHOTOS);
    ValuesBucket.Put(AppUriPermissionColumn::DATE_MODIFIED, MediaFileUtils::UTCTimeMilliSeconds());
    sDataShareHelper_->Insert(insertUri, ValuesBucket);
    return photoUri;
}

static PhotoPermissionType GetRandomTemporaryPermission()
{
    randomNumber++;
    if (randomNumber > MAX_PERMISSION_INDEX) {
        randomNumber = 0;
    }
    if (randomNumber == 0) {
        return PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO;
    } else if (randomNumber == 1) {
        return PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO;
    } else {
        return PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO;
    }
}

static bool CompareIfArraysEquals(const unsigned char originArray[],
    const unsigned char targetArray[], int32_t size)
{
    for (int i = 0; i < size - 1; i++) {
        if (originArray[i] != targetArray[i]) {
            return false;
        }
    }
    return true;
}

/**
 * @tc.number    : MediaLibraryManager_test_001
 * @tc.name      : create a test.jpg
 * @tc.desc      : create a image asset to see if error occurs
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_test_001::Start");
    string displayName = "test.jpg";
    string uri =  mediaLibraryManager->CreateAsset(displayName);
    EXPECT_NE(uri, "");
    int32_t destFd = mediaLibraryManager->OpenAsset(uri, MEDIA_FILEMODE_READWRITE);
    EXPECT_NE(destFd <= 0, true);
    int32_t resWrite = write(destFd, FILE_CONTENT_JPG, sizeof(FILE_CONTENT_JPG));
    if (resWrite == -1) {
        EXPECT_EQ(false, true);
    }
    auto ret = mediaLibraryManager->CloseAsset(uri, destFd);
    EXPECT_EQ(ret, E_SUCCESS);
    MEDIA_INFO_LOG("CreateFile:: end Create file: %{public}s", displayName.c_str());
}

/**
 * @tc.number    : MediaLibraryManager_test_002
 * @tc.name      : create image again to see if error occurs
 * @tc.desc      : create same name file to see if error occur and
 *               : read image msg to see if equals
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_test_002::Start");
    string displayName = "test2.jpg";
    string uri =  mediaLibraryManager->CreateAsset(displayName);
    MEDIA_INFO_LOG("createFile uri: %{public}s", uri.c_str());
    EXPECT_NE(uri, "");
    int32_t destFd = mediaLibraryManager->OpenAsset(uri, MEDIA_FILEMODE_READWRITE);
    EXPECT_NE(destFd <= 0, true);
    int32_t resWrite = write(destFd, FILE_CONTENT_JPG, sizeof(FILE_CONTENT_JPG));
    if (resWrite == -1) {
        EXPECT_EQ(false, true);
    }
    mediaLibraryManager->CloseAsset(uri, destFd);

    int32_t srcFd = mediaLibraryManager->OpenAsset(uri, MEDIA_FILEMODE_READWRITE);
    int64_t srcLen = lseek(srcFd, 0, SEEK_END);
    lseek(srcFd, 0, SEEK_SET);
    unsigned char *buf = static_cast<unsigned char*>(malloc(srcLen));
    EXPECT_NE((buf == nullptr), true);
    read(srcFd, buf, srcLen);
    EXPECT_EQ(CompareIfArraysEquals(buf, FILE_CONTENT_JPG, sizeof(FILE_CONTENT_JPG)), true);
    free(buf);
    MEDIA_INFO_LOG("CreateFile:: end Create file: %{public}s", displayName.c_str());
}

/**
 * @tc.number    : MediaLibraryManager_test_003
 * @tc.name      : create video to see if error occurs
 * @tc.desc      : create video file to see if error occur and
 *               : read video msg to see if equals
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_test_003::Start");
    string displayName = "testVideo.mp4";
    string uri =  mediaLibraryManager->CreateAsset(displayName);
    MEDIA_INFO_LOG("createFile uri: %{public}s", uri.c_str());
    EXPECT_NE(uri, "");
    int32_t destFd = mediaLibraryManager->OpenAsset(uri, MEDIA_FILEMODE_READWRITE);
    EXPECT_NE(destFd <= 0, true);
    int32_t resWrite = write(destFd, FILE_CONTENT_MP4, sizeof(FILE_CONTENT_MP4));
    if (resWrite == -1) {
        EXPECT_EQ(false, true);
    }
    mediaLibraryManager->CloseAsset(uri, destFd);
    int32_t srcFd = mediaLibraryManager->OpenAsset(uri, MEDIA_FILEMODE_READWRITE);
    int64_t srcLen = lseek(srcFd, 0, SEEK_END);
    lseek(srcFd, 0, SEEK_SET);
    unsigned char *buf = static_cast<unsigned char*>(malloc(srcLen));
    EXPECT_NE((buf == nullptr), true);
    read(srcFd, buf, srcLen);
    EXPECT_EQ(CompareIfArraysEquals(buf, FILE_CONTENT_MP4, sizeof(FILE_CONTENT_MP4)), true);
    free(buf);
    MEDIA_INFO_LOG("CreateFile:: end Create file: %{public}s", displayName.c_str());
}

/**
 * @tc.number    : MediaLibraryManager_test_004
 * @tc.name      : create error type asset testVideo.xxx to see if error occurs
 * @tc.desc      : create error type asset to see if error occurs
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_test_004::Start");
    string displayName = "testVideo.xxx";
    string uri =  mediaLibraryManager->CreateAsset(displayName);
    MEDIA_INFO_LOG("createFile uri: %{public}s", uri.c_str());
    EXPECT_EQ(uri, "");
    MEDIA_INFO_LOG("CreateFile:: end Create file: %{public}s", displayName.c_str());
}

/**
 * @tc.number    : MediaLibraryManager_test_005
 * @tc.name      : create png image again to see if error occurs
 * @tc.desc      : create png image to see if error occur and
 *               : read image msg to see if equals
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_test_005::Start");
    string displayName = "testPNG.png";
    string uri =  mediaLibraryManager->CreateAsset(displayName);
    MEDIA_INFO_LOG("createFile uri: %{public}s", uri.c_str());
    EXPECT_NE(uri, "");
    int32_t destFd = mediaLibraryManager->OpenAsset(uri, MEDIA_FILEMODE_READWRITE);
    EXPECT_NE(destFd <= 0, true);
    int32_t resWrite = write(destFd, FILE_CONTENT_JPG, sizeof(FILE_CONTENT_JPG));
    if (resWrite == -1) {
        EXPECT_EQ(false, true);
    }
    mediaLibraryManager->CloseAsset(uri, destFd);

    int32_t srcFd = mediaLibraryManager->OpenAsset(uri, MEDIA_FILEMODE_READWRITE);
    int64_t srcLen = lseek(srcFd, 0, SEEK_END);
    lseek(srcFd, 0, SEEK_SET);
    unsigned char *buf = static_cast<unsigned char*>(malloc(srcLen));
    EXPECT_NE((buf == nullptr), true);
    read(srcFd, buf, srcLen);
    free(buf);
    MEDIA_INFO_LOG("CreateFile:: end Create file: %{public}s", displayName.c_str());
}

/**
 * @tc.number    : MediaLibraryManager_GetBatchAstcs_test_006
 * @tc.name      : Query astc batch to see if error occurs
 * @tc.desc      : Input uri list to obtain astc bacth
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GetBatchAstcs_test_006, TestSize.Level0)
{
    vector<string> uriBatch;
    vector<vector<uint8_t>> astcBatch;
    int ret = mediaLibraryManager->GetBatchAstcs(uriBatch, astcBatch);
    EXPECT_EQ(ret, E_INVALID_URI);

    string beginUri = "file://media/Photo/64/IMG_063/IMG_11311.jpg?oper=astc&width=256&height=256&time_id=00000001";
    uriBatch.push_back("0000000001");
    ret = mediaLibraryManager->GetBatchAstcs(uriBatch, astcBatch);
    EXPECT_EQ(ret, E_INVALID_URI);

    uriBatch.clear();
    uriBatch.push_back(beginUri);
    ret = mediaLibraryManager->GetBatchAstcs(uriBatch, astcBatch);
    EXPECT_EQ(ret, E_INVALID_URI);

    uriBatch.clear();
    beginUri = "file://media/Photo/64/IMG_063/IMG_11311.jpg?oper=astc&width=128&height=128&time_id=00000001";
    uriBatch.push_back(beginUri);
    ret = mediaLibraryManager->GetBatchAstcs(uriBatch, astcBatch);

    uriBatch.clear();
    beginUri = "file://media/Photo/64/IMG_063/IMG_11311.jpg?oper=astc&width=64&height=64&time_id=00000001";
    uriBatch.push_back(beginUri);
    ret = mediaLibraryManager->GetBatchAstcs(uriBatch, astcBatch);
}

/**
 * @tc.number    : MediaLibraryManager_GetAstc_test_007
 * @tc.name      : Get astc image to see if error occurs
 * @tc.desc      : Input uri to obtain astc
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GetAstc_test_007, TestSize.Level0)
{
    string uriStr1 = "file://media/Photo/64/test?oper=thumbnail&width=256&height=256&path=test";
    auto pixelmap1 = mediaLibraryManager->GetAstc(Uri(uriStr1));
    EXPECT_EQ(pixelmap1, nullptr);

    string uriStr2 = "file://media/Photo/64/testoper=astc&width=256&height=256&path=test";
    auto pixelmap2 = mediaLibraryManager->GetAstc(Uri(uriStr2));
    EXPECT_EQ(pixelmap2, nullptr);

    string uriStr3 = "file://media/Photo/64/test?oper=astc&width=256&height=256&path=test";
    auto pixelmap3 = mediaLibraryManager->GetAstc(Uri(uriStr3));
    EXPECT_EQ(pixelmap3, nullptr);
}

/**
 * @tc.number    : MediaLibraryManager_test_008
 * @tc.name      : Read video of moving photo to see if error occurs
 * @tc.desc      : Input uri to read video of moving photo
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_test_008, TestSize.Level0)
{
    // read invalid uri
    EXPECT_EQ(mediaLibraryManager->ReadMovingPhotoVideo(""), -1);
    EXPECT_EQ(mediaLibraryManager->ReadMovingPhotoVideo("file://media/Photo"), -1);
    EXPECT_EQ(mediaLibraryManager->ReadMovingPhotoVideo("file://media/Photo/1"), -1);
    EXPECT_EQ(mediaLibraryManager->ReadMovingPhotoVideo("file://media/Photo/1/IMG_008/IMG_008.jpg"), -1);

    string displayName = "movingPhoto.jpg";
    string uri = mediaLibraryManager->CreateAsset(displayName);
    MEDIA_INFO_LOG("createFile uri: %{public}s", uri.c_str());
    EXPECT_NE(uri, "");

    int32_t fd = mediaLibraryManager->OpenAsset(uri, MEDIA_FILEMODE_READWRITE);
    EXPECT_GE(fd, 0);
    mediaLibraryManager->CloseAsset(uri, fd);

    int32_t rfd = mediaLibraryManager->ReadMovingPhotoVideo(uri);
    EXPECT_LE(rfd, 0);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_test_009, TestSize.Level0)
{
    // read invalid uri
    EXPECT_EQ(mediaLibraryManager->ReadPrivateMovingPhoto(""), -1);
    EXPECT_EQ(mediaLibraryManager->ReadPrivateMovingPhoto("file://media/Photo"), -1);
    EXPECT_EQ(mediaLibraryManager->ReadPrivateMovingPhoto("file://media/Photo/1"), -1);
    EXPECT_EQ(mediaLibraryManager->ReadPrivateMovingPhoto("file://media/Photo/1/IMG_009/IMG_009.jpg"), -1);

    string displayName = "movingPhoto.jpg";
    string uri = mediaLibraryManager->CreateAsset(displayName);
    MEDIA_INFO_LOG("createFile uri: %{public}s", uri.c_str());
    EXPECT_NE(uri, "");

    int32_t fd = mediaLibraryManager->OpenAsset(uri, MEDIA_FILEMODE_READWRITE);
    EXPECT_GE(fd, 0);
    mediaLibraryManager->CloseAsset(uri, fd);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CreatePhotoAssetProxy_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_CreatePhotoAssetProxy_test_001 enter");
    auto photoAssetProxy = mediaLibraryManager->CreatePhotoAssetProxy(CameraShotType::MOVING_PHOTO, 0, 0);
    ASSERT_NE(photoAssetProxy, nullptr);
    sptr<PhotoProxyTest> photoProxyTest = new(std::nothrow) PhotoProxyTest();
    ASSERT_NE(photoProxyTest, nullptr);
    string titleExpect = photoProxyTest->GetTitle();
    photoProxyTest->SetFormat(PhotoFormat::JPG);
    photoProxyTest->SetPhotoQuality(PhotoQuality::LOW);

    photoAssetProxy->AddPhotoProxy((sptr<PhotoProxy>&)photoProxyTest);

    auto fileAsset = photoAssetProxy->GetFileAsset();
    ASSERT_NE(fileAsset, nullptr);
    EXPECT_EQ(fileAsset->GetTitle(), titleExpect);
    EXPECT_EQ(fileAsset->GetResultNapiType(), ResultNapiType::TYPE_PHOTOACCESS_HELPER);

    vector<string> columns { PhotoColumn::PHOTO_ID, PhotoColumn::PHOTO_QUALITY, PhotoColumn::PHOTO_DIRTY,
        PhotoColumn::PHOTO_IS_TEMP };
    DataSharePredicates predicates;
    predicates.EqualTo(MediaColumn::MEDIA_ID, fileAsset->GetId());

    string uriStr = URI_QUERY_PHOTO;
    MediaFileUtils::UriAppendKeyValue(uriStr, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri queryFileUri(uriStr);
    shared_ptr<DataShareResultSet> resultSet = nullptr;
    resultSet = sDataShareHelper_->Query(queryFileUri, predicates, columns);
    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToFirstRow(), E_OK);

    EXPECT_EQ(photoProxyTest->GetPhotoId(), GetStringVal(PhotoColumn::PHOTO_ID, resultSet));
    EXPECT_EQ(-1, GetInt32Val(PhotoColumn::PHOTO_DIRTY, resultSet));
    EXPECT_EQ(1, GetInt32Val(PhotoColumn::PHOTO_IS_TEMP, resultSet));

    MEDIA_INFO_LOG("MediaLibraryManager_CreatePhotoAssetProxy_test_001 exit");
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CreatePhotoAssetProxy_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_CreatePhotoAssetProxy_test_002 enter");
    auto photoAssetProxy = mediaLibraryManager->CreatePhotoAssetProxy(CameraShotType::MOVING_PHOTO, 0, 0);
    sptr<PhotoProxyTest> photoProxyTest = new(std::nothrow) PhotoProxyTest();
    ASSERT_NE(photoProxyTest, nullptr);

    photoAssetProxy->AddPhotoProxy((sptr<PhotoProxy>&)photoProxyTest);
    int32_t fd = photoAssetProxy->GetVideoFd();
    EXPECT_GE(fd, 0);
    MEDIA_INFO_LOG("MediaLibraryManager_CreatePhotoAssetProxy_test_002 exit");
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GetVideoFd_empty_share, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GetVideoFd_empty_share enter");
    // empty datashare GetVideoFd will return error
    auto photoAssetProxyPtr = make_shared<PhotoAssetProxy>();
    auto ret = photoAssetProxyPtr->GetVideoFd();
    EXPECT_EQ(ret, E_ERR);
    MEDIA_INFO_LOG("MediaLibraryManager_GetVideoFd_empty_share exit");
}

/**
 * @brief verify PhotoAssetProxy::UpdatePhotoBurst
 *
 * GIVEN ProtoProxy::GetBurstKey()
 * WHEN ProtoProxy::GetBurstKey() is xxxxxxxx-xxxx-xxxx-xxxxxxxx-xxxx
 * THEN media_library.db#Photos#burstKey is xxxxxxxx-xxxx-xxxx-xxxxxxxx-xxxx
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CreatePhotoAssetProxy_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_CreatePhotoAssetProxy_test_003 enter");
    auto photoAssetProxy = mediaLibraryManager->CreatePhotoAssetProxy(CameraShotType::BURST, 0, 0);
    ASSERT_NE(photoAssetProxy, nullptr);
    // mock data for PhotoProxy
    sptr<PhotoProxyTest> photoProxyTest = new(std::nothrow) PhotoProxyTest();
    photoProxyTest->SetIsCoverPhoto(false);
    std::string burstKey = "xxxxxxxx-xxxx-xxxx-xxxxxxxx-xxxx";
    photoProxyTest->SetBurstKey(burstKey);
    ASSERT_NE(photoProxyTest, nullptr);
    string titleExpect = photoProxyTest->GetTitle();
    photoProxyTest->SetFormat(PhotoFormat::JPG);
    photoProxyTest->SetPhotoQuality(PhotoQuality::HIGH);
    // call PhotoAssetProxy::AddPhotoProxy to access PhotoAssetProxy::UpdatePhotoBurst
    photoAssetProxy->AddPhotoProxy((sptr<PhotoProxy>&)photoProxyTest);
    auto fileAsset = photoAssetProxy->GetFileAsset();
    ASSERT_NE(fileAsset, nullptr);
    // query from db
    vector<string> columns{ PhotoColumn::PHOTO_ID, PhotoColumn::PHOTO_QUALITY, PhotoColumn::PHOTO_DIRTY,
        PhotoColumn::PHOTO_BURST_COVER_LEVEL, PhotoColumn::PHOTO_BURST_KEY };
    DataSharePredicates predicates;
    predicates.EqualTo(MediaColumn::MEDIA_ID, fileAsset->GetId());
 
    string uriStr = URI_QUERY_PHOTO;
    MediaFileUtils::UriAppendKeyValue(uriStr, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri queryFileUri(uriStr);
    shared_ptr<DataShareResultSet> resultSet = nullptr;
    resultSet = sDataShareHelper_->Query(queryFileUri, predicates, columns);
    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToFirstRow(), E_OK);
 
    // assert
    EXPECT_EQ(0, GetInt32Val(PhotoColumn::PHOTO_BURST_COVER_LEVEL, resultSet));
    EXPECT_EQ(burstKey, GetStringVal(PhotoColumn::PHOTO_BURST_KEY, resultSet));
 
    MEDIA_INFO_LOG("MediaLibraryManager_CreatePhotoAssetProxy_test_003 exit");
}
 
/**
 * @brief verify PhotoAssetProxy::UpdatePhotoBurst
 *
 * GIVEN ProtoProxy::IsCoverPhoto()
 * WHEN ProtoProxy::IsCoverPhoto() is true
 * THEN media_library.db#Photos#burst_cover_level is 1
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CreatePhotoAssetProxy_test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_CreatePhotoAssetProxy_test_004 enter");
    auto photoAssetProxy = mediaLibraryManager->CreatePhotoAssetProxy(CameraShotType::BURST, 0, 0);
    ASSERT_NE(photoAssetProxy, nullptr);
    // mock data for PhotoProxy
    sptr<PhotoProxyTest> photoProxyTest = new(std::nothrow) PhotoProxyTest();
    photoProxyTest->SetIsCoverPhoto(true);
    std::string burstKey = "xxxxxxxx-xxxx-xxxx-xxxxxxxx-xxxx";
    photoProxyTest->SetBurstKey(burstKey);
    ASSERT_NE(photoProxyTest, nullptr);
    string titleExpect = photoProxyTest->GetTitle();
    photoProxyTest->SetFormat(PhotoFormat::JPG);
    photoProxyTest->SetPhotoQuality(PhotoQuality::HIGH);
    // call PhotoAssetProxy::AddPhotoProxy to access PhotoAssetProxy::UpdatePhotoBurst
    photoAssetProxy->AddPhotoProxy((sptr<PhotoProxy>&)photoProxyTest);
    auto fileAsset = photoAssetProxy->GetFileAsset();
    ASSERT_NE(fileAsset, nullptr);
    // query from db
    vector<string> columns{ PhotoColumn::PHOTO_ID, PhotoColumn::PHOTO_QUALITY, PhotoColumn::PHOTO_DIRTY,
        PhotoColumn::PHOTO_BURST_COVER_LEVEL, PhotoColumn::PHOTO_BURST_KEY };
    DataSharePredicates predicates;
    predicates.EqualTo(MediaColumn::MEDIA_ID, fileAsset->GetId());
 
    string uriStr = URI_QUERY_PHOTO;
    MediaFileUtils::UriAppendKeyValue(uriStr, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri queryFileUri(uriStr);
    shared_ptr<DataShareResultSet> resultSet = nullptr;
    resultSet = sDataShareHelper_->Query(queryFileUri, predicates, columns);
    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToFirstRow(), E_OK);
 
    // assert
    EXPECT_EQ(1, GetInt32Val(PhotoColumn::PHOTO_BURST_COVER_LEVEL, resultSet));
    EXPECT_EQ(burstKey, GetStringVal(PhotoColumn::PHOTO_BURST_KEY, resultSet));
 
    MEDIA_INFO_LOG("MediaLibraryManager_CreatePhotoAssetProxy_test_004 exit");
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_NotifyVideoSaveFinished_test, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_NotifyVideoSaveFinished_test enter");
    auto photoAssetProxy = mediaLibraryManager->CreatePhotoAssetProxy(CameraShotType::MOVING_PHOTO, 0, 0);
    ASSERT_NE(photoAssetProxy, nullptr);
    photoAssetProxy->NotifyVideoSaveFinished();
    MEDIA_INFO_LOG("MediaLibraryManager_NotifyVideoSaveFinished_test exit");
}

// Scenario1: Test when uriBatch is empty then GetBatchAstcs returns E_INVALID_URI.
HWTEST_F(MediaLibraryManagerTest, GetBatchAstcs_ShouldReturnE, TestSize.Level0)
{
    std::vector<std::string> uriBatch;
    std::vector<std::vector<uint8_t>> astcBatch;
    EXPECT_EQ(manager.GetBatchAstcs(uriBatch, astcBatch), E_INVALID_URI);
}

// Scenario2: Test when uriBatch contains ML_URI_OFFSET then GetBatchAstcs calls GetAstcsByOffset.
HWTEST_F(MediaLibraryManagerTest, GetBatchAstcs_ShouldCallGetAstcsByOffset_001, TestSize.Level0)
{
    std::vector<std::string> uriBatch = {"/media/ml/uri/offset/1"};
    std::vector<std::vector<uint8_t>> astcBatch;
    EXPECT_EQ(manager.GetBatchAstcs(uriBatch, astcBatch), E_INVALID_URI);
}

HWTEST_F(MediaLibraryManagerTest, GetBatchAstcs_ShouldCallGetAstcsByOffset_002, TestSize.Level0)
{
    std::vector<std::string> uriBatch = {"/media/ml/uri/offset/1/image?size=100x200"};
    std::vector<std::vector<uint8_t>> astcBatch;
    EXPECT_EQ(manager.GetBatchAstcs(uriBatch, astcBatch), E_INVALID_URI);
}

HWTEST_F(MediaLibraryManagerTest, GetBatchAstcs_ShouldCallGetAstcsByOffset_003, TestSize.Level0)
{
    std::vector<std::string> uriBatch = {"/media/ml/uri/offset/1/image?size=32x32"};
    std::vector<std::vector<uint8_t>> astcBatch;
    EXPECT_EQ(manager.GetBatchAstcs(uriBatch, astcBatch), E_INVALID_URI);
}

// Scenario3: Test when uriBatch does not contain ML_URI_OFFSET then GetBatchAstcs calls GetAstcsBatch.
HWTEST_F(MediaLibraryManagerTest, GetBatchAstcs_ShouldCallGetAstcsBatch_004, TestSize.Level0)
{
    std::vector<std::string> uriBatch = {"/media/ml/uri/1"};
    std::vector<std::vector<uint8_t>> astcBatch;
    EXPECT_EQ(manager.GetBatchAstcs(uriBatch, astcBatch), E_INVALID_URI);
}

HWTEST_F(MediaLibraryManagerTest, ReadMovingPhotoVideo_001, TestSize.Level0)
{
    string uri = "";
    EXPECT_EQ(manager.ReadMovingPhotoVideo(uri), -1);
}

HWTEST_F(MediaLibraryManagerTest, ReadMovingPhotoVideo_002, TestSize.Level0)
{
    string uri = "..;";
    EXPECT_EQ(manager.ReadMovingPhotoVideo(uri), -1);
}

HWTEST_F(MediaLibraryManagerTest, ReadMovingPhoto_001, TestSize.Level0)
{
    string uri = "";
    EXPECT_EQ(manager.ReadPrivateMovingPhoto(uri), -1);
}

HWTEST_F(MediaLibraryManagerTest, ReadMovingPhoto_002, TestSize.Level0)
{
    string uri = "..;";
    EXPECT_EQ(manager.ReadPrivateMovingPhoto(uri), -1);
}

HWTEST_F(MediaLibraryManagerTest, GetMovingPhotoImageUri_001, TestSize.Level0)
{
    std::string uri = "";
    std::string result = manager.GetMovingPhotoImageUri(uri);
    EXPECT_EQ(result, "");
}

HWTEST_F(MediaLibraryManagerTest, GetMovingPhotoImageUri_002, TestSize.Level0)
{
    std::string uri = "mediaLibraryUri";
    std::string result = manager.GetMovingPhotoImageUri(uri);
    EXPECT_EQ(result, uri);
}

HWTEST_F(MediaLibraryManagerTest, GetUrisByOldUris_001, TestSize.Level0)
{
    std::vector<std::string> uris;
    // test case 1 empty uris will return emty map
    auto ret = manager.GetUrisByOldUris(uris);
    EXPECT_EQ(ret.empty(), true);

    // test case 2 normal uris
    uris.emplace_back(UFM_CREATE_PHOTO);
    uris.emplace_back(UFM_CREATE_AUDIO);
    uris.emplace_back(UFM_CREATE_PHOTO_ALBUM);
    ret = manager.GetUrisByOldUris(uris);
    EXPECT_EQ(ret.empty(), true);

    // test case 3 cover max uris will reutrn empty map
    uris.clear();
    for (int32_t i = 0; i < URI_SIZE; i++) {
        uris.emplace_back("testuri");
    }
    ret = manager.GetUrisByOldUris(uris);
    EXPECT_EQ(ret.empty(), true);

    // invalid uris
    uris.clear();
    uris.emplace_back("you_look_only_once");
    uris.emplace_back("//media/we_shall_never_surrender/");
    uris.emplace_back("//media/we_shall_never/_surrender");
    uris.emplace_back("/storage/emulated/love_and_peace/");
    uris.emplace_back("12345");
    uris.emplace_back("");
    ret = manager.GetUrisByOldUris(uris);
    EXPECT_EQ(ret.empty(), false);
}

HWTEST_F(MediaLibraryManagerTest, GetMovingPhotoDateModified_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetMovingPhotoDateModified_001 enter");
    int64_t startTime = MediaFileUtils::UTCTimeMilliSeconds();
    auto photoAssetProxy = mediaLibraryManager->CreatePhotoAssetProxy(CameraShotType::MOVING_PHOTO, 0, 0);
    ASSERT_NE(photoAssetProxy, nullptr);
    sptr<PhotoProxyTest> photoProxyTest = new (std::nothrow) PhotoProxyTest();
    ASSERT_NE(photoProxyTest, nullptr);
    photoProxyTest->SetFormat(PhotoFormat::JPG);
    photoProxyTest->SetPhotoQuality(PhotoQuality::LOW);
    photoAssetProxy->AddPhotoProxy((sptr<PhotoProxy>&)photoProxyTest);
    auto fileAsset = photoAssetProxy->GetFileAsset();
    ASSERT_NE(fileAsset, nullptr);

    string filePath = fileAsset->GetPath();
    string displayName = fileAsset->GetDisplayName();
    string extrUri = MediaFileUtils::GetExtraUri(displayName, filePath);
    string assetUri = MediaFileUtils::GetUriByExtrConditions("file://media/Photo/",
        to_string(fileAsset->GetId()), extrUri);
    int32_t fd = mediaLibraryManager->OpenAsset(assetUri, MEDIA_FILEMODE_READWRITE);
    EXPECT_NE(fd <= 0, true);
    write(fd, FILE_CONTENT_JPG, sizeof(FILE_CONTENT_JPG));
    mediaLibraryManager->CloseAsset(assetUri, fd);

    int64_t movingPhotoDateModified = mediaLibraryManager->GetMovingPhotoDateModified(assetUri);
    EXPECT_EQ(movingPhotoDateModified != startTime, true);
    EXPECT_EQ(movingPhotoDateModified != MediaFileUtils::UTCTimeMilliSeconds(), true);
    MEDIA_INFO_LOG("GetMovingPhotoDateModified_001 exit");
}

HWTEST_F(MediaLibraryManagerTest, GetMovingPhotoDateModified_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("GetMovingPhotoDateModified_002 enter");
    int64_t dateModified = mediaLibraryManager->GetMovingPhotoDateModified("");
    EXPECT_EQ(dateModified, E_ERR);

    dateModified = mediaLibraryManager->GetMovingPhotoDateModified("file://media/image/1/test/test.jpg");
    EXPECT_EQ(dateModified, E_ERR);

    dateModified = mediaLibraryManager->GetMovingPhotoDateModified("file://media/Photo/4096/IMG_2024_001/test.jpg");
    EXPECT_EQ(dateModified, E_ERR);
    MEDIA_INFO_LOG("GetMovingPhotoDateModified_002 exit");
}

/**
 * @tc.number    : MediaLibraryManager_GrantPhotoUriPermission_test_001
 * @tc.name      : grant photo type uri permissions
 * @tc.desc      : check database grant results whether match
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_001 enter");
    int64_t srcTokenId = 1;
    int64_t targetTokenId = 2;
    vector<string> uris;
    vector<string> inColumn;
    for (int i = 0; i < 5; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        uris.push_back(uri);
        inColumn.push_back(MediaFileUtils::GetIdFromUri(uri));
    }
    auto permissionType = PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO;
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, uris, permissionType, SensitiveType);
    std::shared_ptr<OHOS::DataShare::DataShareResultSet> queryPhotoResult;
    QueryUriPermissionTokenIdResult(srcTokenId, targetTokenId, inColumn, TYPE_PHOTOS, queryPhotoResult);
    ASSERT_EQ(queryPhotoResult->GoToFirstRow(), E_OK);
    do {
        int32_t permissionType = GetInt32Val(AppUriPermissionColumn::PERMISSION_TYPE, queryPhotoResult);
        EXPECT_EQ(permissionType, static_cast<int32_t>(PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO));
    } while (!queryPhotoResult->GoToNextRow());
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_001 exit");
}

/**
 * @tc.number    : MediaLibraryManager_GrantPhotoUriPermission_test_002
 * @tc.name      : grant vidio type uri permissions
 * @tc.desc      : check database grant results whether match
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_002 enter");
    int64_t srcTokenId = 1;
    int64_t targetTokenId = 3;
    vector<string> uris;
    vector<string> inColumn;
    for (int i = 0; i < 5; i++) {
        auto uri = CreatePhotoAsset("test.mp4");
        uris.push_back(uri);
        inColumn.push_back(MediaFileUtils::GetIdFromUri(uri));
    }
    auto permissionType = PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO;
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, uris, permissionType, SensitiveType);
    std::shared_ptr<OHOS::DataShare::DataShareResultSet> queryPhotoResult;
    QueryUriPermissionTokenIdResult(srcTokenId, targetTokenId, inColumn, TYPE_PHOTOS, queryPhotoResult);
    ASSERT_EQ(queryPhotoResult->GoToFirstRow(), E_OK);
    do {
        int32_t permissionType = GetInt32Val(AppUriPermissionColumn::PERMISSION_TYPE, queryPhotoResult);
        EXPECT_EQ(permissionType, static_cast<int32_t>(PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO));
    } while (!queryPhotoResult->GoToNextRow());
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_002 exit");
}

/**
 * @tc.number    : MediaLibraryManager_GrantPhotoUriPermission_test_003
 * @tc.name      : grant audio type for uri permissions
 * @tc.desc      : check database grant results whether match
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_003 enter");
    int64_t srcTokenId = 1;
    int64_t targetTokenId = 4;
    vector<string> uris;
    vector<string> inColumn;
    for (int i = 0; i < 5; i++) {
        string struri = CreateFile(MEDIALIBRARY_AUDIO_URI, "Audios/", "Test" + to_string(audioIndex++) + ".mp3",
        MEDIA_TYPE_AUDIO, FILE_CONTENT_MP3);
        inColumn.push_back(MediaFileUtils::GetIdFromUri(struri));
        uris.push_back(struri);
    }
    auto permissionType = PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO;
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, uris, permissionType, SensitiveType);
    std::shared_ptr<OHOS::DataShare::DataShareResultSet> queryAudioResult;
    QueryUriPermissionTokenIdResult(srcTokenId, targetTokenId, inColumn, TYPE_AUDIOS, queryAudioResult);
    ASSERT_EQ(queryAudioResult->GoToFirstRow(), E_OK);
    do {
        int32_t permissionType = GetInt32Val(AppUriPermissionColumn::PERMISSION_TYPE, queryAudioResult);
        EXPECT_EQ(permissionType, static_cast<int32_t>(PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO));
    } while (!queryAudioResult->GoToNextRow());
     
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_003 exit");
}

/**
 * @tc.number    : MediaLibraryManager_GrantPhotoUriPermission_test_004
 * @tc.name      : grant photo 、vidio and audio type mixed uris of permissions
 * @tc.desc      : check database grant results whether match
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_004 enter");
    int64_t srcTokenId = 1;
    int64_t targetTokenId = 5;
    vector<string> photoUris, vedioUris, audioUris;
    vector<string> photoInColumn, vedioInColumn, audioInColumn;
    for (int i = 0; i < 5; i++) {
        auto photoUri = CreatePhotoAsset("test.jpg");
        auto vedioUri = CreatePhotoAsset("test.mp4");
        string audioUri = CreateFile(MEDIALIBRARY_AUDIO_URI, "Audios/", "Test" + to_string(audioIndex++) + ".mp3",
        MEDIA_TYPE_AUDIO, FILE_CONTENT_MP3);
        photoUris.push_back(photoUri);
        vedioUris.push_back(vedioUri);
        audioUris.push_back(audioUri);
        photoInColumn.push_back(MediaFileUtils::GetIdFromUri(photoUri));
        vedioInColumn.push_back(MediaFileUtils::GetIdFromUri(vedioUri));
        audioInColumn.push_back(MediaFileUtils::GetIdFromUri(audioUri));
    }
    auto permissionType = PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO;
    mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, photoUris, permissionType,
        HideSensitiveType::NO_DESENSITIZE);
    permissionType = PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO;
    mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, vedioUris, permissionType,
        HideSensitiveType::NO_DESENSITIZE);
    permissionType = PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO;
    mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, audioUris, permissionType,
        HideSensitiveType::NO_DESENSITIZE);
    std::shared_ptr<OHOS::DataShare::DataShareResultSet> queryPhotoResult;
    std::shared_ptr<OHOS::DataShare::DataShareResultSet> queryVedioResult;
    std::shared_ptr<OHOS::DataShare::DataShareResultSet> queryAudioResult;
    QueryUriPermissionTokenIdResult(srcTokenId, targetTokenId, photoInColumn, TYPE_PHOTOS, queryPhotoResult);
    QueryUriPermissionTokenIdResult(srcTokenId, targetTokenId, vedioInColumn, TYPE_PHOTOS, queryVedioResult);
    QueryUriPermissionTokenIdResult(srcTokenId, targetTokenId, audioInColumn, TYPE_AUDIOS, queryAudioResult);
    ASSERT_EQ(queryPhotoResult->GoToFirstRow(), E_OK);
    ASSERT_EQ(queryVedioResult->GoToFirstRow(), E_OK);
    ASSERT_EQ(queryAudioResult->GoToFirstRow(), E_OK);
    do {
        int32_t permissionType = GetInt32Val(AppUriPermissionColumn::PERMISSION_TYPE, queryPhotoResult);
        EXPECT_EQ(permissionType, static_cast<int32_t>(PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO));
    } while (!queryPhotoResult->GoToNextRow());
    do {
        int32_t permissionType = GetInt32Val(AppUriPermissionColumn::PERMISSION_TYPE, queryVedioResult);
        EXPECT_EQ(permissionType, static_cast<int32_t>(PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO));
    } while (!queryVedioResult->GoToNextRow());
    do {
        int32_t permissionType = GetInt32Val(AppUriPermissionColumn::PERMISSION_TYPE, queryAudioResult);
        EXPECT_EQ(permissionType, static_cast<int32_t>(PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO));
    } while (!queryAudioResult->GoToNextRow());
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_004 exit");
}

/**
 * @tc.number    : MediaLibraryManager_GrantPhotoUriPermission_test_005
 * @tc.name      : same type but different uri grant different permissions
 * @tc.desc      : check database grant results whether match
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_005 enter");
    int64_t srcTokenId = 1;
    int64_t targetTokenId = 6;
    vector<string> uris;
    vector<string> uris1;
    vector<string> uris2;
    vector<string> uris3;
    vector<string> uris4;
    vector<string> inColumn;
    vector<int32_t> expectResult;
    for (int i = 0; i < 20; i++) {
        auto uriStr = CreatePhotoAsset("test.jpg");
        inColumn.push_back(MediaFileUtils::GetIdFromUri(uriStr));
        uris.push_back(uriStr);
    }
    uris1.assign(uris.begin(), uris.begin()+5);
    uris2.assign(uris.begin()+5, uris.begin()+10);
    uris3.assign(uris.begin()+10, uris.begin()+15);
    uris4.assign(uris.begin()+15, uris.begin()+20);
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    auto permissionType = PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO;
    mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, uris1, permissionType, SensitiveType);
    expectResult.insert(expectResult.begin(), 5, 0);

    permissionType = PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO;
    mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, uris2, permissionType, SensitiveType);
    expectResult.insert(expectResult.end(), 5, 2);

    permissionType = PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO;
    mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, uris4, permissionType, SensitiveType);
    expectResult.insert(expectResult.end(), 5, 3);

    vector<int32_t>::iterator it = expectResult.begin();
    std::shared_ptr<OHOS::DataShare::DataShareResultSet> queryPhotoResult;
    QueryUriPermissionTokenIdResult(srcTokenId, targetTokenId, inColumn, TYPE_PHOTOS, queryPhotoResult);
    ASSERT_EQ(queryPhotoResult->GoToFirstRow(), E_OK);
    do {
        int32_t permissionType = GetInt32Val(AppUriPermissionColumn::PERMISSION_TYPE, queryPhotoResult);
        EXPECT_EQ(*it++, permissionType);
    } while (!queryPhotoResult->GoToNextRow());
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_005 exit");
}

/**
 * @tc.number    : MediaLibraryManager_GrantPhotoUriPermission_test_006
 * @tc.name      : same type but different uri grant random permissions
 * @tc.desc      : check database grant results whether match
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_test_006, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_006 enter");
    int64_t srcTokenId = 1;
    int64_t targetTokenId = 7;
    vector<string> uris;
    vector<string> inColumn;
    vector<int32_t> expectResult;
    auto permissionType = PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO;
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    for (int i = 0; i < 20; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        inColumn.push_back(MediaFileUtils::GetIdFromUri(uri));
        vector<string> Tempuris{uri};
        uris.push_back(uri);
        permissionType = GetRandomTemporaryPermission();
        expectResult.push_back(static_cast<int32_t>(permissionType));
        mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, Tempuris, permissionType,
            SensitiveType);
    }
    std::shared_ptr<OHOS::DataShare::DataShareResultSet> queryPhotoResult;
    QueryUriPermissionTokenIdResult(srcTokenId, targetTokenId, inColumn, TYPE_PHOTOS, queryPhotoResult);
    vector<int32_t>::iterator it = expectResult.begin();
    ASSERT_EQ(queryPhotoResult->GoToFirstRow(), E_OK);
    do {
        int32_t permissionType = GetInt32Val(AppUriPermissionColumn::PERMISSION_TYPE, queryPhotoResult);
        EXPECT_EQ(*it++, permissionType);
    } while (!queryPhotoResult->GoToNextRow());
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_006 exit");
}

/**
 * @tc.number    : MediaLibraryManager_GrantPhotoUriPermission_test_007
 * @tc.name      : grand file type do not match
 * @tc.desc      : check error result
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_test_007, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_007 enter");
    int64_t srcTokenId = 1;
    int64_t targetTokenId = 8;
    vector<string> uris;
    for (int i = 0; i < 5; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        uris.push_back(uri);
    }
    auto permissionType = PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO;
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    auto ret = mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, uris, permissionType,
        SensitiveType);
    ASSERT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_007 exit");
}

/**
 * @tc.number    : MediaLibraryManager_GrantPhotoUriPermission_test_008
 * @tc.name      : uri number are over size
 * @tc.desc      : check error result
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_test_008, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_008 enter");
    int64_t srcTokenId = 1;
    int64_t targetTokenId = 9;
    vector<string> uris;
    uris.resize(1001);
    auto permissionType = PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO;
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    auto ret = mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, uris, permissionType,
        SensitiveType);
    ASSERT_EQ(ret, E_ERR);
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_008 exit");
}

/**
 * @tc.number    : MediaLibraryManager_GrantPhotoUriPermission_test_009
 * @tc.name      : All uris are grant permission and then grant other permissions
 * @tc.desc      : check database grant results whether match
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_test_009, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_009 enter");
    int64_t srcTokenId = 1;
    int64_t targetTokenId = 10;
    vector<string> uris;
    vector<string> uris1;
    vector<string> uris2;
    vector<string> uris3;
    vector<string> uris4;
    vector<string> inColumn;
    vector<int32_t> expectResult;
    for (int i = 0; i < 20; i++) {
        auto uriStr = CreatePhotoAsset("test.jpg");
        uris.push_back(uriStr);
        inColumn.push_back(MediaFileUtils::GetIdFromUri(uriStr));
    }
    uris1.assign(uris.begin(), uris.begin()+5);
    uris2.assign(uris.begin()+5, uris.begin()+10);
    uris3.assign(uris.begin()+10, uris.begin()+15);
    uris4.assign(uris.begin()+15, uris.begin()+20);
    auto permissionType = PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO;
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, uris, permissionType, SensitiveType);

    permissionType = PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO;
    mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, uris1, permissionType, SensitiveType);
    expectResult.insert(expectResult.begin(), 5, 0);
    permissionType = PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO;
    mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, uris2, permissionType, SensitiveType);
    expectResult.insert(expectResult.end(), 5, 2);
    permissionType = PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO;
    mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, uris3, permissionType, SensitiveType);
    expectResult.insert(expectResult.end(), 5, 3);
    mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, uris4, permissionType, SensitiveType);
    expectResult.insert(expectResult.end(), 5, 3);

    vector<int32_t>::iterator it = expectResult.begin();
    std::shared_ptr<OHOS::DataShare::DataShareResultSet> queryPhotoResult;
    QueryUriPermissionTokenIdResult(srcTokenId, targetTokenId, inColumn, TYPE_PHOTOS, queryPhotoResult);
    ASSERT_EQ(queryPhotoResult->GoToFirstRow(), E_OK);
    do {
        int32_t permissionType = GetInt32Val(AppUriPermissionColumn::PERMISSION_TYPE, queryPhotoResult);
        EXPECT_EQ(*it++, permissionType);
    } while (!queryPhotoResult->GoToNextRow());
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_009 exit");
}

/**
 * @tc.number    : MediaLibraryManager_GrantPhotoUriPermission_test_010
 * @tc.name      : All uris are grant rand permission and then grant a same permission type
 * @tc.desc      : check database grant results whether match
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_test_010, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_010 enter");
    int64_t srcTokenId = 1;
    int64_t targetTokenId = 11;
    vector<string> uris;
    vector<string> inColumn;
    auto permissionType = PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO;
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    for (int i = 0; i < 20; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        string fileId = MediaFileUtils::GetIdFromUri(uri);
        inColumn.push_back(fileId);
        vector<string> Tempuris{uri};
        uris.push_back(uri);
        permissionType = GetRandomTemporaryPermission();
        mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, Tempuris, permissionType,
            SensitiveType);
    }

    permissionType = PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO;
    mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, uris, permissionType, SensitiveType);
    std::shared_ptr<OHOS::DataShare::DataShareResultSet> queryPhotoResult;
    QueryUriPermissionTokenIdResult(srcTokenId, targetTokenId, inColumn, TYPE_PHOTOS, queryPhotoResult);
    ASSERT_EQ(queryPhotoResult->GoToFirstRow(), E_OK);

    do {
        int32_t permissionType = GetInt32Val(AppUriPermissionColumn::PERMISSION_TYPE, queryPhotoResult);
        EXPECT_LE(permissionType, static_cast<int32_t>(PhotoPermissionType::PERSIST_READWRITE_IMAGEVIDEO));
    } while (!queryPhotoResult->GoToNextRow());
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_010 exit");
}

/**
 * @tc.number    : MediaLibraryManager_GrantPhotoUriPermission_test_011
 * @tc.name      : grant uris serial times of permission
 * @tc.desc      : check database grant results whether match
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_test_011, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_011 enter");
    int64_t srcTokenId = 1;
    int64_t targetTokenId = 12;
    vector<string> uris;
    vector<string> inColumn;
    for (int i = 0; i < 10; i++) {
        string uri = CreateOwnerPrivliegeAssets(srcTokenId, targetTokenId);
        uris.push_back(uri);
        inColumn.push_back(MediaFileUtils::GetIdFromUri(uri));
    }
    auto permissionType = PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO;
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, uris, permissionType, SensitiveType);
    permissionType = PhotoPermissionType::PERSIST_READ_IMAGEVIDEO;
    mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, uris, permissionType, SensitiveType);
    permissionType = PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO;
    mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, uris, permissionType, SensitiveType);
    permissionType = PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO;
    mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, uris, permissionType, SensitiveType);

    std::shared_ptr<OHOS::DataShare::DataShareResultSet> queryPhotoResult;
    QueryUriPermissionTokenIdResult(srcTokenId, targetTokenId, inColumn, TYPE_PHOTOS, queryPhotoResult);
    ASSERT_EQ(queryPhotoResult->GoToFirstRow(), E_OK);
    do {
        int32_t permissionType = GetInt32Val(AppUriPermissionColumn::PERMISSION_TYPE, queryPhotoResult);
        EXPECT_LE(permissionType, static_cast<int32_t>(PhotoPermissionType::PERSIST_READWRITE_IMAGEVIDEO));
    } while (!queryPhotoResult->GoToNextRow());
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_011 exit");
}

/**
 * @tc.number    : MediaLibraryManager_GrantPhotoUriPermission_test_012
 * @tc.name      : uris are mix with all grant permissions
 * @tc.desc      : check database grant results whether match
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_test_012, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_012 enter");
    int64_t srcTokenId = 1;
    int64_t targetTokenId = 13;
    vector<string> uris;
    vector<string> photosInColumn;
    vector<string> previliegeInColumn;
    auto permissionType = PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO;
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    for (int i = 0; i < 10; i++) {
        string previlegeUri = CreateOwnerPrivliegeAssets(srcTokenId, targetTokenId);
        auto photouri = CreatePhotoAsset("test.jpg");
        uris.push_back(previlegeUri);
        uris.push_back(photouri);
        previliegeInColumn.push_back(MediaFileUtils::GetIdFromUri(previlegeUri));
        photosInColumn.push_back(MediaFileUtils::GetIdFromUri(photouri));
        vector<string> Tempuris{photouri};
        permissionType = GetRandomTemporaryPermission();
        mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, Tempuris, permissionType,
            SensitiveType);
    }
    permissionType = PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO;
    mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, uris, permissionType, SensitiveType);
    std::shared_ptr<OHOS::DataShare::DataShareResultSet> queryPhotoResult;
    std::shared_ptr<OHOS::DataShare::DataShareResultSet> queryPreviliegeResult;
    QueryUriPermissionTokenIdResult(srcTokenId, targetTokenId, photosInColumn, TYPE_PHOTOS, queryPhotoResult);
    QueryUriPermissionTokenIdResult(srcTokenId, targetTokenId, previliegeInColumn, TYPE_PHOTOS, queryPreviliegeResult);
    ASSERT_EQ(queryPhotoResult->GoToFirstRow(), E_OK);
    ASSERT_EQ(queryPreviliegeResult->GoToFirstRow(), E_OK);

    do {
        int32_t permissionType = GetInt32Val(AppUriPermissionColumn::PERMISSION_TYPE, queryPhotoResult);
        EXPECT_LE(permissionType, static_cast<int32_t>(PhotoPermissionType::PERSIST_READWRITE_IMAGEVIDEO));
    } while (!queryPhotoResult->GoToNextRow());

    do {
        int32_t permissionType = GetInt32Val(AppUriPermissionColumn::PERMISSION_TYPE, queryPreviliegeResult);
        EXPECT_LE(permissionType, static_cast<int32_t>(PhotoPermissionType::PERSIST_READWRITE_IMAGEVIDEO));
    } while (!queryPreviliegeResult->GoToNextRow());

    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_012 exit");
}

/**
 * @tc.number    : MediaLibraryManager_GrantPhotoUriPermission_test_013
 * @tc.name      : permissionType error
 * @tc.desc      : check error result
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_test_013, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_013 enter");
    int64_t srcTokenId = 1;
    int64_t targetTokenId = 14;
    vector<string> uris;
    for (int i = 0; i < 5; i++) {
        string uri = CreateOwnerPrivliegeAssets(srcTokenId, targetTokenId);
        uris.push_back(uri);
    }
    auto permissionType = PhotoPermissionType::PERSIST_READ_IMAGEVIDEO;
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    auto ret = mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, uris, permissionType,
        SensitiveType);
    ASSERT_EQ(ret, E_ERR);
    permissionType = static_cast<PhotoPermissionType>(4);
    ret = mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, uris, permissionType,
        SensitiveType);
    ASSERT_EQ(ret, E_ERR);
    permissionType = PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO;
    ret = mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, uris, permissionType,
        SensitiveType);
    ASSERT_EQ(ret, E_SUCCESS);
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_013 exit");
}

/**
 * @tc.number    : MediaLibraryManager_GrantPhotoUriPermission_test_014
 * @tc.name      : HideSensitiveType Error
 * @tc.desc      : check error result
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_test_014, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_014 enter");
    int64_t srcTokenId = 1;
    int64_t targetTokenId = 15;
    vector<string> uris;
    for (int i = 0; i < 5; i++) {
        string uri = CreateOwnerPrivliegeAssets(srcTokenId, targetTokenId);
        uris.push_back(uri);
    }
    auto permissionType = PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO;
    auto SensitiveType = static_cast<HideSensitiveType>(-1);
    auto ret = mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, uris, permissionType,
        SensitiveType);
    ASSERT_EQ(ret, E_ERR);
    SensitiveType = static_cast<HideSensitiveType>(4);
    ret = mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, uris, permissionType,
        SensitiveType);
    ASSERT_EQ(ret, E_ERR);
    SensitiveType = HideSensitiveType::ALL_DESENSITIZE;
    ret = mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, uris, permissionType,
        SensitiveType);
    ASSERT_EQ(ret, E_SUCCESS);
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_014 exit");
}

/**
 * @tc.number    : MediaLibraryManager_GrantPhotoUriPermission_test_015
 * @tc.name      : Filter not exist photo uri
 * @tc.desc      : check database grant results whether match
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_test_015, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_015 enter");
    int64_t srcTokenId = 1;
    int64_t targetTokenId = 16;
    vector<string> Uris;
    vector<string> inColumn;
    int32_t resultCount = 0;
    for (int i = 0; i < 10; i++) {
        string photosUri = CreatePhotoAsset("test.jpg");
        string existUri = CreatePhotoAsset("test2.jpg");
        DeletAssetInDb(photosUri, TYPE_PHOTOS);
        Uris.push_back(photosUri);
        Uris.push_back(existUri);
        inColumn.push_back(MediaFileUtils::GetIdFromUri(photosUri));
        inColumn.push_back(MediaFileUtils::GetIdFromUri(existUri));
    }
    auto permissionType = PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO;
    auto SensitiveType = HideSensitiveType::ALL_DESENSITIZE;
    mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, Uris, permissionType, SensitiveType);

    std::shared_ptr<OHOS::DataShare::DataShareResultSet> queryResult;
    QueryUriPermissionTokenIdResult(srcTokenId, targetTokenId, inColumn, TYPE_PHOTOS, queryResult);
    ASSERT_EQ(queryResult->GoToFirstRow(), E_OK);
    do {
        int32_t permissionType = GetInt32Val(AppUriPermissionColumn::PERMISSION_TYPE, queryResult);
        EXPECT_EQ(permissionType, static_cast<int32_t>(PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO));
        resultCount++;
    } while (!queryResult->GoToNextRow());
    ASSERT_EQ(resultCount, 10);
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_015 exit");
}

/**
 * @tc.number    : MediaLibraryManager_GrantPhotoUriPermission_test_016
 * @tc.name      : Filter not exist audio uri
 * @tc.desc      : check database grant results whether match
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_test_016, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_016 enter");
    int64_t srcTokenId = 1;
    int64_t targetTokenId = 17;
    vector<string> Uris;
    vector<string> inColumn;
    int32_t resultCount = 0;
    for (int i = 0; i < 10; i++) {
        string audiosUri = CreateFile(MEDIALIBRARY_AUDIO_URI, "Audios/", "Test" + to_string(audioIndex++) + ".mp3",
        MEDIA_TYPE_AUDIO, FILE_CONTENT_MP3);
        string audiosExistUri = CreateFile(MEDIALIBRARY_AUDIO_URI, "Audios/", "Test" + to_string(audioIndex++) + ".mp3",
        MEDIA_TYPE_AUDIO, FILE_CONTENT_MP3);
        DeletAssetInDb(audiosUri, TYPE_AUDIOS);
        Uris.push_back(audiosExistUri);
        Uris.push_back(audiosUri);
        inColumn.push_back(MediaFileUtils::GetIdFromUri(audiosUri));
        inColumn.push_back(MediaFileUtils::GetIdFromUri(audiosExistUri));
    }
    auto permissionType = PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO;
    auto SensitiveType = HideSensitiveType::ALL_DESENSITIZE;
    mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, Uris, permissionType, SensitiveType);

    std::shared_ptr<OHOS::DataShare::DataShareResultSet> queryResult;
    QueryUriPermissionTokenIdResult(srcTokenId, targetTokenId, inColumn, TYPE_AUDIOS, queryResult);
    ASSERT_EQ(queryResult->GoToFirstRow(), E_OK);
    do {
        int32_t permissionType = GetInt32Val(AppUriPermissionColumn::PERMISSION_TYPE, queryResult);
        EXPECT_EQ(permissionType, static_cast<int32_t>(PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO));
        resultCount++;
    } while (!queryResult->GoToNextRow());
    ASSERT_EQ(resultCount, 10);
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_016 exit");
}

/**
 * @tc.number    : MediaLibraryManager_GrantPhotoUriPermission_test_017
 * @tc.name      : Max uri number
 * @tc.desc      : check database grant results whether match
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_test_017, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_017 enter");
    int64_t srcTokenId = 1;
    int64_t targetTokenId = 18;
    vector<string> errorUris;
    vector<string> inColumn;
    int32_t resultCount = 0;
    string uri = CreatePhotoAsset("test.jpg");
    inColumn.push_back(MediaFileUtils::GetIdFromUri(uri));
    for (int i = 0; i < 1000; i++) {
        errorUris.push_back(uri);
    }
    auto permissionType = PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO;
    auto SensitiveType = HideSensitiveType::ALL_DESENSITIZE;
    auto ret = mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, errorUris, permissionType,
        SensitiveType);
    ASSERT_EQ(ret, E_SUCCESS);
    std::shared_ptr<OHOS::DataShare::DataShareResultSet> queryResult;
    QueryUriPermissionTokenIdResult(srcTokenId, targetTokenId, inColumn, TYPE_PHOTOS, queryResult);
    ASSERT_EQ(queryResult->GoToFirstRow(), E_OK);
    do {
        int32_t permissionType = GetInt32Val(AppUriPermissionColumn::PERMISSION_TYPE, queryResult);
        EXPECT_EQ(permissionType, static_cast<int32_t>(PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO));
        resultCount++;
    } while (!queryResult->GoToNextRow());
    ASSERT_EQ(resultCount, 1);
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_017 exit");
}

/**
 * @tc.number    : MediaLibraryManager_CheckPhotoUriPermission_test_001
 * @tc.name      : Check only read system permission uri permission results
 * @tc.desc      : Grant system read permission to see CheckPhotoUriPermission results
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CheckPhotoUriPermission_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_001 enter");
    vector<string> uris;
    vector<bool> resultSet;
    vector<string> perms;
    uint64_t tokenId = 0;
    perms.push_back("ohos.permission.READ_MEDIA");
    perms.push_back("ohos.permission.WRITE_MEDIA");
    perms.push_back("ohos.permission.READ_IMAGEVIDEO");
    perms.push_back("ohos.permission.WRITE_IMAGEVIDEO");
    
    PermissionUtilsUnitTest::SetAccessTokenPermission("MediaLibraryManagerTest", perms, tokenId);
    ASSERT_TRUE(tokenId != 0);
    for (int i = 0; i < 10; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        uris.push_back(uri);
    }

    int32_t permissionFlag = 1;
    auto ret = mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlag);
    EXPECT_EQ(ret, E_SUCCESS);
    for (const auto res : resultSet) {
        EXPECT_EQ(res, true);
    }
    permissionFlag = 2;
    mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlag);
    for (const auto res : resultSet) {
        EXPECT_EQ(res, true);
    }
    permissionFlag = 3;
    mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlag);
    for (const auto res : resultSet) {
        EXPECT_EQ(res, true);
    }
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_001 exit");
}

/**
 * @tc.number    : MediaLibraryManager_CheckPhotoUriPermission_test_002
 * @tc.name      : Check has read and wirte system permission uri permission results
 * @tc.desc      : Grant system read and write permission to see CheckPhotoUriPermission results
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CheckPhotoUriPermission_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_002 enter");
    vector<string> uris;
    vector<bool> resultSet;
    vector<string> perms;
    uint64_t tokenId = 0;
    perms.push_back("ohos.permission.READ_IMAGEVIDEO");
    perms.push_back("ohos.permission.WRITE_IMAGEVIDEO");
    PermissionUtilsUnitTest::SetAccessTokenPermission("MediaLibraryManagerTest", perms, tokenId);
    ASSERT_TRUE(tokenId != 0);
    for (int i = 0; i < 10; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        uris.push_back(uri);
    }

    uint32_t permissionFlag = 1;
    mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlag);
    for (const auto res : resultSet) {
        EXPECT_EQ(res, true);
    }
    permissionFlag = 2;
    mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlag);
    for (const auto res : resultSet) {
        EXPECT_EQ(res, true);
    }
    permissionFlag = 3;
    mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlag);
    for (const auto res : resultSet) {
        EXPECT_EQ(res, true);
    }
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_002 exit");
}
/**
 * @tc.number    : MediaLibraryManager_CheckPhotoUriPermission_test_003
 * @tc.name      : Check no system permission uri permission results
 * @tc.desc      : No system permission and see CheckPhotoUriPermission check results
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CheckPhotoUriPermission_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_003 enter");
    vector<string> perms;
    uint64_t tokenId = 0;
    vector<string> uris;
    vector<bool> resultSet;
    for (int i = 0; i < 10; i++) {
        auto uriStr = CreatePhotoAsset("test.jpg");
        uris.push_back(uriStr);
    }
    uint32_t permissionFlag = 1;
    mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlag);
    for (const auto res : resultSet) {
        EXPECT_EQ(res, false);
    }
    permissionFlag = 2;
    mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlag);
    for (const auto res : resultSet) {
        EXPECT_EQ(res, false);
    }
    permissionFlag = 3;
    mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlag);
    for (const auto res : resultSet) {
        EXPECT_EQ(res, false);
    }
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_003 exit");
}

/**
 * @tc.number    : MediaLibraryManager_CheckPhotoUriPermission_test_004
 * @tc.name      : Grant Audio system read permission
 * @tc.desc      : Check uri permission results when has Audio system read permission
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CheckPhotoUriPermission_test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_004 enter");
    vector<string> uris;
    vector<bool> resultSet;
    uint64_t tokenId = 0;
    vector<string> perms;
    perms.push_back("ohos.permission.READ_IMAGEVIDEO");
    perms.push_back("ohos.permission.WRITE_IMAGEVIDEO");
    perms.push_back("ohos.permission.READ_AUDIO");
    PermissionUtilsUnitTest::SetAccessTokenPermission("MediaLibraryManagerTest", perms, tokenId);
    ASSERT_TRUE(tokenId != 0);
    for (int i = 0; i < 10; i++) {
        string uri = CreateFile(MEDIALIBRARY_AUDIO_URI, "Audios/", "Test" + to_string(audioIndex++) + ".mp3",
        MEDIA_TYPE_AUDIO, FILE_CONTENT_MP3);
        uris.push_back(uri);
    }

    uint32_t permissionFlag = 1;
    auto ret = mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlag);
    EXPECT_EQ(ret, E_SUCCESS);
    for (const auto res : resultSet) {
        EXPECT_EQ(res, true);
    }
    permissionFlag = 2;
    mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlag);
    for (const auto res : resultSet) {
        EXPECT_EQ(res, true);
    }
    permissionFlag = 3;
    mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlag);
    for (const auto res : resultSet) {
        EXPECT_EQ(res, true);
    }
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_004 exit");
}

/**
 * @tc.number    : MediaLibraryManager_CheckPhotoUriPermission_test_005
 * @tc.name      : Grant Audio system write permission
 * @tc.desc      : Check uri permission results when has Audio system wirte permission
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CheckPhotoUriPermission_test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_005 enter");
    vector<string> uris;
    vector<bool> resultSet;
    uint64_t tokenId = 0;
    vector<string> perms;
    perms.push_back("ohos.permission.READ_IMAGEVIDEO");
    perms.push_back("ohos.permission.WRITE_IMAGEVIDEO");
    perms.push_back("ohos.permission.WRITE_AUDIO");
    PermissionUtilsUnitTest::SetAccessTokenPermission("MediaLibraryManagerTest", perms, tokenId);
    ASSERT_TRUE(tokenId != 0);
    for (int i = 0; i < 10; i++) {
        string uri = CreateFile(MEDIALIBRARY_AUDIO_URI, "Audios/", "Test" + to_string(audioIndex++) + ".mp3",
        MEDIA_TYPE_AUDIO, FILE_CONTENT_MP3);
        uris.push_back(uri);
    }

    uint32_t permissionFlag = 1;
    mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlag);
    for (const auto res : resultSet) {
        EXPECT_EQ(res, true);
    }
    permissionFlag = 2;
    mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlag);
    for (const auto res : resultSet) {
        EXPECT_EQ(res, true);
    }
    permissionFlag = 3;
    mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlag);
    for (const auto res : resultSet) {
        EXPECT_EQ(res, true);
    }
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_005 exit");
}

/**
 * @tc.number    : MediaLibraryManager_CheckPhotoUriPermission_test_006
 * @tc.name      : Grant Audio system read and write permission
 * @tc.desc      : Check uri permission results when has Audio system read and wirte permission
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CheckPhotoUriPermission_test_006, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_006 enter");
    vector<string> uris;
    vector<bool> resultSet;
    uint64_t tokenId = 0;
    vector<string> perms;
    perms.push_back("ohos.permission.READ_IMAGEVIDEO");
    perms.push_back("ohos.permission.WRITE_IMAGEVIDEO");
    perms.push_back("ohos.permission.READ_AUDIO");
    perms.push_back("ohos.permission.WRITE_AUDIO");
    PermissionUtilsUnitTest::SetAccessTokenPermission("MediaLibraryManagerTest", perms, tokenId);
    ASSERT_TRUE(tokenId != 0);
    for (int i = 0; i < 10; i++) {
        string uri = CreateFile(MEDIALIBRARY_AUDIO_URI, "Audios/", "Test" + to_string(audioIndex++) + ".mp3",
        MEDIA_TYPE_AUDIO, FILE_CONTENT_MP3);
        uris.push_back(uri);
    }

    uint32_t permissionFlag = 1;
    mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlag);
    for (const auto res : resultSet) {
        EXPECT_EQ(res, true);
    }
    permissionFlag = 2;
    mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlag);
    for (const auto res : resultSet) {
        EXPECT_EQ(res, true);
    }
    permissionFlag = 3;
    mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlag);
    for (const auto res : resultSet) {
        EXPECT_EQ(res, true);
    }
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_006 exit");
}

/**
 * @tc.number    : MediaLibraryManager_CheckPhotoUriPermission_test_007
 * @tc.name      : Has no system permissions but all uri have grant other permissions
 * @tc.desc      : Check uri permissions results when all uri have grant other permissions
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CheckPhotoUriPermission_test_007, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_007 enter");
    vector<string> perms;
    int64_t srctokenId = 7;
    int64_t targerTokenId = 70;
    vector<string> uris;
    vector<bool> resultSet;
    vector<bool> expectReadResult;
    vector<bool> expectWriteResult;
    vector<bool> expectReadWriteResult;
    auto permissionType = PhotoPermissionType::PERSIST_READ_IMAGEVIDEO;
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    for (int i = 0; i < 20; i++) {
        string uri = CreatePhotoAsset("test.jpg");
        vector<string> Tempuris{uri};
        uris.push_back(uri);
        permissionType = GetRandomTemporaryPermission();
        if (static_cast<int32_t>(permissionType) == 0) {
            expectReadResult.push_back(true);
            expectWriteResult.push_back(false);
            expectReadWriteResult.push_back(false);
        } else if (static_cast<int32_t>(permissionType) == 1) {
            expectReadResult.push_back(false);
            expectWriteResult.push_back(true);
            expectReadWriteResult.push_back(false);
        } else {
            expectReadResult.push_back(true);
            expectWriteResult.push_back(true);
            expectReadWriteResult.push_back(true);
        }
        mediaLibraryExtendManager->GrantPhotoUriPermission(srctokenId, targerTokenId, Tempuris, permissionType,
            SensitiveType);
    }
    uint32_t permissionFlag = 1;
    mediaLibraryExtendManager->CheckPhotoUriPermission(targerTokenId, uris, resultSet, permissionFlag);
    for (int i = 0; i < resultSet.size(); i++) {
        EXPECT_EQ(resultSet[i], expectReadResult[i]);
    }
    permissionFlag = 2;
    mediaLibraryExtendManager->CheckPhotoUriPermission(targerTokenId, uris, resultSet, permissionFlag);
    for (int i = 0; i < resultSet.size(); i++) {
        EXPECT_EQ(resultSet[i], expectWriteResult[i]);
    }
    permissionFlag = 3;
    mediaLibraryExtendManager->CheckPhotoUriPermission(targerTokenId, uris, resultSet, permissionFlag);
    for (int i = 0; i < resultSet.size(); i++) {
        EXPECT_EQ(resultSet[i], expectReadWriteResult[i]);
    }
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_007 exit");
}

/**
 * @tc.number    : MediaLibraryManager_CheckPhotoUriPermission_test_008
 * @tc.name      : Has no system permissions but part of uri have grant other permissions
 * @tc.desc      : Check uri permissions results when part of have grant other permissions
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CheckPhotoUriPermission_test_008, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_008 enter");
    vector<string> perms;
    int64_t srctokenId = 8;
    int64_t targetTokenId = 80;
    vector<string> uris;
    vector<bool> resultSet;
    vector<vector<bool>> expectResult;
    expectResult.resize(3);
    auto permissionType = PhotoPermissionType::PERSIST_READ_IMAGEVIDEO;
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    for (int i = 0; i < 10; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        vector<string> Tempuris{uri};
        uris.push_back(uri);
        permissionType = GetRandomTemporaryPermission();
        if (static_cast<int32_t>(permissionType) == 0) {
            expectResult[0].push_back(true);
            expectResult[1].push_back(false);
            expectResult[2].push_back(false);
        } else if (static_cast<int32_t>(permissionType) == 1) {
            expectResult[0].push_back(false);
            expectResult[1].push_back(true);
            expectResult[2].push_back(false);
        } else {
            expectResult[0].push_back(true);
            expectResult[1].push_back(true);
            expectResult[2].push_back(true);
        }
        mediaLibraryExtendManager->GrantPhotoUriPermission(srctokenId, targetTokenId, Tempuris, permissionType,
            SensitiveType);
    }
    for (int i = 0; i < 5; i++) {
        uris.push_back(CreatePhotoAsset("test.jpg"));
        expectResult[0].push_back(false);
        expectResult[1].push_back(false);
        expectResult[2].push_back(false);
    }
    uint32_t permissionFlag = 1;
    for (int i = 0; i < 3; i++) {
        mediaLibraryExtendManager->CheckPhotoUriPermission(targetTokenId, uris, resultSet, permissionFlag);
        for (int j = 0; j < resultSet.size(); j++) {
            EXPECT_EQ(resultSet[j], expectResult[i][j]);
        }
        permissionFlag++;
        MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_008 exit");
    }
}

/**
 * @tc.number    : MediaLibraryManager_CheckPhotoUriPermission_test_009
 * @tc.name      : Has read system permissions and also uri have grant other permissions
 * @tc.desc      : Check uri permissions results when has system read permission and other permission
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CheckPhotoUriPermission_test_009, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_009 enter");
    vector<string> uris;
    vector<bool> resultSet;
    vector<bool> expectWriteResult;
    vector<bool> expectReadWriteResult;
    auto permissionType = PhotoPermissionType::PERSIST_READ_IMAGEVIDEO;
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    uint64_t tokenId = 0;
    vector<string> perms;
    perms.push_back("ohos.permission.READ_MEDIA");
    perms.push_back("ohos.permission.WRITE_MEDIA");
    perms.push_back("ohos.permission.READ_IMAGEVIDEO");
    perms.push_back("ohos.permission.WRITE_IMAGEVIDEO");

    PermissionUtilsUnitTest::SetAccessTokenPermission("MediaLibraryManagerTest", perms, tokenId);
    ASSERT_TRUE(tokenId != 0);
    for (int i = 0; i < 10; i++) {
        string uri = CreatePhotoAsset("test.jpg");
        vector<string> Tempuris{uri};
        uris.push_back(uri);
        permissionType = GetRandomTemporaryPermission();
        if (static_cast<int32_t>(permissionType) == 0) {
            expectWriteResult.push_back(false);
            expectReadWriteResult.push_back(false);
        } else if (static_cast<int32_t>(permissionType) == 2) {
            expectWriteResult.push_back(true);
            expectReadWriteResult.push_back(true);
        } else {
            expectWriteResult.push_back(true);
            expectReadWriteResult.push_back(true);
        }
        mediaLibraryExtendManager->GrantPhotoUriPermission(tokenId, tokenId, Tempuris, permissionType, SensitiveType);
    }

    uint32_t permissionFlag = 1;
    mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlag);
    for (int i = 0; i < resultSet.size(); i++) {
        EXPECT_EQ(resultSet[i], true);
    }
    permissionFlag = 2;
    mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlag);
    for (int i = 0; i < resultSet.size(); i++) {
        EXPECT_EQ(resultSet[i], expectWriteResult[i]);
    }
    permissionFlag = 3;
    mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlag);
    for (int i = 0; i < resultSet.size(); i++) {
        EXPECT_EQ(resultSet[i], expectReadWriteResult[i]);
    }
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_009 exit");
}

/**
 * @tc.number    : MediaLibraryManager_CheckPhotoUriPermission_test_010
 * @tc.name      : Has read and write system permissions and also uri have grant other permissions
 * @tc.desc      : Check uri permissions results when has system read and write permission and other permissions
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CheckPhotoUriPermission_test_010, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_010 enter");
    vector<string> uris;
    vector<bool> resultSet;
    auto permissionType = PhotoPermissionType::PERSIST_READ_IMAGEVIDEO;
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    uint64_t tokenId = 0;
    vector<string> perms;
    perms.push_back("ohos.permission.READ_IMAGEVIDEO");
    perms.push_back("ohos.permission.WRITE_IMAGEVIDEO");
    PermissionUtilsUnitTest::SetAccessTokenPermission("MediaLibraryManagerTest", perms, tokenId);
    ASSERT_TRUE(tokenId != 0);
    for (int i = 0; i < 10; i++) {
        string uri = CreatePhotoAsset("test.jpg");
        vector<string> Tempuris{uri};
        uris.push_back(uri);
        permissionType = GetRandomTemporaryPermission();
        mediaLibraryExtendManager->GrantPhotoUriPermission(tokenId, tokenId, Tempuris, permissionType, SensitiveType);
    }

    int32_t permissionFlag = 1;
    mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlag);
    for (int i = 0; i < resultSet.size(); i++) {
        EXPECT_EQ(resultSet[i], true);
    }
    permissionFlag = 2;
    mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlag);
    for (int i = 0; i < resultSet.size(); i++) {
        EXPECT_EQ(resultSet[i], true);
    }
    permissionFlag = 3;
    mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlag);
    for (int i = 0; i < resultSet.size(); i++) {
        EXPECT_EQ(resultSet[i], true);
    }
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_0010 exit");
}

/**
 * @tc.number    : MediaLibraryManager_CheckPhotoUriPermission_test_011
 * @tc.name      : uri numuber are oversize
 * @tc.desc      : check error result
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CheckPhotoUriPermission_test_011, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_011 enter");
    ASSERT_TRUE(tokenId != 0);
    tokenId = 0;
    vector<string> uris;
    vector<bool> resultSet;
    uint32_t permissionFlag = 1;
    uris.resize(1001);
    auto ret = mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlag);
    EXPECT_EQ(ret, E_ERR);
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_011 exit");
}

/**
 * @tc.number    : MediaLibraryManager_CheckPhotoUriPermission_test_012
 * @tc.name      : file type do not match
 * @tc.desc      : check error result
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CheckPhotoUriPermission_test_012, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_012 enter");
    ASSERT_TRUE(tokenId != 0);
    tokenId = 0;
    vector<string> uris;
    vector<bool> resultSet;
    uint32_t permissionFlag = 1;
    for (int i = 0; i < 5; i++) {
        string uri = CreatePhotoAsset("test.jpg");
        uris.push_back(uri);
    }
    auto ret = mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlag);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_012 exit");
}

/**
 * @tc.number    : MediaLibraryManager_CheckPhotoUriPermission_test_013
 * @tc.name      : file check flag do not match
 * @tc.desc      : check error result
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CheckPhotoUriPermission_test_013, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_013 enter");
    ASSERT_TRUE(tokenId != 0);
    tokenId = 0;
    vector<string> uris;
    int64_t srcTokenId = 13;
    int64_t targetTokenId = 130;
    vector<bool> resultSet;
    auto permissionType = PhotoPermissionType::PERSIST_READ_IMAGEVIDEO;
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    uint32_t permissionFlag = 0;
    for (int i = 0; i < 5; i++) {
        string uri = CreatePhotoAsset("test.jpg");
        vector<string> Tempuris{uri};
        uris.push_back(uri);
        permissionType = GetRandomTemporaryPermission();
        mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, targetTokenId, Tempuris, permissionType,
            SensitiveType);
    }
    auto ret = mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlag);
    EXPECT_EQ(ret, E_ERR);
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_013 exit");
}

/**
 * @tc.number    : MediaLibraryExtendManager_GrantPhotoUriPermission_test_001
 * @tc.name      : grant photo type uri permissions
 * @tc.desc      : check database grant results whether match
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryExtendManager_GrantPhotoUriPermission_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryExtendManager_GrantPhotoUriPermission_test_001 enter");
    int src_tokenId = 1;
    int target_tokenId = 2;
    vector<string> uris;
    vector<string> inColumn;
    for (int i = 0; i < 5; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        uris.push_back(uri);
        inColumn.push_back(MediaFileUtils::GetIdFromUri(uri));
    }
    auto permissionType = PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO;
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    mediaLibraryExtendManager->GrantPhotoUriPermission(src_tokenId, target_tokenId, uris, permissionType,
        SensitiveType);
    std::shared_ptr<OHOS::DataShare::DataShareResultSet> queryPhotoResult;
    QueryUriPermissionTokenIdResult(src_tokenId, target_tokenId, inColumn, TYPE_PHOTOS, queryPhotoResult);
    ASSERT_EQ(queryPhotoResult->GoToFirstRow(), E_OK);
    do {
        int32_t permissionType = GetInt32Val(AppUriPermissionColumn::PERMISSION_TYPE, queryPhotoResult);
        EXPECT_EQ(permissionType, static_cast<int32_t>(PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO));
    } while (!queryPhotoResult->GoToNextRow());
    MEDIA_INFO_LOG("MediaLibraryExtendManager_GrantPhotoUriPermission_test_001 exit");
}

/**
 * @tc.number    : MediaLibraryExtendManager_GrantPhotoUriPermission_test_002
 * @tc.name      : HideSensitiveType Error
 * @tc.desc      : check error result
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryExtendManager_GrantPhotoUriPermission_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryExtendManager_GrantPhotoUriPermission_test_002 enter");
    int src_tokenId = 5;
    int target_tokenId = 6;
    vector<string> uris;
    for (int i = 0; i < 5; i++) {
        string uri = CreateOwnerPrivliegeAssets(src_tokenId, target_tokenId);
        uris.push_back(uri);
    }
    auto permissionType = PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO;
    auto SensitiveType = static_cast<HideSensitiveType>(-1);
    auto ret = mediaLibraryExtendManager->GrantPhotoUriPermission(src_tokenId, tokenId, uris, permissionType,
        SensitiveType);
    ASSERT_EQ(ret, E_ERR);
    SensitiveType = static_cast<HideSensitiveType>(4);
    ret = mediaLibraryExtendManager->GrantPhotoUriPermission(src_tokenId, target_tokenId, uris, permissionType,
        SensitiveType);
    ASSERT_EQ(ret, E_ERR);
    SensitiveType = HideSensitiveType::ALL_DESENSITIZE;
    ret = mediaLibraryExtendManager->GrantPhotoUriPermission(src_tokenId, target_tokenId, uris, permissionType,
        SensitiveType);
    ASSERT_EQ(ret, E_SUCCESS);
    MEDIA_INFO_LOG("MediaLibraryExtendManager_GrantPhotoUriPermission_test_002 exit");
}

/**
 * @tc.number    : MediaLibraryExtendManager_CheckPhotoUriPermission_test_001
 * @tc.name      : Check only read system permission uri permission results
 * @tc.desc      : Grant system read permission to see CheckPhotoUriPermission results
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryExtendManager_CheckPhotoUriPermission_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryExtendManager_CheckPhotoUriPermission_test_001 enter");
    vector<string> uris;
    vector<bool> resultSet;
    for (int i = 0; i < 10; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        uris.push_back(uri);
    }
    vector<string> perms;
    uint64_t tokenId = 0;
    perms.push_back("ohos.permission.READ_IMAGEVIDEO");
    perms.push_back("ohos.permission.WRITE_IMAGEVIDEO");
    PermissionUtilsUnitTest::SetAccessTokenPermission("MediaLibraryManagerTest", perms, tokenId);
    ASSERT_TRUE(tokenId != 0);

    uint32_t permissionFlag = 1;
    mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlag);
    for (const auto res : resultSet) {
        EXPECT_EQ(res, true);
    }
    permissionFlag = 2;
    mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlag);
    for (const auto res : resultSet) {
        EXPECT_EQ(res, true);
    }
    permissionFlag = 3;
    mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlag);
    for (const auto res : resultSet) {
        EXPECT_EQ(res, true);
    }
    MEDIA_INFO_LOG("MediaLibraryExtendManager_CheckPhotoUriPermission_test_001 exit");
}

/**
 * @tc.number    : MediaLibraryExtendManager_CheckPhotoUriPermission_test_002
 * @tc.name      : file check flag do not match
 * @tc.desc      : check error result
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryExtendManager_CheckPhotoUriPermission_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryExtendManager_CheckPhotoUriPermission_test_002 enter");
    ASSERT_TRUE(tokenId != 0);
    tokenId = 0;
    vector<string> uris;
    vector<bool> resultSet;
    auto permissionType = PhotoPermissionType::PERSIST_READ_IMAGEVIDEO;
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    uint32_t permissionFlag = 0;
    for (int i = 0; i < 5; i++) {
        string uri = CreatePhotoAsset("test.jpg");
        vector<string> Tempuris{uri};
        uris.push_back(uri);
        permissionType = GetRandomTemporaryPermission();
        mediaLibraryExtendManager->GrantPhotoUriPermission(0, 2, Tempuris, permissionType, SensitiveType);
    }
    auto ret = mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlag);
    EXPECT_EQ(ret, E_ERR);
    MEDIA_INFO_LOG("MediaLibraryExtendManager_CheckPhotoUriPermission_test_002 exit");
}

/**
 * @tc.number    : MediaLibraryExtendManager_CancelPhotoUriPermission_test_001
 * @tc.name      : cancel permission
 * @tc.desc      : cancel permission success
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryExtendManager_CancelPhotoUriPermission_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryExtendManager_CancelPhotoUriPermission_test_001 enter");
    int src_tokenId = 1;
    int target_tokenId = 2;
    vector<string> uris;
    vector<string> inColumn;
    for (int i = 0; i < 5; i++) {
        auto uri = CreatePhotoAsset("test.mp4");
        uris.push_back(uri);
        inColumn.push_back(MediaFileUtils::GetIdFromUri(uri));
    }
    auto permissionType = PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO;
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    int32_t ret = mediaLibraryExtendManager->GrantPhotoUriPermission(src_tokenId, target_tokenId, uris, permissionType,
        SensitiveType);
    EXPECT_EQ(ret, 0);
    ret = mediaLibraryExtendManager->CancelPhotoUriPermission(src_tokenId, target_tokenId, uris);
    EXPECT_EQ(ret, 0);
    MEDIA_INFO_LOG("MediaLibraryExtendManager_CancelPhotoUriPermission_test_001 exit");
}

/**
 * @tc.number    : MediaLibraryExtendManager_CancelPhotoUriPermission_test_002
 * @tc.name      : cancel permission
 * @tc.desc      : cancel permission fail
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryExtendManager_CancelPhotoUriPermission_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaLibraryExtendManager_CancelPhotoUriPermission_test__002 enter");
    int src_tokenId = 3;
    int target_tokenId = 2;
    vector<string> uris;
    int32_t ret = mediaLibraryExtendManager->CancelPhotoUriPermission(src_tokenId, target_tokenId, uris);
    EXPECT_EQ(ret, E_ERR);
    MEDIA_INFO_LOG("MediaLibraryExtendManager_CancelPhotoUriPermission_test_002 exit");
}

HWTEST_F(MediaLibraryManagerTest, GetUriFromFilePath_001, TestSize.Level0)
{
    string filePath;
    string file = "/path/to/file";
    Uri fileUri(file);
    string userId;
    auto result = manager.GetUriFromFilePath(filePath, fileUri, userId);
    EXPECT_EQ(result, E_INVALID_PATH);
}

HWTEST_F(MediaLibraryManagerTest, GetUriFromFilePath_002, TestSize.Level0)
{
    string filePath = PRE_PATH_VALUES;
    string file = "/path/to/file";
    Uri fileUri(file);
    string userId;
    auto result = manager.GetUriFromFilePath(filePath, fileUri, userId);
    EXPECT_EQ(result, E_CHECK_ROOT_DIR_FAIL);
}

HWTEST_F(MediaLibraryManagerTest, GetSandboxPath_001, TestSize.Level0)
{
    std::string path = "/storage/cloud/";
    Size size;
    bool isAstc = true;
    auto result = manager.GetSandboxPath(path, size, isAstc);
    EXPECT_EQ(result, "");
}

HWTEST_F(MediaLibraryManagerTest, GetSandboxPath_002, TestSize.Level0)
{
    std::string path = ROOT_MEDIA_DIR;
    Size size;
    size.width = DEFAULT_ORIGINAL;
    size.height = DEFAULT_ORIGINAL;
    bool isAstc = false;
    auto result = manager.GetSandboxPath(path, size, isAstc);
    EXPECT_EQ(result, ROOT_SANDBOX_DIR + ".thumbs/" + "/LCD.jpg");
}

HWTEST_F(MediaLibraryManagerTest, GetSandboxPath_003, TestSize.Level0)
{
    std::string path = ROOT_MEDIA_DIR;
    Size size;
    size.width = 256;
    size.height = 768;
    bool isAstc = false;
    auto result = manager.GetSandboxPath(path, size, isAstc);
    EXPECT_NE(result, ROOT_SANDBOX_DIR + ".thumbs/" + "/LCD.jpg");
}

HWTEST_F(MediaLibraryManagerTest, GetSandboxPath_004, TestSize.Level0)
{
    std::string path = ROOT_MEDIA_DIR;
    Size size;
    size.width = 768;
    size.height = 768;
    bool isAstc = false;
    auto result = manager.GetSandboxPath(path, size, isAstc);
    EXPECT_EQ(result, ROOT_SANDBOX_DIR + ".thumbs/" + "/LCD.jpg");
}

HWTEST_F(MediaLibraryManagerTest, GetUriIdPrefix_001, TestSize.Level0)
{
    std::string fileUri = "";
    manager.GetUriIdPrefix(fileUri);
    EXPECT_EQ(fileUri, "");
}

HWTEST_F(MediaLibraryManagerTest, GetUriIdPrefix_002, TestSize.Level0)
{
    std::string fileUri = "/Photo";
    manager.GetUriIdPrefix(fileUri);
    EXPECT_EQ(fileUri, "/Photo");
}

HWTEST_F(MediaLibraryManagerTest, GetUriIdPrefix_003, TestSize.Level0)
{
    std::string fileUri = "a/b/Photo";
    manager.GetUriIdPrefix(fileUri);
    EXPECT_EQ(fileUri, "a");
}

HWTEST_F(MediaLibraryManagerTest, IfSizeEqualsRatio_001, TestSize.Level0)
{
    Size imageSize;
    imageSize.height = 0;
    Size targetSize;
    targetSize.height = 0;
    auto ret = manager.IfSizeEqualsRatio(imageSize, targetSize);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryManagerTest, IfSizeEqualsRatio_002, TestSize.Level0)
{
    Size imageSize;
    imageSize.height = 10;
    imageSize.width = 10;
    Size targetSize;
    targetSize.height = 20;
    targetSize.width = 90000;
    auto ret = manager.IfSizeEqualsRatio(imageSize, targetSize);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryManagerTest, IfSizeEqualsRatio_003, TestSize.Level0)
{
    Size imageSize;
    imageSize.height = 100;
    imageSize.width = 100;
    Size targetSize;
    targetSize.height = 300;
    targetSize.width = 300;
    auto ret = manager.IfSizeEqualsRatio(imageSize, targetSize);
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryManagerTest, OpenReadOnlyAppSandboxVideo_001, TestSize.Level0)
{
    string uri;
    auto ret = manager.OpenReadOnlyAppSandboxVideo(uri);
    EXPECT_EQ(ret, -1);
}

HWTEST_F(MediaLibraryManagerTest, GetSandboxMovingPhotoTime_001, TestSize.Level0)
{
    string uri;
    auto ret = manager.GetSandboxMovingPhotoTime(uri);
    EXPECT_EQ(ret, -1);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_emptyuris, TestSize.Level0)
{
    string appid = "testApp";
    // empty uris GrantPhotoUriPermission will return E_ERR
    vector<string> uris;
    PhotoPermissionType photoPermissionType = PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO;
    HideSensitiveType hideSensitiveTpye = HideSensitiveType::ALL_DESENSITIZE;
    int32_t ret = mediaLibraryManager->GrantPhotoUriPermission(appid, uris, photoPermissionType, hideSensitiveTpye);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_exceedMax, TestSize.Level0)
{
    string appid = "testApp";
    vector<string> uris(URI_SIZE + 1, "testUri");
    PhotoPermissionType photoPermissionType = PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO;
    HideSensitiveType hideSensitiveTpye = HideSensitiveType::ALL_DESENSITIZE;
    int32_t ret = mediaLibraryManager->GrantPhotoUriPermission(appid, uris, photoPermissionType, hideSensitiveTpye);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_invalid_permission_type, TestSize.Level0)
{
    string appid = "testApp";
    vector<string> uris ={ "testUri" };
    PhotoPermissionType photoPermissionType = static_cast<PhotoPermissionType>(100);
    HideSensitiveType hideSensitiveTpye = HideSensitiveType::ALL_DESENSITIZE;
    int32_t ret = mediaLibraryManager->GrantPhotoUriPermission(appid, uris, photoPermissionType, hideSensitiveTpye);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_invalid_hide_type, TestSize.Level0)
{
    string appid = "testApp";
    vector<string> uris ={ "testUri" };
    PhotoPermissionType photoPermissionType = PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO;
    HideSensitiveType hideSensitiveTpye = static_cast<HideSensitiveType>(100);
    int32_t ret = mediaLibraryManager->GrantPhotoUriPermission(appid, uris, photoPermissionType, hideSensitiveTpye);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_invalid_uris, TestSize.Level0)
{
    string appid = "testApp";
    vector<string> uris ={ "testUri" };
    PhotoPermissionType photoPermissionType = PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO;
    HideSensitiveType hideSensitiveTpye = HideSensitiveType::ALL_DESENSITIZE;
    int32_t ret = mediaLibraryManager->GrantPhotoUriPermission(appid, uris, photoPermissionType, hideSensitiveTpye);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_normal_uris, TestSize.Level0)
{
    string appid = "testApp";
    vector<string> uris;
    for (int i = 0; i < 5; i++) {
        uris.push_back(CreatePhotoAsset("test.mp4"));
    }
    PhotoPermissionType photoPermissionType = PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO;
    HideSensitiveType hideSensitiveTpye = HideSensitiveType::ALL_DESENSITIZE;
    int32_t ret = mediaLibraryManager->GrantPhotoUriPermission(appid, uris, photoPermissionType, hideSensitiveTpye);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CheckPhotoUriPermission_checkinput_failed, TestSize.Level0)
{
    uint32_t flag = 1;
    uint32_t tokenId = 1;
    vector<bool> results;
    string appid = "testAppId";
    vector<string> urisSource;

    auto ret = mediaLibraryManager->CheckPhotoUriPermission(tokenId, appid, urisSource, results, flag);
    EXPECT_EQ(ret, E_ERR);

    urisSource.assign(URI_SIZE + 1, "tesUri");
    ret = mediaLibraryManager->CheckPhotoUriPermission(tokenId, appid, urisSource, results, flag);
    EXPECT_EQ(ret, E_ERR);

    flag = 0;
    urisSource.assign(2, "testUri");
    ret = mediaLibraryManager->CheckPhotoUriPermission(tokenId, appid, urisSource, results, flag);
    EXPECT_EQ(ret, E_ERR);

    flag = 4;
    ret = mediaLibraryManager->CheckPhotoUriPermission(tokenId, appid, urisSource, results, flag);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CheckPhotoUriPermission_typeClassify_failed, TestSize.Level0)
{
    uint32_t flag = 1;
    uint32_t tokenId = 1;
    vector<bool> results;
    string appid = "testAppId";
    vector<string> urisSource = { "testuri" };

    auto ret = mediaLibraryManager->CheckPhotoUriPermission(tokenId, appid, urisSource, results, flag);
    EXPECT_EQ(ret, E_ERR);

    urisSource.clear();
    for (int i = 0; i < 5; i++) {
        urisSource.push_back(CreatePhotoAsset("test.mp4"));
    }
    ret = mediaLibraryManager->CheckPhotoUriPermission(tokenId, appid, urisSource, results, flag);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GetAstc_emptyUris, TestSize.Level0)
{
    string uriStr;
    auto pixelMap = mediaLibraryManager->GetAstc(Uri(uriStr));
    EXPECT_EQ(pixelMap, nullptr);
}
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GetAstcYearAndMonth_test, TestSize.Level0)
{
    vector<string> uris;
    int32_t ret = mediaLibraryManager->GetAstcYearAndMonth(uris);
    EXPECT_EQ(ret, E_ERR);

    for (int i = 0; i < 5; i++) {
        uris.push_back(CreatePhotoAsset("test.mp4"));
    }
    ret = ret = mediaLibraryManager->GetAstcYearAndMonth(uris);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_ReadPrivateMovingPhoto_test, TestSize.Level0)
{
    EXPECT_NE(mediaLibraryExtendManager, nullptr);
    string uri = "test";
    EXPECT_EQ(mediaLibraryExtendManager->ReadPrivateMovingPhoto(uri, HideSensitiveType::ALL_DESENSITIZE), E_ERR);
    uri = "../test/test.txt";
    EXPECT_EQ(mediaLibraryExtendManager->ReadPrivateMovingPhoto(uri, HideSensitiveType::ALL_DESENSITIZE), E_ERR);
    uri = CreatePhotoAsset("test.mp4");
    EXPECT_EQ(mediaLibraryExtendManager->ReadPrivateMovingPhoto(uri, HideSensitiveType::ALL_DESENSITIZE), E_ERR);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GetResultSetFromDb_test, TestSize.Level0)
{
    EXPECT_NE(mediaLibraryExtendManager, nullptr);
    string columnName = "file_id";
    string value = "1";
    vector<string> columns;
    EXPECT_NE(mediaLibraryExtendManager->GetResultSetFromDb(columnName, value, columns), nullptr);
}
} // namespace Media
} // namespace OHOS
