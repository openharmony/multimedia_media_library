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
#include "medialibrary_mock_tocken.h"
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
#include "data_secondary_directory_uri.h"

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
void ClearFile();
void ClearAllFile();
void CreateDataHelper(int32_t systemAbilityId);

constexpr int STORAGE_MANAGER_MANAGER_ID = 5003;
int g_albumMediaType = MEDIA_TYPE_ALBUM;
int64_t g_oneImageSize = 0;
const int CLEAN_TIME = 1;
const int SCAN_WAIT_TIME = 10;
constexpr int32_t URI_SIZE = 101;
uint64_t tokenId = 0;
int32_t txtIndex = 0;
int32_t audioIndex = 0;
int32_t randomNumber = 0;
static constexpr int32_t SLEEP_FIVE_SECONDS = 5;

struct UriParams {
    string path;
    string fileUri;
    Size size;
    bool isAstc;
    DecodeDynamicRange dynamicRange;
    string user;
};

static const unsigned char FILE_CONTENT_JPG[] = {
    0x49, 0x44, 0x33, 0x03, 0x20, 0x20, 0x20, 0x0c, 0x24, 0x5d, 0x54, 0x45, 0x4e, 0x43, 0x20, 0x20, 0x20, 0x0b,
    0x20, 0x20, 0x20,
};

static const unsigned char FILE_CONTENT_MP4[] = {
    0x20, 0x20, 0x20, 0x20, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6f, 0x6d, 0x20, 0x20, 0x02, 0x20, 0x69, 0x73, 0x6f,
    0x6d, 0x69, 0x73, 0x6f, 0x32, 0x61, 0x76, 0x63, 0x31, 0x6d, 0x70, 0x34, 0x31, 0x20, 0x20, 0x20, 0x08, 0x66, 0x72,
    0x65, 0x65, 0x20, 0x49, 0xdd, 0x01, 0x6d, 0x64, 0x61, 0x74, 0x20, 0x20, 0x02, 0xa0, 0x06, 0x05, 0xff, 0xff, 0x9c,
};

static const std::vector<std::string> perms = {
    "ohos.permission.READ_IMAGEVIDEO",
    "ohos.permission.WRITE_IMAGEVIDEO",
    "ohos.permission.READ_AUDIO",
    "ohos.permission.WRITE_AUDIO",
    "ohos.permission.READ_MEDIA",
    "ohos.permission.WRITE_MEDIA",
    "ohos.permission.MEDIA_LOCATION",
    "ohos.permission.GET_BUNDLE_INFO_PRIVILEGED"
};

MediaLibraryManager* mediaLibraryManager = MediaLibraryManager::GetMediaLibraryManager();
MediaLibraryExtendManager* mediaLibraryExtendManager = MediaLibraryExtendManager::GetMediaLibraryExtendManager();
static std::shared_ptr<MediaLibraryMockHapToken> hapToken = nullptr;

void MediaLibraryManagerTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("MediaLibraryManagerTest::SetUpTestCase:: invoked");
    CreateDataHelper(STORAGE_MANAGER_MANAGER_ID);
    ASSERT_NE(sDataShareHelper_, nullptr);

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

void mockToken(const std::vector<std::string>& perms, shared_ptr<MediaLibraryMockHapToken>& token)
{
    // mock tokenID
    token = make_shared<MediaLibraryMockHapToken>("com.ohos.medialibrary.medialibrarydata", perms);
    for (auto &perm : perms) {
        MediaLibraryMockTokenUtils::GrantPermissionByTest(IPCSkeleton::GetSelfTokenID(), perm, 0);
    }
}

// SetUp:Execute before each test case
void MediaLibraryManagerTest::SetUp(void)
{
    // restore shell token before testcase
    uint64_t shellToken = IPCSkeleton::GetSelfTokenID();
    MediaLibraryMockTokenUtils::RestoreShellToken(shellToken);
    mockToken(perms, hapToken);
    system("rm -rf /storage/cloud/100/files/Photo/*");
}

void MediaLibraryManagerTest::TearDown(void)
{
    // rescovery shell toekn after tesecase
    hapToken = nullptr;
    SetSelfTokenID(MediaLibraryMockTokenUtils::GetShellToken());
    MediaLibraryMockTokenUtils::ResetToken();
}

void CreateDataHelper(int32_t systemAbilityId)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(saManager, nullptr);

    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    ASSERT_NE(remoteObj, nullptr);

    mediaLibraryManager->InitMediaLibraryManager(remoteObj);
    MEDIA_INFO_LOG("InitMediaLibraryManager success!");

    if (sDataShareHelper_ == nullptr) {
        const sptr<IRemoteObject> &token = remoteObj;
        sDataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
        ASSERT_NE(sDataShareHelper_, nullptr);
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
    ASSERT_NE(sDataShareHelper_, nullptr);
    Uri deleteAssetUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(MEDIA_DATA_DB_ID, MediaFileUtils::GetIdFromUri(fileUri));
    int retVal = sDataShareHelper_->Delete(deleteAssetUri, predicates);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test DeleteFile::uri :%{private}s", deleteAssetUri.ToString().c_str());
    EXPECT_NE(retVal, E_ERR);
}

void ClearFile()
{
    ASSERT_NE(sDataShareHelper_, nullptr);
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
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_test_001::Start");
    string displayName = "test.jpg";
    string uri =  mediaLibraryManager->CreateAsset(displayName);
    ASSERT_NE(uri, "");
    int32_t destFd = mediaLibraryManager->OpenAsset(uri, MEDIA_FILEMODE_READWRITE);
    ASSERT_GT(destFd, 0);
    int32_t resWrite = write(destFd, FILE_CONTENT_JPG, sizeof(FILE_CONTENT_JPG));
    ASSERT_NE(resWrite, -1);
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
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_test_002::Start");
    string displayName = "test2.jpg";
    string uri =  mediaLibraryManager->CreateAsset(displayName);
    MEDIA_INFO_LOG("createFile uri: %{public}s", uri.c_str());
    ASSERT_NE(uri, "");
    int32_t destFd = mediaLibraryManager->OpenAsset(uri, MEDIA_FILEMODE_READWRITE);
    ASSERT_GT(destFd, 0);
    int32_t resWrite = write(destFd, FILE_CONTENT_JPG, sizeof(FILE_CONTENT_JPG));
    ASSERT_NE(resWrite, -1);
    mediaLibraryManager->CloseAsset(uri, destFd);

    int32_t srcFd = mediaLibraryManager->OpenAsset(uri, MEDIA_FILEMODE_READWRITE);
    int64_t srcLen = lseek(srcFd, 0, SEEK_END);
    lseek(srcFd, 0, SEEK_SET);
    unsigned char *buf = static_cast<unsigned char*>(malloc(srcLen));
    ASSERT_NE(buf, nullptr);
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
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_test_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_test_003::Start");
    string displayName = "testVideo.mp4";
    string uri =  mediaLibraryManager->CreateAsset(displayName);
    MEDIA_INFO_LOG("createFile uri: %{public}s", uri.c_str());
    ASSERT_NE(uri, "");
    int32_t destFd = mediaLibraryManager->OpenAsset(uri, MEDIA_FILEMODE_READWRITE);
    ASSERT_GT(destFd, 0);
    int32_t resWrite = write(destFd, FILE_CONTENT_MP4, sizeof(FILE_CONTENT_MP4));
    ASSERT_NE(resWrite, -1);

    mediaLibraryManager->CloseAsset(uri, destFd);
    int32_t srcFd = mediaLibraryManager->OpenAsset(uri, MEDIA_FILEMODE_READWRITE);
    int64_t srcLen = lseek(srcFd, 0, SEEK_END);
    lseek(srcFd, 0, SEEK_SET);
    unsigned char *buf = static_cast<unsigned char*>(malloc(srcLen));
    ASSERT_NE(buf, nullptr);
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
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_test_004, TestSize.Level1)
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
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_test_005, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_test_005::Start");
    string displayName = "testPNG.png";
    string uri =  mediaLibraryManager->CreateAsset(displayName);
    MEDIA_INFO_LOG("createFile uri: %{public}s", uri.c_str());
    ASSERT_NE(uri, "");
    int32_t destFd = mediaLibraryManager->OpenAsset(uri, MEDIA_FILEMODE_READWRITE);
    ASSERT_GT(destFd, 0);
    int32_t resWrite = write(destFd, FILE_CONTENT_JPG, sizeof(FILE_CONTENT_JPG));
    ASSERT_NE(resWrite, -1);
    mediaLibraryManager->CloseAsset(uri, destFd);

    int32_t srcFd = mediaLibraryManager->OpenAsset(uri, MEDIA_FILEMODE_READWRITE);
    int64_t srcLen = lseek(srcFd, 0, SEEK_END);
    lseek(srcFd, 0, SEEK_SET);
    unsigned char *buf = static_cast<unsigned char*>(malloc(srcLen));
    ASSERT_NE(buf, nullptr);
    read(srcFd, buf, srcLen);
    free(buf);
    MEDIA_INFO_LOG("CreateFile:: end Create file: %{public}s", displayName.c_str());
}

/**
 * @tc.number    : MediaLibraryManager_GetBatchAstcs_test_006
 * @tc.name      : Query astc batch to see if error occurs
 * @tc.desc      : Input uri list to obtain astc bacth
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GetBatchAstcs_test_006, TestSize.Level1)
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
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GetAstc_test_007, TestSize.Level1)
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
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_test_008, TestSize.Level1)
{
    // read invalid uri
    EXPECT_EQ(mediaLibraryManager->ReadMovingPhotoVideo(""), -1);
    EXPECT_EQ(mediaLibraryManager->ReadMovingPhotoVideo("file://media/Photo"), -1);
    EXPECT_EQ(mediaLibraryManager->ReadMovingPhotoVideo("file://media/Photo/1"), -1);
    EXPECT_EQ(mediaLibraryManager->ReadMovingPhotoVideo("file://media/Photo/1/IMG_008/IMG_008.jpg"), -1);

    string displayName = "movingPhoto.jpg";
    string uri = mediaLibraryManager->CreateAsset(displayName);
    MEDIA_INFO_LOG("createFile uri: %{public}s", uri.c_str());
    ASSERT_NE(uri, "");

    int32_t fd = mediaLibraryManager->OpenAsset(uri, MEDIA_FILEMODE_READWRITE);
    EXPECT_GE(fd, 0);
    mediaLibraryManager->CloseAsset(uri, fd);

    int32_t rfd = mediaLibraryManager->ReadMovingPhotoVideo(uri);
    EXPECT_LE(rfd, 0);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_test_009, TestSize.Level1)
{
    // read invalid uri
    EXPECT_EQ(mediaLibraryManager->ReadPrivateMovingPhoto(""), -1);
    EXPECT_EQ(mediaLibraryManager->ReadPrivateMovingPhoto("file://media/Photo"), -1);
    EXPECT_EQ(mediaLibraryManager->ReadPrivateMovingPhoto("file://media/Photo/1"), -1);
    EXPECT_EQ(mediaLibraryManager->ReadPrivateMovingPhoto("file://media/Photo/1/IMG_009/IMG_009.jpg"), -1);

    string displayName = "movingPhoto.jpg";
    string uri = mediaLibraryManager->CreateAsset(displayName);
    MEDIA_INFO_LOG("createFile uri: %{public}s", uri.c_str());
    ASSERT_NE(uri, "");

    int32_t fd = mediaLibraryManager->OpenAsset(uri, MEDIA_FILEMODE_READWRITE);
    EXPECT_GE(fd, 0);
    mediaLibraryManager->CloseAsset(uri, fd);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CreatePhotoAssetProxy_test_001, TestSize.Level1)
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

    int32_t rowCount = 0;
    int32_t ret = resultSet->GetRowCount(rowCount);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(rowCount, 1);
    MEDIA_INFO_LOG("MediaLibraryManager_CreatePhotoAssetProxy_test_001 exit");
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CreatePhotoAssetProxy_test_002, TestSize.Level1)
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

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GetVideoFd_empty_share, TestSize.Level1)
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
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CreatePhotoAssetProxy_test_003, TestSize.Level1)
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

    // assert
    int32_t rowCount = 0;
    int32_t ret = resultSet->GetRowCount(rowCount);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(rowCount, 1);
    MEDIA_INFO_LOG("MediaLibraryManager_CreatePhotoAssetProxy_test_003 exit");
}
 
/**
 * @brief verify PhotoAssetProxy::UpdatePhotoBurst
 *
 * GIVEN ProtoProxy::IsCoverPhoto()
 * WHEN ProtoProxy::IsCoverPhoto() is true
 * THEN media_library.db#Photos#burst_cover_level is 1
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CreatePhotoAssetProxy_test_004, TestSize.Level1)
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

    // assert
    int32_t rowCount = 0;
    int32_t ret = resultSet->GetRowCount(rowCount);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(rowCount, 1);
    MEDIA_INFO_LOG("MediaLibraryManager_CreatePhotoAssetProxy_test_004 exit");
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_NotifyVideoSaveFinished_test, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_NotifyVideoSaveFinished_test enter");
    auto photoAssetProxy = mediaLibraryManager->CreatePhotoAssetProxy(CameraShotType::MOVING_PHOTO, 0, 0);
    ASSERT_NE(photoAssetProxy, nullptr);
    photoAssetProxy->NotifyVideoSaveFinished();
    MEDIA_INFO_LOG("MediaLibraryManager_NotifyVideoSaveFinished_test exit");
}

// Scenario1: Test when uriBatch is empty then GetBatchAstcs returns E_INVALID_URI.
HWTEST_F(MediaLibraryManagerTest, GetBatchAstcs_ShouldReturnE, TestSize.Level1)
{
    std::vector<std::string> uriBatch;
    std::vector<std::vector<uint8_t>> astcBatch;
    EXPECT_EQ(manager.GetBatchAstcs(uriBatch, astcBatch), E_INVALID_URI);
}

// Scenario2: Test when uriBatch contains ML_URI_OFFSET then GetBatchAstcs calls GetAstcsByOffset.
HWTEST_F(MediaLibraryManagerTest, GetBatchAstcs_ShouldCallGetAstcsByOffset_001, TestSize.Level1)
{
    std::vector<std::string> uriBatch = {"/media/ml/uri/offset/1"};
    std::vector<std::vector<uint8_t>> astcBatch;
    EXPECT_EQ(manager.GetBatchAstcs(uriBatch, astcBatch), E_INVALID_URI);
}

HWTEST_F(MediaLibraryManagerTest, GetBatchAstcs_ShouldCallGetAstcsByOffset_002, TestSize.Level1)
{
    std::vector<std::string> uriBatch = {"/media/ml/uri/offset/1/image?size=100x200"};
    std::vector<std::vector<uint8_t>> astcBatch;
    EXPECT_EQ(manager.GetBatchAstcs(uriBatch, astcBatch), E_INVALID_URI);
}

HWTEST_F(MediaLibraryManagerTest, GetBatchAstcs_ShouldCallGetAstcsByOffset_003, TestSize.Level1)
{
    std::vector<std::string> uriBatch = {"/media/ml/uri/offset/1/image?size=32x32"};
    std::vector<std::vector<uint8_t>> astcBatch;
    EXPECT_EQ(manager.GetBatchAstcs(uriBatch, astcBatch), E_INVALID_URI);
}

// Scenario3: Test when uriBatch does not contain ML_URI_OFFSET then GetBatchAstcs calls GetAstcsBatch.
HWTEST_F(MediaLibraryManagerTest, GetBatchAstcs_ShouldCallGetAstcsBatch_004, TestSize.Level1)
{
    std::vector<std::string> uriBatch = {"/media/ml/uri/1"};
    std::vector<std::vector<uint8_t>> astcBatch;
    EXPECT_EQ(manager.GetBatchAstcs(uriBatch, astcBatch), E_INVALID_URI);
}

HWTEST_F(MediaLibraryManagerTest, ReadMovingPhotoVideo_001, TestSize.Level1)
{
    string uri = "";
    EXPECT_EQ(manager.ReadMovingPhotoVideo(uri), -1);
}

HWTEST_F(MediaLibraryManagerTest, ReadMovingPhotoVideo_002, TestSize.Level1)
{
    string uri = "..;";
    EXPECT_EQ(manager.ReadMovingPhotoVideo(uri), -1);
}

HWTEST_F(MediaLibraryManagerTest, ReadMovingPhoto_001, TestSize.Level1)
{
    string uri = "";
    EXPECT_EQ(manager.ReadPrivateMovingPhoto(uri), -1);
}

HWTEST_F(MediaLibraryManagerTest, ReadMovingPhoto_002, TestSize.Level1)
{
    string uri = "..;";
    EXPECT_EQ(manager.ReadPrivateMovingPhoto(uri), -1);
}

HWTEST_F(MediaLibraryManagerTest, GetMovingPhotoImageUri_001, TestSize.Level1)
{
    std::string uri = "";
    std::string result = manager.GetMovingPhotoImageUri(uri);
    EXPECT_EQ(result, "");
}

HWTEST_F(MediaLibraryManagerTest, GetMovingPhotoImageUri_002, TestSize.Level1)
{
    std::string uri = "mediaLibraryUri";
    std::string result = manager.GetMovingPhotoImageUri(uri);
    EXPECT_EQ(result, uri);
}

HWTEST_F(MediaLibraryManagerTest, GetUrisByOldUris_001, TestSize.Level1)
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

HWTEST_F(MediaLibraryManagerTest, GetMovingPhotoDateModified_001, TestSize.Level1)
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
    ASSERT_GT(fd, 0);
    write(fd, FILE_CONTENT_JPG, sizeof(FILE_CONTENT_JPG));
    mediaLibraryManager->CloseAsset(assetUri, fd);

    int64_t movingPhotoDateModified = mediaLibraryManager->GetMovingPhotoDateModified(assetUri);
    EXPECT_EQ(movingPhotoDateModified != startTime, true);
    EXPECT_EQ(movingPhotoDateModified != MediaFileUtils::UTCTimeMilliSeconds(), true);
    MEDIA_INFO_LOG("GetMovingPhotoDateModified_001 exit");
}

HWTEST_F(MediaLibraryManagerTest, GetMovingPhotoDateModified_002, TestSize.Level1)
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
 * @tc.name      : 仅授权临时读权限
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_001 enter");
    uint64_t tokenId = 1;
    uint64_t srcTokenId = 2;

    vector<string> uris;
    for (int i = 0; i < 6; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        uris.push_back(uri);
    }
    vector<PhotoPermissionType> permissionTypes{
        PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO,
    };
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    auto ret =
        mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, tokenId, uris, permissionTypes, SensitiveType);
    ASSERT_EQ(ret, E_OK);

    vector<bool> resultSet;
    vector<uint32_t> permissionFlags{1, 2, 3, 1, 2, 3};
    ret = mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlags);
    EXPECT_EQ(ret, E_SUCCESS);

    vector<bool> expectSet{true, false, false, true, false, false};
    EXPECT_EQ(resultSet, expectSet);
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_001 exit");
}

/**
 * @tc.number    : MediaLibraryManager_GrantPhotoUriPermission_test_002
 * @tc.name      : 仅授权临时写权限
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_002 enter");
    uint64_t tokenId = 1;
    uint64_t srcTokenId = 2;

    vector<string> uris;
    for (int i = 0; i < 6; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        uris.push_back(uri);
    }
    vector<PhotoPermissionType> permissionTypes{
        PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO,
    };
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    auto ret =
        mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, tokenId, uris, permissionTypes, SensitiveType);
    ASSERT_EQ(ret, E_OK);

    vector<bool> resultSet;
    vector<uint32_t> permissionFlags{1, 2, 3, 1, 2, 3};
    ret = mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlags);
    EXPECT_EQ(ret, E_SUCCESS);

    vector<bool> expectSet(6, true);
    EXPECT_EQ(resultSet, expectSet);
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_002 exit");
}

/**
 * @tc.number    : MediaLibraryManager_GrantPhotoUriPermission_test_003
 * @tc.name      : 仅授权临时读写权限
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_test_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_003 enter");
    uint64_t tokenId = 1;
    uint64_t srcTokenId = 2;

    vector<string> uris;
    for (int i = 0; i < 6; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        uris.push_back(uri);
    }
    vector<PhotoPermissionType> permissionTypes{
        PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO,
    };
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    auto ret =
        mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, tokenId, uris, permissionTypes, SensitiveType);
    ASSERT_EQ(ret, E_OK);

    vector<bool> resultSet;
    vector<uint32_t> permissionFlags{1, 2, 3, 1, 2, 3};
    ret = mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlags);
    EXPECT_EQ(ret, E_SUCCESS);

    vector<bool> expectSet(6, true);
    EXPECT_EQ(resultSet, expectSet);
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_003 exit");
}

/**
 * @tc.number    : MediaLibraryManager_GrantPhotoUriPermission_test_004
 * @tc.name      : 仅授权持久读权限
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_test_004, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_004 enter");
    uint64_t tokenId = 1;
    uint64_t srcTokenId = 2;

    vector<string> uris;
    for (int i = 0; i < 6; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        uris.push_back(uri);
    }
    vector<PhotoPermissionType> permissionTypes{
        PhotoPermissionType::PERSIST_READ_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_READ_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_READ_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_READ_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_READ_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_READ_IMAGEVIDEO,
    };
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    auto ret =
        mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, tokenId, uris, permissionTypes, SensitiveType);
    ASSERT_EQ(ret, E_OK);

    vector<bool> resultSet;
    vector<uint32_t> permissionFlags{1, 2, 3, 1, 2, 3};
    ret = mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlags);
    EXPECT_EQ(ret, E_SUCCESS);

    vector<bool> expectSet{true, false, false, true, false, false};
    EXPECT_EQ(resultSet, expectSet);
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_004 exit");
}

/**
 * @tc.number    : MediaLibraryManager_GrantPhotoUriPermission_test_005
 * @tc.name      : 仅授权持久写权限
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_test_005, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_005 enter");
    uint64_t tokenId = 1;
    uint64_t srcTokenId = 2;

    vector<string> uris;
    for (int i = 0; i < 6; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        uris.push_back(uri);
    }
    vector<PhotoPermissionType> permissionTypes{
        PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO,
    };
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    auto ret =
        mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, tokenId, uris, permissionTypes, SensitiveType);
    ASSERT_EQ(ret, E_OK);

    vector<bool> resultSet;
    vector<uint32_t> permissionFlags{1, 2, 3, 1, 2, 3};
    ret = mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlags);
    EXPECT_EQ(ret, E_SUCCESS);

    vector<bool> expectSet{false, true, false, false, true, false};
    EXPECT_EQ(resultSet, expectSet);
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_005 exit");
}

/**
 * @tc.number    : MediaLibraryManager_GrantPhotoUriPermission_test_006
 * @tc.name      : 仅授权持久读写权限
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_test_006, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_006 enter");
    uint64_t tokenId = 1;
    uint64_t srcTokenId = 2;

    vector<string> uris;
    for (int i = 0; i < 6; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        uris.push_back(uri);
    }
    vector<PhotoPermissionType> permissionTypes{
        PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO,
    };
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    auto ret =
        mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, tokenId, uris, permissionTypes, SensitiveType);
    ASSERT_EQ(ret, E_OK);

    vector<bool> resultSet;
    vector<uint32_t> permissionFlags{1, 2, 3, 1, 2, 3};
    ret = mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlags);
    EXPECT_EQ(ret, E_SUCCESS);

    vector<bool> expectSet(6, true);
    EXPECT_EQ(resultSet, expectSet);
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_006 exit");
}

/**
 * @tc.number    : MediaLibraryManager_GrantPhotoUriPermission_test_007
 * @tc.name      : 不同uri授权不同的持久权限
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_test_007, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_007 enter");
    uint64_t tokenId = 1;
    uint64_t srcTokenId = 2;

    vector<string> uris;
    for (int i = 0; i < 6; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        uris.push_back(uri);
    }
    vector<PhotoPermissionType> permissionTypes{
        PhotoPermissionType::PERSIST_READ_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO,
        PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_READ_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO,
        PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO,
    };
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    auto ret =
        mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, tokenId, uris, permissionTypes, SensitiveType);
    ASSERT_EQ(ret, E_OK);

    vector<bool> resultSet;
    vector<uint32_t> permissionFlags(6, 2);
    ret = mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlags);
    EXPECT_EQ(ret, E_SUCCESS);

    vector<bool> expectSet{false, true, true, false, true, true};
    EXPECT_EQ(resultSet, expectSet);
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_007 exit");
}

/**
 * @tc.number    : MediaLibraryManager_GrantPhotoUriPermission_test_008
 * @tc.name      : 异常场景：uri列表中存储重复uri，授权不同的权限
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_test_008, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_008 enter");
    uint64_t tokenId = 1;
    uint64_t srcTokenId = 2;

    vector<string> uris;
    for (int i = 0; i < 6; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        uris.push_back(uri);
        uris.push_back(uri);
    }
    vector<PhotoPermissionType> permissionTypes{
        PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_READ_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_READ_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO,
        PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO,
    };
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    auto ret =
        mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, tokenId, uris, permissionTypes, SensitiveType);
    ASSERT_EQ(ret, E_OK);

    vector<bool> resultSet;
    vector<uint32_t> permissionFlags{3, 2, 1, 3, 2, 1, 3, 2, 1, 3, 2, 1};
    ret = mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlags);
    EXPECT_EQ(ret, E_SUCCESS);

    vector<bool> expectSet{false, false, true, true, true, true, false, false, true, true, true, true};
    EXPECT_EQ(resultSet, expectSet);
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_008 exit");
}

/**
 * @tc.number    : MediaLibraryManager_GrantPhotoUriPermission_test_009
 * @tc.name      : 异常场景：uri列表中存储重复uri，授权相同的权限
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_test_009, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_009 enter");
    uint64_t tokenId = 1;
    uint64_t srcTokenId = 2;

    vector<string> uris;
    for (int i = 0; i < 6; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        uris.push_back(uri);
        uris.push_back(uri);
    }
    vector<PhotoPermissionType> permissionTypes{
        PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_READ_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_READ_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO,
        PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO,
    };
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    auto ret =
        mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, tokenId, uris, permissionTypes, SensitiveType);
    ASSERT_EQ(ret, E_OK);

    vector<bool> resultSet;
    vector<uint32_t> permissionFlags{3, 2, 1, 3, 2, 3, 3, 2, 1, 3, 2, 1};
    ret = mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlags);
    EXPECT_EQ(ret, E_SUCCESS);

    vector<bool> expectSet{false, false, true, false, true, true, true, true, false, false, true, true};
    EXPECT_EQ(resultSet, expectSet);
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_009 exit");
}

/**
 * @tc.number    : MediaLibraryManager_GrantPhotoUriPermission_test_010
 * @tc.name      :异常场景：授权PERSIST_READWRITE_IMAGEVIDEO权限
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_test_010, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_010 enter");
    uint64_t tokenId = 1;
    uint64_t srcTokenId = 2;

    vector<string> uris;
    for (int i = 0; i < 6; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        uris.push_back(uri);
    }
    vector<PhotoPermissionType> permissionTypes{
        PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_READ_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO,
    };
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    auto ret =
        mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, tokenId, uris, permissionTypes, SensitiveType);
    ASSERT_EQ(ret, E_ERR);

    vector<bool> resultSet;
    vector<uint32_t> permissionFlags(6, 1);
    ret = mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlags);
    EXPECT_EQ(ret, E_SUCCESS);

    vector<bool> expectSet(6, false);
    EXPECT_EQ(resultSet, expectSet);

    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_010 exit");
}

/**
 * @tc.number    : MediaLibraryManager_GrantPhotoUriPermission_test_011
 * @tc.name      :异常场景：授权uri列表和权限列表长度不等
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_test_011, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_011 enter");
    uint64_t tokenId = 1;
    uint64_t srcTokenId = 2;

    vector<string> uris;
    for (int i = 0; i < 6; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        uris.push_back(uri);
    }

    vector<PhotoPermissionType> permissionTypes{
        PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_READ_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO,
        PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO,
    };
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    auto ret =
        mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, tokenId, uris, permissionTypes, SensitiveType);
    ASSERT_EQ(ret, E_ERR);

    vector<bool> resultSet;
    vector<uint32_t> permissionFlags(6, 1);
    ret = mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlags);
    EXPECT_EQ(ret, E_SUCCESS);

    vector<bool> expectSet(6, false);
    EXPECT_EQ(resultSet, expectSet);

    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_011 exit");
}

/**
 * @tc.number    : MediaLibraryManager_GrantPhotoUriPermission_test_012
 * @tc.name      :异常场景：授权uri列表中存在格式错误的uri
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_test_012, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_012 enter");
    uint64_t tokenId = 1;
    uint64_t srcTokenId = 2;

    vector<string> uris;
    for (int i = 0; i < 5; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        uris.push_back(uri);
    }
    vector<string> checkUris = uris;
    uris.push_back("test_with_bad_uri.jpg");

    vector<PhotoPermissionType> permissionTypes{
        PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_READ_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO,
        PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO,
    };
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    auto ret =
        mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, tokenId, uris, permissionTypes, SensitiveType);
    ASSERT_EQ(ret, E_ERR);

    vector<bool> resultSet;
    vector<uint32_t> permissionFlags(5, 1);
    ret = mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, checkUris, resultSet, permissionFlags);
    EXPECT_EQ(ret, E_SUCCESS);

    vector<bool> expectSet(5, false);
    EXPECT_EQ(resultSet, expectSet);

    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_012 exit");
}

/**
 * @tc.number    : MediaLibraryManager_GrantPhotoUriPermission_test_013
 * @tc.name      :异常场景：授权uri列表的长度超过限制
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GrantPhotoUriPermission_test_013, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_013 enter");
    uint64_t tokenId = 1;
    uint64_t srcTokenId = 2;

    vector<string> uris;
    for (int i = 0; i < 1001; i++) {
        string uri = "test_uris_for_exceeds_limit_size.jpg";
        uris.push_back(uri);
    }

    vector<PhotoPermissionType> permissionTypes(1001, PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO);
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    auto ret =
        mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, tokenId, uris, permissionTypes, SensitiveType);
    EXPECT_EQ(ret, E_ERR);

    MEDIA_INFO_LOG("MediaLibraryManager_GrantPhotoUriPermission_test_013 exit");
}

/**
 * @tc.number    : MediaLibraryManager_CheckPhotoUriPermission_test_001
 * @tc.name      : 仅查询读权限，应用无读权限
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CheckPhotoUriPermission_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_001 enter");
    uint64_t tokenId = 1;
    uint64_t srcTokenId = 2;
    uint64_t targetTokenId = 3;
    vector<string> uris;
    for (int i = 0; i < 6; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        uris.push_back(uri);
    }
    vector<PhotoPermissionType> permissionTypes{
        PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_READ_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO,
    };
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    auto ret = mediaLibraryExtendManager->GrantPhotoUriPermission(
        srcTokenId, targetTokenId, uris, permissionTypes, SensitiveType);
    ASSERT_EQ(ret, E_OK);

    vector<bool> resultSet;
    vector<uint32_t> permissionFlags(6, 1);
    ret = mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlags);
    EXPECT_EQ(ret, E_SUCCESS);

    vector<bool> expectSet(6, false);
    EXPECT_EQ(resultSet, expectSet);
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_001 exit");
}

/**
 * @tc.number    : MediaLibraryManager_CheckPhotoUriPermission_test_002
 * @tc.name      : 仅查询写权限，应用无写权限
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CheckPhotoUriPermission_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_002 enter");
    uint64_t tokenId = 1;
    uint64_t srcTokenId = 2;
    uint64_t targetTokenId = 3;
    vector<string> uris;
    for (int i = 0; i < 6; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        uris.push_back(uri);
    }
    vector<PhotoPermissionType> permissionTypes{
        PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_READ_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO,
    };
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    auto ret = mediaLibraryExtendManager->GrantPhotoUriPermission(
        srcTokenId, targetTokenId, uris, permissionTypes, SensitiveType);
    ASSERT_EQ(ret, E_OK);

    vector<bool> resultSet;
    vector<uint32_t> permissionFlags(6, 2);
    ret = mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlags);
    EXPECT_EQ(ret, E_SUCCESS);

    vector<bool> expectSet(6, false);
    EXPECT_EQ(resultSet, expectSet);
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_002 exit");
}

/**
 * @tc.number    : MediaLibraryManager_CheckPhotoUriPermission_test_003
 * @tc.name      : 仅查询读写权限，应用无读写权限
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CheckPhotoUriPermission_test_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_003 enter");
    uint64_t tokenId = 1;
    uint64_t srcTokenId = 2;
    uint64_t targetTokenId = 3;
    vector<string> uris;
    for (int i = 0; i < 6; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        uris.push_back(uri);
    }
    vector<PhotoPermissionType> permissionTypes{
        PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_READ_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO,
    };
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    auto ret = mediaLibraryExtendManager->GrantPhotoUriPermission(
        srcTokenId, targetTokenId, uris, permissionTypes, SensitiveType);
    ASSERT_EQ(ret, E_OK);
    vector<bool> resultSet;
    vector<uint32_t> permissionFlags(6, 3);
    ret = mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlags);
    EXPECT_EQ(ret, E_SUCCESS);

    vector<bool> expectSet(6, false);
    EXPECT_EQ(resultSet, expectSet);
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_003 exit");
}

/**
 * @tc.number    : MediaLibraryManager_CheckPhotoUriPermission_test_004
 * @tc.name      : 仅查询读权限，应用有读权限
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CheckPhotoUriPermission_test_004, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_004 enter");
    // erase mock token
    hapToken = nullptr;
    SetSelfTokenID(MediaLibraryMockTokenUtils::GetShellToken());
    MediaLibraryMockTokenUtils::ResetToken();

    std::vector<std::string> perms = {
        "ohos.permission.WRITE_MEDIA",
        "ohos.permission.READ_IMAGEVIDEO",
        "ohos.permission.WRITE_IMAGEVIDEO",
        "ohos.permission.SHORT_TERM_WRITE_IMAGEVIDEO",
    };

    uint64_t shellToken = IPCSkeleton::GetSelfTokenID();
    MediaLibraryMockTokenUtils::RestoreShellToken(shellToken);
    mockToken(perms, hapToken);

    vector<string> uris;
    for (int i = 0; i < 6; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        uris.push_back(uri);
    }

    vector<bool> resultSet;
    vector<uint32_t> permissionFlags(6, 1);
    auto ret = mediaLibraryExtendManager->CheckPhotoUriPermission(IPCSkeleton::GetSelfTokenID(),
        uris, resultSet, permissionFlags);
    EXPECT_EQ(ret, E_SUCCESS);

    vector<bool> expectSet(6, true);
    EXPECT_EQ(resultSet, expectSet);
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_004 exit");
}

/**
 * @tc.number    : MediaLibraryManager_CheckPhotoUriPermission_test_005
 * @tc.name      : 仅查询写权限，应用有写权限
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CheckPhotoUriPermission_test_005, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_005 enter");
    // erase mock token
    hapToken = nullptr;
    SetSelfTokenID(MediaLibraryMockTokenUtils::GetShellToken());
    MediaLibraryMockTokenUtils::ResetToken();

    std::vector<std::string> perms = { "ohos.permission.WRITE_IMAGEVIDEO" };
    uint64_t shellToken = IPCSkeleton::GetSelfTokenID();
    MediaLibraryMockTokenUtils::RestoreShellToken(shellToken);
    mockToken(perms, hapToken);

    vector<string> uris;
    for (int i = 0; i < 6; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        uris.push_back(uri);
    }

    vector<bool> resultSet;
    vector<uint32_t> permissionFlags(6, 2);
    auto ret = mediaLibraryExtendManager->CheckPhotoUriPermission(IPCSkeleton::GetSelfTokenID(),
        uris, resultSet, permissionFlags);
    EXPECT_EQ(ret, E_SUCCESS);

    vector<bool> expectSet(6, true);
    EXPECT_EQ(resultSet, expectSet);
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_005 exit");
}

/**
 * @tc.number    : MediaLibraryManager_CheckPhotoUriPermission_test_006
 * @tc.name      : 仅查询读写权限，应用有读写权限
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CheckPhotoUriPermission_test_006, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_006 enter");
    // erase mock token
    hapToken = nullptr;
    SetSelfTokenID(MediaLibraryMockTokenUtils::GetShellToken());
    MediaLibraryMockTokenUtils::ResetToken();

    std::vector<std::string> perms = {
        "ohos.permission.READ_IMAGEVIDEO",
        "ohos.permission.WRITE_IMAGEVIDEO",
    };

    uint64_t shellToken = IPCSkeleton::GetSelfTokenID();
    MediaLibraryMockTokenUtils::RestoreShellToken(shellToken);
    mockToken(perms, hapToken);

    vector<string> uris;
    for (int i = 0; i < 6; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        uris.push_back(uri);
    }

    vector<bool> resultSet;
    vector<uint32_t> permissionFlags(6, 3);
    auto ret = mediaLibraryExtendManager->CheckPhotoUriPermission(IPCSkeleton::GetSelfTokenID(),
        uris, resultSet, permissionFlags);
    EXPECT_EQ(ret, E_SUCCESS);

    vector<bool> expectSet(6, true);
    EXPECT_EQ(resultSet, expectSet);
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_006 exit");
}

/**
 * @tc.number    : MediaLibraryManager_CheckPhotoUriPermission_test_007
 * @tc.name      : 混合查询，uri列表存在读，写，读写权限查询，应用无权限
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CheckPhotoUriPermission_test_007, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_007 enter");
    uint64_t tokenId = 1;
    uint64_t srcTokenId = 2;
    uint64_t targetTokenId = 3;
    vector<string> uris;
    for (int i = 0; i < 6; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        uris.push_back(uri);
    }
    vector<PhotoPermissionType> permissionTypes{
        PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_READ_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO,
    };
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    auto ret = mediaLibraryExtendManager->GrantPhotoUriPermission(
        srcTokenId, targetTokenId, uris, permissionTypes, SensitiveType);
    ASSERT_EQ(ret, E_OK);

    vector<bool> resultSet;
    vector<uint32_t> permissionFlags{1, 2, 3, 1, 2, 3};
    ret = mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlags);
    EXPECT_EQ(ret, E_SUCCESS);

    vector<bool> expectSet(6, false);
    EXPECT_EQ(resultSet, expectSet);
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_007 exit");
}

/**
 * @tc.number    : MediaLibraryManager_CheckPhotoUriPermission_test_008
 * @tc.name      : 混合查询，uri列表存在读，写，读写权限查询，应用写权限
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CheckPhotoUriPermission_test_008, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_008 enter");
    // erase mock token
    hapToken = nullptr;
    SetSelfTokenID(MediaLibraryMockTokenUtils::GetShellToken());
    MediaLibraryMockTokenUtils::ResetToken();

    std::vector<std::string> perms = { "ohos.permission.WRITE_IMAGEVIDEO" };
    uint64_t shellToken = IPCSkeleton::GetSelfTokenID();
    MediaLibraryMockTokenUtils::RestoreShellToken(shellToken);
    mockToken(perms, hapToken);

    vector<string> uris;
    for (int i = 0; i < 6; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        uris.push_back(uri);
    }

    vector<bool> resultSet;
    vector<uint32_t> permissionFlags{1, 2, 3, 1, 2, 3};
    auto ret = mediaLibraryExtendManager->CheckPhotoUriPermission(IPCSkeleton::GetSelfTokenID(),
        uris, resultSet, permissionFlags);
    EXPECT_EQ(ret, E_SUCCESS);

    vector<bool> expectSet(6, true);
    EXPECT_EQ(resultSet, expectSet);
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_008 exit");
}

/**
 * @tc.number    : MediaLibraryManager_CheckPhotoUriPermission_test_009
 * @tc.name      : 混合查询，uri列表存在读，写，读写权限查询，应用读写权限
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CheckPhotoUriPermission_test_009, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_009 enter");
    hapToken = nullptr;
    SetSelfTokenID(MediaLibraryMockTokenUtils::GetShellToken());
    MediaLibraryMockTokenUtils::ResetToken();

    std::vector<std::string> perms = {
        "ohos.permission.READ_IMAGEVIDEO",
        "ohos.permission.WRITE_IMAGEVIDEO",
    };

    uint64_t shellToken = IPCSkeleton::GetSelfTokenID();
    MediaLibraryMockTokenUtils::RestoreShellToken(shellToken);
    mockToken(perms, hapToken);

    vector<string> uris;
    for (int i = 0; i < 6; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        uris.push_back(uri);
    }

    vector<bool> resultSet;
    vector<uint32_t> permissionFlags{1, 2, 3, 1, 2, 3};
    auto ret = mediaLibraryExtendManager->CheckPhotoUriPermission(IPCSkeleton::GetSelfTokenID(),
        uris, resultSet, permissionFlags);
    EXPECT_EQ(ret, E_SUCCESS);

    vector<bool> expectSet(6, true);
    EXPECT_EQ(resultSet, expectSet);
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_009 exit");
}

/**
 * @tc.number    : MediaLibraryManager_CheckPhotoUriPermission_test_010
 * @tc.name      : 异常场景，uri列表存在重复的uri，uri列表存在读，写，读写权限查询，应用无权限
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CheckPhotoUriPermission_test_010, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_010 enter");
    uint64_t tokenId = 1;
    uint64_t srcTokenId = 2;

    vector<string> grantUris;
    vector<string> checkUris;
    for (int i = 0; i < 6; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        grantUris.insert(grantUris.end(), 2, uri);
        checkUris.push_back(uri);
    }
    vector<PhotoPermissionType> permissionTypes{
        PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_READ_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_READ_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO,
    };
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    auto ret = mediaLibraryExtendManager->GrantPhotoUriPermission(
        srcTokenId, tokenId, grantUris, permissionTypes, SensitiveType);
    ASSERT_EQ(ret, E_OK);

    vector<bool> resultSet;
    vector<uint32_t> permissionFlags{3, 2, 1, 3, 2, 1};
    ret = mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, checkUris, resultSet, permissionFlags);
    EXPECT_EQ(ret, E_SUCCESS);

    vector<bool> expectSet{false, true, true, false, true, true};
    EXPECT_EQ(resultSet, expectSet);
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_010 exit");
}

/**
 * @tc.number    : MediaLibraryManager_CheckPhotoUriPermission_test_011
 * @tc.name      : 异常场景，uri列表的长度超过限制，读权限查询，应用有读权限
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CheckPhotoUriPermission_test_011, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_011 enter");
    hapToken = nullptr;
    SetSelfTokenID(MediaLibraryMockTokenUtils::GetShellToken());
    MediaLibraryMockTokenUtils::ResetToken();

    std::vector<std::string> perms = { "ohos.permission.READ_IMAGEVIDEO" };
    uint64_t shellToken = IPCSkeleton::GetSelfTokenID();
    MediaLibraryMockTokenUtils::RestoreShellToken(shellToken);
    mockToken(perms, hapToken);

    vector<string> uris;
    for (int i = 0; i < 1001; i++) {
        string uri = "test_uris_for_exceeds_limit_size.jpg";
        uris.push_back(uri);
    }

    vector<bool> resultSet;
    vector<uint32_t> permissionFlags(1001, 1);
    auto ret = mediaLibraryExtendManager->CheckPhotoUriPermission(IPCSkeleton::GetSelfTokenID(),
        uris, resultSet, permissionFlags);
    EXPECT_EQ(ret, E_ERR);

    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_011 exit");
}

/**
 * @tc.number    : MediaLibraryManager_CheckPhotoUriPermission_test_012
 * @tc.name      : 异常场景：查询uri列表和权限列表长度不等
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CheckPhotoUriPermission_test_012, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_012 enter");
    uint64_t tokenId = 1;
    vector<string> uris;
    for (int i = 0; i < 6; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        uris.push_back(uri);
    }

    vector<bool> resultSet;
    vector<uint32_t> permissionFlags(7, 1);
    auto ret = mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlags);
    EXPECT_EQ(ret, E_ERR);
    EXPECT_EQ(resultSet.size(), 0);

    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_012 exit");
}

/**
 * @tc.number    : MediaLibraryManager_CheckPhotoUriPermission_test_013
 * @tc.name      : 异常场景：查询uri列表中存在格式错误的uri
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CheckPhotoUriPermission_test_013, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_013 enter");
    uint64_t tokenId = 1;
    vector<string> uris;
    for (int i = 0; i < 5; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        uris.push_back(uri);
    }
    uris.push_back("test_with_bad_uri.jpg");

    vector<bool> resultSet;
    vector<uint32_t> permissionFlags(6, 1);
    auto ret = mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlags);
    EXPECT_EQ(ret, E_ERR);
    EXPECT_EQ(resultSet.size(), 0);

    MEDIA_INFO_LOG("MediaLibraryManager_CheckPhotoUriPermission_test_013 exit");
}

/**
 * @tc.number    : MediaLibraryExtendManager_CancelPhotoUriPermission_test_001
 * @tc.name      : 正常cancel临时读权限
 * @tc.desc      : cancel permission success
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryExtendManager_CancelPhotoUriPermission_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryExtendManager_CancelPhotoUriPermission_test_001 enter");
    int src_tokenId = 1;
    int target_tokenId = 2;
    vector<string> uris;
    vector<PhotoPermissionType> permissionTypes;
    vector<OperationMode> modes;
    for (int i = 0; i < 5; i++) {
        auto uri = CreatePhotoAsset("test.mp4");
        uris.push_back(uri);
        permissionTypes.push_back(PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO);
        modes.push_back(OperationMode::READ_MODE);
    }
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    int32_t ret = mediaLibraryExtendManager->GrantPhotoUriPermission(
        src_tokenId, target_tokenId, uris, permissionTypes, SensitiveType);
    EXPECT_EQ(ret, 0);
    ret = mediaLibraryExtendManager->CancelPhotoUriPermission(src_tokenId, target_tokenId, uris, false, modes);
    EXPECT_EQ(ret, 0);
    MEDIA_INFO_LOG("MediaLibraryExtendManager_CancelPhotoUriPermission_test_001 exit");
}

/**
 * @tc.number    : MediaLibraryExtendManager_CancelPhotoUriPermission_test_002
 * @tc.name      : 正常cancel永久读权限
 * @tc.desc      : cancel permission success
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryExtendManager_CancelPhotoUriPermission_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryExtendManager_CancelPhotoUriPermission_test_002 enter");
    int src_tokenId = 1;
    int target_tokenId = 2;
    vector<string> uris;
    vector<PhotoPermissionType> permissionTypes;
    vector<OperationMode> modes;
    for (int i = 0; i < 5; i++) {
        auto uri = CreatePhotoAsset("test.mp4");
        uris.push_back(uri);
        permissionTypes.push_back(PhotoPermissionType::PERSIST_READ_IMAGEVIDEO);
        modes.push_back(OperationMode::READ_MODE);
    }
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    int32_t ret = mediaLibraryExtendManager->GrantPhotoUriPermission(
        src_tokenId, target_tokenId, uris, permissionTypes, SensitiveType);
    EXPECT_EQ(ret, 0);
    ret = mediaLibraryExtendManager->CancelPhotoUriPermission(src_tokenId, target_tokenId, uris, true, modes);
    EXPECT_EQ(ret, 0);
    MEDIA_INFO_LOG("MediaLibraryExtendManager_CancelPhotoUriPermission_test_002 exit");
}

/**
 * @tc.number    : MediaLibraryExtendManager_CancelPhotoUriPermission_test_003
 * @tc.name      : 正常cancel永久写权限
 * @tc.desc      : cancel permission
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryExtendManager_CancelPhotoUriPermission_test_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryExtendManager_CancelPhotoUriPermission_test_003 enter");
    int src_tokenId = 3;
    int target_tokenId = 2;
    vector<string> uris;
    vector<string> inColumn;
    vector<OperationMode> modes;
    vector<PhotoPermissionType> permissionTypes;
    for (int i = 0; i < 5; i++) {
        auto uri = CreatePhotoAsset("test.mp4");
        uris.push_back(uri);
        inColumn.push_back(MediaFileUtils::GetIdFromUri(uri));
        modes.push_back(OperationMode::WRITE_MODE);
        permissionTypes.push_back(PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO);
    }
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    int32_t ret = mediaLibraryExtendManager->GrantPhotoUriPermission(src_tokenId, target_tokenId, uris,
        permissionTypes, SensitiveType);
    EXPECT_EQ(ret, 0);
    ret = mediaLibraryExtendManager->CancelPhotoUriPermission(src_tokenId, target_tokenId, uris,
        true, modes);
    EXPECT_EQ(ret, 0);
    MEDIA_INFO_LOG("MediaLibraryExtendManager_CancelPhotoUriPermission_test_003 exit");
}

/**
 * @tc.number    : MediaLibraryExtendManager_CancelPhotoUriPermission_test_004
 * @tc.name      : 正常cancel临时写权限
 * @tc.desc      : 1.授权一批uri临时读权限 2.cancel永久写权限
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryExtendManager_CancelPhotoUriPermission_test_004, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryExtendManager_CancelPhotoUriPermission_test_004 enter");
    int src_tokenId = 3;
    int target_tokenId = 2;
    vector<string> uris;
    vector<string> inColumn;
    vector<OperationMode> modes;
    vector<PhotoPermissionType> permissionTypes;
    for (int i = 0; i < 5; i++) {
        auto uri = CreatePhotoAsset("test.mp4");
        uris.push_back(uri);
        inColumn.push_back(MediaFileUtils::GetIdFromUri(uri));
        modes.push_back(OperationMode::WRITE_MODE);
        permissionTypes.push_back(PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO);
    }
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    int32_t ret = mediaLibraryExtendManager->GrantPhotoUriPermission(src_tokenId, target_tokenId, uris,
        permissionTypes, SensitiveType);
    EXPECT_EQ(ret, 0);
    ret = mediaLibraryExtendManager->CancelPhotoUriPermission(src_tokenId, target_tokenId, uris,
        false, modes);
    EXPECT_EQ(ret, 0);
    MEDIA_INFO_LOG("MediaLibraryExtendManager_CancelPhotoUriPermission_test_004 exit");
}

/**
 * @tc.number    : MediaLibraryExtendManager_CancelPhotoUriPermission_test_005
 * @tc.name      : 读权限取消
 * @tc.desc      : 1.授权一批uri永久读权限，授权临时读权限
                   2.cancel永久写权限
                   3.check写权限，预期无权限
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryExtendManager_CancelPhotoUriPermission_test_005, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryExtendManager_CancelPhotoUriPermission_test_005 enter");
    uint64_t tokenId = 1;
    uint64_t srcTokenId = 2;

    vector<string> uris;
    for (int i = 0; i < 6; i++) {
        auto uri = CreatePhotoAsset("test.mp4");
        uris.push_back(uri);
    }
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    vector<PhotoPermissionType> persistRead(6, PhotoPermissionType::PERSIST_READ_IMAGEVIDEO);
    auto ret =
        mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, tokenId, uris, persistRead, SensitiveType);
    ASSERT_EQ(ret, E_SUCCESS);

    vector<PhotoPermissionType> tempRead(6, PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO);
    ret = mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, tokenId, uris, tempRead, SensitiveType);
    ASSERT_EQ(ret, E_SUCCESS);

    vector<OperationMode> modes(6, OperationMode::WRITE_MODE);
    ret = mediaLibraryExtendManager->CancelPhotoUriPermission(srcTokenId, tokenId, uris, true, modes);
    EXPECT_EQ(ret, E_SUCCESS);

    vector<bool> resultSet;
    vector<uint32_t> permissionFlags(6, 2);
    ret = mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlags);
    EXPECT_EQ(ret, E_SUCCESS);

    vector<bool> expectSet(6, false);
    EXPECT_EQ(resultSet, expectSet);
    MEDIA_INFO_LOG("MediaLibraryExtendManager_CancelPhotoUriPermission_test_005 exit");
}

/**
 * @tc.number    : MediaLibraryExtendManager_CancelPhotoUriPermission_test_006
 * @tc.name      : 写权限取消
 * @tc.desc      : 1.授权一批uri永久写权限，授权临时写权限
                   2.cancel永久写权限
                   3.check写权限，预期无权限
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryExtendManager_CancelPhotoUriPermission_test_006, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryExtendManager_CancelPhotoUriPermission_test_006 enter");
    uint64_t tokenId = 1;
    uint64_t srcTokenId = 2;

    vector<string> uris;
    for (int i = 0; i < 6; i++) {
        auto uri = CreatePhotoAsset("test.mp4");
        uris.push_back(uri);
    }
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    vector<PhotoPermissionType> persistRead(6, PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO);
    auto ret =
        mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, tokenId, uris, persistRead, SensitiveType);
    ASSERT_EQ(ret, E_SUCCESS);

    vector<PhotoPermissionType> tempRead(6, PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO);
    ret = mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, tokenId, uris, tempRead, SensitiveType);
    ASSERT_EQ(ret, E_SUCCESS);

    vector<OperationMode> modes(6, OperationMode::WRITE_MODE);
    ret = mediaLibraryExtendManager->CancelPhotoUriPermission(srcTokenId, tokenId, uris, true, modes);
    EXPECT_EQ(ret, E_SUCCESS);

    vector<bool> resultSet;
    vector<uint32_t> permissionFlags(6, 2);
    ret = mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet, permissionFlags);
    EXPECT_EQ(ret, E_SUCCESS);

    vector<bool> expectSet(6, false);
    EXPECT_EQ(resultSet, expectSet);
    MEDIA_INFO_LOG("MediaLibraryExtendManager_CancelPhotoUriPermission_test_006 exit");
}

/**
 * @tc.number    : MediaLibraryExtendManager_CancelPhotoUriPermission_test_007
 * @tc.name      : 读写权限取消
 * @tc.desc      : 	1.授权一批uri永久读写权限
                    2.cancel永久读权限
                    3.check读权限，预期无权限
                    4.cancel永久写权限
                    5.check写权限，预期无权限
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryExtendManager_CancelPhotoUriPermission_test_007, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryExtendManager_CancelPhotoUriPermission_test_007 enter");
    uint64_t tokenId = 1;
    uint64_t srcTokenId = 2;

    vector<string> uris;
    for (int i = 0; i < 6; i++) {
        auto uri = CreatePhotoAsset("test.mp4");
        uris.push_back(uri);
    }
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    vector<PhotoPermissionType> persistRead(6, PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO);
    auto ret =
        mediaLibraryExtendManager->GrantPhotoUriPermission(srcTokenId, tokenId, uris, persistRead, SensitiveType);
    ASSERT_EQ(ret, E_SUCCESS);

    vector<OperationMode> readModes(6, OperationMode::READ_MODE);
    ret = mediaLibraryExtendManager->CancelPhotoUriPermission(srcTokenId, tokenId, uris, true, readModes);
    EXPECT_EQ(ret, E_SUCCESS);

    vector<bool> resultSet1;
    vector<uint32_t> permissionFlags1(6, 1);
    ret = mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet1, permissionFlags1);
    EXPECT_EQ(ret, E_SUCCESS);

    vector<bool> expectSet1(6, false);
    EXPECT_EQ(resultSet1, expectSet1);

    vector<OperationMode> writeModes(6, OperationMode::WRITE_MODE);
    ret = mediaLibraryExtendManager->CancelPhotoUriPermission(srcTokenId, tokenId, uris, true, writeModes);
    EXPECT_EQ(ret, E_SUCCESS);

    vector<bool> resultSet2;
    vector<uint32_t> permissionFlags2(6, 2);
    ret = mediaLibraryExtendManager->CheckPhotoUriPermission(tokenId, uris, resultSet2, permissionFlags2);
    EXPECT_EQ(ret, E_SUCCESS);

    vector<bool> expectSet2(6, false);
    EXPECT_EQ(resultSet2, expectSet2);
    MEDIA_INFO_LOG("MediaLibraryExtendManager_CancelPhotoUriPermission_test_007 exit");
}

/**
 * @tc.number    : MediaLibraryExtendManager_CancelPhotoUriPermission_test_008
 * @tc.name      : 异常场景，uris传入空列表
 * @tc.desc      : cancel permission fail
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryExtendManager_CancelPhotoUriPermission_test_008, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryExtendManager_CancelPhotoUriPermission_test_008 enter");
    int src_tokenId = 3;
    int target_tokenId = 2;
    vector<string> uris;
    int32_t ret = mediaLibraryExtendManager->CancelPhotoUriPermission(src_tokenId, target_tokenId, uris);
    EXPECT_EQ(ret, E_ERR);
    MEDIA_INFO_LOG("MediaLibraryExtendManager_CancelPhotoUriPermission_test_008 exit");
}

/**
 * @tc.number    : MediaLibraryExtendManager_CancelPhotoUriPermission_test_009
 * @tc.name      : 异常场景，uris传入长度超过限制
 * @tc.desc      : cancel permission fail
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryExtendManager_CancelPhotoUriPermission_test_009, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryExtendManager_CancelPhotoUriPermission_test_009 enter");
    int src_tokenId = 3;
    int target_tokenId = 2;
    vector<string> uris;
    for (int i = 0; i < 1001; i++) {
        string uri = "test_uris_for_exceeds_limit_size.mp4";
        uris.push_back(uri);
    }
    int32_t ret = mediaLibraryExtendManager->CancelPhotoUriPermission(src_tokenId, target_tokenId, uris);
    EXPECT_EQ(ret, E_ERR);
    MEDIA_INFO_LOG("MediaLibraryExtendManager_CancelPhotoUriPermission_test_009 exit");
}

HWTEST_F(MediaLibraryManagerTest, GetUriFromFilePath_001, TestSize.Level1)
{
    string filePath;
    string file = "/path/to/file";
    Uri fileUri(file);
    string userId;
    auto result = manager.GetUriFromFilePath(filePath, fileUri, userId);
    EXPECT_EQ(result, E_INVALID_PATH);
}

HWTEST_F(MediaLibraryManagerTest, GetUriFromFilePath_002, TestSize.Level1)
{
    string filePath = PRE_PATH_VALUES;
    string file = "/path/to/file";
    Uri fileUri(file);
    string userId;
    auto result = manager.GetUriFromFilePath(filePath, fileUri, userId);
    EXPECT_EQ(result, E_CHECK_ROOT_DIR_FAIL);
}

HWTEST_F(MediaLibraryManagerTest, GetSandboxPath_001, TestSize.Level1)
{
    std::string path = "/storage/cloud/";
    Size size;
    bool isAstc = true;
    auto result = manager.GetSandboxPath(path, size, isAstc);
    EXPECT_EQ(result, "");
}

HWTEST_F(MediaLibraryManagerTest, GetSandboxPath_002, TestSize.Level1)
{
    std::string path = ROOT_MEDIA_DIR;
    Size size;
    size.width = DEFAULT_ORIGINAL;
    size.height = DEFAULT_ORIGINAL;
    bool isAstc = false;
    auto result = manager.GetSandboxPath(path, size, isAstc);
    EXPECT_EQ(result, ROOT_SANDBOX_DIR + ".thumbs/" + "/LCD.jpg");
}

HWTEST_F(MediaLibraryManagerTest, GetSandboxPath_003, TestSize.Level1)
{
    std::string path = ROOT_MEDIA_DIR;
    Size size;
    size.width = 256;
    size.height = 768;
    bool isAstc = false;
    auto result = manager.GetSandboxPath(path, size, isAstc);
    EXPECT_NE(result, ROOT_SANDBOX_DIR + ".thumbs/" + "/LCD.jpg");
}

HWTEST_F(MediaLibraryManagerTest, GetSandboxPath_004, TestSize.Level1)
{
    std::string path = ROOT_MEDIA_DIR;
    Size size;
    size.width = 768;
    size.height = 768;
    bool isAstc = false;
    auto result = manager.GetSandboxPath(path, size, isAstc);
    EXPECT_EQ(result, ROOT_SANDBOX_DIR + ".thumbs/" + "/LCD.jpg");
}

HWTEST_F(MediaLibraryManagerTest, GetUriIdPrefix_001, TestSize.Level1)
{
    std::string fileUri = "";
    manager.GetUriIdPrefix(fileUri);
    EXPECT_EQ(fileUri, "");
}

HWTEST_F(MediaLibraryManagerTest, GetUriIdPrefix_002, TestSize.Level1)
{
    std::string fileUri = "/Photo";
    manager.GetUriIdPrefix(fileUri);
    EXPECT_EQ(fileUri, "/Photo");
}

HWTEST_F(MediaLibraryManagerTest, GetUriIdPrefix_003, TestSize.Level1)
{
    std::string fileUri = "a/b/Photo";
    manager.GetUriIdPrefix(fileUri);
    EXPECT_EQ(fileUri, "a");
}

HWTEST_F(MediaLibraryManagerTest, IfSizeEqualsRatio_001, TestSize.Level1)
{
    Size imageSize;
    imageSize.height = 0;
    Size targetSize;
    targetSize.height = 0;
    auto ret = manager.IfSizeEqualsRatio(imageSize, targetSize);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryManagerTest, IfSizeEqualsRatio_002, TestSize.Level1)
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

HWTEST_F(MediaLibraryManagerTest, IfSizeEqualsRatio_003, TestSize.Level1)
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

HWTEST_F(MediaLibraryManagerTest, OpenReadOnlyAppSandboxVideo_001, TestSize.Level1)
{
    string uri;
    auto ret = manager.OpenReadOnlyAppSandboxVideo(uri);
    EXPECT_EQ(ret, -1);
}

HWTEST_F(MediaLibraryManagerTest, GetSandboxMovingPhotoTime_001, TestSize.Level1)
{
    string uri;
    auto ret = manager.GetSandboxMovingPhotoTime(uri);
    EXPECT_EQ(ret, -1);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GetAstc_emptyUris, TestSize.Level1)
{
    string uriStr;
    auto pixelMap = mediaLibraryManager->GetAstc(Uri(uriStr));
    EXPECT_EQ(pixelMap, nullptr);
}

HWTEST_F(MediaLibraryManagerTest, GetResultSetFromPhotos_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetResultSetFromPhotos_001 enter");
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

    EXPECT_NE(mediaLibraryExtendManager, nullptr);
    vector<string> columns;
    EXPECT_NE(mediaLibraryExtendManager->GetResultSetFromPhotos(assetUri, columns), nullptr);
    MEDIA_INFO_LOG("GetResultSetFromPhotos_001 exit");
}

HWTEST_F(MediaLibraryManagerTest, GetResultSetFromPhotos_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetResultSetFromPhotos_002 enter");
    EXPECT_NE(mediaLibraryExtendManager, nullptr);
    string value = "1";
    vector<string> columns;
    EXPECT_EQ(mediaLibraryExtendManager->GetResultSetFromPhotos(value, columns), nullptr);
    MEDIA_INFO_LOG("GetResultSetFromPhotos_002 exit");
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GetAstcYearAndMonth_test, TestSize.Level1)
{
    vector<string> uris;
    int32_t ret = mediaLibraryManager->GetAstcYearAndMonth(uris);
    EXPECT_EQ(ret, E_ERR);

    for (int i = 0; i < 5; i++) {
        uris.push_back(CreatePhotoAsset("test.mp4"));
    }
    ret = mediaLibraryManager->GetAstcYearAndMonth(uris);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_ReadPrivateMovingPhoto_test, TestSize.Level1)
{
    EXPECT_NE(mediaLibraryExtendManager, nullptr);
    string uri = "test";
    EXPECT_EQ(mediaLibraryExtendManager->ReadPrivateMovingPhoto(uri, HideSensitiveType::ALL_DESENSITIZE), E_ERR);
    uri = "../test/test.txt";
    EXPECT_EQ(mediaLibraryExtendManager->ReadPrivateMovingPhoto(uri, HideSensitiveType::ALL_DESENSITIZE), E_ERR);
    uri = CreatePhotoAsset("test.mp4");
    EXPECT_EQ(mediaLibraryExtendManager->ReadPrivateMovingPhoto(uri, HideSensitiveType::ALL_DESENSITIZE), E_ERR);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GetResultSetFromDb_test, TestSize.Level1)
{
    EXPECT_NE(mediaLibraryExtendManager, nullptr);
    string columnName = "file_id";
    string value = "1";
    vector<string> columns;
    EXPECT_NE(mediaLibraryExtendManager->GetResultSetFromDb(columnName, value, columns), nullptr);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_InitMediaLibraryManager_test, TestSize.Level1)
{
    ASSERT_NE(mediaLibraryManager, nullptr);
    int32_t ret = 0;
    string uri = "file://media-test_value";
    string openMode = "test_value";
    mediaLibraryManager->InitMediaLibraryManager();
    ret = mediaLibraryManager->OpenAsset(uri, openMode);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GetAstcYearAndMonth_test_002, TestSize.Level1)
{
    ASSERT_NE(mediaLibraryManager, nullptr);
    std::vector<string> uris;
    int32_t ret;
    for (int i = 0; i < 5; i++) {
        uris.push_back(CreatePhotoAsset("test.mp4"));
    }
    ret = mediaLibraryManager->GetAstcYearAndMonth(uris);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_QueryTotalSize_test, TestSize.Level1)
{
    ASSERT_NE(mediaLibraryManager, nullptr);
    int32_t ret;
    MediaVolume outMediaVolume;
    ret = mediaLibraryManager->QueryTotalSize(outMediaVolume);
    EXPECT_EQ(ret, E_SUCCESS);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GetResultSetFromDb_test_002, TestSize.Level1)
{
    ASSERT_NE(mediaLibraryManager, nullptr);
    std::string columnName = MEDIA_DATA_DB_URI;
    std::string value = "test";
    std::vector<string> columns;
    std::shared_ptr<DataShare::DataShareResultSet> res =
        mediaLibraryManager->GetResultSetFromDb(columnName, value, columns);
    EXPECT_EQ(res, nullptr);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GetResultSetFromDb_test_003, TestSize.Level1)
{
    ASSERT_NE(mediaLibraryManager, nullptr);
    std::shared_ptr<DataShareResultSet> ptr = nullptr;
    std::string columnName = "file_id_test";
    std::string value = "test";
    std::vector<string> columns;
    ptr = mediaLibraryManager->GetResultSetFromDb(columnName, value, columns);
    EXPECT_NE(ptr, nullptr);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CheckResultSet_test, TestSize.Level1)
{
    ASSERT_NE(mediaLibraryManager, nullptr);
    std::shared_ptr<DataShareResultSet> resultSet = nullptr;
    int32_t ret;
    ret = mediaLibraryManager->CheckResultSet(resultSet);
    EXPECT_NE(ret, E_SUCCESS);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_CheckResultSet_test_002, TestSize.Level1)
{
    ASSERT_NE(mediaLibraryManager, nullptr);
    vector<string> columns;
    DataSharePredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> " + to_string(g_albumMediaType);
    predicates.SetWhereClause(prefix);
    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<DataShareResultSet> resultSet = nullptr;
    ASSERT_NE(sDataShareHelper_, nullptr);
    resultSet = sDataShareHelper_->Query(queryFileUri, predicates, columns);
    ASSERT_NE(resultSet, nullptr);
    int32_t ret;
    ret = mediaLibraryManager->CheckResultSet(resultSet);
    EXPECT_EQ(ret, E_SUCCESS);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GetFilePathFromUri_test, TestSize.Level1)
{
    ASSERT_NE(mediaLibraryManager, nullptr);
    string file = "/path/to/file";
    Uri fileUri(file);
    string filePath = "/path/to/testfile";
    string userId = "100";
    int32_t ret;
    ret = mediaLibraryManager->GetFilePathFromUri(fileUri, filePath, userId);
    EXPECT_NE(ret, E_SUCCESS);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GetFilePathFromUri_test_002, TestSize.Level1)
{
    ASSERT_NE(mediaLibraryManager, nullptr);
    string file = "/path/to/file";
    Uri fileUri(file);
    string filePath = "/path/to/testfile";
    string userId = "100";
    int32_t ret;
#define MEDIALIBRARY_COMPATIBILITY
    ret = mediaLibraryManager->GetFilePathFromUri(fileUri, filePath, userId);
#undef MEDIALIBRARY_COMPATIBILITY
    EXPECT_NE(ret, E_SUCCESS);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_OpenThumbnail_test, TestSize.Level1)
{
    ASSERT_NE(mediaLibraryManager, nullptr);
    string uristr = URI_QUERY_PHOTO;
    string filePath = "/path/to/testfile";
    Size size;
    bool isAstc = true;
    int ret;
    ret = MediaLibraryManager::OpenThumbnail(uristr, filePath, size, isAstc);
    EXPECT_EQ(ret, E_ERR);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_DecodeThumbnail_test, TestSize.Level1)
{
    ASSERT_NE(mediaLibraryManager, nullptr);
    UniqueFd uniqueFd;
    Size size;
    DecodeDynamicRange dynamicRange = DecodeDynamicRange::SDR;
    std::unique_ptr<PixelMap> ret = nullptr;
    ret = MediaLibraryManager::DecodeThumbnail(uniqueFd, size, dynamicRange);
    EXPECT_EQ(ret, nullptr);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_QueryThumbnail_test, TestSize.Level1)
{
    ASSERT_NE(mediaLibraryManager, nullptr);
    UriParams params;
    params.path = "/path/to/testfile";
    params.fileUri = "/Photo";
    params.isAstc = true;
    std::unique_ptr<PixelMap> ret = nullptr;
    ret = MediaLibraryManager::QueryThumbnail(params);
    EXPECT_EQ(ret, nullptr);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GetThumbnail_test, TestSize.Level1)
{
    ASSERT_NE(mediaLibraryManager, nullptr);
    string file = "/path/to/file";
    Uri fileUri(file);
    std::unique_ptr<PixelMap> ret = nullptr;
    ret = mediaLibraryManager->GetThumbnail(fileUri);
    EXPECT_EQ(ret, nullptr);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GetBatchAstcs_test, TestSize.Level1)
{
    ASSERT_NE(mediaLibraryManager, nullptr);
    vector<string> uriBatch;
    vector<vector<uint8_t>> astcBatch;
    string beginUri =
        "file://media/Photo/64/IMG_063/IMG_11311.jpg?oper=astc&width=256&height=256&time_id=00000001";
    uriBatch.push_back(beginUri);
    uriBatch.push_back("/media/ml/uri/offset/1");
    uriBatch.push_back("&offset=");
    int32_t ret = mediaLibraryManager->GetBatchAstcs(uriBatch, astcBatch);
    EXPECT_EQ(ret, E_INVALID_URI);
}

HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_DecodeAstc_test, TestSize.Level1)
{
    ASSERT_NE(mediaLibraryManager, nullptr);
    UniqueFd uniqueFd;
    unique_ptr<PixelMap> ret = nullptr;
    ret = MediaLibraryManager::DecodeAstc(uniqueFd);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.number    : MediaLibraryManager_GetAlbumLpath_test_001
 * @tc.name      : Get lpath by albumId
 * @tc.desc      : Get lpath by albumId success
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GetAlbumLpath_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GetAlbumLpath_test_001 enter");
    ASSERT_NE(mediaLibraryManager, nullptr);
    uint32_t ownerAlbumId = 1;
    std::string lpath = "";
    int32_t ret = mediaLibraryManager->GetAlbumLpath(ownerAlbumId, lpath);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("MediaLibraryManager_GetAlbumLpath_test_001 exit");
}

/**
 * @tc.number    : MediaLibraryManager_GetAlbumLpaths_test_001
 * @tc.name      : Get lpaths by albumType
 * @tc.desc      : Get lpaths by albumType failed
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GetAlbumLpaths_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GetAlbumLpaths_test_001 enter");
    ASSERT_NE(mediaLibraryManager, nullptr);
    uint32_t albumType = 1024;
    std::shared_ptr<DataShare::ResultSet> resultSet = nullptr;
    int32_t ret = mediaLibraryManager->GetAlbumLpaths(albumType, resultSet);
    EXPECT_EQ(ret, E_FAIL);
    MEDIA_INFO_LOG("MediaLibraryManager_GetAlbumLpaths_test_001 exit");
}

/**
 * @tc.number    : MediaLibraryManager_GetAlbumLpaths_test_002
 * @tc.name      : Get lpaths by albumType
 * @tc.desc      : Get lpaths by albumType success
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GetAlbumLpaths_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GetAlbumLpaths_test_002 enter");
    ASSERT_NE(mediaLibraryManager, nullptr);
    uint32_t albumType = 0;
    std::shared_ptr<DataShare::ResultSet> resultSet = nullptr;
    int32_t ret = mediaLibraryManager->GetAlbumLpaths(albumType, resultSet);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("MediaLibraryManager_GetAlbumLpaths_test_002 exit");
}

/**
 * @tc.number    : MediaLibraryManager_GetAlbumLpaths_test_003
 * @tc.name      : Get lpaths by albumType
 * @tc.desc      : Get lpaths by albumType success
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_GetAlbumLpaths_test_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_GetAlbumLpaths_test_003 enter");
    ASSERT_NE(mediaLibraryManager, nullptr);
    uint32_t albumType = 2048;
    std::shared_ptr<DataShare::ResultSet> resultSet = nullptr;
    int32_t ret = mediaLibraryManager->GetAlbumLpaths(albumType, resultSet);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("MediaLibraryManager_GetAlbumLpaths_test_003 exit");
}

/**
 * @tc.number    : MediaLibraryManager_RetainCloudMediaAsset_test_001
 * @tc.name      : RetainCloudMediaAsset: HDC_RETAIN_FORCE
 * @tc.desc      : RetainCloudMediaAsset failed
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryManager_RetainCloudMediaAsset_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryManager_RetainCloudMediaAsset_test_001 enter");
    ASSERT_NE(mediaLibraryManager, nullptr);
    CloudMediaRetainType retainType = CloudMediaRetainType::HDC_RETAIN_FORCE;
    int32_t ret = mediaLibraryManager->RetainCloudMediaAsset(retainType);
    EXPECT_NE(ret, E_OK);
    MEDIA_INFO_LOG("MediaLibraryManager_RetainCloudMediaAsset_test_001 exit");
}

/**
 * @tc.number    : MediaLibraryExtendManager_GetPhotoUrisPermission_test_001
 * @tc.name      : Get 不支持的权限类型
 * @tc.desc      : Get permission fail
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryExtendManager_GetPhotoUrisPermission_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryExtendManager_GetPhotoUrisPermission_test_001 enter");
    int target_tokenId = 2;
    vector<string> uris;
    vector<bool> result;
    for (int i = 0; i < 5; i++) {
        auto uri = CreatePhotoAsset("test.mp4");
        uris.push_back(uri);
    }

    vector<PhotoPermissionType> permissionTypes1(5, PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO);
    int32_t ret = mediaLibraryExtendManager->GetPhotoUrisPermission(target_tokenId, uris, permissionTypes1, result);
    EXPECT_EQ(ret, E_ERR);

    vector<PhotoPermissionType> permissionTypes2(5, PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO);
    ret = mediaLibraryExtendManager->GetPhotoUrisPermission(target_tokenId, uris, permissionTypes2, result);
    EXPECT_EQ(ret, E_ERR);

    vector<PhotoPermissionType> permissionTypes3(5, PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO);
    ret = mediaLibraryExtendManager->GetPhotoUrisPermission(target_tokenId, uris, permissionTypes3, result);
    EXPECT_EQ(ret, E_ERR);

    vector<PhotoPermissionType> permissionTypes4(5, PhotoPermissionType::PERSIST_READWRITE_IMAGEVIDEO);
    ret = mediaLibraryExtendManager->GetPhotoUrisPermission(target_tokenId, uris, permissionTypes4, result);
    EXPECT_EQ(ret, E_ERR);

    MEDIA_INFO_LOG("MediaLibraryExtendManager_GetPhotoUrisPermission_test_001 exit");
}

/**
 * @tc.number    : MediaLibraryExtendManager_GetPhotoUrisPermission_test_002
 * @tc.name      : uris列表长度不合法
 * @tc.desc      : Get permission fail
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryExtendManager_GetPhotoUrisPermission_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryExtendManager_GetPhotoUrisPermission_test_002 enter");
    int target_tokenId = 3;
    vector<bool> result;
    vector<string> uris;
    vector<PhotoPermissionType> permissionTypes;
    int32_t ret = mediaLibraryExtendManager->GetPhotoUrisPermission(target_tokenId, uris, permissionTypes, result);
    EXPECT_EQ(ret, E_ERR);

    uris.resize(5);
    permissionTypes.resize(8);
    ret = mediaLibraryExtendManager->GetPhotoUrisPermission(target_tokenId, uris, permissionTypes, result);
    EXPECT_EQ(ret, E_ERR);

    uris.resize(1001);
    permissionTypes.resize(1001);
    ret = mediaLibraryExtendManager->GetPhotoUrisPermission(target_tokenId, uris, permissionTypes, result);
    EXPECT_EQ(ret, E_ERR);

    MEDIA_INFO_LOG("MediaLibraryExtendManager_GetPhotoUrisPermission_test_002 exit");
}

/**
 * @tc.number    : MediaLibraryExtendManager_GetPhotoUrisPermission_test_003
 * @tc.name      : 单一权限类型
 * @tc.desc      : Get permission success
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryExtendManager_GetPhotoUrisPermission_test_003, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryExtendManager_GetPhotoUrisPermission_test_003 enter");
    uint64_t srcTokenId = 2;
    uint64_t targetTokenId = 3;
    vector<string> uris;
    vector<bool> result1;
    vector<PhotoPermissionType> permissionTypes;
    for (int i = 0; i < 5; i++) {
        auto uri = CreatePhotoAsset("test.mp4");
        uris.push_back(uri);
        permissionTypes.push_back(PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO);
    }
    int32_t ret = mediaLibraryExtendManager->GetPhotoUrisPermission(targetTokenId, uris, permissionTypes, result1);
    EXPECT_EQ(ret, 0);
    vector<bool> expectSet1{false, false, false, false, false};
    EXPECT_EQ(result1, expectSet1);
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    ret = mediaLibraryExtendManager->GrantPhotoUriPermission(
        srcTokenId, targetTokenId, uris, permissionTypes, SensitiveType);
    ASSERT_EQ(ret, E_OK);
    vector<bool> result2;
    vector<PhotoPermissionType> getPermissionTypes{
        PhotoPermissionType::PERSIST_READ_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO,
        PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO,
    };
    ret = mediaLibraryExtendManager->GetPhotoUrisPermission(targetTokenId, uris, getPermissionTypes, result2);
    EXPECT_EQ(ret, E_OK);
    vector<bool> expectSet2{false, true, false, false, true};
    EXPECT_EQ(result2, expectSet2);
    MEDIA_INFO_LOG("MediaLibraryExtendManager_GetPhotoUrisPermission_test_003 exit");
}

/**
 * @tc.number    : MediaLibraryExtendManager_GetPhotoUrisPermission_test_004
 * @tc.name      : 混合权限类型：Get uris列表存在永久读，写，读写权限
 * @tc.desc      : Get permission success
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryExtendManager_GetPhotoUrisPermission_test_004, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryExtendManager_GetPhotoUrisPermission_test_004 enter");
    uint64_t srcTokenId = 2;
    uint64_t targetTokenId = 3;
    vector<string> uris;
    for (int i = 0; i < 6; i++) {
        auto uri = CreatePhotoAsset("test.jpg");
        uris.push_back(uri);
    }
    vector<PhotoPermissionType> permissionTypes{
        PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_READ_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO,
        PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO,
    };
    auto SensitiveType = HideSensitiveType::GEOGRAPHIC_LOCATION_DESENSITIZE;
    auto ret = mediaLibraryExtendManager->GrantPhotoUriPermission(
        srcTokenId, targetTokenId, uris, permissionTypes, SensitiveType);
    ASSERT_EQ(ret, E_OK);
    vector<bool> result;
    vector<PhotoPermissionType> getPermissionTypes{
        PhotoPermissionType::PERSIST_READ_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_READ_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO,
        PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO,
        PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO,
    };
    ret = mediaLibraryExtendManager->GetPhotoUrisPermission(targetTokenId, uris, getPermissionTypes, result);
    EXPECT_EQ(ret, E_OK);
    vector<bool> expectSet{false, true, false, false, true, true};
    EXPECT_EQ(result, expectSet);
    MEDIA_INFO_LOG("MediaLibraryExtendManager_GetPhotoUrisPermission_test_004 exit");
}

/**
 * @tc.number    : MediaLibraryExtendManager_GetUrisFromFusePaths_test_001
 * @tc.name      : Get uri
 * @tc.desc      : Get uri success
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryExtendManager_GetUrisFromFusePaths_test_001, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryExtendManager_GetUrisFromFusePaths_test_001 enter");
    vector<string> paths = {"/data/storage/el2/media/test.mp4"};
    vector<string> uris;
    int32_t ret = mediaLibraryExtendManager->GetUrisFromFusePaths(paths, uris);
    EXPECT_EQ(ret, 0);
    MEDIA_INFO_LOG("MediaLibraryExtendManager_GetUrisFromFusePaths_test_001 exit");
}

/**
 * @tc.number    : MediaLibraryExtendManager_GetUrisFromFusePaths_test_002
 * @tc.name      : Get uri
 * @tc.desc      : Get uri fail
 */
HWTEST_F(MediaLibraryManagerTest, MediaLibraryExtendManager_GetUrisFromFusePaths_test_002, TestSize.Level1)
{
    MEDIA_INFO_LOG("MediaLibraryExtendManager_GetUrisFromFusePaths_test_002 enter");
    vector<string> paths = {"/data/storage/el2/test.mp4"};
    vector<string> uris;
    int32_t ret = mediaLibraryExtendManager->GetUrisFromFusePaths(paths, uris);
    EXPECT_EQ(ret, E_ERR);
    MEDIA_INFO_LOG("MediaLibraryExtendManager_GetUrisFromFusePaths_test_002 exit");
}
} // namespace Media
} // namespace OHOS
