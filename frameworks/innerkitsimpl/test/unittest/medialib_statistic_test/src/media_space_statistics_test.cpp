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

#include "media_space_statistics_test.h"

#include "datashare_helper.h"
#include "get_self_permissions.h"
#include "hilog/log.h"
#include "iservice_registry.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "media_file_utils.h"
#include "media_library_manager.h"
#include "media_log.h"
#include "media_volume.h"
#include "scanner_utils.h"
#include "system_ability_definition.h"

using namespace std;
using namespace OHOS;
using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::AppExecFwk;

/**
 * @FileName MediaSpaceStatisticsTest
 * @Desc Media space statistics function test
 *
 */
namespace OHOS {
namespace Media {
std::shared_ptr<DataShare::DataShareHelper> sDataShareHelper_ = nullptr;
void CreateFile(std::string baseURI, std::string targetPath, std::string newName, MediaType mediaType,
    const unsigned char fileContent[], const int len);
std::unique_ptr<FileAsset> GetFile(int mediaTypeId);
void ClearFile();
void CreateDataHelper(int32_t systemAbilityId);

constexpr int STORAGE_MANAGER_MANAGER_ID = 5003;
int g_albumMediaType = MEDIA_TYPE_ALBUM;
const int COPY_TIME = 9;
const int SCAN_WAIT_TIME = 10;
int64_t g_oneImageSize = 0;
int64_t g_oneVideoSize = 0;
int64_t g_oneAudioSize = 0;
int64_t g_oneFileSize = 0;

static const unsigned char FILE_CONTENT_TXT[] = {
    0x49, 0x44, 0x33, 0x03, 0x20, 0x20, 0x20, 0x0c, 0x24
};
static const unsigned char FILE_CONTENT_JPG[] = {
    0x49, 0x44, 0x33, 0x03, 0x20, 0x20, 0x20, 0x0c, 0x24, 0x5d, 0x54, 0x45, 0x4e, 0x43, 0x20, 0x20, 0x20, 0x0b,
    0x20, 0x20, 0x20, 0x50
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
    0xdc, 0x45, 0xe9, 0xbd, 0xe6, 0xd9, 0x48, 0xb7, 0x96, 0x2c, 0xd8, 0x20, 0xd9, 0x23, 0xee, 0xef, 0x78, 0x32, 0x36,
    0x34, 0x20, 0x2d, 0x20, 0x63, 0x6f, 0x72, 0x65, 0x20, 0x31, 0x35, 0x39, 0x20, 0x2d, 0x20, 0x48, 0x2e, 0x32, 0x36,
    0x34, 0x2f, 0x4d, 0x50, 0x45, 0x47, 0x2d, 0x34, 0x20, 0x41, 0x56, 0x43, 0x20, 0x63, 0x6f, 0x64, 0x65, 0x63, 0x20,
    0x2d, 0x20, 0x43, 0x6f, 0x70, 0x79, 0x6c, 0x65, 0x66, 0x74, 0x20, 0x32, 0x30, 0x30, 0x33, 0x2d, 0x32, 0x30, 0x31,
    0x39, 0x20, 0x2d, 0x20, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x76, 0x69, 0x64, 0x65,
    0x6f, 0x6c, 0x61, 0x6e, 0x2e, 0x6f, 0x72, 0x67, 0x2f, 0x78, 0x32, 0x36, 0x34, 0x2e, 0x68, 0x74, 0x6d, 0x6c, 0x20,
    0x2d, 0x20, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x3a, 0x20, 0x63, 0x61, 0x62, 0x61, 0x63, 0x3d, 0x31, 0x20,
    0x72, 0x65, 0x66, 0x3d, 0x33, 0x20, 0x64, 0x65, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x3d, 0x31, 0x3a, 0x30, 0x3a, 0x30,
    0x20, 0x61, 0x6e, 0x61, 0x6c, 0x79, 0x73, 0x65, 0x3d, 0x30, 0x78, 0x33, 0x3a, 0x30, 0x78, 0x31, 0x31, 0x33, 0x20,
    0x6d, 0x65, 0x3d, 0x68, 0x65, 0x78, 0x20, 0x73, 0x75, 0x62, 0x6d, 0x65, 0x3d, 0x37, 0x20, 0x70, 0x73, 0x79, 0x3d,
    0x31, 0x20, 0x70, 0x73, 0x79, 0x5f, 0x72, 0x64, 0x3d, 0x31, 0x2e, 0x30, 0x30, 0x3a, 0x30, 0x2e, 0x30, 0x30, 0x20,
    0x6d, 0x69, 0x78, 0x65, 0x64, 0x5f, 0x72, 0x65, 0x66, 0x3d, 0x31, 0x20, 0x6d, 0x65, 0x5f, 0x72, 0x61, 0x6e, 0x67,
    0x65, 0x3d, 0x31, 0x36, 0x20, 0x63, 0x68, 0x72, 0x6f, 0x6d, 0x61, 0x5f, 0x6d, 0x65, 0x3d, 0x31, 0x20, 0x74, 0x72,
    0x65, 0x6c, 0x6c, 0x69, 0x73, 0x3d, 0x31, 0x20, 0x38, 0x78, 0x38, 0x64, 0x63, 0x74, 0x3d, 0x31, 0x20, 0x63, 0x71,
    0x6d, 0x3d, 0x30, 0x20, 0x64, 0x65, 0x61, 0x64, 0x7a, 0x6f, 0x6e, 0x65, 0x3d, 0x32, 0x31, 0x2c, 0x31, 0x31, 0x20,
    0x66, 0x61, 0x73, 0x74, 0x5f, 0x70, 0x73, 0x6b, 0x69, 0x70, 0x3d, 0x31, 0x20, 0x63, 0x68, 0x72, 0x6f, 0x6d, 0x61,
    0x5f, 0x71, 0x70, 0x5f, 0x6f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x3d, 0x2d, 0x32, 0x20, 0x74, 0x68, 0x72, 0x65, 0x61,
    0x64, 0x73, 0x3d, 0x36, 0x20, 0x6c, 0x6f, 0x6f, 0x6b, 0x61, 0x68, 0x65, 0x61, 0x64, 0x5f, 0x74, 0x68, 0x72, 0x65,
    0x61, 0x64, 0x73, 0x3d, 0x31, 0x20, 0x73, 0x6c, 0x69, 0x63, 0x65, 0x64, 0x5f, 0x74, 0x68, 0x72, 0x65, 0x61, 0x64,
    0x73, 0x3d, 0x30, 0x20, 0x6e, 0x72, 0x3d, 0x30, 0x20, 0x64, 0x65, 0x63, 0x69, 0x6d, 0x61, 0x74, 0x65, 0x3d, 0x31,
    0x20, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6c, 0x61, 0x63, 0x65, 0x64, 0x3d, 0x30, 0x20, 0x62, 0x6c, 0x75, 0x72, 0x61,
    0x79, 0x5f, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x74, 0x3d, 0x30, 0x20, 0x63, 0x6f, 0x6e, 0x73, 0x74, 0x72, 0x61, 0x69,
    0x6e, 0x65, 0x64, 0x5f, 0x69, 0x6e, 0x74, 0x72, 0x61, 0x3d, 0x30, 0x20, 0x62, 0x66, 0x72, 0x61, 0x6d, 0x65, 0x73,
    0x3d, 0x33, 0x20, 0x62, 0x5f, 0x70, 0x79, 0x72, 0x61, 0x6d, 0x69, 0x64, 0x3d, 0x32, 0x20, 0x62, 0x5f, 0x61, 0x64,
    0x61, 0x70, 0x74, 0x3d, 0x31, 0x20, 0x62, 0x5f, 0x62, 0x69, 0x61, 0x73, 0x3d, 0x30, 0x20, 0x64, 0x69, 0x72, 0x65,
    0x63, 0x74, 0x3d, 0x31, 0x20, 0x77, 0x65, 0x69, 0x67, 0x68, 0x74, 0x62, 0x3d, 0x31, 0x20, 0x6f, 0x70, 0x65, 0x6e,
    0x5f, 0x67, 0x6f, 0x70, 0x3d, 0x30, 0x20, 0x77, 0x65, 0x69, 0x67, 0x68, 0x74, 0x70, 0x3d, 0x32, 0x20, 0x6b, 0x65,
    0x79, 0x69, 0x6e, 0x74, 0x3d, 0x32, 0x35, 0x30, 0x20, 0x6b, 0x65, 0x79, 0x69, 0x6e, 0x74, 0x5f, 0x6d, 0x69, 0x6e,
    0x3d, 0x32, 0x35, 0x20, 0x73, 0x63, 0x65, 0x6e, 0x65, 0x63, 0x75
};

std::shared_ptr<DataShare::DataShareHelper> GetDataShareHelper()
{
    if (sDataShareHelper_ == nullptr) {
        CreateDataHelper(STORAGE_MANAGER_MANAGER_ID);
    }
    if (sDataShareHelper_ == nullptr) {
        MEDIA_ERR_LOG("GetDataShareHelper ::sDataShareHelper_ is nullptr");
    }
    return sDataShareHelper_;
}

MediaLibraryManager* mediaLibraryManager = MediaLibraryManager::GetMediaLibraryManager();

void MediaSpaceStatisticsTest::SetUpTestCase(void)
{
    // test QueryTotalSize when sDataShareHelper_ is nullptr
    MediaVolume mediaVolume;
    mediaLibraryManager->QueryTotalSize(mediaVolume);
    mediaLibraryManager->CloseAsset("", 0);

    vector<string> perms;
    perms.push_back("ohos.permission.READ_MEDIA");
    perms.push_back("ohos.permission.WRITE_MEDIA");
    perms.push_back("ohos.permission.FILE_ACCESS_MANAGER");
    perms.push_back("ohos.permission.GET_BUNDLE_INFO_PRIVILEGED");
    uint64_t tokenId = 0;
    PermissionUtilsUnitTest::SetAccessTokenPermission("MediaSpaceStatisticsUnitTest", perms, tokenId);
    ASSERT_TRUE(tokenId != 0);

    MEDIA_INFO_LOG("MediaSpaceStatisticsTest::SetUpTestCase:: invoked");
    // // make sure board is empty
    ClearFile();

    // create base file
    CreateFile(MEDIALIBRARY_IMAGE_URI, "Pictures/", "MediaSpaceStatisticsTest.jpg", MEDIA_TYPE_IMAGE,
        FILE_CONTENT_JPG, sizeof(FILE_CONTENT_JPG));
    CreateFile(MEDIALIBRARY_VIDEO_URI, "Videos/", "MediaSpaceStatisticsTest.mp4", MEDIA_TYPE_VIDEO,
        FILE_CONTENT_MP4, sizeof(FILE_CONTENT_MP4));
    CreateFile(MEDIALIBRARY_AUDIO_URI, "Audios/", "MediaSpaceStatisticsTest.mp3", MEDIA_TYPE_AUDIO,
        FILE_CONTENT_MP3, sizeof(FILE_CONTENT_MP3));
    CreateFile(MEDIALIBRARY_FILE_URI, "Documents/", "MediaSpaceStatisticsTest.txt", MEDIA_TYPE_FILE,
        FILE_CONTENT_TXT, sizeof(FILE_CONTENT_TXT));

    std::shared_ptr<DataShare::DataShareHelper> helper = GetDataShareHelper();
    Uri scanUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_BOARDCASTOPRN);
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_FILE_PATH, ROOT_MEDIA_DIR);
    auto ret = helper->Insert(scanUri, valuesBucket);
    EXPECT_EQ(ret, 0);
    sleep(SCAN_WAIT_TIME);

    // get base size
    g_oneImageSize = GetFile(MEDIA_TYPE_IMAGE)->GetSize();
    g_oneVideoSize = GetFile(MEDIA_TYPE_VIDEO)->GetSize();
    g_oneAudioSize = GetFile(MEDIA_TYPE_AUDIO)->GetSize();
    g_oneFileSize = GetFile(MEDIA_TYPE_FILE)->GetSize();
    MEDIA_INFO_LOG("MediaSpaceStatisticsTest::SetUpTestCase:: g_oneImageSize = %{public}lld",
        (long long)g_oneImageSize);
    MEDIA_INFO_LOG("MediaSpaceStatisticsTest::SetUpTestCase:: g_oneVideoSize = %{public}lld",
        (long long)g_oneVideoSize);
    MEDIA_INFO_LOG("MediaSpaceStatisticsTest::SetUpTestCase:: g_oneAudioSize = %{public}lld",
        (long long)g_oneAudioSize);
    MEDIA_INFO_LOG("MediaSpaceStatisticsTest::SetUpTestCase:: g_oneFileSize = %{public}lld",
        (long long)g_oneFileSize);
    MEDIA_INFO_LOG("MediaSpaceStatisticsTest::SetUpTestCase:: Finish");
}

void MediaSpaceStatisticsTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("MediaSpaceStatisticsTest::TearDownTestCase:: invoked");
    sDataShareHelper_ = nullptr;
    MEDIA_INFO_LOG("MediaSpaceStatisticsTest::TearDownTestCase:: Finish");
}

// SetUp:Execute before each test case
void MediaSpaceStatisticsTest::SetUp(void) {}

void MediaSpaceStatisticsTest::TearDown(void) {}

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
    MEDIA_INFO_LOG("InitMediaLibraryManager success~!");

    if (sDataShareHelper_ == nullptr) {
        const sptr<IRemoteObject> &token = remoteObj;
        sDataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    }

    mediaLibraryManager->InitMediaLibraryManager(remoteObj);
}

std::unique_ptr<FileAsset> GetFile(int mediaTypeId)
{
    std::shared_ptr<DataShare::DataShareHelper> helper = GetDataShareHelper();
    vector<string> columns;
    DataSharePredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " = " + std::to_string(mediaTypeId);
    predicates.SetWhereClause(prefix);
    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<DataShareResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, predicates, columns);
    EXPECT_NE((resultSet == nullptr), true);

    unique_ptr<FetchResult<FileAsset>> fetchFileResult = make_unique<FetchResult<FileAsset>>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() <= 0), true);

    unique_ptr<FileAsset> fileAsset = fetchFileResult->GetLastObject();
    EXPECT_NE((fileAsset == nullptr), true);
    return fileAsset;
}

void DeleteFile(std::string fileUri)
{
    std::shared_ptr<DataShare::DataShareHelper> helper = GetDataShareHelper();
    Uri deleteAssetUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_DELETEASSET + '/' + fileUri);
    int retVal = helper->Delete(deleteAssetUri, {});
    MEDIA_INFO_LOG("MediaSpaceStatistics_test DeleteFile::uri :%{private}s", deleteAssetUri.ToString().c_str());
    EXPECT_NE((retVal < 0), true);
}

void ClearFile()
{
    std::shared_ptr<DataShare::DataShareHelper> helper = GetDataShareHelper();
    vector<string> columns;
    DataSharePredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> " + to_string(g_albumMediaType);
    predicates.SetWhereClause(prefix);
    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<DataShareResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, predicates, columns);
    EXPECT_NE((resultSet == nullptr), true);

    unique_ptr<FetchResult<FileAsset>> fetchFileResult = make_unique<FetchResult<FileAsset>>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() < 0), true);
    unique_ptr<FileAsset> fileAsset = fetchFileResult->GetFirstObject();
    while (fileAsset != nullptr) {
        DeleteFile(fileAsset->GetUri());
        fileAsset = fetchFileResult->GetNextObject();
    }
}

void CreateFile(std::string baseURI, std::string targetPath, std::string newName, MediaType mediaType,
    const unsigned char fileContent[], const int len)
{
    MEDIA_INFO_LOG("CreateFile:: start Create file: %s", newName.c_str());
    std::shared_ptr<DataShare::DataShareHelper> helper = GetDataShareHelper();

    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CREATEASSET);
    DataShareValuesBucket valuesBucket;
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

void CopyFile(std::string srcUri, std::string baseURI, std::string targetPath, std::string newName,
    MediaType mediaType, int sleepSecond)
{
    MEDIA_INFO_LOG("CopyFile:: start Copy sleepSecond[%d] file: %s", sleepSecond, newName.c_str());
    std::shared_ptr<DataShare::DataShareHelper> helper = GetDataShareHelper();
    Uri openFileUri(srcUri);
    int32_t srcFd = helper->OpenFile(openFileUri, MEDIA_FILEMODE_READWRITE);
    EXPECT_NE(srcFd <= 0, true);

    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CREATEASSET);
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    valuesBucket.Put(MEDIA_DATA_DB_NAME, newName);
    valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, targetPath);
    int32_t index = helper->Insert(createAssetUri, valuesBucket);
    string destUri = baseURI + "/" + std::to_string(index);
    Uri openFileUriDest(destUri);
    int32_t destFd = helper->OpenFile(openFileUriDest, MEDIA_FILEMODE_READWRITE);
    EXPECT_NE(destFd <= 0, true);

    int64_t srcLen = lseek(srcFd, 0, SEEK_END);
    lseek(srcFd, 0, SEEK_SET);
    char buf[srcLen];
    int32_t readRet = read(srcFd, buf, srcLen);
    int32_t resWrite = write(destFd, buf, readRet);
    if (resWrite == -1) {
        EXPECT_EQ(false, true);
    }

    mediaLibraryManager->CloseAsset(srcUri, srcFd);
    mediaLibraryManager->CloseAsset(destUri, destFd);
    sleep(sleepSecond);
    MEDIA_INFO_LOG("CopyFile:: end Copy file: %s", newName.c_str());
}

void CheckQuerySize(std::string testNo, int mediaTypeId, int targetFileNumber)
{
    MediaVolume mediaVolume;
    mediaLibraryManager->QueryTotalSize(mediaVolume);
    int64_t querySize = 0;
    int64_t targetSize = 0;
    if (mediaTypeId == MEDIA_TYPE_IMAGE) {
        querySize = mediaVolume.GetImagesSize();
        targetSize = targetFileNumber * g_oneImageSize;
    } else if (mediaTypeId == MEDIA_TYPE_VIDEO) {
        querySize = mediaVolume.GetVideosSize();
        targetSize = targetFileNumber * g_oneVideoSize;
    } else if (mediaTypeId == MEDIA_TYPE_AUDIO) {
        querySize = mediaVolume.GetAudiosSize();
        targetSize = targetFileNumber * g_oneAudioSize;
    } else if (mediaTypeId == MEDIA_TYPE_FILE) {
        querySize = mediaVolume.GetFilesSize();
        targetSize = targetFileNumber * g_oneFileSize;
    }
    MEDIA_INFO_LOG("%s QueryTotalSize querySize = %{public}lld", testNo.c_str(), (long long)querySize);
    MEDIA_INFO_LOG("%s QueryTotalSize targetSize = %{public}lld", testNo.c_str(), (long long)targetSize);
    EXPECT_EQ(querySize > 0, true);
    EXPECT_EQ(querySize, targetSize);
}

/**
 * @tc.number    : MediaSpaceStatistics_test_001
 * @tc.name      : get Media image size
 * @tc.desc      : 1.push 01.jpg into the device and make sure there is only one image
 *                 2.call the method to get media size
 *                 3.compare the size
 */
HWTEST_F(MediaSpaceStatisticsTest, MediaSpaceStatistics_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_001::Start");
    CheckQuerySize("MediaSpaceStatistics_test_001", MEDIA_TYPE_IMAGE, 1);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_001::End");
}

/**
 * @tc.number    : MediaSpaceStatistics_test_002
 * @tc.name      : get Media image size
 * @tc.desc      : 1.on MediaSpaceStatistics_test_001, read current image size
 *                 2.copy one image
 *                 3.get all images size
 *                 4.Compare the new total size
 *
 */
HWTEST_F(MediaSpaceStatisticsTest, MediaSpaceStatistics_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_002::Start");
    std::unique_ptr<FileAsset> fileAsset = GetFile(MEDIA_TYPE_IMAGE);
    CopyFile(fileAsset->GetUri(), MEDIALIBRARY_IMAGE_URI, "Pictures/",
                    "copy_MediaSpaceStatistics_test.jpg", MEDIA_TYPE_IMAGE, 10);
    CheckQuerySize("MediaSpaceStatistics_test_002", MEDIA_TYPE_IMAGE, 2);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_002::End");
}

/**
 * @tc.number    : MediaSpaceStatistics_test_003
 * @tc.name      : get Media image size
 * @tc.desc      : 1.on MediaSpaceStatistics_test_002, query image file
 *                 2.delete one image file
 *                 3.get all images size
 *                 4.Compare the new total size
 */
HWTEST_F(MediaSpaceStatisticsTest, MediaSpaceStatistics_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_003::Start");
    std::unique_ptr<FileAsset> fileAsset = GetFile(MEDIA_TYPE_IMAGE);
    DeleteFile(fileAsset->GetUri());
    CheckQuerySize("MediaSpaceStatistics_test_003", MEDIA_TYPE_IMAGE, 1);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_003::End");
}

/**
 * @tc.number    : MediaSpaceStatistics_test_004
 * @tc.name      : get Media image size
 * @tc.desc      : 1.on MediaSpaceStatistics_test_003, read current image size
 *                 2.copy 99 images
 *                 3.get all images size
 *                 4.Compare the new total size
 */
HWTEST_F(MediaSpaceStatisticsTest, MediaSpaceStatistics_test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_004::Start");
    std::unique_ptr<FileAsset> fileAsset = GetFile(MEDIA_TYPE_IMAGE);

    for (int i = 0; i < COPY_TIME; i++)
    {
        string newName = "copy_MediaSpaceStatistics_test_" + std::to_string(i) + ".jpg";
        int sleepSecond = 3;

        CopyFile(fileAsset->GetUri(), MEDIALIBRARY_IMAGE_URI, "Pictures/", newName, MEDIA_TYPE_IMAGE, sleepSecond);
    }
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_004:: Copy finish!!!");

    CheckQuerySize("MediaSpaceStatistics_test_004", MEDIA_TYPE_IMAGE, COPY_TIME + 1);

    MEDIA_INFO_LOG("MediaSpaceStatistics_test_004::End");
}

/**
 * @tc.number    : MediaSpaceStatistics_test_005
 * @tc.name      : get Media video size
 * @tc.desc      : 1.push 01.mp4 into the device and make sure there is only one video
 *                 2.call the method to get media size
 *                 3.compare the size
 */
HWTEST_F(MediaSpaceStatisticsTest, MediaSpaceStatistics_test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_005::Start");
    CheckQuerySize("MediaSpaceStatistics_test_005", MEDIA_TYPE_VIDEO, 1);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_005::End");
}

/**
 * @tc.number    : MediaSpaceStatistics_test_006
 * @tc.name      : get Media video size
 * @tc.desc      : 1.on MediaSpaceStatistics_test_005, read current video size
 *                 2.copy one video
 *                 3.get all videos size
 *                 4.Compare the new total size
 */
HWTEST_F(MediaSpaceStatisticsTest, MediaSpaceStatistics_test_006, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_006::Start");
    std::unique_ptr<FileAsset> fileAsset = GetFile(MEDIA_TYPE_VIDEO);
    CopyFile(fileAsset->GetUri(), MEDIALIBRARY_VIDEO_URI, "Videos/",
                    "copy_MediaSpaceStatistics_test.mp4", MEDIA_TYPE_VIDEO, 10);
    CheckQuerySize("MediaSpaceStatistics_test_006", MEDIA_TYPE_VIDEO, 2);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_006::End");
}

/**
 * @tc.number    : MediaSpaceStatistics_test_007
 * @tc.name      : get Media video size
 * @tc.desc      : 1.on MediaSpaceStatistics_test_006, read current video size
 *                 2.delete one video file
 *                 3.get videos size
 *                 4.Compare the new total size
 */
HWTEST_F(MediaSpaceStatisticsTest, MediaSpaceStatistics_test_007, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_007::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = GetDataShareHelper();
    std::unique_ptr<FileAsset> fileAsset = GetFile(MEDIA_TYPE_VIDEO);
    DeleteFile(fileAsset->GetUri());
    CheckQuerySize("MediaSpaceStatistics_test_007", MEDIA_TYPE_VIDEO, 1);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_007::End");
}

/**
 * @tc.number    : MediaSpaceStatistics_test_008
 * @tc.name      : get Media video size
 * @tc.desc      : 1.on MediaSpaceStatistics_test_007, read current video size
 *                 2.copy 99 video
 *                 3.get all videos size
 *                 4.Compare the new total size
 */
HWTEST_F(MediaSpaceStatisticsTest, MediaSpaceStatistics_test_008, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_008::Start");
    std::unique_ptr<FileAsset> fileAsset = GetFile(MEDIA_TYPE_VIDEO);
    for (int i = 0; i < COPY_TIME; i++)
    {
        string newName = "copy_MediaSpaceStatistics_test_" + std::to_string(i) + ".mp4";
        int sleepSecond = 3;
        CopyFile(fileAsset->GetUri(), MEDIALIBRARY_VIDEO_URI, "Videos/", newName, MEDIA_TYPE_VIDEO, sleepSecond);
    }
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_008:: Copy finish!!!");
    CheckQuerySize("MediaSpaceStatistics_test_008", MEDIA_TYPE_VIDEO, COPY_TIME + 1);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_008::End");
}

/**
 * @tc.number    : MediaSpaceStatistics_test_009
 * @tc.name      : get Media audio size
 * @tc.desc      : 1.push 01.mp3 into the device and make sure there is only one audio
 *                 2.call the method to get media size
 *                 3.compare the size
 */
HWTEST_F(MediaSpaceStatisticsTest, MediaSpaceStatistics_test_009, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_009::Start");
    CheckQuerySize("MediaSpaceStatistics_test_009", MEDIA_TYPE_AUDIO, 1);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_009::End");
}

/**
 * @tc.number    : MediaSpaceStatistics_test_010
 * @tc.name      : get Media audio size
 * @tc.desc      : 1.on MediaSpaceStatistics_test_009, read current audio size
 *                 2.copy one audio
 *                 3.get all audios size
 *                 4.Compare the new total size
 */
HWTEST_F(MediaSpaceStatisticsTest, MediaSpaceStatistics_test_010, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_010::Start");
    std::unique_ptr<FileAsset> fileAsset = GetFile(MEDIA_TYPE_AUDIO);
    CopyFile(fileAsset->GetUri(), MEDIALIBRARY_AUDIO_URI, "Audios/",
                    "copy_MediaSpaceStatistics_test.mp3", MEDIA_TYPE_AUDIO, 10);
    CheckQuerySize("MediaSpaceStatistics_test_010", MEDIA_TYPE_AUDIO, 2);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_010::End");
}

/**
 * @tc.number    : MediaSpaceStatistics_test_011
 * @tc.name      : get Media audio size
 * @tc.desc      : 1.on MediaSpaceStatistics_test_010,query audio file
 *                 2.delete one audio file
 *                 3.get audio size
 *                 4.Compare the new total size
 */
HWTEST_F(MediaSpaceStatisticsTest, MediaSpaceStatistics_test_011, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_011::Start");
    std::unique_ptr<FileAsset> fileAsset = GetFile(MEDIA_TYPE_AUDIO);
    DeleteFile(fileAsset->GetUri());
    CheckQuerySize("MediaSpaceStatistics_test_011", MEDIA_TYPE_AUDIO, 1);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_011::End");
}

/**
 * @tc.number    : MediaSpaceStatistics_test_012
 * @tc.name      : get Media audio size
 * @tc.desc      : 1.on MediaSpaceStatistics_test_011, read current audio size
 *                 2.copy 99 audios
 *                 3.get all audios size
 *                 4.Compare the new total size
 */
HWTEST_F(MediaSpaceStatisticsTest, MediaSpaceStatistics_test_012, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_012::Start");
    std::unique_ptr<FileAsset> fileAsset = GetFile(MEDIA_TYPE_AUDIO);
    for (int i = 0; i < COPY_TIME; i++)
    {
        string newName = "copy_MediaSpaceStatistics_test_" + std::to_string(i) + ".mp3";
        int sleepSecond = 3;
        CopyFile(fileAsset->GetUri(), MEDIALIBRARY_AUDIO_URI, "Audios/", newName, MEDIA_TYPE_AUDIO, sleepSecond);
    }
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_012:: Copy finish!!!");
    CheckQuerySize("MediaSpaceStatistics_test_012", MEDIA_TYPE_AUDIO, COPY_TIME + 1);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_012::End");
}

/**
 * @tc.number    : MediaSpaceStatistics_test_013
 * @tc.name      : get Media file size
 * @tc.desc      : 1.push 01.txt into the device and make sure there is only one file
 *                 2.call the method to get media size
 *                 3.compare the size
 */
HWTEST_F(MediaSpaceStatisticsTest, MediaSpaceStatistics_test_013, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_013::Start");
    CheckQuerySize("MediaSpaceStatistics_test_013", MEDIA_TYPE_FILE, 1);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_013::End");
}

/**
 * @tc.number    : MediaSpaceStatistics_test_014
 * @tc.name      : get Media(image,video,audio,file) size
 * @tc.desc      : 1.on MediaSpaceStatistics_test_013, read current file size
 *                 2.copy one file
 *                 3.get all files size
 *                 4.Compare the new total size
 */
HWTEST_F(MediaSpaceStatisticsTest, MediaSpaceStatistics_test_014, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_014::Start");
    std::unique_ptr<FileAsset> fileAsset = GetFile(MEDIA_TYPE_FILE);
    CopyFile(fileAsset->GetUri(), MEDIALIBRARY_FILE_URI, "Documents/",
                    "copy_MediaSpaceStatistics_test.txt", MEDIA_TYPE_FILE, 10);
    CheckQuerySize("MediaSpaceStatistics_test_014", MEDIA_TYPE_FILE, 2);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_014::End");
}

/**
 * @tc.number    : MediaSpaceStatistics_test_015
 * @tc.name      : get Media(image,video,audio,file) size
 * @tc.desc      : 1.on MediaSpaceStatistics_test_014, query file file
 *                 2.delete one file
 *                 3.get files size
 *                 4.Compare the new total size
 */
HWTEST_F(MediaSpaceStatisticsTest, MediaSpaceStatistics_test_015, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_015::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = GetDataShareHelper();
    std::unique_ptr<FileAsset> fileAsset = GetFile(MEDIA_TYPE_FILE);
    DeleteFile(fileAsset->GetUri());
    CheckQuerySize("MediaSpaceStatistics_test_015", MEDIA_TYPE_FILE, 1);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_015::End");
}

/**
 * @tc.number    : MediaSpaceStatistics_test_016
 * @tc.name      : get Media(image,video,audio,file) size
 * @tc.desc      : 1.on MediaSpaceStatistics_test_015, read current file size
 *                 2.copy 99 files
 *                 3.get all files size
 *                 4.Compare the new total size
 */
HWTEST_F(MediaSpaceStatisticsTest, MediaSpaceStatistics_test_016, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_016::Start");
    std::unique_ptr<FileAsset> fileAsset = GetFile(MEDIA_TYPE_FILE);
    for (int i = 0; i < COPY_TIME; i++)
    {
        string newName = "copy_MediaSpaceStatistics_test_" + std::to_string(i) + ".txt";
        int sleepSecond = 3;
        CopyFile(fileAsset->GetUri(), MEDIALIBRARY_FILE_URI, "Documents/", newName, MEDIA_TYPE_FILE, sleepSecond);
    }
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_012:: Copy finish!!!");
    CheckQuerySize("MediaSpaceStatistics_test_015", MEDIA_TYPE_FILE, COPY_TIME + 1);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_016::End");
}

HWTEST_F(MediaSpaceStatisticsTest, MediaSpaceStatistics_test_017, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_018::Start");
    const string TEST_URI = "";
    const int32_t TEST_FD = 10000;
    mediaLibraryManager->CloseAsset(TEST_URI, TEST_FD);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_018::End");
}

/**
 * @tc.number    : MediaSpaceStatistics_test_018
 * @tc.name      : get Media(image,video,audio,file) size
 * @tc.desc      : 1.delete all media
 *                 2.query media size
 *                 3.make sure size is 0
 */
HWTEST_F(MediaSpaceStatisticsTest, MediaSpaceStatistics_test_018, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_017::Start");
    ClearFile();
    MediaVolume mediaVolume;
    mediaLibraryManager->QueryTotalSize(mediaVolume);
    EXPECT_EQ(mediaVolume.GetImagesSize(), 0);
    EXPECT_EQ(mediaVolume.GetVideosSize(), 0);
    EXPECT_EQ(mediaVolume.GetAudiosSize(), 0);
    EXPECT_EQ(mediaVolume.GetFilesSize(), 0);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_017::End");
}
} // namespace Media
} // namespace OHOS
