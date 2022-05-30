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

#include "media_spacestatistics_test.h"
#include "hilog/log.h"
#include "media_log.h"

using OHOS::HiviewDFX::HiLog;
using OHOS::HiviewDFX::HiLogLabel;

using namespace std;
using namespace OHOS;
using namespace OHOS::Media;
using namespace testing::ext;
using namespace OHOS::NativeRdb;

/**
 * @FileName MediaSpaceStatistics_test
 * @Desc Media space statistics function test
 *
 */
namespace OHOS {
namespace Media {
std::shared_ptr<AppExecFwk::DataAbilityHelper> sMediaDataHelper_ = nullptr;

void MediaSpaceStatistics_test::WaitForCallback()
{
}

void MediaSpaceStatistics_test::SetUpTestCase(void)
{
}

void MediaSpaceStatistics_test::TearDownTestCase(void)
{
    sMediaDataHelper_ = nullptr;
}

// SetUp:Execute before each test case
void MediaSpaceStatistics_test::SetUp() {}

void MediaSpaceStatistics_test::TearDown(void) {}

int uid = 5010;
int64_t g_imageSize = 0;
int64_t g_videoSize = 0;
int64_t g_audioSize = 0;
int64_t g_fileSize = 0;

MediaLibraryManager* mediaLibraryManager = MediaLibraryManager::GetMediaLibraryManager();

void CreateDataAHelper(int32_t systemAbilityId)
{
    MEDIA_INFO_LOG("CreateDataAHelper::CreateDataAHelper");
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        MEDIA_ERR_LOG("CreateDataAHelper:: Get system ability mgr failed.");
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    while (remoteObj == nullptr) {
        MEDIA_ERR_LOG("CreateDataAHelper:: GetSystemAbility Service Failed.");
    }
    mediaLibraryManager->InitMediaLibraryManager(remoteObj);
    MEDIA_INFO_LOG("CreateDataAHelper:: InitMediaLibraryManager success~!");

    if (sMediaDataHelper_ == nullptr) {
        const sptr<IRemoteObject> &token = remoteObj;
        string strUri = MEDIALIBRARY_DATA_URI;
        sMediaDataHelper_ = AppExecFwk::DataAbilityHelper::Creator(token, make_shared<Uri>(strUri));
    }
}

std::shared_ptr<AppExecFwk::DataAbilityHelper> GetMediaDataHelper()
{
    if (sMediaDataHelper_ == nullptr) {
        CreateDataAHelper(uid);
    }
    if (sMediaDataHelper_ == nullptr) {
        MEDIA_ERR_LOG("GetMediaDataHelper ::sMediaDataHelper_ is nullptr");
    }
    return sMediaDataHelper_;
}


void CopyFile(std::string srcUri, std::string baseURI, std::string targetPath, std::string newName, int sleepSecond){
    MEDIA_INFO_LOG("CopyFile:: start Copy sleepSecond[%d] file: %s", sleepSecond, newName.c_str());
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = GetMediaDataHelper();
    Uri openFileUri(srcUri);
    int32_t srcFd = helper->OpenFile(openFileUri, MEDIA_FILEMODE_READWRITE);
    EXPECT_NE(srcFd <= 0, true);

    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CREATEASSET);
    NativeRdb::ValuesBucket valuesBucket;
    MediaType mediaType = MEDIA_TYPE_IMAGE;
    valuesBucket.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    valuesBucket.PutString(MEDIA_DATA_DB_NAME, newName);
    valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, targetPath);
    int32_t index = helper->Insert(createAssetUri, valuesBucket);
    string destUri = baseURI + "/" + to_string(index);
    Uri openFileUriDest(destUri);
    int32_t destFd = helper->OpenFile(openFileUriDest, MEDIA_FILEMODE_READWRITE);
    EXPECT_NE(destFd <= 0, true);

    int64_t srcLen = lseek(srcFd, 0, SEEK_END);
    lseek(srcFd, 0, SEEK_SET);
    char buf[srcLen];
    int32_t readRet = read(srcFd, buf, srcLen);
    int32_t resWrite = write(destFd, buf, readRet);
    if (resWrite == -1){
        EXPECT_EQ(false, true);
    }

    mediaLibraryManager->CloseAsset(srcUri, srcFd);
    mediaLibraryManager->CloseAsset(destUri, destFd);
    sleep(sleepSecond);
    MEDIA_INFO_LOG("CopyFile:: end Copy file: %s", newName.c_str());
}


/**
 * @tc.number    : MediaSpaceStatistics_test_001
 * @tc.name      : get Media image size
 * @tc.desc      : 1.push 01.jpg into the device and make sure there is only one image
 *                 2.call the method to get media size
 *                 3.compare the size
 */
HWTEST_F(MediaSpaceStatistics_test, MediaSpaceStatistics_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_001::Start");
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = GetMediaDataHelper();
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    vector<string> columns;
    DataAbilityPredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " = 3 ";
    predicates.SetWhereClause(prefix);
    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, columns, predicates);
    EXPECT_NE((resultSet == nullptr), true);

    fetchFileResult = make_unique<FetchResult>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() <= 0), true);

    unique_ptr<FileAsset> fileAsset = nullptr;
    fileAsset = fetchFileResult->GetFirstObject();
    int64_t objectSize = fileAsset->GetSize();
    g_imageSize = objectSize;
    int errorCode = DATA_ABILITY_FAIL;
    MediaVolume mediaVolume;
    errorCode = mediaLibraryManager->QueryTotalSize(mediaVolume);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_001::QueryTotalSize image size = %{public}lld", (long long)mediaVolume.GetImagesSize());
    EXPECT_EQ((mediaVolume.GetImagesSize() == objectSize), true);
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
HWTEST_F(MediaSpaceStatistics_test, MediaSpaceStatistics_test_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_002::Start");
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = GetMediaDataHelper();
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    vector<string> columns;
    DataAbilityPredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " = 3 ";
    predicates.SetWhereClause(prefix);

    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, columns, predicates);
    EXPECT_NE((resultSet == nullptr), true);

    fetchFileResult = make_unique<FetchResult>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() <= 0), true);

    unique_ptr<FileAsset> fileAsset = nullptr;
    fileAsset = fetchFileResult->GetFirstObject();
    int64_t objectSize = fileAsset->GetSize();
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_002::objectSize = %{public}lld", (long long)objectSize);
    EXPECT_NE((fileAsset == nullptr), true);

    CopyFile(fileAsset->GetUri(), MEDIALIBRARY_IMAGE_URI, "Pictures/", "copy_MediaSpaceStatistics_test.jpg", 10);

    int errorCode = DATA_ABILITY_FAIL;
    MediaVolume mediaVolume;
    errorCode = mediaLibraryManager->QueryTotalSize(mediaVolume);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_002 QueryTotalSize image size = %{public}lld", (long long)mediaVolume.GetImagesSize());
    EXPECT_EQ((mediaVolume.GetImagesSize() == 2 * objectSize), true);
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
HWTEST_F(MediaSpaceStatistics_test, MediaSpaceStatistics_test_003, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_003::Start");
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = GetMediaDataHelper();
    int errorCode = DATA_ABILITY_FAIL;
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    vector<string> columns;
    DataAbilityPredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " = 3 ";
    predicates.SetWhereClause(prefix);

    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, columns, predicates);
    EXPECT_NE((resultSet == nullptr), true);
    fetchFileResult = make_unique<FetchResult>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() < 0), true);
    unique_ptr<FileAsset> fileAsset = fetchFileResult->GetLastObject();
    if(fileAsset != nullptr) {
        Uri deleteAssetUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_DELETEASSET);
        NativeRdb::ValuesBucket valuesBucketDelete;
        MEDIA_INFO_LOG("MediaSpaceStatistics_test_003::uri :%{private}s", fileAsset->GetUri().c_str());
        valuesBucketDelete.PutString(MEDIA_DATA_DB_URI, fileAsset->GetUri());
        int retVal = helper->Insert(deleteAssetUri, valuesBucketDelete);
        EXPECT_NE((retVal < 0), true);
    }
    MediaVolume mediaVolume;
    errorCode = mediaLibraryManager->QueryTotalSize(mediaVolume);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_003 QueryTotalSize image size = %{public}lld", (long long)mediaVolume.GetImagesSize());
    EXPECT_EQ((mediaVolume.GetImagesSize() == g_imageSize), true);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_003::End");
}

/**
 * @tc.number    : MediaSpaceStatistics_test_004
 * @tc.name      : get Media image size
 * @tc.desc      : 1.on MediaSpaceStatistics_test_003, read current image size
 *                 2.copy 999 images
 *                 3.get all images size
 *                 4.Compare the new total size
 */
HWTEST_F(MediaSpaceStatistics_test, MediaSpaceStatistics_test_004, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_004::Start");
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = GetMediaDataHelper();
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    vector<string> columns;
    DataAbilityPredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " = 3 ";
    predicates.SetWhereClause(prefix);

    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, columns, predicates);
    EXPECT_NE((resultSet == nullptr), true);

    fetchFileResult = make_unique<FetchResult>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() <= 0), true);

    unique_ptr<FileAsset> fileAsset = nullptr;
    fileAsset = fetchFileResult->GetFirstObject();
    int64_t objectSize = fileAsset->GetSize();
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_004::objectSize = %{public}lld", (long long)objectSize);
    EXPECT_NE((fileAsset == nullptr), true);

    for (int i = 0; i < 99; i++)
    {
        string newName = "copy_MediaSpaceStatistics_test_" + std::to_string(i) + ".jpg";
        int sleepSecond = 0;
        if(i + 1 == 99){
            sleepSecond = 10;
        }
        CopyFile(fileAsset->GetUri(), MEDIALIBRARY_IMAGE_URI, "Pictures/", newName, sleepSecond);
    }
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_004:: Copy finish!!!");

    int errorCode = DATA_ABILITY_FAIL;
    MediaVolume mediaVolume;
    errorCode = mediaLibraryManager->QueryTotalSize(mediaVolume);
    int64_t newImageSize = mediaVolume.GetImagesSize();
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_004 QueryTotalSize image newImageSize = %{public}lld", (long long)newImageSize);
    int64_t targetSize = 100 * objectSize;
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_004 QueryTotalSize image targetSize = %{public}lld", (long long)targetSize);
    EXPECT_EQ((newImageSize == targetSize), true);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_004::End");
}



/**
 * @tc.number    : MediaSpaceStatistics_test_005
 * @tc.name      : get Media video size
 * @tc.desc      : 1.push 01.mp4 into the device and make sure there is only one video
 *                 2.call the method to get media size
 *                 3.compare the size
 */
HWTEST_F(MediaSpaceStatistics_test, MediaSpaceStatistics_test_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_005::Start");
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = GetMediaDataHelper();
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    vector<string> columns;
    DataAbilityPredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " = 4 ";
    predicates.SetWhereClause(prefix);

    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, columns, predicates);
    EXPECT_NE((resultSet == nullptr), true);

    fetchFileResult = make_unique<FetchResult>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() <= 0), true);

    unique_ptr<FileAsset> fileAsset = nullptr;
    fileAsset = fetchFileResult->GetFirstObject();
    int64_t objectSize = fileAsset->GetSize();
    g_videoSize = objectSize;
    int errorCode = DATA_ABILITY_FAIL;
    MediaVolume mediaVolume;
    errorCode = mediaLibraryManager->QueryTotalSize(mediaVolume);
    MEDIA_INFO_LOG("QueryTotalSize video size = %{public}lld", (long long)mediaVolume.GetVideosSize());
    EXPECT_EQ((mediaVolume.GetVideosSize() == objectSize), true);
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
HWTEST_F(MediaSpaceStatistics_test, MediaSpaceStatistics_test_006, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_006::Start");
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = GetMediaDataHelper();
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    vector<string> columns;
    DataAbilityPredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " = 4 ";
    predicates.SetWhereClause(prefix);

    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, columns, predicates);
    EXPECT_NE((resultSet == nullptr), true);

    fetchFileResult = make_unique<FetchResult>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() <= 0), true);

    unique_ptr<FileAsset> fileAsset = nullptr;
    fileAsset = fetchFileResult->GetFirstObject();
    int64_t objectSize = fileAsset->GetSize();
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_006::objectSize = %{public}lld", (long long)objectSize);
    EXPECT_NE((fileAsset == nullptr), true);

    CopyFile(fileAsset->GetUri(), MEDIALIBRARY_VIDEO_URI, "Videos/", "copy_MediaSpaceStatistics_test.mp4", 10);

    int errorCode = DATA_ABILITY_FAIL;
    MediaVolume mediaVolume;
    errorCode = mediaLibraryManager->QueryTotalSize(mediaVolume);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_006 QueryTotalSize video size = %{public}lld", (long long)mediaVolume.GetVideosSize());
    EXPECT_EQ((mediaVolume.GetVideosSize() == 2 * objectSize), true);

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
HWTEST_F(MediaSpaceStatistics_test, MediaSpaceStatistics_test_007, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_007::Start");
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = GetMediaDataHelper();
    int errorCode = DATA_ABILITY_FAIL;
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    vector<string> columns;
    DataAbilityPredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " = 4 ";
    predicates.SetWhereClause(prefix);

    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, columns, predicates);
    EXPECT_NE((resultSet == nullptr), true);
    fetchFileResult = make_unique<FetchResult>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() < 0), true);
    unique_ptr<FileAsset> fileAsset = fetchFileResult->GetLastObject();
    if(fileAsset != nullptr) {
        Uri deleteAssetUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_DELETEASSET);
        NativeRdb::ValuesBucket valuesBucketDelete;
        MEDIA_INFO_LOG("MediaSpaceStatistics_test_007::uri :%{private}s", fileAsset->GetUri().c_str());
        valuesBucketDelete.PutString(MEDIA_DATA_DB_URI, fileAsset->GetUri());
        int retVal = helper->Insert(deleteAssetUri, valuesBucketDelete);
        EXPECT_NE((retVal < 0), true);
    }
    MediaVolume mediaVolume;
    errorCode = mediaLibraryManager->QueryTotalSize(mediaVolume);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_007 QueryTotalSize video size = %{public}lld", (long long)mediaVolume.GetVideosSize());
    EXPECT_EQ((mediaVolume.GetVideosSize() == g_videoSize), true);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_007::End");
}

/**
 * @tc.number    : MediaSpaceStatistics_test_008
 * @tc.name      : get Media video size
 * @tc.desc      : 1.on MediaSpaceStatistics_test_007, read current video size
 *                 2.copy 999 video
 *                 3.get all videos size
 *                 4.Compare the new total size
 */
HWTEST_F(MediaSpaceStatistics_test, MediaSpaceStatistics_test_008, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_008::Start");
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = GetMediaDataHelper();
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    vector<string> columns;
    DataAbilityPredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " = 4 ";
    predicates.SetWhereClause(prefix);

    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, columns, predicates);
    EXPECT_NE((resultSet == nullptr), true);

    fetchFileResult = make_unique<FetchResult>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() <= 0), true);

    unique_ptr<FileAsset> fileAsset = nullptr;
    fileAsset = fetchFileResult->GetFirstObject();
    int64_t objectSize = fileAsset->GetSize();
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_008::objectSize = %{public}lld", (long long)objectSize);
    EXPECT_NE((fileAsset == nullptr), true);

    for (int i = 0; i < 99; i++)
    {
        string newName = "copy_MediaSpaceStatistics_test_" + std::to_string(i) + ".mp4";
        int sleepSecond = 0;
        if(i + 1 == 99){
            sleepSecond = 10;
        }
        CopyFile(fileAsset->GetUri(), MEDIALIBRARY_VIDEO_URI, "Videos/", newName, sleepSecond);
    }
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_008:: Copy finish!!!");

    int errorCode = DATA_ABILITY_FAIL;
    MediaVolume mediaVolume;
    errorCode = mediaLibraryManager->QueryTotalSize(mediaVolume);
    int64_t newVideosSize = mediaVolume.GetVideosSize();
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_008 QueryTotalSize video newVideosSize = %{public}lld", (long long)newVideosSize);
    int64_t targetSize = 100 * objectSize;
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_008 QueryTotalSize image targetSize = %{public}lld", (long long)targetSize);
    EXPECT_EQ((newVideosSize == targetSize), true);

    MEDIA_INFO_LOG("MediaSpaceStatistics_test_008::End");
}

/**
 * @tc.number    : MediaSpaceStatistics_test_009
 * @tc.name      : get Media audio size
 * @tc.desc      : 1.push 01.mp3 into the device and make sure there is only one audio
 *                 2.call the method to get media size
 *                 3.compare the size
 */
HWTEST_F(MediaSpaceStatistics_test, MediaSpaceStatistics_test_009, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_009::Start");
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = GetMediaDataHelper();
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    vector<string> columns;
    DataAbilityPredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " = 5 ";
    predicates.SetWhereClause(prefix);

    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, columns, predicates);
    EXPECT_NE((resultSet == nullptr), true);

    fetchFileResult = make_unique<FetchResult>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() <= 0), true);

    unique_ptr<FileAsset> fileAsset = nullptr;
    fileAsset = fetchFileResult->GetFirstObject();
    int64_t objectSize = fileAsset->GetSize();
    g_audioSize = objectSize;
    int errorCode = DATA_ABILITY_FAIL;
    MediaVolume mediaVolume;
    errorCode = mediaLibraryManager->QueryTotalSize(mediaVolume);
    MEDIA_INFO_LOG("QueryTotalSize audio size = %{public}lld", (long long)mediaVolume.GetAudiosSize());
    EXPECT_EQ((mediaVolume.GetAudiosSize() == objectSize), true);
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
HWTEST_F(MediaSpaceStatistics_test, MediaSpaceStatistics_test_010, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_010::Start");
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = GetMediaDataHelper();
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    vector<string> columns;
    DataAbilityPredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " = 5 ";
    predicates.SetWhereClause(prefix);

    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, columns, predicates);
    EXPECT_NE((resultSet == nullptr), true);

    fetchFileResult = make_unique<FetchResult>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() <= 0), true);

    unique_ptr<FileAsset> fileAsset = nullptr;
    fileAsset = fetchFileResult->GetFirstObject();
    int64_t objectSize = fileAsset->GetSize();
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_010::objectSize = %{public}lld", (long long)objectSize);
    EXPECT_NE((fileAsset == nullptr), true);

    CopyFile(fileAsset->GetUri(), MEDIALIBRARY_AUDIO_URI, "Audios/", "copy_MediaSpaceStatistics_test.mp3", 10);

    int errorCode = DATA_ABILITY_FAIL;
    MediaVolume mediaVolume;
    errorCode = mediaLibraryManager->QueryTotalSize(mediaVolume);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_010 QueryTotalSize audio size = %{public}lld", (long long)mediaVolume.GetAudiosSize());
    EXPECT_EQ((mediaVolume.GetAudiosSize() == 2 * objectSize), true);

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
HWTEST_F(MediaSpaceStatistics_test, MediaSpaceStatistics_test_011, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_011::Start");
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = GetMediaDataHelper();
    int errorCode = DATA_ABILITY_FAIL;
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    vector<string> columns;
    DataAbilityPredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " = 5 ";
    predicates.SetWhereClause(prefix);

    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, columns, predicates);
    EXPECT_NE((resultSet == nullptr), true);
    fetchFileResult = make_unique<FetchResult>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() < 0), true);
    unique_ptr<FileAsset> fileAsset = fetchFileResult->GetLastObject();
    if(fileAsset != nullptr) {
        Uri deleteAssetUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_DELETEASSET);
        NativeRdb::ValuesBucket valuesBucketDelete;
        MEDIA_INFO_LOG("MediaSpaceStatistics_test_011::uri :%{private}s", fileAsset->GetUri().c_str());
        valuesBucketDelete.PutString(MEDIA_DATA_DB_URI, fileAsset->GetUri());
        int retVal = helper->Insert(deleteAssetUri, valuesBucketDelete);
        EXPECT_NE((retVal < 0), true);
    }
    MediaVolume mediaVolume;
    errorCode = mediaLibraryManager->QueryTotalSize(mediaVolume);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_011 QueryTotalSize image size = %{public}lld", (long long)mediaVolume.GetAudiosSize());
    EXPECT_EQ((mediaVolume.GetAudiosSize() == g_audioSize), true);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_011::End");
}

/**
 * @tc.number    : MediaSpaceStatistics_test_012
 * @tc.name      : get Media audio size
 * @tc.desc      : 1.on MediaSpaceStatistics_test_011, read current audio size
 *                 2.copy 999 audios
 *                 3.get all audios size
 *                 4.Compare the new total size
 */
HWTEST_F(MediaSpaceStatistics_test, MediaSpaceStatistics_test_012, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_012::Start");
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = GetMediaDataHelper();
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    vector<string> columns;
    DataAbilityPredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " = 5 ";
    predicates.SetWhereClause(prefix);

    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, columns, predicates);
    EXPECT_NE((resultSet == nullptr), true);

    fetchFileResult = make_unique<FetchResult>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() <= 0), true);

    unique_ptr<FileAsset> fileAsset = nullptr;
    fileAsset = fetchFileResult->GetFirstObject();
    int64_t objectSize = fileAsset->GetSize();
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_012::objectSize = %{public}lld", (long long)objectSize);
    EXPECT_NE((fileAsset == nullptr), true);

    for (int i = 0; i < 99; i++)
    {
        string newName = "copy_MediaSpaceStatistics_test_" + std::to_string(i) + ".mp3";
        int sleepSecond = 0;
        if(i + 1 == 99){
            sleepSecond = 10;
        }
        CopyFile(fileAsset->GetUri(), MEDIALIBRARY_AUDIO_URI, "Audios/", newName, sleepSecond);
    }
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_012:: Copy finish!!!");

    int errorCode = DATA_ABILITY_FAIL;
    MediaVolume mediaVolume;
    errorCode = mediaLibraryManager->QueryTotalSize(mediaVolume);
    int64_t newAudiosSize = mediaVolume.GetAudiosSize();
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_008 QueryTotalSize video newAudiosSize = %{public}lld", (long long)newAudiosSize);
    int64_t targetSize = 100 * objectSize;
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_008 QueryTotalSize image targetSize = %{public}lld", (long long)targetSize);
    EXPECT_EQ((newAudiosSize == targetSize), true);

    MEDIA_INFO_LOG("MediaSpaceStatistics_test_012::End");
}

/**
 * @tc.number    : MediaSpaceStatistics_test_013
 * @tc.name      : get Media file size
 * @tc.desc      : 1.push 01.txt into the device and make sure there is only one file
 *                 2.call the method to get media size
 *                 3.compare the size
 */
HWTEST_F(MediaSpaceStatistics_test, MediaSpaceStatistics_test_013, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_013::Start");
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = GetMediaDataHelper();
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    vector<string> columns;
    DataAbilityPredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " = 1 ";
    predicates.SetWhereClause(prefix);

    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, columns, predicates);
    EXPECT_NE((resultSet == nullptr), true);

    fetchFileResult = make_unique<FetchResult>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() <= 0), true);

    unique_ptr<FileAsset> fileAsset = nullptr;
    fileAsset = fetchFileResult->GetFirstObject();
    int64_t objectSize = fileAsset->GetSize();
    g_fileSize = objectSize;
    int errorCode = DATA_ABILITY_FAIL;
    MediaVolume mediaVolume;
    errorCode = mediaLibraryManager->QueryTotalSize(mediaVolume);
    MEDIA_INFO_LOG("QueryTotalSize file size = %{public}lld", (long long)mediaVolume.GetFilesSize());
    EXPECT_EQ((mediaVolume.GetFilesSize() == objectSize), true);
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
HWTEST_F(MediaSpaceStatistics_test, MediaSpaceStatistics_test_014, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_014::Start");
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = GetMediaDataHelper();
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    vector<string> columns;
    DataAbilityPredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " = 1 ";
    predicates.SetWhereClause(prefix);

    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, columns, predicates);
    EXPECT_NE((resultSet == nullptr), true);

    fetchFileResult = make_unique<FetchResult>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() <= 0), true);

    unique_ptr<FileAsset> fileAsset = nullptr;
    fileAsset = fetchFileResult->GetFirstObject();
    int64_t objectSize = fileAsset->GetSize();
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_014::objectSize = %{public}lld", (long long)objectSize);
    EXPECT_NE((fileAsset == nullptr), true);

    CopyFile(fileAsset->GetUri(), MEDIALIBRARY_FILE_URI, "Documents/", "copy_MediaSpaceStatistics_test.txt", 10);

    int errorCode = DATA_ABILITY_FAIL;
    MediaVolume mediaVolume;
    errorCode = mediaLibraryManager->QueryTotalSize(mediaVolume);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_014 QueryTotalSize files size = %{public}lld", (long long)mediaVolume.GetFilesSize());
    EXPECT_EQ((mediaVolume.GetFilesSize() == 2 * objectSize), true);

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
HWTEST_F(MediaSpaceStatistics_test, MediaSpaceStatistics_test_015, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_015::Start");
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = GetMediaDataHelper();
    int errorCode = DATA_ABILITY_FAIL;
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    vector<string> columns;
    DataAbilityPredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " = 1 ";
    predicates.SetWhereClause(prefix);

    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, columns, predicates);
    EXPECT_NE((resultSet == nullptr), true);
    fetchFileResult = make_unique<FetchResult>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() < 0), true);
    unique_ptr<FileAsset> fileAsset = fetchFileResult->GetLastObject();
    if(fileAsset != nullptr) {
        Uri deleteAssetUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_DELETEASSET);
        NativeRdb::ValuesBucket valuesBucketDelete;
        MEDIA_INFO_LOG("MediaSpaceStatistics_test_015::uri :%{private}s", fileAsset->GetUri().c_str());
        valuesBucketDelete.PutString(MEDIA_DATA_DB_URI, fileAsset->GetUri());
        int retVal = helper->Insert(deleteAssetUri, valuesBucketDelete);
        EXPECT_NE((retVal < 0), true);
    }
    MediaVolume mediaVolume;
    errorCode = mediaLibraryManager->QueryTotalSize(mediaVolume);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_015 QueryTotalSize files size = %{public}lld", (long long)mediaVolume.GetFilesSize());
    EXPECT_EQ((mediaVolume.GetFilesSize() == g_fileSize), true);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_015::End");
}

/**
 * @tc.number    : MediaSpaceStatistics_test_016
 * @tc.name      : get Media(image,video,audio,file) size
 * @tc.desc      : 1.on MediaSpaceStatistics_test_015, read current file size
 *                 2.copy 999 files
 *                 3.get all files size
 *                 4.Compare the new total size
 */
HWTEST_F(MediaSpaceStatistics_test, MediaSpaceStatistics_test_016, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_016::Start");
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = GetMediaDataHelper();
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    vector<string> columns;
    DataAbilityPredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " = 1 ";
    predicates.SetWhereClause(prefix);

    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, columns, predicates);
    EXPECT_NE((resultSet == nullptr), true);

    fetchFileResult = make_unique<FetchResult>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() <= 0), true);

    unique_ptr<FileAsset> fileAsset = nullptr;
    fileAsset = fetchFileResult->GetFirstObject();
    int64_t objectSize = fileAsset->GetSize();
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_016::objectSize = %{public}lld", (long long)objectSize);
    EXPECT_NE((fileAsset == nullptr), true);

    for (int i = 0; i < 99; i++)
    {
        string newName = "copy_MediaSpaceStatistics_test_" + std::to_string(i) + ".txt";
        int sleepSecond = 0;
        if(i + 1 == 99){
            sleepSecond = 10;
        }
        CopyFile(fileAsset->GetUri(), MEDIALIBRARY_FILE_URI, "Documents/", newName, sleepSecond);
    }
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_012:: Copy finish!!!");

    int errorCode = DATA_ABILITY_FAIL;
    MediaVolume mediaVolume;
    errorCode = mediaLibraryManager->QueryTotalSize(mediaVolume);
    int64_t newFilesSize = mediaVolume.GetFilesSize();
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_016 QueryTotalSize video newFilesSize = %{public}lld", (long long)newFilesSize);
    int64_t targetSize = 100 * objectSize;
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_016 QueryTotalSize image targetSize = %{public}lld", (long long)targetSize);
    EXPECT_EQ((newFilesSize == targetSize), true);

    MEDIA_INFO_LOG("MediaSpaceStatistics_test_016::End");
}

/**
 * @tc.number    : MediaSpaceStatistics_test_017
 * @tc.name      : get Media(image,video,audio,file) size
 * @tc.desc      : 1.delete all media
 *                 2.query media size
 *                 3.make sure size is 0
 */
HWTEST_F(MediaSpaceStatistics_test, MediaSpaceStatistics_test_017, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_017::Start");
    std::shared_ptr<AppExecFwk::DataAbilityHelper> helper = GetMediaDataHelper();
    int errorCode = DATA_ABILITY_FAIL;
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    vector<string> columns;
    DataAbilityPredicates predicates;
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> 8 ";
    predicates.SetWhereClause(prefix);

    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, columns, predicates);
    EXPECT_NE((resultSet == nullptr), true);
    fetchFileResult = make_unique<FetchResult>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() < 0), true);
    unique_ptr<FileAsset> fileAsset = fetchFileResult->GetFirstObject();
    while (fileAsset != nullptr) {
        Uri deleteAssetUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_DELETEASSET);
        NativeRdb::ValuesBucket valuesBucketDelete;
        MEDIA_INFO_LOG("MediaSpaceStatistics_test_017::uri :%{private}s", fileAsset->GetUri().c_str());
        valuesBucketDelete.PutString(MEDIA_DATA_DB_URI, fileAsset->GetUri());
        int retVal = helper->Insert(deleteAssetUri, valuesBucketDelete);
        EXPECT_NE((retVal < 0), true);

        fileAsset = fetchFileResult->GetNextObject();
    }
    MediaVolume mediaVolume;
    errorCode = mediaLibraryManager->QueryTotalSize(mediaVolume);
    EXPECT_EQ((mediaVolume.GetImagesSize() == 0), true);
    EXPECT_EQ((mediaVolume.GetVideosSize() == 0), true);
    EXPECT_EQ((mediaVolume.GetAudiosSize() == 0), true);
    EXPECT_EQ((mediaVolume.GetFilesSize() == 0), true);
    MEDIA_INFO_LOG("MediaSpaceStatistics_test_017::End");
}

} // namespace Media
} // namespace OHOS
