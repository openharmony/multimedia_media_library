/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "mediascanner_unit_test.h"
#include "hilog/log.h"

using OHOS::HiviewDFX::HiLog;
using OHOS::HiviewDFX::HiLogLabel;

using namespace std;
using namespace OHOS;
using namespace OHOS::Media;
using namespace testing::ext;

namespace OHOS {
namespace Media {
MediaLibraryDataAbility g_rdbStoreTest;
int g_albumId;

namespace {
    constexpr HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN, "ApplicationMediaScannerGtest"};
    shared_ptr<IMediaScannerClient> g_msInstance = nullptr;

    int32_t g_callbackStatus(0);
    int32_t g_filescanstatus(0);
    bool g_isCallbackReceived(false);

    std::string g_callbackName("");
    std::mutex g_mutex;
    std::condition_variable g_condVar;
    const mode_t RWX_USR_GRP_OTH = 0777;
} // namespace

ApplicationCallback::ApplicationCallback(const std::string &testCaseName) : testCaseName_(testCaseName) {}

void ApplicationCallback::OnScanFinished(const int32_t status, const std::string &uri, const std::string &path)
{
    g_callbackStatus = status;
    g_callbackName = testCaseName_;
    g_isCallbackReceived = true;
    g_condVar.notify_all();
}

void MediaScannerUnitTest::WaitForCallback()
{
    std::unique_lock<std::mutex> lock(g_mutex);
    g_condVar.wait_until(lock, std::chrono::system_clock::now() + std::chrono::minutes(1),
        []() { return g_isCallbackReceived == true; });
}

void MediaScannerUnitTest::SetUpTestCase(void)
{
    g_msInstance = MediaScannerHelperFactory::CreateScannerHelper();
    if (g_msInstance == nullptr) {
        HiLog::Error(LABEL, "Scanner instance not available");
    }

    g_rdbStoreTest.InitMediaLibraryRdbStore();

    chmod("/storage/media/local/files/media_library.db", RWX_USR_GRP_OTH);
    chmod("/storage/media/local/files/media_library.db-shm", RWX_USR_GRP_OTH);
    chmod("/storage/media/local/files/media_library.db-wal", RWX_USR_GRP_OTH);
}

void MediaScannerUnitTest::TearDownTestCase(void)
{
    g_msInstance = nullptr;

    // Delete the intermediate file/folders created
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri deleteAlbumUri(abilityUri + "/" + Media::MEDIA_ALBUMOPRN + "/" + Media::MEDIA_ALBUMOPRN_DELETEALBUM);
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutInt(MEDIA_DATA_DB_ID, g_albumId);
    g_rdbStoreTest.Insert(deleteAlbumUri, valuesBucket);

    if (remove("/storage/media/local/files/media_library.db") != 0
        || remove("/storage/media/local/files/media_library.db-shm") != 0
        || remove("/storage/media/local/files/media_library.db-wal") != 0) {
        HiLog::Error(LABEL, "Db deletion failed");
    }
}

// SetUp:Execute before each test case
void MediaScannerUnitTest::SetUp() {}

void MediaScannerUnitTest::TearDown(void) {}

/*
 * Feature: MediaScanner
 * Function: Scan a directory with empty content
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerUnitTest,  mediascanner_ScanDir_test_001, TestSize.Level0)
{
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAlbumUri(abilityUri + "/" + Media::MEDIA_ALBUMOPRN + "/" + Media::MEDIA_ALBUMOPRN_CREATEALBUM);
    string path = "/storage/media/local/files/gtest_scanDir";

    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(MEDIA_DATA_DB_FILE_PATH, path);
    g_albumId = g_rdbStoreTest.Insert(createAlbumUri, valuesBucket);
    EXPECT_NE((g_albumId <= 0), true);

    EXPECT_EQ((g_msInstance != nullptr), true);
    int result;
    std::string testcaseName("mediascanner_ScanDir_test_001");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);
    result = g_msInstance->ScanDir(path, appCallback);
    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature : MediaScannerUnitTest
 * Function : Scan a image file with 0 size
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerUnitTest, mediascanner_ScanImage_Test_001, TestSize.Level0)
{
    // Create an image
    int index = DATA_ABILITY_FAIL;
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CREATEASSET);
    NativeRdb::ValuesBucket valuesBucket1;
    string path = "/storage/media/local/files/gtest_scanDir/gtest_new_ScanImgFile001.jpg";
    MediaType mediaType = MEDIA_TYPE_IMAGE;
    valuesBucket1.PutString(MEDIA_DATA_DB_FILE_PATH, path);
    valuesBucket1.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    index = g_rdbStoreTest.Insert(createAssetUri, valuesBucket1);
    string createUri = MEDIALIBRARY_IMAGE_URI + "/" + to_string(index);
    EXPECT_NE((index <= 0), true);

    // open file
    Uri openFileUri(createUri);
    int fd1 = g_rdbStoreTest.OpenFile(openFileUri, "r");
    EXPECT_NE((fd1 <= 0), true);

    // close file
    int ret = DATA_ABILITY_FAIL;
    Uri closeAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CLOSEASSET);
    NativeRdb::ValuesBucket valuesBucket2;
    valuesBucket2.PutString(MEDIA_DATA_DB_URI, createUri);
    if (fd1 >= 0) {
        ret = close(fd1);
    }
    EXPECT_NE((ret != 0), true);
    ret = g_rdbStoreTest.Insert(closeAssetUri, valuesBucket2);
    EXPECT_NE((ret != 0), true);

    // scan the file
    int result;
    std::string testcaseName("mediascanner_ScanImage_Test_001");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);

    EXPECT_EQ((g_msInstance != nullptr), true);
    result = g_msInstance->ScanFile(path, appCallback);
    EXPECT_EQ(result, g_filescanstatus);
    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature : MediaScannerUnitTest
 * Function : Scan a video file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerUnitTest, mediascanner_ScanVideo_Test_001, TestSize.Level0)
{
    // Create video file
    int index = DATA_ABILITY_FAIL;
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CREATEASSET);
    NativeRdb::ValuesBucket valuesBucket1;
    string path = "/storage/media/local/files/gtest_scanDir/gtest_new_ScanVideoFile002.mp4";
    MediaType mediaType = MEDIA_TYPE_VIDEO;
    valuesBucket1.PutString(MEDIA_DATA_DB_FILE_PATH, path);
    valuesBucket1.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    index = g_rdbStoreTest.Insert(createAssetUri, valuesBucket1);
    string createUri = MEDIALIBRARY_VIDEO_URI + "/" + to_string(index);
    EXPECT_NE((index <= 0), true);

    // open file
    Uri openFileUri(createUri);
    int fd1 = g_rdbStoreTest.OpenFile(openFileUri, "r");
    EXPECT_NE((fd1 <= 0), true);

    // close file
    int ret = DATA_ABILITY_FAIL;
    Uri closeAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CLOSEASSET);
    NativeRdb::ValuesBucket valuesBucket2;
    valuesBucket2.PutString(MEDIA_DATA_DB_URI, createUri);
    if (fd1 >= 0) {
        ret = close(fd1);
    }
    EXPECT_NE((ret != 0), true);
    ret = g_rdbStoreTest.Insert(closeAssetUri, valuesBucket2);
    EXPECT_NE((ret != 0), true);

    int result;
    std::string testcaseName("mediascanner_ScanVideo_Test_001");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);

    EXPECT_EQ((g_msInstance != nullptr), true);
    result = g_msInstance->ScanFile(path, appCallback);
    EXPECT_EQ(result, g_filescanstatus);
    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature : MediaScannerUnitTest
 * Function : Scan a audio file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerUnitTest, mediascanner_ScanAudio_Test_001, TestSize.Level0)
{
    // Create audio file
    int index = DATA_ABILITY_FAIL;
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CREATEASSET);
    NativeRdb::ValuesBucket valuesBucket1;
    string path = "/storage/media/local/files/gtest_scanDir/gtest_new_ScanAudioFile003.aac";
    MediaType mediaType = MEDIA_TYPE_AUDIO;
    valuesBucket1.PutString(MEDIA_DATA_DB_FILE_PATH, path);
    valuesBucket1.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    index = g_rdbStoreTest.Insert(createAssetUri, valuesBucket1);
    string createUri = MEDIALIBRARY_AUDIO_URI + "/" + to_string(index);
    EXPECT_NE((index <= 0), true);

    // open file
    Uri openFileUri(createUri);
    int fd1 = g_rdbStoreTest.OpenFile(openFileUri, "r");
    EXPECT_NE((fd1 <= 0), true);

    // close file
    int ret = DATA_ABILITY_FAIL;
    Uri closeAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CLOSEASSET);
    NativeRdb::ValuesBucket valuesBucket2;
    valuesBucket2.PutString(MEDIA_DATA_DB_URI, createUri);
    if (fd1 >= 0) {
        ret = close(fd1);
    }
    EXPECT_NE((ret != 0), true);
    ret = g_rdbStoreTest.Insert(closeAssetUri, valuesBucket2);
    EXPECT_NE((ret != 0), true);

    int result;
    std::string testcaseName("mediascanner_ScanAudio_Test_001");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);

    EXPECT_EQ((g_msInstance != nullptr), true);
    result = g_msInstance->ScanFile(path, appCallback);
    EXPECT_EQ(result, g_filescanstatus);
    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature : MediaScannerUnitTest
 * Function : Scan a normal text file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerUnitTest, mediascanner_ScanTextFile_Test_001, TestSize.Level0)
{
    // Create text file
    int index = DATA_ABILITY_FAIL;
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CREATEASSET);
    NativeRdb::ValuesBucket valuesBucket1;
    string path = "/storage/media/local/files/gtest_scanDir/gtest_new_ScanTextFile004.txt";
    MediaType mediaType = MEDIA_TYPE_FILE;
    valuesBucket1.PutString(MEDIA_DATA_DB_FILE_PATH, path);
    valuesBucket1.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    index = g_rdbStoreTest.Insert(createAssetUri, valuesBucket1);
    string createUri = MEDIALIBRARY_FILE_URI + "/" + to_string(index);
    EXPECT_NE((index <= 0), true);

    // open file
    Uri openFileUri(createUri);
    int fd1 = g_rdbStoreTest.OpenFile(openFileUri, "w");
    EXPECT_NE((fd1 <= 0), true);

    // Write into the file
    if (fd1 > 0) {
        string content = "This is a dummy text file";
        int sz = write(fd1, (void *)(content.c_str()), content.length());
        EXPECT_EQ((sz >= 0), true);
    }

    // close file
    int ret = DATA_ABILITY_FAIL;
    Uri closeAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CLOSEASSET);
    NativeRdb::ValuesBucket valuesBucket2;
    valuesBucket2.PutString(MEDIA_DATA_DB_URI, createUri);
    if (fd1 >= 0) {
        ret = close(fd1);
    }
    EXPECT_NE((ret != 0), true);
    ret = g_rdbStoreTest.Insert(closeAssetUri, valuesBucket2);
    EXPECT_NE((ret != 0), true);

    int result;
    std::string testcaseName("mediascanner_ScanTextFile_Test_001");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);

    EXPECT_EQ((g_msInstance != nullptr), true);
    result = g_msInstance->ScanFile(path, appCallback);
    EXPECT_EQ(result, g_filescanstatus);
    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature : MediaScannerUnitTest
 * Function : Scan a hidden file
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : NA
 */
HWTEST_F(MediaScannerUnitTest, mediascanner_ScanHiddenFile_Test_001, TestSize.Level0)
{
    // Create  hidden file
    int index = DATA_ABILITY_FAIL;
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CREATEASSET);
    NativeRdb::ValuesBucket valuesBucket1;
    string path = "/storage/media/local/files/gtest_scanDir/.hiddenFile";
    MediaType mediaType = MEDIA_TYPE_FILE;
    valuesBucket1.PutString(MEDIA_DATA_DB_FILE_PATH, path);
    valuesBucket1.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    index = g_rdbStoreTest.Insert(createAssetUri, valuesBucket1);
    EXPECT_EQ((index == 0), true);

    int result;
    std::string testcaseName("mediascanner_ScanHiddenFile_Test_001");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);

    EXPECT_EQ((g_msInstance != nullptr), true);
    result = g_msInstance->ScanFile(path, appCallback);
    EXPECT_EQ(result, g_filescanstatus);
    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, ERR_NOT_ACCESSIBLE);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a directory with image, video, audio and other type of files
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerUnitTest,  mediascanner_ScanDir_test_002, TestSize.Level0)
{
    string path = "/storage/media/local/files/gtest_scanDir";
    int result;
    std::string testcaseName("mediascanner_ScanDir_test_002");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);

    EXPECT_EQ((g_msInstance != nullptr), true);
    result = g_msInstance->ScanDir(path, appCallback);
    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a directory with .nomedia file
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerUnitTest,  mediascanner_ScanDir_Nomedia_test_001, TestSize.Level0)
{
    // Create a folder which will contain .nomedia file
    int index = DATA_ABILITY_FAIL;
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAlbumUri(abilityUri + "/" + Media::MEDIA_ALBUMOPRN + "/" + Media::MEDIA_ALBUMOPRN_CREATEALBUM);
    string path = "/storage/media/local/files/gtest_scanDir/FolderWithNomedia";
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(MEDIA_DATA_DB_FILE_PATH, path);
    int albumId = g_rdbStoreTest.Insert(createAlbumUri, valuesBucket);
    EXPECT_NE((albumId <= 0), true);

    // Create a .nomedia file inside the newly created folder
    Uri createAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CREATEASSET);
    NativeRdb::ValuesBucket valuesBucket1;
    string filepath = "/storage/media/local/files/gtest_scanDir/FolderWithNomedia/.nomedia";
    MediaType mediaType = MEDIA_TYPE_FILE;
    valuesBucket1.PutString(MEDIA_DATA_DB_FILE_PATH, filepath);
    valuesBucket1.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    index = g_rdbStoreTest.Insert(createAssetUri, valuesBucket1);
    EXPECT_EQ((index == 0), true);

    // Scan the hidden folder now
    int result;
    std::string testcaseName("mediascanner_ScanDir_Nomedia_test_001");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);

    EXPECT_EQ((g_msInstance != nullptr), true);
    result = g_msInstance->ScanDir(path, appCallback);
    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, ERR_NOT_ACCESSIBLE);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a directory with path provided as relative, must convert to canonical form
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerUnitTest,  mediascanner_ScanDir_CononicalPathtest_001, TestSize.Level0)
{
    string path = "/storage/media/local/files/gtest_scanDir/FolderWithNomedia/..";
    int result;
    std::string testcaseName("mediascanner_ScanDir_CononicalPathtest_001");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);

    EXPECT_EQ((g_msInstance != nullptr), true);
    result = g_msInstance->ScanDir(path, appCallback);
    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a directory which is hidden (starts with a .)
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerUnitTest,  mediascanner_ScanDir_HiddenDirtest_001, TestSize.Level0)
{
    // Create a folder which starts with a .
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAlbumUri(abilityUri + "/" + Media::MEDIA_ALBUMOPRN + "/" + Media::MEDIA_ALBUMOPRN_CREATEALBUM);
    string path = "/storage/media/local/files/gtest_scanDir/.HiddenFolder";
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(MEDIA_DATA_DB_FILE_PATH, path);
    int albumId = g_rdbStoreTest.Insert(createAlbumUri, valuesBucket);
    EXPECT_EQ((albumId == 0), true);

    int result;
    std::string testcaseName("mediascanner_ScanDir_HiddenDirtest_001");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);

    EXPECT_EQ((g_msInstance != nullptr), true);
    result = g_msInstance->ScanDir(path, appCallback);
    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, ERR_NOT_ACCESSIBLE);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a directory which has only folder and no files
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerUnitTest,  mediascanner_ScanDir_OnlyFoldersAsContent_001, TestSize.Level0)
{
    // Create a folder which will contain only folders
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri createAlbumUri(abilityUri + "/" + Media::MEDIA_ALBUMOPRN + "/" + Media::MEDIA_ALBUMOPRN_CREATEALBUM);
    string path = "/storage/media/local/files/gtest_scanDir/DirWithOnlyFolders";
    NativeRdb::ValuesBucket valuesBucket1;
    valuesBucket1.PutString(MEDIA_DATA_DB_FILE_PATH, path);
    int albumId1 = g_rdbStoreTest.Insert(createAlbumUri, valuesBucket1);
    EXPECT_NE((albumId1 <= 0), true);

    string path2 = "/storage/media/local/files/gtest_scanDir/DirWithOnlyFolders/Folder1";
    NativeRdb::ValuesBucket valuesBucket2;
    valuesBucket2.PutString(MEDIA_DATA_DB_FILE_PATH, path2);
    int albumId2 = g_rdbStoreTest.Insert(createAlbumUri, valuesBucket2);
    EXPECT_NE((albumId2 <= 0), true);

    string path3 = "/storage/media/local/files/gtest_scanDir/DirWithOnlyFolders/Folder2";
    NativeRdb::ValuesBucket valuesBucket3;
    valuesBucket3.PutString(MEDIA_DATA_DB_FILE_PATH, path3);
    int albumId3 = g_rdbStoreTest.Insert(createAlbumUri, valuesBucket3);
    EXPECT_NE((albumId3 <= 0), true);

    int result;
    std::string testcaseName("mediascanner_ScanDir_OnlyFoldersAsContent_001");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);

    EXPECT_EQ((g_msInstance != nullptr), true);
    result = g_msInstance->ScanDir(path, appCallback);
    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}

/*
 * Feature: MediaScanner
 * Function: Scan a directory with various file types (including hidden file), hidden and normal folders
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaScannerUnitTest,  mediascanner_ScanDir_RecursiveScan_001, TestSize.Level0)
{
    string path = "/storage/media/local/files/gtest_scanDir";
    int result;
    std::string testcaseName("mediascanner_ScanDir_RecursiveScan_001");
    g_isCallbackReceived = false;
    g_callbackStatus = -1;
    g_callbackName = "";
    auto appCallback = make_shared<ApplicationCallback>(testcaseName);

    EXPECT_EQ((g_msInstance != nullptr), true);
    result = g_msInstance->ScanDir(path, appCallback);
    EXPECT_EQ(result, g_filescanstatus);

    if (result == 0) {
        // Wait here for callback. If not callback for 2 mintues, will skip this step
        WaitForCallback();
        EXPECT_EQ(g_callbackStatus, g_filescanstatus);
        EXPECT_STREQ(g_callbackName.c_str(), testcaseName.c_str());
    }
}
} // namespace Media
} // namespace OHOS
