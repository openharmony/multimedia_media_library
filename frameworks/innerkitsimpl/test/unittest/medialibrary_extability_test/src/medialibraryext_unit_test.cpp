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
#define MLOG_TAG "FileExtUnitTest"

#include "medialibraryext_unit_test.h"

#include <unistd.h>

#include "iservice_registry.h"
#include "media_library_manager.h"
#include "file_access_helper.h"
#include "datashare_helper.h"
#include "media_log.h"
#include "file_access_framework_errno.h"
#include "medialibrary_errno.h"
#include "result_set_utils.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::Media;
using namespace testing::ext;
int g_uid = 5003;

namespace OHOS {
namespace Media {
namespace {
    std::shared_ptr<DataShare::DataShareHelper> g_mediaDataShareHelper;
    std::shared_ptr<FileAccessFwk::FileAccessHelper> g_mediaFileExtHelper;
    std::unique_ptr<FileAsset> g_pictures = nullptr;
    std::unique_ptr<FileAsset> g_camera = nullptr;
    std::unique_ptr<FileAsset> g_videos = nullptr;
    std::unique_ptr<FileAsset> g_documents = nullptr;
    std::unique_ptr<FileAsset> g_download = nullptr;
    const string g_distributedPrefix =
        "datashare://1d3cb099659d53b3ee15faaab3c00a8ff983382ebc8b01aabde039ed084e167b/media/";
    const string g_commonPrefix = "datashare:///media/";
    const string g_rootUri = "root";
    const string g_commonUri = "file/1";
    const string g_invalidUri = "file/test";
    const string g_invalidFileName = "te/st.jpg";
    const string g_invalidDirName = "te/st";
    const bool g_createAssetFailed = false;
} // namespace

std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper(int32_t systemAbilityId)
{
    MEDIA_INFO_LOG("CreateDataShareHelper::CreateFileExtHelper ");
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        MEDIA_INFO_LOG("CreateFileExtHelper CreateDataShareHelper Get system ability mgr failed.");
        return nullptr;
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    while (remoteObj == nullptr) {
        MEDIA_INFO_LOG("CreateFileExtHelper GetSystemAbility Service Failed.");
        return nullptr;
    }
    return DataShare::DataShareHelper::Creator(remoteObj, MEDIALIBRARY_DATA_URI);
}

std::shared_ptr<FileAccessFwk::FileAccessHelper> CreateFileExtHelper(int32_t systemAbilityId)
{
    MEDIA_INFO_LOG("DataMedialibraryRdbHelper::CreateFileExtHelper ");
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        MEDIA_INFO_LOG("DataMedialibraryRdbHelper::CreateFileExtHelper Get system ability mgr failed.");
        return nullptr;
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    while (remoteObj == nullptr) {
        MEDIA_INFO_LOG("DataMedialibraryRdbHelper::CreateFileExtHelper GetSystemAbility Service Failed.");
        return nullptr;
    }
    AppExecFwk::Want want;
    want.SetElementName("com.ohos.medialibrary.medialibrarydata", "FileExtensionAbility");
    vector<AAFwk::Want> wants {want};
    FileAccessFwk::FileAccessHelper::GetRegisterFileAccessExtAbilityInfo();
    return FileAccessFwk::FileAccessHelper::Creator(remoteObj, wants);
}

bool GetFileAsset(const int index, unique_ptr<FileAsset> &fileAsset)
{
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    vector<string> columns;
    DataShare::DataSharePredicates predicates;
    string selections = MEDIA_DATA_DB_ID + " = " + to_string(index);
    predicates.SetWhereClause(selections);
    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    auto resultSet = helper->Query(queryFileUri, predicates, columns);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("GetFileAsset::resultSet == nullptr");
        return false;
    }
    unique_ptr<FetchResult> fetchFileResult = make_unique<FetchResult>(move(resultSet));
    if (fetchFileResult->GetCount() <= 0) {
        MEDIA_ERR_LOG("GetFileAsset::GetCount <= 0");
        return false;
    }
    fileAsset = fetchFileResult->GetFirstObject();
    if (fileAsset == nullptr) {
        MEDIA_ERR_LOG("GetFileAsset::fileAsset = nullptr.");
        return false;
    }
    return true;
}

bool CreateAlbum(string displayName, unique_ptr<FileAsset> &parentAlbumAsset, unique_ptr<FileAsset> &albumAsset)
{
    MEDIA_INFO_LOG("CreateAlbum::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    Uri createAlbumUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_ALBUMOPRN + "/" + MEDIA_ALBUMOPRN_CREATEALBUM);
    string dirPath;
    if (parentAlbumAsset == nullptr) {
        dirPath = ROOT_MEDIA_DIR + displayName;
    } else {
        dirPath = parentAlbumAsset->GetPath() + "/" + displayName;
    }
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_FILE_PATH, dirPath);
    valuesBucket.Put(MEDIA_DATA_DB_NAME, displayName);
    auto retVal = helper->Insert(createAlbumUri, valuesBucket);
    MEDIA_INFO_LOG("CreateAlbum:: %{public}s, retVal: %{public}d", dirPath.c_str(), retVal);
    EXPECT_EQ((retVal > 0), true);
    if (retVal <= 0) {
        MEDIA_ERR_LOG("CreateAlbum::create failed, %{public}s", dirPath.c_str());
        return false;
    }
    if (!GetFileAsset(retVal, albumAsset)) {
        MEDIA_ERR_LOG("CreateAlbum::GetFileAsset failed, %{public}s", dirPath.c_str());
        return false;
    }
    return true;
}

bool CreateFile(string displayName, unique_ptr<FileAsset> &parentAlbumAsset, unique_ptr<FileAsset> &fileAsset,
    MediaType mediaType = MEDIA_TYPE_IMAGE)
{
    MEDIA_INFO_LOG("CreateFile::Start");
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    Uri createAssetUri(MEDIALIBRARY_DATA_URI + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_CREATEASSET);
    DataShare::DataShareValuesBucket valuesBucket;
    string relativePath = parentAlbumAsset->GetRelativePath() + parentAlbumAsset->GetDisplayName() + "/";
    valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    valuesBucket.Put(MEDIA_DATA_DB_NAME, displayName);
    valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    int32_t retVal = helper->Insert(createAssetUri, valuesBucket);
    MEDIA_INFO_LOG("CreateFile:: %{public}s, retVal: %{public}d", (relativePath + displayName).c_str(), retVal);
    EXPECT_EQ((retVal > 0), true);
    if (retVal <= 0) {
        MEDIA_ERR_LOG("CreateFile::create failed, %{public}s", (relativePath + displayName).c_str());
        return false;
    }
    if (!GetFileAsset(retVal, fileAsset)) {
        MEDIA_ERR_LOG("CreateFile::GetFileAsset failed, %{public}s", (relativePath + displayName).c_str());
        return false;
    }
    return true;
}

void CreateRootDir()
{
    unique_ptr<FileAsset> rootAsset = nullptr;
    CreateAlbum("Pictures", rootAsset, g_pictures);
    CreateAlbum("Camera", rootAsset, g_camera);
    CreateAlbum("Videos", rootAsset, g_videos);
    CreateAlbum("Documents", rootAsset, g_documents);
    CreateAlbum("Download", rootAsset, g_download);
}

void MediaLibraryExtUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("SetUpTestCase invoked");
    auto ret = setuid(20000000);
    MEDIA_DEBUG_LOG("setuid ret: %d", ret);
    g_mediaFileExtHelper = CreateFileExtHelper(g_uid);
    g_mediaDataShareHelper = CreateDataShareHelper(g_uid);
    if (g_mediaFileExtHelper == nullptr) {
        MEDIA_DEBUG_LOG("medialibraryDataAbilityHelper fail");
        return;
    }
    if (g_mediaDataShareHelper == nullptr) {
        MEDIA_DEBUG_LOG("g_mediaDataShareHelper fail");
        return;
    }

    Uri deleteAssetUri(MEDIALIBRARY_DATA_URI);
    DataShare::DataSharePredicates predicates;
    string selections = MEDIA_DATA_DB_ID + " <> 0 ";
    predicates.SetWhereClause(selections);
    int retVal = g_mediaDataShareHelper->Delete(deleteAssetUri, predicates);
    MEDIA_INFO_LOG("SetUpTestCase Delete retVal: %{public}d", retVal);
    EXPECT_EQ((retVal >= 0), true);

    CreateRootDir();
}

void MediaLibraryExtUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("TearDownTestCase invoked");
}

// SetUp:Execute before each test case
void MediaLibraryExtUnitTest::SetUp() {}

void MediaLibraryExtUnitTest::TearDown(void) {}

bool CheckEnvironment()
{
    if (g_mediaFileExtHelper == nullptr) {
        MEDIA_ERR_LOG("g_mediaFileExtHelper == nullptr");
        EXPECT_EQ(true, false);
        return false;
    }
    if (g_mediaDataShareHelper == nullptr) {
        MEDIA_ERR_LOG("g_mediaDataShareHelper == nullptr");
        EXPECT_EQ(true, false);
        return false;
    }
    if (g_pictures == nullptr) {
        MEDIA_ERR_LOG("g_pictures == nullptr");
        EXPECT_EQ(true, false);
        return false;
    }
    return true;
}

bool IsFileExists(const string &fileName)
{
    string path = "/storage/media/100/" + fileName.substr(strlen("/storage/media/"));
    MEDIA_DEBUG_LOG("IsFileExists path %{public}s", path.c_str());
    struct stat statInfo {};
    int errCode = stat(path.c_str(), &statInfo);
    MEDIA_DEBUG_LOG("IsFileExists errCode %{public}d", errCode);
    if (errCode == SUCCESS) {
        return true;
    } else {
        return false;
    }
}

string GetRenameNewPath(const string &oldPath, const string &displayName)
{
    size_t slashIndex = oldPath.rfind('/');
    return (oldPath.substr(0, slashIndex) + "/" + displayName);
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check environment
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_CheckSetUpEnv_test_001, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    // Pictures Album has been create in setup
    MEDIA_DEBUG_LOG("medialib_CheckSetUpEnv_test_001");
    if (g_pictures == nullptr) {
        EXPECT_EQ(g_createAssetFailed, true);
    }
    EXPECT_EQ(IsFileExists(g_pictures->GetPath()), true);
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check openfile
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_OpenFile_test_001, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!CreateFile("OpenFile_test_001.jpg", g_pictures, fileAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    Uri uri(fileAsset->GetUri());
    int fd = g_mediaFileExtHelper->OpenFile(uri, O_RDWR);
    MEDIA_DEBUG_LOG("medialib_OpenFile_test_001 uri: %{public}s, fd: %{public}d", uri.ToString().c_str(), fd);
    EXPECT_EQ(fd != FileAccessFwk::ERR_IPC_ERROR, TRUE);
    if (fd != FileAccessFwk::ERR_IPC_ERROR) {
        char str[] = "Hello World!";
        int size_written = -1, size_read = -1, strLen = strlen(str);
        size_written = write(fd, str, strLen);
        if (size_written == -1) {
            MEDIA_DEBUG_LOG("medialib_OpenFile_test_001 write errno: %{public}d, errmsg: %{public}s",
                errno, strerror(errno));
        }
        EXPECT_EQ(size_written, strLen);
        memset_s(str, sizeof(str), 0, sizeof(str));
        lseek(fd, 0, SEEK_SET);
        size_read = read(fd, str, strLen);
        if (size_read == -1) {
            MEDIA_DEBUG_LOG("medialib_OpenFile_test_001 read errno: %{public}d, errmsg: %{public}s",
                errno, strerror(errno));
        }
        EXPECT_EQ(size_read, strLen);
        MEDIA_DEBUG_LOG("medialib_OpenFile_test_001 size_written: %{public}d, size_read: %{public}d",
            size_written, size_read);
    } else {
        MEDIA_DEBUG_LOG("medialib_OpenFile_test_001 OpenFile errno: %{public}d, errmsg: %{public}s",
            errno, strerror(errno));
    }
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check openfile
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_OpenFile_test_002, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    Uri uri(g_pictures->GetUri());
    MEDIA_DEBUG_LOG("medialib_OpenFile_test_002 uri %{public}s", uri.ToString().c_str());
    int fd = g_mediaFileExtHelper->OpenFile(uri, O_RDWR);
    if (fd == FileAccessFwk::ERR_IPC_ERROR) {
        MEDIA_DEBUG_LOG("medialib_OpenFile_test_002 OpenFile errno: %{public}d, errmsg: %{public}s",
            errno, strerror(errno));
    }
    EXPECT_EQ(fd, FileAccessFwk::ERR_IPC_ERROR);
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check createfile
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_CreateFile_test_001, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    unique_ptr<FileAsset> albumAsset = nullptr;
    if (!CreateAlbum("CreateFile_test_001", g_pictures, albumAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    Uri parentUri(albumAsset->GetUri());
    Uri newUri("");
    string displayName = "CreateFile001.jpg";
    string filePath = albumAsset->GetPath() + "/" + displayName;
    MEDIA_DEBUG_LOG("medialib_CreateFile_test_001 parentUri: %{public}s, displayName: %{public}s, filePath: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str(), filePath.c_str());
    EXPECT_EQ(IsFileExists(filePath), false);
    int32_t ret = g_mediaFileExtHelper->CreateFile(parentUri, displayName, newUri);
    EXPECT_EQ(ret, E_SUCCESS);
    EXPECT_EQ(IsFileExists(filePath), true);
    MEDIA_DEBUG_LOG("medialib_CreateFile_test_001 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check createfile
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_CreateFile_test_002, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    unique_ptr<FileAsset> albumAsset = nullptr;
    if (!CreateAlbum("CreateFile_test_002", g_pictures, albumAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    Uri parentUri(albumAsset->GetUri());
    Uri newUri("");
    string displayName = g_invalidFileName;
    MEDIA_DEBUG_LOG("medialib_CreateFile_test_002 parentUri: %{public}s, displayName: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str());
    int32_t ret = g_mediaFileExtHelper->CreateFile(parentUri, displayName, newUri);
    EXPECT_EQ(ret, FileAccessFwk::ERR_IPC_ERROR);
    MEDIA_DEBUG_LOG("medialib_CreateFile_test_002 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check createfile
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_CreateFile_test_003, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    Uri parentUri(g_commonPrefix + g_invalidUri);
    Uri newUri("");
    string displayName = "CreateFile001.jpg";
    MEDIA_DEBUG_LOG("medialib_CreateFile_test_003 parentUri: %{public}s, displayName: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str());
    int32_t ret = g_mediaFileExtHelper->CreateFile(parentUri, displayName, newUri);
    EXPECT_EQ(ret, FileAccessFwk::ERR_IPC_ERROR);
    MEDIA_DEBUG_LOG("medialib_CreateFile_test_003 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check createfile
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_CreateFile_test_004, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    Uri parentUri(g_distributedPrefix + g_commonUri);
    Uri newUri("");
    string displayName = "CreateFile001.jpg";
    MEDIA_DEBUG_LOG("medialib_CreateFile_test_004 parentUri: %{public}s, displayName: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str());
    int32_t ret = g_mediaFileExtHelper->CreateFile(parentUri, displayName, newUri);
    EXPECT_EQ(ret, FileAccessFwk::ERR_IPC_ERROR);
    MEDIA_DEBUG_LOG("medialib_CreateFile_test_004 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check createfile
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_CreateFile_test_005, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    unique_ptr<FileAsset> albumAsset = nullptr;
    if (!CreateAlbum("CreateFile_test_005", g_pictures, albumAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!CreateFile("CreateFile_test_005.jpg", albumAsset, fileAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    Uri parentUri(albumAsset->GetUri());
    Uri newUri("");
    string displayName = "CreateFile_test_005.jpg";
    MEDIA_DEBUG_LOG("medialib_CreateFile_test_005 parentUri: %{public}s, displayName: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str());
    int32_t ret = g_mediaFileExtHelper->CreateFile(parentUri, displayName, newUri);
    EXPECT_EQ(ret, FileAccessFwk::ERR_IPC_ERROR);
    MEDIA_DEBUG_LOG("medialib_CreateFile_test_005 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check mkdir
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_Mkdir_test_001, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    Uri parentUri(g_commonPrefix + g_rootUri);
    string displayName = "Audios";
    string dirPath = ROOT_MEDIA_DIR + displayName;
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_001 parentUri: %{public}s, displayName: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str());
    EXPECT_EQ(IsFileExists(dirPath), false);
    Uri newUri("");
    int32_t ret = g_mediaFileExtHelper->Mkdir(parentUri, displayName, newUri);
    EXPECT_EQ(IsFileExists(dirPath), true);
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_001 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check mkdir
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_Mkdir_test_002, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    Uri parentUri(g_distributedPrefix + g_rootUri);
    string displayName = "Mkdir_test_002";
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_002 parentUri: %{public}s, displayName: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str());
    Uri newUri("");
    int32_t ret = g_mediaFileExtHelper->Mkdir(parentUri, displayName, newUri);
    EXPECT_EQ(ret, FileAccessFwk::ERR_IPC_ERROR);
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_002 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check mkdir
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_Mkdir_test_003, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    Uri parentUri(g_commonPrefix + g_rootUri);
    string displayName = "Mkdir_test_003";
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_003 parentUri: %{public}s, displayName: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str());
    Uri newUri("");
    int32_t ret = g_mediaFileExtHelper->Mkdir(parentUri, displayName, newUri);
    EXPECT_EQ(ret, FileAccessFwk::ERR_IPC_ERROR);
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_003 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check mkdir
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_Mkdir_test_004, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    Uri parentUri(g_pictures->GetUri());
    string displayName = "Mkdir_test_004";
    string dirPath = g_pictures->GetPath() + "/" + displayName;
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_004 parentUri: %{public}s, displayName: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str());
    EXPECT_EQ(IsFileExists(dirPath), false);
    Uri newUri("");
    int32_t ret = g_mediaFileExtHelper->Mkdir(parentUri, displayName, newUri);
    EXPECT_EQ(IsFileExists(dirPath), true);
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_004 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check mkdir
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_Mkdir_test_005, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    Uri parentUri(g_commonPrefix + g_invalidUri);
    string displayName = "Mkdir_test_005";
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_005 parentUri: %{public}s, displayName: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str());
    Uri newUri("");
    int32_t ret = g_mediaFileExtHelper->Mkdir(parentUri, displayName, newUri);
    EXPECT_EQ(ret, FileAccessFwk::ERR_IPC_ERROR);
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_005 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check mkdir
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_Mkdir_test_006, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    Uri parentUri(g_distributedPrefix + g_commonUri);
    string displayName = "Mkdir_test_006";
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_006 parentUri: %{public}s, displayName: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str());
    Uri newUri("");
    int32_t ret = g_mediaFileExtHelper->Mkdir(parentUri, displayName, newUri);
    EXPECT_EQ(ret, FileAccessFwk::ERR_IPC_ERROR);
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_006 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check mkdir
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_Mkdir_test_007, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    Uri parentUri(g_pictures->GetUri());
    string displayName = g_invalidDirName;
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_007 parentUri: %{public}s, displayName: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str());
    Uri newUri("");
    int32_t ret = g_mediaFileExtHelper->Mkdir(parentUri, displayName, newUri);
    EXPECT_EQ(ret, FileAccessFwk::ERR_IPC_ERROR);
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_007 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check mkdir
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_Mkdir_test_008, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    unique_ptr<FileAsset> albumAsset = nullptr;
    if (!CreateAlbum("Mkdir_test_008", g_pictures, albumAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    Uri parentUri(g_pictures->GetUri());
    string displayName = "Mkdir_test_008";
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_008 parentUri: %{public}s, displayName: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str());
    Uri newUri("");
    int32_t ret = g_mediaFileExtHelper->Mkdir(parentUri, displayName, newUri);
    EXPECT_EQ(ret, FileAccessFwk::ERR_IPC_ERROR);
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_008 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check delete file
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_Delete_test_001, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    unique_ptr<FileAsset> albumAsset = nullptr;
    if (!CreateAlbum("Delete_test_001", g_pictures, albumAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!CreateFile("Delete_test_001.jpg", albumAsset, fileAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    Uri sourceUri(fileAsset->GetUri());
    MEDIA_DEBUG_LOG("medialib_Delete_test_001 sourceUri %{public}s", sourceUri.ToString().c_str());
    EXPECT_EQ(IsFileExists(fileAsset->GetPath()), true);
    int32_t ret = g_mediaFileExtHelper->Delete(sourceUri);
    EXPECT_EQ(IsFileExists(fileAsset->GetPath()), false);
    MEDIA_DEBUG_LOG("medialib_Delete_test_001 ret: %{public}d", ret);
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check delete file
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_Delete_test_002, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    Uri sourceUri(g_distributedPrefix + g_commonUri);
    MEDIA_DEBUG_LOG("medialib_Delete_test_002 sourceUri %{public}s", sourceUri.ToString().c_str());
    int32_t ret = g_mediaFileExtHelper->Delete(sourceUri);
    EXPECT_EQ(ret, FileAccessFwk::ERR_IPC_ERROR);
    MEDIA_DEBUG_LOG("medialib_Delete_test_002 ret: %{public}d", ret);
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check move file
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_Move_test_001, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    unique_ptr<FileAsset> srcAlbumAsset = nullptr;
    if (!CreateAlbum("Move_test_001", g_pictures, srcAlbumAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    unique_ptr<FileAsset> destAlbumAsset = nullptr;
    if (!CreateAlbum("Move_test_001_dst", g_pictures, destAlbumAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!CreateFile("Move_test_001.jpg", srcAlbumAsset, fileAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    Uri sourceUri(fileAsset->GetUri());
    Uri targetUri(destAlbumAsset->GetUri());
    Uri newUri("");
    MEDIA_DEBUG_LOG("medialib_Move_test_001 sourceUri: %{public}s, targetUri: %{public}s",
        sourceUri.ToString().c_str(), targetUri.ToString().c_str());
    string srcPath = fileAsset->GetPath();
    string displayName = fileAsset->GetDisplayName();
    string targetPath = destAlbumAsset->GetPath() + "/" + displayName;
    MEDIA_DEBUG_LOG("medialib_Move_test_001 srcPath: %{public}s, targetPath: %{public}s",
        srcPath.c_str(), targetPath.c_str());
    EXPECT_EQ(IsFileExists(srcPath), true);
    EXPECT_EQ(IsFileExists(targetPath), false);
    int32_t ret = g_mediaFileExtHelper->Move(sourceUri, targetUri, newUri);
    EXPECT_EQ(IsFileExists(srcPath), false);
    EXPECT_EQ(IsFileExists(targetPath), true);
    MEDIA_DEBUG_LOG("medialib_Move_test_001 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check move file
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_Move_test_002, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    unique_ptr<FileAsset> srcAlbumAsset = nullptr;
    if (!CreateAlbum("Move_test_002", g_pictures, srcAlbumAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!CreateFile("Move_test_002.jpg", srcAlbumAsset, fileAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    unique_ptr<FileAsset> destAlbumAsset = nullptr;
    if (!CreateAlbum("Move_test_002_dest", g_pictures, destAlbumAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    Uri sourceUri(srcAlbumAsset->GetUri());
    Uri targetUri(destAlbumAsset->GetUri());
    Uri newUri("");
    MEDIA_DEBUG_LOG("medialib_Move_test_002 sourceUri: %{public}s, targetUri: %{public}s",
        sourceUri.ToString().c_str(), targetUri.ToString().c_str());
    string srcPath = srcAlbumAsset->GetPath();
    string displayName = srcAlbumAsset->GetDisplayName();
    string targetPath = destAlbumAsset->GetPath() + "/" + displayName;
    MEDIA_DEBUG_LOG("medialib_Move_test_002 srcPath: %{public}s, targetPath: %{public}s",
        srcPath.c_str(), targetPath.c_str());
    EXPECT_EQ(IsFileExists(srcPath), true);
    EXPECT_EQ(IsFileExists(targetPath), false);
    int32_t ret = g_mediaFileExtHelper->Move(sourceUri, targetUri, newUri);
    EXPECT_EQ(IsFileExists(srcPath), false);
    EXPECT_EQ(IsFileExists(targetPath), true);
    MEDIA_DEBUG_LOG("medialib_Move_test_002 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check move file
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_Move_test_003, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!CreateFile("Move_test_003.jpg", g_pictures, fileAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    Uri sourceUri(fileAsset->GetUri());
    Uri targetUri(g_commonPrefix + g_invalidUri);
    Uri newUri("");
    MEDIA_DEBUG_LOG("medialib_Move_test_003 sourceUri: %{public}s, targetUri: %{public}s",
        sourceUri.ToString().c_str(), targetUri.ToString().c_str());
    int32_t ret = g_mediaFileExtHelper->Move(sourceUri, targetUri, newUri);
    EXPECT_EQ(ret, FileAccessFwk::ERR_IPC_ERROR);
    MEDIA_DEBUG_LOG("medialib_Move_test_003 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check move file
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_Move_test_004, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!CreateFile("Move_test_004.jpg", g_pictures, fileAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    Uri sourceUri(fileAsset->GetUri());
    Uri targetUri(g_distributedPrefix + g_commonUri);
    Uri newUri("");
    MEDIA_DEBUG_LOG("medialib_Move_test_004 sourceUri: %{public}s, targetUri: %{public}s",
        sourceUri.ToString().c_str(), targetUri.ToString().c_str());
    int32_t ret = g_mediaFileExtHelper->Move(sourceUri, targetUri, newUri);
    EXPECT_EQ(ret, FileAccessFwk::ERR_IPC_ERROR);
    MEDIA_DEBUG_LOG("medialib_Move_test_004 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check move file
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_Move_test_005, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    unique_ptr<FileAsset> albumAsset = nullptr;
    if (!CreateAlbum("Move_test_005_dest", g_pictures, albumAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    Uri sourceUri(g_commonPrefix + g_invalidUri);
    Uri targetUri(albumAsset->GetUri());
    Uri newUri("");
    MEDIA_DEBUG_LOG("medialib_Move_test_005 sourceUri: %{public}s, targetUri: %{public}s",
        sourceUri.ToString().c_str(), targetUri.ToString().c_str());
    int32_t ret = g_mediaFileExtHelper->Move(sourceUri, targetUri, newUri);
    EXPECT_EQ(ret, FileAccessFwk::ERR_IPC_ERROR);
    MEDIA_DEBUG_LOG("medialib_Move_test_005 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check move file
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_Move_test_006, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    unique_ptr<FileAsset> albumAsset = nullptr;
    if (!CreateAlbum("Move_test_006_dest", g_pictures, albumAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    Uri sourceUri(g_distributedPrefix + g_commonUri);
    Uri targetUri(albumAsset->GetUri());
    Uri newUri("");
    MEDIA_DEBUG_LOG("medialib_Move_test_006 sourceUri: %{public}s, targetUri: %{public}s",
        sourceUri.ToString().c_str(), targetUri.ToString().c_str());
    int32_t ret = g_mediaFileExtHelper->Move(sourceUri, targetUri, newUri);
    EXPECT_EQ(ret, FileAccessFwk::ERR_IPC_ERROR);
    MEDIA_DEBUG_LOG("medialib_Move_test_006 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check move file
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_Move_test_007, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!CreateFile("Move_test_007.jpg", g_pictures, fileAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    unique_ptr<FileAsset> albumAsset = nullptr;
    if (!CreateAlbum("Move_test_007_dest", g_pictures, albumAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    unique_ptr<FileAsset> tempFileAsset = nullptr;
    if (!CreateFile("Move_test_007.jpg", albumAsset, tempFileAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    Uri sourceUri(fileAsset->GetUri());
    Uri targetUri(albumAsset->GetUri());
    Uri newUri("");
    MEDIA_DEBUG_LOG("medialib_Move_test_007 sourceUri: %{public}s, targetUri: %{public}s",
        sourceUri.ToString().c_str(), targetUri.ToString().c_str());
    int32_t ret = g_mediaFileExtHelper->Move(sourceUri, targetUri, newUri);
    EXPECT_EQ(ret, FileAccessFwk::ERR_IPC_ERROR);
    MEDIA_DEBUG_LOG("medialib_Move_test_007 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check move file
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_Move_test_008, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    if (g_camera == nullptr) {
        MEDIA_ERR_LOG("g_camera == nullptr");
        EXPECT_EQ(true, false);
        return;
    }
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!CreateFile("Move_test_008.jpg", g_pictures, fileAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    Uri sourceUri(fileAsset->GetUri());
    Uri targetUri(g_camera->GetUri());
    MEDIA_DEBUG_LOG("medialib_Move_test_008 sourceUri: %{public}s, targetUri: %{public}s",
        sourceUri.ToString().c_str(), targetUri.ToString().c_str());
    Uri newUri("");
    string srcPath = fileAsset->GetPath();
    string displayName = fileAsset->GetDisplayName();
    string targetPath = g_camera->GetPath() + "/" + displayName;
    MEDIA_DEBUG_LOG("medialib_Move_test_008 srcPath: %{public}s, targetPath: %{public}s",
        srcPath.c_str(), targetPath.c_str());
    EXPECT_EQ(IsFileExists(srcPath), true);
    EXPECT_EQ(IsFileExists(targetPath), false);
    int32_t ret = g_mediaFileExtHelper->Move(sourceUri, targetUri, newUri);
    EXPECT_EQ(IsFileExists(srcPath), false);
    EXPECT_EQ(IsFileExists(targetPath), true);
    MEDIA_DEBUG_LOG("medialib_Move_test_008 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check move file
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_Move_test_009, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    if (g_videos == nullptr) {
        MEDIA_ERR_LOG("g_videos == nullptr");
        EXPECT_EQ(true, false);
        return;
    }
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!CreateFile("Move_test_009.jpg", g_pictures, fileAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    Uri sourceUri(fileAsset->GetUri());
    Uri targetUri(g_videos->GetUri());
    Uri newUri("");
    MEDIA_DEBUG_LOG("medialib_Move_test_009 sourceUri: %{public}s, targetUri: %{public}s",
        sourceUri.ToString().c_str(), targetUri.ToString().c_str());
    int32_t ret = g_mediaFileExtHelper->Move(sourceUri, targetUri, newUri);
    EXPECT_EQ(ret, FileAccessFwk::ERR_IPC_ERROR);
    MEDIA_DEBUG_LOG("medialib_Move_test_009 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check move file
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_Move_test_010, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    if (g_camera == nullptr) {
        MEDIA_ERR_LOG("g_camera == nullptr");
        EXPECT_EQ(true, false);
        return;
    }
    unique_ptr<FileAsset> albumAsset = nullptr;
    if (!CreateAlbum("Move_test_010", g_pictures, albumAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!CreateFile("Move_test_010.jpg", albumAsset, fileAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    Uri sourceUri(albumAsset->GetUri());
    Uri targetUri(g_camera->GetUri());
    Uri newUri("");
    MEDIA_DEBUG_LOG("medialib_Move_test_010 sourceUri: %{public}s, targetUri: %{public}s",
        sourceUri.ToString().c_str(), targetUri.ToString().c_str());
    string srcPath = albumAsset->GetPath();
    string displayName = albumAsset->GetDisplayName();
    string targetPath = g_camera->GetPath() + "/" + displayName;
    MEDIA_DEBUG_LOG("medialib_Move_test_010 srcPath: %{public}s, targetPath: %{public}s",
        srcPath.c_str(), targetPath.c_str());
    EXPECT_EQ(IsFileExists(srcPath), true);
    EXPECT_EQ(IsFileExists(targetPath), false);
    int32_t ret = g_mediaFileExtHelper->Move(sourceUri, targetUri, newUri);
    EXPECT_EQ(IsFileExists(srcPath), false);
    EXPECT_EQ(IsFileExists(targetPath), true);
    MEDIA_DEBUG_LOG("medialib_Move_test_010 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check move file
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_Move_test_011, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    if (g_download == nullptr) {
        MEDIA_ERR_LOG("g_download == nullptr");
        EXPECT_EQ(true, false);
        return;
    }
    unique_ptr<FileAsset> albumAsset = nullptr;
    if (!CreateAlbum("Move_test_011", g_download, albumAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    unique_ptr<FileAsset> fileAsset1 = nullptr;
    if (!CreateFile("Move_test_011.jpg", albumAsset, fileAsset1)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    unique_ptr<FileAsset> fileAsset2 = nullptr;
    if (!CreateFile("Move_test_011.txt", albumAsset, fileAsset2, MEDIA_TYPE_FILE)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    Uri sourceUri(albumAsset->GetUri());
    Uri targetUri(g_pictures->GetUri());
    Uri newUri("");
    MEDIA_DEBUG_LOG("medialib_Move_test_011 sourceUri: %{public}s, targetUri: %{public}s",
        sourceUri.ToString().c_str(), targetUri.ToString().c_str());
    int32_t ret = g_mediaFileExtHelper->Move(sourceUri, targetUri, newUri);
    EXPECT_EQ(ret, FileAccessFwk::ERR_IPC_ERROR);
    MEDIA_DEBUG_LOG("medialib_Move_test_011 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check rename file
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_Rename_test_001, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!CreateFile("Rename_test_001.jpg", g_pictures, fileAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    Uri sourceUri(fileAsset->GetUri());
    Uri newUri("");
    string displayName = "new_Rename_test_001.jpg";
    MEDIA_DEBUG_LOG("medialib_Rename_test_001 sourceUri: %{public}s, displayName: %{public}s",
        sourceUri.ToString().c_str(), displayName.c_str());
    string oldPath = fileAsset->GetPath();
    string newPath = GetRenameNewPath(oldPath, displayName);
    MEDIA_DEBUG_LOG("medialib_Rename_test_001 oldPath: %{public}s, newPath: %{public}s",
        oldPath.c_str(), newPath.c_str());
    EXPECT_EQ(IsFileExists(oldPath), true);
    EXPECT_EQ(IsFileExists(newPath), false);
    int32_t ret = g_mediaFileExtHelper->Rename(sourceUri, displayName, newUri);
    EXPECT_EQ(IsFileExists(oldPath), false);
    EXPECT_EQ(IsFileExists(newPath), true);
    MEDIA_DEBUG_LOG("medialib_Rename_test_001 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check rename file
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_Rename_test_002, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    unique_ptr<FileAsset> albumAsset = nullptr;
    if (!CreateAlbum("Rename_test_002", g_pictures, albumAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!CreateFile("Rename_test_002.jpg", albumAsset, fileAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    Uri sourceUri(albumAsset->GetUri());
    Uri newUri("");
    string displayName = "new_Rename_test_002";
    MEDIA_DEBUG_LOG("medialib_Rename_test_002 sourceUri: %{public}s, displayName: %{public}s",
        sourceUri.ToString().c_str(), displayName.c_str());
    string oldPath = albumAsset->GetPath();
    string newPath = GetRenameNewPath(oldPath, displayName);
    MEDIA_DEBUG_LOG("medialib_Rename_test_002 oldPath: %{public}s, newPath: %{public}s",
        oldPath.c_str(), newPath.c_str());
    EXPECT_EQ(IsFileExists(oldPath), true);
    EXPECT_EQ(IsFileExists(newPath), false);
    int32_t ret = g_mediaFileExtHelper->Rename(sourceUri, displayName, newUri);
    EXPECT_EQ(IsFileExists(oldPath), false);
    EXPECT_EQ(IsFileExists(newPath), true);
    MEDIA_DEBUG_LOG("medialib_Rename_test_002 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check rename file
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_Rename_test_003, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    Uri sourceUri(g_commonPrefix + g_invalidUri);
    Uri newUri("");
    string displayName = "rename";
    MEDIA_DEBUG_LOG("medialib_Rename_test_003 sourceUri: %{public}s, displayName: %{public}s",
        sourceUri.ToString().c_str(), displayName.c_str());
    int32_t ret = g_mediaFileExtHelper->Rename(sourceUri, displayName, newUri);
    EXPECT_EQ(ret, FileAccessFwk::ERR_IPC_ERROR);
    MEDIA_DEBUG_LOG("medialib_Rename_test_003 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check rename file
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_Rename_test_004, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    Uri sourceUri(g_distributedPrefix + g_commonUri);
    Uri newUri("");
    string displayName = "rename";
    MEDIA_DEBUG_LOG("medialib_Rename_test_004 sourceUri: %{public}s, displayName: %{public}s",
        sourceUri.ToString().c_str(), displayName.c_str());
    int32_t ret = g_mediaFileExtHelper->Rename(sourceUri, displayName, newUri);
    EXPECT_EQ(ret, FileAccessFwk::ERR_IPC_ERROR);
    MEDIA_DEBUG_LOG("medialib_Rename_test_004 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check rename file
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_Rename_test_005, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!CreateFile("Rename_test_005.jpg", g_pictures, fileAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    Uri sourceUri(fileAsset->GetUri());
    Uri newUri("");
    string displayName = g_invalidFileName;
    MEDIA_DEBUG_LOG("medialib_Rename_test_005 sourceUri: %{public}s, displayName: %{public}s",
        sourceUri.ToString().c_str(), displayName.c_str());
    int32_t ret = g_mediaFileExtHelper->Rename(sourceUri, displayName, newUri);
    EXPECT_EQ(ret, FileAccessFwk::ERR_IPC_ERROR);
    MEDIA_DEBUG_LOG("medialib_Rename_test_005 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check rename file
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_Rename_test_006, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!CreateFile("Rename_test_006.jpg", g_pictures, fileAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    unique_ptr<FileAsset> tempFileAsset = nullptr;
    if (!CreateFile("new_Rename_test_006.jpg", g_pictures, tempFileAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    Uri sourceUri(fileAsset->GetUri());
    Uri newUri("");
    string displayName = "new_Rename_test_006.jpg";
    MEDIA_DEBUG_LOG("medialib_Rename_test_006 sourceUri: %{public}s, displayName: %{public}s",
        sourceUri.ToString().c_str(), displayName.c_str());
    int32_t ret = g_mediaFileExtHelper->Rename(sourceUri, displayName, newUri);
    EXPECT_EQ(ret, FileAccessFwk::ERR_IPC_ERROR);
    MEDIA_DEBUG_LOG("medialib_Rename_test_006 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check rename file
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_Rename_test_007, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!CreateFile("Rename_test_007.jpg", g_pictures, fileAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    Uri sourceUri(fileAsset->GetUri());
    Uri newUri("");
    string displayName = "Rename_test_007.txt";
    MEDIA_DEBUG_LOG("medialib_Rename_test_007 sourceUri: %{public}s, displayName: %{public}s",
        sourceUri.ToString().c_str(), displayName.c_str());
    int32_t ret = g_mediaFileExtHelper->Rename(sourceUri, displayName, newUri);
    EXPECT_EQ(ret, FileAccessFwk::ERR_IPC_ERROR);
    MEDIA_DEBUG_LOG("medialib_Rename_test_007 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check listfile
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_ListFile_test_001, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    Uri selectUri(g_commonPrefix + g_rootUri);
    MEDIA_DEBUG_LOG("medialib_ListFile_test_001 selectUri %{public}s", selectUri.ToString().c_str());
    vector<FileAccessFwk::FileInfo> fileList = g_mediaFileExtHelper->ListFile(selectUri);
    // Camera, Videos, Pictures, Audios, Documents, Download
    EXPECT_EQ(fileList.size(), 6);
    MEDIA_DEBUG_LOG("medialib_ListFile_test_001 fileList.size() %{public}lu", (long)fileList.size());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check listfile
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_ListFile_test_002, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    unique_ptr<FileAsset> albumAsset = nullptr;
    if (!CreateAlbum("ListFile_test_002", g_pictures, albumAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    unique_ptr<FileAsset> tempAsset = nullptr;
    if (!CreateAlbum("ListFile_test_002", albumAsset, tempAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    if (!CreateFile("ListFile_test_002_1.jpg", albumAsset, tempAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    if (!CreateFile("ListFile_test_002_2.jpg", albumAsset, tempAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    if (!CreateFile("ListFile_test_002_3.jpg", albumAsset, tempAsset)) {
        EXPECT_EQ(g_createAssetFailed, true);
        return;
    }
    Uri selectUri(albumAsset->GetUri());
    MEDIA_DEBUG_LOG("medialib_ListFile_test_002 selectUri %{public}s", selectUri.ToString().c_str());
    vector<FileAccessFwk::FileInfo> fileList = g_mediaFileExtHelper->ListFile(selectUri);
    EXPECT_EQ(fileList.size(), 4);
    MEDIA_DEBUG_LOG("medialib_ListFile_test_002 fileList.size() %{public}lu", (long)fileList.size());
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check getroots
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_GetRoots_test_001, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    vector<FileAccessFwk::DeviceInfo> deviceList = g_mediaFileExtHelper->GetRoots();
    EXPECT_EQ(deviceList.size(), 1);
    MEDIA_DEBUG_LOG("medialib_GetRoots_test_001 deviceList.size() %{public}lu", (long)deviceList.size());
}
} // namespace Media
} // namespace OHOS
