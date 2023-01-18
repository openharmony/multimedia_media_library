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

#include <fcntl.h>

#include "datashare_helper.h"
#include "file_access_extension_info.h"
#include "file_access_framework_errno.h"
#include "file_access_helper.h"
#include "file_filter.h"
#include "get_self_permissions.h"
#include "iservice_registry.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_errno.h"
#include "media_library_manager.h"
#include "media_log.h"
#include "result_set_utils.h"
#include "scanner_utils.h"

using namespace std;
using namespace OHOS;
using namespace testing::ext;
constexpr int STORAGE_MANAGER_MANAGER_ID = 5003;

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
    const bool CREATE_ASSET_FAILED = false;
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
    vector<AAFwk::Want> wantVec;
    auto ret = FileAccessFwk::FileAccessHelper::GetRegisteredFileAccessExtAbilityInfo(wantVec);
    if (ret == FileAccessFwk::E_GETINFO) {
        MEDIA_ERR_LOG("CreateFileExtHelper::GetRegisteredFileAccessExtAbilityInfo failed");
        return nullptr;
    }
    AppExecFwk::Want want;
    want.SetElementName("com.ohos.medialibrary.medialibrarydata", "FileExtensionAbility");
    vector<AAFwk::Want> wants {want};
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
    unique_ptr<FetchResult<FileAsset>> fetchFileResult = make_unique<FetchResult<FileAsset>>(move(resultSet));
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

void DeleteAllDataInDb()
{
    Uri deleteAssetUri(MEDIALIBRARY_DATA_URI);
    DataShare::DataSharePredicates predicates;
    string selections = MEDIA_DATA_DB_ID + " <> 0 ";
    predicates.SetWhereClause(selections);
    int retVal = g_mediaDataShareHelper->Delete(deleteAssetUri, predicates);
    MEDIA_INFO_LOG("SetUpTestCase Delete retVal: %{public}d", retVal);
    EXPECT_EQ((retVal >= 0), true);
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
    vector<string> perms;
    perms.push_back("ohos.permission.READ_MEDIA");
    perms.push_back("ohos.permission.WRITE_MEDIA");
    perms.push_back("ohos.permission.FILE_ACCESS_MANAGER");
    perms.push_back("ohos.permission.GET_BUNDLE_INFO_PRIVILEGED");
    uint64_t tokenId = 0;
    PermissionUtilsUnitTest::SetAccessTokenPermission("MediaLibraryExtUnitTest", perms, tokenId);
    ASSERT_TRUE(tokenId != 0);

    const int DEFAULT_USER_SUID = 20000000;
    const int ROOT_USER_SUID = 0;
    setuid(DEFAULT_USER_SUID);
    g_mediaFileExtHelper = CreateFileExtHelper(STORAGE_MANAGER_MANAGER_ID);
    setuid(ROOT_USER_SUID);
    g_mediaDataShareHelper = CreateDataShareHelper(STORAGE_MANAGER_MANAGER_ID);
    if (g_mediaFileExtHelper == nullptr) {
        MEDIA_DEBUG_LOG("medialibraryDataAbilityHelper fail");
        return;
    }
    if (g_mediaDataShareHelper == nullptr) {
        MEDIA_DEBUG_LOG("g_mediaDataShareHelper fail");
        return;
    }
}

void MediaLibraryExtUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("TearDownTestCase invoked");
}

// SetUp:Execute before each test case
void MediaLibraryExtUnitTest::SetUp()
{
    system("rm -rf /storage/media/100/local/files/*");
    DeleteAllDataInDb();
    CreateRootDir();
}

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
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
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
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }
    Uri uri(fileAsset->GetUri());
    int fd = -1;
    auto ret = g_mediaFileExtHelper->OpenFile(uri, O_RDWR, fd);
    MEDIA_DEBUG_LOG("medialib_OpenFile_test_001 uri: %{public}s, fd: %{public}d", uri.ToString().c_str(), fd);
    EXPECT_EQ(ret == E_SUCCESS, true);
    if (ret == E_SUCCESS) {
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
    int fd = -1;
    auto ret = g_mediaFileExtHelper->OpenFile(uri, O_RDWR, fd);
    if (ret == JS_INNER_FAIL) {
        MEDIA_DEBUG_LOG("medialib_OpenFile_test_002 OpenFile errno: %{public}d, errmsg: %{public}s",
            errno, strerror(errno));
    }
    EXPECT_EQ(ret, JS_INNER_FAIL);
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
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
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
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }
    Uri parentUri(albumAsset->GetUri());
    Uri newUri("");
    string displayName = g_invalidFileName;
    MEDIA_DEBUG_LOG("medialib_CreateFile_test_002 parentUri: %{public}s, displayName: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str());
    int32_t ret = g_mediaFileExtHelper->CreateFile(parentUri, displayName, newUri);
    EXPECT_EQ(ret, JS_E_DISPLAYNAME);
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
    EXPECT_EQ(ret, JS_E_URI);
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
    EXPECT_EQ(ret, JS_E_URI);
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
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!CreateFile("CreateFile_test_005.jpg", albumAsset, fileAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }
    Uri parentUri(albumAsset->GetUri());
    Uri newUri("");
    string displayName = "CreateFile_test_005.jpg";
    MEDIA_DEBUG_LOG("medialib_CreateFile_test_005 parentUri: %{public}s, displayName: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str());
    int32_t ret = g_mediaFileExtHelper->CreateFile(parentUri, displayName, newUri);
    EXPECT_EQ(ret, JS_ERR_FILE_EXIST);
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
    Uri parentUri(g_commonPrefix + g_rootUri + MEDIALIBRARY_TYPE_FILE_URI);
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
    Uri parentUri(g_distributedPrefix + g_rootUri + MEDIALIBRARY_TYPE_FILE_URI);
    string displayName = "Mkdir_test_002";
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_002 parentUri: %{public}s, displayName: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str());
    Uri newUri("");
    int32_t ret = g_mediaFileExtHelper->Mkdir(parentUri, displayName, newUri);
    EXPECT_EQ(ret, JS_E_URI);
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
    Uri parentUri(g_commonPrefix + g_rootUri + MEDIALIBRARY_TYPE_FILE_URI);
    string displayName = "Mkdir_test_003";
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_003 parentUri: %{public}s, displayName: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str());
    Uri newUri("");
    int32_t ret = g_mediaFileExtHelper->Mkdir(parentUri, displayName, newUri);
    EXPECT_EQ(ret, JS_E_DISPLAYNAME);
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
    EXPECT_EQ(ret, JS_E_URI);
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
    EXPECT_EQ(ret, JS_E_URI);
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
    EXPECT_EQ(ret, JS_E_DISPLAYNAME);
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
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }
    Uri parentUri(g_pictures->GetUri());
    string displayName = "Mkdir_test_008";
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_008 parentUri: %{public}s, displayName: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str());
    Uri newUri("");
    int32_t ret = g_mediaFileExtHelper->Mkdir(parentUri, displayName, newUri);
    EXPECT_EQ(ret, JS_ERR_FILE_EXIST);
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
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!CreateFile("Delete_test_001.jpg", albumAsset, fileAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
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
    EXPECT_EQ(ret, JS_E_URI);
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
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }
    unique_ptr<FileAsset> destAlbumAsset = nullptr;
    if (!CreateAlbum("Move_test_001_dst", g_pictures, destAlbumAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!CreateFile("Move_test_001.jpg", srcAlbumAsset, fileAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
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
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!CreateFile("Move_test_002.jpg", srcAlbumAsset, fileAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }
    unique_ptr<FileAsset> destAlbumAsset = nullptr;
    if (!CreateAlbum("Move_test_002_dest", g_pictures, destAlbumAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
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
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }
    Uri sourceUri(fileAsset->GetUri());
    Uri targetUri(g_commonPrefix + g_invalidUri);
    Uri newUri("");
    MEDIA_DEBUG_LOG("medialib_Move_test_003 sourceUri: %{public}s, targetUri: %{public}s",
        sourceUri.ToString().c_str(), targetUri.ToString().c_str());
    int32_t ret = g_mediaFileExtHelper->Move(sourceUri, targetUri, newUri);
    EXPECT_EQ(ret, JS_E_URI);
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
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }
    Uri sourceUri(fileAsset->GetUri());
    Uri targetUri(g_distributedPrefix + g_commonUri);
    Uri newUri("");
    MEDIA_DEBUG_LOG("medialib_Move_test_004 sourceUri: %{public}s, targetUri: %{public}s",
        sourceUri.ToString().c_str(), targetUri.ToString().c_str());
    int32_t ret = g_mediaFileExtHelper->Move(sourceUri, targetUri, newUri);
    EXPECT_EQ(ret, JS_E_URI);
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
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }
    Uri sourceUri(g_commonPrefix + g_invalidUri);
    Uri targetUri(albumAsset->GetUri());
    Uri newUri("");
    MEDIA_DEBUG_LOG("medialib_Move_test_005 sourceUri: %{public}s, targetUri: %{public}s",
        sourceUri.ToString().c_str(), targetUri.ToString().c_str());
    int32_t ret = g_mediaFileExtHelper->Move(sourceUri, targetUri, newUri);
    EXPECT_EQ(ret, JS_E_URI);
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
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }
    Uri sourceUri(g_distributedPrefix + g_commonUri);
    Uri targetUri(albumAsset->GetUri());
    Uri newUri("");
    MEDIA_DEBUG_LOG("medialib_Move_test_006 sourceUri: %{public}s, targetUri: %{public}s",
        sourceUri.ToString().c_str(), targetUri.ToString().c_str());
    int32_t ret = g_mediaFileExtHelper->Move(sourceUri, targetUri, newUri);
    EXPECT_EQ(ret, JS_E_URI);
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
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }
    unique_ptr<FileAsset> albumAsset = nullptr;
    if (!CreateAlbum("Move_test_007_dest", g_pictures, albumAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }
    unique_ptr<FileAsset> tempFileAsset = nullptr;
    if (!CreateFile("Move_test_007.jpg", albumAsset, tempFileAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }
    Uri sourceUri(fileAsset->GetUri());
    Uri targetUri(albumAsset->GetUri());
    Uri newUri("");
    MEDIA_DEBUG_LOG("medialib_Move_test_007 sourceUri: %{public}s, targetUri: %{public}s",
        sourceUri.ToString().c_str(), targetUri.ToString().c_str());
    int32_t ret = g_mediaFileExtHelper->Move(sourceUri, targetUri, newUri);
    EXPECT_EQ(ret, JS_ERR_FILE_EXIST);
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
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
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
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }
    Uri sourceUri(fileAsset->GetUri());
    Uri targetUri(g_videos->GetUri());
    Uri newUri("");
    MEDIA_DEBUG_LOG("medialib_Move_test_009 sourceUri: %{public}s, targetUri: %{public}s",
        sourceUri.ToString().c_str(), targetUri.ToString().c_str());
    int32_t ret = g_mediaFileExtHelper->Move(sourceUri, targetUri, newUri);
    EXPECT_EQ(ret, JS_E_FILE_EXTENSION);
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
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!CreateFile("Move_test_010.jpg", albumAsset, fileAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
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
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }
    unique_ptr<FileAsset> fileAsset1 = nullptr;
    if (!CreateFile("Move_test_011.jpg", albumAsset, fileAsset1)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }
    unique_ptr<FileAsset> fileAsset2 = nullptr;
    if (!CreateFile("Move_test_011.txt", albumAsset, fileAsset2, MEDIA_TYPE_FILE)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }
    Uri sourceUri(albumAsset->GetUri());
    Uri targetUri(g_pictures->GetUri());
    Uri newUri("");
    MEDIA_DEBUG_LOG("medialib_Move_test_011 sourceUri: %{public}s, targetUri: %{public}s",
        sourceUri.ToString().c_str(), targetUri.ToString().c_str());
    int32_t ret = g_mediaFileExtHelper->Move(sourceUri, targetUri, newUri);
    EXPECT_EQ(ret, JS_E_MOVE_DENIED);
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
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
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
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!CreateFile("Rename_test_002.jpg", albumAsset, fileAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
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
    EXPECT_EQ(ret, JS_E_URI);
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
    EXPECT_EQ(ret, JS_E_URI);
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
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }
    Uri sourceUri(fileAsset->GetUri());
    Uri newUri("");
    string displayName = g_invalidFileName;
    MEDIA_DEBUG_LOG("medialib_Rename_test_005 sourceUri: %{public}s, displayName: %{public}s",
        sourceUri.ToString().c_str(), displayName.c_str());
    int32_t ret = g_mediaFileExtHelper->Rename(sourceUri, displayName, newUri);
    EXPECT_EQ(ret, JS_E_DISPLAYNAME);
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
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }
    unique_ptr<FileAsset> tempFileAsset = nullptr;
    if (!CreateFile("new_Rename_test_006.jpg", g_pictures, tempFileAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }
    Uri sourceUri(fileAsset->GetUri());
    Uri newUri("");
    string displayName = "new_Rename_test_006.jpg";
    MEDIA_DEBUG_LOG("medialib_Rename_test_006 sourceUri: %{public}s, displayName: %{public}s",
        sourceUri.ToString().c_str(), displayName.c_str());
    int32_t ret = g_mediaFileExtHelper->Rename(sourceUri, displayName, newUri);
    EXPECT_EQ(ret, JS_ERR_FILE_EXIST);
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
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }
    Uri sourceUri(fileAsset->GetUri());
    Uri newUri("");
    string displayName = "Rename_test_007.txt";
    MEDIA_DEBUG_LOG("medialib_Rename_test_007 sourceUri: %{public}s, displayName: %{public}s",
        sourceUri.ToString().c_str(), displayName.c_str());
    int32_t ret = g_mediaFileExtHelper->Rename(sourceUri, displayName, newUri);
    EXPECT_EQ(ret, JS_E_FILE_EXTENSION);
    MEDIA_DEBUG_LOG("medialib_Rename_test_007 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

void DisplayFileList(const vector<FileAccessFwk::FileInfo> &fileList)
{
    for (auto t : fileList) {
        MEDIA_DEBUG_LOG("medialib_ListFile_test_001 file.uri: %s, file.fileName: %s, file.mode: %d, file.mimeType: %s",
            t.uri.c_str(), t.fileName.c_str(), t.mode, t.mimeType.c_str());
    }
}

bool InitListFileTest1(unique_ptr<FileAsset> &albumAsset)
{
    if (!CreateAlbum("ListFile_test_001", g_pictures, albumAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return false;
    }
    unique_ptr<FileAsset> tempAsset = nullptr;
    if (!CreateAlbum("ListFile_test_001", albumAsset, tempAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return false;
    }
    if (!CreateFile("ListFile_test_001_1.jpg", albumAsset, tempAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return false;
    }
    if (!CreateFile("ListFile_test_001_2.jpg", albumAsset, tempAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return false;
    }
    if (!CreateFile("ListFile_test_001_3.jpg", albumAsset, tempAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return false;
    }
    if (!CreateFile("ListFile_test_001_1.mp4", g_videos, tempAsset, MEDIA_TYPE_VIDEO)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return false;
    }
    return true;
}

void ListFileFromRootResult(vector<FileAccessFwk::FileInfo> rootFileList, int offset, int maxCount)
{
    const size_t URI_FILE_ROOT_FILE_SIZE = 5;
    const size_t URI_MEDIA_ROOT_IMAGE_SIZE = 1;
    const size_t URI_MEDIA_ROOT_VIDEO_SIZE = 1;
    const size_t URI_MEDIA_ROOT_AUDIO_SIZE = 0;
    DistributedFS::FileFilter filter;
    // URI_FILE_ROOT & URI_MEDIA_ROOT
    for (auto mediaRootInfo : rootFileList) {
        vector<FileAccessFwk::FileInfo> fileList;
        auto ret = g_mediaFileExtHelper->ListFile(mediaRootInfo, offset, maxCount, filter, fileList);
        EXPECT_EQ(ret, E_SUCCESS);

        // URI_FILE_ROOT
        if (mediaRootInfo.mimeType == DEFAULT_FILE_MIME_TYPE) {
            MEDIA_DEBUG_LOG("medialib_ListFile_test_001 URI_FILE_ROOT uri: %{public}s", mediaRootInfo.uri.c_str());
            MEDIA_DEBUG_LOG("medialib_ListFile_test_001 URI_FILE_ROOT fileList.size(): %{public}d",
                (int)fileList.size());
            DisplayFileList(fileList);
            EXPECT_EQ(fileList.size(), URI_FILE_ROOT_FILE_SIZE);
            continue;
        }

        // URI_MEDIA_ROOT image
        if (mediaRootInfo.mimeType == DEFAULT_IMAGE_MIME_TYPE) {
            MEDIA_DEBUG_LOG("medialib_ListFile_test_001 URI_MEDIA_ROOT uri: %{public}s", mediaRootInfo.uri.c_str());
            MEDIA_DEBUG_LOG("medialib_ListFile_test_001 URI_MEDIA_ROOT fileList.size(): %{public}d",
                (int)fileList.size());
            DisplayFileList(fileList);
            EXPECT_EQ(fileList.size(), URI_MEDIA_ROOT_IMAGE_SIZE);
        }

        // URI_MEDIA_ROOT video
        if (mediaRootInfo.mimeType == DEFAULT_VIDEO_MIME_TYPE) {
            MEDIA_DEBUG_LOG("medialib_ListFile_test_001 URI_MEDIA_ROOT uri: %{public}s", mediaRootInfo.uri.c_str());
            MEDIA_DEBUG_LOG("medialib_ListFile_test_001 URI_MEDIA_ROOT fileList.size(): %{public}d",
                (int)fileList.size());
            DisplayFileList(fileList);
            EXPECT_EQ(fileList.size(), URI_MEDIA_ROOT_VIDEO_SIZE);
        }

        // URI_MEDIA_ROOT audio
        if (mediaRootInfo.mimeType == DEFAULT_AUDIO_MIME_TYPE) {
            MEDIA_DEBUG_LOG("medialib_ListFile_test_001 URI_MEDIA_ROOT uri: %{public}s", mediaRootInfo.uri.c_str());
            MEDIA_DEBUG_LOG("medialib_ListFile_test_001 URI_MEDIA_ROOT fileList.size(): %{public}d",
                (int)fileList.size());
            DisplayFileList(fileList);
            EXPECT_EQ(fileList.size(), URI_MEDIA_ROOT_AUDIO_SIZE);
        }
    }
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
    unique_ptr<FileAsset> albumAsset = nullptr;
    if (!InitListFileTest1(albumAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }
    const int64_t offset = 0;
    const int64_t maxCount = 100;
    DistributedFS::FileFilter filter;

    // URI_ROOT
    FileAccessFwk::FileInfo rootInfo;
    rootInfo.uri = g_commonPrefix + g_rootUri;
    MEDIA_DEBUG_LOG("medialib_ListFile_test_001 URI_ROOT uri: %{public}s", rootInfo.uri.c_str());
    vector<FileAccessFwk::FileInfo> rootFileList;
    auto ret = g_mediaFileExtHelper->ListFile(rootInfo, offset, maxCount, filter, rootFileList);
    EXPECT_EQ(ret, E_SUCCESS);
    MEDIA_DEBUG_LOG("medialib_ListFile_test_001 URI_ROOT fileList.size(): %{public}d", (int)rootFileList.size());
    DisplayFileList(rootFileList);
    EXPECT_EQ(rootFileList.size(), 4);

    ListFileFromRootResult(rootFileList, offset, maxCount);
}

bool InitListFileTest2(unique_ptr<FileAsset> &albumAsset)
{
    if (!CreateAlbum("ListFile_test_002", g_pictures, albumAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return false;
    }
    unique_ptr<FileAsset> tempAsset = nullptr;
    if (!CreateAlbum("ListFile_test_002", albumAsset, tempAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return false;
    }
    if (!CreateAlbum("ListFile_002", albumAsset, tempAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return false;
    }
    if (!CreateFile("ListFile_test_002.jpg", albumAsset, tempAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return false;
    }
    if (!CreateFile("ListFile_test_002_1.jpg", albumAsset, tempAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return false;
    }
    if (!CreateFile("ListFile_test_002.png", albumAsset, tempAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return false;
    }
    if (!CreateFile("ListFile_002.jpg", albumAsset, tempAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return false;
    }
    if (!CreateFile("ListFile_002_1.jpg", albumAsset, tempAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return false;
    }
    if (!CreateFile("ListFile_002.png", albumAsset, tempAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return false;
    }
    return true;
}

void ListFileTestLimit(FileAccessFwk::FileInfo dirInfo)
{
    const int64_t OFFSET_1 = 0;
    const int64_t OFFSET_2 = 5;
    const int64_t MAX_COUNT_1 = 5;
    const int64_t MAX_COUNT_2 = 100;
    vector<pair<int64_t, int64_t>> limits = { make_pair(OFFSET_1, MAX_COUNT_1),
        make_pair(OFFSET_2, MAX_COUNT_1), make_pair(OFFSET_1, MAX_COUNT_2), make_pair(OFFSET_2, MAX_COUNT_2) };
    const int DIR_RESULT = 8;
    const int ALBUM_RESULT = 6;

    DistributedFS::FileFilter filter;
    for (auto limit : limits) {
        // URI_DIR
        dirInfo.mimeType = DEFAULT_FILE_MIME_TYPE;
        vector<FileAccessFwk::FileInfo> dirFileList;
        auto ret = g_mediaFileExtHelper->ListFile(dirInfo, limit.first, limit.second, filter, dirFileList);
        EXPECT_EQ(ret, E_SUCCESS);
        EXPECT_EQ(dirFileList.size(), min((DIR_RESULT - limit.first), limit.second));
        // URI_ALBUM
        dirInfo.mimeType = DEFAULT_IMAGE_MIME_TYPE;
        vector<FileAccessFwk::FileInfo> albumFileList;
        ret = g_mediaFileExtHelper->ListFile(dirInfo, limit.first, limit.second, filter, albumFileList);
        EXPECT_EQ(ret, E_SUCCESS);
        EXPECT_EQ(albumFileList.size(), min((ALBUM_RESULT - limit.first), limit.second));
    }
}

void ListFileTestFilter(FileAccessFwk::FileInfo dirInfo)
{
    const int FILTER_COUNT = 3;
    const string SUFFIX_1 = ".jpg";
    const string SUFFIX_2 = ".png";
    const int32_t JPG_COUNT = 4;
    const int32_t PNG_COUNT = 2;
    const vector<int32_t> DIR_RESULT = {JPG_COUNT, PNG_COUNT, JPG_COUNT + PNG_COUNT};
    const vector<int32_t> ALBUM_RESULT = {JPG_COUNT, PNG_COUNT, JPG_COUNT + PNG_COUNT};
    vector<DistributedFS::FileFilter> filters;
    DistributedFS::FileFilter tempFilter;
    tempFilter.SetHasFilter(true);
    tempFilter.SetSuffix({ SUFFIX_1 });
    filters.push_back(tempFilter);
    tempFilter.SetSuffix({ SUFFIX_2 });
    filters.push_back(tempFilter);
    tempFilter.SetSuffix({ SUFFIX_1, SUFFIX_2 });
    filters.push_back(tempFilter);

    const int64_t offset = 0;
    const int64_t maxCount = 100;
    for (size_t i = 0; i < FILTER_COUNT; i++) {
        MEDIA_ERR_LOG("medialib_ListFile_test_002:: filter.hasFilter: %d, filter.suffix: %s",
            (int)filters[i].GetHasFilter(), filters[i].GetSuffix()[0].c_str());
        // URI_DIR
        dirInfo.mimeType = DEFAULT_FILE_MIME_TYPE;
        vector<FileAccessFwk::FileInfo> dirFileList;
        auto ret = g_mediaFileExtHelper->ListFile(dirInfo, offset, maxCount, filters[i], dirFileList);
        MEDIA_ERR_LOG("medialib_ListFile_test_002:: dirFileList.size(): %d", (int)dirFileList.size());
        DisplayFileList(dirFileList);
        EXPECT_EQ(ret, E_SUCCESS);
        EXPECT_EQ(dirFileList.size(), DIR_RESULT[i]);
        // URI_ALBUM
        dirInfo.mimeType = DEFAULT_IMAGE_MIME_TYPE;
        vector<FileAccessFwk::FileInfo> albumFileList;
        ret = g_mediaFileExtHelper->ListFile(dirInfo, offset, maxCount, filters[i], albumFileList);
        MEDIA_ERR_LOG("medialib_ListFile_test_002:: albumFileList.size(): %d", (int)albumFileList.size());
        DisplayFileList(albumFileList);
        EXPECT_EQ(ret, E_SUCCESS);
        EXPECT_EQ(albumFileList.size(), ALBUM_RESULT[i]);
    }
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
    if (!InitListFileTest2(albumAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }

    const int32_t DIR_RESULT = 8;
    const int32_t ALBUM_RESULT = 6;
    const int64_t offset = 0;
    const int64_t maxCount = 100;
    DistributedFS::FileFilter filter;

    // URI_DIR
    FileAccessFwk::FileInfo dirInfo;
    dirInfo.uri = albumAsset->GetUri();
    dirInfo.mimeType = DEFAULT_FILE_MIME_TYPE;
    MEDIA_DEBUG_LOG("medialib_ListFile_test_002 URI_DIR uri: %{public}s", dirInfo.uri.c_str());
    vector<FileAccessFwk::FileInfo> dirFileList;
    auto ret = g_mediaFileExtHelper->ListFile(dirInfo, offset, maxCount, filter, dirFileList);
    EXPECT_EQ(ret, E_SUCCESS);
    MEDIA_DEBUG_LOG("medialib_ListFile_test_002 URI_DIR fileList.size(): %{public}d", (int)dirFileList.size());
    DisplayFileList(dirFileList);
    EXPECT_EQ(dirFileList.size(), DIR_RESULT);

    // URI_ALBUM
    FileAccessFwk::FileInfo albumInfo;
    albumInfo.uri = albumAsset->GetUri();
    albumInfo.mimeType = DEFAULT_IMAGE_MIME_TYPE;
    MEDIA_DEBUG_LOG("medialib_ListFile_test_002 URI_ALBUM uri: %{public}s", albumInfo.uri.c_str());
    vector<FileAccessFwk::FileInfo> albumFileList;
    ret = g_mediaFileExtHelper->ListFile(albumInfo, offset, maxCount, filter, albumFileList);
    EXPECT_EQ(ret, E_SUCCESS);
    MEDIA_DEBUG_LOG("medialib_ListFile_test_002 URI_ALBUM fileList.size(): %{public}d", (int)albumFileList.size());
    DisplayFileList(albumFileList);
    EXPECT_EQ(albumFileList.size(), ALBUM_RESULT);

    // test limit and filter
    FileAccessFwk::FileInfo fileInfo;
    fileInfo.uri = albumAsset->GetUri();
    ListFileTestLimit(fileInfo);
    ListFileTestFilter(fileInfo);
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
    vector<FileAccessFwk::RootInfo> rootList;
    auto ret = g_mediaFileExtHelper->GetRoots(rootList);
    EXPECT_EQ(ret, E_SUCCESS);
    EXPECT_EQ(rootList.size(), 1);
    MEDIA_DEBUG_LOG("medialib_GetRoots_test_001 rootList.size() %{public}lu", (long)rootList.size());
}

bool InitScanFile(unique_ptr<FileAsset> &albumAsset)
{
    unique_ptr<FileAsset> tempAsset = nullptr;
    unique_ptr<FileAsset> albumAsset2 = nullptr;
    if (!CreateAlbum("ScanFile_test_001", g_pictures, albumAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return false;
    }
    if (!CreateAlbum("ScanFile_test_001", albumAsset, albumAsset2)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return false;
    }
    if (!CreateFile("ScanFile_test_001_1.jpg", albumAsset, tempAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return false;
    }
    if (!CreateFile("ScanFile_test_001_2.jpg", albumAsset, tempAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return false;
    }
    if (!CreateFile("ScanFile_test_001_3.png", albumAsset, tempAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return false;
    }
    if (!CreateFile("ScanFile_test_001_4.jpg", albumAsset, tempAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return false;
    }
    if (!CreateFile("ScanFile_test_001_5.jpg", albumAsset, tempAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return false;
    }
    if (!CreateFile("ScanFile_test_001_6.jpg", albumAsset2, tempAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return false;
    }
    if (!CreateFile("ScanFile_test_001_7.png", albumAsset2, tempAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return false;
    }
    if (!CreateFile("ScanFile_test_001_8.jpg", albumAsset2, tempAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return false;
    }
    return true;
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check scanfile
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_ScanFile_test_001, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }

    unique_ptr<FileAsset> albumAsset = nullptr;
    if (!InitScanFile(albumAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }

    int64_t offset = 0;
    int64_t maxCount = 100;
    DistributedFS::FileFilter filter;

    // URI_DIR
    FileAccessFwk::FileInfo dirInfo;
    dirInfo.uri = albumAsset->GetUri();
    dirInfo.mimeType = DEFAULT_FILE_MIME_TYPE;
    MEDIA_DEBUG_LOG("medialib_ListFile_test_001 URI_DIR uri: %{public}s", dirInfo.uri.c_str());
    vector<FileAccessFwk::FileInfo> dirFileList;
    auto ret = g_mediaFileExtHelper->ScanFile(dirInfo, offset, maxCount, filter, dirFileList);
    EXPECT_EQ(ret, E_SUCCESS);
    EXPECT_EQ(dirFileList.size(), 8);

    vector<FileAccessFwk::FileInfo> limitDirFileList1;
    ret = g_mediaFileExtHelper->ScanFile(dirInfo, offset, 5, filter, limitDirFileList1);
    EXPECT_EQ(ret, E_SUCCESS);
    EXPECT_EQ(limitDirFileList1.size(), 5);

    vector<FileAccessFwk::FileInfo> limitDirFileList2;
    ret = g_mediaFileExtHelper->ScanFile(dirInfo, 5, maxCount, filter, limitDirFileList2);
    EXPECT_EQ(ret, E_SUCCESS);
    EXPECT_EQ(limitDirFileList2.size(), 3);
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check scanfile
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_ScanFile_test_002, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    unique_ptr<FileAsset> albumAsset = nullptr;
    if (!InitScanFile(albumAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }
    int64_t offset = 0;
    int64_t maxCount = 100;
    DistributedFS::FileFilter filter;

    // URI_DIR
    FileAccessFwk::FileInfo dirInfo;
    dirInfo.uri = "datashare:///media/root";
    dirInfo.mimeType = DEFAULT_FILE_MIME_TYPE;
    MEDIA_DEBUG_LOG("medialib_ListFile_test_002 URI_DIR uri: %{public}s", dirInfo.uri.c_str());
    vector<FileAccessFwk::FileInfo> dirFileList;
    auto ret = g_mediaFileExtHelper->ScanFile(dirInfo, offset, maxCount, filter, dirFileList);
    EXPECT_EQ(ret, E_SUCCESS);
    EXPECT_EQ(dirFileList.size(), 8);

    vector<FileAccessFwk::FileInfo> limitDirFileList1;
    ret = g_mediaFileExtHelper->ScanFile(dirInfo, offset, 5, filter, limitDirFileList1);
    EXPECT_EQ(ret, E_SUCCESS);
    EXPECT_EQ(limitDirFileList1.size(), 5);

    vector<FileAccessFwk::FileInfo> limitDirFileList2;
    ret = g_mediaFileExtHelper->ScanFile(dirInfo, 5, maxCount, filter, limitDirFileList2);
    EXPECT_EQ(ret, E_SUCCESS);
    EXPECT_EQ(limitDirFileList2.size(), 3);
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check scanfile
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_ScanFile_test_003, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }

    unique_ptr<FileAsset> albumAsset = nullptr;
    if (!InitScanFile(albumAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }

    int64_t offset = 0;
    int64_t maxCount = 100;
    DistributedFS::FileFilter filter;
    vector<string> suffix { ".jpg" };
    filter.SetSuffix(suffix);
    // URI_DIR
    FileAccessFwk::FileInfo dirInfo;
    dirInfo.uri = albumAsset->GetUri();
    dirInfo.mimeType = DEFAULT_FILE_MIME_TYPE;
    MEDIA_DEBUG_LOG("medialib_ListFile_test_003 URI_DIR uri: %{public}s", dirInfo.uri.c_str());
    vector<FileAccessFwk::FileInfo> dirFileList;
    auto ret = g_mediaFileExtHelper->ScanFile(dirInfo, offset, maxCount, filter, dirFileList);
    EXPECT_EQ(ret, E_SUCCESS);
    EXPECT_EQ(dirFileList.size(), 6);

    vector<FileAccessFwk::FileInfo> limitDirFileList1;
    ret = g_mediaFileExtHelper->ScanFile(dirInfo, offset, 5, filter, limitDirFileList1);
    EXPECT_EQ(ret, E_SUCCESS);
    EXPECT_EQ(limitDirFileList1.size(), 5);

    vector<FileAccessFwk::FileInfo> limitDirFileList2;
    ret = g_mediaFileExtHelper->ScanFile(dirInfo, 5, maxCount, filter, limitDirFileList2);
    EXPECT_EQ(ret, E_SUCCESS);
    EXPECT_EQ(limitDirFileList2.size(), 1);
}

/*
 * Feature: MediaLibraryExtUnitTest
 * Function: check access
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription:
 */
HWTEST_F(MediaLibraryExtUnitTest, medialib_Access_test_001, TestSize.Level0)
{
    if (!CheckEnvironment()) {
        return;
    }
    unique_ptr<FileAsset> albumAsset = nullptr;
    if (!CreateAlbum("Access_test_001", g_pictures, albumAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }
    unique_ptr<FileAsset> fileAsset = nullptr;
    if (!CreateFile("Access_test_001.jpg", albumAsset, fileAsset)) {
        EXPECT_EQ(CREATE_ASSET_FAILED, true);
        return;
    }
    bool isExist = false;
    Uri uri(fileAsset->GetUri());
    auto ret = g_mediaFileExtHelper->Access(uri, isExist);
    EXPECT_EQ(ret, E_SUCCESS);
    EXPECT_EQ(isExist, true);

    // delete the file
    g_mediaFileExtHelper->Delete(uri);

    isExist = false;
    ret = g_mediaFileExtHelper->Access(uri, isExist);
    EXPECT_EQ(ret, JS_E_URI);
    EXPECT_EQ(isExist, false);
}
} // namespace Media
} // namespace OHOS
