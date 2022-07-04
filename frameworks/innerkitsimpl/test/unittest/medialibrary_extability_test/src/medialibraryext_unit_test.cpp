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

#include "medialibraryext_unit_test.h"
#include "iservice_registry.h"
#include "media_library_manager.h"
#include "file_access_helper.h"
#include "datashare_helper.h"
#include "media_log.h"
#include "file_access_framework_errno.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::Media;
using namespace testing::ext;
int uid = 5003;

namespace OHOS {
namespace Media {
namespace {
    string g_storagePath = "/storage/media/100/local/files";
    std::unordered_map<string, shared_ptr<Asset>> g_assetMap;
    std::shared_ptr<DataShare::DataShareHelper> g_mediaDataShareHelper;
    std::shared_ptr<FileAccessFwk::FileAccessHelper> g_mediaFileExtHelper;
    bool g_envReady = false;
} // namespace

MediaLibraryManager* mediaLibraryManager = MediaLibraryManager::GetMediaLibraryManager();

unsigned char FILE_CONTENT_JPG[] = {
    0x49, 0x44, 0x33, 0x03, 0x20, 0x20, 0x20, 0x0c, 0x24, 0x5d, 0x54, 0x45, 0x4e, 0x43, 0x20, 0x20, 0x20, 0x0b,
    0x20, 0x20, 0x20, 0x50
};

string ConvertPath(string path)
{
    string tmp = "/storage/media/100/";
    path = tmp + path.substr(strlen("/storage/media/"));
    return path;
}

void Asset::GetInfo()
{
    MEDIA_DEBUG_LOG("path:%{public}s uri:%{public}s fileId:%{public}d", path_.c_str(), uri_.c_str(), fileId_);
}

void MedialibraryEnvInitDir()
{
    g_assetMap["Camera"] = make_shared<Asset>("Camera", MediaType::MEDIA_TYPE_ALBUM);
    g_assetMap["Videos"] = make_shared<Asset>("Videos", MediaType::MEDIA_TYPE_ALBUM);
    g_assetMap["Pictures"] = make_shared<Asset>("Pictures", MediaType::MEDIA_TYPE_ALBUM);
    g_assetMap["Documents"] = make_shared<Asset>("Documents", MediaType::MEDIA_TYPE_ALBUM);
    g_assetMap["Download"] = make_shared<Asset>("Download", MediaType::MEDIA_TYPE_ALBUM);
    g_assetMap["Dir_OpenFile_test_001"] = make_shared<Asset>("Dir_OpenFile_test_001", MediaType::MEDIA_TYPE_ALBUM);
    g_assetMap["Dir_CreateFile_test_001"] = make_shared<Asset>("Dir_CreateFile_test_001", MediaType::MEDIA_TYPE_ALBUM);
    g_assetMap["Dir_Delete_test_001"] = make_shared<Asset>("Dir_Delete_test_001", MediaType::MEDIA_TYPE_ALBUM);
    g_assetMap["Dir_Move_test_001"] = make_shared<Asset>("Dir_Move_test_001", MediaType::MEDIA_TYPE_ALBUM);
    g_assetMap["Dir_Move_test_001_dst"] = make_shared<Asset>("Dir_Move_test_001_dst", MediaType::MEDIA_TYPE_ALBUM);
    g_assetMap["Dir_Move_test_002"] = make_shared<Asset>("Dir_Move_test_002", MediaType::MEDIA_TYPE_ALBUM);
    g_assetMap["Dir_Move_test_002_dst"] = make_shared<Asset>("Dir_Move_test_002_dst", MediaType::MEDIA_TYPE_ALBUM);
    g_assetMap["Dir_Move_test_003"] = make_shared<Asset>("Dir_Move_test_003", MediaType::MEDIA_TYPE_ALBUM);
    g_assetMap["Dir_Move_test_004"] = make_shared<Asset>("Dir_Move_test_004", MediaType::MEDIA_TYPE_ALBUM);
    g_assetMap["Dir_Rename_test_001"] = make_shared<Asset>("Dir_Rename_test_001", MediaType::MEDIA_TYPE_ALBUM);
    g_assetMap["Dir_Rename_test_002"] = make_shared<Asset>("Dir_Rename_test_002", MediaType::MEDIA_TYPE_ALBUM);
    g_assetMap["Dir_Rename_test_003"] = make_shared<Asset>("Dir_Rename_test_003", MediaType::MEDIA_TYPE_ALBUM);
    g_assetMap["Dir_ListFile_test_002"] = make_shared<Asset>("Dir_ListFile_test_002", MediaType::MEDIA_TYPE_ALBUM);
    g_assetMap["Dir_ListFile_temp"] = make_shared<Asset>("Dir_ListFile_temp", MediaType::MEDIA_TYPE_ALBUM);
    g_assetMap["temp.png"] = make_shared<Asset>("temp.png", "Camera/", MediaType::MEDIA_TYPE_IMAGE);
    g_assetMap["temp.mp4"] = make_shared<Asset>("temp.mp4", "Videos/", MediaType::MEDIA_TYPE_VIDEO);
    g_assetMap["temp.jpg"] = make_shared<Asset>("temp.jpg", "Pictures/", MediaType::MEDIA_TYPE_IMAGE);
    g_assetMap["temp.txt"] = make_shared<Asset>("temp.txt", "Documents/", MediaType::MEDIA_TYPE_FILE);
    g_assetMap["temp.exe"] = make_shared<Asset>("temp.exe", "Download/", MediaType::MEDIA_TYPE_FILE);
}

void MedialibraryEnvInitFile()
{
    g_assetMap["Open001.jpg"] = make_shared<Asset>("Open001.jpg", "Pictures/Dir_OpenFile_test_001/",
        MediaType::MEDIA_TYPE_IMAGE);
    g_assetMap["Temp001.jpg"] = make_shared<Asset>("Temp001.jpg", "Pictures/Dir_CreateFile_test_001/",
        MediaType::MEDIA_TYPE_IMAGE);
    g_assetMap["Delete001.jpg"] = make_shared<Asset>("Delete001.jpg", "Pictures/Dir_Delete_test_001/",
        MediaType::MEDIA_TYPE_IMAGE);
    g_assetMap["Move001.jpg"] = make_shared<Asset>("Move001.jpg", "Pictures/Dir_Move_test_001/",
        MediaType::MEDIA_TYPE_IMAGE);
    g_assetMap["Move002.jpg"] = make_shared<Asset>("Move002.jpg", "Pictures/Dir_Move_test_001/",
        MediaType::MEDIA_TYPE_IMAGE);
    g_assetMap["Move003.jpg"] = make_shared<Asset>("Move003.jpg", "Pictures/Dir_Move_test_001/",
        MediaType::MEDIA_TYPE_IMAGE);
    g_assetMap["Move004.jpg"] = make_shared<Asset>("Move004.jpg", "Pictures/Dir_Move_test_001/",
        MediaType::MEDIA_TYPE_IMAGE);
    g_assetMap["Move002.jpg_1"] = make_shared<Asset>("Move002.jpg", "Pictures/Dir_Move_test_001_dst/",
        MediaType::MEDIA_TYPE_IMAGE);
    g_assetMap["Temp002.jpg"] = make_shared<Asset>("Temp002.jpg", "Pictures/Dir_Move_test_001_dst/",
        MediaType::MEDIA_TYPE_IMAGE);
    g_assetMap["Temp003.jpg"] = make_shared<Asset>("Temp003.jpg", "Pictures/Dir_Move_test_002/",
        MediaType::MEDIA_TYPE_IMAGE);
    g_assetMap["Temp004.jpg"] = make_shared<Asset>("Temp004.jpg", "Pictures/Dir_Move_test_002_dst/",
        MediaType::MEDIA_TYPE_IMAGE);
    g_assetMap["Temp005.jpg"] = make_shared<Asset>("Temp005.jpg", "Pictures/Dir_Move_test_003/",
        MediaType::MEDIA_TYPE_IMAGE);
    g_assetMap["Move005.png"] = make_shared<Asset>("Move005.png", "Download/Dir_Move_test_004/",
        MediaType::MEDIA_TYPE_IMAGE);
    g_assetMap["Move005.txt"] = make_shared<Asset>("Move005.txt", "Download/Dir_Move_test_004/",
        MediaType::MEDIA_TYPE_FILE);
    g_assetMap["Rename001.jpg"] = make_shared<Asset>("Rename001.jpg", "Pictures/Dir_Rename_test_001/",
        MediaType::MEDIA_TYPE_IMAGE);
    g_assetMap["Rename002.jpg"] = make_shared<Asset>("Rename002.jpg", "Pictures/Dir_Rename_test_001/",
        MediaType::MEDIA_TYPE_IMAGE);
    g_assetMap["Rename003.jpg"] = make_shared<Asset>("Rename003.jpg", "Pictures/Dir_Rename_test_001/",
        MediaType::MEDIA_TYPE_IMAGE);
    g_assetMap["Rename003_rename.jpg"] = make_shared<Asset>("Rename003_rename.jpg", "Pictures/Dir_Rename_test_001/",
        MediaType::MEDIA_TYPE_IMAGE);
    g_assetMap["Rename004.jpg"] = make_shared<Asset>("Rename004.jpg", "Pictures/Dir_Rename_test_001/",
        MediaType::MEDIA_TYPE_IMAGE);
    g_assetMap["Temp006.jpg"] = make_shared<Asset>("Temp006.jpg", "Pictures/Dir_Rename_test_002/",
        MediaType::MEDIA_TYPE_IMAGE);
    g_assetMap["Temp007.jpg"] = make_shared<Asset>("Temp007.jpg", "Pictures/Dir_Rename_test_002/Dir_Rename_test_003/",
        MediaType::MEDIA_TYPE_IMAGE);
    g_assetMap["ListFile001.jpg"] = make_shared<Asset>("ListFile001.jpg", "Pictures/Dir_ListFile_test_002/",
        MediaType::MEDIA_TYPE_IMAGE);
    g_assetMap["ListFile002.jpg"] = make_shared<Asset>("ListFile002.jpg", "Pictures/Dir_ListFile_test_002/",
        MediaType::MEDIA_TYPE_IMAGE);
    g_assetMap["ListFile003.jpg"] = make_shared<Asset>("ListFile003.jpg", "Pictures/Dir_ListFile_test_002/",
        MediaType::MEDIA_TYPE_IMAGE);
    g_assetMap["Temp008.jpg"] = make_shared<Asset>("Temp008.jpg", "Pictures/Dir_ListFile_test_002/Dir_ListFile_temp/",
        MediaType::MEDIA_TYPE_IMAGE);
}

void MedialibraryEnvInit()
{
    MedialibraryEnvInitDir();
    MedialibraryEnvInitFile();
}

std::unique_ptr<FileAsset> GetFile(int id)
{
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    vector<string> columns;
    DataSharePredicates predicates;
    string prefix = MEDIA_DATA_DB_ID + " = " + to_string(id);
    predicates.SetWhereClause(prefix);
    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<DataShareResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, predicates, columns);
    EXPECT_NE((resultSet == nullptr), true);

    unique_ptr<FetchResult> fetchFileResult = make_unique<FetchResult>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() <= 0), true);

    unique_ptr<FileAsset> fileAsset = fetchFileResult->GetLastObject();
    EXPECT_NE((fileAsset == nullptr), true);
    return fileAsset;
}

std::unique_ptr<FileAsset> GetFile(const string &name)
{
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    vector<string> columns;
    DataSharePredicates predicates;
    string prefix = MEDIA_DATA_DB_NAME + " = '" + name + "'";
    predicates.SetWhereClause(prefix);
    Uri queryFileUri(MEDIALIBRARY_DATA_URI);
    shared_ptr<DataShareResultSet> resultSet = nullptr;
    resultSet = helper->Query(queryFileUri, predicates, columns);
    MEDIA_ERR_LOG("file name %{public}s", name.c_str());
    EXPECT_NE((resultSet == nullptr), true);

    unique_ptr<FetchResult> fetchFileResult = make_unique<FetchResult>(move(resultSet));
    EXPECT_NE((fetchFileResult->GetCount() <= 0), true);

    unique_ptr<FileAsset> fileAsset = fetchFileResult->GetLastObject();
    EXPECT_NE((fileAsset == nullptr), true);
    return fileAsset;
}

string GetFilePath(int id)
{
    unique_ptr<FileAsset> fileAsset = GetFile(id);
    if (fileAsset == nullptr) {
        MEDIA_ERR_LOG("file not exist, id %{public}d", id);
        return "";
    }
    MEDIA_ERR_LOG("file id %{public}d, path %{public}s", id, fileAsset->GetPath().c_str());
    return fileAsset->GetPath();
}

void CleanAll()
{
    string cmd = "rm -rf " + g_storagePath + "/*";
    system(cmd.c_str());
    MEDIA_DEBUG_LOG("SetUpTestCase %{public}s", cmd.c_str());
    DataSharePredicates predicates;
    string prefix = MEDIA_DATA_DB_ID + " <> -1";
    predicates.SetWhereClause(prefix);
    Uri deleteUri(MEDIALIBRARY_DATA_URI);
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    int32_t index = helper->Delete(deleteUri, predicates);
    MEDIA_DEBUG_LOG("CleanAll index %{public}d", index);
}

void CreateFile(std::string baseURI, shared_ptr<Asset> &asset, unsigned char fileContent[], int len)
{
    Uri createAssetUri(Media::MEDIALIBRARY_DATA_URI + "/" + Media::MEDIA_FILEOPRN + "/" +
        Media::MEDIA_FILEOPRN_CREATEASSET);
    DataShareValuesBucket valuesBucket;
    std::string targetPath = asset->GetDir();
    std::string newName = asset->GetName();
    int mediaType = asset->GetType();
    valuesBucket.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    valuesBucket.PutString(MEDIA_DATA_DB_NAME, newName);
    valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, targetPath);
    MEDIA_INFO_LOG("CreateFile:: start Create file: %s", newName.c_str());
    std::shared_ptr<DataShare::DataShareHelper> helper = g_mediaDataShareHelper;
    int32_t index = helper->Insert(createAssetUri, valuesBucket);
    string destUri = baseURI + "/" + std::to_string(index);
    asset->SetUri(destUri);
    asset->SetPath(GetFilePath(index));
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

void CreateAsset()
{
    for (auto obj : g_assetMap) {
        shared_ptr<Asset> asset = obj.second;
        if (asset->GetType() != MediaType::MEDIA_TYPE_ALBUM) {
            CreateFile(MEDIALIBRARY_IMAGE_URI, asset, FILE_CONTENT_JPG, sizeof(FILE_CONTENT_JPG));
        }
    }
    for (auto obj : g_assetMap) {
        shared_ptr<Asset> asset = obj.second;
        if (asset->GetType() == MediaType::MEDIA_TYPE_ALBUM) {
            unique_ptr<FileAsset> file = GetFile(asset->GetName());
            if (!file) {
                return;
            }
            MEDIA_INFO_LOG("CreateFile::Album: %{public}s", file->GetUri().c_str());
            asset->SetUri(file->GetUri());
            asset->SetPath(file->GetPath());
        }
    }
}

std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper(int32_t systemAbilityId)
{
    MEDIA_INFO_LOG("CreateDataShareHelper::CreateFileExtHelper ");
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        MEDIA_INFO_LOG("CreateDataShareHelper Get system ability mgr failed.");
        return nullptr;
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    while (remoteObj == nullptr) {
        MEDIA_INFO_LOG("CreateDataShareHelper GetSystemAbility Service Failed.");
        return nullptr;
    }
    mediaLibraryManager->InitMediaLibraryManager(remoteObj);
    return DataShare::DataShareHelper::Creator(remoteObj, MEDIALIBRARY_DATA_URI);
}

std::shared_ptr<FileAccessFwk::FileAccessHelper> CreateFileExtHelper(int32_t systemAbilityId)
{
    MEDIA_INFO_LOG("DataMedialibraryRdbHelper::CreateFileExtHelper ");
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        MEDIA_INFO_LOG("DataMedialibraryRdbHelper Get system ability mgr failed.");
        return nullptr;
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    while (remoteObj == nullptr) {
        MEDIA_INFO_LOG("DataMedialibraryRdbHelper GetSystemAbility Service Failed.");
        return nullptr;
    }
    AppExecFwk::Want want;
    want.SetElementName("com.ohos.medialibrary.medialibrarydata", "FileExtensionAbility");
    return FileAccessFwk::FileAccessHelper::Creator(remoteObj, want);
}

void MediaLibraryExtUnitTest::SetUpTestCase(void)
{
    MEDIA_DEBUG_LOG("SetUpTestCase invoked");
    g_mediaFileExtHelper = CreateFileExtHelper(uid);
    g_mediaDataShareHelper = CreateDataShareHelper(uid);
    if (g_mediaFileExtHelper == nullptr) {
        MEDIA_DEBUG_LOG("medialibraryDataAbilityHelper fail");
        return;
    }
    if (g_mediaDataShareHelper == nullptr) {
        MEDIA_DEBUG_LOG("g_mediaDataShareHelper fail");
        return;
    }
    CleanAll();
    MedialibraryEnvInit();
    CreateAsset();
    sleep(1);
}

void MediaLibraryExtUnitTest::TearDownTestCase(void)
{
    MEDIA_DEBUG_LOG("TearDownTestCase invoked");
}

// SetUp:Execute before each test case
void MediaLibraryExtUnitTest::SetUp() {}

void MediaLibraryExtUnitTest::TearDown(void) {}

bool CheckFileExtHelper()
{
    if (g_mediaFileExtHelper == nullptr) {
        MEDIA_DEBUG_LOG("DataAbilityHelper init fail");
        return false;
    }
    return true;
}

int32_t IsFileExists(const string &fileName)
{
    struct stat statInfo {};
    MEDIA_DEBUG_LOG("IsFileExists fileName %{public}s", fileName.c_str());
    int errCode = stat(fileName.c_str(), &statInfo);
    MEDIA_DEBUG_LOG("IsFileExists errCode %{public}d", errCode);
    if (errCode == SUCCESS) {
        return SUCCESS;
    } else {
        return FAIL;
    }
}

string GetRenameNewPath(const string &oldPath, const string &displayName)
{
    size_t slashIndex = oldPath.rfind('/');
    return (oldPath.substr(0, slashIndex) + SLASH_CHAR + displayName);
}

bool IsEnvReady()
{
    EXPECT_EQ(g_envReady, TRUE);
    return g_envReady;
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
    // Pictures Album has been create in setup
    MEDIA_DEBUG_LOG("medialib_CheckSetUpEnv_test_001");
    if (IsFileExists(ConvertPath(g_assetMap["Pictures"]->GetPath())) == SUCCESS) {
        g_envReady = true;
    }
    EXPECT_EQ(IsFileExists(ConvertPath(g_assetMap["Pictures"]->GetPath())), SUCCESS);
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    Uri uri(g_assetMap["Open001.jpg"]->GetUri());
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
        memset(str, 0, sizeof(str));
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    Uri uri(g_assetMap["Pictures"]->GetUri());
    MEDIA_DEBUG_LOG("medialib_OpenFile_test_002 uri %{public}s", uri.ToString().c_str());
    int fd = g_mediaFileExtHelper->OpenFile(uri, O_RDWR);
    if (fd == FileAccessFwk::ERR_IPC_ERROR) {
        MEDIA_DEBUG_LOG("medialib_OpenFile_test_002 OpenFile errno: %{public}d, errmsg: %{public}s",
            errno, strerror(errno));
    }
    EXPECT_EQ(fd, FileAccessFwk::ERR_IPC_ERROR);
    MEDIA_DEBUG_LOG("medialib_OpenFile_test_002 ret: %{public}d, errno: %{public}d, errmsg: %{public}s",
        fd, errno, strerror(errno));
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    shared_ptr<Asset> album = g_assetMap["Dir_CreateFile_test_001"];
    Uri parentUri(album->GetUri());
    Uri newUri("");
    string displayName = "CreateFile001.jpg";
    string filePath = album->GetPath() + "/" + displayName;
    MEDIA_DEBUG_LOG("medialib_CreateFile_test_001 parentUri: %{public}s, displayName: %{public}s, filePath: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str(), filePath.c_str());
    EXPECT_EQ(IsFileExists(ConvertPath(filePath)), FAIL);
    int32_t ret = g_mediaFileExtHelper->CreateFile(parentUri, displayName, newUri);
    EXPECT_EQ(ret == 0, TRUE);
    EXPECT_EQ(IsFileExists(ConvertPath(filePath)), SUCCESS);
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    Uri parentUri(g_assetMap["Dir_CreateFile_test_001"]->GetUri());
    Uri newUri("");
    string displayName = "CreateFile/001.jpg";
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    string uri = "datashare:///media/file/test";
    Uri parentUri(uri);
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    string uri = "datashare://1d3cb099659d53b3ee15faaab3c00a8ff983382ebc8b01aabde039ed084e167b/media/file/1";
    Uri parentUri(uri);
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    shared_ptr<Asset> album = g_assetMap["Dir_CreateFile_test_001"];
    Uri parentUri(album->GetUri());
    Uri newUri("");
    string displayName = "Temp001.jpg";
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    Uri parentUri("datashare:///media/root");
    string displayName = "Audios";
    string dirPath = ROOT_MEDIA_DIR + displayName;
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_001 parentUri: %{public}s, displayName: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str());
    EXPECT_EQ(IsFileExists(ConvertPath(dirPath)), FAIL);
    Uri newUri("");
    int32_t ret = g_mediaFileExtHelper->Mkdir(parentUri, displayName, newUri);
    EXPECT_EQ(IsFileExists(ConvertPath(dirPath)), SUCCESS);
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    Uri parentUri("datashare://1d3cb099659d53b3ee15faaab3c00a8ff983382ebc8b01aabde039ed084e167b/root");
    string displayName = "Mkdir001";
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    Uri parentUri("datashare:///media/root");
    string displayName = "Mkdir001";
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    Uri parentUri(g_assetMap["Pictures"]->GetUri());
    string displayName = "Mkdir001";
    string dirPath = g_assetMap["Pictures"]->GetPath() + "/" + displayName;
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_004 parentUri: %{public}s, displayName: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str());
    EXPECT_EQ(IsFileExists(ConvertPath(dirPath)), FAIL);
    Uri newUri("");
    int32_t ret = g_mediaFileExtHelper->Mkdir(parentUri, displayName, newUri);
    EXPECT_EQ(IsFileExists(ConvertPath(dirPath)), SUCCESS);
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    Uri parentUri("datashare:///media/file/test");
    string displayName = "Mkdir001";
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    Uri parentUri("datashare://1d3cb099659d53b3ee15faaab3c00a8ff983382ebc8b01aabde039ed084e167b/media/file/2");
    string displayName = "Mkdir001";
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    Uri parentUri(g_assetMap["Pictures"]->GetUri());
    string displayName = "Mkdir002/Mkdir003";
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    Uri parentUri(g_assetMap["Pictures"]->GetUri());
    string displayName = "Dir_OpenFile_test_001";
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    shared_ptr<Asset> jpg = g_assetMap["Delete001.jpg"];
    Uri sourceUri(jpg->GetUri());
    MEDIA_DEBUG_LOG("medialib_Delete_test_001 sourceUri %{public}s", sourceUri.ToString().c_str());
    string filePath = jpg->GetPath();
    EXPECT_EQ(IsFileExists(ConvertPath(filePath)), SUCCESS);
    int32_t ret = g_mediaFileExtHelper->Delete(sourceUri);
    EXPECT_EQ(IsFileExists(ConvertPath(filePath)), FAIL);
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    string source = "datashare://1d3cb099659d53b3ee15faaab3c00a8ff983382ebc8b01aabde039ed084e167b/media/file/2";
    Uri sourceUri(source);
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    shared_ptr<Asset> src = g_assetMap["Move001.jpg"];
    shared_ptr<Asset> targetAlbum = g_assetMap["Dir_Move_test_001_dst"];
    Uri sourceUri(src->GetUri());
    Uri targetUri(targetAlbum->GetUri());
    Uri newUri("");
    MEDIA_DEBUG_LOG("medialib_Move_test_001 sourceUri: %{public}s, targetUri: %{public}s",
        sourceUri.ToString().c_str(), targetUri.ToString().c_str());
    string srcPath = src->GetPath();
    string displayName = src->GetName();
    string targetPath = targetAlbum->GetPath() + "/" + displayName;
    MEDIA_DEBUG_LOG("medialib_Move_test_001 srcPath: %{public}s, targetPath: %{public}s",
        srcPath.c_str(), targetPath.c_str());
    EXPECT_EQ(IsFileExists(ConvertPath(srcPath)), SUCCESS);
    EXPECT_EQ(IsFileExists(ConvertPath(targetPath)), FAIL);
    int32_t ret = g_mediaFileExtHelper->Move(sourceUri, targetUri, newUri);
    EXPECT_EQ(IsFileExists(ConvertPath(srcPath)), FAIL);
    EXPECT_EQ(IsFileExists(ConvertPath(targetPath)), SUCCESS);
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    shared_ptr<Asset> src = g_assetMap["Dir_Move_test_002"];
    shared_ptr<Asset> targetAlbum = g_assetMap["Dir_Move_test_002_dst"];
    Uri sourceUri(src->GetUri());
    Uri targetUri(targetAlbum->GetUri());
    Uri newUri("");
    MEDIA_DEBUG_LOG("medialib_Move_test_002 sourceUri: %{public}s, targetUri: %{public}s",
        sourceUri.ToString().c_str(), targetUri.ToString().c_str());
    string srcPath = src->GetPath();
    string displayName = src->GetName();
    string targetPath = targetAlbum->GetPath() + "/" + displayName;
    MEDIA_DEBUG_LOG("medialib_Move_test_002 srcPath: %{public}s, targetPath: %{public}s",
        srcPath.c_str(), targetPath.c_str());
    EXPECT_EQ(IsFileExists(ConvertPath(srcPath)), SUCCESS);
    EXPECT_EQ(IsFileExists(ConvertPath(targetPath)), FAIL);
    int32_t ret = g_mediaFileExtHelper->Move(sourceUri, targetUri, newUri);
    EXPECT_EQ(IsFileExists(ConvertPath(srcPath)), FAIL);
    EXPECT_EQ(IsFileExists(ConvertPath(targetPath)), SUCCESS);
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    Uri sourceUri(g_assetMap["Temp002.jpg"]->GetUri());
    string uri = "datashare:///media/file/test";
    Uri targetUri(uri);
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    Uri sourceUri(g_assetMap["Temp002.jpg"]->GetUri());
    string uri = "datashare://1d3cb099659d53b3ee15faaab3c00a8ff983382ebc8b01aabde039ed084e167b/media/file/2";
    Uri targetUri(uri);
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    Uri sourceUri("datashare:///media/file/test");
    Uri targetUri(g_assetMap["Dir_Move_test_001_dst"]->GetUri());
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    Uri sourceUri("datashare://1d3cb099659d53b3ee15faaab3c00a8ff983382ebc8b01aabde039ed084e167b/media/file/2");
    Uri targetUri(g_assetMap["Dir_Move_test_001_dst"]->GetUri());
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    Uri sourceUri(g_assetMap["Move002.jpg"]->GetUri());
    Uri targetUri(g_assetMap["Dir_Move_test_001_dst"]->GetUri());
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    shared_ptr<Asset> src = g_assetMap["Move003.jpg"];
    shared_ptr<Asset> targetAlbum = g_assetMap["Camera"];
    Uri sourceUri(src->GetUri());
    Uri targetUri(targetAlbum->GetUri());
    MEDIA_DEBUG_LOG("medialib_Move_test_008 sourceUri: %{public}s, targetUri: %{public}s",
        sourceUri.ToString().c_str(), targetUri.ToString().c_str());
    Uri newUri("");
    string srcPath = src->GetPath();
    string displayName = src->GetName();
    string targetPath = targetAlbum->GetPath() + "/" + displayName;
    MEDIA_DEBUG_LOG("medialib_Move_test_008 srcPath: %{public}s, targetPath: %{public}s",
        srcPath.c_str(), targetPath.c_str());
    EXPECT_EQ(IsFileExists(ConvertPath(srcPath)), SUCCESS);
    EXPECT_EQ(IsFileExists(ConvertPath(targetPath)), FAIL);
    int32_t ret = g_mediaFileExtHelper->Move(sourceUri, targetUri, newUri);
    EXPECT_EQ(IsFileExists(ConvertPath(srcPath)), FAIL);
    EXPECT_EQ(IsFileExists(ConvertPath(targetPath)), SUCCESS);
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    Uri sourceUri(g_assetMap["Move004.jpg"]->GetUri());
    Uri targetUri(g_assetMap["Videos"]->GetUri());
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    shared_ptr<Asset> src = g_assetMap["Dir_Move_test_003"];
    shared_ptr<Asset> targetAlbum = g_assetMap["Camera"];
    Uri sourceUri(src->GetUri());
    Uri targetUri(targetAlbum->GetUri());
    Uri newUri("");
    MEDIA_DEBUG_LOG("medialib_Move_test_010 sourceUri: %{public}s, targetUri: %{public}s",
        sourceUri.ToString().c_str(), targetUri.ToString().c_str());
    string srcPath = src->GetPath();
    string displayName = src->GetName();
    string targetPath = targetAlbum->GetPath() + "/" + displayName;
    MEDIA_DEBUG_LOG("medialib_Move_test_010 srcPath: %{public}s, targetPath: %{public}s",
        srcPath.c_str(), targetPath.c_str());
    EXPECT_EQ(IsFileExists(ConvertPath(srcPath)), SUCCESS);
    EXPECT_EQ(IsFileExists(ConvertPath(targetPath)), FAIL);
    int32_t ret = g_mediaFileExtHelper->Move(sourceUri, targetUri, newUri);
    EXPECT_EQ(IsFileExists(ConvertPath(srcPath)), FAIL);
    EXPECT_EQ(IsFileExists(ConvertPath(targetPath)), SUCCESS);
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    Uri sourceUri(g_assetMap["Dir_Move_test_004"]->GetUri());
    Uri targetUri(g_assetMap["Pictures"]->GetUri());
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    shared_ptr<Asset> jpg = g_assetMap["Rename001.jpg"];
    Uri sourceUri(jpg->GetUri());
    Uri newUri("");
    string displayName = "Rename001_rename.jpg";
    MEDIA_DEBUG_LOG("medialib_Rename_test_001 sourceUri: %{public}s, displayName: %{public}s",
        sourceUri.ToString().c_str(), displayName.c_str());
    string oldPath = jpg->GetPath();
    string newPath = GetRenameNewPath(oldPath, displayName);
    MEDIA_DEBUG_LOG("medialib_Rename_test_001 oldPath: %{public}s, newPath: %{public}s",
        oldPath.c_str(), newPath.c_str());
    EXPECT_EQ(IsFileExists(ConvertPath(oldPath)), SUCCESS);
    EXPECT_EQ(IsFileExists(ConvertPath(newPath)), FAIL);
    int32_t ret = g_mediaFileExtHelper->Rename(sourceUri, displayName, newUri);
    EXPECT_EQ(IsFileExists(ConvertPath(oldPath)), FAIL);
    EXPECT_EQ(IsFileExists(ConvertPath(newPath)), SUCCESS);
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    shared_ptr<Asset> album = g_assetMap["Dir_Rename_test_002"];
    Uri sourceUri(album->GetUri());
    Uri newUri("");
    string displayName = "Dir_Rename_test_002_rename";
    MEDIA_DEBUG_LOG("medialib_Rename_test_002 sourceUri: %{public}s, displayName: %{public}s",
        sourceUri.ToString().c_str(), displayName.c_str());
    string oldPath = album->GetPath();
    string newPath = GetRenameNewPath(oldPath, displayName);
    MEDIA_DEBUG_LOG("medialib_Rename_test_002 oldPath: %{public}s, newPath: %{public}s",
        oldPath.c_str(), newPath.c_str());
    EXPECT_EQ(IsFileExists(ConvertPath(oldPath)), SUCCESS);
    EXPECT_EQ(IsFileExists(ConvertPath(newPath)), FAIL);
    int32_t ret = g_mediaFileExtHelper->Rename(sourceUri, displayName, newUri);
    EXPECT_EQ(IsFileExists(ConvertPath(oldPath)), FAIL);
    EXPECT_EQ(IsFileExists(ConvertPath(newPath)), SUCCESS);
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    string uri = "datashare:///media/file/test";
    Uri sourceUri(uri);
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    string uri = "datashare://1d3cb099659d53b3ee15faaab3c00a8ff983382ebc8b01aabde039ed084e167b/media/file/2";
    Uri sourceUri(uri);
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    Uri sourceUri(g_assetMap["Rename002.jpg"]->GetUri());
    Uri newUri("");
    string displayName = "Rename/002.jpg";
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    Uri sourceUri(g_assetMap["Rename003.jpg"]->GetUri());
    Uri newUri("");
    string displayName = "Rename003_rename.jpg";
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    Uri sourceUri(g_assetMap["Rename004.jpg"]->GetUri());
    Uri newUri("");
    string displayName = "Rename004.txt";
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    Uri selectUri("datashare:///media/root");
    MEDIA_DEBUG_LOG("medialib_ListFile_test_001 selectUri %{public}s", selectUri.ToString().c_str());
    vector<FileAccessFwk::FileInfo> fileList = g_mediaFileExtHelper->ListFile(selectUri);
    // Camera, Videos, Pictures, Audios, Documents, Download
    EXPECT_EQ(fileList.size(), 6);
    for (auto t : fileList) {
        MEDIA_DEBUG_LOG("medialib_ListFile_test_001 t.fileName %{public}s", t.fileName.c_str());
    }
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    shared_ptr<Asset> jpg = g_assetMap["Dir_ListFile_test_002"];
    Uri selectUri(jpg->GetUri());
    MEDIA_DEBUG_LOG("medialib_ListFile_test_002 selectUri %{public}s", selectUri.ToString().c_str());
    vector<FileAccessFwk::FileInfo> fileList = g_mediaFileExtHelper->ListFile(selectUri);
    // Pictures/Dir_ListFile_test_002/ListFile001.jpg
    // Pictures/Dir_ListFile_test_002/ListFile002.jpg
    // Pictures/Dir_ListFile_test_002/ListFile003.jpg
    // Pictures/Dir_ListFile_test_002/Dir_ListFile_temp
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
    if (!CheckFileExtHelper()) {
        return;
    }
    CHECK_AND_RETURN_LOG(IsEnvReady(), "The environment is not ready.");
    vector<FileAccessFwk::DeviceInfo> deviceList = g_mediaFileExtHelper->GetRoots();
    EXPECT_EQ(deviceList.size(), 1);
    MEDIA_DEBUG_LOG("medialib_GetRoots_test_001 deviceList.size() %{public}lu", (long)deviceList.size());
}
} // namespace Media
} // namespace OHOS
