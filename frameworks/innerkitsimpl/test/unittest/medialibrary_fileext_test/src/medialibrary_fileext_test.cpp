/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#include "medialibrary_fileext_test.h"

#include <regex>

#include "file_asset.h"
#include "get_self_permissions.h"
#include "js_runtime.h"
#include "medialibrary_command.h"
#include "media_file_ext_ability.h"
#include "media_file_extention_utils.h"
#include "media_log.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_photo_operations.h"
#include "medialibrary_unittest_utils.h"
#include "scanner_utils.h"
#include "securec.h"
#include "uri.h"
#include "values_bucket.h"

using namespace std;
using namespace OHOS;
using namespace testing::ext;
using namespace FileAccessFwk;

namespace OHOS {
namespace Media {
static constexpr int32_t SLEEP_FIVE_SECONDS = 5;
namespace {
    shared_ptr<FileAsset> g_pictures = nullptr;
    shared_ptr<FileAsset> g_camera = nullptr;
    shared_ptr<FileAsset> g_videos = nullptr;
    shared_ptr<FileAsset> g_audios = nullptr;
    shared_ptr<FileAsset> g_documents = nullptr;
    shared_ptr<FileAsset> g_download = nullptr;
    shared_ptr<MediaFileExtAbility> mediaFileExtAbility = nullptr;
    const string DISTRIBUTED_PREFIX =
        "datashare://1d3cb099659d53b3ee15faaab3c00a8ff983382ebc8b01aabde039ed084e167b/media/";
    const string COMMON_PREFIX = "datashare:///media/";
    const string ROOT_URI = "root";
    const string COMMON_URI = "file/1";
    const string INVALID_URI = "file/test";
    const string INVALID_FILE_NAME = "te/st.jpg";
    const string INVALID_DIR_NAME = "te/st";
    
    // Unordered set contains list supported audio formats
    const std::unordered_set<std::string> SUPPORTED_AUDIO_FORMATS_SET {
        AUDIO_CONTAINER_TYPE_AAC,
        AUDIO_CONTAINER_TYPE_MP3,
        AUDIO_CONTAINER_TYPE_FLAC,
        AUDIO_CONTAINER_TYPE_WAV,
        AUDIO_CONTAINER_TYPE_OGG,
        AUDIO_CONTAINER_TYPE_M4A
    };

    // Unordered set contains list supported video formats
    const std::unordered_set<std::string> SUPPORTED_VIDEO_FORMATS_SET {
        VIDEO_CONTAINER_TYPE_MP4,
        VIDEO_CONTAINER_TYPE_3GP,
        VIDEO_CONTAINER_TYPE_MPG,
        VIDEO_CONTAINER_TYPE_MOV,
        VIDEO_CONTAINER_TYPE_WEBM,
        VIDEO_CONTAINER_TYPE_MKV,
        VIDEO_CONTAINER_TYPE_H264,
        VIDEO_CONTAINER_TYPE_MPEG,
        VIDEO_CONTAINER_TYPE_TS,
        VIDEO_CONTAINER_TYPE_M4V,
        VIDEO_CONTAINER_TYPE_3G2
    };

    // Unordered set contains list supported image formats
    const std::unordered_set<std::string> SUPPORTED_IMAGE_FORMATS_SET {
        IMAGE_CONTAINER_TYPE_BMP,
        IMAGE_CONTAINER_TYPE_BM,
        IMAGE_CONTAINER_TYPE_GIF,
        IMAGE_CONTAINER_TYPE_JPG,
        IMAGE_CONTAINER_TYPE_JPEG,
        IMAGE_CONTAINER_TYPE_JPE,
        IMAGE_CONTAINER_TYPE_PNG,
        IMAGE_CONTAINER_TYPE_WEBP,
        IMAGE_CONTAINER_TYPE_RAW,
        IMAGE_CONTAINER_TYPE_SVG,
        IMAGE_CONTAINER_TYPE_HEIF
    };
} // namespace

class ArkJsRuntime : public AbilityRuntime::JsRuntime {
public:
    ArkJsRuntime() {};

    ~ArkJsRuntime() {};

    void StartDebugMode(const DebugOption debugOption) {};
    void FinishPreload() {};
    bool LoadRepairPatch(const string& patchFile, const string& baseFile)
    {
        return true;
    };
    bool NotifyHotReloadPage()
    {
        return true;
    };
    bool UnLoadRepairPatch(const string& patchFile)
    {
        return true;
    };
    bool RunScript(const string& path, const string& hapPath, bool useCommonChunk = false)
    {
        return true;
    };
};

void MediaLibraryFileExtUnitTest::SetUpTestCase(void)
{
    MediaLibraryUnitTestUtils::Init();

    ArkJsRuntime runtime;
    mediaFileExtAbility = make_shared<MediaFileExtAbility>(runtime);

    vector<string> perms = { "ohos.permission.MEDIA_LOCATION" };
    uint64_t tokenId = 0;
    PermissionUtilsUnitTest::SetAccessTokenPermission("MediaLibraryFileExtUnitTest", perms, tokenId);
    ASSERT_TRUE(tokenId != 0);
}

void MediaLibraryFileExtUnitTest::TearDownTestCase(void)
{
    MEDIA_ERR_LOG("TearDownTestCase start");
    if (mediaFileExtAbility != nullptr) {
        mediaFileExtAbility = nullptr;
    }
    MEDIA_INFO_LOG("TearDownTestCase end");
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_FIVE_SECONDS));
}

void MediaLibraryFileExtUnitTest::SetUp()
{
    MediaLibraryUnitTestUtils::CleanTestFiles();
    MediaLibraryUnitTestUtils::InitRootDirs();
    g_pictures = MediaLibraryUnitTestUtils::GetRootAsset(TEST_PICTURES);
    g_camera = MediaLibraryUnitTestUtils::GetRootAsset(TEST_CAMERA);
    g_videos = MediaLibraryUnitTestUtils::GetRootAsset(TEST_VIDEOS);
    g_audios =  MediaLibraryUnitTestUtils::GetRootAsset(TEST_AUDIOS);
    g_documents =  MediaLibraryUnitTestUtils::GetRootAsset(TEST_DOCUMENTS);
    g_download = MediaLibraryUnitTestUtils::GetRootAsset(TEST_DOWNLOAD);
}

void MediaLibraryFileExtUnitTest::TearDown(void) {}

string ReturnUri(string prefixType, string uriType, string subUri = "")
{
    return (prefixType + uriType + subUri);
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_OpenFile_test_001, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    Uri fileAsset("");
    shared_ptr<FileAsset> albumAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("CreateFile_test_001", g_documents, albumAsset), true);
    Uri parentUri(albumAsset->GetUri());
    ASSERT_EQ(mediaFileExtAbility->CreateFile(parentUri, "OpenFile_test_001.jpg", fileAsset), E_SUCCESS);
    int fd = -1;
    auto ret = mediaFileExtAbility->OpenFile(fileAsset, O_RDWR, fd);
    MEDIA_DEBUG_LOG("medialib_OpenFile_test_001 fileAsset: %{public}s, fd: %{public}d",
        fileAsset.ToString().c_str(), fd);
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

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_OpenFile_test_002, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    Uri uri(g_documents->GetUri());
    MEDIA_DEBUG_LOG("medialib_OpenFile_test_002 uri %{public}s", uri.ToString().c_str());
    int fd = -1;
    auto ret = mediaFileExtAbility->OpenFile(uri, O_RDWR, fd);
    if (ret == JS_INNER_FAIL) {
        MEDIA_DEBUG_LOG("medialib_OpenFile_test_002 OpenFile errno: %{public}d, errmsg: %{public}s",
            errno, strerror(errno));
    }
    EXPECT_EQ(ret, JS_INNER_FAIL);
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_CreateFile_test_001, TestSize.Level0)
{
    MEDIA_DEBUG_LOG("medialib_CreateFile_test_001::Start");
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    shared_ptr<FileAsset> albumAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("CreateFile_test_001", g_documents, albumAsset), true);
    Uri parentUri(albumAsset->GetUri());
    Uri newUri("");
    string displayName = "CreateFile001.jpg";
    string filePath = albumAsset->GetPath() + "/" + displayName;
    MEDIA_DEBUG_LOG("parentUri: %{private}s, displayName: %{public}s, filePath: %{private}s",
        parentUri.ToString().c_str(), displayName.c_str(), filePath.c_str());
    EXPECT_EQ(MediaLibraryUnitTestUtils::IsFileExists(filePath), false);
    int32_t ret = mediaFileExtAbility->CreateFile(parentUri, displayName, newUri);
    EXPECT_EQ(ret, E_SUCCESS);
    EXPECT_EQ(MediaLibraryUnitTestUtils::IsFileExists(filePath), true);
    MEDIA_DEBUG_LOG("ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
    MEDIA_DEBUG_LOG("medialib_CreateFile_test_001::End");
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_CreateFile_test_002, TestSize.Level0)
{
    MEDIA_DEBUG_LOG("medialib_CreateFile_test_002::Start");
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    shared_ptr<FileAsset> albumAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("CreateFile_test_002", g_documents, albumAsset), true);
    Uri parentUri(albumAsset->GetUri());
    Uri newUri("");
    string displayName = INVALID_FILE_NAME;
    MEDIA_DEBUG_LOG("parentUri: %{public}s, displayName: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str());
    int32_t ret = mediaFileExtAbility->CreateFile(parentUri, displayName, newUri);
    EXPECT_EQ(ret, JS_E_DISPLAYNAME);
    MEDIA_DEBUG_LOG("ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
    MEDIA_DEBUG_LOG("medialib_CreateFile_test_002::End");
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_CreateFile_test_003, TestSize.Level0)
{
    MEDIA_DEBUG_LOG("medialib_CreateFile_test_003::Start");
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    Uri parentUri(ReturnUri(COMMON_PREFIX, INVALID_URI));
    Uri newUri("");
    string displayName = "CreateFile001.jpg";
    MEDIA_DEBUG_LOG("parentUri: %{public}s, displayName: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str());
    int32_t ret = mediaFileExtAbility->CreateFile(parentUri, displayName, newUri);
    EXPECT_EQ(ret, JS_E_URI);
    MEDIA_DEBUG_LOG("ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
    MEDIA_DEBUG_LOG("medialib_CreateFile_test_003::End");
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_CreateFile_test_004, TestSize.Level0)
{
    MEDIA_DEBUG_LOG("medialib_CreateFile_test_004::Start");
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    Uri parentUri(ReturnUri(DISTRIBUTED_PREFIX, COMMON_URI));
    Uri newUri("");
    string displayName = "CreateFile001.jpg";
    MEDIA_DEBUG_LOG("parentUri: %{public}s, displayName: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str());
    int32_t ret = mediaFileExtAbility->CreateFile(parentUri, displayName, newUri);
    EXPECT_EQ(ret, JS_E_URI);
    MEDIA_DEBUG_LOG("ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
    MEDIA_DEBUG_LOG("medialib_CreateFile_test_004::End");
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_CreateFile_test_005, TestSize.Level0)
{
    MEDIA_DEBUG_LOG("medialib_CreateFile_test_005::Start");
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    shared_ptr<FileAsset> albumAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("CreateFile_test_005", g_documents, albumAsset), true);
    shared_ptr<FileAsset> fileAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("CreateFile_test_005.jpg", albumAsset, fileAsset), true);
    Uri parentUri(albumAsset->GetUri());
    Uri newUri("");
    string displayName = "CreateFile_test_005.jpg";
    MEDIA_DEBUG_LOG("parentUri: %{public}s, displayName: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str());
    int32_t ret = mediaFileExtAbility->CreateFile(parentUri, displayName, newUri);
    EXPECT_EQ(ret, JS_ERR_FILE_EXIST);
    MEDIA_DEBUG_LOG("ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
    MEDIA_DEBUG_LOG("medialib_CreateFile_test_005::End");
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Mkdir_test_001, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    auto audioAsset = MediaLibraryUnitTestUtils::GetRootAsset(TEST_AUDIOS);
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_001 delete audios start, uri: %{public}s", audioAsset->GetUri().c_str());
    ASSERT_EQ(MediaLibraryUnitTestUtils::DeleteDir(audioAsset->GetPath(), to_string(audioAsset->GetId())), true);
    Uri parentUri(ReturnUri(COMMON_PREFIX, ROOT_URI, MEDIALIBRARY_TYPE_FILE_URI));
    string displayName = "Documents";
    string dirPath = ROOT_MEDIA_DIR + displayName;
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_001 parentUri: %{public}s, displayName: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str());
    Uri newUri("");
    int32_t ret = mediaFileExtAbility->Mkdir(parentUri, displayName, newUri);
    EXPECT_EQ(MediaLibraryUnitTestUtils::IsFileExists(dirPath), true);
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_001 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Mkdir_test_002, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    Uri parentUri(ReturnUri(DISTRIBUTED_PREFIX, ROOT_URI, MEDIALIBRARY_TYPE_FILE_URI));
    string displayName = "Mkdir_test_002";
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_002 parentUri: %{public}s, displayName: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str());
    Uri newUri("");
    int32_t ret = mediaFileExtAbility->Mkdir(parentUri, displayName, newUri);
    EXPECT_EQ(ret, JS_E_URI);
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_002 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Mkdir_test_003, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    Uri parentUri(ReturnUri(COMMON_PREFIX, ROOT_URI, MEDIALIBRARY_TYPE_FILE_URI));
    string displayName = "Mkdir_test_003";
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_003 parentUri: %{public}s, displayName: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str());
    Uri newUri("");
    int32_t ret = mediaFileExtAbility->Mkdir(parentUri, displayName, newUri);
    EXPECT_EQ(ret, JS_E_DISPLAYNAME);
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_003 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Mkdir_test_004, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    Uri parentUri(g_download->GetUri());
    string displayName = "Mkdir_test_004";
    string dirPath = g_download->GetPath() + "/" + displayName;
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_004 parentUri: %{public}s, displayName: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str());
    EXPECT_EQ(MediaLibraryUnitTestUtils::IsFileExists(dirPath), false);
    Uri newUri("");
    int32_t ret = mediaFileExtAbility->Mkdir(parentUri, displayName, newUri);
    EXPECT_EQ(MediaLibraryUnitTestUtils::IsFileExists(dirPath), true);
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_004 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Mkdir_test_005, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    Uri parentUri(ReturnUri(COMMON_PREFIX, INVALID_URI));
    string displayName = "Mkdir_test_005";
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_005 parentUri: %{public}s, displayName: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str());
    Uri newUri("");
    int32_t ret = mediaFileExtAbility->Mkdir(parentUri, displayName, newUri);
    EXPECT_EQ(ret, JS_E_URI);
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_005 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Mkdir_test_006, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    Uri parentUri(ReturnUri(DISTRIBUTED_PREFIX, COMMON_URI));
    string displayName = "Mkdir_test_006";
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_006 parentUri: %{public}s, displayName: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str());
    Uri newUri("");
    int32_t ret = mediaFileExtAbility->Mkdir(parentUri, displayName, newUri);
    EXPECT_EQ(ret, JS_E_URI);
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_006 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Mkdir_test_007, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    Uri parentUri(g_download->GetUri());
    string displayName = INVALID_DIR_NAME;
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_007 parentUri: %{public}s, displayName: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str());
    Uri newUri("");
    int32_t ret = mediaFileExtAbility->Mkdir(parentUri, displayName, newUri);
    EXPECT_EQ(ret, JS_E_DISPLAYNAME);
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_007 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Mkdir_test_008, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    shared_ptr<FileAsset> albumAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("Mkdir_test_008", g_download, albumAsset), true);
    Uri parentUri(g_download->GetUri());
    string displayName = "Mkdir_test_008";
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_008 parentUri: %{public}s, displayName: %{public}s",
        parentUri.ToString().c_str(), displayName.c_str());
    Uri newUri("");
    int32_t ret = mediaFileExtAbility->Mkdir(parentUri, displayName, newUri);
    EXPECT_EQ(ret, JS_ERR_FILE_EXIST);
    MEDIA_DEBUG_LOG("medialib_Mkdir_test_008 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Mkdir_test_009, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    Uri parentUri(g_camera->GetUri());
    string displayName = "test";
    Uri newUri("");
    int32_t ret = MediaFileExtentionUtils::Mkdir(parentUri, displayName, newUri);
    EXPECT_EQ(ret, JS_ERR_PERMISSION_DENIED);
    Uri parentUriTest(g_videos->GetUri());
    ret = MediaFileExtentionUtils::Mkdir(parentUriTest, displayName, newUri);
    EXPECT_EQ(ret, JS_ERR_PERMISSION_DENIED);
    Uri parentUriOne(g_pictures->GetUri());
    ret = MediaFileExtentionUtils::Mkdir(parentUriOne, displayName, newUri);
    EXPECT_EQ(ret, JS_ERR_PERMISSION_DENIED);
    Uri parentUriTwo(g_audios->GetUri());
    ret = MediaFileExtentionUtils::Mkdir(parentUriTwo, displayName, newUri);
    EXPECT_EQ(ret, JS_ERR_PERMISSION_DENIED);
    Uri parentUriThree(g_documents->GetUri());
    ret = MediaFileExtentionUtils::Mkdir(parentUriThree, displayName, newUri);
    EXPECT_GT(ret, E_SUCCESS);
    Uri parentUriFour(g_download->GetUri());
    ret = MediaFileExtentionUtils::Mkdir(parentUriFour, displayName, newUri);
    EXPECT_GT(ret, E_SUCCESS);
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Delete_test_001, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    shared_ptr<FileAsset> albumAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("Delete_test_001", g_documents, albumAsset), true);
    shared_ptr<FileAsset> fileAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("Delete_test_001.jpg", albumAsset, fileAsset), true);
    Uri sourceUri(fileAsset->GetUri());
    MEDIA_DEBUG_LOG("medialib_Delete_test_001 sourceUri %{public}s", sourceUri.ToString().c_str());
    EXPECT_EQ(MediaLibraryUnitTestUtils::IsFileExists(fileAsset->GetPath()), true);
    int32_t ret = mediaFileExtAbility->Delete(sourceUri);
    EXPECT_EQ(MediaLibraryUnitTestUtils::IsFileExists(fileAsset->GetPath()), false);
    MEDIA_DEBUG_LOG("medialib_Delete_test_001 ret: %{public}d", ret);
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Delete_test_002, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    Uri sourceUri(ReturnUri(DISTRIBUTED_PREFIX, COMMON_URI));
    MEDIA_DEBUG_LOG("medialib_Delete_test_002 sourceUri %{public}s", sourceUri.ToString().c_str());
    int32_t ret = mediaFileExtAbility->Delete(sourceUri);
    EXPECT_EQ(ret, JS_E_URI);
    MEDIA_DEBUG_LOG("medialib_Delete_test_002 ret: %{public}d", ret);
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Delete_test_003, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    shared_ptr<FileAsset> albumAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("Delete_test_001", g_pictures, albumAsset), true);
    shared_ptr<FileAsset> fileAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("Delete_test_001.jpg", albumAsset, fileAsset), true);
    Uri sourceUri(fileAsset->GetUri());
    int32_t ret = MediaFileExtentionUtils::Delete(sourceUri);
    EXPECT_EQ(ret, E_URI_INVALID);
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("Delete_test_001.jpg", g_documents, fileAsset), true);
    Uri sourceUriOne(fileAsset->GetUri());
    ret = MediaFileExtentionUtils::Delete(sourceUriOne);
    EXPECT_GT(ret, E_SUCCESS);
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("Delete_test_001.jpg", g_download, fileAsset), true);
    Uri sourceUriTwo(fileAsset->GetUri());
    ret = MediaFileExtentionUtils::Delete(sourceUriTwo);
    EXPECT_GT(ret, E_SUCCESS);
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("Delete_test_001.jpg", g_camera, fileAsset), true);
    Uri sourceUriThree(fileAsset->GetUri());
    ret = MediaFileExtentionUtils::Delete(sourceUriThree);
    EXPECT_EQ(ret, E_URI_INVALID);
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("Delete_test_001.mp4", g_videos, fileAsset), true);
    Uri sourceUriFour(fileAsset->GetUri());
    ret = MediaFileExtentionUtils::Delete(sourceUriFour);
    EXPECT_EQ(ret, E_URI_INVALID);
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("Delete_test_001.mp3", g_audios, fileAsset), true);
    Uri sourceUriFive(fileAsset->GetUri());
    ret = MediaFileExtentionUtils::Delete(sourceUriFive);
    EXPECT_EQ(ret, E_URI_INVALID);
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Move_test_001, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    shared_ptr<FileAsset> srcAlbumAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("Move_test_001", g_download, srcAlbumAsset), true);
    shared_ptr<FileAsset> destAlbumAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("Move_test_001_dst", g_download, destAlbumAsset), true);
    shared_ptr<FileAsset> fileAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("Move_test_001.jpg", srcAlbumAsset, fileAsset), true);
    Uri sourceUri(fileAsset->GetUri());
    Uri targetUri(destAlbumAsset->GetUri());
    Uri newUri("");
    MEDIA_DEBUG_LOG("medialib_Move_test_001 sourceUri: %{public}s, targetUri: %{public}s",
        sourceUri.ToString().c_str(), targetUri.ToString().c_str());
    string srcPath = fileAsset->GetPath();
    string displayName = fileAsset->GetDisplayName();
    string targetPath = destAlbumAsset->GetPath() + "/" + displayName;
    MEDIA_DEBUG_LOG("medialib_Move_test_001 srcPath: %{private}s, targetPath: %{private}s",
        srcPath.c_str(), targetPath.c_str());
    EXPECT_EQ(MediaLibraryUnitTestUtils::IsFileExists(srcPath), true);
    EXPECT_EQ(MediaLibraryUnitTestUtils::IsFileExists(targetPath), false);
    int32_t ret = mediaFileExtAbility->Move(sourceUri, targetUri, newUri);
    EXPECT_EQ(MediaLibraryUnitTestUtils::IsFileExists(srcPath), false);
    EXPECT_EQ(MediaLibraryUnitTestUtils::IsFileExists(targetPath), true);
    MEDIA_DEBUG_LOG("medialib_Move_test_001 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Move_test_002, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    shared_ptr<FileAsset> srcAlbumAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("Move_test_002", g_documents, srcAlbumAsset), true);
    shared_ptr<FileAsset> fileAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("Move_test_002.jpg", srcAlbumAsset, fileAsset), true);
    shared_ptr<FileAsset> destAlbumAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("Move_test_002_dest", g_download, destAlbumAsset), true);
    Uri sourceUri(srcAlbumAsset->GetUri());
    Uri targetUri(destAlbumAsset->GetUri());
    Uri newUri("");
    MEDIA_DEBUG_LOG("medialib_Move_test_002 sourceUri: %{public}s, targetUri: %{public}s",
        sourceUri.ToString().c_str(), targetUri.ToString().c_str());
    string srcPath = srcAlbumAsset->GetPath();
    string displayName = srcAlbumAsset->GetDisplayName();
    string targetPath = destAlbumAsset->GetPath() + "/" + displayName;
    MEDIA_DEBUG_LOG("medialib_Move_test_002 srcPath: %{private}s, targetPath: %{private}s",
        srcPath.c_str(), targetPath.c_str());
    EXPECT_EQ(MediaLibraryUnitTestUtils::IsFileExists(srcPath), true);
    EXPECT_EQ(MediaLibraryUnitTestUtils::IsFileExists(targetPath), false);
    int32_t ret = mediaFileExtAbility->Move(sourceUri, targetUri, newUri);
    EXPECT_EQ(MediaLibraryUnitTestUtils::IsFileExists(srcPath), false);
    EXPECT_EQ(MediaLibraryUnitTestUtils::IsFileExists(targetPath), true);
    MEDIA_DEBUG_LOG("medialib_Move_test_002 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Move_test_003, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    shared_ptr<FileAsset> fileAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("Move_test_003.jpg", g_download, fileAsset), true);
    Uri sourceUri(fileAsset->GetUri());
    Uri targetUri(ReturnUri(COMMON_PREFIX, INVALID_URI));
    Uri newUri("");
    MEDIA_DEBUG_LOG("medialib_Move_test_003 sourceUri: %{public}s, targetUri: %{public}s",
        sourceUri.ToString().c_str(), targetUri.ToString().c_str());
    int32_t ret = mediaFileExtAbility->Move(sourceUri, targetUri, newUri);
    EXPECT_EQ(ret, JS_E_URI);
    MEDIA_DEBUG_LOG("medialib_Move_test_003 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Move_test_004, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    shared_ptr<FileAsset> fileAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("Move_test_004.jpg", g_download, fileAsset), true);
    Uri sourceUri(fileAsset->GetUri());
    Uri targetUri(ReturnUri(DISTRIBUTED_PREFIX, COMMON_URI));
    Uri newUri("");
    MEDIA_DEBUG_LOG("medialib_Move_test_004 sourceUri: %{public}s, targetUri: %{public}s",
        sourceUri.ToString().c_str(), targetUri.ToString().c_str());
    int32_t ret = mediaFileExtAbility->Move(sourceUri, targetUri, newUri);
    EXPECT_EQ(ret, JS_E_URI);
    MEDIA_DEBUG_LOG("medialib_Move_test_004 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Move_test_005, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    shared_ptr<FileAsset> albumAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("Move_test_005_dest", g_download, albumAsset), true);
    Uri sourceUri(ReturnUri(COMMON_PREFIX, INVALID_URI));
    Uri targetUri(albumAsset->GetUri());
    Uri newUri("");
    MEDIA_DEBUG_LOG("medialib_Move_test_005 sourceUri: %{public}s, targetUri: %{public}s",
        sourceUri.ToString().c_str(), targetUri.ToString().c_str());
    int32_t ret = mediaFileExtAbility->Move(sourceUri, targetUri, newUri);
    EXPECT_EQ(ret, JS_E_URI);
    MEDIA_DEBUG_LOG("medialib_Move_test_005 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Move_test_006, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    shared_ptr<FileAsset> albumAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("Move_test_006_dest", g_download, albumAsset), true);
    Uri sourceUri(ReturnUri(DISTRIBUTED_PREFIX, COMMON_URI));
    Uri targetUri(albumAsset->GetUri());
    Uri newUri("");
    MEDIA_DEBUG_LOG("medialib_Move_test_006 sourceUri: %{public}s, targetUri: %{public}s",
        sourceUri.ToString().c_str(), targetUri.ToString().c_str());
    int32_t ret = mediaFileExtAbility->Move(sourceUri, targetUri, newUri);
    EXPECT_EQ(ret, JS_E_URI);
    MEDIA_DEBUG_LOG("medialib_Move_test_006 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Move_test_007, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    shared_ptr<FileAsset> fileAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("Move_test_007.jpg", g_download, fileAsset), true);
    shared_ptr<FileAsset> albumAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("Move_test_007_dest", g_download, albumAsset), true);
    shared_ptr<FileAsset> tempFileAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("Move_test_007.jpg", albumAsset, tempFileAsset), true);
    Uri sourceUri(fileAsset->GetUri());
    Uri targetUri(albumAsset->GetUri());
    Uri newUri("");
    MEDIA_DEBUG_LOG("medialib_Move_test_007 sourceUri: %{public}s, targetUri: %{public}s",
        sourceUri.ToString().c_str(), targetUri.ToString().c_str());
    int32_t ret = mediaFileExtAbility->Move(sourceUri, targetUri, newUri);
    EXPECT_EQ(ret, JS_ERR_FILE_EXIST);
    MEDIA_DEBUG_LOG("medialib_Move_test_007 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Move_test_008, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    if (g_documents == nullptr) {
        MEDIA_ERR_LOG("g_documents == nullptr");
        EXPECT_EQ(true, false);
        return;
    }
    shared_ptr<FileAsset> fileAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("Move_test_008.jpg", g_download, fileAsset), true);
    Uri sourceUri(fileAsset->GetUri());
    Uri targetUri(g_documents->GetUri());
    MEDIA_DEBUG_LOG("medialib_Move_test_008 sourceUri: %{public}s, targetUri: %{public}s",
        sourceUri.ToString().c_str(), targetUri.ToString().c_str());
    Uri newUri("");
    string srcPath = fileAsset->GetPath();
    string displayName = fileAsset->GetDisplayName();
    string targetPath = g_documents->GetPath() + "/" + displayName;
    MEDIA_DEBUG_LOG("medialib_Move_test_008 srcPath: %{private}s, targetPath: %{private}s",
        srcPath.c_str(), targetPath.c_str());
    EXPECT_EQ(MediaLibraryUnitTestUtils::IsFileExists(srcPath), true);
    EXPECT_EQ(MediaLibraryUnitTestUtils::IsFileExists(targetPath), false);
    int32_t ret = mediaFileExtAbility->Move(sourceUri, targetUri, newUri);
    EXPECT_EQ(MediaLibraryUnitTestUtils::IsFileExists(srcPath), false);
    EXPECT_EQ(MediaLibraryUnitTestUtils::IsFileExists(targetPath), true);
    MEDIA_DEBUG_LOG("medialib_Move_test_008 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Move_test_009, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    shared_ptr<FileAsset> srcAlbumAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("Move_test_002", g_pictures, srcAlbumAsset), true);
    shared_ptr<FileAsset> fileAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("Move_test_002.jpg", srcAlbumAsset, fileAsset), true);
    shared_ptr<FileAsset> destAlbumAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("Move_test_002_dest", g_pictures, destAlbumAsset), true);
    Uri sourceUri(srcAlbumAsset->GetUri());
    Uri targetUri(destAlbumAsset->GetUri());
    Uri newUri("");
    int32_t ret = MediaFileExtentionUtils::Move(sourceUri, targetUri, newUri);
    EXPECT_EQ(ret, JS_ERR_PERMISSION_DENIED);
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("Move_test_002_dest", g_camera, destAlbumAsset), true);
    Uri targetUriOne(destAlbumAsset->GetUri());
    ret = MediaFileExtentionUtils::Move(sourceUri, targetUriOne, newUri);
    EXPECT_EQ(ret, JS_ERR_PERMISSION_DENIED);
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("Move_test_002_dest", g_videos, destAlbumAsset), true);
    Uri targetUriTwo(destAlbumAsset->GetUri());
    ret = MediaFileExtentionUtils::Move(sourceUri, targetUriTwo, newUri);
    EXPECT_EQ(ret, JS_ERR_PERMISSION_DENIED);
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("Move_test_002_dest", g_audios, destAlbumAsset), true);
    Uri targetUriThree(destAlbumAsset->GetUri());
    ret = MediaFileExtentionUtils::Move(sourceUri, targetUriThree, newUri);
    EXPECT_EQ(ret, JS_ERR_PERMISSION_DENIED);
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("Move_test_002_dest", g_documents, destAlbumAsset), true);
    Uri targetUriFour(destAlbumAsset->GetUri());
    ret = MediaFileExtentionUtils::Move(sourceUri, targetUriFour, newUri);
    EXPECT_EQ(ret, JS_ERR_PERMISSION_DENIED);
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("Move_test_002_dest", g_download, destAlbumAsset), true);
    Uri targetUriFive(destAlbumAsset->GetUri());
    ret = MediaFileExtentionUtils::Move(sourceUri, targetUriFive, newUri);
    EXPECT_EQ(ret, JS_ERR_PERMISSION_DENIED);
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Rename_test_001, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    shared_ptr<FileAsset> fileAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("Rename_test_001.jpg", g_documents, fileAsset), true);
    Uri sourceUri(fileAsset->GetUri());
    Uri newUri("");
    string displayName = "new_Rename_test_001.jpg";
    MEDIA_DEBUG_LOG("medialib_Rename_test_001 sourceUri: %{public}s, displayName: %{public}s",
        sourceUri.ToString().c_str(), displayName.c_str());
    string oldPath = fileAsset->GetPath();
    string newPath = oldPath.substr(0, oldPath.rfind('/')) + "/" + displayName;
    MEDIA_DEBUG_LOG("medialib_Rename_test_001 oldPath: %{private}s, newPath: %{private}s",
        oldPath.c_str(), newPath.c_str());
    EXPECT_EQ(MediaLibraryUnitTestUtils::IsFileExists(oldPath), true);
    EXPECT_EQ(MediaLibraryUnitTestUtils::IsFileExists(newPath), false);
    int32_t ret = mediaFileExtAbility->Rename(sourceUri, displayName, newUri);
    EXPECT_EQ(MediaLibraryUnitTestUtils::IsFileExists(oldPath), false);
    EXPECT_EQ(MediaLibraryUnitTestUtils::IsFileExists(newPath), true);
    MEDIA_DEBUG_LOG("medialib_Rename_test_001 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Rename_test_002, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    shared_ptr<FileAsset> albumAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("Rename_test_002", g_documents, albumAsset), true);
    shared_ptr<FileAsset> fileAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("Rename_test_002.jpg", g_documents, fileAsset), true);
    Uri sourceUri(albumAsset->GetUri());
    Uri newUri("");
    string displayName = "new_Rename_test_002.png";
    MEDIA_DEBUG_LOG("medialib_Rename_test_002 sourceUri: %{public}s, displayName: %{public}s",
        sourceUri.ToString().c_str(), displayName.c_str());
    string oldPath = albumAsset->GetPath();
    string newPath = oldPath.substr(0, oldPath.rfind('/')) + "/" + displayName;
    MEDIA_DEBUG_LOG("medialib_Rename_test_002 oldPath: %{private}s, newPath: %{private}s",
        oldPath.c_str(), newPath.c_str());
    EXPECT_EQ(MediaLibraryUnitTestUtils::IsFileExists(oldPath), true);
    EXPECT_EQ(MediaLibraryUnitTestUtils::IsFileExists(newPath), false);
    int32_t ret = MediaFileExtentionUtils::Rename(sourceUri, displayName, newUri);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Rename_test_003, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    Uri sourceUri(ReturnUri(COMMON_PREFIX, INVALID_URI));
    Uri newUri("");
    string displayName = "rename";
    MEDIA_DEBUG_LOG("medialib_Rename_test_003 sourceUri: %{public}s, displayName: %{public}s",
        sourceUri.ToString().c_str(), displayName.c_str());
    int32_t ret = mediaFileExtAbility->Rename(sourceUri, displayName, newUri);
    EXPECT_EQ(ret, JS_E_URI);
    MEDIA_DEBUG_LOG("medialib_Rename_test_003 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Rename_test_004, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    Uri sourceUri(ReturnUri(DISTRIBUTED_PREFIX, COMMON_URI));
    Uri newUri("");
    string displayName = "rename";
    MEDIA_DEBUG_LOG("medialib_Rename_test_004 sourceUri: %{public}s, displayName: %{public}s",
        sourceUri.ToString().c_str(), displayName.c_str());
    int32_t ret = mediaFileExtAbility->Rename(sourceUri, displayName, newUri);
    EXPECT_EQ(ret, JS_E_URI);
    MEDIA_DEBUG_LOG("medialib_Rename_test_004 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Rename_test_005, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    shared_ptr<FileAsset> fileAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("Rename_test_005.jpg", g_documents, fileAsset), true);
    Uri sourceUri(fileAsset->GetUri());
    Uri newUri("");
    string displayName = INVALID_FILE_NAME;
    MEDIA_DEBUG_LOG("medialib_Rename_test_005 sourceUri: %{public}s, displayName: %{public}s",
        sourceUri.ToString().c_str(), displayName.c_str());
    int32_t ret = mediaFileExtAbility->Rename(sourceUri, displayName, newUri);
    EXPECT_EQ(ret, JS_E_DISPLAYNAME);
    MEDIA_DEBUG_LOG("medialib_Rename_test_005 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Rename_test_006, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    shared_ptr<FileAsset> fileAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("Rename_test_006.jpg", g_documents, fileAsset), true);
    shared_ptr<FileAsset> tempFileAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("new_Rename_test_006.jpg", g_documents, tempFileAsset), true);
    Uri sourceUri(fileAsset->GetUri());
    Uri newUri("");
    string displayName = "new_Rename_test_006.jpg";
    MEDIA_DEBUG_LOG("medialib_Rename_test_006 sourceUri: %{public}s, displayName: %{public}s",
        sourceUri.ToString().c_str(), displayName.c_str());
    int32_t ret = mediaFileExtAbility->Rename(sourceUri, displayName, newUri);
    EXPECT_EQ(ret, JS_ERR_FILE_EXIST);
    MEDIA_DEBUG_LOG("medialib_Rename_test_006 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Rename_test_007, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    shared_ptr<FileAsset> fileAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("Rename_test_007.jpg", g_documents, fileAsset), true);
    Uri sourceUri(fileAsset->GetUri());
    Uri newUri("");
    string displayName = "Rename_test_007.txt";
    MEDIA_DEBUG_LOG("medialib_Rename_test_007 sourceUri: %{public}s, displayName: %{public}s",
        sourceUri.ToString().c_str(), displayName.c_str());
    int32_t ret = mediaFileExtAbility->Rename(sourceUri, displayName, newUri);
    EXPECT_EQ(ret, E_SUCCESS);
    MEDIA_DEBUG_LOG("medialib_Rename_test_007 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Rename_test_008, TestSize.Level0)
{
    Uri sourceUri("");
    Uri parentUri(g_pictures->GetUri());
    int32_t ret = MediaFileExtentionUtils::CreateFile(parentUri, "Rename_test_007.jpg", sourceUri);
    EXPECT_EQ(ret, JS_ERR_PERMISSION_DENIED);
    Uri newUri("");
    string displayName = "new_Rename_test_007.jpg";
    ret = MediaFileExtentionUtils::Rename(sourceUri, displayName, newUri);
    EXPECT_EQ(ret, E_URI_INVALID);
    Uri parentUriOne(g_documents->GetUri());
    ret = MediaFileExtentionUtils::CreateFile(parentUriOne, "Rename_test_007.jpg", sourceUri);
    EXPECT_GT(ret, E_SUCCESS);
    ret = MediaFileExtentionUtils::Rename(sourceUri, displayName, newUri);
    EXPECT_EQ(ret, E_SUCCESS);
    Uri parentUriTwo(g_download->GetUri());
    ret = MediaFileExtentionUtils::CreateFile(parentUriTwo, "Rename_test_007.jpg", sourceUri);
    EXPECT_GT(ret, E_SUCCESS);
    ret = MediaFileExtentionUtils::Rename(sourceUri, displayName, newUri);
    EXPECT_EQ(ret, E_SUCCESS);
}

void DisplayFileList(const vector<FileInfo> &fileList)
{
    MEDIA_DEBUG_LOG("DisplayFileList::Start");
    for (auto t : fileList) {
        MEDIA_DEBUG_LOG("file.uri: %s, file.fileName: %s, file.mode: %d, file.mimeType: %s",
            t.uri.c_str(), t.fileName.c_str(), t.mode, t.mimeType.c_str());
    }
    MEDIA_DEBUG_LOG("DisplayFileList::End");
}

void ListFileFromRootResult(vector<FileInfo> rootFileList, int offset, int maxCount)
{
    const size_t URI_FILE_ROOT_FILE_SIZE = 2;
    const size_t URI_MEDIA_ROOT_IMAGE_SIZE = 0;
    const size_t URI_MEDIA_ROOT_VIDEO_SIZE = 0;
    const size_t URI_MEDIA_ROOT_AUDIO_SIZE = 0;
    FileAccessFwk::FileFilter filter;
    // URI_FILE_ROOT & URI_MEDIA_ROOT
    for (auto mediaRootInfo : rootFileList) {
        vector<FileInfo> fileList;
        auto ret = mediaFileExtAbility->ListFile(mediaRootInfo, offset, maxCount, filter, fileList);
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
            EXPECT_GT(fileList.size(), URI_MEDIA_ROOT_IMAGE_SIZE);
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

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_ListFile_test_001, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }

    shared_ptr<FileAsset> albumAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("ListFile_test_001", g_pictures, albumAsset), true);
    shared_ptr<FileAsset> tempAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("ListFile_test_001", albumAsset, tempAsset), true);
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("ListFile_test_001_1.jpg", albumAsset, tempAsset), true);
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("ListFile_test_001_2.jpg", albumAsset, tempAsset), true);
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("ListFile_test_001_3.jpg", albumAsset, tempAsset), true);
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("ListFile_test_001_1.mp4", g_videos, tempAsset), true);
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::CREATE,
        MediaLibraryApi::API_10);
    string name = "photo.jpg";
    NativeRdb::ValuesBucket values;
    values.PutString(MediaColumn::MEDIA_NAME, name);
    values.PutInt(MediaColumn::MEDIA_TYPE, MediaType::MEDIA_TYPE_IMAGE);
    cmd.SetValueBucket(values);
    int32_t ret = MediaLibraryPhotoOperations::Create(cmd);
    EXPECT_GE(ret, 0);
    const int64_t offset = 0;
    const int64_t maxCount = 100;
    FileAccessFwk::FileFilter filter;

    // URI_ROOT
    FileInfo rootInfo;
    rootInfo.uri = ReturnUri(COMMON_PREFIX, ROOT_URI);
    MEDIA_DEBUG_LOG("medialib_ListFile_test_001 URI_ROOT uri: %{public}s", rootInfo.uri.c_str());
    vector<FileInfo> rootFileList;
    ret = mediaFileExtAbility->ListFile(rootInfo, offset, maxCount, filter, rootFileList);
    EXPECT_EQ(ret, E_SUCCESS);
    MEDIA_DEBUG_LOG("medialib_ListFile_test_001 URI_ROOT fileList.size(): %{public}d", (int)rootFileList.size());
    DisplayFileList(rootFileList);
    EXPECT_EQ(rootFileList.size(), 4);

    ListFileFromRootResult(rootFileList, offset, maxCount);
}

void ListFileTestLimit(FileInfo dirInfo)
{
    const int64_t OFFSET_1 = 0;
    const int64_t OFFSET_2 = 5;
    const int64_t MAX_COUNT_1 = 5;
    const int64_t MAX_COUNT_2 = 100;
    vector<pair<int64_t, int64_t>> limits = { make_pair(OFFSET_1, MAX_COUNT_1),
        make_pair(OFFSET_2, MAX_COUNT_1), make_pair(OFFSET_1, MAX_COUNT_2), make_pair(OFFSET_2, MAX_COUNT_2) };
    const int DIR_RESULT = 8;

    FileAccessFwk::FileFilter filter;
    for (auto limit : limits) {
        // URI_DIR
        dirInfo.mimeType = DEFAULT_FILE_MIME_TYPE;
        vector<FileInfo> dirFileList;
        auto ret = mediaFileExtAbility->ListFile(dirInfo, limit.first, limit.second, filter, dirFileList);
        EXPECT_EQ(ret, E_SUCCESS);
        EXPECT_EQ(dirFileList.size(), min((DIR_RESULT - limit.first), limit.second));
    }
}

void ListFileTestFilter(FileInfo dirInfo)
{
    const int FILTER_COUNT = 3;
    const string SUFFIX_1 = ".jpg";
    const string SUFFIX_2 = ".png";
    const int32_t JPG_COUNT = 4;
    const int32_t PNG_COUNT = 2;
    const vector<int32_t> DIR_RESULT = {JPG_COUNT, PNG_COUNT, JPG_COUNT + PNG_COUNT};
    const vector<int32_t> ALBUM_RESULT = {JPG_COUNT, PNG_COUNT, JPG_COUNT + PNG_COUNT};
    vector<FileAccessFwk::FileFilter> filters;
    FileAccessFwk::FileFilter tempFilter;
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
        vector<FileInfo> dirFileList;
        auto ret = mediaFileExtAbility->ListFile(dirInfo, offset, maxCount, filters[i], dirFileList);
        MEDIA_ERR_LOG("medialib_ListFile_test_002:: dirFileList.size(): %d", (int)dirFileList.size());
        DisplayFileList(dirFileList);
        EXPECT_EQ(ret, E_SUCCESS);
        EXPECT_EQ(dirFileList.size(), DIR_RESULT[i]);
    }
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_ListFile_test_002, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    shared_ptr<FileAsset> albumAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("ListFile_test_002", g_documents, albumAsset), true);
    shared_ptr<FileAsset> tempAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("ListFile_test_002", albumAsset, tempAsset), true);
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("ListFile_002", albumAsset, tempAsset), true);
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("ListFile_test_002.jpg", albumAsset, tempAsset), true);
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("ListFile_test_002_1.jpg", albumAsset, tempAsset), true);
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("ListFile_test_002.png", albumAsset, tempAsset), true);
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("ListFile_002.jpg", albumAsset, tempAsset), true);
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("ListFile_002_1.jpg", albumAsset, tempAsset), true);
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("ListFile_002.png", albumAsset, tempAsset), true);

    const int32_t DIR_RESULT = 8;
    const int64_t offset = 0;
    const int64_t maxCount = 100;
    FileAccessFwk::FileFilter filter;

    // URI_DIR
    FileInfo dirInfo;
    dirInfo.uri = albumAsset->GetUri();
    dirInfo.mimeType = DEFAULT_FILE_MIME_TYPE;
    MEDIA_DEBUG_LOG("medialib_ListFile_test_002 URI_DIR uri: %{public}s", dirInfo.uri.c_str());
    vector<FileInfo> dirFileList;
    auto ret = mediaFileExtAbility->ListFile(dirInfo, offset, maxCount, filter, dirFileList);
    EXPECT_EQ(ret, E_SUCCESS);
    MEDIA_DEBUG_LOG("medialib_ListFile_test_002 URI_DIR fileList.size(): %{public}d", (int)dirFileList.size());
    DisplayFileList(dirFileList);
    EXPECT_EQ(dirFileList.size(), DIR_RESULT);

    // test limit and filter
    FileInfo fileInfo;
    fileInfo.uri = albumAsset->GetUri();
    ListFileTestLimit(fileInfo);
    ListFileTestFilter(fileInfo);
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_GetRoots_test_001, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    vector<RootInfo> rootList;
    auto ret = mediaFileExtAbility->GetRoots(rootList);
    EXPECT_EQ(ret, E_SUCCESS);
    MEDIA_DEBUG_LOG("medialib_GetRoots_test_001 rootList.size() %{public}lu", (long)rootList.size());
}

inline void InitScanFile(shared_ptr<FileAsset> &albumAsset)
{
    shared_ptr<FileAsset> tempAsset = nullptr;
    shared_ptr<FileAsset> albumAsset2 = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("ScanFile_test", g_documents, albumAsset), true);
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("ScanFile_test", albumAsset, albumAsset2), true);
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("ScanFile_test_1.jpg", albumAsset, tempAsset), true);
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("ScanFile_test_2.jpg", albumAsset, tempAsset), true);
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("ScanFile_test_3.png", albumAsset, tempAsset), true);
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("ScanFile_test_4.jpg", albumAsset, tempAsset), true);
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("ScanFile_test_5.jpg", albumAsset, tempAsset), true);
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("ScanFile_test_6.jpg", albumAsset2, tempAsset), true);
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("ScanFile_test_7.png", albumAsset2, tempAsset), true);
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("ScanFile_test_8.jpg", albumAsset2, tempAsset), true);
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_ScanFile_test_001, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }

    shared_ptr<FileAsset> albumAsset = nullptr;
    InitScanFile(albumAsset);

    int64_t offset = 0;
    int64_t maxCount = 100;
    FileAccessFwk::FileFilter filter;

    // URI_DIR
    FileInfo dirInfo;
    dirInfo.uri = albumAsset->GetUri();
    dirInfo.mimeType = DEFAULT_FILE_MIME_TYPE;
    MEDIA_DEBUG_LOG("medialib_ScanFile_test_001 URI_DIR uri: %{public}s", dirInfo.uri.c_str());
    vector<FileInfo> dirFileList;
    int32_t ret = MediaFileExtentionUtils::ScanFile(dirInfo, offset, maxCount, filter, dirFileList);
    EXPECT_EQ(ret, E_SUCCESS);
    EXPECT_EQ(dirFileList.size(), 8);

    vector<FileInfo> limitDirFileList1;
    ret = MediaFileExtentionUtils::ScanFile(dirInfo, offset, 5, filter, limitDirFileList1);
    EXPECT_EQ(ret, E_SUCCESS);
    EXPECT_EQ(limitDirFileList1.size(), 5);

    vector<FileInfo> limitDirFileList2;
    ret = MediaFileExtentionUtils::ScanFile(dirInfo, 5, maxCount, filter, limitDirFileList2);
    EXPECT_EQ(ret, E_SUCCESS);
    EXPECT_EQ(limitDirFileList2.size(), 3);
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_ScanFile_test_002, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    shared_ptr<FileAsset> albumAsset = nullptr;
    InitScanFile(albumAsset);

    int64_t offset = 0;
    int64_t maxCount = 100;
    FileAccessFwk::FileFilter filter;

    // URI_DIR
    FileInfo dirInfo;
    dirInfo.uri = "datashare:///media/root";
    dirInfo.mimeType = DEFAULT_FILE_MIME_TYPE;
    MEDIA_DEBUG_LOG("medialib_ListFile_test_002 URI_DIR uri: %{public}s", dirInfo.uri.c_str());
    vector<FileInfo> dirFileList;
    auto ret = mediaFileExtAbility->ScanFile(dirInfo, offset, maxCount, filter, dirFileList);
    EXPECT_EQ(ret, E_SUCCESS);
    EXPECT_GT(dirFileList.size(), 4);

    vector<FileInfo> limitDirFileList1;
    ret = mediaFileExtAbility->ScanFile(dirInfo, offset, 5, filter, limitDirFileList1);
    EXPECT_EQ(ret, E_SUCCESS);
    EXPECT_EQ(limitDirFileList1.size(), 5);

    vector<FileInfo> limitDirFileList2;
    ret = mediaFileExtAbility->ScanFile(dirInfo, 5, maxCount, filter, limitDirFileList2);
    EXPECT_EQ(ret, E_SUCCESS);
    EXPECT_GT(limitDirFileList2.size(), 3);
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_ScanFile_test_003, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }

    shared_ptr<FileAsset> albumAsset = nullptr;
    InitScanFile(albumAsset);

    int64_t offset = 0;
    int64_t maxCount = 100;
    FileAccessFwk::FileFilter filter;
    vector<string> suffix { ".jpg" };
    filter.SetSuffix(suffix);
    // URI_DIR
    FileInfo dirInfo;
    dirInfo.uri = albumAsset->GetUri();
    dirInfo.mimeType = DEFAULT_FILE_MIME_TYPE;
    MEDIA_DEBUG_LOG("medialib_ListFile_test_003 URI_DIR uri: %{public}s", dirInfo.uri.c_str());
    vector<FileInfo> dirFileList;
    auto ret = mediaFileExtAbility->ScanFile(dirInfo, offset, maxCount, filter, dirFileList);
    EXPECT_EQ(ret, E_SUCCESS);
    EXPECT_EQ(dirFileList.size(), 6);

    vector<FileInfo> limitDirFileList1;
    ret = mediaFileExtAbility->ScanFile(dirInfo, offset, 5, filter, limitDirFileList1);
    EXPECT_EQ(ret, E_SUCCESS);
    EXPECT_EQ(limitDirFileList1.size(), 5);

    vector<FileInfo> limitDirFileList2;
    ret = mediaFileExtAbility->ScanFile(dirInfo, 5, maxCount, filter, limitDirFileList2);
    EXPECT_EQ(ret, E_SUCCESS);
    EXPECT_EQ(limitDirFileList2.size(), 1);
}

void PrintFileInfo(const FileInfo &fileInfo, const string &testcase)
{
    MEDIA_INFO_LOG("testcase: %{public}s FileInfo uri: %{public}s, fileName: %{public}s, mode: %{public}d",
        testcase.c_str(), fileInfo.uri.c_str(), fileInfo.fileName.c_str(), fileInfo.mode);
    MEDIA_INFO_LOG("testcase: %{public}s FileInfo size: %{public}lld, mtime: %{public}lld, mimeType: %{public}s",
        testcase.c_str(), (long long)fileInfo.size, (long long)fileInfo.mtime, fileInfo.mimeType.c_str());
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_GetFileInfoFromUri_test_001, TestSize.Level0)
{
    Uri uri(ReturnUri(MEDIALIBRARY_MEDIA_PREFIX, MEDIALIBRARY_ROOT));
    FileInfo fileInfo;
    auto ret = mediaFileExtAbility->GetFileInfoFromUri(uri, fileInfo);
    PrintFileInfo(fileInfo, "medialib_GetFileInfoFromUri_test_001");
    EXPECT_EQ(ret, E_SUCCESS);
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_GetFileInfoFromUri_test_002, TestSize.Level0)
{
    Uri uri(ReturnUri(MEDIALIBRARY_MEDIA_PREFIX, MEDIALIBRARY_ROOT, MEDIALIBRARY_TYPE_FILE_URI));
    FileInfo fileInfo;
    auto ret = mediaFileExtAbility->GetFileInfoFromUri(uri, fileInfo);
    PrintFileInfo(fileInfo, "medialib_GetFileInfoFromUri_test_002");
    EXPECT_EQ(ret, E_SUCCESS);
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_GetFileInfoFromUri_test_003, TestSize.Level0)
{
    Uri uri(ReturnUri(MEDIALIBRARY_MEDIA_PREFIX, MEDIALIBRARY_ROOT, MEDIALIBRARY_TYPE_IMAGE_URI));
    FileInfo fileInfo;
    auto ret = mediaFileExtAbility->GetFileInfoFromUri(uri, fileInfo);
    PrintFileInfo(fileInfo, "medialib_GetFileInfoFromUri_test_003");
    EXPECT_EQ(ret, E_SUCCESS);
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_GetFileInfoFromUri_test_004, TestSize.Level0)
{
    Uri uri(ReturnUri(MEDIALIBRARY_MEDIA_PREFIX, MEDIALIBRARY_ROOT, MEDIALIBRARY_TYPE_VIDEO_URI));
    FileInfo fileInfo;
    auto ret = mediaFileExtAbility->GetFileInfoFromUri(uri, fileInfo);
    PrintFileInfo(fileInfo, "medialib_GetFileInfoFromUri_test_004");
    EXPECT_EQ(ret, E_SUCCESS);
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_GetFileInfoFromUri_test_005, TestSize.Level0)
{
    Uri uri(ReturnUri(MEDIALIBRARY_MEDIA_PREFIX, MEDIALIBRARY_ROOT, MEDIALIBRARY_TYPE_AUDIO_URI));
    FileInfo fileInfo;
    auto ret = mediaFileExtAbility->GetFileInfoFromUri(uri, fileInfo);
    PrintFileInfo(fileInfo, "medialib_GetFileInfoFromUri_test_005");
    EXPECT_EQ(ret, E_SUCCESS);
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_GetFileInfoFromUri_test_006, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    shared_ptr<FileAsset> albumAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("GetFileInfoFromUri_test_006", g_download, albumAsset), true);
    shared_ptr<FileAsset> fileAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("GetFileInfoFromUri_test_006.jpg", albumAsset, fileAsset), true);
    Uri uri(fileAsset->GetUri());
    FileInfo fileInfo;
    auto ret = mediaFileExtAbility->GetFileInfoFromUri(uri, fileInfo);
    PrintFileInfo(fileInfo, "medialib_GetFileInfoFromUri_test_006");
    EXPECT_EQ(ret, E_SUCCESS);

    int32_t fileMode = DOCUMENT_FLAG_REPRESENTS_FILE | DOCUMENT_FLAG_SUPPORTS_READ | DOCUMENT_FLAG_SUPPORTS_WRITE;
    EXPECT_EQ(fileInfo.fileName, "GetFileInfoFromUri_test_006.jpg");
    EXPECT_EQ(fileInfo.size, 0);
    EXPECT_EQ(fileInfo.uri, fileAsset->GetUri());
    EXPECT_EQ(fileInfo.mtime, fileAsset->GetDateModified());
    EXPECT_EQ(fileInfo.mode, fileMode);
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_GetFileInfoFromUri_test_007, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    shared_ptr<FileAsset> albumAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("GetFileInfoFromUri_test_007", g_pictures, albumAsset), true);
    Uri uri(albumAsset->GetUri());
    FileInfo albumInfo;
    auto ret = mediaFileExtAbility->GetFileInfoFromUri(uri, albumInfo);
    PrintFileInfo(albumInfo, "medialib_GetFileInfoFromUri_test_007");
    EXPECT_EQ(ret, E_SUCCESS);

    int32_t albumMode = DOCUMENT_FLAG_REPRESENTS_DIR | DOCUMENT_FLAG_SUPPORTS_READ | DOCUMENT_FLAG_SUPPORTS_WRITE;
    EXPECT_EQ(albumInfo.fileName, "GetFileInfoFromUri_test_007");
    EXPECT_EQ(albumInfo.size, 0);
    EXPECT_NE(albumAsset->GetSize(), 0);
    EXPECT_EQ(albumInfo.uri, albumAsset->GetUri());
    EXPECT_EQ(albumInfo.mtime, albumAsset->GetDateModified());
    EXPECT_EQ(albumInfo.mode, albumMode);
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_GetFileInfoFromRelativePath_test_001, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    shared_ptr<FileAsset> albumAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateAlbum("GetFileInfoFromRelativePath_001", g_pictures, albumAsset), true);
    FileInfo parentInfo;
    auto ret = mediaFileExtAbility->GetFileInfoFromRelativePath(albumAsset->GetRelativePath(), parentInfo);
    PrintFileInfo(parentInfo, "medialib_GetFileInfoFromRelativePath_test_001");
    EXPECT_EQ(ret, E_SUCCESS);

    int32_t albumMode = DOCUMENT_FLAG_REPRESENTS_DIR | DOCUMENT_FLAG_SUPPORTS_READ | DOCUMENT_FLAG_SUPPORTS_WRITE;
    EXPECT_EQ(parentInfo.fileName, g_pictures->GetDisplayName());
    EXPECT_EQ(parentInfo.size, 0);
    EXPECT_EQ(parentInfo.uri, g_pictures->GetUri());
    EXPECT_EQ(parentInfo.mtime, g_pictures->GetDateModified());
    EXPECT_EQ(parentInfo.mode, albumMode);
    EXPECT_EQ(parentInfo.relativePath, "");
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_GetFileInfoFromRelativePath_test_002, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    shared_ptr<FileAsset> fileAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("GetFileInfoFromRelativePath_002.jpg", g_pictures, fileAsset),
        true);
    FileInfo parentInfo;
    auto ret = mediaFileExtAbility->GetFileInfoFromRelativePath(fileAsset->GetRelativePath(), parentInfo);
    PrintFileInfo(parentInfo, "medialib_GetFileInfoFromRelativePath_test_002");
    EXPECT_EQ(ret, E_SUCCESS);

    int32_t albumMode = DOCUMENT_FLAG_REPRESENTS_DIR | DOCUMENT_FLAG_SUPPORTS_READ | DOCUMENT_FLAG_SUPPORTS_WRITE;
    EXPECT_EQ(parentInfo.fileName, g_pictures->GetDisplayName());
    EXPECT_EQ(parentInfo.size, 0);
    EXPECT_EQ(parentInfo.uri, g_pictures->GetUri());
    EXPECT_EQ(parentInfo.mode, albumMode);
    EXPECT_EQ(parentInfo.relativePath, "");
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_GetFileInfoFromRelativePath_test_003, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }
    FileInfo rootInfo;
    auto ret = mediaFileExtAbility->GetFileInfoFromRelativePath("", rootInfo);
    PrintFileInfo(rootInfo, "medialib_GetFileInfoFromRelativePath_test_003");
    EXPECT_EQ(ret, E_SUCCESS);

    int32_t albumReadOnlyMode = DOCUMENT_FLAG_REPRESENTS_DIR | DOCUMENT_FLAG_SUPPORTS_READ;
    EXPECT_EQ(rootInfo.fileName, "MEDIA_TYPE_FILE");
    EXPECT_EQ(rootInfo.size, 0);
    EXPECT_EQ(rootInfo.uri, ReturnUri(MEDIALIBRARY_DATA_URI, MEDIALIBRARY_TYPE_FILE_URI));
    EXPECT_EQ(rootInfo.mtime, 0);
    EXPECT_EQ(rootInfo.mode, albumReadOnlyMode);
    EXPECT_EQ(rootInfo.relativePath, "");
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_GetFileInfoFromRelativePath_test_004, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }

    FileInfo parentInfo;
    string testRelativePath = "Pictures/";
    EXPECT_EQ(mediaFileExtAbility->GetFileInfoFromRelativePath(testRelativePath, parentInfo), E_SUCCESS);

    testRelativePath = "Pictures";
    EXPECT_EQ(mediaFileExtAbility->GetFileInfoFromRelativePath(testRelativePath, parentInfo), E_SUCCESS);

    shared_ptr<FileAsset> fileAsset = nullptr;
    ASSERT_EQ(MediaLibraryUnitTestUtils::CreateFile("GetFileInfoFromRelativePath_004.jpg", g_pictures, fileAsset),
        true);
    testRelativePath = "Pictures/GetFileInfoFromRelativePath_004.jpg";
    EXPECT_EQ(mediaFileExtAbility->GetFileInfoFromRelativePath(testRelativePath, parentInfo), E_SUCCESS);
}

void MediaFileExtensionCheck(const shared_ptr<FileAsset> &parent, const unordered_set<string> extensions,
    const string &title, bool expect)
{
    Uri parentUri(parent->GetUri());
    Uri newUri("");

    for (const auto &extension : extensions) {
        string displayName = title + "." + extension;
        string filePath = parent->GetPath() + "/" + displayName;
        int32_t ret = mediaFileExtAbility->CreateFile(parentUri, displayName, newUri);
        if (expect) {
            EXPECT_EQ(ret, E_SUCCESS);
            EXPECT_EQ(MediaLibraryUnitTestUtils::IsFileExists(filePath), true);
        } else {
            EXPECT_NE(ret, E_SUCCESS);
            EXPECT_EQ(MediaLibraryUnitTestUtils::IsFileExists(filePath), false);
        }
        if (expect && ret) {
            MEDIA_INFO_LOG("Root dir: %{private}s, file: %{public}s, path: %{private}s, CreateFile ret: %{public}d",
                parent->GetDisplayName().c_str(), displayName.c_str(), filePath.c_str(), ret);
        }
    }
}

void DocumentsExtensionCheck(const shared_ptr<FileAsset> &parent, const string &title, bool expect)
{
    const unordered_set<string> extensions = { ".jpg1", ".txt" };

    Uri parentUri(parent->GetUri());
    Uri newUri("");

    for (const auto &extension : extensions) {
        string displayName = title + extension;
        string filePath = parent->GetPath() + "/" + displayName;
        int32_t ret = mediaFileExtAbility->CreateFile(parentUri, displayName, newUri);
        if (expect) {
            EXPECT_EQ(ret, E_SUCCESS);
            EXPECT_EQ(MediaLibraryUnitTestUtils::IsFileExists(filePath), true);
        } else {
            EXPECT_NE(ret, E_SUCCESS);
            EXPECT_EQ(MediaLibraryUnitTestUtils::IsFileExists(filePath), false);
        }
        if (expect && ret) {
            MEDIA_ERR_LOG("Root dir: %{private}s, file: %{public}s, path: %{private}s, CreateFile ret: %{public}d",
                parent->GetDisplayName().c_str(), displayName.c_str(), filePath.c_str(), ret);
        }
    }
}

void SpecialCharacterExtensionCheck(const shared_ptr<FileAsset> &parent, const string &title, bool expect)
{
    Uri parentUri(parent->GetUri());
    Uri newUri("");

    const int32_t MAX_ASCII = 127;
    for (int i = 0; i <= MAX_ASCII; i ++) {
        string displayName = title + "." + static_cast<char>(i);
        string filePath = parent->GetPath() + "/" + displayName;
        static const string DISPLAYNAME_REGEX_CHECK = R"([\\/:*?"<>|])";
        std::regex express(DISPLAYNAME_REGEX_CHECK);
        bool bValid = std::regex_search(displayName, express);
        int32_t ret = MediaFileExtentionUtils::CreateFile(parentUri, displayName, newUri);
        if (expect && (!bValid)) {
            EXPECT_EQ(ret, E_SUCCESS);
        } else {
            EXPECT_NE(ret, E_SUCCESS);
        }
        if (expect && (!bValid) && ret) {
            MEDIA_ERR_LOG("Dir: %{public}s, name: %{public}s, ret: %{public}d, suffix: %{public}c, bValid: %{public}d",
                parent->GetDisplayName().c_str(), displayName.c_str(), ret, static_cast<char>(i), bValid);
        }
    }
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_ExtensionCheck_test_001, TestSize.Level0)
{
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MEDIA_ERR_LOG("MediaLibraryDataManager invalid");
        exit(1);
    }

    const string title = "Extention001";
    MediaFileExtensionCheck(g_documents, SUPPORTED_IMAGE_FORMATS_SET, title, true);
    MediaFileExtensionCheck(g_documents, SUPPORTED_VIDEO_FORMATS_SET, title, true);
    MediaFileExtensionCheck(g_documents, SUPPORTED_AUDIO_FORMATS_SET, title, true);
    DocumentsExtensionCheck(g_documents, title, true);
    SpecialCharacterExtensionCheck(g_documents, title, true);

    MediaFileExtensionCheck(g_download, SUPPORTED_IMAGE_FORMATS_SET, title, true);
    MediaFileExtensionCheck(g_download, SUPPORTED_VIDEO_FORMATS_SET, title, true);
    MediaFileExtensionCheck(g_download, SUPPORTED_AUDIO_FORMATS_SET, title, true);
    DocumentsExtensionCheck(g_download, title, true);
    SpecialCharacterExtensionCheck(g_download, title, true);
}

int RenameTest(const shared_ptr<FileAsset> &parent, string nameCreate, string nameRename)
{
    Uri parentUri(parent->GetUri());
    Uri newUri("");
    Uri newUriTest("");
    if (mediaFileExtAbility->CreateFile(parentUri, nameCreate, newUri) != E_SUCCESS) {
        return -1;
    }
    int32_t ret = mediaFileExtAbility->Rename(newUri, nameRename, newUriTest);
    mediaFileExtAbility->Delete(newUri);
    return ret;
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Copy_test_001, TestSize.Level0)
{
    Uri sourceUri("");
    Uri parentUri(g_documents->GetUri());
    int32_t ret = MediaFileExtentionUtils::CreateFile(parentUri, "Rename_test_007.jpg", sourceUri);
    EXPECT_GT(ret, E_SUCCESS);
    Uri parentUriOne(g_download->GetUri());
    vector<CopyResult> copyResult;
    ret = MediaFileExtentionUtils::Copy(sourceUri, parentUriOne, copyResult, true);
    EXPECT_EQ(ret, E_SUCCESS);
    ret = MediaFileExtentionUtils::Copy(sourceUri, parentUriOne, copyResult, true);
    EXPECT_EQ(ret, E_SUCCESS);
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Copy_test_002, TestSize.Level0)
{
    Uri parentUri(g_documents->GetUri());
    string displayName = "medialib_Mkdir_test_002";
    Uri newUri("");
    int32_t ret = MediaFileExtentionUtils::Mkdir(parentUri, displayName, newUri);
    EXPECT_GT(ret, E_SUCCESS);
    Uri parentUriOne(g_download->GetUri());
    vector<CopyResult> copyResult;
    ret = MediaFileExtentionUtils::Copy(newUri, parentUriOne, copyResult, true);
    EXPECT_EQ(ret, E_SUCCESS);
    MEDIA_DEBUG_LOG("medialib_Copy_test_002 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Copy_test_003, TestSize.Level0)
{
    Uri parentUri(g_documents->GetUri());
    string displayName = "medialib_Mkdir_test_003";
    Uri newUri("");
    int32_t ret = MediaFileExtentionUtils::Mkdir(parentUri, displayName, newUri);
    EXPECT_GT(ret, E_SUCCESS);
    ret = MediaFileExtentionUtils::CreateFile(newUri, "medialib_Copy_test_003.jpg", newUri);
    EXPECT_GT(ret, E_SUCCESS);
    Uri parentUriOne(g_pictures->GetUri());
    vector<CopyResult> copyResult;
    ret = MediaFileExtentionUtils::Copy(newUri, parentUriOne, copyResult, true);
    EXPECT_EQ(ret, JS_ERR_PERMISSION_DENIED);
    MEDIA_DEBUG_LOG("medialib_Copy_test_003 ret: %{public}d, newUri: %{public}s", ret, newUri.ToString().c_str());
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Copy_test_004, TestSize.Level0)
{
    Uri sourceUri("");
    Uri parentUri(g_documents->GetUri());
    int32_t ret = MediaFileExtentionUtils::CreateFile(parentUri, "medialib_Copy_test_004.png", sourceUri);
    EXPECT_GT(ret, E_SUCCESS);
    Uri parentUriOne(g_pictures->GetUri());
    vector<CopyResult> copyResult;
    ret = MediaFileExtentionUtils::Copy(sourceUri, parentUriOne, copyResult, true);
    EXPECT_EQ(ret, JS_ERR_PERMISSION_DENIED);
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Copy_test_005, TestSize.Level0)
{
    Uri sourceUri("");
    Uri parentUri(g_documents->GetUri());
    int32_t ret = MediaFileExtentionUtils::CreateFile(parentUri, "medialib_Copy_test_005.png", sourceUri);
    EXPECT_GT(ret, E_SUCCESS);
    vector<CopyResult> copyResult;
    ret = MediaFileExtentionUtils::Copy(sourceUri, sourceUri, copyResult, true);
    EXPECT_LT(ret, 0);
}

/**
 * @tc.number    : medialib_Rename_test_009
 * @tc.name      : file rename function test under download
 * @tc.desc      : Create files to invoke the Rename() interface.
 */
HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Rename_test_009, TestSize.Level0)
{
    string nameCreate = "download_test." + *SUPPORTED_IMAGE_FORMATS_SET.begin();
    string nameRename = "download_test." + *++SUPPORTED_IMAGE_FORMATS_SET.begin();
    EXPECT_EQ(RenameTest(g_download, nameCreate, nameRename), E_SUCCESS);
    nameRename = "download." + *SUPPORTED_AUDIO_FORMATS_SET.begin();
    EXPECT_EQ(RenameTest(g_download, nameCreate, nameRename), E_SUCCESS);
    nameRename = "&%^&." + *SUPPORTED_VIDEO_FORMATS_SET.begin();
    EXPECT_EQ(RenameTest(g_download, nameCreate, nameRename), E_SUCCESS);
    nameRename = "124.BMP";
    EXPECT_EQ(RenameTest(g_download, nameCreate, nameRename), E_SUCCESS);
    nameRename = "ABC.1234";
    EXPECT_EQ(RenameTest(g_download, nameCreate, nameRename), E_SUCCESS);
    nameRename = "asd.@@@";
    EXPECT_EQ(RenameTest(g_download, nameCreate, nameRename), E_SUCCESS);
    nameRename = "medialib_Rename_test.   name";
    EXPECT_EQ(RenameTest(g_download, nameCreate, nameRename), E_SUCCESS);
    nameRename = "5678.测试";
    EXPECT_EQ(RenameTest(g_download, nameCreate, nameRename), E_SUCCESS);
    nameRename = "测试.bmp";
    EXPECT_EQ(RenameTest(g_download, nameCreate, nameRename), E_SUCCESS);
}

/**
 * @tc.number    : medialib_Rename_test_010
 * @tc.name      : file rename function test under documents
 * @tc.desc      : Create files to invoke the Rename() interface.
 */
HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Rename_test_010, TestSize.Level0)
{
    string nameCreate = "documents_test.gz";
    string nameRename = "documents_test.GZ";
    EXPECT_EQ(RenameTest(g_documents, nameCreate, nameRename), E_SUCCESS);
    nameRename = "documents.1234";
    EXPECT_EQ(RenameTest(g_documents, nameCreate, nameRename), E_SUCCESS);
    nameRename = "9%1.@@@";
    EXPECT_EQ(RenameTest(g_documents, nameCreate, nameRename), E_SUCCESS);
    nameRename = "ABC.   name";
    EXPECT_EQ(RenameTest(g_documents, nameCreate, nameRename), E_SUCCESS);
    nameRename = "测试.   name";
    EXPECT_EQ(RenameTest(g_documents, nameCreate, nameRename), E_SUCCESS);
    nameRename = "1234.))))";
    EXPECT_EQ(RenameTest(g_documents, nameCreate, nameRename), E_SUCCESS);
}

/**
 * @tc.number    : medialib_Rename_test_011
 * @tc.name      : file rename function test under documents
 * @tc.desc      : Create files to invoke the Rename() interface.
 */
HWTEST_F(MediaLibraryFileExtUnitTest, medialib_Rename_test_011, TestSize.Level0)
{
    string nameCreate = "documents_test.gz";
    string nameRename = "documents_test." + *SUPPORTED_IMAGE_FORMATS_SET.begin();
    EXPECT_EQ(RenameTest(g_documents, nameCreate, nameRename), E_SUCCESS);
    nameRename = "documents." + *SUPPORTED_AUDIO_FORMATS_SET.begin();
    EXPECT_EQ(RenameTest(g_documents, nameCreate, nameRename), E_SUCCESS);
    nameRename = "%&$." + *SUPPORTED_VIDEO_FORMATS_SET.begin();
    EXPECT_EQ(RenameTest(g_documents, nameCreate, nameRename), E_SUCCESS);
    nameRename = "ASX.BMP";
    EXPECT_EQ(RenameTest(g_documents, nameCreate, nameRename), E_SUCCESS);
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_checkUriValid_test_001, TestSize.Level0)
{
    bool ret = MediaFileExtentionUtils::CheckUriValid("");
    EXPECT_EQ(ret, false);
    ret = MediaFileExtentionUtils::CheckUriValid("datashare://test");
    EXPECT_EQ(ret, false);
    ret = MediaFileExtentionUtils::CheckUriValid("datashare://test/");
    EXPECT_EQ(ret, false);
    ret = MediaFileExtentionUtils::CheckUriValid("datashare://test/CheckUriValid");
    EXPECT_EQ(ret, false);
    ret = MediaFileExtentionUtils::CheckUriValid("datashare://test/CheckUriValid1");
    EXPECT_EQ(ret, false);
    ret = MediaFileExtentionUtils::CheckUriValid("datashare://media/1");
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_checkDistributedUri_test_001, TestSize.Level0)
{
    bool ret = MediaFileExtentionUtils::CheckDistributedUri("");
    EXPECT_EQ(ret, true);
    ret = MediaFileExtentionUtils::CheckDistributedUri("datashare://test/CheckDistributedUri");
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_checkUriSupport_test_001, TestSize.Level0)
{
    int32_t ret = MediaFileExtentionUtils::CheckUriSupport("");
    EXPECT_EQ(ret, E_URI_INVALID);
    ret = MediaFileExtentionUtils::CheckUriSupport("datashare://media/1");
    EXPECT_EQ(ret, E_DISTIBUTED_URI_NO_SUPPORT);
    ret = MediaFileExtentionUtils::CheckUriSupport("datashare:///media/1");
    EXPECT_EQ(ret, E_SUCCESS);
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_getResultSetFromDb_test_001, TestSize.Level0)
{
    string value = "getResultSetFromDb";
    vector<string> columns;
    auto queryResultSet = MediaFileExtentionUtils::GetResultSetFromDb(MEDIA_DATA_DB_URI, value, columns);
    EXPECT_EQ(queryResultSet, nullptr);
    string field = "/storage/cloud/files";
    queryResultSet = MediaFileExtentionUtils::GetResultSetFromDb(MEDIA_DATA_DB_URI, value, columns);
    EXPECT_EQ(queryResultSet, nullptr);
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_isFileExistInDb_test_001, TestSize.Level0)
{
    string path = "datashare://1";
    bool ret = MediaFileExtentionUtils::IsFileExistInDb(path);
    EXPECT_EQ(ret, false);
    string pathTest = "";
    ret = MediaFileExtentionUtils::IsFileExistInDb(pathTest);
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_resolveUri_test_001, TestSize.Level0)
{
    FileInfo fileInfo;
    MediaFileUriType uriType;
    fileInfo.uri = "resolveUri";
    int32_t ret = MediaFileExtentionUtils::ResolveUri(fileInfo, uriType);
    EXPECT_EQ(ret, E_INVALID_URI);
    fileInfo.uri = "datashare://";
    ret = MediaFileExtentionUtils::ResolveUri(fileInfo, uriType);
    EXPECT_EQ(ret, E_INVALID_URI);
    fileInfo.uri = "datashare:///media";
    ret = MediaFileExtentionUtils::ResolveUri(fileInfo, uriType);
    EXPECT_EQ(ret, E_INVALID_URI);
    fileInfo.uri = "datashare:///media/root";
    ret = MediaFileExtentionUtils::ResolveUri(fileInfo, uriType);
    EXPECT_EQ(ret, E_SUCCESS);
    fileInfo.uri = "datashare:///media/roottest";
    ret = MediaFileExtentionUtils::ResolveUri(fileInfo, uriType);
    EXPECT_EQ(ret, E_INVALID_URI);
    fileInfo.uri = "datashare:///media/file";
    ret = MediaFileExtentionUtils::ResolveUri(fileInfo, uriType);
    EXPECT_EQ(ret, E_SUCCESS);
    fileInfo.uri = "datashare:///media/1";
    ret = MediaFileExtentionUtils::ResolveUri(fileInfo, uriType);
    EXPECT_EQ(ret, E_SUCCESS);
    fileInfo.uri = "datashare://media/test";
    ret = MediaFileExtentionUtils::ResolveUri(fileInfo, uriType);
    EXPECT_EQ(ret, E_INVALID_URI);
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_checkValidDirName_test_001, TestSize.Level0)
{
    string displayName = "";
    bool ret = MediaFileExtentionUtils::CheckValidDirName(displayName);
    EXPECT_EQ(ret, false);
    string displayNameTest = "Camera/";
    ret = MediaFileExtentionUtils::CheckValidDirName(displayNameTest);
    EXPECT_EQ(ret, true);
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_checkMkdirValid_test_001, TestSize.Level0)
{
    MediaFileUriType uriType = URI_FILE_ROOT;
    string parentUriStr = "datashare:///1";
    string displayName = "Camera/";
    int32_t ret = MediaFileExtentionUtils::CheckMkdirValid(uriType, parentUriStr, displayName);
    EXPECT_EQ(ret, E_INVALID_DISPLAY_NAME);
    parentUriStr = "datashare://test/";
    ret = MediaFileExtentionUtils::CheckMkdirValid(uriType, parentUriStr, displayName);
    EXPECT_EQ(ret, E_DISTIBUTED_URI_NO_SUPPORT);
    parentUriStr = "datashare:///test/";
    displayName = "Camera";
    ret = MediaFileExtentionUtils::CheckMkdirValid(uriType, parentUriStr, displayName);
    EXPECT_EQ(ret, E_SUCCESS);

    uriType = URI_MEDIA_ROOT;
    ret = MediaFileExtentionUtils::CheckMkdirValid(uriType, parentUriStr, displayName);
    EXPECT_EQ(ret, E_URI_INVALID);
    parentUriStr = "datashare:///media/1";
    displayName = "Camera/";
    ret = MediaFileExtentionUtils::CheckMkdirValid(uriType, parentUriStr, displayName);
    EXPECT_EQ(ret, E_INVALID_DISPLAY_NAME);
    displayName = "test";
    ret = MediaFileExtentionUtils::CheckMkdirValid(uriType, parentUriStr, displayName);
    EXPECT_EQ(ret, E_SUCCESS);
}

HWTEST_F(MediaLibraryFileExtUnitTest, medialib_getAlbumRelativePathFromDB_test_001, TestSize.Level0)
{
    string selectUri = "datashare:///media/file";
    string relativePath = "/storage/cloud/files";
    bool ret = MediaFileExtentionUtils::GetAlbumRelativePathFromDB(selectUri, relativePath);
    EXPECT_EQ(ret, false);
}
} // namespace Media
} // namespace OHOS
