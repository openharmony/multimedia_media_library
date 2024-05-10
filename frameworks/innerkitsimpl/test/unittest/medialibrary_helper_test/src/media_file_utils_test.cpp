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

#include "medialibrary_helper_test.h"

#include <fcntl.h>
#include <fstream>
#include <iterator>

#include "media_file_uri.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_db_const.h"
#include "medialibrary_type_const.h"
#include "medialibrary_errno.h"
#include "userfile_manager_types.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_IsFileExists_Test_001, TestSize.Level0)
{
    string filePath = "/data/test/isfileexists_001";
    EXPECT_EQ(MediaFileUtils::IsFileExists(filePath), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_IsDirEmpty_Test_001, TestSize.Level0)
{
    string dirPath = "/data/test/isdirempty_001";
    EXPECT_EQ(MediaFileUtils::IsDirEmpty(dirPath), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_IsDirEmpty_Test_002, TestSize.Level0)
{
    string dirPath = "/data/test/isdirempty_002";
    string subPath = dirPath + "/isdirempty_002";
    EXPECT_EQ(MediaFileUtils::CreateDirectory(subPath), true);
    EXPECT_EQ(MediaFileUtils::IsDirEmpty(dirPath), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_IsDirEmpty_Test_003, TestSize.Level0)
{
    string dirPath = "/data/test/isdirempty_003";
    EXPECT_EQ(MediaFileUtils::CreateDirectory(dirPath), true);
    EXPECT_EQ(MediaFileUtils::IsDirEmpty(dirPath), true);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CreateFile_Test_001, TestSize.Level0)
{
    string filePath = "/data/test/createfile_001";
    EXPECT_EQ(MediaFileUtils::CreateFile(filePath), true);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CreateFile_Test_002, TestSize.Level0)
{
    string filePath = "";
    EXPECT_EQ(MediaFileUtils::CreateFile(filePath), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CreateFile_Test_003, TestSize.Level0)
{
    string filePath = "/data/test/createfile_003";
    EXPECT_EQ(MediaFileUtils::CreateFile(filePath), true);
    EXPECT_EQ(MediaFileUtils::CreateFile(filePath), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CreateFile_Test_004, TestSize.Level0)
{
    string filePath = "/data/test/test/test/test/createfile_004";
    EXPECT_EQ(MediaFileUtils::CreateFile(filePath), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_DeleteFile_Test_001, TestSize.Level0)
{
    string filePath = "/data/test/deletefile_001";
    EXPECT_EQ(MediaFileUtils::DeleteFile(filePath), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_DeleteDir_Test_001, TestSize.Level0)
{
    string dirPath = "/data/test/deletedir_001";
    EXPECT_EQ(MediaFileUtils::CreateDirectory(dirPath), true);
    EXPECT_EQ(MediaFileUtils::DeleteDir(dirPath), true);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_DeleteDir_Test_002, TestSize.Level0)
{
    string dirPath = "/data/test/deletedir_002";
    EXPECT_EQ(MediaFileUtils::DeleteDir(dirPath), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_MoveFile_Test_001, TestSize.Level0)
{
    string oldPath = "/data/test/movefile_001";
    string newPath = "/data/test/movefile_001_move";
    EXPECT_EQ(MediaFileUtils::CreateFile(oldPath), true);
    EXPECT_EQ(MediaFileUtils::MoveFile(oldPath, newPath), true);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_MoveFile_Test_002, TestSize.Level0)
{
    string oldPath = "/data/test/movefile_002";
    string newPath = "/data/test/movefile_002_move";
    EXPECT_EQ(MediaFileUtils::CreateFile(oldPath), true);
    EXPECT_EQ(MediaFileUtils::CreateFile(newPath), true);
    EXPECT_EQ(MediaFileUtils::MoveFile(oldPath, newPath), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_MoveFile_Test_003, TestSize.Level0)
{
    string oldPath = "/data/test/movefile_003";
    string newPath = "/data/test/movefile_003_move";
    EXPECT_EQ(MediaFileUtils::MoveFile(oldPath, newPath), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CreateDirectory_Test_001, TestSize.Level0)
{
    string dirPath = "/data/test/createdir_001";
    EXPECT_EQ(MediaFileUtils::CreateDirectory(dirPath), true);
}

static bool CheckFileString(const string &filePath, const string &text)
{
    ifstream inputFile(filePath);
    if (inputFile.is_open()) {
        string context((istreambuf_iterator<char>(inputFile)), (istreambuf_iterator<char>()));
        inputFile.close();
        if (context == text) {
            return true;
        } else {
            return false;
        }
    } else {
        return false;
    }
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_WriteStrToFile_Test_001, TestSize.Level0)
{
    string testString = "123456";
    string testPath = "/data/test/WriteStrToFileTest_001";
    EXPECT_EQ(MediaFileUtils::WriteStrToFile("", testString), false);
    EXPECT_EQ(MediaFileUtils::WriteStrToFile(testPath, ""), false);
    EXPECT_EQ(MediaFileUtils::WriteStrToFile(testPath, testString), false);
    EXPECT_EQ(MediaFileUtils::CreateFile(testPath), true);
    EXPECT_EQ(MediaFileUtils::WriteStrToFile(testPath, ""), false);
    EXPECT_EQ(MediaFileUtils::WriteStrToFile(testPath, testString), true);
    EXPECT_EQ(CheckFileString(testPath, testString), true);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CopyByFd_Test_001, TestSize.Level0)
{
    string oldPath = "/data/test/CopyByFd_001";
    string newPath = "/data/test/CopyByFd_002";
    string testString = "123456";

    EXPECT_EQ(MediaFileUtils::CreateFile(oldPath), true);
    EXPECT_EQ(MediaFileUtils::CreateFile(newPath), true);
    EXPECT_EQ(MediaFileUtils::WriteStrToFile(oldPath, testString), true);

    int32_t rfd = open(oldPath.c_str(), O_RDONLY);
    int32_t wfd = open(newPath.c_str(), O_RDWR);
    EXPECT_EQ(MediaFileUtils::CopyFile(rfd, wfd), true);
    close(rfd);
    close(wfd);
    EXPECT_EQ(CheckFileString(newPath, testString), true);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_RenameDir_Test_001, TestSize.Level0)
{
    string oldPath = "/data/test/renamedir_001";
    string newPath = "/data/test/renamedir_001_renamed";
    EXPECT_EQ(MediaFileUtils::CreateDirectory(oldPath), true);
    EXPECT_EQ(MediaFileUtils::RenameDir(oldPath, newPath), true);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_RenameDir_Test_002, TestSize.Level0)
{
    string oldPath = "/data/test/renamedir_002";
    string newPath = "";
    EXPECT_EQ(MediaFileUtils::CreateDirectory(oldPath), true);
    EXPECT_EQ(MediaFileUtils::RenameDir(oldPath, newPath), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetFileTitle_test_001, TestSize.Level0)
{
    string displayName = "";
    string ret = MediaFileUtils::GetTitleFromDisplayName(displayName);
    EXPECT_EQ(ret, "");
    displayName = "medialib.test";
    ret = MediaFileUtils::GetTitleFromDisplayName(displayName);
    EXPECT_NE(ret, "");
    displayName = "medialib.";
    ret = MediaFileUtils::GetTitleFromDisplayName(displayName);
    EXPECT_NE(ret, "");
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CheckDisplayName_Test_001, TestSize.Level0)
{
    string displayName = "";
    EXPECT_LT(MediaFileUtils::CheckDisplayName(displayName), 0);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CheckDisplayName_Test_002, TestSize.Level0)
{
    string displayName = ".nofile";
    EXPECT_LT(MediaFileUtils::CheckDisplayName(displayName), 0);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CheckDisplayName_Test_003, TestSize.Level0)
{
    string displayName = "test";
    EXPECT_LT(MediaFileUtils::CheckDisplayName(displayName), 0);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CheckDisplayName_Test_004, TestSize.Level0)
{
    string displayName = "test:*\'";
    EXPECT_LT(MediaFileUtils::CheckDisplayName(displayName), 0);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CheckDisplayName_Test_005, TestSize.Level0)
{
    string displayName = "test.test.jpg";
    EXPECT_LT(MediaFileUtils::CheckDisplayName(displayName), 0);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CheckDisplayName_Test_006, TestSize.Level0)
{
    string displayName = "test.jpg";
    EXPECT_EQ(MediaFileUtils::CheckDisplayName(displayName), 0);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CheckFileDisplayName_Test_001, TestSize.Level0)
{
    string displayName = "test.test.jpg";
    EXPECT_EQ(MediaFileUtils::CheckFileDisplayName(displayName), 0);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetAlbumDateModified_Test_001, TestSize.Level0)
{
    string dirPath = "/data/test/getalbumdatemodified_001";
    EXPECT_EQ(MediaFileUtils::CreateDirectory(dirPath), true);
    EXPECT_EQ(MediaFileUtils::GetAlbumDateModified(dirPath) > 0, true);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetAlbumDateModified_Test_002, TestSize.Level0)
{
    string dirPath = "";
    EXPECT_EQ(MediaFileUtils::GetAlbumDateModified(dirPath), 0);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetAlbumDateModified_Test_003, TestSize.Level0)
{
    string dirPath = "/data/test/getalbumdatemodified_003";
    EXPECT_EQ(MediaFileUtils::GetAlbumDateModified(dirPath), 0);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_UTCTimeSeconds_Test_001, TestSize.Level0)
{
    EXPECT_EQ(MediaFileUtils::UTCTimeSeconds() > 0, true);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetNetworkIdFromUri_Test_001, TestSize.Level0)
{
    string tempNetworkId = "1d3cb099659d53b3ee15faaab3c00a8ff983382ebc8b01aabde039ed084e167b";
    string uri = MEDIALIBRARY_DATA_ABILITY_PREFIX + tempNetworkId + MEDIALIBRARY_DATA_URI_IDENTIFIER;
    EXPECT_EQ(MediaFileUtils::GetNetworkIdFromUri(uri), tempNetworkId);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetNetworkIdFromUri_Test_002, TestSize.Level0)
{
    string uri = "";
    EXPECT_EQ(MediaFileUtils::GetNetworkIdFromUri(uri), "");
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetNetworkIdFromUri_Test_003, TestSize.Level0)
{
    string uri = MEDIALIBRARY_DATA_URI_IDENTIFIER;
    EXPECT_EQ(MediaFileUtils::GetNetworkIdFromUri(uri), "");
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetNetworkIdFromUri_Test_004, TestSize.Level0)
{
    string uri = MEDIALIBRARY_DATA_ABILITY_PREFIX;
    EXPECT_EQ(MediaFileUtils::GetNetworkIdFromUri(uri), "");
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetNetworkIdFromUri_Test_005, TestSize.Level0)
{
    string uri = MEDIALIBRARY_DATA_ABILITY_PREFIX + MEDIALIBRARY_DATA_URI_IDENTIFIER;
    EXPECT_EQ(MediaFileUtils::GetNetworkIdFromUri(uri), "");
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_UpdatePath_Test_002, TestSize.Level0)
{
    string path = "";
    string uri = "";
    EXPECT_EQ(MediaFileUtils::UpdatePath(path, uri), path);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_UpdatePath_Test_003, TestSize.Level0)
{
    string path = "/storage/cloud/100/files";
    string uri = MEDIALIBRARY_DATA_ABILITY_PREFIX + MEDIALIBRARY_DATA_URI_IDENTIFIER;
    EXPECT_EQ(MediaFileUtils::UpdatePath(path, uri), path);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_UpdatePath_Test_005, TestSize.Level0)
{
    string path = "local/files";
    string tempNetworkId = "1d3cb099659d53b3ee15faaab3c00a8ff983382ebc8b01aabde039ed084e167b";
    string uri = MEDIALIBRARY_DATA_ABILITY_PREFIX + tempNetworkId + MEDIALIBRARY_DATA_URI_IDENTIFIER;
    EXPECT_EQ(MediaFileUtils::UpdatePath(path, uri), path);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_UpdatePath_Test_006, TestSize.Level0)
{
    string path = "/storage/cloud/100";
    string tempNetworkId = "1d3cb099659d53b3ee15faaab3c00a8ff983382ebc8b01aabde039ed084e167b";
    string uri = MEDIALIBRARY_DATA_ABILITY_PREFIX + tempNetworkId + MEDIALIBRARY_DATA_URI_IDENTIFIER;
    EXPECT_EQ(MediaFileUtils::UpdatePath(path, uri), path);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_UpdatePath_Test_007, TestSize.Level0)
{
    string path = "/storage/cloud/100";
    string uri = "";
    EXPECT_EQ(MediaFileUtils::UpdatePath(path, uri), path);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetMediaType_Test_001, TestSize.Level0)
{
    string displayName = "";
    EXPECT_EQ(MediaFileUtils::GetMediaType(displayName), MEDIA_TYPE_ALL);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetMediaType_Test_002, TestSize.Level0)
{
    string displayName = "test";
    EXPECT_EQ(MediaFileUtils::GetMediaType(displayName), MEDIA_TYPE_FILE);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetMediaType_Test_003, TestSize.Level0)
{
    string displayName = "test.mp3";
    EXPECT_EQ(MediaFileUtils::GetMediaType(displayName), MEDIA_TYPE_AUDIO);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetMediaType_Test_004, TestSize.Level0)
{
    string displayName = "test.mp4";
    EXPECT_EQ(MediaFileUtils::GetMediaType(displayName), MEDIA_TYPE_VIDEO);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetMediaType_Test_005, TestSize.Level0)
{
    string displayName = "test.jpg";
    EXPECT_EQ(MediaFileUtils::GetMediaType(displayName), MEDIA_TYPE_IMAGE);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetMediaType_Test_006, TestSize.Level0)
{
    string displayName = "test.txt";
    EXPECT_EQ(MediaFileUtils::GetMediaType(displayName), MEDIA_TYPE_FILE);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetFilename_Test_001, TestSize.Level0)
{
    string filePath = "";
    EXPECT_EQ(MediaFileUtils::GetFileName(filePath), "");
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetFilename_Test_002, TestSize.Level0)
{
    string filePath = "test";
    EXPECT_EQ(MediaFileUtils::GetFileName(filePath), "");
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetFilename_Test_003, TestSize.Level0)
{
    string filePath = "test/";
    EXPECT_EQ(MediaFileUtils::GetFileName(filePath), "");
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetFilename_Test_004, TestSize.Level0)
{
    string filePath = "test/test";
    EXPECT_EQ(MediaFileUtils::GetFileName(filePath), "test");
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_IsFileTablePath_Test_001, TestSize.Level0)
{
    string filePath = "";
    EXPECT_EQ(MediaFileUtils::IsFileTablePath(filePath), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_IsFileTablePath_Test_002, TestSize.Level0)
{
    string filePath = "/1234546541315645464545165";
    EXPECT_EQ(MediaFileUtils::IsFileTablePath(filePath), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_IsFileTablePath_Test_003, TestSize.Level0)
{
    string filePath = ROOT_MEDIA_DIR;
    EXPECT_EQ(MediaFileUtils::IsFileTablePath(filePath), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_IsFileTablePath_Test_004, TestSize.Level0)
{
    string filePath = ROOT_MEDIA_DIR + DOCS_PATH;
    EXPECT_EQ(MediaFileUtils::IsFileTablePath(filePath), true);
    filePath = ROOT_MEDIA_DIR + AUDIO_DIR_VALUES;
    EXPECT_EQ(MediaFileUtils::IsFileTablePath(filePath), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_IsPhotoTablePath_Test_001, TestSize.Level0)
{
    string filePath = "";
    EXPECT_EQ(MediaFileUtils::IsPhotoTablePath(filePath), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_IsPhotoTablePath_Test_002, TestSize.Level0)
{
    string filePath = "/1234546541315645464545165";
    EXPECT_EQ(MediaFileUtils::IsPhotoTablePath(filePath), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_IsPhotoTablePath_Test_003, TestSize.Level0)
{
    string filePath = ROOT_MEDIA_DIR;
    EXPECT_EQ(MediaFileUtils::IsPhotoTablePath(filePath), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_IsPhotoTablePath_Test_004, TestSize.Level0)
{
    string filePath = ROOT_MEDIA_DIR + PHOTO_BUCKET;
    EXPECT_EQ(MediaFileUtils::IsPhotoTablePath(filePath), true);
    filePath = ROOT_MEDIA_DIR + PIC_DIR_VALUES;
    EXPECT_EQ(MediaFileUtils::IsPhotoTablePath(filePath), true);
    filePath = ROOT_MEDIA_DIR + VIDEO_DIR_VALUES;
    EXPECT_EQ(MediaFileUtils::IsPhotoTablePath(filePath), true);
    filePath = ROOT_MEDIA_DIR + CAMERA_DIR_VALUES;
    EXPECT_EQ(MediaFileUtils::IsPhotoTablePath(filePath), true);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_IsPhotoTablePath_Test_005, TestSize.Level0)
{
    string filePath = ROOT_MEDIA_DIR + AUDIO_DIR_VALUES;
    EXPECT_EQ(MediaFileUtils::IsPhotoTablePath(filePath), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetRealUriFromVirtualUri_Test_001, TestSize.Level0)
{
    const string virtualUri = "file://media/image/12";
    string realUri = MediaFileUtils::GetRealUriFromVirtualUri(virtualUri);
    EXPECT_EQ(realUri, "file://media/image/3");
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetRealUriFromVirtualUri_Test_002, TestSize.Level0)
{
    const string virtualUri = "file://media/audio/12";
    string realUri = MediaFileUtils::GetRealUriFromVirtualUri(virtualUri);
    EXPECT_EQ(realUri, "file://media/audio/3");
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetRealUriFromVirtualUri_Test_003, TestSize.Level0)
{
    const string virtualUri = "file://media/video/12";
    string realUri = MediaFileUtils::GetRealUriFromVirtualUri(virtualUri);
    EXPECT_EQ(realUri, "file://media/video/3");
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetRealUriFromVirtualUri_Test_004, TestSize.Level0)
{
    const string virtualUri = "file://media/Photo/12/VID_2023_001/VID_2023.jpg";
    string realUri = MediaFileUtils::GetRealUriFromVirtualUri(virtualUri);
    EXPECT_EQ(realUri, virtualUri);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetRealUriFromVirtualUri_Test_005, TestSize.Level0)
{
    const string virtualUri = "file://media/Audio/12/VID_169_001/VID_2023.mp3";
    string realUri = MediaFileUtils::GetRealUriFromVirtualUri(virtualUri);
    EXPECT_EQ(realUri, virtualUri);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetRealUriFromVirtualUri_Test_006, TestSize.Level0)
{
    const string virtualUri = "file://com.demo.a/data/storage/e12/base/files/12.txt";
    string realUri = MediaFileUtils::GetRealUriFromVirtualUri(virtualUri);
    EXPECT_EQ(realUri, virtualUri);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetRealUriFromVirtualUri_Test_007, TestSize.Level0)
{
    const string virtualUri = "file://docs/storage/Users/currentUsers/Documents/12.txt";
    string realUri = MediaFileUtils::GetRealUriFromVirtualUri(virtualUri);
    EXPECT_EQ(realUri, virtualUri);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetRealUriFromVirtualUri_Test_008, TestSize.Level0)
{
    const string virtualUri = "file://docs/storage/Users/currentUsers/Desktop/12.txt";
    string realUri = MediaFileUtils::GetRealUriFromVirtualUri(virtualUri);
    EXPECT_EQ(realUri, virtualUri);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetRealUriFromVirtualUri_Test_009, TestSize.Level0)
{
    const string virtualUri = "file://docs/storage/Users/currentUsers/Download/12.txt";
    string realUri = MediaFileUtils::GetRealUriFromVirtualUri(virtualUri);
    EXPECT_EQ(realUri, virtualUri);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetRealUriFromVirtualUri_Test_010, TestSize.Level0)
{
    const string virtualUri = "file://docs/storage/External/12.txt";
    string realUri = MediaFileUtils::GetRealUriFromVirtualUri(virtualUri);
    EXPECT_EQ(realUri, virtualUri);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetRealUriFromVirtualUri_Test_011, TestSize.Level0)
{
    const string virtualUri = "file://docs/storage/Share/12.txt";
    string realUri = MediaFileUtils::GetRealUriFromVirtualUri(virtualUri);
    EXPECT_EQ(realUri, virtualUri);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_ModifyAsset_Test_001, TestSize.Level0)
{
    string oldPath;
    string newPath;
    int32_t ret = MediaFileUtils::ModifyAsset(oldPath, newPath);
    EXPECT_EQ(ret, E_MODIFY_DATA_FAIL);

    oldPath = "";
    newPath = "datashare://test";
    ret = MediaFileUtils::ModifyAsset(oldPath, newPath);
    EXPECT_EQ(ret, E_MODIFY_DATA_FAIL);

    oldPath = "datashare://test";
    newPath = "";
    ret = MediaFileUtils::ModifyAsset(oldPath, newPath);
    EXPECT_EQ(ret, E_MODIFY_DATA_FAIL);

    oldPath = "datashare://test";
    newPath = "datashare://test/Photo";
    ret = MediaFileUtils::ModifyAsset(oldPath, newPath);
    EXPECT_EQ(ret, E_NO_SUCH_FILE);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_ModifyAsset_Test_002, TestSize.Level0)
{
    string oldPath = "datashare://test/Photo";
    string newPath = "datashare://test/Download";
    int32_t ret = MediaFileUtils::ModifyAsset(oldPath, newPath);
    EXPECT_EQ(ret, E_NO_SUCH_FILE);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CreateAsset_Test_001, TestSize.Level0)
{
    string filePath;
    int32_t ret = MediaFileUtils::CreateAsset(filePath);
    EXPECT_EQ(ret, E_VIOLATION_PARAMETERS);

    filePath = "datashare://test";
    MediaFileUtils::CreateAsset(filePath);
    EXPECT_EQ(ret, E_VIOLATION_PARAMETERS);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_IsUriV10_Test_001, TestSize.Level0)
{
    string mediaType = URI_TYPE_PHOTO;
    bool ret = MediaFileUtils::IsUriV10(mediaType);
    EXPECT_EQ(ret, true);

    mediaType = URI_TYPE_PHOTO_ALBUM;
    ret = MediaFileUtils::IsUriV10(mediaType);
    EXPECT_EQ(ret, true);

    mediaType = URI_TYPE_AUDIO_V10;
    ret = MediaFileUtils::IsUriV10(mediaType);
    EXPECT_EQ(ret, true);

    mediaType = "";
    ret = MediaFileUtils::IsUriV10(mediaType);
    EXPECT_EQ(ret, false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_UriAppendKeyValue_Test_001, TestSize.Level0)
{
    string uri;
    string key;
    string value;
    MediaFileUtils::UriAppendKeyValue(uri, key, value);
    EXPECT_EQ((uri == ""), false);
    EXPECT_EQ((key == ""), true);
    EXPECT_EQ((value == ""), true);

    uri = "datashare://test";
    key = "test";
    value = "testFile";
    MediaFileUtils::UriAppendKeyValue(uri, key, value);
    EXPECT_EQ((uri == ""), false);
    EXPECT_EQ((key == ""), false);
    EXPECT_EQ((value == ""), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_Encode_Test_001, TestSize.Level0)
{
    string uri;
    string str = MediaFileUtils::Encode(uri);
    EXPECT_EQ((str == ""), true);

    uri = "test";
    str = MediaFileUtils::Encode(uri);
    EXPECT_EQ((str == ""), false);

    uri = "test/Photo";
    str = MediaFileUtils::Encode(uri);
    EXPECT_EQ((str == ""), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetUriByExtrConditions_Test_001, TestSize.Level0)
{
    string prefix;
    string fileId;
    string suffix;
    string str = MediaFileUtils::GetUriByExtrConditions(prefix, fileId, suffix);
    EXPECT_EQ(str, "");

    prefix = "test";
    fileId = "1234567890";
    suffix = "file";
    str = MediaFileUtils::GetUriByExtrConditions(prefix, fileId, suffix);
    EXPECT_EQ(str, "test1234567890file");
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetMovingPhotoVideoPath_Test_001, TestSize.Level0)
{
    string path = "/storage/cloud/files/Photo/1/IMG_test.jpg";
    string videoPath = "/storage/cloud/files/Photo/1/IMG_test.mp4";
    EXPECT_EQ(MediaFileUtils::GetMovingPhotoVideoPath(path), videoPath);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetMovingPhotoVideoPath_Test_002, TestSize.Level0)
{
    string path = "/storage/cloud/files/Photo/1/invalidPath";
    string videoPath = "";
    EXPECT_EQ(MediaFileUtils::GetMovingPhotoVideoPath(path), videoPath);
    EXPECT_EQ(MediaFileUtils::GetMovingPhotoVideoPath(""), videoPath);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CheckMovingPhotoExtension_Test_001, TestSize.Level0)
{
    vector<string> validExtensions = { "jpg", "jpeg", "jpe", "heif", "hif" };
    for (const auto& extension : validExtensions) {
        EXPECT_EQ(MediaFileUtils::CheckMovingPhotoExtension(extension), true);
    }
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CheckMovingPhotoExtension_Test_002, TestSize.Level0)
{
    vector<string> invalidExtensions = { "arw", "avif", "bm", "bmp", "cur", "dng", "gif", "heic", "heics", "heifs",
        "ico", "nrw", "pef", "png", "raf", "raw", "rw2", "srw", "svg", "webp" };
    for (const auto& extension : invalidExtensions) {
        EXPECT_EQ(MediaFileUtils::CheckMovingPhotoExtension(extension), false);
    }
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CheckMovingPhotoVideoExtension_Test_001, TestSize.Level0)
{
    vector<string> validExtensions = { "m4v", "f4v", "mp4v", "mpeg4", "mp4" };
    for (const auto& extension : validExtensions) {
        EXPECT_EQ(MediaFileUtils::CheckMovingPhotoVideoExtension(extension), true);
    }
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CheckMovingPhotoVideoExtension_Test_002, TestSize.Level0)
{
    vector<string> invalidExtensions = { "3gpp2", "3gp2", "3g2", "3gpp", "3gp", "avi", "m2ts", "mts",
        "ts", "yt", "wrf", "mpeg", "mpeg2", "mpv2", "mp2v", "m2v", "m2t", "mpeg1", "mpv1", "mp1v", "m1v",
        "mpg", "mov", "mkv", "webm", "h264" };
    for (const auto& extension : invalidExtensions) {
        EXPECT_EQ(MediaFileUtils::CheckMovingPhotoVideoExtension(extension), false);
    }
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CheckMovingPhotoImage_Test_001, TestSize.Level0)
{
    string videoPath = "/storage/cloud/files/Photo/1/IMG_test_invalid.gif";
    EXPECT_EQ(MediaFileUtils::CheckMovingPhotoImage(videoPath), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CheckMovingPhotoVideo_Test_001, TestSize.Level0)
{
    string videoPath = "/storage/cloud/files/Photo/1/IMG_test_invalid.mp4";
    EXPECT_EQ(MediaFileUtils::CheckMovingPhotoVideo(videoPath), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CheckMovingPhotoVideoDuration_Test_001, TestSize.Level0)
{
    EXPECT_EQ(MediaFileUtils::CheckMovingPhotoVideoDuration(-4000), false);
    EXPECT_EQ(MediaFileUtils::CheckMovingPhotoVideoDuration(-3000), false);
    EXPECT_EQ(MediaFileUtils::CheckMovingPhotoVideoDuration(-2500), false);
    EXPECT_EQ(MediaFileUtils::CheckMovingPhotoVideoDuration(-2000), false);
    EXPECT_EQ(MediaFileUtils::CheckMovingPhotoVideoDuration(-1000), false);
    EXPECT_EQ(MediaFileUtils::CheckMovingPhotoVideoDuration(0), false);
    EXPECT_EQ(MediaFileUtils::CheckMovingPhotoVideoDuration(1000), false);
    EXPECT_EQ(MediaFileUtils::CheckMovingPhotoVideoDuration(2000), true);
    EXPECT_EQ(MediaFileUtils::CheckMovingPhotoVideoDuration(2500), true);
    EXPECT_EQ(MediaFileUtils::CheckMovingPhotoVideoDuration(3000), true);
    EXPECT_EQ(MediaFileUtils::CheckMovingPhotoVideoDuration(4000), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_IsMediaLibraryUri_Test_001, TestSize.Level0)
{
    string uri = "file://media/Photo/12/IMG_2023_001/IMG_2023.jpg";
    EXPECT_EQ(MediaFileUtils::IsMediaLibraryUri(uri), true);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_IsMediaLibraryUri_Test_002, TestSize.Level0)
{
    string uri("file://com.example.testdemo/data/storage/el2/base/haps/test.jpg");
    uri.append(";");
    uri.append("file://com.example.testdemo/data/storage/el2/base/haps/test.mp4");
    EXPECT_EQ(MediaFileUtils::IsMediaLibraryUri(uri), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_IsMediaLibraryUri_Test_003, TestSize.Level0)
{
    string uri = "";
    EXPECT_EQ(MediaFileUtils::IsMediaLibraryUri(uri), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_SplitMovingPhotoUri_Test_001, TestSize.Level0)
{
    string uri = "file://media/Photo/12/IMG_2023_001/IMG_2023.jpg";
    std::vector<std::string> ret;
    EXPECT_EQ(MediaFileUtils::SplitMovingPhotoUri(uri, ret), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_SplitMovingPhotoUri_Test_002, TestSize.Level0)
{
    string uri("file://com.example.testdemo/data/storage/el2/base/haps/test.jpg");
    uri.append(";");
    uri.append("file://com.example.testdemo/data/storage/el2/base/haps/test.mp4");
    std::vector<std::string> ret;
    EXPECT_EQ(MediaFileUtils::SplitMovingPhotoUri(uri, ret), true);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_SplitMovingPhotoUri_Test_003, TestSize.Level0)
{
    string uri = "";
    std::vector<std::string> ret;
    EXPECT_EQ(MediaFileUtils::SplitMovingPhotoUri(uri, ret), false);
}
} // namespace Media
} // namespace OHOS