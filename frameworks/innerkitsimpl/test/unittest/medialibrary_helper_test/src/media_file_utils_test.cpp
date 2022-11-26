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

#include "medialibrary_helper_test.h"

#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_db_const.h"
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

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_RemoveDirectory_Test_001, TestSize.Level0)
{
    string dirPath = "/data/test/removedir_001";
    string subPath = dirPath + "/removedir_001";
    EXPECT_EQ(MediaFileUtils::CreateDirectory(subPath), true);
    EXPECT_EQ(MediaFileUtils::RemoveDirectory(dirPath), 0);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CopyFile_Test_001, TestSize.Level0)
{
    string oldPath = "/data/test/copyfile_001";
    string newPath = "/data/test/copyfile_001_copy";
    EXPECT_EQ(MediaFileUtils::CreateFile(oldPath), true);
    EXPECT_EQ(MediaFileUtils::CopyFile(oldPath, newPath), true);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CopyFile_Test_002, TestSize.Level0)
{
    string oldPath = "";
    string newPath = "";
    EXPECT_EQ(MediaFileUtils::CopyFile(oldPath, newPath), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CopyFile_Test_003, TestSize.Level0)
{
    string oldPath = "/data/test/copyfile_003";
    string newPath = "";
    EXPECT_EQ(MediaFileUtils::CopyFile(oldPath, newPath), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CopyFile_Test_004, TestSize.Level0)
{
    string oldPath = "/data/test/copyfile_004";
    string newPath = "/data/test/copyfile_004_copy";
    EXPECT_EQ(MediaFileUtils::CopyFile(oldPath, newPath), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CopyFile_Test_005, TestSize.Level0)
{
    string oldPath = "/data/test/copyfile_005";
    string newPath = "/data/test/copyfile_005_copy";
    string newPathCorrected = "/data/test/copyfile_005_copy/copyfile_005";
    EXPECT_EQ(MediaFileUtils::CreateFile(oldPath), true);
    EXPECT_EQ(MediaFileUtils::CreateDirectory(newPath), true);
    EXPECT_EQ(MediaFileUtils::CreateFile(newPathCorrected), true);
    EXPECT_EQ(MediaFileUtils::CopyFile(oldPath, newPath), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CopyFile_Test_006, TestSize.Level0)
{
    string oldPath = "/data/test/copyfile_006";
    string newPath = "/data/test/copyfile_006_copy";
    EXPECT_EQ(MediaFileUtils::CreateFile(oldPath), true);
    EXPECT_EQ(MediaFileUtils::CreateDirectory(newPath), true);
    EXPECT_EQ(MediaFileUtils::CopyFile(oldPath, newPath), true);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CopyFile_Test_008, TestSize.Level0)
{
    string oldPath = "/data/test/";
    string newPath = "/data/test/copyfile_008_copy";
    EXPECT_EQ(MediaFileUtils::CreateFile(oldPath), false);
    EXPECT_EQ(MediaFileUtils::CreateDirectory(newPath), true);
    EXPECT_EQ(MediaFileUtils::CopyFile(oldPath, newPath), false);
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

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CheckDisplayName_Test_001, TestSize.Level0)
{
    string displayName = "";
    EXPECT_EQ(MediaFileUtils::CheckDisplayName(displayName), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CheckDisplayName_Test_002, TestSize.Level0)
{
    string displayName = ".nofile";
    EXPECT_EQ(MediaFileUtils::CheckDisplayName(displayName), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CheckDisplayName_Test_003, TestSize.Level0)
{
    string displayName = "test";
    EXPECT_EQ(MediaFileUtils::CheckDisplayName(displayName), true);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CheckDisplayName_Test_004, TestSize.Level0)
{
    string displayName = "test:*\'";
    EXPECT_EQ(MediaFileUtils::CheckDisplayName(displayName), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CheckTitle_Test_001, TestSize.Level0)
{
    string title = "test";
    EXPECT_EQ(MediaFileUtils::CheckTitle(title), true);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CheckTitle_Test_002, TestSize.Level0)
{
    string title = "";
    EXPECT_EQ(MediaFileUtils::CheckTitle(title), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_CheckTitle_Test_003, TestSize.Level0)
{
    string title = "test\\.";
    EXPECT_EQ(MediaFileUtils::CheckTitle(title), false);
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

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_UpdatePath_Test_001, TestSize.Level0)
{
    string path = "/storage/media/100/local/files";
    string tempNetworkId = "1d3cb099659d53b3ee15faaab3c00a8ff983382ebc8b01aabde039ed084e167b";
    string uri = MEDIALIBRARY_DATA_ABILITY_PREFIX + tempNetworkId + MEDIALIBRARY_DATA_URI_IDENTIFIER;
    EXPECT_EQ(MediaFileUtils::UpdatePath(path, uri), "/storage/media/100/" + tempNetworkId + "/files");
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_UpdatePath_Test_002, TestSize.Level0)
{
    string path = "";
    string uri = "";
    EXPECT_EQ(MediaFileUtils::UpdatePath(path, uri), path);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_UpdatePath_Test_003, TestSize.Level0)
{
    string path = "/storage/media/100/local/files";
    string uri = MEDIALIBRARY_DATA_ABILITY_PREFIX + MEDIALIBRARY_DATA_URI_IDENTIFIER;
    EXPECT_EQ(MediaFileUtils::UpdatePath(path, uri), path);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_UpdatePath_Test_004, TestSize.Level0)
{
    string path = "/storage/media/100/";
    string tempNetworkId = "1d3cb099659d53b3ee15faaab3c00a8ff983382ebc8b01aabde039ed084e167b";
    string uri = MEDIALIBRARY_DATA_ABILITY_PREFIX + tempNetworkId + MEDIALIBRARY_DATA_URI_IDENTIFIER;
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
    string path = "/storage/media/100/local";
    string tempNetworkId = "1d3cb099659d53b3ee15faaab3c00a8ff983382ebc8b01aabde039ed084e167b";
    string uri = MEDIALIBRARY_DATA_ABILITY_PREFIX + tempNetworkId + MEDIALIBRARY_DATA_URI_IDENTIFIER;
    EXPECT_EQ(MediaFileUtils::UpdatePath(path, uri), path);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_UpdatePath_Test_007, TestSize.Level0)
{
    string path = "/storage/media/100/local";
    string uri = "";
    EXPECT_EQ(MediaFileUtils::UpdatePath(path, uri), path);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetFileMediaTypeUri_Test_001, TestSize.Level0)
{
    string uri = MEDIALIBRARY_DATA_URI + MEDIALIBRARY_TYPE_AUDIO_URI;
    EXPECT_EQ(MediaFileUtils::GetFileMediaTypeUri(MEDIA_TYPE_AUDIO, ""), uri);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetFileMediaTypeUri_Test_002, TestSize.Level0)
{
    string uri = MEDIALIBRARY_DATA_URI + MEDIALIBRARY_TYPE_VIDEO_URI;
    EXPECT_EQ(MediaFileUtils::GetFileMediaTypeUri(MEDIA_TYPE_VIDEO, ""), uri);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetFileMediaTypeUri_Test_003, TestSize.Level0)
{
    string uri = MEDIALIBRARY_DATA_URI + MEDIALIBRARY_TYPE_IMAGE_URI;
    EXPECT_EQ(MediaFileUtils::GetFileMediaTypeUri(MEDIA_TYPE_IMAGE, ""), uri);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetFileMediaTypeUri_Test_004, TestSize.Level0)
{
    string uri = MEDIALIBRARY_DATA_URI + MEDIALIBRARY_TYPE_FILE_URI;
    EXPECT_EQ(MediaFileUtils::GetFileMediaTypeUri(MEDIA_TYPE_FILE, ""), uri);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetFileMediaTypeUri_Test_005, TestSize.Level0)
{
    string uri = MEDIALIBRARY_DATA_URI + MEDIALIBRARY_TYPE_FILE_URI;
    EXPECT_EQ(MediaFileUtils::GetFileMediaTypeUri(MEDIA_TYPE_ALL, ""), uri);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetUriByNameAndId_Test_001, TestSize.Level0)
{
    string displayName = "test.jpg";
    string networkId = "";
    int32_t fd = 1;
    string targetUri = MEDIALIBRARY_DATA_URI + MEDIALIBRARY_TYPE_IMAGE_URI + "/" + to_string(fd);
    EXPECT_EQ(MediaFileUtils::GetUriByNameAndId(displayName, networkId, fd), targetUri);
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
    EXPECT_EQ(MediaFileUtils::GetFilename(filePath), "");
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetFilename_Test_002, TestSize.Level0)
{
    string filePath = "test";
    EXPECT_EQ(MediaFileUtils::GetFilename(filePath), "");
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetFilename_Test_003, TestSize.Level0)
{
    string filePath = "test/";
    EXPECT_EQ(MediaFileUtils::GetFilename(filePath), "");
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetFilename_Test_004, TestSize.Level0)
{
    string filePath = "test/test";
    EXPECT_EQ(MediaFileUtils::GetFilename(filePath), "test");
}
} // namespace Media
} // namespace OHOS