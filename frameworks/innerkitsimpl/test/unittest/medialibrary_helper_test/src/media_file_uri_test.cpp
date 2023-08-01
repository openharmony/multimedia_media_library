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

#include "medialibrary_helper_test.h"
#include "media_file_uri.h"
#include "media_log.h"
#include "userfile_manager_types.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {

static const string networkId_ = "1d3cb099659d53b3ee15faaab3c00a8ff983382ebc8b01aabde039ed084e167b";
static const int32_t fd_ = 12;

const int32_t TYPE_URI = 1;
const int32_t TYPE_URI_FD = 2;
const int32_t TYPE_URI_PREFIX = 3;

string PathSplicing(string subpath, int32_t type)
{
    string Uri = "";
    switch (type) {
        case TYPE_URI:
            Uri = (ML_FILE_URI_PREFIX + subpath + "/" + to_string(fd_) + ML_URI_NETWORKID_EQUAL + networkId_);
            break;
        case TYPE_URI_FD:
            Uri = (ML_FILE_URI_PREFIX + subpath + "/" + to_string(fd_));
            break;
        case TYPE_URI_PREFIX:
            Uri = (subpath + to_string(fd_) + ML_URI_NETWORKID_EQUAL + networkId_);
            break;
        default:
            MEDIA_ERR_LOG("ERROR: No such type");
            break;
    }
    return Uri;
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUri_Test_001, TestSize.Level0)
{
    string uri = PathSplicing(MEDIALIBRARY_TYPE_AUDIO_URI, TYPE_URI);
    MediaFileUri fileUri(uri);
    string targetUri = fileUri.ToString();
    EXPECT_EQ(targetUri, uri);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUri_Test_002, TestSize.Level0)
{
    string uri = PathSplicing(MEDIALIBRARY_TYPE_IMAGE_URI, TYPE_URI);
    MediaFileUri fileUri(MEDIA_TYPE_IMAGE, to_string(fd_), networkId_);
    string targetUri = fileUri.ToString();
    EXPECT_EQ(targetUri, uri);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUri_Test_003, TestSize.Level0)
{
    string uri = PathSplicing(MEDIALIBRARY_TYPE_AUDIO_URI, TYPE_URI);
    MediaFileUri fileUri(MEDIA_TYPE_AUDIO, to_string(fd_), networkId_);
    string targetUri = fileUri.ToString();
    EXPECT_EQ(targetUri, uri);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUri_Test_004, TestSize.Level0)
{
    string uri = PathSplicing(MEDIALIBRARY_TYPE_VIDEO_URI, TYPE_URI);
    MediaFileUri fileUri(MEDIA_TYPE_VIDEO, to_string(fd_), networkId_);
    string targetUri = fileUri.ToString();
    EXPECT_EQ(targetUri, uri);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUri_Test_005, TestSize.Level0)
{
    string uri = PathSplicing(MEDIALIBRARY_TYPE_FILE_URI, TYPE_URI);
    MediaFileUri fileUri(MEDIA_TYPE_FILE, to_string(fd_), networkId_);
    string targetUri = fileUri.ToString();
    EXPECT_EQ(targetUri, uri);

    MediaFileUri fileUri_(MEDIA_TYPE_ALBUM, to_string(fd_), networkId_);
    targetUri = fileUri_.ToString();
    EXPECT_EQ(targetUri, uri);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUri_Test_006, TestSize.Level0)
{
    string uri = PathSplicing(MEDIALIBRARY_TYPE_IMAGE_URI, TYPE_URI);
    MediaFileUri fileUri(MEDIA_TYPE_IMAGE, to_string(fd_), networkId_, MEDIA_API_VERSION_DEFAULT);
    string targetUri = fileUri.ToString();
    EXPECT_EQ(targetUri, uri);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUri_Test_007, TestSize.Level0)
{
    string uri = PathSplicing(MEDIALIBRARY_TYPE_AUDIO_URI, TYPE_URI);
    MediaFileUri fileUri(MEDIA_TYPE_AUDIO, to_string(fd_), networkId_, MEDIA_API_VERSION_DEFAULT);
    string targetUri = fileUri.ToString();
    EXPECT_EQ(targetUri, uri);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUri_Test_008, TestSize.Level0)
{
    string uri = PathSplicing(MEDIALIBRARY_TYPE_VIDEO_URI, TYPE_URI);
    MediaFileUri fileUri(MEDIA_TYPE_VIDEO, to_string(fd_), networkId_, MEDIA_API_VERSION_DEFAULT);
    string targetUri = fileUri.ToString();
    EXPECT_EQ(targetUri, uri);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUri_Test_009, TestSize.Level0)
{
    string uri = PathSplicing(MEDIALIBRARY_TYPE_FILE_URI, TYPE_URI);
    MediaFileUri fileUri(MEDIA_TYPE_FILE, to_string(fd_), networkId_, MEDIA_API_VERSION_DEFAULT);
    string targetUri = fileUri.ToString();
    EXPECT_EQ(targetUri, uri);

    MediaFileUri fileUri_(MEDIA_TYPE_MEDIA, to_string(fd_), networkId_, MEDIA_API_VERSION_DEFAULT);
    targetUri = fileUri_.ToString();
    EXPECT_EQ(targetUri, uri);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUri_Test_010, TestSize.Level0)
{
    string uri = PathSplicing(MEDIALIBRARY_TYPE_ALBUM_URI, TYPE_URI);
    MediaFileUri fileUri(MEDIA_TYPE_ALBUM, to_string(fd_), networkId_, MEDIA_API_VERSION_DEFAULT);
    string targetUri = fileUri.ToString();
    EXPECT_EQ(targetUri, uri);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUri_Test_011, TestSize.Level0)
{
    string uri = PathSplicing(MEDIALIBRARY_TYPE_SMART_URI, TYPE_URI);
    MediaFileUri fileUri(MEDIA_TYPE_SMARTALBUM, to_string(fd_), networkId_, MEDIA_API_VERSION_DEFAULT);
    string targetUri = fileUri.ToString();
    EXPECT_EQ(targetUri, uri);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUri_Test_012, TestSize.Level0)
{
    string uri = PathSplicing(PhotoColumn::PHOTO_TYPE_URI, TYPE_URI);
    MediaFileUri fileUri(MEDIA_TYPE_IMAGE, to_string(fd_), networkId_, MEDIA_API_VERSION_V10);
    string targetUri = fileUri.ToString();
    EXPECT_EQ(targetUri, uri);

    MediaFileUri fileUri_(MEDIA_TYPE_VIDEO, to_string(fd_), networkId_, MEDIA_API_VERSION_V10);
    targetUri = fileUri_.ToString();
    EXPECT_EQ(targetUri, uri);
}

    
HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUri_Test_013, TestSize.Level0)
{
    string uri = PathSplicing(AudioColumn::AUDIO_URI_PREFIX, TYPE_URI_PREFIX);
    MediaFileUri fileUri(MEDIA_TYPE_AUDIO, to_string(fd_), networkId_, MEDIA_API_VERSION_V10);
    string targetUri = fileUri.ToString();
    EXPECT_EQ(targetUri, uri);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUri_Test_014, TestSize.Level0)
{
    string uri = PathSplicing(MEDIALIBRARY_TYPE_FILE_URI, TYPE_URI);
    MediaFileUri fileUri(MEDIA_TYPE_FILE, to_string(fd_), networkId_, MEDIA_API_VERSION_V10);
    string targetUri = fileUri.ToString();
    EXPECT_EQ(targetUri, uri);

    MediaFileUri fileUri_(MEDIA_TYPE_ALBUM, to_string(fd_), networkId_, MEDIA_API_VERSION_V10);
    targetUri = fileUri_.ToString();
    EXPECT_EQ(targetUri, uri);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUri_Test_015, TestSize.Level0)
{
    string uri = PathSplicing(MEDIALIBRARY_TYPE_FILE_URI, TYPE_URI_FD);
    MediaFileUri fileUri(MEDIA_TYPE_FILE, to_string(fd_));
    string targetUri = fileUri.ToString();
    EXPECT_EQ(targetUri, uri);

    MediaFileUri fileUri_(MEDIA_TYPE_ALBUM, to_string(fd_));
    targetUri = fileUri_.ToString();
    EXPECT_EQ(targetUri, uri);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_IsValid_Test_001, TestSize.Level0)
{
    string uri = "/data/test/";
    EXPECT_EQ(MediaFileUri(uri).IsValid(), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_IsValid_Test_002, TestSize.Level0)
{
    string uri = "datashare://data/test/";
    EXPECT_EQ(MediaFileUri(uri).IsValid(), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_IsValid_Test_003, TestSize.Level0)
{
    string uri = "datashare://media/test/";
    EXPECT_EQ(MediaFileUri(uri).IsValid(), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_IsValid_Test_004, TestSize.Level0)
{
    string uri = "datashare://media/test/6";
    EXPECT_EQ(MediaFileUri(uri).IsValid(), true);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUri_GetNetworkId_Test_001, TestSize.Level0)
{
    string uri = "/data/test/";
    EXPECT_EQ(MediaFileUri(uri).GetNetworkId(), "");
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUri_GetNetworkId_Test_002, TestSize.Level0)
{
    string uri = "file://data/test/";
    EXPECT_EQ(MediaFileUri(uri).GetNetworkId(), "");
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUri_GetNetworkId_Test_003, TestSize.Level0)
{
    string uri = "datashare://data/test/";
    EXPECT_EQ(MediaFileUri(uri).GetNetworkId(), "data");
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUri_GetNetworkId_Test_004, TestSize.Level0)
{
    string uri = "file://data/test/?networkid=123";
    EXPECT_EQ(MediaFileUri(uri).GetNetworkId(), "123");
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUri_GetNetworkId_Test_005, TestSize.Level0)
{
    string uri = "file://data/test/?networkid=123&test=456";
    EXPECT_EQ(MediaFileUri(uri).GetNetworkId(), "123");
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUri_GetNetworkId_Test_006, TestSize.Level0)
{
    string uri = "file://data/test/?networkid=123&test=456/path/test/";
    EXPECT_EQ(MediaFileUri(uri).GetNetworkId(), "123");
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUri_GetFileId_Test_001, TestSize.Level0)
{
    string uri = "/data/test/";
    EXPECT_EQ(MediaFileUri(uri).GetFileId(), "-1");
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUri_GetFileId_Test_002, TestSize.Level0)
{
    string uri = "file://data/test/";
    EXPECT_EQ(MediaFileUri(uri).GetFileId(), "-1");
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUri_GetFileId_Test_003, TestSize.Level0)
{
    string uri = "file://data/test/tt";
    EXPECT_EQ(MediaFileUri(uri).GetFileId(), "-1");
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUri_GetFileId_Test_004, TestSize.Level0)
{
    string uri = "file://data/test/123";
    EXPECT_EQ(MediaFileUri(uri).GetFileId(), "123");
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUri_GetFileId_Test_005, TestSize.Level0)
{
    string uri = "datashare://data/test/123";
    EXPECT_EQ(MediaFileUri(uri).GetFileId(), "123");
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUri_GetFileId_Test_006, TestSize.Level0)
{
    string uri = "data://data/test/123";
    EXPECT_EQ(MediaFileUri(uri).GetFileId(), "123");
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUri_GetFilePath_Test_001, TestSize.Level0)
{
    string uri = "";
    EXPECT_EQ(MediaFileUri(uri).GetFilePath(), "");
    uri = "data://data/test/123";
    EXPECT_EQ(MediaFileUri(uri).GetFilePath(), "");
    uri = "file://data/test/123";
    EXPECT_EQ(MediaFileUri(uri).GetFilePath(), "");
    uri = "datashare://data/test/123";
    EXPECT_EQ(MediaFileUri(uri).GetFilePath(), "");
    uri = "file://data/test/tt";
    EXPECT_EQ(MediaFileUri(uri).GetFilePath(), "");
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_IsApi10_Test_001, TestSize.Level0)
{
    string uri = "/data/test/";
    EXPECT_EQ(MediaFileUri(uri).IsApi10(), false);
    uri = "datashare://data/test/";
    EXPECT_EQ(MediaFileUri(uri).IsApi10(), false);
    uri = "datashare://media/test/";
    EXPECT_EQ(MediaFileUri(uri).IsApi10(), false);
    uri = "datashare://media/test/6";
    EXPECT_EQ(MediaFileUri(uri).IsApi10(), false);
    uri = "";
    EXPECT_EQ(MediaFileUri(uri).IsApi10(), false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetQueryKeys_Test_001, TestSize.Level0)
{
    string uri = "";
    auto &queryKey = MediaFileUri(uri).GetQueryKeys();
    EXPECT_EQ(queryKey.count("operation"), 0);
    uri = "file://data/test/123";
    queryKey = MediaFileUri(uri).GetQueryKeys();
    EXPECT_EQ(queryKey.count("operation"), 0);
    uri = "datashare://media/test/";
    queryKey = MediaFileUri(uri).GetQueryKeys();
    EXPECT_GE(queryKey.count("operation"), 0);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetTableName_Test_001, TestSize.Level0)
{
    string uri = "";
    EXPECT_EQ(MediaFileUri(uri).GetTableName(), "");

    uri = "file://data/test/testCase";
    EXPECT_EQ(MediaFileUri(uri).GetTableName(), "");

    uri = "datashare://media/test/";
    EXPECT_EQ(MediaFileUri(uri).GetTableName(), "");
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_GetMediaTypeFromUri_Test_001, TestSize.Level0)
{
    string uri = "file://data/test";
    EXPECT_EQ(MediaFileUri::GetMediaTypeFromUri(uri), MEDIA_TYPE_DEFAULT);

    uri = "file://data/test/testCase";
    EXPECT_EQ(MediaFileUri::GetMediaTypeFromUri(uri), MEDIA_TYPE_DEFAULT);

    uri = "datashare://media/test/";
    EXPECT_EQ(MediaFileUri::GetMediaTypeFromUri(uri), MEDIA_TYPE_DEFAULT);
}

HWTEST_F(MediaLibraryHelperUnitTest, MediaFileUtils_RemoveAllFragment_Test_001, TestSize.Level0)
{
    string uri = "file://data/test/testCase/123";
    MediaFileUri::RemoveAllFragment(uri);
    EXPECT_EQ(uri, "file://data/test/testCase/123");

    uri = "file://data/test/testCase";
    MediaFileUri::RemoveAllFragment(uri);
    EXPECT_EQ(uri, "file://data/test/testCase");

    uri = "datashare://media/test/";
    MediaFileUri::RemoveAllFragment(uri);
    EXPECT_EQ(uri, "datashare://media/test/");
}

} // namespace Media
} // namespace OHOS