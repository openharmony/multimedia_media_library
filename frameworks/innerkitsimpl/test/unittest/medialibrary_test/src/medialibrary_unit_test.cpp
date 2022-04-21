/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "medialibrary_unit_test.h"
#include "media_log.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
IMediaLibraryClient* g_mediaLibClientInstance = nullptr;

void MediaLibraryUnitTest::SetUpTestCase(void)
{
    g_mediaLibClientInstance = IMediaLibraryClient::GetMediaLibraryClientInstance();
}

void MediaLibraryUnitTest::TearDownTestCase(void)
{
    string albumUri;
    AlbumAsset albumAsset;
    AssetType assetType = ASSET_IMAGEALBUM;

    albumUri = "/storage/media/local/files/gtest";
    if (g_mediaLibClientInstance != nullptr) {
        (void)g_mediaLibClientInstance->DeleteMediaAlbumAsset(assetType, albumAsset, albumUri);
    }

    g_mediaLibClientInstance = nullptr;
}

/* SetUp:Execute before each test case */
void MediaLibraryUnitTest::SetUp() {}

void MediaLibraryUnitTest::TearDown(void) {}

/*
 * Feature: MediaLibrary
 * Function: CreateMediaAsset
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Create media audio asset in requested directory.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_CreateMediaAsset_testlevel0_001, TestSize.Level0)
{
    bool errCode = false;
    MediaAsset mediaAsset;
    AssetType assetType = ASSET_AUDIO;
    mediaAsset.name_ = "test_001_audio.mp3";
    mediaAsset.albumName_ = "gtest/001/audio";
    if (g_mediaLibClientInstance != nullptr) {
        errCode = g_mediaLibClientInstance->CreateMediaAsset(assetType, mediaAsset);
    }
    EXPECT_NE(errCode, false);
}

/*
 * Feature: MediaLibrary
 * Function: CreateMediaAsset
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Create media audio asset in ROOT_DIR=/storage/media/local/files directory.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_CreateMediaAsset_test_002, TestSize.Level1)
{
    bool errCode = false;
    MediaAsset mediaAsset;
    AssetType assetType = ASSET_AUDIO;

    mediaAsset.name_ = "gtest_002_audio.mp3";
    mediaAsset.albumName_ = "";
    if (g_mediaLibClientInstance != nullptr) {
        errCode = g_mediaLibClientInstance->CreateMediaAsset(assetType, mediaAsset);

        // clearing the file created
        mediaAsset.uri_ = "/storage/media/local/files/gtest_002_audio.mp3";
        (void)g_mediaLibClientInstance->DeleteMediaAsset(assetType, mediaAsset);
    }
    EXPECT_NE(errCode, false);
}
/*
 * Feature: MediaLibrary
 * Function: GetAudioAssets
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Get audio assets prsent in particular directory and subdirectories.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_GetAudioAssets_testlevel0_001, TestSize.Level0)
{
    vector<unique_ptr<AudioAsset>> audioAssetList;
    unsigned int size = 0;
    string dirPath = "gtest/001/audio";
    vector<string> selectionArgs;
    struct stat statInfo {};
    string dirPathCheck = "/storage/media/local/files/" + dirPath;

    if (stat(dirPathCheck.c_str(), &statInfo) == 0) {
        if (statInfo.st_mode & S_IFDIR) {
            if (g_mediaLibClientInstance != nullptr) {
                audioAssetList = g_mediaLibClientInstance->GetAudioAssets(dirPath, selectionArgs);
            }
        }
    }
    EXPECT_NE(audioAssetList.size(), size);
}

/*
 * Feature: MediaLibrary
 * Function: GetAudioAssets
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Get audio assets from ROOT_DIR=/storage/media/local/files directory and subdirectories.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_GetAudioAssets_test_002, TestSize.Level1)
{
    vector<unique_ptr<AudioAsset>> audioAssetList;
    unsigned int size = 0;
    string dirPath = ""; // ROOT_DIR
    vector<string> selectionArgs;

    if (g_mediaLibClientInstance != nullptr) {
        audioAssetList = g_mediaLibClientInstance->GetAudioAssets(dirPath, selectionArgs);
    }
    EXPECT_NE(audioAssetList.size(), size);
}

/*
 * Feature: MediaLibrary
 * Function: CreateMediaAsset
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Create media video asset in requested directory.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_CreateMediaAsset_testlevel0_003, TestSize.Level0)
{
    bool errCode = false;
    MediaAsset mediaAsset;
    AssetType assetType = ASSET_VIDEO;

    mediaAsset.name_ = "test_002_video.mp4";
    mediaAsset.albumName_ = "gtest/002/video";
    if (g_mediaLibClientInstance != nullptr) {
        errCode = g_mediaLibClientInstance->CreateMediaAsset(assetType, mediaAsset);
    }
    EXPECT_NE(errCode, false);
}

/*
 * Feature: MediaLibrary
 * Function: CreateMediaAsset
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Create media video sset in ROOT_DIR=/storage/media/local/files directory.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_CreateMediaAsset_test_004, TestSize.Level1)
{
    bool errCode = false;
    MediaAsset mediaAsset;
    AssetType assetType = ASSET_VIDEO;

    mediaAsset.name_ = "test_002_video.mp4";
    mediaAsset.albumName_ = "";
    if (g_mediaLibClientInstance != nullptr) {
        errCode = g_mediaLibClientInstance->CreateMediaAsset(assetType, mediaAsset);

        // clearing the file created
        mediaAsset.uri_ = "/storage/media/local/files/test_002_video.mp4";
        (void)g_mediaLibClientInstance->DeleteMediaAsset(assetType, mediaAsset);
    }
    EXPECT_NE(errCode, false);
}

/*
 * Feature: MediaLibrary
 * Function: GetVideoAssets
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Get video assets present in particular directory and subdirectories.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_GetVideoAssets_testlevel0_001, TestSize.Level0)
{
    vector<unique_ptr<VideoAsset>> videoAssetList;
    unsigned int size = 0;
    string dirPath = "gtest/002/video";
    vector<string> selectionArgs;
    struct stat statInfo {};
    string dirPathCheck = "/storage/media/local/files/" + dirPath;

    if (stat(dirPathCheck.c_str(), &statInfo) == 0) {
        if (statInfo.st_mode & S_IFDIR) {
            if (g_mediaLibClientInstance != nullptr) {
                videoAssetList = g_mediaLibClientInstance->GetVideoAssets(dirPath, selectionArgs);
            }
        }
    }
    EXPECT_NE(videoAssetList.size(), size);
}

/*
 * Feature: MediaLibrary
 * Function: GetVideoAssets
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Get video assets from ROOT_DIR=/storage/media/local/files directory and subdirectories.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_GetVideoAssets_test_002, TestSize.Level1)
{
    vector<unique_ptr<VideoAsset>> videoAssetList;
    unsigned int size = 0;
    string dirPath = "";
    vector<string> selectionArgs;

    if (g_mediaLibClientInstance != nullptr) {
        videoAssetList = g_mediaLibClientInstance->GetVideoAssets(dirPath, selectionArgs);
    }
    EXPECT_NE(videoAssetList.size(), size);
}

/*
 * Feature: MediaLibrary
 * Function: CreateMediaAsset
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Create media image asset in requested directory.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_CreateMediaAsset_testlevel0_005, TestSize.Level0)
{
    bool errCode = false;
    MediaAsset mediaAsset;
    AssetType assetType = ASSET_IMAGE;

    mediaAsset.name_ = "test_003_image.jpg";
    mediaAsset.albumName_ = "gtest/003/image";
    if (g_mediaLibClientInstance != nullptr) {
        errCode = g_mediaLibClientInstance->CreateMediaAsset(assetType, mediaAsset);
    }
    EXPECT_NE(errCode, false);
}

/*
 * Feature: MediaLibrary
 * Function: CreateMediaAsset
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Create media image asset in ROOT_DIR=/storage/media/local/files directory.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_CreateMediaAsset_test_006, TestSize.Level1)
{
    bool errCode = false;
    MediaAsset mediaAsset;
    AssetType assetType = ASSET_IMAGE;

    mediaAsset.name_ = "test_003_image.jpg";
    mediaAsset.albumName_ = "";
    if (g_mediaLibClientInstance != nullptr) {
        errCode = g_mediaLibClientInstance->CreateMediaAsset(assetType, mediaAsset);

        // clearing the file created
        mediaAsset.uri_ = "/storage/media/local/files/test_003_image.jpg";
        (void)g_mediaLibClientInstance->DeleteMediaAsset(assetType, mediaAsset);
    }
    EXPECT_NE(errCode, false);
}

/*
 * Feature: MediaLibrary
 * Function: CreateMediaAsset
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Create existing media asset in requested directory.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_CreateMediaAsset_test_007, TestSize.Level1)
{
    bool errCode = true;
    MediaAsset mediaAsset;
    AssetType assetType = ASSET_IMAGE;
    // create existing file
    mediaAsset.name_ = "test_003_image.jpg";
    mediaAsset.albumName_ = "gtest/003/image";
    if (g_mediaLibClientInstance != nullptr) {
        errCode = g_mediaLibClientInstance->CreateMediaAsset(assetType, mediaAsset);
    }
    EXPECT_EQ(errCode, false);
}

/*
 * Feature: MediaLibrary
 * Function: GetImageAssets
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Get image assets present in particular directory and subdirectories.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_GetImageAssets_testlevel0_001, TestSize.Level0)
{
    vector<unique_ptr<ImageAsset>> imageAssetList;
    unsigned int size = 0;
    string dirPath = "gtest/003/image";
    vector<string> selectionArgs;
    struct stat statInfo {};
    string dirPathCheck = "/storage/media/local/files/" + dirPath;

    if (stat(dirPathCheck.c_str(), &statInfo) == 0) {
        if (statInfo.st_mode & S_IFDIR) {
            if (g_mediaLibClientInstance != nullptr) {
                imageAssetList = g_mediaLibClientInstance->GetImageAssets(dirPath, selectionArgs);
            }
        }
    }
    EXPECT_NE(imageAssetList.size(), size);
}

/*
 * Feature: MediaLibrary
 * Function: GetImageAssets
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Get image assets from ROOT_DIR=/storage/media/local/files directory and subdirectories.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_GetImageAssets_test_002, TestSize.Level1)
{
    vector<unique_ptr<ImageAsset>> imageAssetList;
    unsigned int size = 0;
    string dirPath = "";
    vector<string> selectionArgs;

    if (g_mediaLibClientInstance != nullptr) {
        imageAssetList = g_mediaLibClientInstance->GetImageAssets(dirPath, selectionArgs);
    }
    EXPECT_NE(imageAssetList.size(), size);
}

/*
 * Feature: MediaLibrary
 * Function: GetMediaAssets
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Get media assets present in particular directory and subdirectories.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_GetMediaAssets_testlevel0_001, TestSize.Level0)
{
    vector<unique_ptr<MediaAsset>> mediaAssetList;
    unsigned int size = 0;
    string dirPath = "gtest/003/image";
    vector<string> selectionArgs;
    struct stat statInfo {};
    string dirPathCheck = "/storage/media/local/files/" + dirPath;

    if (stat(dirPathCheck.c_str(), &statInfo) == 0) {
        if (statInfo.st_mode & S_IFDIR) {
            if (g_mediaLibClientInstance != nullptr) {
                mediaAssetList = g_mediaLibClientInstance->GetMediaAssets(dirPath, selectionArgs);
            }
        }
    }
    EXPECT_NE(mediaAssetList.size(), size);
}

/*
 * Feature: MediaLibrary
 * Function: GetMediaAssets
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Get media assets from ROOT_DIR=/storage/media/local/files directory and subdirectories.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_GetMediaAssets_test_002, TestSize.Level1)
{
    vector<unique_ptr<MediaAsset>> mediaAssetList;
    unsigned int size = 0;
    string dirPath = "";
    vector<string> selectionArgs;

    if (g_mediaLibClientInstance != nullptr) {
        mediaAssetList = g_mediaLibClientInstance->GetMediaAssets(dirPath, selectionArgs);
    }
    EXPECT_NE(mediaAssetList.size(), size);
}

/*
 * Feature: MediaLibrary
 * Function: GetImageAlbumAssets
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Get image media assets present in particular directory and subdirectories.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_GetIMageAlbumAssets_testlevel0_001, TestSize.Level0)
{
    vector<unique_ptr<AlbumAsset>> albumAssetList;
    unsigned int size = 0;
    string dirPath = "gtest/003";
    vector<string> selectionArgs;
    struct stat statInfo {};
    string dirPathCheck = "/storage/media/local/files/" + dirPath;

    if (stat(dirPathCheck.c_str(), &statInfo) == 0) {
        if (statInfo.st_mode & S_IFDIR) {
            if (g_mediaLibClientInstance != nullptr) {
                albumAssetList = g_mediaLibClientInstance->GetImageAlbumAssets(dirPath, selectionArgs);
            }
        }
    }
    EXPECT_NE(albumAssetList.size(), size);
}

/*
 * Feature: MediaLibrary
 * Function: GetImageAlbumAssets
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Get image album assets from ROOT_DIR=/storage/media/local/files/ directory and subdirectories.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_GetImageAlbumAssets_test_002, TestSize.Level1)
{
    bool errCode = false;
    AlbumAsset albumAsset;
    AssetType assetType = ASSET_IMAGEALBUM;

    albumAsset.SetAlbumName("crtalbum002");
    if (g_mediaLibClientInstance != nullptr) {
        errCode = g_mediaLibClientInstance->CreateMediaAlbumAsset(assetType, albumAsset);
    }
    EXPECT_NE(errCode, false);

    vector<unique_ptr<AlbumAsset>> albumAssetList;
    unsigned int size = 0;
    string dirPath = "";
    vector<string> selectionArgs;

    if (g_mediaLibClientInstance != nullptr) {
        albumAssetList = g_mediaLibClientInstance->GetImageAlbumAssets(dirPath, selectionArgs);
    }
    EXPECT_NE(albumAssetList.size(), size);

    errCode = false;
    string albumUri;

    // delete the empty album
    albumUri = "/storage/media/local/files/crtalbum002";
    if (g_mediaLibClientInstance != nullptr) {
        errCode = g_mediaLibClientInstance->DeleteMediaAlbumAsset(assetType, albumAsset, albumUri);
    }
    EXPECT_NE(errCode, false);
}

/*
 * Feature: MediaLibrary
 * Function: GetVideoAlbumAssets
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Get video media assets present in particular directory and subdirectories.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_GetVideoAlbumAssets_testlevel0_003, TestSize.Level0)
{
    vector<unique_ptr<AlbumAsset>> albumAssetList;
    unsigned int size = 0;
    string dirPath = "gtest/002";
    vector<string> selectionArgs;
    struct stat statInfo {};
    string dirPathCheck = "/storage/media/local/files/" + dirPath;

    if (stat(dirPathCheck.c_str(), &statInfo) == 0) {
        if (statInfo.st_mode & S_IFDIR) {
            if (g_mediaLibClientInstance != nullptr) {
                albumAssetList = g_mediaLibClientInstance->GetVideoAlbumAssets(dirPath, selectionArgs);
            }
        }
    }
    EXPECT_NE(albumAssetList.size(), size);
}

/*
 * Feature: MediaLibrary
 * Function: GetVideoAlbumAssets
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Get video album assets from ROOT_DIR=/storage/media/local/files directory and subdirectories.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_GetVideoAlbumAssets_test_004, TestSize.Level1)
{
    vector<unique_ptr<AlbumAsset>> albumAssetList;
    unsigned int size = 0;
    string dirPath = "";
    vector<string> selectionArgs;

    if (g_mediaLibClientInstance != nullptr) {
        albumAssetList = g_mediaLibClientInstance->GetVideoAlbumAssets(dirPath, selectionArgs);
    }
    EXPECT_EQ(albumAssetList.size(), size);
}

/*
 * Feature: MediaLibrary
 * Function: ModifyMediaAsset
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Modify media audio asset in requested directory.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_ModifyMediaAsset_testlevel0_001, TestSize.Level0)
{
    bool errCode = false;
    MediaAsset srcMediaAsset;
    MediaAsset dstMediaAsset;
    AssetType assetType = ASSET_AUDIO;

    srcMediaAsset.name_ = "test_001_audio.mp3";
    srcMediaAsset.uri_ = "/storage/media/local/files/gtest/001/audio/test_001_audio.mp3";
    dstMediaAsset.name_ = "test_001_audio_modify.mp3";
    dstMediaAsset.uri_ = "/storage/media/local/files/gtest/001/audio/test_001_audio.mp3";
    if (g_mediaLibClientInstance != nullptr) {
        errCode = g_mediaLibClientInstance->ModifyMediaAsset(assetType, srcMediaAsset, dstMediaAsset);
    }
    EXPECT_NE(errCode, false);
}

/*
 * Feature: MediaLibrary
 * Function: ModifyMediaAsset
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Modify media audio mp3 file to wav in requested directory.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_ModifyMediaAsset_test_002, TestSize.Level1)
{
    bool errCode = true;
    MediaAsset srcMediaAsset;
    MediaAsset dstMediaAsset;
    AssetType assetType = ASSET_AUDIO;

    srcMediaAsset.name_ = "test_002_audio.mp3";
    srcMediaAsset.uri_ = "/storage/media/local/files/gtest/001/audio/test_002_audio.mp3";
    dstMediaAsset.name_ = "test_002_audio_modify.wav";
    dstMediaAsset.uri_ = "/storage/media/local/files/gtest/001/audio/test_002_audio.mp3";
    if (g_mediaLibClientInstance != nullptr) {
        errCode = g_mediaLibClientInstance->ModifyMediaAsset(assetType, srcMediaAsset, dstMediaAsset);
    }
    EXPECT_EQ(errCode, false);
}

/*
 * Feature: MediaLibrary
 * Function: ModifyMediaAsset
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Modify media audio asset  in requested non existing directory.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_ModifyMediaAsset_test_003, TestSize.Level1)
{
    bool errCode = false;
    MediaAsset srcMediaAsset;
    MediaAsset dstMediaAsset;
    AssetType assetType = ASSET_AUDIO;

    srcMediaAsset.name_ = "test_002_audio.mp3";
    srcMediaAsset.uri_ = "/storage/media/local/files/gtest/001/audio_nofile/test_002_audio.mp3";
    dstMediaAsset.uri_ = "/storage/media/local/files/gtest/001/audio_nofile/test_002_audio.mp3";
    dstMediaAsset.name_ = "test_002_audio_modify.mp3";
    if (g_mediaLibClientInstance != nullptr) {
        errCode = g_mediaLibClientInstance->ModifyMediaAsset(assetType, srcMediaAsset, dstMediaAsset);
    }
    EXPECT_EQ(errCode, false);
}

/*
 * Feature: MediaLibrary
 * Function: CopyMediaAsset
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: copy media asset to requested new directory, which gets created.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_CopyMediaAsset_testlevel0_001, TestSize.Level0)
{
    bool errCode = false;
    MediaAsset srcMediaAsset;
    MediaAsset dstMediaAsset;
    AssetType assetType = ASSET_AUDIO;
    // copy to requested albumName
    srcMediaAsset.name_ = "test_001_audio_modify.mp3";
    srcMediaAsset.uri_ = "/storage/media/local/files/gtest/001/audio/test_001_audio_modify.mp3";
    dstMediaAsset.albumName_ = "gtest/001/copyaudio";
    if (g_mediaLibClientInstance != nullptr) {
        errCode = g_mediaLibClientInstance->CopyMediaAsset(assetType, srcMediaAsset, dstMediaAsset);
    }
    EXPECT_NE(errCode, false);
}

/*
 * Feature: MediaLibrary
 * Function: CopyMediaAsset
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: copy media asset to requested non existing directory.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_CopyMediaAsset_testlevel0_002, TestSize.Level0)
{
    bool errCode = false;
    MediaAsset srcMediaAsset;
    MediaAsset dstMediaAsset;
    AssetType assetType = ASSET_IMAGE;
    // create and Copy to requested albumName
    srcMediaAsset.name_ = "test_003_image.jpg";
    srcMediaAsset.uri_ = "/storage/media/local/files/gtest/003/image/test_003_image.jpg";
    dstMediaAsset.albumName_ = "gtest/copyjpg/001/image";
    if (g_mediaLibClientInstance != nullptr) {
        errCode = g_mediaLibClientInstance->CopyMediaAsset(assetType, srcMediaAsset, dstMediaAsset);
    }
    EXPECT_NE(errCode, false);
}

/*
 * Feature: MediaLibrary
 * Function: CopyMediaAsset
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: copy media asset to ROOT_DIR=/storage/media/local/files directory.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_CopyMediaAsset_test_003, TestSize.Level1)
{
    bool errCode = false;
    MediaAsset srcMediaAsset;
    MediaAsset dstMediaAsset;
    AssetType assetType = ASSET_AUDIO;
    // copy to ROOT_DIR
    srcMediaAsset.name_ = "test_001_audio_modify.mp3";
    srcMediaAsset.uri_ = "/storage/media/local/files/gtest/001/copyaudio/test_001_audio_modify.mp3";
    dstMediaAsset.albumName_ = "";
    if (g_mediaLibClientInstance != nullptr) {
        errCode = g_mediaLibClientInstance->CopyMediaAsset(assetType, srcMediaAsset, dstMediaAsset);
    }
    EXPECT_EQ(errCode, false);
}

/*
 * Feature: MediaLibrary
 * Function: CopyMediaAsset
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: copy media asset in requested directory without source file name .
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_CopyMediaAsset_test_004, TestSize.Level1)
{
    bool errCode = false;
    MediaAsset srcMediaAsset;
    MediaAsset dstMediaAsset;
    AssetType assetType = ASSET_AUDIO;

    srcMediaAsset.name_ = "";
    srcMediaAsset.uri_ = "/storage/media/local/files/gtest/001/audio/test_fail.mp3";
    dstMediaAsset.albumName_ = "";
    if (g_mediaLibClientInstance != nullptr) {
        errCode = g_mediaLibClientInstance->CopyMediaAsset(assetType, srcMediaAsset, dstMediaAsset);
    }
    EXPECT_EQ(errCode, false);
}

/*
 * Feature: MediaLibrary
 * Function: DeleteMediaAsset
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Delete media audio asset from requested directory.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_DeleteMediaAsset_testlevel0_001, TestSize.Level0)
{
    bool errCode = false;
    MediaAsset mediaAsset;
    AssetType assetType = ASSET_AUDIO;

    mediaAsset.name_ = "test_001_audio_modify.mp3";
    mediaAsset.uri_ = "/storage/media/local/files/gtest/001/copyaudio/test_001_audio_modify.mp3";
    if (g_mediaLibClientInstance != nullptr) {
        errCode = g_mediaLibClientInstance->DeleteMediaAsset(assetType, mediaAsset);
    }
    EXPECT_NE(errCode, false);
}

/*
 * Feature: MediaLibrary
 * Function: DeleteMediaAsset
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Delete media video asset in requested directory.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_DeleteMediaAsset_testlevel0_002, TestSize.Level0)
{
    bool errCode = false;
    MediaAsset mediaAsset;
    AssetType assetType = ASSET_VIDEO;

    mediaAsset.name_ = "test_002_video.mp4";
    mediaAsset.uri_ = "/storage/media/local/files/gtest/002/video/test_002_video.mp4";
    if (g_mediaLibClientInstance != nullptr) {
        errCode = g_mediaLibClientInstance->DeleteMediaAsset(assetType, mediaAsset);
    }
    EXPECT_NE(errCode, false);
}

/*
 * Feature: MediaLibrary
 * Function: DeleteMediaAsset
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Create media image asset in requested directory.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_DeleteMediaAsset_testlevel0_003, TestSize.Level0)
{
    bool errCode = false;
    MediaAsset mediaAsset;
    AssetType assetType = ASSET_IMAGE;

    mediaAsset.name_ = "test_003_image.jpg";
    mediaAsset.uri_ = "/storage/media/local/files/gtest/003/image/test_003_image.jpg";
    if (g_mediaLibClientInstance != nullptr) {
        errCode = g_mediaLibClientInstance->DeleteMediaAsset(assetType, mediaAsset);
    }
    EXPECT_NE(errCode, false);
}

/*
 * Feature: MediaLibrary
 * Function: DeleteMediaAsset
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Delete media asset from requested empty directory path
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_DeleteMediaAsset_test_004, TestSize.Level1)
{
    bool errCode = true;
    MediaAsset mediaAsset;
    AssetType assetType = ASSET_AUDIO;

    mediaAsset.name_ = "";
    mediaAsset.uri_ = "";
    if (g_mediaLibClientInstance != nullptr) {
        errCode = g_mediaLibClientInstance->DeleteMediaAsset(assetType, mediaAsset);
    }
    EXPECT_EQ(errCode, false);
}

/*
 * Feature: MediaLibrary
 * Function: CreateMediaAlbumAsset
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Create album asset in requested directory.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_CreateMediaAlbumAsset_testlevel0_001, TestSize.Level0)
{
    bool errCode = false;
    AlbumAsset albumAsset;
    AssetType assetType = ASSET_GENERIC_ALBUM;

    albumAsset.SetAlbumName("gtest/crtalbum001");
    if (g_mediaLibClientInstance != nullptr) {
        errCode = g_mediaLibClientInstance->CreateMediaAlbumAsset(assetType, albumAsset);
    }
    EXPECT_NE(errCode, false);
}

/*
 * Feature: MediaLibrary
 * Function: ModifyMediaAlbumAsset
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Modify image album asset from requested directory.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_ModifyMediaAlbumAsset_testlevel0_001, TestSize.Level0)
{
    bool errCode = false;
    AlbumAsset srcAlbumAsset;
    AlbumAsset dstAlbumAsset;
    string albumUri;
    AssetType assetType = ASSET_IMAGEALBUM;

    srcAlbumAsset.SetAlbumName("gtest/copyjpg/001/image");
    dstAlbumAsset.SetAlbumName("modify_image001");
    albumUri = "/storage/media/local/files/gtest/copyjpg/001/image";
    if (g_mediaLibClientInstance != nullptr) {
        errCode = g_mediaLibClientInstance->ModifyMediaAlbumAsset(assetType, srcAlbumAsset, dstAlbumAsset, albumUri);
    }
    EXPECT_NE(errCode, false);
}

/*
 * Feature: MediaLibrary
 * Function: ModifyMediaAlbumAsset
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Modify image album asset in requested "non existing" directory.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_ModifyMediaAlbumAsset_test_002, TestSize.Level1)
{
    bool errCode = true;
    AlbumAsset srcAlbumAsset;
    AlbumAsset dstAlbumAsset;
    string albumUri;
    AssetType assetType = ASSET_IMAGEALBUM;

    srcAlbumAsset.SetAlbumName("test/album001");
    dstAlbumAsset.SetAlbumName("modify_album002");
    albumUri = "/storage/media/local/files/test2/album001";
    if (g_mediaLibClientInstance != nullptr) {
        errCode = g_mediaLibClientInstance->ModifyMediaAlbumAsset(assetType, srcAlbumAsset, dstAlbumAsset, albumUri);
    }
    EXPECT_EQ(errCode, false);
}

/*
 * Feature: MediaLibrary
 * Function: DeleteMediaAlbumAsset
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Delete media album from requested directory path.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_DeleteMediaAlbumAsset_testlevel0_001, TestSize.Level0)
{
    bool errCode = false;
    AlbumAsset albumAsset;
    string albumUri;
    struct stat statInfo {};
    AssetType assetType = ASSET_IMAGEALBUM;

    albumAsset.SetAlbumName("gtest/copyjpg/001/modify_image001");
    albumUri = "/storage/media/local/files/gtest/copyjpg/001/modify_image001";
    if (stat(albumUri.c_str(), &statInfo) == 0) {
        if (statInfo.st_mode & S_IFDIR) {
            if (g_mediaLibClientInstance != nullptr) {
                errCode = g_mediaLibClientInstance->DeleteMediaAlbumAsset(assetType, albumAsset, albumUri);
            }
        }
    }
    EXPECT_NE(errCode, false);
}

/*
 * Feature: MediaLibrary
 * Function: DeleteMediaAlbumAsset
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Delete media album from requested non existing path.
 */
HWTEST_F(MediaLibraryUnitTest, medialibrary_DeleteMediaAlbumAsset_test_002, TestSize.Level1)
{
    bool errCode = true;
    AlbumAsset albumAsset;
    string albumUri;
    AssetType assetType = ASSET_IMAGEALBUM;

    albumAsset.SetAlbumName("gtest/modify_album001");
    albumUri = "/storage/media/local/files/test/modify_album002";
    if (g_mediaLibClientInstance != nullptr) {
        errCode = g_mediaLibClientInstance->DeleteMediaAlbumAsset(assetType, albumAsset, albumUri);
    }
    EXPECT_EQ(errCode, false);
}
} // namespace Media
} // namespace OHOS
