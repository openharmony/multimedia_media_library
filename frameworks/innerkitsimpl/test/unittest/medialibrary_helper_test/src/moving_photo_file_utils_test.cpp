/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "moving_photo_file_utils.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
static const unsigned char FILE_TEST_JPG[] = {
    0xFF, 0xD8, 0xFF, 0xE0, 0x01, 0x02, 0x03, 0x04, 0xFF, 0xD9
};

static const unsigned char FILE_TEST_MP4[] = {
    0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6F, 0x6D, 0x01, 0x02, 0x03, 0x04
};

static const unsigned char FILE_TEST_EXTRA_DATA[] = {
    0x76, 0x33, 0x5f, 0x66, 0x30, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x30, 0x3a,
    0x30, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x4c, 0x49, 0x56, 0x45,
    0x5f, 0x33, 0x36, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20 };

static const unsigned char FILE_TEST_LIVE_PHOTO[] = {
    0xFF, 0xD8, 0xFF, 0xE0, 0x01, 0x02, 0x03, 0x04, 0xFF, 0xD9, 0x00,
    0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6F, 0x6D,
    0x01, 0x02, 0x03, 0x04, 0x76, 0x33, 0x5f, 0x66, 0x30, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x30, 0x3a, 0x30, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x4c, 0x49, 0x56, 0x45, 0x5f, 0x33, 0x36, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20
};

static bool WriteFileContent(const string& path, const unsigned char content[], int32_t size)
{
    int32_t fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC);
    if (fd < 0) {
        MEDIA_ERR_LOG("Failed to open %{public}s", path.c_str());
        return false;
    }

    int32_t resWrite = write(fd, content, size);
    if (resWrite == -1) {
        MEDIA_ERR_LOG("Failed to write content");
        close(fd);
        return false;
    }

    close(fd);
    return true;
}

static bool CompareIfContentEquals(const unsigned char originArray[], const string& path, const int32_t size)
{
    int32_t fd = open(path.c_str(), O_RDONLY);
    int32_t len = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    if (len < 0 || len != size) {
        MEDIA_ERR_LOG("Failed to check size: %{public}d %{public}d", size, len);
        return false;
    }
    unsigned char* buf = static_cast<unsigned char*>(malloc(len));
    if (buf == nullptr) {
        return false;
    }
    read(fd, buf, len);
    close(fd);

    for (int i = 0; i < size - 1; i++) {
        if (originArray[i] != buf[i]) {
            free(buf);
            return false;
        }
    }

    free(buf);
    return true;
}

HWTEST_F(MediaLibraryHelperUnitTest, MovingPhotoFileUtils_ConvertToMovingPhoto_001, TestSize.Level0)
{
    string dirPath = "/data/test/ConvertToMovingPhoto_001";
    EXPECT_EQ(MediaFileUtils::CreateDirectory(dirPath), true);
    string livePhotoPath = dirPath + "/" + "livePhoto.jpg";
    EXPECT_EQ(WriteFileContent(livePhotoPath, FILE_TEST_LIVE_PHOTO, sizeof(FILE_TEST_LIVE_PHOTO)), true);
    string imagePath = dirPath + "/" + "image.jpg";
    string videoPath = dirPath + "/" + "video.mp4";
    string extraDataPath = dirPath + "/" + "extraData";
    EXPECT_EQ(MovingPhotoFileUtils::ConvertToMovingPhoto(livePhotoPath, imagePath, videoPath, extraDataPath), E_OK);
    EXPECT_EQ(CompareIfContentEquals(FILE_TEST_JPG, imagePath, sizeof(FILE_TEST_JPG)), true);
    EXPECT_EQ(CompareIfContentEquals(FILE_TEST_MP4, videoPath, sizeof(FILE_TEST_MP4)), true);
    EXPECT_EQ(CompareIfContentEquals(FILE_TEST_EXTRA_DATA, extraDataPath, sizeof(FILE_TEST_EXTRA_DATA)), true);
}

HWTEST_F(MediaLibraryHelperUnitTest, MovingPhotoFileUtils_ConvertToMovingPhoto_002, TestSize.Level0)
{
    string dirPath = "/data/test/ConvertToMovingPhoto_002";
    EXPECT_EQ(MediaFileUtils::CreateDirectory(dirPath), true);
    string livePhotoPath = dirPath + "/" + "livePhotoSamePath.jpg";
    EXPECT_EQ(WriteFileContent(livePhotoPath, FILE_TEST_LIVE_PHOTO, sizeof(FILE_TEST_LIVE_PHOTO)), true);
    string imagePath = dirPath + "/" + "livePhotoSamePath.jpg";
    string videoPath = dirPath + "/" + "video.mp4";
    string extraDataPath = dirPath + "/" + "extraData";
    EXPECT_EQ(MovingPhotoFileUtils::ConvertToMovingPhoto(livePhotoPath, imagePath, videoPath, extraDataPath), E_OK);
    EXPECT_EQ(CompareIfContentEquals(FILE_TEST_JPG, imagePath, sizeof(FILE_TEST_JPG)), true);
    EXPECT_EQ(CompareIfContentEquals(FILE_TEST_MP4, videoPath, sizeof(FILE_TEST_MP4)), true);
    EXPECT_EQ(CompareIfContentEquals(FILE_TEST_EXTRA_DATA, extraDataPath, sizeof(FILE_TEST_EXTRA_DATA)), true);
}

HWTEST_F(MediaLibraryHelperUnitTest, MovingPhotoFileUtils_GetCoverPosition_001, TestSize.Level0)
{
    string dirPath = "/data/test/GetCoverPosition_001";
    EXPECT_EQ(MediaFileUtils::CreateDirectory(dirPath), true);
    string videoPath = dirPath + "/" + "video.mp4";
    EXPECT_EQ(WriteFileContent(videoPath, FILE_TEST_MP4, sizeof(FILE_TEST_MP4)), true);
    uint64_t coverPosition;
    EXPECT_LT(MovingPhotoFileUtils::GetCoverPosition(videoPath, 0, coverPosition), E_OK);
}

HWTEST_F(MediaLibraryHelperUnitTest, MovingPhotoFileUtils_GetVersionAndFrameNum_001, TestSize.Level0)
{
    string tag = "v3_f31_c";
    uint32_t version;
    uint32_t frameIndex;
    bool hasCinemagraphInfo;
    int32_t ret = MovingPhotoFileUtils::GetVersionAndFrameNum(tag, version, frameIndex, hasCinemagraphInfo);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(version, 3);
    EXPECT_EQ(frameIndex, 31);
    EXPECT_EQ(hasCinemagraphInfo, true);
}

HWTEST_F(MediaLibraryHelperUnitTest, MovingPhotoFileUtils_GetVersionAndFrameNum_002, TestSize.Level0)
{
    string tag = "v2_f30";
    uint32_t version;
    uint32_t frameIndex;
    bool hasCinemagraphInfo;
    int32_t ret = MovingPhotoFileUtils::GetVersionAndFrameNum(tag, version, frameIndex, hasCinemagraphInfo);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(version, 2);
    EXPECT_EQ(frameIndex, 30);
    EXPECT_EQ(hasCinemagraphInfo, false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MovingPhotoFileUtils_GetVersionAndFrameNum_003, TestSize.Level0)
{
    string tag = "V2_F29_C";
    uint32_t version;
    uint32_t frameIndex;
    bool hasCinemagraphInfo;
    int32_t ret = MovingPhotoFileUtils::GetVersionAndFrameNum(tag, version, frameIndex, hasCinemagraphInfo);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(version, 2);
    EXPECT_EQ(frameIndex, 29);
    EXPECT_EQ(hasCinemagraphInfo, true);
}

HWTEST_F(MediaLibraryHelperUnitTest, MovingPhotoFileUtils_GetVersionAndFrameNum_004, TestSize.Level0)
{
    string tag = "V3_F33";
    uint32_t version;
    uint32_t frameIndex;
    bool hasCinemagraphInfo;
    int32_t ret = MovingPhotoFileUtils::GetVersionAndFrameNum(tag, version, frameIndex, hasCinemagraphInfo);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(version, 3);
    EXPECT_EQ(frameIndex, 33);
    EXPECT_EQ(hasCinemagraphInfo, false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MovingPhotoFileUtils_GetVersionAndFrameNum_005, TestSize.Level0)
{
    string tag = "";
    uint32_t version;
    uint32_t frameIndex;
    bool hasCinemagraphInfo;
    int32_t ret = MovingPhotoFileUtils::GetVersionAndFrameNum(tag, version, frameIndex, hasCinemagraphInfo);
    EXPECT_LT(ret, E_OK);

    tag = "invalid";
    ret = MovingPhotoFileUtils::GetVersionAndFrameNum(tag, version, frameIndex, hasCinemagraphInfo);
    EXPECT_LT(ret, E_OK);

    tag = "31";
    ret = MovingPhotoFileUtils::GetVersionAndFrameNum(tag, version, frameIndex, hasCinemagraphInfo);
    EXPECT_LT(ret, E_OK);
}

HWTEST_F(MediaLibraryHelperUnitTest, MovingPhotoFileUtils_GetVersionAndFrameNum_006, TestSize.Level0)
{
    string dirPath = "/data/test/GetVersionAndFrameNum_006";
    EXPECT_EQ(MediaFileUtils::CreateDirectory(dirPath), true);
    string livePhotoPath = dirPath + "/" + "livePhoto.jpg";
    EXPECT_EQ(WriteFileContent(livePhotoPath, FILE_TEST_LIVE_PHOTO, sizeof(FILE_TEST_LIVE_PHOTO)), true);

    int32_t fd = open(livePhotoPath.c_str(), O_RDONLY);
    uint32_t version;
    uint32_t frameIndex;
    bool hasCinemagraphInfo;
    int32_t ret = MovingPhotoFileUtils::GetVersionAndFrameNum(fd, version, frameIndex, hasCinemagraphInfo);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(version, 3);
    EXPECT_EQ(frameIndex, 0);
    EXPECT_EQ(hasCinemagraphInfo, false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MovingPhotoFileUtils_GetVersionAndFrameNum_007, TestSize.Level0)
{
    string dirPath = "/data/test/GetVersionAndFrameNum_007";
    EXPECT_EQ(MediaFileUtils::CreateDirectory(dirPath), true);
    string livePhotoPath = dirPath + "/" + "extraData";
    EXPECT_EQ(WriteFileContent(livePhotoPath, FILE_TEST_EXTRA_DATA, sizeof(FILE_TEST_EXTRA_DATA)), true);

    int32_t fd = open(livePhotoPath.c_str(), O_RDONLY);
    uint32_t version;
    uint32_t frameIndex;
    bool hasCinemagraphInfo;
    int32_t ret = MovingPhotoFileUtils::GetVersionAndFrameNum(fd, version, frameIndex, hasCinemagraphInfo);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(version, 3);
    EXPECT_EQ(frameIndex, 0);
    EXPECT_EQ(hasCinemagraphInfo, false);
}

HWTEST_F(MediaLibraryHelperUnitTest, MovingPhotoFileUtils_GetMovingPhotoVideoPath_001, TestSize.Level0)
{
    string imagePath = "/storage/cloud/files/Photo/1/IMG_123435213_231.jpg";
    string videoPath = "/storage/cloud/files/Photo/1/IMG_123435213_231.mp4";
    EXPECT_EQ(MovingPhotoFileUtils::GetMovingPhotoVideoPath(imagePath), videoPath);
}

HWTEST_F(MediaLibraryHelperUnitTest, MovingPhotoFileUtils_GetMovingPhotoVideoPath_002, TestSize.Level0)
{
    string imagePath = "/storage/cloud/files/.hiddenTest/IMG_123435213_231";
    EXPECT_EQ(MovingPhotoFileUtils::GetMovingPhotoVideoPath(imagePath), "");
}

HWTEST_F(MediaLibraryHelperUnitTest, MovingPhotoFileUtils_GetMovingPhotoExtraDataDir_001, TestSize.Level0)
{
    string imagePath = "/storage/cloud/files/Photo/1/IMG_123435213_231.jpg";
    string extraDataDir = "/storage/cloud/files/.editData/Photo/1/IMG_123435213_231.jpg";
    EXPECT_EQ(MovingPhotoFileUtils::GetMovingPhotoExtraDataDir(imagePath), extraDataDir);
}

HWTEST_F(MediaLibraryHelperUnitTest, MovingPhotoFileUtils_GetMovingPhotoExtraDataPath_001, TestSize.Level0)
{
    string imagePath = "/storage/cloud/files/Photo/1/IMG_123435213_231.jpg";
    string extraDataPath = "/storage/cloud/files/.editData/Photo/1/IMG_123435213_231.jpg/extraData";
    EXPECT_EQ(MovingPhotoFileUtils::GetMovingPhotoExtraDataPath(imagePath), extraDataPath);
}

bool CompareFile(const unsigned char originArray[], off_t originSize,
    const unsigned char targetArray[], off_t targetSize)
{
    if (originSize != targetSize) {
        MEDIA_INFO_LOG("[lcl] originSize %{public}ld, targetSize %{public}ld", originSize, targetSize);
        return false;
    }
    bool isEqual = true;
    for (int i = 0; i < targetSize; i++) {
        if (originArray[i] != targetArray[i]) {
            MEDIA_INFO_LOG("[lcl] originSize %{public}c, targetSize %{public}c, i %{public}d", originArray[i], targetArray[i], i);
            isEqual = false;
        }
    }
    return isEqual;
}

HWTEST_F(MediaLibraryHelperUnitTest, MovingPhotoFileUtils_convert_live_photo_test_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("start tdd MovingPhotoFileUtils_convert_live_photo_test_001");

    // create live photo
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::CREATE, MediaLibraryApi::API_10);
    ValuesBucket values;
    values.PutString(ASSET_EXTENTION, "jpg");
    values.PutString(PhotoColumn::MEDIA_TITLE, "live_photo");
    values.PutInt(MediaColumn::MEDIA_TYPE, MediaType::MEDIA_TYPE_IMAGE);
    values.PutInt(PhotoColumn::PHOTO_SUBTYPE, static_cast<int>(PhotoSubType::MOVING_PHOTO));
    cmd.SetValueBucket(values);
    cmd.SetBundleName("values");
    MediaLibraryPhotoOperations::Create(cmd);
    int32_t fileId = QueryPhotoIdByDisplayName("live_photo.jpg");
    ASSERT_GE(fileId, 0);

    MediaFileUri fileUri(MediaType::MEDIA_TYPE_IMAGE, to_string(fileId), "", MEDIA_API_VERSION_V10);
    string fileUriStr = fileUri.ToString();
    Uri uri(fileUriStr);
    MediaLibraryCommand openImageCmd(uri, Media::OperationType::OPEN);
    int32_t imageFd = MediaLibraryPhotoOperations::Open(openImageCmd, "w");
    ASSERT_GE(imageFd, 0);
    int32_t resWrite = write(imageFd, FILE_TEST_JPG, sizeof(FILE_TEST_JPG));
    if (resWrite == -1) {
        EXPECT_EQ(false, true);
    }

    string videoUriStr = fileUriStr;
    MediaFileUtils::UriAppendKeyValue(videoUriStr, MEDIA_MOVING_PHOTO_OPRN_KEYWORD, OPEN_MOVING_PHOTO_VIDEO);
    Uri videoUri(videoUriStr);
    MediaLibraryCommand videoCmd(videoUri, Media::OperationType::OPEN);
    videoCmd.SetOprnObject(OperationObject::FILESYSTEM_PHOTO);
    int32_t videoFd = MediaLibraryDataManager::GetInstance()->OpenFile(videoCmd, "w");
    ASSERT_GE(videoFd, 0);
    resWrite = write(videoFd, FILE_TEST_MP4, sizeof(FILE_TEST_MP4));
    if (resWrite == -1) {
        EXPECT_EQ(false, true);
    }

    MediaLibraryCommand closeCmd(OperationObject::FILESYSTEM_PHOTO, OperationType::CLOSE);
    ValuesBucket closeValues;
    closeValues.PutString(MEDIA_DATA_DB_URI, fileUriStr);
    closeCmd.SetValueBucket(closeValues);
    MediaLibraryPhotoOperations::Close(closeCmd);

    // read live photo video
    string livePhotoUriStr = fileUriStr;
    MediaFileUtils::UriAppendKeyValue(livePhotoUriStr, MEDIA_MOVING_PHOTO_OPRN_KEYWORD, OPEN_PRIVATE_LIVE_PHOTO);
    Uri livePhotoUri(livePhotoUriStr);
    MediaLibraryCommand livePhotoCmd(livePhotoUri, Media::OperationType::OPEN);
    livePhotoCmd.SetOprnObject(OperationObject::FILESYSTEM_PHOTO);
    int32_t livePhotoFd = MediaLibraryDataManager::GetInstance()->OpenFile(livePhotoCmd, "rw");
    ASSERT_GE(livePhotoFd, 0);
    int64_t destLen = lseek(livePhotoFd, 0, SEEK_END);
    lseek(livePhotoFd, 0, SEEK_SET);
    unsigned char *buf = static_cast<unsigned char*>(malloc(destLen));
    EXPECT_NE((buf == nullptr), true);
    read(livePhotoFd, buf, destLen);

    bool result = CompareFile(FILE_TEST_LIVE_PHOTO, sizeof(FILE_TEST_LIVE_PHOTO), buf, destLen);
    free(buf);
    close(livePhotoFd);
    EXPECT_EQ(result, true);
    MEDIA_INFO_LOG("end tdd MovingPhotoFileUtils_convert_live_photo_test_001");
}
} // namespace Media
} // namespace OHOS