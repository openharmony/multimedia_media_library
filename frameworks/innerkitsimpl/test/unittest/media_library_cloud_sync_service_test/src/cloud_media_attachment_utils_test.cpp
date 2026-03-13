/*
 * Copyright (C).2026 Huawei Device Co., Ltd.
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

#define MLOG_TAG "CloudMediaAttachmentUtilsTest"

#include "cloud_media_attachment_utils_test.h"

#include <fstream>
#include <unistd.h>
#include <sys/stat.h>

#include "cloud_media_attachment_utils.h"
#include "photos_dto.h"
#include "cloud_file_data_dto.h"
#include "medialibrary_errno.h"
#include "media_log.h"
#include "media_edit_utils.h"
#include "photo_file_utils.h"
#include "cloud_media_file_utils.h"
#include "thumbnail_const.h"

using namespace testing::ext;
using namespace OHOS::Media::CloudSync;
using namespace OHOS::Media;

namespace OHOS {
namespace Media {
namespace CloudSync {

static const std::string TEST_ROOT_DIR = "/data/test/cloud_media_attachment_test/";
static const std::string TEST_FILE_PATH = "/data/test/cloud_media_attachment_test/test_photo.jpg";
static const std::string TEST_THUMB_DIR = "/storage/media/local/.thumbs/";
static const std::string ROOT_MEDIA_DIR = "/storage/media/local/files/";

void CloudMediaAttachmentUtilsTest::SetUpTestCase()
{
    MEDIA_INFO_LOG("CloudMediaAttachmentUtilsTest::SetUpTestCase enter");
    CreateTestDirectory(TEST_ROOT_DIR);
    CreateTestDirectory(TEST_THUMB_DIR);
    CreateTestDirectory(ROOT_MEDIA_DIR);
    CreateTestFile(TEST_FILE_PATH, "test photo content");
}

void CloudMediaAttachmentUtilsTest::TearDownTestCase()
{
    MEDIA_INFO_LOG("CloudMediaAttachmentUtilsTest::TearDownTestCase enter");
    DeleteTestFile(TEST_FILE_PATH);
    DeleteTestDirectory(TEST_ROOT_DIR);
}

void CloudMediaAttachmentUtilsTest::SetUp()
{
    MEDIA_INFO_LOG("CloudMediaAttachmentUtilsTest::SetUp enter");
}

void CloudMediaAttachmentUtilsTest::TearDown()
{
    MEDIA_INFO_LOG("CloudMediaAttachmentUtilsTest::TearDown enter");
}

bool CloudMediaAttachmentUtilsTest::CreateTestDirectory(const std::string &path)
{
    if (access(path.c_str(), F_OK) == 0) {
        return true;
    }
    int rwPermission = 0755;
    return mkdir(path.c_str(), rwPermission) == 0;
}

bool CloudMediaAttachmentUtilsTest::CreateTestFile(const std::string &path, const std::string &content)
{
    std::ofstream file(path);
    if (!file.is_open()) {
        return false;
    }
    file << content;
    file.close();
    return access(path.c_str(), F_OK) == 0;
}

bool CloudMediaAttachmentUtilsTest::DeleteTestFile(const std::string &path)
{
    if (access(path.c_str(), F_OK) != 0) {
        return true;
    }
    return unlink(path.c_str()) == 0;
}

bool CloudMediaAttachmentUtilsTest::DeleteTestDirectory(const std::string &path)
{
    std::string cmd = "rm -rf " + path;
    return system(cmd.c_str()) == 0;
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetAttachment_Content_Success, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAttachment_Content_Success test start");
    std::string testPath = TEST_ROOT_DIR + "test_photo_001.jpg";
    CreateTestFile(testPath, "test content 001");
    
    DownloadAssetData downloadData;
    downloadData.fileId = 1001;
    downloadData.cloudId = "test_cloud_id_001";
    downloadData.fileSize = 2048;
    downloadData.mediaType = 1;
    downloadData.originalCloudId = "test_original_cloud_id_001";
    downloadData.path = testPath;
    downloadData.editTime = 0;
    downloadData.effectMode = 0;
    downloadData.orientation = 0;
    downloadData.fileSourceType = 0;
    downloadData.storagePath = TEST_ROOT_DIR;
    downloadData.hidden = 0;
    downloadData.dateTrashed = 0;
    downloadData.subtype = 0;
    
    PhotosDto photosDto;
    
    int32_t result = CloudMediaAttachmentUtils::GetAttachment("content", downloadData, photosDto);
    
    EXPECT_EQ(result, E_OK);
    EXPECT_FALSE(photosDto.attachment.empty());
    
    auto it = photosDto.attachment.find("content");
    EXPECT_NE(it, photosDto.attachment.end());
    if (it != photosDto.attachment.end()) {
        EXPECT_EQ(it->second.size, 2048);
    }
    
    DeleteTestFile(testPath);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetAttachment_Thumbnail_Success, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAttachment_Thumbnail_Success test start");
    std::string testPath = ROOT_MEDIA_DIR + "test_photo_002.jpg";
    CreateTestFile(testPath, "test content 002");
    
    std::string thumbPath = TEST_THUMB_DIR + "test_photo_002/THM.jpg";
    CreateTestDirectory(TEST_THUMB_DIR + "test_photo_002/");
    CreateTestFile(thumbPath, "thumbnail content");
    
    DownloadAssetData downloadData;
    downloadData.fileId = 1002;
    downloadData.cloudId = "test_cloud_id_002";
    downloadData.fileSize = 4096;
    downloadData.mediaType = 1;
    downloadData.originalCloudId = "test_original_cloud_id_002";
    downloadData.path = testPath;
    downloadData.editTime = 0;
    downloadData.effectMode = 0;
    downloadData.orientation = 0;
    downloadData.fileSourceType = 0;
    downloadData.storagePath = TEST_ROOT_DIR;
    downloadData.hidden = 0;
    downloadData.dateTrashed = 0;
    downloadData.subtype = 0;
    
    PhotosDto photosDto;
    
    int32_t result = CloudMediaAttachmentUtils::GetAttachment("thumbnail", downloadData, photosDto);
    
    EXPECT_EQ(result, E_OK);
    EXPECT_FALSE(photosDto.attachment.empty());
    
    auto it = photosDto.attachment.find("thumbnail");
    EXPECT_NE(it, photosDto.attachment.end());
    
    DeleteTestFile(testPath);
    DeleteTestFile(thumbPath);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetAttachment_Lcd_Success, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAttachment_Lcd_Success test start");
    std::string testPath = ROOT_MEDIA_DIR + "test_photo_003.jpg";
    CreateTestFile(testPath, "test content 003");
    
    std::string lcdPath = TEST_THUMB_DIR + "test_photo_003/LCD.jpg";
    CreateTestDirectory(TEST_THUMB_DIR + "test_photo_003/");
    CreateTestFile(lcdPath, "lcd content");
    
    DownloadAssetData downloadData;
    downloadData.fileId = 1003;
    downloadData.cloudId = "test_cloud_id_003";
    downloadData.fileSize = 8192;
    downloadData.mediaType = 1;
    downloadData.originalCloudId = "test_original_cloud_id_003";
    downloadData.path = testPath;
    downloadData.editTime = 0;
    downloadData.effectMode = 0;
    downloadData.orientation = 0;
    downloadData.fileSourceType = 0;
    downloadData.storagePath = TEST_ROOT_DIR;
    downloadData.hidden = 0;
    downloadData.dateTrashed = 0;
    downloadData.subtype = 0;
    
    PhotosDto photosDto;
    
    int32_t result = CloudMediaAttachmentUtils::GetAttachment("lcd", downloadData, photosDto);
    
    EXPECT_EQ(result, E_OK);
    EXPECT_FALSE(photosDto.attachment.empty());
    
    auto it = photosDto.attachment.find("lcd");
    EXPECT_NE(it, photosDto.attachment.end());
    
    DeleteTestFile(testPath);
    DeleteTestFile(lcdPath);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetAttachment_InvalidFileKey, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAttachment_InvalidFileKey test start");
    std::string testPath = TEST_ROOT_DIR + "test_photo_004.jpg";
    CreateTestFile(testPath, "test content 004");
    
    DownloadAssetData downloadData;
    downloadData.fileId = 1004;
    downloadData.cloudId = "test_cloud_id_004";
    downloadData.fileSize = 1024;
    downloadData.mediaType = 1;
    downloadData.originalCloudId = "test_original_cloud_id_004";
    downloadData.path = testPath;
    downloadData.editTime = 0;
    downloadData.effectMode = 0;
    downloadData.orientation = 0;
    downloadData.fileSourceType = 0;
    downloadData.storagePath = TEST_ROOT_DIR;
    downloadData.hidden = 0;
    downloadData.dateTrashed = 0;
    downloadData.subtype = 0;
    
    PhotosDto photosDto;
    
    int32_t result = CloudMediaAttachmentUtils::GetAttachment("invalid_key", downloadData, photosDto);
    
    EXPECT_EQ(result, E_ERR);
    EXPECT_TRUE(photosDto.attachment.empty());
    
    DeleteTestFile(testPath);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetAttachment_EmptyFileKey, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAttachment_EmptyFileKey test start");
    std::string testPath = TEST_ROOT_DIR + "test_photo_005.jpg";
    CreateTestFile(testPath, "test content 005");
    
    DownloadAssetData downloadData;
    downloadData.fileId = 1005;
    downloadData.cloudId = "test_cloud_id_005";
    downloadData.fileSize = 1024;
    downloadData.mediaType = 1;
    downloadData.originalCloudId = "test_original_cloud_id_005";
    downloadData.path = testPath;
    downloadData.editTime = 0;
    downloadData.effectMode = 0;
    downloadData.orientation = 0;
    downloadData.fileSourceType = 0;
    downloadData.storagePath = TEST_ROOT_DIR;
    downloadData.hidden = 0;
    downloadData.dateTrashed = 0;
    downloadData.subtype = 0;
    
    PhotosDto photosDto;
    
    int32_t result = CloudMediaAttachmentUtils::GetAttachment("", downloadData, photosDto);
    
    EXPECT_EQ(result, E_ERR);
    EXPECT_TRUE(photosDto.attachment.empty());
    
    DeleteTestFile(testPath);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetThumbnail_Rotation0_Success, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetThumbnail_Rotation0_Success test start");
    std::string testPath = ROOT_MEDIA_DIR + "test_photo_006.jpg";
    CreateTestFile(testPath, "test content 006");
    
    std::string thumbPath = TEST_THUMB_DIR + "test_photo_006/THM.jpg";
    CreateTestDirectory(TEST_THUMB_DIR + "test_photo_006/");
    CreateTestFile(thumbPath, "thumbnail content rotation 0");
    
    DownloadAssetData downloadData;
    downloadData.fileId = 1006;
    downloadData.cloudId = "test_cloud_id_006";
    downloadData.fileSize = 1024;
    downloadData.mediaType = 1;
    downloadData.originalCloudId = "test_original_cloud_id_006";
    downloadData.path = testPath;
    downloadData.editTime = 0;
    downloadData.effectMode = 0;
    downloadData.orientation = 0;
    downloadData.fileSourceType = 0;
    downloadData.storagePath = TEST_ROOT_DIR;
    downloadData.hidden = 0;
    downloadData.dateTrashed = 0;
    downloadData.subtype = 0;
    
    PhotosDto photosDto;
    
    int32_t result = CloudMediaAttachmentUtils::GetThumbnail("thumbnail", downloadData, photosDto);
    
    EXPECT_EQ(result, E_OK);
    EXPECT_FALSE(photosDto.attachment.empty());
    
    auto it = photosDto.attachment.find("thumbnail");
    EXPECT_NE(it, photosDto.attachment.end());
    
    DeleteTestFile(testPath);
    DeleteTestFile(thumbPath);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetThumbnail_Rotation90_Success, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetThumbnail_Rotation90_Success test start");
    std::string testPath = ROOT_MEDIA_DIR + "test_photo_007.jpg";
    CreateTestFile(testPath, "test content 007");
    
    std::string thumbPath = TEST_THUMB_DIR + "test_photo_007/THM_EX/THM.jpg";
    CreateTestDirectory(TEST_THUMB_DIR + "test_photo_007/THM_EX/");
    CreateTestFile(thumbPath, "thumbnail content rotation 90");
    
    DownloadAssetData downloadData;
    downloadData.fileId = 1007;
    downloadData.cloudId = "test_cloud_id_007";
    downloadData.fileSize = 1024;
    downloadData.mediaType = 1;
    downloadData.originalCloudId = "test_original_cloud_id_007";
    downloadData.path = testPath;
    downloadData.editTime = 0;
    downloadData.effectMode = 0;
    downloadData.orientation = 90;
    downloadData.fileSourceType = 0;
    downloadData.storagePath = TEST_ROOT_DIR;
    downloadData.hidden = 0;
    downloadData.dateTrashed = 0;
    downloadData.subtype = 0;
    
    PhotosDto photosDto;
    
    int32_t result = CloudMediaAttachmentUtils::GetThumbnail("thumbnail", downloadData, photosDto);
    
    EXPECT_EQ(result, E_OK);
    EXPECT_FALSE(photosDto.attachment.empty());
    
    auto it = photosDto.attachment.find("thumbnail");
    EXPECT_NE(it, photosDto.attachment.end());
    
    DeleteTestFile(testPath);
    DeleteTestFile(thumbPath);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetThumbnail_Rotation180_Success, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetThumbnail_Rotation180_Success test start");
    std::string testPath = ROOT_MEDIA_DIR + "test_photo_008.jpg";
    CreateTestFile(testPath, "test content 008");
    
    std::string thumbPath = TEST_THUMB_DIR + "test_photo_008/THM_EX/THM.jpg";
    CreateTestDirectory(TEST_THUMB_DIR + "test_photo_008/THM_EX/");
    CreateTestFile(thumbPath, "thumbnail content rotation 180");
    
    DownloadAssetData downloadData;
    downloadData.fileId = 1008;
    downloadData.cloudId = "test_cloud_id_008";
    downloadData.fileSize = 1024;
    downloadData.mediaType = 1;
    downloadData.originalCloudId = "test_original_cloud_id_008";
    downloadData.path = testPath;
    downloadData.editTime = 0;
    downloadData.effectMode = 0;
    downloadData.orientation = 180;
    downloadData.fileSourceType = 0;
    downloadData.storagePath = TEST_ROOT_DIR;
    downloadData.hidden = 0;
    downloadData.dateTrashed = 0;
    downloadData.subtype = 0;
    
    PhotosDto photosDto;
    
    int32_t result = CloudMediaAttachmentUtils::GetThumbnail("thumbnail", downloadData, photosDto);
    
    EXPECT_EQ(result, E_OK);
    EXPECT_FALSE(photosDto.attachment.empty());
    
    auto it = photosDto.attachment.find("thumbnail");
    EXPECT_NE(it, photosDto.attachment.end());
    
    DeleteTestFile(testPath);
    DeleteTestFile(thumbPath);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetThumbnail_Rotation270_Success, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetThumbnail_Rotation270_Success test start");
    std::string testPath = ROOT_MEDIA_DIR + "test_photo_009.jpg";
    CreateTestFile(testPath, "test content 009");
    
    std::string thumbPath = TEST_THUMB_DIR + "test_photo_009/THM_EX/THM.jpg";
    CreateTestDirectory(TEST_THUMB_DIR + "test_photo_009/THM_EX/");
    CreateTestFile(thumbPath, "thumbnail content rotation 270");
    
    DownloadAssetData downloadData;
    downloadData.fileId = 1009;
    downloadData.cloudId = "test_cloud_id_009";
    downloadData.fileSize = 1024;
    downloadData.mediaType = 1;
    downloadData.originalCloudId = "test_original_cloud_id_009";
    downloadData.path = testPath;
    downloadData.editTime = 0;
    downloadData.effectMode = 0;
    downloadData.orientation = 270;
    downloadData.fileSourceType = 0;
    downloadData.storagePath = TEST_ROOT_DIR;
    downloadData.hidden = 0;
    downloadData.dateTrashed = 0;
    downloadData.subtype = 0;
    
    PhotosDto photosDto;
    
    int32_t result = CloudMediaAttachmentUtils::GetThumbnail("thumbnail", downloadData, photosDto);
    
    EXPECT_EQ(result, E_OK);
    EXPECT_FALSE(photosDto.attachment.empty());
    
    auto it = photosDto.attachment.find("thumbnail");
    EXPECT_NE(it, photosDto.attachment.end());
    
    DeleteTestFile(testPath);
    DeleteTestFile(thumbPath);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetLcdThumbnail_Rotation0_Success, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetLcdThumbnail_Rotation0_Success test start");
    std::string testPath = ROOT_MEDIA_DIR + "test_photo_010.jpg";
    CreateTestFile(testPath, "test content 010");
    
    std::string lcdPath = TEST_THUMB_DIR + "test_photo_010/LCD.jpg";
    CreateTestDirectory(TEST_THUMB_DIR + "test_photo_010/");
    CreateTestFile(lcdPath, "lcd content rotation 0");
    
    DownloadAssetData downloadData;
    downloadData.fileId = 1010;
    downloadData.cloudId = "test_cloud_id_010";
    downloadData.fileSize = 1024;
    downloadData.mediaType = 1;
    downloadData.originalCloudId = "test_original_cloud_id_010";
    downloadData.path = testPath;
    downloadData.editTime = 0;
    downloadData.effectMode = 0;
    downloadData.orientation = 0;
    downloadData.fileSourceType = 0;
    downloadData.storagePath = TEST_ROOT_DIR;
    downloadData.hidden = 0;
    downloadData.dateTrashed = 0;
    downloadData.subtype = 0;
    
    PhotosDto photosDto;
    
    int32_t result = CloudMediaAttachmentUtils::GetLcdThumbnail("lcd", downloadData, photosDto);
    
    EXPECT_EQ(result, E_OK);
    EXPECT_FALSE(photosDto.attachment.empty());
    
    auto it = photosDto.attachment.find("lcd");
    EXPECT_NE(it, photosDto.attachment.end());
    
    DeleteTestFile(testPath);
    DeleteTestFile(lcdPath);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetLcdThumbnail_Rotation90_Success, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetLcdThumbnail_Rotation90_Success test start");
    std::string testPath = ROOT_MEDIA_DIR + "test_photo_011.jpg";
    CreateTestFile(testPath, "test content 011");
    
    std::string lcdPath = TEST_THUMB_DIR + "test_photo_011/THM_EX/LCD.jpg";
    CreateTestDirectory(TEST_THUMB_DIR + "test_photo_011/THM_EX/");
    CreateTestFile(lcdPath, "lcd content rotation 90");
    
    DownloadAssetData downloadData;
    downloadData.fileId = 1011;
    downloadData.cloudId = "test_cloud_id_011";
    downloadData.fileSize = 1024;
    downloadData.mediaType = 1;
    downloadData.originalCloudId = "test_original_cloud_id_011";
    downloadData.path = testPath;
    downloadData.editTime = 0;
    downloadData.effectMode = 0;
    downloadData.orientation = 90;
    downloadData.fileSourceType = 0;
    downloadData.storagePath = TEST_ROOT_DIR;
    downloadData.hidden = 0;
    downloadData.dateTrashed = 0;
    downloadData.subtype = 0;
    
    PhotosDto photosDto;
    
    int32_t result = CloudMediaAttachmentUtils::GetLcdThumbnail("lcd", downloadData, photosDto);
    
    EXPECT_EQ(result, E_OK);
    EXPECT_FALSE(photosDto.attachment.empty());
    
    auto it = photosDto.attachment.find("lcd");
    EXPECT_NE(it, photosDto.attachment.end());
    
    DeleteTestFile(testPath);
    DeleteTestFile(lcdPath);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetLcdThumbnail_Rotation180_Success, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetLcdThumbnail_Rotation180_Success test start");
    std::string testPath = ROOT_MEDIA_DIR + "test_photo_012.jpg";
    CreateTestFile(testPath, "test content 012");
    
    std::string lcdPath = TEST_THUMB_DIR + "test_photo_012/THM_EX/LCD.jpg";
    CreateTestDirectory(TEST_THUMB_DIR + "test_photo_012/THM_EX/");
    CreateTestFile(lcdPath, "lcd content rotation 180");
    
    DownloadAssetData downloadData;
    downloadData.fileId = 1012;
    downloadData.cloudId = "test_cloud_id_012";
    downloadData.fileSize = 1024;
    downloadData.mediaType = 1;
    downloadData.originalCloudId = "test_original_cloud_id_012";
    downloadData.path = testPath;
    downloadData.editTime = 0;
    downloadData.effectMode = 0;
    downloadData.orientation = 180;
    downloadData.fileSourceType = 0;
    downloadData.storagePath = TEST_ROOT_DIR;
    downloadData.hidden = 0;
    downloadData.dateTrashed = 0;
    downloadData.subtype = 0;
    
    PhotosDto photosDto;
    
    int32_t result = CloudMediaAttachmentUtils::GetLcdThumbnail("lcd", downloadData, photosDto);
    
    EXPECT_EQ(result, E_OK);
    EXPECT_FALSE(photosDto.attachment.empty());
    
    auto it = photosDto.attachment.find("lcd");
    EXPECT_NE(it, photosDto.attachment.end());
    
    DeleteTestFile(testPath);
    DeleteTestFile(lcdPath);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetLcdThumbnail_Rotation270_Success, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetLcdThumbnail_Rotation270_Success test start");
    std::string testPath = ROOT_MEDIA_DIR + "test_photo_013.jpg";
    CreateTestFile(testPath, "test content 013");
    
    std::string lcdPath = TEST_THUMB_DIR + "test_photo_013/THM_EX/LCD.jpg";
    CreateTestDirectory(TEST_THUMB_DIR + "test_photo_013/THM_EX/");
    CreateTestFile(lcdPath, "lcd content rotation 270");
    
    DownloadAssetData downloadData;
    downloadData.fileId = 1013;
    downloadData.cloudId = "test_cloud_id_013";
    downloadData.fileSize = 1024;
    downloadData.mediaType = 1;
    downloadData.originalCloudId = "test_original_cloud_id_013";
    downloadData.path = testPath;
    downloadData.editTime = 0;
    downloadData.effectMode = 0;
    downloadData.orientation = 270;
    downloadData.fileSourceType = 0;
    downloadData.storagePath = TEST_ROOT_DIR;
    downloadData.hidden = 0;
    downloadData.dateTrashed = 0;
    downloadData.subtype = 0;
    
    PhotosDto photosDto;
    
    int32_t result = CloudMediaAttachmentUtils::GetLcdThumbnail("lcd", downloadData, photosDto);
    
    EXPECT_EQ(result, E_OK);
    EXPECT_FALSE(photosDto.attachment.empty());
    
    auto it = photosDto.attachment.find("lcd");
    EXPECT_NE(it, photosDto.attachment.end());
    
    DeleteTestFile(testPath);
    DeleteTestFile(lcdPath);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetContent_LargeFileSize_Success, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetContent_LargeFileSize_Success test start");
    std::string testPath = TEST_ROOT_DIR + "test_photo_017.jpg";
    CreateTestFile(testPath, "test content 017");
    
    DownloadAssetData downloadData;
    downloadData.fileId = 1017;
    downloadData.cloudId = "test_cloud_id_017";
    downloadData.fileSize = 1024 * 1024 * 10;
    downloadData.mediaType = 1;
    downloadData.originalCloudId = "test_original_cloud_id_017";
    downloadData.path = testPath;
    downloadData.editTime = 0;
    downloadData.effectMode = 0;
    downloadData.orientation = 0;
    downloadData.fileSourceType = 0;
    downloadData.storagePath = TEST_ROOT_DIR;
    downloadData.hidden = 0;
    downloadData.dateTrashed = 0;
    downloadData.subtype = 0;
    
    PhotosDto photosDto;
    
    int32_t result = CloudMediaAttachmentUtils::GetAttachment("content", downloadData, photosDto);
    
    EXPECT_EQ(result, E_OK);
    EXPECT_FALSE(photosDto.attachment.empty());
    
    auto it = photosDto.attachment.find("content");
    EXPECT_NE(it, photosDto.attachment.end());
    if (it != photosDto.attachment.end()) {
        EXPECT_EQ(it->second.size, 1024 * 1024 * 10);
    }
    
    DeleteTestFile(testPath);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetContent_ZeroFileSize_Success, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetContent_ZeroFileSize_Success test start");
    std::string testPath = TEST_ROOT_DIR + "test_photo_018.jpg";
    CreateTestFile(testPath, "test content 018");
    
    DownloadAssetData downloadData;
    downloadData.fileId = 1018;
    downloadData.cloudId = "test_cloud_id_018";
    downloadData.fileSize = 0;
    downloadData.mediaType = 1;
    downloadData.originalCloudId = "test_original_cloud_id_018";
    downloadData.path = testPath;
    downloadData.editTime = 0;
    downloadData.effectMode = 0;
    downloadData.orientation = 0;
    downloadData.fileSourceType = 0;
    downloadData.storagePath = TEST_ROOT_DIR;
    downloadData.hidden = 0;
    downloadData.dateTrashed = 0;
    downloadData.subtype = 0;
    
    PhotosDto photosDto;
    
    int32_t result = CloudMediaAttachmentUtils::GetAttachment("content", downloadData, photosDto);
    
    EXPECT_EQ(result, E_OK);
    EXPECT_FALSE(photosDto.attachment.empty());
    
    auto it = photosDto.attachment.find("content");
    EXPECT_NE(it, photosDto.attachment.end());
    if (it != photosDto.attachment.end()) {
        EXPECT_EQ(it->second.size, 0);
    }
    
    DeleteTestFile(testPath);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetContent_NegativeFileSize_Success, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetContent_NegativeFileSize_Success test start");
    std::string testPath = TEST_ROOT_DIR + "test_photo_019.jpg";
    CreateTestFile(testPath, "test content 019");
    
    DownloadAssetData downloadData;
    downloadData.fileId = 1019;
    downloadData.cloudId = "test_cloud_id_019";
    downloadData.fileSize = -1;
    downloadData.mediaType = 1;
    downloadData.originalCloudId = "test_original_cloud_id_019";
    downloadData.path = testPath;
    downloadData.editTime = 0;
    downloadData.effectMode = 0;
    downloadData.orientation = 0;
    downloadData.fileSourceType = 0;
    downloadData.storagePath = TEST_ROOT_DIR;
    downloadData.hidden = 0;
    downloadData.dateTrashed = 0;
    downloadData.subtype = 0;
    
    PhotosDto photosDto;
    
    int32_t result = CloudMediaAttachmentUtils::GetAttachment("content", downloadData, photosDto);
    
    EXPECT_EQ(result, E_OK);
    EXPECT_FALSE(photosDto.attachment.empty());
    
    auto it = photosDto.attachment.find("content");
    EXPECT_NE(it, photosDto.attachment.end());
    
    DeleteTestFile(testPath);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetThumbnail_VariousOrientations_Success, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetThumbnail_VariousOrientations_Success test start");
    std::string testPath = ROOT_MEDIA_DIR + "test_photo_023.jpg";
    CreateTestFile(testPath, "test content 023");
    
    std::vector<int32_t> orientations = {0, 90, 180, 270, 360, -90, -180};
    for (size_t i = 0; i < orientations.size(); i++) {
        std::string thumbDir = TEST_THUMB_DIR + "test_photo_023/";
        CreateTestDirectory(thumbDir);
        std::string thumbPath = thumbDir + "THM.jpg";
        CreateTestFile(thumbPath, "thumbnail content");
        
        DownloadAssetData downloadData;
        downloadData.fileId = 1049 + i;
        downloadData.cloudId = "test_cloud_id_023_" + std::to_string(i);
        downloadData.fileSize = 1024;
        downloadData.mediaType = 1;
        downloadData.originalCloudId = "test_original_cloud_id_023_" + std::to_string(i);
        downloadData.path = testPath;
        downloadData.editTime = 0;
        downloadData.effectMode = 0;
        downloadData.orientation = orientations[i];
        downloadData.fileSourceType = 0;
        downloadData.storagePath = TEST_ROOT_DIR;
        downloadData.hidden = 0;
        downloadData.dateTrashed = 0;
        downloadData.subtype = 0;
        
        PhotosDto photosDto;
        
        int32_t result = CloudMediaAttachmentUtils::GetThumbnail("thumbnail", downloadData, photosDto);
        
        EXPECT_EQ(result, E_OK);
        EXPECT_FALSE(photosDto.attachment.empty());
        
        DeleteTestFile(thumbPath);
    }
    
    DeleteTestFile(testPath);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetLcdThumbnail_VariousOrientations_Success, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetLcdThumbnail_VariousOrientations_Success test start");
    std::string testPath = ROOT_MEDIA_DIR + "test_photo_024.jpg";
    CreateTestFile(testPath, "test content 024");
    
    std::vector<int32_t> orientations = {0, 90, 180, 270, 360, -90, -180};
    for (size_t i = 0; i < orientations.size(); i++) {
        std::string lcdDir = TEST_THUMB_DIR + "test_photo_024/";
        CreateTestDirectory(lcdDir);
        std::string lcdPath = lcdDir + "LCD.jpg";
        CreateTestFile(lcdPath, "lcd content");
        
        DownloadAssetData downloadData;
        downloadData.fileId = 1056 + i;
        downloadData.cloudId = "test_cloud_id_024_" + std::to_string(i);
        downloadData.fileSize = 1024;
        downloadData.mediaType = 1;
        downloadData.originalCloudId = "test_original_cloud_id_024_" + std::to_string(i);
        downloadData.path = testPath;
        downloadData.editTime = 0;
        downloadData.effectMode = 0;
        downloadData.orientation = orientations[i];
        downloadData.fileSourceType = 0;
        downloadData.storagePath = TEST_ROOT_DIR;
        downloadData.hidden = 0;
        downloadData.dateTrashed = 0;
        downloadData.subtype = 0;
        
        PhotosDto photosDto;
        
        int32_t result = CloudMediaAttachmentUtils::GetLcdThumbnail("lcd", downloadData, photosDto);
        
        EXPECT_EQ(result, E_OK);
        EXPECT_FALSE(photosDto.attachment.empty());
        
        DeleteTestFile(lcdPath);
    }
    
    DeleteTestFile(testPath);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetAttachment_MultipleCalls_SameDto, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAttachment_MultipleCalls_SameDto test start");
    std::string testPath = TEST_ROOT_DIR + "test_photo_025.jpg";
    CreateTestFile(testPath, "test content 025");
    
    DownloadAssetData downloadData;
    downloadData.fileId = 1063;
    downloadData.cloudId = "test_cloud_id_025";
    downloadData.fileSize = 2048;
    downloadData.mediaType = 1;
    downloadData.originalCloudId = "test_original_cloud_id_025";
    downloadData.path = testPath;
    downloadData.editTime = 0;
    downloadData.effectMode = 0;
    downloadData.orientation = 0;
    downloadData.fileSourceType = 0;
    downloadData.storagePath = TEST_ROOT_DIR;
    downloadData.hidden = 0;
    downloadData.dateTrashed = 0;
    downloadData.subtype = 0;
    
    PhotosDto photosDto;
    
    int32_t result1 = CloudMediaAttachmentUtils::GetAttachment("content", downloadData, photosDto);
    EXPECT_EQ(result1, E_OK);
    
    PhotosDto photosDto2;
    int32_t result2 = CloudMediaAttachmentUtils::GetAttachment("content", downloadData, photosDto2);
    EXPECT_EQ(result2, E_OK);
    
    EXPECT_EQ(photosDto.attachment.size(), photosDto2.attachment.size());
    
    DeleteTestFile(testPath);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetAttachment_VariousMediaTypes_Success, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAttachment_VariousMediaTypes_Success test start");
    std::string testPath = TEST_ROOT_DIR + "test_photo_026.jpg";
    CreateTestFile(testPath, "test content 026");
    
    for (int32_t mediaType = 0; mediaType <= 5; mediaType++) {
        DownloadAssetData downloadData;
        downloadData.fileId = 1064 + mediaType;
        downloadData.cloudId = "test_cloud_id_026_" + std::to_string(mediaType);
        downloadData.fileSize = 2048;
        downloadData.mediaType = mediaType;
        downloadData.originalCloudId = "test_original_cloud_id_026_" + std::to_string(mediaType);
        downloadData.path = testPath;
        downloadData.editTime = 0;
        downloadData.effectMode = 0;
        downloadData.orientation = 0;
        downloadData.fileSourceType = 0;
        downloadData.storagePath = TEST_ROOT_DIR;
        downloadData.hidden = 0;
        downloadData.dateTrashed = 0;
        downloadData.subtype = 0;
        
        PhotosDto photosDto;
        
        int32_t result = CloudMediaAttachmentUtils::GetAttachment("content", downloadData, photosDto);
        
        EXPECT_EQ(result, E_OK);
        EXPECT_FALSE(photosDto.attachment.empty());
    }
    
    DeleteTestFile(testPath);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetAttachment_VariousFileSourceTypes_Success, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAttachment_VariousFileSourceTypes_Success test start");
    std::string testPath = TEST_ROOT_DIR + "test_photo_027.jpg";
    CreateTestFile(testPath, "test content 027");
    
    for (int32_t fileSourceType = 0; fileSourceType <= 3; fileSourceType++) {
        DownloadAssetData downloadData;
        downloadData.fileId = 1070 + fileSourceType;
        downloadData.cloudId = "test_cloud_id_027_" + std::to_string(fileSourceType);
        downloadData.fileSize = 2048;
        downloadData.mediaType = 1;
        downloadData.originalCloudId = "test_original_cloud_id_027_" + std::to_string(fileSourceType);
        downloadData.path = testPath;
        downloadData.editTime = 0;
        downloadData.effectMode = 0;
        downloadData.orientation = 0;
        downloadData.fileSourceType = fileSourceType;
        downloadData.storagePath = TEST_ROOT_DIR;
        downloadData.hidden = 0;
        downloadData.dateTrashed = 0;
        downloadData.subtype = 0;
        
        PhotosDto photosDto;
        
        int32_t result = CloudMediaAttachmentUtils::GetAttachment("content", downloadData, photosDto);
        
        EXPECT_EQ(result, E_OK);
        EXPECT_FALSE(photosDto.attachment.empty());
    }
    
    DeleteTestFile(testPath);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetAttachment_VariousHiddenStates_Success, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAttachment_VariousHiddenStates_Success test start");
    std::string testPath = TEST_ROOT_DIR + "test_photo_028.jpg";
    CreateTestFile(testPath, "test content 028");
    
    for (int32_t hidden = 0; hidden <= 1; hidden++) {
        DownloadAssetData downloadData;
        downloadData.fileId = 1074 + hidden;
        downloadData.cloudId = "test_cloud_id_028_" + std::to_string(hidden);
        downloadData.fileSize = 2048;
        downloadData.mediaType = 1;
        downloadData.originalCloudId = "test_original_cloud_id_028_" + std::to_string(hidden);
        downloadData.path = testPath;
        downloadData.editTime = 0;
        downloadData.effectMode = 0;
        downloadData.orientation = 0;
        downloadData.fileSourceType = 0;
        downloadData.storagePath = TEST_ROOT_DIR;
        downloadData.hidden = hidden;
        downloadData.dateTrashed = 0;
        downloadData.subtype = 0;
        
        PhotosDto photosDto;
        
        int32_t result = CloudMediaAttachmentUtils::GetAttachment("content", downloadData, photosDto);
        
        EXPECT_EQ(result, E_OK);
        EXPECT_FALSE(photosDto.attachment.empty());
    }
    
    DeleteTestFile(testPath);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetAttachment_VariousDateTrashed_Success, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAttachment_VariousDateTrashed_Success test start");
    std::string testPath = TEST_ROOT_DIR + "test_photo_029.jpg";
    CreateTestFile(testPath, "test content 029");
    
    std::vector<int64_t> dateTrashedValues = {0, 1, 1000000, 9999999999};
    for (size_t i = 0; i < dateTrashedValues.size(); i++) {
        DownloadAssetData downloadData;
        downloadData.fileId = 1076 + i;
        downloadData.cloudId = "test_cloud_id_029_" + std::to_string(i);
        downloadData.fileSize = 2048;
        downloadData.mediaType = 1;
        downloadData.originalCloudId = "test_original_cloud_id_029_" + std::to_string(i);
        downloadData.path = testPath;
        downloadData.editTime = 0;
        downloadData.effectMode = 0;
        downloadData.orientation = 0;
        downloadData.fileSourceType = 0;
        downloadData.storagePath = TEST_ROOT_DIR;
        downloadData.hidden = 0;
        downloadData.dateTrashed = dateTrashedValues[i];
        downloadData.subtype = 0;
        
        PhotosDto photosDto;
        
        int32_t result = CloudMediaAttachmentUtils::GetAttachment("content", downloadData, photosDto);
        
        EXPECT_EQ(result, E_OK);
        EXPECT_FALSE(photosDto.attachment.empty());
    }
    
    DeleteTestFile(testPath);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetThumbnail_ComplexScenario_Success, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetThumbnail_ComplexScenario_Success test start");
    std::string testPath = ROOT_MEDIA_DIR + "test_photo_032.jpg";
    CreateTestFile(testPath, "test content 032");
    
    std::string thumbDir = TEST_THUMB_DIR + "test_photo_032/THM_EX/";
    CreateTestDirectory(thumbDir);
    std::string thumbPath = thumbDir + "THM.jpg";
    CreateTestFile(thumbPath, "thumbnail content complex");
    
    DownloadAssetData downloadData;
    downloadData.fileId = 1082;
    downloadData.cloudId = "test_cloud_id_032";
    downloadData.fileSize = 1024 * 1024 * 3;
    downloadData.mediaType = 1;
    downloadData.originalCloudId = "test_original_cloud_id_032";
    downloadData.path = testPath;
    downloadData.editTime = 555555;
    downloadData.effectMode = 3;
    downloadData.orientation = 180;
    downloadData.fileSourceType = 1;
    downloadData.storagePath = TEST_ROOT_DIR;
    downloadData.hidden = 0;
    downloadData.dateTrashed = 0;
    downloadData.subtype = 1;
    
    PhotosDto photosDto;
    int32_t result = CloudMediaAttachmentUtils::GetThumbnail("thumbnail", downloadData, photosDto);
    
    EXPECT_EQ(result, E_OK);
    EXPECT_FALSE(photosDto.attachment.empty());
    
    auto it = photosDto.attachment.find("thumbnail");
    EXPECT_NE(it, photosDto.attachment.end());
    
    DeleteTestFile(testPath);
    DeleteTestFile(thumbPath);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetLcdThumbnail_ComplexScenario_Success, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetLcdThumbnail_ComplexScenario_Success test start");
    std::string testPath = ROOT_MEDIA_DIR + "test_photo_033.jpg";
    CreateTestFile(testPath, "test content 033");
    
    std::string lcdDir = TEST_THUMB_DIR + "test_photo_033/THM_EX/";
    CreateTestDirectory(lcdDir);
    std::string lcdPath = lcdDir + "LCD.jpg";
    CreateTestFile(lcdPath, "lcd content complex");
    
    DownloadAssetData downloadData;
    downloadData.fileId = 1083;
    downloadData.cloudId = "test_cloud_id_033";
    downloadData.fileSize = 1024 * 1024 * 8;
    downloadData.mediaType = 2;
    downloadData.originalCloudId = "test_original_cloud_id_033";
    downloadData.path = testPath;
    downloadData.editTime = 777777;
    downloadData.effectMode = 4;
    downloadData.orientation = 90;
    downloadData.fileSourceType = 2;
    downloadData.storagePath = TEST_ROOT_DIR;
    downloadData.hidden = 0;
    downloadData.dateTrashed = 0;
    downloadData.subtype = 2;
    
    PhotosDto photosDto;
    int32_t result = CloudMediaAttachmentUtils::GetLcdThumbnail("lcd", downloadData, photosDto);
    
    EXPECT_EQ(result, E_OK);
    EXPECT_FALSE(photosDto.attachment.empty());
    
    auto it = photosDto.attachment.find("lcd");
    EXPECT_NE(it, photosDto.attachment.end());
    
    DeleteTestFile(testPath);
    DeleteTestFile(lcdPath);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetAttachment_EdgeCase_EmptyPath, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAttachment_EdgeCase_EmptyPath test start");
    DownloadAssetData downloadData;
    downloadData.fileId = 1084;
    downloadData.cloudId = "test_cloud_id_034";
    downloadData.fileSize = 1024;
    downloadData.mediaType = 1;
    downloadData.originalCloudId = "test_original_cloud_id_034";
    downloadData.path = "";
    downloadData.editTime = 0;
    downloadData.effectMode = 0;
    downloadData.orientation = 0;
    downloadData.fileSourceType = 0;
    downloadData.storagePath = TEST_ROOT_DIR;
    downloadData.hidden = 0;
    downloadData.dateTrashed = 0;
    downloadData.subtype = 0;
    
    PhotosDto photosDto;
    
    int32_t result = CloudMediaAttachmentUtils::GetAttachment("content", downloadData, photosDto);
    
    EXPECT_EQ(result, E_ERR);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetAttachment_EdgeCase_SpecialCharactersInPath, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAttachment_EdgeCase_SpecialCharactersInPath test start");
    std::string testPath = TEST_ROOT_DIR + "test_photo_034.jpg";
    CreateTestFile(testPath, "test content 034");
    
    std::string specialPath = TEST_ROOT_DIR + "test_photo_034_special.jpg";
    CreateTestFile(specialPath, "test content special");
    
    DownloadAssetData downloadData;
    downloadData.fileId = 1085;
    downloadData.cloudId = "test_cloud_id_035";
    downloadData.fileSize = 2048;
    downloadData.mediaType = 1;
    downloadData.originalCloudId = "test_original_cloud_id_035";
    downloadData.path = specialPath;
    downloadData.editTime = 0;
    downloadData.effectMode = 0;
    downloadData.orientation = 0;
    downloadData.fileSourceType = 0;
    downloadData.storagePath = TEST_ROOT_DIR;
    downloadData.hidden = 0;
    downloadData.dateTrashed = 0;
    downloadData.subtype = 0;
    
    PhotosDto photosDto;
    
    int32_t result = CloudMediaAttachmentUtils::GetAttachment("content", downloadData, photosDto);
    
    EXPECT_EQ(result, E_OK);
    
    DeleteTestFile(testPath);
    DeleteTestFile(specialPath);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetAttachment_EdgeCase_VeryLongPath, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAttachment_EdgeCase_VeryLongPath test start");
    std::string longPath = TEST_ROOT_DIR;
    for (int i = 0; i < 10; i++) {
        longPath += "subdir_" + std::to_string(i) + "/";
        CreateTestDirectory(longPath);
    }
    longPath += "test_photo_035.jpg";
    CreateTestFile(longPath, "test content long path");
    
    DownloadAssetData downloadData;
    downloadData.fileId = 1086;
    downloadData.cloudId = "test_cloud_id_036";
    downloadData.fileSize = 2048;
    downloadData.mediaType = 1;
    downloadData.originalCloudId = "test_original_cloud_id_036";
    downloadData.path = longPath;
    downloadData.editTime = 0;
    downloadData.effectMode = 0;
    downloadData.orientation = 0;
    downloadData.fileSourceType = 0;
    downloadData.storagePath = TEST_ROOT_DIR;
    downloadData.hidden = 0;
    downloadData.dateTrashed = 0;
    downloadData.subtype = 0;
    
    PhotosDto photosDto;
    
    int32_t result = CloudMediaAttachmentUtils::GetAttachment("content", downloadData, photosDto);
    
    EXPECT_EQ(result, E_OK);
    
    DeleteTestFile(longPath);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetAttachment_EdgeCase_VeryShortPath, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAttachment_EdgeCase_VeryShortPath test start");
    std::string shortPath = "/tmp/a.jpg";
    CreateTestFile(shortPath, "test content short");
    
    DownloadAssetData downloadData;
    downloadData.fileId = 1087;
    downloadData.cloudId = "test_cloud_id_037";
    downloadData.fileSize = 2048;
    downloadData.mediaType = 1;
    downloadData.originalCloudId = "test_original_cloud_id_037";
    downloadData.path = shortPath;
    downloadData.editTime = 0;
    downloadData.effectMode = 0;
    downloadData.orientation = 0;
    downloadData.fileSourceType = 0;
    downloadData.storagePath = TEST_ROOT_DIR;
    downloadData.hidden = 0;
    downloadData.dateTrashed = 0;
    downloadData.subtype = 0;
    
    PhotosDto photosDto;
    
    int32_t result = CloudMediaAttachmentUtils::GetAttachment("content", downloadData, photosDto);
    
    EXPECT_EQ(result, E_OK);
    
    DeleteTestFile(shortPath);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetAttachment_EdgeCase_MinEditTime, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAttachment_EdgeCase_MinEditTime test start");
    std::string testPath = TEST_ROOT_DIR + "test_photo_037.jpg";
    CreateTestFile(testPath, "test content 037");
    
    DownloadAssetData downloadData;
    downloadData.fileId = 1089;
    downloadData.cloudId = "test_cloud_id_039";
    downloadData.fileSize = 2048;
    downloadData.mediaType = 1;
    downloadData.originalCloudId = "test_original_cloud_id_039";
    downloadData.path = testPath;
    downloadData.editTime = INT64_MIN;
    downloadData.effectMode = 1;
    downloadData.orientation = 0;
    downloadData.fileSourceType = 0;
    downloadData.storagePath = TEST_ROOT_DIR;
    downloadData.hidden = 0;
    downloadData.dateTrashed = 0;
    downloadData.subtype = 1;
    
    PhotosDto photosDto;
    
    int32_t result = CloudMediaAttachmentUtils::GetAttachment("content", downloadData, photosDto);
    
    EXPECT_EQ(result, E_OK);
    
    DeleteTestFile(testPath);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetAttachment_EdgeCase_MaxOrientation, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAttachment_EdgeCase_MaxOrientation test start");
    std::string testPath = ROOT_MEDIA_DIR + "test_photo_038.jpg";
    CreateTestFile(testPath, "test content 038");
    
    std::string thumbDir = TEST_THUMB_DIR + "test_photo_038/";
    CreateTestDirectory(thumbDir);
    std::string thumbPath = thumbDir + "THM.jpg";
    CreateTestFile(thumbPath, "thumbnail content max orientation");
    
    DownloadAssetData downloadData;
    downloadData.fileId = 1090;
    downloadData.cloudId = "test_cloud_id_040";
    downloadData.fileSize = 1024;
    downloadData.mediaType = 1;
    downloadData.originalCloudId = "test_original_cloud_id_040";
    downloadData.path = testPath;
    downloadData.editTime = 0;
    downloadData.effectMode = 0;
    downloadData.orientation = INT32_MAX;
    downloadData.fileSourceType = 0;
    downloadData.storagePath = TEST_ROOT_DIR;
    downloadData.hidden = 0;
    downloadData.dateTrashed = 0;
    downloadData.subtype = 0;
    
    PhotosDto photosDto;
    
    int32_t result = CloudMediaAttachmentUtils::GetThumbnail("thumbnail", downloadData, photosDto);
    
    EXPECT_EQ(result, E_OK);
    
    DeleteTestFile(testPath);
    DeleteTestFile(thumbPath);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetAttachment_EdgeCase_MinOrientation, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetAttachment_EdgeCase_MinOrientation test start");
    std::string testPath = ROOT_MEDIA_DIR + "test_photo_039.jpg";
    CreateTestFile(testPath, "test content 039");
    
    std::string thumbDir = TEST_THUMB_DIR + "test_photo_039/";
    CreateTestDirectory(thumbDir);
    std::string thumbPath = thumbDir + "THM.jpg";
    CreateTestFile(thumbPath, "thumbnail content min orientation");
    
    DownloadAssetData downloadData;
    downloadData.fileId = 1091;
    downloadData.cloudId = "test_cloud_id_041";
    downloadData.fileSize = 1024;
    downloadData.mediaType = 1;
    downloadData.originalCloudId = "test_original_cloud_id_041";
    downloadData.path = testPath;
    downloadData.editTime = 0;
    downloadData.effectMode = 0;
    downloadData.orientation = INT32_MIN;
    downloadData.fileSourceType = 0;
    downloadData.storagePath = TEST_ROOT_DIR;
    downloadData.hidden = 0;
    downloadData.dateTrashed = 0;
    downloadData.subtype = 0;
    
    PhotosDto photosDto;
    
    int32_t result = CloudMediaAttachmentUtils::GetThumbnail("thumbnail", downloadData, photosDto);
    
    EXPECT_EQ(result, E_OK);
    
    DeleteTestFile(testPath);
    DeleteTestFile(thumbPath);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetThumbnail_StressTest_RapidCalls, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetThumbnail_StressTest_RapidCalls test start");
    std::string testPath = ROOT_MEDIA_DIR + "test_photo_042.jpg";
    CreateTestFile(testPath, "test content 042");
    
    std::string thumbDir = TEST_THUMB_DIR + "test_photo_042/";
    CreateTestDirectory(thumbDir);
    std::string thumbPath = thumbDir + "THM.jpg";
    CreateTestFile(thumbPath, "thumbnail content stress");
    
    for (int i = 0; i < 50; i++) {
        DownloadAssetData downloadData;
        downloadData.fileId = 1242 + i;
        downloadData.cloudId = "test_cloud_id_044_" + std::to_string(i);
        downloadData.fileSize = 1024;
        downloadData.mediaType = 1;
        downloadData.originalCloudId = "test_original_cloud_id_044_" + std::to_string(i);
        downloadData.path = testPath;
        downloadData.editTime = 0;
        downloadData.effectMode = 0;
        downloadData.orientation = i % 4;
        downloadData.fileSourceType = 0;
        downloadData.storagePath = TEST_ROOT_DIR;
        downloadData.hidden = 0;
        downloadData.dateTrashed = 0;
        downloadData.subtype = 0;
        
        PhotosDto photosDto;
        
        int32_t result = CloudMediaAttachmentUtils::GetThumbnail("thumbnail", downloadData, photosDto);
        
        EXPECT_EQ(result, E_OK);
        EXPECT_FALSE(photosDto.attachment.empty());
    }
    
    DeleteTestFile(testPath);
    DeleteTestFile(thumbPath);
}

HWTEST_F(CloudMediaAttachmentUtilsTest, GetLcdThumbnail_StressTest_RapidCalls, TestSize.Level1)
{
    MEDIA_INFO_LOG("GetLcdThumbnail_StressTest_RapidCalls test start");
    std::string testPath = ROOT_MEDIA_DIR + "test_photo_043.jpg";
    CreateTestFile(testPath, "test content 043");
    
    std::string lcdDir = TEST_THUMB_DIR + "test_photo_043/";
    CreateTestDirectory(lcdDir);
    std::string lcdPath = lcdDir + "LCD.jpg";
    CreateTestFile(lcdPath, "lcd content stress");
    
    for (int i = 0; i < 50; i++) {
        DownloadAssetData downloadData;
        downloadData.fileId = 1292 + i;
        downloadData.cloudId = "test_cloud_id_045_" + std::to_string(i);
        downloadData.fileSize = 1024;
        downloadData.mediaType = 1;
        downloadData.originalCloudId = "test_original_cloud_id_045_" + std::to_string(i);
        downloadData.path = testPath;
        downloadData.editTime = 0;
        downloadData.effectMode = 0;
        downloadData.orientation = i % 4;
        downloadData.fileSourceType = 0;
        downloadData.storagePath = TEST_ROOT_DIR;
        downloadData.hidden = 0;
        downloadData.dateTrashed = 0;
        downloadData.subtype = 0;
        
        PhotosDto photosDto;
        
        int32_t result = CloudMediaAttachmentUtils::GetLcdThumbnail("lcd", downloadData, photosDto);
        
        EXPECT_EQ(result, E_OK);
        EXPECT_FALSE(photosDto.attachment.empty());
    }
    
    DeleteTestFile(testPath);
    DeleteTestFile(lcdPath);
}
}  // namespace CloudSync
}  // namespace Media
}  // namespace OHOS
