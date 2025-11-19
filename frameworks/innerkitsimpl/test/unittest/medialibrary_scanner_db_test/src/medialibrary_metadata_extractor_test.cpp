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
#include <cstdint>

#include "image_source.h"
#include "medialibrary_errno.h"
#include "medialibrary_scanner_db_test.h"
#include "media_exif.h"
#include "media_scanner_db.h"
#include "userfile_manager_types.h"
#define private public
#include "metadata_extractor.h"
#include "meta.h"
#include "meta_key.h"
#undef private

using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {
HWTEST_F(MediaLibraryScannerDbTest, medialib_Extract_test_001, TestSize.Level1)
{
    unique_ptr<Metadata> data = make_unique<Metadata>();
    unique_ptr<MediaScannerDb> mediaScannerDb;
    string path = "/storage/cloud/files/";
    mediaScannerDb->GetFileBasicInfo(path, data);
    data->SetFileMediaType(static_cast<MediaType>(MEDIA_TYPE_ALBUM));
    int32_t ret = MetadataExtractor::Extract(data);
    EXPECT_EQ(ret, E_AVMETADATA);
}

HWTEST_F(MediaLibraryScannerDbTest, medialib_Extract_test_002, TestSize.Level1)
{
    unique_ptr<Metadata> data = make_unique<Metadata>();
    unique_ptr<MediaScannerDb> mediaScannerDb;
    string path = "/storage/cloud/files/";
    mediaScannerDb->GetFileBasicInfo(path, data);
    data->SetFileMediaType(static_cast<MediaType>(MEDIA_TYPE_DEVICE));
    int32_t ret = MetadataExtractor::Extract(data);
    EXPECT_EQ(ret, E_AVMETADATA);
}

HWTEST_F(MediaLibraryScannerDbTest, medialib_Extract_empty_path, TestSize.Level1)
{
    unique_ptr<Metadata> data = make_unique<Metadata>();
    unique_ptr<MediaScannerDb> mediaScannerDb;
    string path;
    mediaScannerDb->GetFileBasicInfo(path, data);
    data->SetFileMediaType(static_cast<MediaType>(MEDIA_TYPE_IMAGE));
    data->SetPhotoSubType(static_cast<int32_t>(PhotoSubType::MOVING_PHOTO));
    // empty path Extract will return E_IMAGE
    int32_t ret = MetadataExtractor::Extract(data);
    EXPECT_EQ(ret, E_IMAGE);
}

HWTEST_F(MediaLibraryScannerDbTest, medialib_ExtractAVMetadata_empty_path, TestSize.Level1)
{
    unique_ptr<Metadata> data = make_unique<Metadata>();
    unique_ptr<MediaScannerDb> mediaScannerDb;
    string path = "/storage/cloud/files/";
    mediaScannerDb->GetFileBasicInfo(path, data);
    data->SetFileMediaType(static_cast<MediaType>(MEDIA_TYPE_DEVICE));
    data->SetFilePath("");
    // empty path ExtractAVMetadata will return E_AVMETADATA
    int32_t ret = MetadataExtractor::ExtractAVMetadata(data);
    EXPECT_EQ(ret, E_AVMETADATA);
}

HWTEST_F(MediaLibraryScannerDbTest, medialib_ExtractAVMetadata_normal_path, TestSize.Level1)
{
    unique_ptr<Metadata> data = make_unique<Metadata>();
    unique_ptr<MediaScannerDb> mediaScannerDb;
    string path = "/storage/cloud/files/";
    mediaScannerDb->GetFileBasicInfo(path, data);
    data->SetFileMediaType(static_cast<MediaType>(MEDIA_TYPE_DEVICE));
    data->SetFilePath(path);
    int32_t ret = MetadataExtractor::ExtractAVMetadata(data);
    EXPECT_NE(ret, E_OK);
}

HWTEST_F(MediaLibraryScannerDbTest, medialib_ExtractAVMetadata_nonexistent_path, TestSize.Level1)
{
    unique_ptr<Metadata> data = make_unique<Metadata>();
    unique_ptr<MediaScannerDb> mediaScannerDb;
    string path = "/storage/cloud/files/";
    mediaScannerDb->GetFileBasicInfo(path, data);
    data->SetFileMediaType(static_cast<MediaType>(MEDIA_TYPE_DEVICE));
    data->SetFilePath("ExtractAVMetadata");
    int32_t ret = MetadataExtractor::ExtractAVMetadata(data);
    EXPECT_EQ(ret, E_SYSCALL);
}

HWTEST_F(MediaLibraryScannerDbTest, medialib_ExtractAVMetadata_clone_test, TestSize.Level1)
{
    unique_ptr<Metadata> data = make_unique<Metadata>();
    unique_ptr<MediaScannerDb> mediaScannerDb;
    string path;
    mediaScannerDb->GetFileBasicInfo(path, data);
    data->SetFileMediaType(static_cast<MediaType>(MEDIA_TYPE_DEVICE));
    data->SetFilePath(path);
    // empty path ExtractAVMetadata will return E_AVMETADATA
    int32_t ret = MetadataExtractor::ExtractAVMetadata(data, Scene::AV_META_SCENE_CLONE);
    EXPECT_EQ(ret, E_AVMETADATA);
}

HWTEST_F(MediaLibraryScannerDbTest, medialib_ExtractImageMetadata_test_001, TestSize.Level1)
{
    unique_ptr<Metadata> data = make_unique<Metadata>();
    unique_ptr<MediaScannerDb> mediaScannerDb;
    string path = "/storage/cloud/files/";
    mediaScannerDb->GetFileBasicInfo(path, data);
    data->SetFileMediaType(static_cast<MediaType>(MEDIA_TYPE_DEVICE));
    data->SetFilePath(path);
    int32_t ret = MetadataExtractor::ExtractImageMetadata(data);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaLibraryScannerDbTest, medialib_ExtractImageMetadata_test_002, TestSize.Level1)
{
    unique_ptr<Metadata> data = make_unique<Metadata>();
    unique_ptr<MediaScannerDb> mediaScannerDb;
    string path = "/storage/cloud/100/files/Documents/CreateImageLcdTest_001.jpg";
    mediaScannerDb->GetFileBasicInfo(path, data);
    data->SetFileMediaType(static_cast<MediaType>(MEDIA_TYPE_IMAGE));
    data->SetFilePath(path);
    int32_t ret = MetadataExtractor::ExtractImageMetadata(data);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(MediaLibraryScannerDbTest, medialib_ExtractImageMetadata_test_003, TestSize.Level1)
{
    unique_ptr<Metadata> metadata = make_unique<Metadata>();
    string path = "/storage/cloud/100/files/Documents/CreateImageLcdTest_001.jpg";
    metadata->SetFileMediaType(MEDIA_TYPE_IMAGE);
    metadata->SetFilePath(path);
    metadata->SetForAdd(false);

    int64_t dateTaken = 1753081131111L;
    metadata->SetDateTaken(dateTaken);
    int64_t dateModified = 1753081131222L;
    metadata->SetFileDateModified(dateModified);
    int32_t ret = MetadataExtractor::ExtractImageMetadata(metadata);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(metadata->GetDateTaken(), dateTaken);

    dateTaken = -1753081131333L;
    metadata->SetDateTaken(dateTaken);
    dateModified = 1753081131444L;
    metadata->SetFileDateModified(dateModified);
    ret = MetadataExtractor::ExtractImageMetadata(metadata);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(metadata->GetDateTaken(), dateModified);
}

HWTEST_F(MediaLibraryScannerDbTest, medialib_ExtractImageMetadata_test_004, TestSize.Level1)
{
    unique_ptr<Metadata> metadata = make_unique<Metadata>();
    string path = "/storage/cloud/100/files/Documents/CreateImageLcdTest_001.jpg";
    metadata->SetFileMediaType(MEDIA_TYPE_IMAGE);
    metadata->SetFilePath(path);
    metadata->SetForAdd(true);

    int64_t dateTaken = 1753081131555L;
    metadata->SetDateTaken(dateTaken);
    int64_t dateModified = 1753081131666L;
    metadata->SetFileDateModified(dateModified);
    int32_t ret = MetadataExtractor::ExtractImageMetadata(metadata);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(metadata->GetDateTaken(), dateTaken);

    dateTaken = -1753081131777L;
    metadata->SetDateTaken(dateTaken);
    dateModified = 1753081131888L;
    metadata->SetFileDateModified(dateModified);
    ret = MetadataExtractor::ExtractImageMetadata(metadata);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(metadata->GetDateTaken(), dateModified);
}

HWTEST_F(MediaLibraryScannerDbTest, medialib_FillExtractedMetadata_test_001, TestSize.Level1)
{
    unique_ptr<Metadata> data = make_unique<Metadata>();
    unique_ptr<MediaScannerDb> mediaScannerDb;
    string path = "/storage/cloud/files/";
    mediaScannerDb->GetFileBasicInfo(path, data);
    data->SetFileMediaType(static_cast<MediaType>(MEDIA_TYPE_DEVICE));
    data->SetFilePath(path);
    data->SetFileDateModified(static_cast<int64_t>(11));
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    unordered_map<int32_t, std::string> resultMap;
    resultMap = {{AV_KEY_ALBUM, ""}, {AV_KEY_ARTIST, ""}, {AV_KEY_DURATION, ""}, {AV_KEY_DATE_TIME_FORMAT, ""},
        {AV_KEY_VIDEO_HEIGHT, ""}, {AV_KEY_VIDEO_WIDTH, ""}, {AV_KEY_MIME_TYPE, ""}, {AV_KEY_MIME_TYPE, ""},
        {AV_KEY_VIDEO_ORIENTATION, ""}, {AV_KEY_VIDEO_IS_HDR_VIVID, ""}, {AV_KEY_TITLE, ""}, {AV_KEY_GENRE, ""},
        {AV_KEY_DATE_TIME_ISO8601, ""}, {AV_KEY_GLTF_OFFSET, ""}};
    MetadataExtractor::FillExtractedMetadata(resultMap, meta, data);
    EXPECT_EQ(data->GetAlbum(), "");
    EXPECT_EQ(data->GetLongitude(), 0);
    EXPECT_EQ(data->GetLatitude(), 0);
}

HWTEST_F(MediaLibraryScannerDbTest, medialib_FillExtractedMetadata_test_002, TestSize.Level1)
{
    unique_ptr<Metadata> data = make_unique<Metadata>();
    unique_ptr<MediaScannerDb> mediaScannerDb;
    string path = "/storage/cloud/files/";
    mediaScannerDb->GetFileBasicInfo(path, data);
    data->SetFileMediaType(static_cast<MediaType>(MEDIA_TYPE_DEVICE));
    data->SetFilePath(path);
    data->SetFileDateModified(static_cast<int64_t>(11));
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    float longtitude = 1.2;
    float latitude = 138.2;
    meta->SetData(Tag::MEDIA_LONGITUDE, longtitude);
    meta->SetData(Tag::MEDIA_LATITUDE, latitude);
    unordered_map<int32_t, std::string> resultMap;
    resultMap = {{AV_KEY_ALBUM, "a"}, {AV_KEY_ARTIST, "a"}, {AV_KEY_DURATION, "a"}, {AV_KEY_DATE_TIME_FORMAT, "a"},
        {AV_KEY_VIDEO_HEIGHT, "a"}, {AV_KEY_VIDEO_WIDTH, "a"}, {AV_KEY_MIME_TYPE, "a"}, {AV_KEY_MIME_TYPE, "a"},
        {AV_KEY_VIDEO_ORIENTATION, "a"}, {AV_KEY_VIDEO_IS_HDR_VIVID, "a"}, {AV_KEY_TITLE, "a"}, {AV_KEY_GENRE, "a"},
        {AV_KEY_DATE_TIME_ISO8601, "2025-06-11T18:00:00.000000Z"}, {AV_KEY_GLTF_OFFSET, "110"}};
    MetadataExtractor::FillExtractedMetadata(resultMap, meta, data);
    EXPECT_EQ(data->GetDateTaken(), 1749664800000);
    EXPECT_EQ(data->GetAlbum(), "a");
    EXPECT_EQ(data->GetLongitude(), longtitude);
    EXPECT_EQ(data->GetLatitude(), latitude);
}

HWTEST_F(MediaLibraryScannerDbTest, medialib_FillExtractedMetadata_test_003, TestSize.Level1)
{
    unique_ptr<Metadata> data = make_unique<Metadata>();
    unique_ptr<MediaScannerDb> mediaScannerDb;
    string path = "/storage/cloud/files/";
    mediaScannerDb->GetFileBasicInfo(path, data);
    data->SetFileMediaType(static_cast<MediaType>(MEDIA_TYPE_DEVICE));
    data->SetFilePath(path);
    int64_t dateModify = 1749632132523;
    data->SetFileDateModified(dateModify);
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    unordered_map<int32_t, std::string> resultMap;
    resultMap = {{AV_KEY_ALBUM, "a"}, {AV_KEY_ARTIST, "a"}, {AV_KEY_DURATION, "a"}, {AV_KEY_DATE_TIME_FORMAT, "a"},
        {AV_KEY_VIDEO_HEIGHT, "a"}, {AV_KEY_VIDEO_WIDTH, "a"}, {AV_KEY_MIME_TYPE, "a"}, {AV_KEY_MIME_TYPE, "a"},
        {AV_KEY_VIDEO_ORIENTATION, "a"}, {AV_KEY_VIDEO_IS_HDR_VIVID, "a"}, {AV_KEY_TITLE, "a"}, {AV_KEY_GENRE, "a"},
        {AV_KEY_DATE_TIME_ISO8601, "11112"}, {AV_KEY_GLTF_OFFSET, "-1"}};
    MetadataExtractor::FillExtractedMetadata(resultMap, meta, data);
    EXPECT_EQ(data->GetDateTaken(), dateModify);
}

HWTEST_F(MediaLibraryScannerDbTest, medialib_FillExtractedMetadata_test_004, TestSize.Level1)
{
    unique_ptr<Metadata> data = make_unique<Metadata>();
    unique_ptr<MediaScannerDb> mediaScannerDb;
    string path = "/storage/cloud/files/";
    mediaScannerDb->GetFileBasicInfo(path, data);
    data->SetFileMediaType(static_cast<MediaType>(MEDIA_TYPE_DEVICE));
    data->SetFilePath(path);
    int64_t dateModify = 1749632132523;
    data->SetFileDateModified(dateModify);
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    unordered_map<int32_t, std::string> resultMap;
    resultMap = {{AV_KEY_ALBUM, "a"}, {AV_KEY_ARTIST, "a"}, {AV_KEY_DURATION, "a"}, {AV_KEY_DATE_TIME_FORMAT, "a"},
        {AV_KEY_VIDEO_HEIGHT, "a"}, {AV_KEY_VIDEO_WIDTH, "a"}, {AV_KEY_MIME_TYPE, "a"}, {AV_KEY_MIME_TYPE, "a"},
        {AV_KEY_VIDEO_ORIENTATION, "a"}, {AV_KEY_VIDEO_IS_HDR_VIVID, "a"}, {AV_KEY_TITLE, "a"}, {AV_KEY_GENRE, "a"},
        {AV_KEY_DATE_TIME_ISO8601, "2025/06/11 18:00:00Z"}, {AV_KEY_GLTF_OFFSET, "10001"}};
    MetadataExtractor::FillExtractedMetadata(resultMap, meta, data);
    EXPECT_EQ(data->GetDateTaken(), dateModify);
}

unique_ptr<Metadata> CreateImageMetadata(const string &path)
{
    unique_ptr<Metadata> data = make_unique<Metadata>();
    unique_ptr<MediaScannerDb> mediaScannerDb;
    mediaScannerDb->GetFileBasicInfo(path, data);
    data->SetFileMediaType(static_cast<MediaType>(MEDIA_TYPE_IMAGE));
    data->SetPhotoSubType(static_cast<int32_t>(PhotoSubType::DEFAULT));
    data->SetFilePath(path);
    int64_t dateModified = 1763369312532;
    data->SetFileDateModified(dateModified);
    return data;
}

std::unique_ptr<ImageSource> CreateImageSource(const string &path)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(path, opts, errorCode);
    EXPECT_NE(imageSource, nullptr);
    return imageSource;
}

HWTEST_F(MediaLibraryScannerDbTest, medialib_ExtractImageTimeInfo_test_001, TestSize.Level1)
{
    const string srcPath = "/storage/cloud/100/files/Documents/CreateImageLcdTest_001.jpg";
    const string destPath = "/storage/cloud/100/files/Documents/medialib_ExtractImageTimeInfo_test_001.jpg";
    const string cmd = "cp " + srcPath + " " + destPath;
    std::system(cmd.c_str());
    std::unique_ptr<ImageSource> imageSource = CreateImageSource(destPath);

    uint32_t index = 0;
    std::string valueModify = "2018:11:24 15:49:41";
    uint32_t retModify =
        imageSource->ModifyImageProperty(index, PHOTO_DATA_IMAGE_DATE_TIME_ORIGINAL, valueModify, destPath);
    ASSERT_EQ(retModify, E_OK);

    unique_ptr<Metadata> data = CreateImageMetadata(destPath);

    MetadataExtractor::ExtractImageTimeInfo(imageSource, data);
    EXPECT_EQ(data->GetDetailTime(), "2018:11:24 15:49:41");
    EXPECT_EQ(data->GetDateDay(), "20181124");
}

HWTEST_F(MediaLibraryScannerDbTest, medialib_ExtractImageTimeInfo_test_002, TestSize.Level1)
{
    const string srcPath = "/storage/cloud/100/files/Documents/CreateImageLcdTest_001.jpg";
    const string destPath = "/storage/cloud/100/files/Documents/medialib_ExtractImageTimeInfo_test_002.jpg";
    const string cmd = "cp " + srcPath + " " + destPath;
    std::system(cmd.c_str());
    std::unique_ptr<ImageSource> imageSource = CreateImageSource(destPath);
    uint32_t index = 0;
    std::string gpsDateStamp = "2018:09:07";
    uint32_t retModify =
        imageSource->ModifyImageProperty(index, PHOTO_DATA_IMAGE_GPS_DATE_STAMP, gpsDateStamp, destPath);
    ASSERT_EQ(retModify, E_OK);
    std::string gpsTimeStamp = "08:58:21.00";
    retModify = imageSource->ModifyImageProperty(index, PHOTO_DATA_IMAGE_GPS_TIME_STAMP, gpsTimeStamp, destPath);
    ASSERT_EQ(retModify, E_OK);

    unique_ptr<Metadata> data = CreateImageMetadata(destPath);

    MetadataExtractor::ExtractImageTimeInfo(imageSource, data);
    EXPECT_EQ(data->GetDetailTime(), "2018:09:07 08:58:21");
    EXPECT_EQ(data->GetDateDay(), "20180907");
}

HWTEST_F(MediaLibraryScannerDbTest, medialib_ExtractImageTimeInfo_test_003, TestSize.Level1)
{
    const string srcPath = "/storage/cloud/100/files/Documents/CreateImageLcdTest_001.jpg";
    const string destPath = "/storage/cloud/100/files/Documents/medialib_ExtractImageTimeInfo_test_003.jpg";
    const string cmd = "cp " + srcPath + " " + destPath;
    std::system(cmd.c_str());
    std::unique_ptr<ImageSource> imageSource = CreateImageSource(destPath);
    uint32_t index = 0;
    std::string valueModify = "2018:11:27 15:49:41";
    uint32_t retModify = imageSource->ModifyImageProperty(index, PHOTO_DATA_IMAGE_DATE_TIME, valueModify, destPath);
    ASSERT_EQ(retModify, E_OK);

    unique_ptr<Metadata> data = CreateImageMetadata(destPath);

    MetadataExtractor::ExtractImageTimeInfo(imageSource, data);
    EXPECT_EQ(data->GetDetailTime(), "2018:11:27 15:49:41");
    EXPECT_EQ(data->GetDateDay(), "20181127");
}

HWTEST_F(MediaLibraryScannerDbTest, medialib_ExtractImageTimeInfo_test_004, TestSize.Level1)
{
    const string srcPath = "/storage/cloud/100/files/Documents/CreateImageLcdTest_001.jpg";
    const string destPath = "/storage/cloud/100/files/Documents/medialib_ExtractImageTimeInfo_test_004.jpg";
    const string cmd = "cp " + srcPath + " " + destPath;
    std::system(cmd.c_str());
    std::unique_ptr<ImageSource> imageSource = CreateImageSource(destPath);

    unique_ptr<Metadata> data = CreateImageMetadata(destPath);
    data->SetFileDateModified(1541868049000);  // 2018-11-11 00:40:49

    MetadataExtractor::ExtractImageTimeInfo(imageSource, data);
    EXPECT_EQ(data->GetDateDay(), "20181111");
}

unique_ptr<Metadata> CreateVideoMetadata()
{
    unique_ptr<Metadata> data = make_unique<Metadata>();
    unique_ptr<MediaScannerDb> mediaScannerDb;
    string path = "/storage/cloud/100/files/Documents/CreateVideoThumbnailTest_001.mp4";
    mediaScannerDb->GetFileBasicInfo(path, data);
    data->SetFileMediaType(static_cast<MediaType>(MEDIA_TYPE_VIDEO));
    data->SetPhotoSubType(static_cast<int32_t>(PhotoSubType::DEFAULT));
    data->SetFilePath(path);
    int64_t dateModified = 1763369312167;
    data->SetFileDateModified(dateModified);
    return data;
}

unordered_map<int32_t, std::string> GetResultMap()
{
    return {{AV_KEY_ALBUM, ""},
        {AV_KEY_ARTIST, ""},
        {AV_KEY_DURATION, ""},
        {AV_KEY_DATE_TIME_FORMAT, "2025-10-30 10:10:39"},
        {AV_KEY_VIDEO_HEIGHT, ""},
        {AV_KEY_VIDEO_WIDTH, ""},
        {AV_KEY_MIME_TYPE, ""},
        {AV_KEY_MIME_TYPE, ""},
        {AV_KEY_VIDEO_ORIENTATION, ""},
        {AV_KEY_VIDEO_IS_HDR_VIVID, ""},
        {AV_KEY_TITLE, ""},
        {AV_KEY_GENRE, ""},
        {AV_KEY_DATE_TIME_ISO8601, "2025-10-30T02:10:39.000000Z"},
        {AV_KEY_GLTF_OFFSET, ""}};
}

HWTEST_F(MediaLibraryScannerDbTest, medialib_PopulateVideoTimeInfo_test_001, TestSize.Level1)
{
    unique_ptr<Metadata> data = CreateVideoMetadata();
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    meta->SetData(PHOTO_DATA_VIDEO_IOS_CREATION_DATE, "2025-10-30T10:05:39+0800");
    unordered_map<int32_t, std::string> resultMap = GetResultMap();
    MetadataExtractor::PopulateVideoTimeInfo(meta, resultMap, data);
    EXPECT_EQ(data->GetDetailTime(), "2025:10:30 10:05:39");
    EXPECT_EQ(data->GetDateDay(), "20251030");
}

HWTEST_F(MediaLibraryScannerDbTest, medialib_PopulateVideoTimeInfo_test_002, TestSize.Level1)
{
    unique_ptr<Metadata> data = CreateVideoMetadata();
    unordered_map<int32_t, std::string> resultMap = GetResultMap();
    MetadataExtractor::PopulateVideoTimeInfo(nullptr, resultMap, data);
    EXPECT_EQ(data->GetDetailTime(), "2025:10:30 10:10:39");
    EXPECT_EQ(data->GetDateDay(), "20251030");
}

HWTEST_F(MediaLibraryScannerDbTest, medialib_PopulateVideoTimeInfo_test_003, TestSize.Level1)
{
    unique_ptr<Metadata> data = CreateVideoMetadata();
    data->SetFileDateModified(1541878049000);  // 2018-11-11 03:27:29
    unordered_map<int32_t, std::string> resultMap;
    MetadataExtractor::PopulateVideoTimeInfo(nullptr, resultMap, data);
    EXPECT_EQ(data->GetDateDay(), "20181111");
}

HWTEST_F(MediaLibraryScannerDbTest, medialib_FillExtractedMetadata_photo, TestSize.Level1)
{
    unique_ptr<Metadata> data = make_unique<Metadata>();
    unique_ptr<MediaScannerDb> mediaScannerDb;
    string path = "/storage/cloud/files/";
    mediaScannerDb->GetFileBasicInfo(path, data);
    data->SetFileMediaType(static_cast<MediaType>(MEDIA_TYPE_IMAGE));
    // subtype = PhotoSubType::MOVING_PHOTO
    data->SetPhotoSubType(static_cast<int32_t>(PhotoSubType::MOVING_PHOTO));
    data->SetFilePath(path);
    data->SetFileDateModified(static_cast<int64_t>(11));
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    float longtitude = 1.2;
    float latitude = 138.2;
    meta->SetData(Tag::MEDIA_LONGITUDE, longtitude);
    meta->SetData(Tag::MEDIA_LATITUDE, latitude);
    unordered_map<int32_t, std::string> resultMap;
    resultMap = {{AV_KEY_ALBUM, "a"}, {AV_KEY_ARTIST, "a"}, {AV_KEY_DURATION, "a"}, {AV_KEY_DATE_TIME_FORMAT, "a"},
        {AV_KEY_VIDEO_HEIGHT, "a"}, {AV_KEY_VIDEO_WIDTH, "a"}, {AV_KEY_MIME_TYPE, "a"}, {AV_KEY_MIME_TYPE, "a"},
        {AV_KEY_VIDEO_ORIENTATION, "a"}, {AV_KEY_VIDEO_IS_HDR_VIVID, "a"}, {AV_KEY_TITLE, "a"}, {AV_KEY_GENRE, "a"},
        {AV_KEY_DATE_TIME_ISO8601, "a"}, {AV_KEY_GLTF_OFFSET, "a"}};
    MetadataExtractor::FillExtractedMetadata(resultMap, meta, data);
    EXPECT_EQ(data->GetAlbum(), "a");
    EXPECT_EQ(data->GetLongitude(), longtitude);
    EXPECT_EQ(data->GetLatitude(), latitude);
}
} // namespace Media
} // namespace OHOS