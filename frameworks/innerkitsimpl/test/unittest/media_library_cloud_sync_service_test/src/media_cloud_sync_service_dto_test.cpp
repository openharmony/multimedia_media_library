/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#define MLOG_TAG "MediaCloudSync"

#include "media_cloud_sync_service_dto_test.h"

#include <string>
#include "aging_file_query_dto.h"
#include "check_file_data_dto.h"
#include "cloud_file_data_dto.h"
#include "cloud_media_pull_data_dto.h"
#include "download_thumbnail_query_dto.h"
#include "media_operate_result_dto.h"
#include "photo_album_dto.h"
#include "photos_dto.h"
#include "report_failure_dto.h"

using namespace testing::ext;

namespace OHOS::Media::CloudSync {
void CloudMediaSyncServiceDtoTest::SetUpTestCase() {}

void CloudMediaSyncServiceDtoTest::TearDownTestCase() {}

void CloudMediaSyncServiceDtoTest::SetUp() {}

void CloudMediaSyncServiceDtoTest::TearDown() {}

HWTEST_F(CloudMediaSyncServiceDtoTest, AgingFileQueryDto_ToString_Test_001, TestSize.Level1)
{
    AgingFileQueryDto dto;
    dto.time = 2025;
    dto.mediaType = 1;
    dto.sizeLimit = 1000;
    dto.offset = 10;
    std::string expectDtoStr = "{\"time\": 2025, \"mediaType\": 1, \"sizeLimit\": 1000, \"offset\": 10, }";

    std::string dtoStr = dto.ToString();
    EXPECT_EQ(expectDtoStr, dtoStr);
}

HWTEST_F(CloudMediaSyncServiceDtoTest, CheckFileDataDto_FileData_ToString_Test_001, TestSize.Level1)
{
    CheckFileDataDto::FileData fileData = {
        .recordId = "id",
        .isDelete = false,
        .version = "10",
    };
    std::string expectStr = "{\"recordId\": \"id\", \"isDelete\": 0, \"version\": 10\"}";

    std::string fileDataStr = fileData.ToString();
    EXPECT_EQ(expectStr, fileDataStr);
}

HWTEST_F(CloudMediaSyncServiceDtoTest, CheckFileDataDto_ToString_Test_001, TestSize.Level1)
{
    CheckFileDataDto::FileData fileData1 = {
        .recordId = "id1",
        .isDelete = false,
        .version = "10",
    };
    CheckFileDataDto::FileData fileData2 = {
        .recordId = "id2",
        .isDelete = true,
        .version = "20",
    };

    CheckFileDataDto fileDataDto;
    fileDataDto.fileDataList = {fileData1, fileData2};

    std::string expectStr = "{\"fileDataList\": [{\"recordId\": \"id1\", \"isDelete\": 0, \"version\": 10\"}, "
                            "{\"recordId\": \"id2\", \"isDelete\": 1, \"version\": 20\"}]}";
    EXPECT_EQ(expectStr, fileDataDto.ToString());
}

HWTEST_F(CloudMediaSyncServiceDtoTest, CloudMediaPullDataDto_ToString_Test_001, TestSize.Level1)
{
    // todo
    CloudMediaPullDataDto pullDataDto;
    pullDataDto.attributesSrcAlbumIds = {"str1", "str2", "str3", "str4"};

    std::string expectStr = "{}";
    EXPECT_NE(expectStr, pullDataDto.ToString());
}

HWTEST_F(CloudMediaSyncServiceDtoTest, DownloadThumbnailQueryDto_ToString_Test_001, TestSize.Level1)
{
    DownloadThumbnailQueryDto dto = {
        .size = 2048,
        .type = 2,
        .offset = 48,
        .isDownloadDisplayFirst = true,
    };

    std::string expectStr = "{\"size\": 2048, \"type\": 2, \"offset\": 48, \"isDownloadDisplayFirst\": 1, }";
    EXPECT_EQ(expectStr, dto.ToString());
}

HWTEST_F(CloudMediaSyncServiceDtoTest, MediaOperateResultDto_ToString_Test_001, TestSize.Level1)
{
    MediaOperateResultDto dto = {
        .cloudId = "id",
        .errorCode = -1,
        .errorMsg = "invalid",
    };

    std::string expectStr = "{\"cloudId\": \"id\", \"errorCode\": -1, \"errorMsg\": invalid,}";
    EXPECT_EQ(expectStr, dto.ToString());
}

HWTEST_F(CloudMediaSyncServiceDtoTest, PhotoAlbumDto_ToString_Test_001, TestSize.Level1)
{
    PhotoAlbumDto dto = {
        .albumId = 1,
        .albumType = 2,
        .albumSubType = 3,
        .albumName = "test1",
        .lPath = "test2",
        .bundleName = "test3",
        .priority = 0,
        .cloudId = "test4",
        .newCloudId = "test5",
        .localLanguage = "test6",
        .albumDateCreated = 4,
        .albumDateAdded = 5,
        .albumDateModified = 6,
        .isDelete = false,
        .isSuccess = true,
    };

    EXPECT_EQ(dto.ToString().empty(), false);
}

HWTEST_F(CloudMediaSyncServiceDtoTest, PhotosDto_ToString_Test_001, TestSize.Level1)
{
    PhotosDto dto;
    CloudErrorDetail errorDetails1;
    errorDetails1.domain = "11";
    CloudErrorDetail errorDetails2;
    errorDetails2.domain = "22";
    CloudErrorDetail errorDetails3;
    errorDetails3.domain = "33";
    dto.errorDetails = {errorDetails1, errorDetails2, errorDetails3};

    std::string expectStr = "{}";
    EXPECT_NE(expectStr, dto.ToString());
}

HWTEST_F(CloudMediaSyncServiceDtoTest, ReportFailureDto_ToString_Test_001, TestSize.Level1)
{
    ReportFailureDto dto = {
        .apiCode = -1,
        .errorCode = -2,
        .fileId = 100,
        .cloudId = "xxxx",
    };

    std::string expectStr = "{\"apiCode\":-1, \"errorCode\":-2, \"fileId\":100, \"cloudId\":\"xxxx\"}";
    EXPECT_EQ(expectStr, dto.ToString());
}
}