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

#include "database_data_mock_test.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <utime.h>

#include "media_log.h"
#include "database_data_mock.h"
#include "photos_dao.h"
#include "album_dao.h"

using namespace testing::ext;

namespace OHOS::Media::CloudSync {
void DatabaseDataMockTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("SetUpTestCase");
}

void DatabaseDataMockTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("TearDownTestCase");
}

// SetUp:Execute before each test case
void DatabaseDataMockTest::SetUp()
{
    MEDIA_INFO_LOG("SetUp");
}

void DatabaseDataMockTest::TearDown(void)
{
    MEDIA_INFO_LOG("TearDown");
}

HWTEST_F(DatabaseDataMockTest, CSVFileReader, TestSize.Level1)
{
    std::string csvFileFolder = "/data/test/cloudsync/";
    std::string csvFileName = "database_mock-photos.csv";
    CSVFileReader csvFileReader(csvFileFolder + csvFileName);
    int32_t ret = csvFileReader.ReadCSVFile();
    EXPECT_EQ(ret, CSVFileReader::E_OK);
    std::vector<std::string> headers = csvFileReader.GetHeaderNames();
    bool hasColumn = false;
    for (auto &header : headers) {
        if (header == "data") {
            hasColumn = true;
            break;
        }
    }
    EXPECT_TRUE(hasColumn);
    std::vector<CSVRowData> rows = csvFileReader.GetRows();
    EXPECT_GT(rows.size(), 0);
    bool hasValue = false;
    for (auto &row : rows) {
        std::string columnValue = csvFileReader.GetString(row, "data");
        if (columnValue.size() > 0) {
            hasValue = true;
            break;
        }
    }
    EXPECT_TRUE(hasValue);
}

HWTEST_F(DatabaseDataMockTest, DATABASE, TestSize.Level1)
{
    int32_t errorCode = 0;
    std::shared_ptr<NativeRdb::RdbStore> rdbStore = MediaLibraryDatabase().GetRdbStore(errorCode);
    EXPECT_EQ(errorCode, 0);
    ASSERT_NE(rdbStore, nullptr);
}

void DatabaseDataMockTest::CheckPhotos()
{
    PhotosDao photosDao;
    std::string cloudId = "1c854334ffe54d16881f8a92700cddcdfed7976ab9e64fd2bb743183d98c3877";
    std::string data = "/storage/cloud/files/Photo/16/IMG_1739459136_000.jpg";
    std::vector<PhotosPo> photosList = photosDao.QueryPhotosByCloudId(cloudId);
    PhotosPo targetPhotos;
    int32_t ret = photosDao.GetPhotoByCloudId(photosList, cloudId, targetPhotos);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(targetPhotos.cloudId.value_or(""), cloudId);
    EXPECT_EQ(targetPhotos.data.value_or(""), data);
}

void DatabaseDataMockTest::CheckPhotoAlbum()
{
    AlbumDao albumDao;
    std::string cloudId = "default-album-200-1509715215-1726020218000";
    std::string lPath = "/Pictures/Users/K";
    std::vector<std::string> cloudIds = {cloudId};
    std::vector<PhotoAlbumPo> albumList = albumDao.QueryByCloudIds(cloudIds);
    PhotoAlbumPo targetAlbumPo;
    int32_t ret = albumDao.GetAlbumByCloudId(albumList, cloudId, targetAlbumPo);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(targetAlbumPo.cloudId, cloudId);
    EXPECT_EQ(targetAlbumPo.lpath, lPath);
}

HWTEST_F(DatabaseDataMockTest, DATABASE_DATA_MOCK, TestSize.Level1)
{
    // Get RdbStore
    int32_t errorCode = 0;
    std::shared_ptr<NativeRdb::RdbStore> rdbStore = MediaLibraryDatabase().GetRdbStore(errorCode);
    EXPECT_EQ(errorCode, 0);
    ASSERT_NE(rdbStore, nullptr);
    // Test CheckPoint
    DatabaseDataMock dbDataMock;
    int32_t ret = dbDataMock.SetRdbStore(rdbStore).CheckPoint();
    EXPECT_EQ(ret, DatabaseDataMock::E_OK);
    // Verify CheckPoint
    EXPECT_GE(dbDataMock.GetMaxFileId(), 0);
    EXPECT_GT(dbDataMock.GetMaxAlbumId(), 0);
    EXPECT_GT(dbDataMock.GetMaxAnalysisId(), 0);
    // Test Mock Data
    ret = dbDataMock.MockData(DatabaseDataMockTest::GetTableMockInfoList());
    EXPECT_EQ(ret, DatabaseDataMock::E_OK);
    this->CheckPhotos();
    this->CheckPhotoAlbum();
    // Test Rollback
    ret = dbDataMock.Rollback();
    EXPECT_EQ(ret, DatabaseDataMock::E_OK);
}
}  // namespace OHOS::Media::CloudSync