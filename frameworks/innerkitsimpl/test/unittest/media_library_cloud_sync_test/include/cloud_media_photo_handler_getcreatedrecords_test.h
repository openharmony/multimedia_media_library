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

#ifndef OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_PHOTO_HANDLER_GET_CREATED_RECORDS_TEST_H
#define OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_PHOTO_HANDLER_GET_CREATED_RECORDS_TEST_H

#include "gtest/gtest.h"

#include <string>
#include <vector>
#include <map>

#include "media_column_type.h"
#include "database_data_mock.h"

namespace OHOS::Media::CloudSync {
using namespace OHOS::Media::ORM;
using namespace OHOS::Media::TestUtils;
class CloudMediaPhotoHandlerGetCreatedRecordsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

public:
    static std::vector<TableMockInfo> GetTableMockInfoList()
    {
        // Photos
        TableMockInfo photosTableMockInfo;
        photosTableMockInfo.tableName = "Photos";
        photosTableMockInfo.csvFilePath = "/data/test/cloudsync/getcreatedrecords_photo/getcreatedrecords_photo.csv";
        photosTableMockInfo.columnNames = GetKeys(MediaColumnType::PHOTOS_COLUMNS);
        // PhotoAlbum
        TableMockInfo photoAlbumTableMockInfo;
        photoAlbumTableMockInfo.tableName = "PhotoAlbum";
        photoAlbumTableMockInfo.csvFilePath =
            "/data/test/cloudsync/getcreatedrecords_photo/getcreatedrecords_album.csv";
        photoAlbumTableMockInfo.columnNames = GetKeys(MediaColumnType::PHOTO_ALBUM_COLUMNS);
        return {photoAlbumTableMockInfo, photosTableMockInfo};
    }

private:
    static std::vector<std::string> GetKeys(const std::map<std::string, MediaColumnType::DataType> &map)
    {
        std::vector<std::string> result;
        for (const auto &pair : map) {
            result.emplace_back(pair.first);
        }
        return result;
    }

private:
    static DatabaseDataMock dbDataMock_;
};
}  // namespace OHOS::Media::CloudSync
#endif  // OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_PHOTO_HANDLER_GET_CREATED_RECORDS_TEST_H
