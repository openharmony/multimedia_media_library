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

#ifndef TDD_PHOTOS_DAO_H
#define TDD_PHOTOS_DAO_H

#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "media_log.h"
#include "media_library_database.h"
#include "photos_po.h"
#include "photos_po_writer.h"
#include "result_set_reader.h"

namespace OHOS::Media::TestUtils {
using namespace OHOS::Media::ORM;
class PhotosDao {
public:
    PhotosDao()
    {
        // Get RdbStore
        int32_t errorCode = 0;
        this->rdbStore_ = MediaLibraryDatabase().GetRdbStore(errorCode);
    }

public:
    std::vector<PhotosPo> QueryPhotosByCloudId(const std::string &cloudId)
    {
        std::vector<PhotosPo> result;
        std::string sql = SQL_PHOTOS_QUERY_BY_CLOUD_ID;
        std::vector<NativeRdb::ValueObject> params = {cloudId};
        auto resultSet = this->rdbStore_->QuerySql(sql, params);
        if (resultSet == nullptr) {
            MEDIA_ERR_LOG("PhotosDao::QueryPhotoByCloudId Query failed");
            return result;
        }
        result = ResultSetReader<PhotosPoWriter, PhotosPo>(resultSet).ReadRecords();
        if (result.empty()) {
            MEDIA_ERR_LOG("PhotosDao::QueryPhotoByCloudId no photo found");
        }
        return result;
    }
    int32_t GetPhotoByCloudId(
        std::vector<PhotosPo> &photosList, const std::string &cloudId, PhotosPo &photo)
    {
        if (photosList.empty()) {
            return -1;
        }
        for (auto &node : photosList) {
            if (node.cloudId == cloudId) {
                photo = node;
                return 0;
            }
        }
        return -1;
    }

private:
    std::shared_ptr<NativeRdb::RdbStore> rdbStore_;

private:
    const std::string SQL_PHOTOS_QUERY_BY_CLOUD_ID = "SELECT * FROM Photos WHERE cloud_id = ?";
};
}  // namespace OHOS::Media::TestUtils
#endif  // TDD_CSV_FILE_READER_H