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

#ifndef TDD_TEST_UTILS_ALBUM_DAO_H
#define TDD_TEST_UTILS_ALBUM_DAO_H

#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "media_library_database.h"
#include "photo_album_po.h"
#include "photo_album_po_writer.h"
#include "result_set_reader.h"

namespace OHOS::Media::TestUtils {
using namespace OHOS::Media::ORM;
class AlbumDao {
public:
    AlbumDao()
    {
        // Get RdbStore
        int32_t errorCode = 0;
        this->rdbStore_ = MediaLibraryDatabase().GetRdbStore(errorCode);
    }

public:
    std::vector<PhotoAlbumPo> QueryByCloudIds(const std::vector<std::string> &cloudIds)
    {
        std::vector<PhotoAlbumPo> result;
        NativeRdb::AbsRdbPredicates predicates = NativeRdb::AbsRdbPredicates(PhotoAlbumColumns::TABLE);
        predicates.In(PhotoAlbumColumns::ALBUM_CLOUD_ID, cloudIds);
        std::vector<std::string> columns = {"*"};
        auto resultSet = this->rdbStore_->Query(predicates, columns);
        if (resultSet == nullptr) {
            GTEST_LOG_(ERROR) << "AlbumDao::QueryByCloudIds Query failed";
            return result;
        }
        result = ResultSetReader<PhotoAlbumPoWriter, PhotoAlbumPo>(resultSet)
            .ReadRecords();
        if (result.empty()) {
            GTEST_LOG_(ERROR) << "AlbumDao::QueryByCloudIds no photo found";
        }
        return result;
    }
    int32_t GetAlbumByCloudId(
        std::vector<PhotoAlbumPo> &albumList, const std::string &cloudId, PhotoAlbumPo &album)
    {
        if (albumList.empty()) {
            return -1;
        }
        for (auto &node : albumList) {
            if (node.cloudId == cloudId) {
                album = node;
                return 0;
            }
        }
        return -1;
    }

private:
    std::shared_ptr<NativeRdb::RdbStore> rdbStore_;
};
}  // namespace OHOS::Media::TestUtils
#endif  // TDD_TEST_UTILS_ALBUM_DAO_H