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
        std::vector<std::string> columns = {" * "};
        auto resultSet = this->rdbStore_->Query(predicates, columns);
        if (resultSet == nullptr) {
            GTEST_LOG_(ERROR) << "AlbumDao::QueryByCloudIds Query failed";
            return result;
        }
        result = ResultSetReader<PhotoAlbumPoWriter, PhotoAlbumPo>(resultSet).ReadRecords();
        if (result.empty()) {
            GTEST_LOG_(ERROR) << "AlbumDao::QueryByCloudIds no photo found";
        }
        resultSet->Close();
        return result;
    }

    std::vector<PhotoAlbumPo> QueryByAlbumNames(const std::vector<std::string> &albumNames)
    {
        std::vector<PhotoAlbumPo> result;
        NativeRdb::AbsRdbPredicates predicates = NativeRdb::AbsRdbPredicates(PhotoAlbumColumns::TABLE);
        predicates.In(PhotoAlbumColumns::ALBUM_NAME, albumNames);
        std::vector<std::string> columns = {" * "};
        auto resultSet = this->rdbStore_->Query(predicates, columns);
        if (resultSet == nullptr) {
            GTEST_LOG_(ERROR) << "AlbumDao::QueryByAlbumNames Query failed";
            return result;
        }
        result = ResultSetReader<PhotoAlbumPoWriter, PhotoAlbumPo>(resultSet).ReadRecords();
        if (result.empty()) {
            GTEST_LOG_(ERROR) << "AlbumDao::QueryByAlbumNames no photo found";
        }
        resultSet->Close();
        return result;
    }

    void UpdateDirtySyncedByAlbumNames(const std::vector<std::string> &albumNames)
    {
        NativeRdb::AbsRdbPredicates predicates = NativeRdb::AbsRdbPredicates(PhotoAlbumColumns::TABLE);
        predicates.In(PhotoAlbumColumns::ALBUM_NAME, albumNames);
        int32_t rowCount;
        NativeRdb::ValuesBucket bucket;
        bucket.PutInt(PhotoAlbumColumns::ALBUM_DIRTY, static_cast<int32_t>(DirtyType::TYPE_SYNCED));
        int32_t ret = this->rdbStore_->Update(rowCount, bucket, predicates);
        EXPECT_TRUE(ret == NativeRdb::E_OK);
    }

    int32_t GetAlbumDirtyByName(const std::string &albumName)
    {
        int32_t result = -1;
        NativeRdb::AbsRdbPredicates predicates = NativeRdb::AbsRdbPredicates(PhotoAlbumColumns::TABLE);
        predicates.EqualTo(PhotoAlbumColumns::ALBUM_NAME, albumName);
        std::vector<std::string> columns = {PhotoAlbumColumns::ALBUM_DIRTY};
        auto resultSet = this->rdbStore_->Query(predicates, columns);
        if (resultSet == nullptr) {
            GTEST_LOG_(ERROR) << "AlbumDao::GetAlbumDirtyByName Query failed:" << albumName;
            return result;
        }
        int32_t rowCount;
        int32_t ret = resultSet->GetRowCount(rowCount);
        if (ret != NativeRdb::E_OK || rowCount != 1) {
            GTEST_LOG_(ERROR) << "AlbumDao::GetAlbumDirtyByName GetRowCount failed:" << albumName;
            return result;
        }
        if (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            result = GetInt32Val(PhotoAlbumColumns::ALBUM_DIRTY, resultSet);
        }
        resultSet->Close();
        return result;
    }

    int32_t GetAlbumCountByAlbumCloudId(const std::string &cloudId)
    {
        int32_t result = -1;
        NativeRdb::AbsRdbPredicates predicates = NativeRdb::AbsRdbPredicates(PhotoAlbumColumns::TABLE);
        predicates.EqualTo(PhotoAlbumColumns::ALBUM_CLOUD_ID, cloudId);
        std::vector<std::string> columns = {PhotoAlbumColumns::ALBUM_COUNT};
        auto resultSet = this->rdbStore_->Query(predicates, columns);
        if (resultSet == nullptr) {
            GTEST_LOG_(ERROR) << "AlbumDao::GetAlbumCountByAlbumCloudId Query failed:" << cloudId;
            return result;
        }
        int32_t rowCount;
        int32_t ret = resultSet->GetRowCount(rowCount);
        if (ret != NativeRdb::E_OK || rowCount != 1) {
            GTEST_LOG_(ERROR) << "AlbumDao::GetAlbumCountByAlbumCloudId GetRowCount failed:" << cloudId;
            return result;
        }
        if (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            result = GetInt32Val(PhotoAlbumColumns::ALBUM_COUNT, resultSet);
        }
        resultSet->Close();
        return result;
    }

    void UpdateAlbumDirtyByName(const std::string &albumName, int32_t dirty)
    {
        if (dirty < 0) {
            return;
        }
        NativeRdb::AbsRdbPredicates predicates = NativeRdb::AbsRdbPredicates(PhotoAlbumColumns::TABLE);
        predicates.EqualTo(PhotoAlbumColumns::ALBUM_NAME, albumName);
        int32_t rowCount;
        NativeRdb::ValuesBucket bucket;
        bucket.PutInt(PhotoAlbumColumns::ALBUM_DIRTY, dirty);
        this->rdbStore_->Update(rowCount, bucket, predicates);
    }

    std::vector<PhotoAlbumPo> QueryAllAlbums()
    {
        std::vector<PhotoAlbumPo> result;
        NativeRdb::AbsRdbPredicates predicates = NativeRdb::AbsRdbPredicates(PhotoAlbumColumns::TABLE);
        std::vector<std::string> columns = {" * "};
        auto resultSet = this->rdbStore_->Query(predicates, columns);
        if (resultSet == nullptr) {
            GTEST_LOG_(ERROR) << "AlbumDao::QueryAllAlbums Query failed";
            return result;
        }
        result = ResultSetReader<PhotoAlbumPoWriter, PhotoAlbumPo>(resultSet).ReadRecords();
        if (result.empty()) {
            GTEST_LOG_(ERROR) << "AlbumDao::QueryAllAlbums no photo found";
        }
        resultSet->Close();
        return result;
    }

    int32_t GetAlbumByCloudId(std::vector<PhotoAlbumPo> &albumList, const std::string &cloudId, PhotoAlbumPo &album)
    {
        EXPECT_TRUE(!albumList.empty());
        for (auto &node : albumList) {
            GTEST_LOG_(INFO) << "GetAlbumByCloudId: " << node.ToString();
            if (node.cloudId == cloudId) {
                album = node;
                return 0;
            }
        }
        return -1;
    }

    int32_t UpdatePhotoAlbumName(const int32_t &albumId, const std::string &newName)
    {
        NativeRdb::AbsRdbPredicates predicates = NativeRdb::AbsRdbPredicates(PhotoAlbumColumns::TABLE);
        predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, albumId);

        NativeRdb::ValuesBucket valuesBucket;
        valuesBucket.PutString(PhotoAlbumColumns::ALBUM_NAME, newName);

        int32_t changedRows = -1;

        this->rdbStore_->Update(changedRows, valuesBucket, predicates);
        return changedRows;
    }
    int32_t DeleteAlbumByCloudId(const std::string &cloudId, const int32_t &dirty)
    {
        NativeRdb::AbsRdbPredicates predicates = NativeRdb::AbsRdbPredicates(PhotoAlbumColumns::TABLE);
        predicates.EqualTo(PhotoAlbumColumns::ALBUM_CLOUD_ID, cloudId);

        NativeRdb::ValuesBucket valuesBucket;
        valuesBucket.PutInt(PhotoAlbumColumns::ALBUM_DIRTY, dirty);

        int32_t changedRows = -1;

        this->rdbStore_->Update(changedRows, valuesBucket, predicates);
        return changedRows;
    }

private:
    std::shared_ptr<NativeRdb::RdbStore> rdbStore_;
};
}  // namespace OHOS::Media::TestUtils
#endif  // TDD_TEST_UTILS_ALBUM_DAO_H