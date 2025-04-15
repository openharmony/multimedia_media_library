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

#ifndef TDD_DATABASE_DATA_MOCK_H
#define TDD_DATABASE_DATA_MOCK_H

#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "rdb_store.h"
#include "result_set_utils.h"

#include "media_library_database.h"
#include "csv_file_reader.h"
#include "table_writer.h"

namespace OHOS::Media::TestUtils {
struct TableMockInfo {
    std::string tableName;
    std::string csvFilePath;
    std::vector<std::string> columnNames;
};
class DatabaseDataMock {
public:
    enum {
        E_OK,
        E_RDB_STORE_NULL,
        E_PHOTOS_CHECKPOINT_FAIL,
        E_PHOTOALBUM_CHECKPOINT_FAIL,
        E_ANALYSIS_CHECKPOINT_FAIL,
        E_ANALYSIS_FIELD_CHECKPOINT_FAIL,
        E_PHOTOS_MOCKDATA_FAIL,
        E_PHOTOALBUM_MOCKDATA_FAIL,
        E_PHOTOS_ROLLBACK_FAIL,
        E_PHOTOALBUM_ROLLBACK_FAIL,
        E_PHOTOS_MOCKDATA_CSV_FAIL,
        E_PHOTOALBUM_MOCKDATA_CSV_FAIL,
    };

private:
    int64_t maxFileId_;
    int64_t maxAnalysisFileId_;
    int64_t maxAlbumId_;
    int64_t maxAnalysisId_;
    std::shared_ptr<NativeRdb::RdbStore> rdbStore_;

public:
    DatabaseDataMock &SetRdbStore(std::shared_ptr<NativeRdb::RdbStore> rdbStore)
    {
        this->rdbStore_ = rdbStore;
        return *this;
    }

public:  // Getter & Setter
    int64_t GetMaxFileId() const
    {
        return maxFileId_;
    }
    int64_t GetMaxAlbumId() const
    {
        return maxAlbumId_;
    }
    int64_t GetMaxAnalysisId() const
    {
        return maxAnalysisId_;
    }
    int64_t GetMaxAnalysisFileId() const
    {
        return maxAnalysisFileId_;
    }

public:
    int32_t CheckPoint()
    {
        if (this->rdbStore_ == nullptr) {
            return E_RDB_STORE_NULL;
        }
        if (!this->GetMaxFileId(this->maxFileId_)) {
            return E_PHOTOS_CHECKPOINT_FAIL;
        }
        if (!this->GetMaxAlbumId(this->maxAlbumId_)) {
            return E_PHOTOALBUM_CHECKPOINT_FAIL;
        }
        if (!this->GetMaxAnalysisId(this->maxAnalysisId_)) {
            return E_ANALYSIS_CHECKPOINT_FAIL;
        }
        if (!this->GetMaxAnalysisFileId(this->maxAnalysisFileId_)) {
            return E_ANALYSIS_FIELD_CHECKPOINT_FAIL;
        }
        if (this->maxAnalysisFileId_ > this->maxFileId_) {
            this->DeleteAnalysisRecords();
        }
        return E_OK;
    }

    int32_t MockData(const std::vector<TableMockInfo> &tableMockInfos)
    {
        if (this->rdbStore_ == nullptr) {
            return E_RDB_STORE_NULL;
        }
        for (const auto &tableMockInfo : tableMockInfos) {
            int32_t ret = this->MockData(tableMockInfo);
            if (ret != E_OK) {
                return ret;
            }
        }
        return E_OK;
    }

    int32_t Rollback()
    {
        if (this->rdbStore_ == nullptr) {
            return E_RDB_STORE_NULL;
        }
        if (!this->RollbackPhotosToCheckpoint()) {
            GTEST_LOG_(INFO) << "RollBack Photos Error, MaxFileID:" << this->maxFileId_;
        }
        if (!this->RollbackAlbumsToCheckpoint()) {
            GTEST_LOG_(INFO) << "RollBack PhotoAlbum Error, MaxAlbumId:" << this->maxAlbumId_;
        }
        if (!this->RollbackAnalysisToCheckpoint()) {
            GTEST_LOG_(INFO) << "RollBack tab_analysis_total Error, MaxAnalysisId:" << this->maxAnalysisId_;
        }
        return E_OK;
    }

private:
    bool GetMaxFileId(int64_t &maxFileId)
    {
        // Use COALSECE to avoid NULL result when the table is empty.
        std::string querySql = "SELECT COALESCE(MAX(file_id), 0) AS file_id FROM Photos;";
        auto resultSet = this->rdbStore_->QuerySql(querySql);
        if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
            GTEST_LOG_(INFO) << "resultSet is null, querySql: " << querySql;
            return false;
        }
        maxFileId = GetInt64Val("file_id", resultSet);
        return true;
    }
    bool GetMaxAlbumId(int64_t &maxAlbumId)
    {
        // Use COALSECE to avoid NULL result when the table is empty.
        std::string querySql = "SELECT COALESCE(MAX(album_id), 0) AS album_id FROM PhotoAlbum;";
        auto resultSet = this->rdbStore_->QuerySql(querySql);
        if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
            GTEST_LOG_(INFO) << "resultSet is null, querySql: " << querySql;
            return false;
        }
        maxAlbumId = GetInt64Val("album_id", resultSet);
        return true;
    }
    bool GetMaxAnalysisId(int64_t &maxAnalysisId)
    {
        // Use COALSECE to avoid NULL result when the table is empty.
        std::string querySql = "SELECT COALESCE(MAX(id), 0) AS id FROM tab_analysis_total;";
        auto resultSet = this->rdbStore_->QuerySql(querySql);
        if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
            GTEST_LOG_(INFO) << "resultSet is null, querySql: " << querySql;
            return false;
        }
        maxAnalysisId = GetInt64Val("id", resultSet);
        return true;
    }
    bool GetMaxAnalysisFileId(int64_t &maxAnalysisFileId)
    {
        // Use COALSECE to avoid NULL result when the table is empty.
        std::string querySql = "SELECT COALESCE(MAX(file_id), 0) AS file_id FROM tab_analysis_total;";
        auto resultSet = this->rdbStore_->QuerySql(querySql);
        if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
            GTEST_LOG_(INFO) << "resultSet is null, querySql: " << querySql;
            return false;
        }
        maxAnalysisFileId = GetInt64Val("file_id", resultSet);
        return true;
    }
    bool RollbackPhotosToCheckpoint()
    {
        // Accept 0 as maxFileId_ means no photo data.
        if (this->maxFileId_ < 0) {
            return false;
        }
        std::string execSql = "DELETE FROM Photos WHERE file_id > ?;";
        std::vector<NativeRdb::ValueObject> bindArgs = {this->maxFileId_};
        int32_t ret = this->rdbStore_->ExecuteSql(execSql, bindArgs);
        return ret == NativeRdb::E_OK;
    }
    bool RollbackAlbumsToCheckpoint()
    {
        // Reject 0 as maxAlbumId_ means album data never be empty.
        if (this->maxAlbumId_ <= 0) {
            return false;
        }
        std::string execSql = "DELETE FROM PhotoAlbum WHERE album_id > ?;";
        std::vector<NativeRdb::ValueObject> bindArgs = {this->maxAlbumId_};
        int32_t ret = this->rdbStore_->ExecuteSql(execSql, bindArgs);
        return ret == NativeRdb::E_OK;
    }
    bool RollbackAnalysisToCheckpoint()
    {
        // Reject 0 as maxAnalysisId_ means album data never be empty.
        if (this->maxAnalysisId_ <= 0) {
            return false;
        }
        std::string execSql = "DELETE FROM tab_analysis_total WHERE file_id > ?;";
        std::vector<NativeRdb::ValueObject> bindArgs = {this->maxAnalysisId_};
        int32_t ret = this->rdbStore_->ExecuteSql(execSql, bindArgs);
        return ret == NativeRdb::E_OK;
    }
    bool DeleteAnalysisRecords()
    {
        if (this->maxAnalysisFileId_ <= 0) {
            return false;
        }
        std::string execSql = "DELETE FROM tab_analysis_total WHERE file_id > ?;";
        std::vector<NativeRdb::ValueObject> bindArgs = {this->maxFileId_};
        int32_t ret = this->rdbStore_->ExecuteSql(execSql, bindArgs);
        return ret == NativeRdb::E_OK;
    }
    int32_t MockData(const TableMockInfo &tableMockInfo)
    {
        const std::string &tableName = tableMockInfo.tableName;
        const std::string &csvFilePath = tableMockInfo.csvFilePath;
        const std::vector<std::string> &columnNames = tableMockInfo.columnNames;
        CSVFileReader csvFileReader(csvFilePath);
        int32_t ret = csvFileReader.ReadCSVFile();
        if (ret != E_OK) {
            return E_PHOTOALBUM_MOCKDATA_CSV_FAIL;
        }
        std::shared_ptr<NativeRdb::RdbStore> rdbStore = MediaLibraryDatabase().GetRdbStore();
        if (rdbStore == nullptr) {
            return E_RDB_STORE_NULL;
        }
        TableWriter tableWriter(rdbStore);
        return tableWriter.SetTableName(tableName).SetColumnNames(columnNames).SetReader(csvFileReader).Write();
    }
};
}  // namespace OHOS::Media::TestUtils
#endif  // TDD_DATABASE_DATA_MOCK_H