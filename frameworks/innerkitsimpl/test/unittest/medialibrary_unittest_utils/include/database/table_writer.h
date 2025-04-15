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

#ifndef TDD_TABLE_WRITER_H
#define TDD_TABLE_WRITER_H

#include <string>
#include <vector>
#include <fstream>
#include <iostream>

#include "rdb_store.h"
#include "csv_file_reader.h"

namespace OHOS::Media::TestUtils {
class TableWriter {
private:
    std::shared_ptr<NativeRdb::RdbStore> store_;
    std::string tableName_;
    std::vector<std::string> columnNames_;
    CSVFileReader reader_;

public:
    TableWriter(std::shared_ptr<NativeRdb::RdbStore> store) : store_(store)
    {}
    TableWriter &SetTableName(const std::string &tableName)
    {
        this->tableName_ = tableName;
        return *this;
    }
    TableWriter &SetColumnNames(const std::vector<std::string> &columnNames)  // SetColumnDefines
    {
        this->columnNames_ = columnNames;
        return *this;
    }
    TableWriter &SetReader(const CSVFileReader &reader)
    {
        this->reader_ = reader;
        return *this;
    }

private:
    int32_t Write(CSVRowData &rowData)
    {
        NativeRdb::ValuesBucket values;
        std::string columnValue;
        std::string select = "INSERT INTO Photos(";
        std::string where = " VALUES(";
        for (auto &columnName : this->columnNames_) {
            if (columnName == "data_desc") {
                continue;
            }
            columnValue = this->reader_.GetString(rowData, columnName);
            if (columnValue.empty()) {
                continue;
            }
            select.append(columnName).append(",");
            where.append("'").append(columnValue).append("'").append(",");
            values.PutString(columnName, columnValue);
        }
        select.pop_back();
        where.pop_back();
        select.append(")");
        where.append(");");
        select.append(where);
        int64_t rowId;
        int32_t ret = this->store_->Insert(rowId, this->tableName_, values);
        if (ret != NativeRdb::E_OK) {
            GTEST_LOG_(INFO) << "Insert failed, ret: " << ret << ", table:" << this->tableName_
                             << ", data_desc:" << this->reader_.GetString(rowData, "data_desc") << ", sql:" << select;
        }
        return ret;
    }

public:
    int32_t Write()
    {
        CSVRowData rowData;
        int32_t ret;
        while (this->reader_.HasNext(rowData)) {
            ret = this->Write(rowData);
            if (ret != NativeRdb::E_OK) {
                return ret;
            }
        }
        return NativeRdb::E_OK;
    }
};
}  // namespace OHOS::Media::TestUtils
#endif  // TDD_TABLE_WRITER_H