/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_ORM_RESULT_SET_READER_H
#define OHOS_MEDIA_ORM_RESULT_SET_READER_H

#include <string>
#include <map>

#include "cloud_media_sync_const.h"
#include "i_object_writer.h"
#include "result_set_utils.h"

namespace OHOS::Media::ORM {
template <typename OBJECT_WRITER, typename OBJECT_TYPE>
class ResultSetReader {
private:
    std::shared_ptr<NativeRdb::ResultSet> resultSet_;
    std::vector<std::string> columnNames_;

public:
    ResultSetReader(const std::shared_ptr<NativeRdb::ResultSet> resultSet) : resultSet_(resultSet)
    {}
    ~ResultSetReader() = default;

private:
    OBJECT_TYPE ReadRecord()
    {
        OBJECT_TYPE objectPo;
        bool errConn = this->resultSet_ == nullptr;
        CHECK_AND_RETURN_RET(!errConn, objectPo);
        CHECK_AND_RETURN_RET_LOG(!this->columnNames_.empty(), objectPo, "columnNames_ is empty");
        std::shared_ptr<IObjectWriter> objectWriter = std::make_shared<OBJECT_WRITER>(objectPo);
        // read data from resultSet into PO
        std::map<std::string, MediaColumnType::DataType> columns = objectWriter->GetColumns();
        for (const std::string &columnName : this->columnNames_) {
            auto it = columns.find(columnName);
            CHECK_AND_CONTINUE_ERR_LOG(it != columns.end(), "column [%{public}s] not found", columnName.c_str());
            const std::string key = it->first;
            MediaColumnType::DataType type = it->second;
            std::variant<int32_t, int64_t, double, std::string> val;
            switch (type) {
                case MediaColumnType::DataType::INT: {
                    val = GetInt32Val(key, this->resultSet_);
                    objectWriter->SetMemberVariable(key, val);
                    break;
                }
                case MediaColumnType::DataType::LONG: {
                    val = GetInt64Val(key, this->resultSet_);
                    objectWriter->SetMemberVariable(key, val);
                    break;
                }
                case MediaColumnType::DataType::DOUBLE: {
                    val = GetDoubleVal(key, this->resultSet_);
                    objectWriter->SetMemberVariable(key, val);
                    break;
                }
                case MediaColumnType::DataType::STRING: {
                    val = GetStringVal(key, this->resultSet_);
                    objectWriter->SetMemberVariable(key, val);
                    break;
                }
            }
        }
        // provide the copy of PO
        return objectPo;
    }
    int32_t LoadColumnNames(std::shared_ptr<NativeRdb::ResultSet> &resultSet)
    {
        bool conn = this->resultSet_ != nullptr;
        CHECK_AND_RETURN_RET_LOG(conn, E_HAS_DB_ERROR, "LoadColumnNames resultSet is null");
        auto ret = this->resultSet_->GetAllColumnNames(this->columnNames_);
        MEDIA_DEBUG_LOG("LoadColumnNames, ret: %{public}d, count: %{public}zu", ret, this->columnNames_.size());
        return ret;
    }

public:
    int32_t ReadRecords(std::vector<OBJECT_TYPE> &records)
    {
        bool conn = this->resultSet_ != nullptr;
        CHECK_AND_RETURN_RET_LOG(conn, E_HAS_DB_ERROR, "ReadRecords resultSet is null");
        int32_t ret = this->LoadColumnNames(this->resultSet_);
        CHECK_AND_RETURN_RET_LOG(ret == E_OK, ret, "ReadRecords LoadColumnNames failed, ret: %{public}d", ret);
        while (this->resultSet_->GoToNextRow() == NativeRdb::E_OK) {
            records.emplace_back(this->ReadRecord());
        }
        this->resultSet_->Close();
        return E_OK;
    }
    std::vector<OBJECT_TYPE> ReadRecords()
    {
        std::vector<OBJECT_TYPE> records;
        this->ReadRecords(records);
        return records;
    }
};
}  // namespace OHOS::Media::ORM
#endif  // OHOS_MEDIA_ORM_RESULT_SET_READER_H
