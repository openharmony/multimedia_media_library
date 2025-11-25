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
    using SetValHandle = int32_t (ResultSetReader::*)(
        const std::string &, std::shared_ptr<NativeRdb::ResultSet> &, std::shared_ptr<IObjectWriter> &);
    int32_t SetInt32Val(const std::string &columnName, std::shared_ptr<NativeRdb::ResultSet> &resultSet,
        std::shared_ptr<IObjectWriter> &objectWriter)
    {
        CHECK_AND_RETURN_RET(resultSet != nullptr, E_DATA);
        CHECK_AND_RETURN_RET(objectWriter != nullptr, E_DATA);
        const std::map<std::string, MediaColumnType::DataType> &columns = objectWriter->GetColumns();
        auto it = columns.find(columnName);
        CHECK_AND_RETURN_RET(it != columns.end(), E_DATA);
        MediaColumnType::DataType type = it->second;
        CHECK_AND_RETURN_RET(type == MediaColumnType::DataType::INT, E_DATA);
        std::variant<int32_t, int64_t, double, std::string> val = GetInt32Val(columnName, resultSet);
        return objectWriter->SetMemberVariable(columnName, val);
    }

    int32_t SetInt64Val(const std::string &columnName, std::shared_ptr<NativeRdb::ResultSet> &resultSet,
        std::shared_ptr<IObjectWriter> &objectWriter)
    {
        CHECK_AND_RETURN_RET(resultSet != nullptr, E_DATA);
        CHECK_AND_RETURN_RET(objectWriter != nullptr, E_DATA);
        const std::map<std::string, MediaColumnType::DataType> &columns = objectWriter->GetColumns();
        auto it = columns.find(columnName);
        CHECK_AND_RETURN_RET(it != columns.end(), E_DATA);
        MediaColumnType::DataType type = it->second;
        CHECK_AND_RETURN_RET(type == MediaColumnType::DataType::LONG, E_DATA);
        std::variant<int32_t, int64_t, double, std::string> val = GetInt64Val(columnName, resultSet);
        return objectWriter->SetMemberVariable(columnName, val);
    }

    int32_t SetDoubleVal(const std::string &columnName, std::shared_ptr<NativeRdb::ResultSet> &resultSet,
        std::shared_ptr<IObjectWriter> &objectWriter)
    {
        CHECK_AND_RETURN_RET(resultSet != nullptr, E_DATA);
        CHECK_AND_RETURN_RET(objectWriter != nullptr, E_DATA);
        const std::map<std::string, MediaColumnType::DataType> &columns = objectWriter->GetColumns();
        auto it = columns.find(columnName);
        CHECK_AND_RETURN_RET(it != columns.end(), E_DATA);
        MediaColumnType::DataType type = it->second;
        CHECK_AND_RETURN_RET(type == MediaColumnType::DataType::DOUBLE, E_DATA);
        std::variant<int32_t, int64_t, double, std::string> val = GetDoubleVal(columnName, resultSet);
        return objectWriter->SetMemberVariable(columnName, val);
    }

    int32_t SetStringVal(const std::string &columnName, std::shared_ptr<NativeRdb::ResultSet> &resultSet,
        std::shared_ptr<IObjectWriter> &objectWriter)
    {
        CHECK_AND_RETURN_RET(resultSet != nullptr, E_DATA);
        CHECK_AND_RETURN_RET(objectWriter != nullptr, E_DATA);
        // type default is MediaColumnType::DataType::STRING
        std::variant<int32_t, int64_t, double, std::string> val = GetStringVal(columnName, resultSet);
        return objectWriter->SetMemberVariable(columnName, val);
    }

    int32_t SetMemberVariable(const std::string &columnName, std::shared_ptr<NativeRdb::ResultSet> &resultSet,
        std::shared_ptr<IObjectWriter> &objectWriter)
    {
        CHECK_AND_RETURN_RET(resultSet != nullptr, E_DATA);
        CHECK_AND_RETURN_RET(objectWriter != nullptr, E_DATA);
        const std::vector<SetValHandle> setValFuncs = {
            &ResultSetReader::SetInt32Val,
            &ResultSetReader::SetInt64Val,
            &ResultSetReader::SetDoubleVal,
            &ResultSetReader::SetStringVal,
        };
        for (const auto &setValFunc : setValFuncs) {
            auto ret = (this->*setValFunc)(columnName, resultSet, objectWriter);
            CHECK_AND_RETURN_RET(ret != E_OK, E_OK);  // if set value failed, try next method
        }
        return E_DATA;
    }

    OBJECT_TYPE ReadRecord()
    {
        OBJECT_TYPE objectPo;
        bool errConn = this->resultSet_ == nullptr;
        CHECK_AND_RETURN_RET(!errConn, objectPo);
        CHECK_AND_RETURN_RET_LOG(!this->columnNames_.empty(), objectPo, "columnNames_ is empty");
        std::shared_ptr<IObjectWriter> objectWriter = std::make_shared<OBJECT_WRITER>(objectPo);
        // read data from resultSet into PO
        for (const std::string &columnName : this->columnNames_) {
            this->SetMemberVariable(columnName, this->resultSet_, objectWriter);
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
