/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "utils/database_utils.h"

#include "constant.h"
#include "datashare_errno.h"
#include "fetch_result.h"
#include "medialibrary_errno.h"
#include "result_set_utils.h"
#include "utils/db_const.h"

namespace OHOS {
namespace Media {
namespace MediaTool {
bool DatabaseUtils::Dump(const DumpOpt &opt, const std::shared_ptr<FetchResult<FileAsset>> &resultSet)
{
    if (resultSet == nullptr) {
        return true;
    }
    return DatabaseUtils::Dump(opt, resultSet->GetDataShareResultSet());
}

bool DatabaseUtils::Dump(const DumpOpt &opt, const std::shared_ptr<DataShare::DataShareResultSet> &resultSet)
{
    if (resultSet == nullptr) {
        return true;
    }
    std::vector<ColumnInfo> columnInfos;
    int32_t err = GetColumnInfo(resultSet, columnInfos);
    if (err != NativeRdb::E_OK) {
        return false;
    }
    if (opt.title) {
        printf("%s\n", TitleToStr(opt, columnInfos).c_str());
    }
    int32_t count = 0;
    auto ret = resultSet->GetRowCount(count);
    if (ret != E_OK) {
        printf("%s get row count failed. ret:%d.\n", STR_FAIL.c_str(), ret);
        return false;
    }
    if (count <= 0) {
        return true;
    }
    ret = resultSet->GoToFirstRow();
    if (ret != E_OK) {
        printf("%s goto first row failed. ret:%d.\n", STR_FAIL.c_str(), ret);
        return false;
    }
    for (int32_t i = 0; i < opt.count; i++) {
        int32_t row = opt.start + i;
        if (row >= count) {
            break;
        }
        ret = resultSet->GoToRow(row);
        if (ret != E_OK) {
            printf("%s goto row failed. ret:%d, row:%d.\n", STR_FAIL.c_str(), ret, row);
            return false;
        }
        std::string str;
        ret = RowToStr(opt, resultSet, columnInfos, str);
        if (ret != E_OK) {
            printf("%s row to string failed. ret:%d\n", STR_FAIL.c_str(), ret);
            return false;
        }
        printf("%s\n", str.c_str());
    }
    return true;
}

std::string DatabaseUtils::TitleToStr(const DumpOpt &opt, const std::vector<ColumnInfo> &columnInfos)
{
    std::string str;
    for (size_t index = 0; index < columnInfos.size(); index++) {
        auto &columnInfo = columnInfos[index];
        std::string split = (index == 0) ? "" : opt.split;
        str.append(split + columnInfo.name);
    }
    return str;
}

int DatabaseUtils::RowToStr(const DumpOpt &opt, const std::shared_ptr<DataShare::DataShareResultSet> &resultSet,
    const std::vector<ColumnInfo> &columnInfos, std::string &rowStr)
{
    rowStr.clear();
    if (resultSet == nullptr) {
        return DataShare::E_ERROR;
    }
    for (size_t index = 0; index < columnInfos.size(); index++) {
        auto &columnInfo = columnInfos[index];
        std::string value;
        int status = FieldToStr(opt, columnInfo, resultSet, value);
        if (status != DataShare::E_OK) {
            return DataShare::E_ERROR;
        }
        std::string split = (index == 0) ? "" : opt.split;
        rowStr.append(split + value);
    }
    return DataShare::E_OK;
}

int DatabaseUtils::FieldToStr(const DumpOpt &opt, const ColumnInfo &columnInfo,
    const std::shared_ptr<DataShare::DataShareResultSet> &resultSet, std::string &value)
{
    value.clear();
    if (resultSet == nullptr) {
        return DataShare::E_ERROR;
    }
    bool isNull = false;
    int status = resultSet->IsColumnNull(columnInfo.index, isNull);
    if ((status == DataShare::E_OK) && isNull) {
        value = "null";
        return DataShare::E_OK;
    }
    status = DataShare::E_OK;
    std::string strValue;
    switch (columnInfo.type) {
        case ResultSetDataType::TYPE_STRING: {
            strValue = get<std::string>(ResultSetUtils::GetValFromColumn(columnInfo.name, resultSet, columnInfo.type));
            break;
        }
        case ResultSetDataType::TYPE_INT32: {
            int32_t int32Value = get<int32_t>(ResultSetUtils::GetValFromColumn(columnInfo.name,
                resultSet, columnInfo.type));
            strValue = std::to_string(int32Value);
            break;
        }
        case ResultSetDataType::TYPE_INT64: {
            int64_t int64Value = get<int64_t>(ResultSetUtils::GetValFromColumn(columnInfo.name,
                resultSet, columnInfo.type));
            strValue = std::to_string(int64Value);
            break;
        }
        case ResultSetDataType::TYPE_DOUBLE: {
            double doubleValue = get<double>(ResultSetUtils::GetValFromColumn(columnInfo.name,
                resultSet, columnInfo.type));
            strValue = std::to_string(doubleValue);
            break;
        }
        default: {
            status = DataShare::E_ERROR;
            break;
        }
    }
    if (status != DataShare::E_OK) {
        printf("%s field to string failed. status:%d, type:%d, name:%s.\n", STR_FAIL.c_str(),
            status, columnInfo.type, columnInfo.name.c_str());
        return status;
    }
    value = (columnInfo.type == ResultSetDataType::TYPE_STRING) ? opt.delimiter + strValue + opt.delimiter : strValue;
    return DataShare::E_OK;
}

int32_t DatabaseUtils::GetColumnInfo(const std::shared_ptr<DataShare::DataShareResultSet> &resultSet,
    std::vector<ColumnInfo> &columnInfos)
{
    if (resultSet == nullptr) {
        return Media::E_ERR;
    }
    std::vector<std::string> names;
    int32_t err = resultSet->GetAllColumnNames(names);
    if (err != NativeRdb::E_OK) {
        printf("%s get all column names failed. err:%d.\n", STR_FAIL.c_str(), err);
        return err;
    }
    for (const auto &name : names) {
        ColumnInfo columnInfo;
        columnInfo.name = name;
        err = resultSet->GetColumnIndex(name, columnInfo.index);
        if (err != NativeRdb::E_OK) {
            printf("%s get column index failed. err:%d, name:%s.\n", STR_FAIL.c_str(), err, name.c_str());
            return err;
        }
        if (RESULT_TYPE_MAP.count(name) <= 0) {
            printf("%s please add %s into RESULT_TYPE_MAP.\n", STR_WARN.c_str(), name.c_str());
            continue;
        }
        columnInfo.type = RESULT_TYPE_MAP.at(name);
        columnInfos.push_back(columnInfo);
    }
    return NativeRdb::E_OK;
}
} // namespace MediaTool
} // namespace Media
} // namespace OHOS
