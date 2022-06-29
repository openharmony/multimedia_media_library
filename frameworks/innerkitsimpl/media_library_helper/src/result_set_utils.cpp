/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "result_set_utils.h"
#include "media_log.h"

using namespace std;
namespace OHOS {
namespace Media {
variant<int32_t, string> ResultSetUtils::GetValFromColumn(const string &columnName,
    shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet, ResultSetDataType type)
{
    int32_t index = 0;
    variant<int32_t, string> cellValue(0);
    int32_t integerVal = 0;
    string stringVal;
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, cellValue, "resultSet == nullptr");
    resultSet->GetColumnIndex(columnName, index);
    switch (type) {
        case ResultSetDataType::TYPE_STRING:
            resultSet->GetString(index, stringVal);
            cellValue = stringVal;
            break;
        case ResultSetDataType::TYPE_INT32:
            resultSet->GetInt(index, integerVal);
            cellValue = integerVal;
            break;
        default:
            break;
    }
    return cellValue;
}

int64_t ResultSetUtils::GetLongValFromColumn(string columnName, shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet)
{
    int index = 0;
    int64_t longVal = 0;
    resultSet->GetColumnIndex(columnName, index);
    resultSet->GetLong(index, longVal);
    return longVal;
}
} // namespace Media
} // namespace OHOS
