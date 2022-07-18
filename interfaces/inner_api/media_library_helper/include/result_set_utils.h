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
#ifndef INTERFACES_INNERAPI_MEDIA_LIBRARY_HELPER_INCLUDE_RESULT_SET_UTILS_H_
#define INTERFACES_INNERAPI_MEDIA_LIBRARY_HELPER_INCLUDE_RESULT_SET_UTILS_H_

#include "fetch_result.h"
namespace OHOS {
namespace Media {
class ResultSetUtils {
public:
    template<typename T>
    static std::variant<int32_t, std::string, int64_t> GetValFromColumn(const std::string &columnName,
        T &resultSet, ResultSetDataType type)
    {
        int32_t index = 0;
        std::variant<int32_t, std::string, int64_t> cellValue(0);
        int32_t integerVal = 0;
        int64_t longVal = 0;
        std::string stringVal;
        if (resultSet == nullptr) {
            return cellValue;
        }
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
            case ResultSetDataType::TYPE_INT64:
                resultSet->GetLong(index, longVal);
                cellValue = longVal;
            default:
                break;
        }
        return cellValue;
    }
};
} // namespace Media
} // namespace  OHOS
#endif // INTERFACES_INNERAPI_MEDIA_LIBRARY_HELPER_INCLUDE_RESULT_SET_UTILS_H_
