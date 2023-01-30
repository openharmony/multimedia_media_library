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

#include "medialibrary_common_log.h"
#include "fetch_result.h"

namespace OHOS {
namespace Media {
class ResultSetUtils {
public:
    template<typename T>
    static std::variant<int32_t, std::string, int64_t, double> GetValFromColumn(const std::string &columnName,
        T &resultSet, ResultSetDataType type)
    {
        if (resultSet == nullptr) {
            COMMON_ERR_LOG("resultSet is nullptr");
            return DefaultVariantVal(type);
        }

        int32_t err;
        int32_t index = 0;
        err = resultSet->GetColumnIndex(columnName, index);
        if (err) {
            COMMON_ERR_LOG("get column index err %{public}d", err);
            return DefaultVariantVal(type);
        }

        std::variant<int32_t, std::string, int64_t, double> data;
        switch (type) {
            case ResultSetDataType::TYPE_STRING: {
                std::string stringVal;
                err = resultSet->GetString(index, stringVal);
                CHECK_AND_ERR_LOG(!err, "get string err %{public}d", err);
                data = stringVal;
                break;
            }
            case ResultSetDataType::TYPE_INT32: {
                int32_t integerVal;
                err = resultSet->GetInt(index, integerVal);
                CHECK_AND_ERR_LOG(!err, "get int err %{public}d", err);
                data = integerVal;
                break;
            }
            case ResultSetDataType::TYPE_INT64: {
                int64_t integer64Val;
                err = resultSet->GetLong(index, integer64Val);
                CHECK_AND_ERR_LOG(!err, "get int64 err %{public}d", err);
                data = integer64Val;
                break;
            }
            case ResultSetDataType::TYPE_DOUBLE: {
                double doubleVal;
                err = resultSet->GetDouble(index, doubleVal);
                CHECK_AND_ERR_LOG(!err, "get double err %{public}d", err);
                data = doubleVal;
                break;
            }
            default: {
                COMMON_ERR_LOG("invalid data type %{public}d", type);
                break;
            }
        }

        return data;
    }

private:
    static std::variant<int32_t, std::string, int64_t, double> DefaultVariantVal(ResultSetDataType type)
    {
        switch (type) {
            case ResultSetDataType::TYPE_STRING:
                return std::string();
            case ResultSetDataType::TYPE_INT32:
                return 0;
            case ResultSetDataType::TYPE_INT64:
                return static_cast<int64_t>(0);
            case ResultSetDataType::TYPE_DOUBLE:
                return static_cast<double>(0);
            default:
                COMMON_ERR_LOG("invalid data type %{public}d", type);
        }

        return 0;
    }
};

template<typename ResultSet>
static inline std::string GetStringVal(const std::string &field, const ResultSet &result)
{
    return get<std::string>(ResultSetUtils::GetValFromColumn(field, result, TYPE_STRING));
}
template<typename ResultSet>
static inline int32_t GetInt32Val(const std::string &field, const ResultSet &result)
{
    return get<int32_t>(ResultSetUtils::GetValFromColumn(field, result, TYPE_INT32));
}
template<typename ResultSet>
static inline int64_t GetInt64Val(const std::string &field, const ResultSet &result)
{
    return get<int64_t>(ResultSetUtils::GetValFromColumn(field, result, TYPE_INT64));
}
} // namespace Media
} // namespace  OHOS
#endif // INTERFACES_INNERAPI_MEDIA_LIBRARY_HELPER_INCLUDE_RESULT_SET_UTILS_H_
