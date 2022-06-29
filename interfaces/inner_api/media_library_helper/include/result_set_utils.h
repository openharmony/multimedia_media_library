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
    static std::variant<int32_t, std::string> GetValFromColumn(const std::string &columnName,
        std::shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet, ResultSetDataType type);
    static int64_t GetLongValFromColumn(std::string columnName,
        std::shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet);
};
} // namespace Media
} // namespace  OHOS
#endif // INTERFACES_INNERAPI_MEDIA_LIBRARY_HELPER_INCLUDE_RESULT_SET_UTILS_H_
