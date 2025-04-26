/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#ifndef FRAMEWORKS_MEDIATOOLS_UTILS_DATABASE_UTILS_H_
#define FRAMEWORKS_MEDIATOOLS_UTILS_DATABASE_UTILS_H_
#include <string>
#include <vector>

#include "datashare_result_set.h"
#include "fetch_result.h"
#include "file_asset.h"
#include "utils/constant_utils.h"

namespace OHOS {
namespace Media {
namespace MediaTool {
class DatabaseUtils {
public:
    static bool Dump(const DumpOpt &opt, const std::shared_ptr<FetchResult<FileAsset>> &resultSet);
    static bool Dump(const DumpOpt &opt, const std::shared_ptr<DataShare::DataShareResultSet> &resultSet);
    static std::string TitleToStr(const DumpOpt &opt, const std::vector<ColumnInfo> &columnInfos);
    static int RowToStr(const DumpOpt &opt, const std::shared_ptr<DataShare::DataShareResultSet> &resultSet,
        const std::vector<ColumnInfo> &columnInfos, std::string &rowStr);
    static int FieldToStr(const DumpOpt &opt, const ColumnInfo &columnInfo,
        const std::shared_ptr<DataShare::DataShareResultSet> &resultSet, std::string &value);
    static int32_t GetColumnInfo(const DumpOpt &opt, const std::shared_ptr<DataShare::DataShareResultSet> &resultSet,
        std::vector<ColumnInfo> &columnInfos);
};
} // namespace MediaTool
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_MEDIATOOLS_UTILS_DATABASE_UTILS_H_
