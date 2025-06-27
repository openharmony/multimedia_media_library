/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "medialibrary_trigger_utils.h"

namespace OHOS {
namespace Media {

std::string MediaLibraryTriggerUtils::BracketVec(const std::vector<AccurateRefresh::PhotoAssetChangeData>& values,
    const std::string& wrapper)
{
    std::stringstream ss;
    ss << "(";
    for (size_t i = 0; i < values.size(); i++) {
        ss << wrapper << values[i].ToString() << wrapper;
        if (i + 1 < values.size()) {
            ss << ", ";
        }
    }
    ss << ")";
    return ss.str();
}

bool MediaLibraryTriggerUtils::CheckResultSet(std::shared_ptr<NativeRdb::ResultSet> &resultSet)
{
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Input resultset is nullptr");
        return false;
    }
    int count = 0;
    int ret = resultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Failed to get resultset row count, ret: %{public}d", ret);
        return false;
    }
    if (count <= 0) {
        MEDIA_ERR_LOG("Failed to get count, count: %{public}d", count);
        return false;
    }
    ret = resultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Failed to go to first row, ret: %{public}d", ret);
        return false;
    }
    return true;
}

std::string MediaLibraryTriggerUtils::WrapQuotation(const std::string& s)
{
    return "'" + s + "'";
}
} // namespace Media
} // namespace OHOS