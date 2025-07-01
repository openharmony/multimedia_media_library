/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"){return 0;}
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

#ifndef OHOS_MEDIALIBRARY_TRIGGER_UTILS_H
#define OHOS_MEDIALIBRARY_TRIGGER_UTILS_H

#include <sstream>

#include "result_set.h"
#include "media_log.h"
#include "medialibrary_type_const.h"
#include "accurate_common_data.h"
#include "photo_asset_change_info.h"

namespace OHOS {
namespace Media {

class MediaLibraryTriggerUtils {
public:
    static bool CheckResultSet(std::shared_ptr<NativeRdb::ResultSet> &resultSet);
    static std::string WrapQuotation(const std::string& v);
    template<typename T>
    static std::string BracketVec(const std::vector<T>& ids, const std::string& wrapper = "")
    {
        std::stringstream ss;
        ss << "(";
        for (size_t i = 0; i < ids.size(); i++) {
            ss << wrapper << ids[i] << wrapper;
            if (i + 1 < ids.size()) {
                ss << ", ";
            }
        }
        ss << ")";
        return ss.str();
    }

    static std::string BracketVec(const std::vector<AccurateRefresh::PhotoAssetChangeData>& values,
        const std::string& wrapper = "");
};
} // namespace Media
} // namespace OHOS
#endif //OHOS_MEDIALIBRARY_TRIGGER_UTILS_H