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
#ifndef ANALYSIS_ALBUM_BATCH_UPDATE_HELPER_H
#define ANALYSIS_ALBUM_BATCH_UPDATE_HELPER_H

#include <vector>
#include <string>
#include <unordered_map>
#include <memory>


#include "accurate_common_data.h"
#include "medialibrary_rdb_utils.h"
#include "rdb_store.h"
#include "values_bucket.h"

namespace OHOS {
namespace Media {
namespace AccurateRefresh {

// 批量更新结构
struct BatchUpdateItem {
    int32_t albumId {INVALID_INT32_VALUE};
    bool shouldUpdateCount {false};
    bool shouldUpdateCover {false};
    int32_t newCount {INVALID_INT32_VALUE};
    std::string newCover;
    int32_t albumSubType;
};

// 支持分片批量更新
class AnalysisAlbumBatchUpdateHelper {
public:
    static bool BuildCaseSql(const std::vector<BatchUpdateItem> &items, std::string &sql,
        std::vector<NativeRdb::ValueObject> &bindArgs);
};


} // namespace AccurateRefresh
} // namespace Media
} // namespace OHOS
#endif // ANALYSIS_ALBUM_BATCH_UPDATE_HELPER_H
