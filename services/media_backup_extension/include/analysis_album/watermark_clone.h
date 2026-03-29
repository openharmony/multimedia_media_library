/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef WATER_MARK_CLONE_H
#define WATER_MARK_CLONE_H

#include <optional>
#include <type_traits>
#include <string>

#include "backup_const.h"
#include "rdb_store.h"

namespace OHOS::Media {
using IdSetPair = std::pair<std::unordered_set<int32_t>, std::unordered_set<int32_t>>;
struct AnalysisWaterMarkTbl {
    std::optional<int32_t> fileId;
    std::optional<int32_t> status;
    std::optional<int32_t> type;
    std::optional<double> valid_region_x;
    std::optional<double> valid_region_y;
    std::optional<double> valid_region_width;
    std::optional<double> valid_region_height;
    std::optional<std::string> algo_version;
};

class WaterMarkClone {
public:
    WaterMarkClone(
        const std::shared_ptr<NativeRdb::RdbStore>& sourceRdb,
        const std::shared_ptr<NativeRdb::RdbStore>& destRdb,
        const std::unordered_map<int32_t, PhotoInfo>& photoInfoMap);

    bool Clone();

    int64_t GetMigratedWaterCount() const { return migrateWaterMarkNum_; }
    int64_t GetTotalTimeCost() const { return migrateWaterMarkTotalTimeCost_; }

private:
    std::vector<AnalysisWaterMarkTbl> QueryAnalysisWaterMarkTbl(const std::string& fileIdClause,
        const std::vector<std::string>& commonColumns);

    void ParseAnalysisWaterMarkResultSet(const std::shared_ptr<NativeRdb::ResultSet>& resultSet,
        AnalysisWaterMarkTbl& analysisWaterMarkTbl);

    void ProcessWaterMarkTbls(std::vector<AnalysisWaterMarkTbl>& waterMarkTbls);

    void BatchInsertWaterMark(const std::vector<AnalysisWaterMarkTbl>& waterMarkTbls);

    NativeRdb::ValuesBucket CreateValuesBucketFromWaterMarkTbl(const AnalysisWaterMarkTbl& waterMarkTbl);

    int32_t BatchInsertWithRetry(const std::string& tableName,
        std::vector<NativeRdb::ValuesBucket>& values, int64_t& rowNum);

    bool ShouldClone(const std::string& fileIdOldInClause, int64_t start);

    template<typename T>
    void PutIfPresent(NativeRdb::ValuesBucket& values, const std::string& columnName,
        const std::optional<T>& optionalValue)
    {
        if (optionalValue.has_value()) {
            if constexpr (std::is_same_v<std::decay_t<T>, int32_t>) {
                values.PutInt(columnName, optionalValue.value());
            } else if constexpr (std::is_same_v<std::decay_t<T>, int64_t>) {
                values.PutLong(columnName, optionalValue.value());
            } else if constexpr (std::is_same_v<std::decay_t<T>, std::string>) {
                values.PutString(columnName, optionalValue.value());
            } else if constexpr (std::is_same_v<std::decay_t<T>, double>) {
                values.PutDouble(columnName, optionalValue.value());
            }
        }
    }

private:
    std::shared_ptr<NativeRdb::RdbStore> sourceRdb_;
    std::shared_ptr<NativeRdb::RdbStore> destRdb_;
    const std::unordered_map<int32_t, PhotoInfo>& photoInfoMap_;

    int64_t migrateWaterMarkNum_ = 0;
    int64_t migrateWaterMarkTotalTimeCost_ = 0;
};
} // namespace OHOS::Media
#endif // WATER_MARK_CLONE_H