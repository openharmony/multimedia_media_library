/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef BEAUTY_SCORE_CLONE_H
#define BEAUTY_SCORE_CLONE_H

#include <string>
#include <vector>
#include <optional>
#include <type_traits>
#include <memory>
#include <unordered_map>
#include <unordered_set>

#include "backup_const.h"
#include "rdb_store.h"


namespace OHOS {
namespace Media {
struct BeautyScoreTbl {
    std::optional<int32_t> id;
    std::optional<int32_t> file_id;
    std::optional<int32_t> aesthetics_score;
    std::optional<std::string> aesthetics_version;
    std::optional<double> prob;
    std::optional<std::string> analysis_version;
    std::optional<int32_t> selected_flag;
    std::optional<std::string> selected_algo_version;
    std::optional<int32_t> selected_status;
    std::optional<int32_t> negative_flag;
    std::optional<std::string> negative_algo_version;
};

class BeautyScoreClone {
public:
    BeautyScoreClone(
        const std::shared_ptr<NativeRdb::RdbStore>& sourceRdb,
        const std::shared_ptr<NativeRdb::RdbStore>& destRdb,
        const std::unordered_map<int32_t, PhotoInfo>& photoInfoMap);

    bool CloneBeautyScoreInfo();

    int64_t GetMigratedScoreCount() const { return migrateScoreNum_; }
    int64_t GetMigratedFileCount() const { return migrateScoreFileNumber_; }
    int64_t GetTotalTimeCost() const { return migrateScoreTotalTimeCost_; }

private:
    std::vector<BeautyScoreTbl> QueryBeautyScoreTbl(int32_t offset, std::string &fileIdClause,
        const std::vector<std::string> &commonColumns);
    void ParseBeautyScoreResultSet(const std::shared_ptr<NativeRdb::ResultSet>& resultSet,
        BeautyScoreTbl& beautyScoreTbl);
    std::vector<BeautyScoreTbl> ProcessBeautyScoreTbls(
        const std::vector<BeautyScoreTbl>& beautyScoreTbls);
    void BatchInsertBeautyScores(const std::vector<BeautyScoreTbl>& beautyScoreTbls);
    NativeRdb::ValuesBucket CreateValuesBucketFromBeautyScoreTbl(
        const BeautyScoreTbl& beautyScoreTbl);
    int32_t BatchInsertWithRetry(const std::string &tableName,
        std::vector<NativeRdb::ValuesBucket> &values, int64_t &rowNum);
    void DeleteExistingBeautyScoreData(const std::vector<int32_t>& newFileIds);
    void UpdateTotalTblBeautyScoreStatus(std::shared_ptr<NativeRdb::RdbStore> rdbStore,
        std::vector<int32_t> newFileIds);

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

    int64_t migrateScoreNum_ = 0;
    int64_t migrateScoreFileNumber_ = 0;
    int64_t migrateScoreTotalTimeCost_ = 0;
};
} // namespace Media
} // namespace OHOS

#endif // BEAUTY_SCORE_CLONE_H