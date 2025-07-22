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
constexpr size_t SQL_BATCH_SIZE = 1000;
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
    std::optional<std::string> aesthetics_all_version;
    std::optional<int32_t> aesthetics_score_all;
    std::optional<int32_t> is_filtered_hard;
    std::optional<double> clarity_score_all;
    std::optional<double> saturation_score_all;
    std::optional<double> luminance_score_all;
    std::optional<double> semantics_score;
    std::optional<int32_t> is_black_white_stripe;
    std::optional<int32_t> is_blurry;
    std::optional<int32_t> is_mosaic;
};

class BeautyScoreClone {
public:
    BeautyScoreClone(
        const std::shared_ptr<NativeRdb::RdbStore>& sourceRdb,
        const std::shared_ptr<NativeRdb::RdbStore>& destRdb,
        const std::unordered_map<int32_t, PhotoInfo>& photoInfoMap,
        const int64_t maxBeautyFileId);

    bool CloneBeautyScoreInfo();

    int64_t GetMigratedScoreCount() const { return migrateScoreNum_; }
    int64_t GetMigratedFileCount() const { return migrateScoreFileNumber_; }
    int64_t GetTotalTimeCost() const { return migrateScoreTotalTimeCost_; }

private:
    bool CloneBeautyScoreInBatches(const std::vector<int32_t>& oldFileIds,
        const std::vector<std::string>& commonColumns);
    std::vector<BeautyScoreTbl> QueryBeautyScoreTbl(const std::string &fileIdClause,
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
    void UpdateTotalTblBeautyScoreStatus(std::shared_ptr<NativeRdb::RdbStore> rdbStore,
        const std::vector<int32_t>& newFileIds);
    void UpdateTotalTblBeautyScoreAllStatus(std::shared_ptr<NativeRdb::RdbStore> rdbStore,
        const std::vector<int32_t>& newFileIds);
    std::unordered_map<int32_t, int32_t> QueryBeautyScoreMap(shared_ptr<NativeRdb::RdbStore> rdbStore,
        const std::string& sql, const std::string& keyColumnName, const std::string& valueColumnName);
    std::unordered_map<int32_t, int32_t> QueryScoresForColumnInBatches(
        std::shared_ptr<NativeRdb::RdbStore> oldRdbStore, const std::vector<int32_t>& fileIdOld,
        const std::string& scoreColumnName);
    void ApplyScoreUpdatesToNewDb(std::shared_ptr<NativeRdb::RdbStore> newRdbStore,
        const std::unordered_map<int32_t, int32_t>& oldFileIdToScoreMap, const std::string& scoreColumnName);
    void UpdateAnalysisTotalTblForScoreColumn(std::shared_ptr<NativeRdb::RdbStore> newRdbStore,
        std::shared_ptr<NativeRdb::RdbStore> oldRdbStore, const std::vector<int32_t>& fileIdOld,
        const std::string& scoreColumnName);
    void UpdateAnalysisTotalTblBeautyScore(std::shared_ptr<NativeRdb::RdbStore> newRdbStore,
        std::shared_ptr<NativeRdb::RdbStore> oldRdbStore, const std::vector<int32_t>& fileIdNew,
        const std::vector<int32_t>& fileIdOld);
    void UpdateAnalysisTotalTblBeautyScoreAll(std::shared_ptr<NativeRdb::RdbStore> newRdbStore,
        std::shared_ptr<NativeRdb::RdbStore> oldRdbStore, const std::vector<int32_t>& fileIdNew,
        const std::vector<int32_t>& fileIdOld);

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

    template<typename T, typename U>
    void PutWithDefault(NativeRdb::ValuesBucket& values, const std::string& columnName,
        const std::optional<T>& optionalValue, const U& defaultValue);

private:
    std::shared_ptr<NativeRdb::RdbStore> sourceRdb_;
    std::shared_ptr<NativeRdb::RdbStore> destRdb_;
    const std::unordered_map<int32_t, PhotoInfo>& photoInfoMap_;
    int64_t maxBeautyFileId_ {0};

    int64_t migrateScoreNum_ = 0;
    int64_t migrateScoreFileNumber_ = 0;
    int64_t migrateScoreTotalTimeCost_ = 0;
};

template<typename T, typename U>
void BeautyScoreClone::PutWithDefault(NativeRdb::ValuesBucket& values, const std::string& columnName,
    const std::optional<T>& optionalValue, const U& defaultValue)
{
    if (optionalValue.has_value()) {
        PutIfPresent(values, columnName, optionalValue);
    } else {
        PutIfPresent(values, columnName, std::optional<U>(defaultValue));
    }
}
} // namespace Media
} // namespace OHOS

#endif // BEAUTY_SCORE_CLONE_H