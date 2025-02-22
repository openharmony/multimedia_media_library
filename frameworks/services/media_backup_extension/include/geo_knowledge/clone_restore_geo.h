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

#ifndef CLONE_RESTORE_GEO_H
#define CLONE_RESTORE_GEO_H

#include <string>

#include "backup_const.h"
#include "nlohmann/json.hpp"
#include "rdb_store.h"

namespace OHOS::Media {
class CloneRestoreGeo {
public:
    void Init(int32_t sceneCode, const std::string &taskId,
        std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb, std::shared_ptr<NativeRdb::RdbStore> mediaRdb);
    void RestoreGeoKnowledgeInfos();
    void RestoreMaps(std::vector<FileInfo> &fileInfos);
    void ReportGeoRestoreTask();

    template<typename T>
    static void PutIfPresent(NativeRdb::ValuesBucket& values, const std::string& columnName,
        const std::optional<T>& optionalValue);

    template<typename T>
    static void PutIfInIntersection(NativeRdb::ValuesBucket& values, const std::string& columnName,
        const std::optional<T>& optionalValue, const std::unordered_set<std::string> &intersection);

private:
    struct GeoCloneInfo {
        std::optional<int64_t> locationKey;
        std::optional<std::string> cityId;
        std::optional<std::string> language;
        std::optional<std::string> country;
        std::optional<std::string> adminArea;
        std::optional<std::string> subAdminArea;
        std::optional<std::string> locality;
        std::optional<std::string> subLocality;
        std::optional<std::string> thoroughfare;
        std::optional<std::string> subThoroughfare;
        std::optional<std::string> featureName;
        std::optional<std::string> cityName;
        std::optional<std::string> addressDescription;
        std::optional<std::string> aoi;
        std::optional<std::string> poi;
        std::optional<std::string> firstAoi;
        std::optional<std::string> firstPoi;
        std::optional<std::string> locationVersion;
        std::optional<std::string> firstAoiCategory;
        std::optional<std::string> firstPoiCategory;
        std::optional<std::string> locationType;
        std::optional<double> latitude;
        std::optional<double> longitude;
    };

    struct AnaTotalInfo {
        int32_t geo;
        int32_t fileId;
    };

    void FailUpdate(int32_t errCodeUpdate, int32_t &batchCnt, int32_t &batchAnaCnt);
    void FailUpdateAna(int32_t errCodeUpdateAna, int32_t &batchAnaCnt);
    void GetGeoKnowledgeInfos();
    void GetAnalysisGeoInfos();
    void GetGeoKnowledgeInfo(GeoCloneInfo &info, std::shared_ptr<NativeRdb::ResultSet> resultSet);
    void BatchQueryPhoto(std::vector<FileInfo> &fileInfos);
    void GetMapInsertValue(NativeRdb::ValuesBucket &value, std::vector<GeoCloneInfo>::iterator it,
        const std::unordered_set<std::string> &intersection, int32_t fileId);
    bool CheckTableColumns(const std::string& tableName, std::unordered_map<std::string, std::string>& columns);
    int32_t BatchUpdate(const std::string &tableName, std::vector<std::string> &fileIds);
    int32_t BatchUpdateAna(const std::string &tableName, std::vector<std::string> &analysisIds);
    int32_t BatchInsertWithRetry(const std::string &tableName, std::vector<NativeRdb::ValuesBucket> &values,
        int64_t &rowNum);
    std::string UpdateMapInsertValues(std::vector<NativeRdb::ValuesBucket> &values,
        std::vector<std::string> &analysisIds, const FileInfo &fileInfo, int32_t &batchCnt, int32_t &batchAnaCnt);
    std::string UpdateByGeoLocation(std::vector<NativeRdb::ValuesBucket> &values,
        std::vector<std::string> &analysisIds, const FileInfo &fileInfo, int32_t &batchCnt, int32_t &batchAnaCnt);
    std::unordered_set<std::string> GetCommonColumns(const std::string &tableName);

private:
    int32_t sceneCode_{-1};
    std::string taskId_;
    std::string systemLanguage_{"zh-Hans"};
    std::shared_ptr<NativeRdb::RdbStore> mediaRdb_;
    std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb_;
    std::vector<GeoCloneInfo> geoInfos_;
    std::vector<AnaTotalInfo> anaTotalfos_;
    std::atomic<int32_t> successInsertCnt_{0};
    std::atomic<int32_t> successUpdateCnt_{0};
    std::atomic<int32_t> failInsertCnt_{0};
    std::atomic<int32_t> failUpdateCnt_{0};
};

template<typename T>
void CloneRestoreGeo::PutIfPresent(NativeRdb::ValuesBucket& values, const std::string& columnName,
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

template<typename T>
void CloneRestoreGeo::PutIfInIntersection(NativeRdb::ValuesBucket& values, const std::string& columnName,
    const std::optional<T>& optionalValue, const std::unordered_set<std::string> &intersection)
{
    if (intersection.count(columnName) > 0) {
        PutIfPresent<T>(values, columnName, optionalValue);
        return;
    }
}
} // namespace OHOS::Media
#endif // CLONE_RESTORE_GEO_H