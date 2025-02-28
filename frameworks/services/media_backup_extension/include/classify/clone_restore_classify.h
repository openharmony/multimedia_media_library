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

#ifndef CLONE_RESTORE_CLASSIFY_H
#define CLONE_RESTORE_CLASSIFY_H

#include <string>

#include "backup_const.h"
#include "rdb_store.h"

namespace OHOS::Media {
class CloneRestoreClassify {
public:
    void Init(int32_t sceneCode, const std::string &taskId,
        std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb, std::shared_ptr<NativeRdb::RdbStore> mediaRdb);
    void RestoreClassifyInfos();
    void RestoreMaps(std::vector<FileInfo> &fileInfos);
    void RestoreVideoMaps(std::vector<FileInfo> &fileInfos);
    void ReportClassifyRestoreTask();

    template<typename T>
    static void PutIfPresent(NativeRdb::ValuesBucket& values, const std::string& columnName,
        const std::optional<T>& optionalValue);

    template<typename T>
    static void PutIfInIntersection(NativeRdb::ValuesBucket& values, const std::string& columnName,
        const std::optional<T>& optionalValue, const std::unordered_set<std::string> &intersection);

private:
    struct ClassifyCloneInfo {
        std::optional<int64_t> id;
        std::optional<int64_t> fileId;
        std::optional<int64_t> categoryId;
        std::optional<std::string> subLabel;
        std::optional<double> prob;
        std::optional<std::string> feature;
        std::optional<std::string> simResult;
        std::optional<std::string> labelVersion;
        std::optional<std::string> saliencySubProb;
        std::optional<std::string> analysisVersion;
    };
    struct ClassifyVideoCloneInfo {
        std::optional<int64_t> id;
        std::optional<int64_t> fileId;
        std::optional<std::string> categoryId;
        std::optional<double> confidenceProbability;
        std::optional<std::string> subCategory;
        std::optional<double> subConfidenceProb;
        std::optional<std::string> subLabel;
        std::optional<double> subLabelProb;
        std::optional<int64_t> subLabelType;
        std::optional<std::string> tracks;
        std::optional<std::vector<uint8_t>> videoPartFeature;
        std::optional<std::string> filterTag;
        std::optional<std::string> algoVersion;
        std::optional<std::string> analysisVersion;
        std::optional<int64_t> triggerGenerateThumbnail;
    };

    void GetClassifyInfos(std::shared_ptr<NativeRdb::RdbStore> rdb,
        std::vector<ClassifyCloneInfo> &classifyInfo);
    void GetClassifyVideoInfos(std::shared_ptr<NativeRdb::RdbStore> rdb,
        std::vector<ClassifyVideoCloneInfo> &classifyVideoInfo);
    void UpdateMapInsertValues(std::vector<NativeRdb::ValuesBucket> &values, const FileInfo &fileInfo);
    void UpdateVideoMapInsertValues(std::vector<NativeRdb::ValuesBucket> &values, const FileInfo &fileInfo);

    void GetClassifyInfo(ClassifyCloneInfo &info, std::shared_ptr<NativeRdb::ResultSet> resultSet);
    void GetMapInsertValue(NativeRdb::ValuesBucket &value, std::vector<ClassifyCloneInfo>::iterator it,
        const std::unordered_set<std::string> &intersection, int32_t fileId);
    void GetClassifyVideoInfo(ClassifyVideoCloneInfo &info, std::shared_ptr<NativeRdb::ResultSet> resultSet);
    void GetVideoMapInsertValue(NativeRdb::ValuesBucket &value, std::vector<ClassifyVideoCloneInfo>::iterator it,
        const std::unordered_set<std::string> &intersection, int32_t fileId);

    bool CheckTableColumns(const std::string& tableName, std::unordered_map<std::string, std::string>& columns);
    std::unordered_set<std::string> GetCommonColumns(const std::string &tableName);
    int32_t BatchInsertWithRetry(const std::string &tableName, std::vector<NativeRdb::ValuesBucket> &values,
        int64_t &rowNum);

private:
    int32_t sceneCode_{-1};
    std::string taskId_;
    std::shared_ptr<NativeRdb::RdbStore> mediaRdb_;
    std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb_;
    std::vector<ClassifyCloneInfo> classifyInfos_;
    std::vector<ClassifyCloneInfo> dstClassifyInfos_;
    std::vector<ClassifyVideoCloneInfo> classifyVideoInfos_;
    std::vector<ClassifyVideoCloneInfo> dstClassifyVideoInfos_;
    std::atomic<int32_t> successInsertLabelCnt_{0};
    std::atomic<int32_t> successInsertVideoLabelCnt_{0};
    std::atomic<int32_t> failInsertLabelCnt_{0};
    std::atomic<int32_t> failInsertVideoLabelCnt_{0};
};

template<typename T>
void CloneRestoreClassify::PutIfPresent(NativeRdb::ValuesBucket& values, const std::string& columnName,
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
        } else if constexpr (std::is_same_v<std::decay_t<T>, std::vector<uint8_t>>) {
            values.PutBlob(columnName, optionalValue.value());
        }
    }
}

template<typename T>
void CloneRestoreClassify::PutIfInIntersection(NativeRdb::ValuesBucket& values, const std::string& columnName,
    const std::optional<T>& optionalValue, const std::unordered_set<std::string> &intersection)
{
    if (intersection.count(columnName) > 0) {
        PutIfPresent<T>(values, columnName, optionalValue);
    }
}
} // namespace OHOS::Media
#endif // CLONE_RESTORE_CLASSIFY_H