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

#ifndef CLASSIFY_RESTORE_H
#define CLASSIFY_RESTORE_H

#include <string>

#include "backup_const.h"
#include "rdb_store.h"
#include "classify_aggregate_types.h"
#include "media_library_db_upgrade.h"

namespace OHOS::Media {
class ClassifyRestore {
public:
    void Init(int32_t sceneCode, const std::string &taskId,
        std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb, std::shared_ptr<NativeRdb::RdbStore> galleryRdb);
    void RestoreClassify(const std::unordered_map<int32_t, PhotoInfo> &photoInfoMap);

private:
    struct GalleryLabelInfo {
        int32_t categoryId = -2;
        std::string subLabel;
        double prob = 0;
        std::string version;
        int32_t fileIdOld = -1;
        PhotoInfo photoInfo;
    };

    int32_t BatchInsertWithRetry(const std::string &tableName,
        std::vector<NativeRdb::ValuesBucket> &values, int64_t &rowNum);
    void GetMaxIds();
    void ProcessLabelInfo(const std::shared_ptr<NativeRdb::ResultSet> &resultSet,
        const std::unordered_map<int32_t, PhotoInfo> &photoInfoMap);
    void RestoreLabel(const std::unordered_map<int32_t, PhotoInfo> &photoInfoMap);
    void ReportRestoreTask();
    void TransferLabelInfo(GalleryLabelInfo &info);
    void UpdateLabelInsertValues(std::vector<NativeRdb::ValuesBucket> &values,
        const GalleryLabelInfo &info);
    void UpdateStatus(std::vector<int32_t> &fileIds);
    std::vector<int32_t> ParseSubLabel(const std::string &subLabel) const;
    std::unordered_set<int32_t> GetAggregateTypes(const std::vector<int32_t> &labels) const;
    void CollectAlbumInfo(int32_t fileIdNew, int32_t categoryId, const std::vector<int32_t> &labels);
    int32_t EnsureClassifyAlbumId(const std::string &albumName);
    void DeleteExistingAlbumMappings(int32_t albumId, const std::vector<int32_t> &assetIds);
    void InsertAlbumMappings(std::vector<NativeRdb::ValuesBucket> &values);
    void UpdateAlbumCounts(const std::unordered_set<int32_t> &albumIds);
    void CreateOrUpdateCategoryAlbums();
    void EnsureSpecialAlbums();
    void EnsureSelfieAlbum();
    void EnsureUserCommentAlbum();
    void HandleOcr(const std::unordered_map<int32_t, std::vector<int32_t>> &subLabelMap);
    void HandleOcrHelper(const std::vector<int32_t> &fileIds);
    void AddIdCardAlbum(OcrAggregateType type, std::unordered_set<int32_t> &fileIdsToUpdateSet);
    void ProcessCategoryAlbums();

private:
    int32_t sceneCode_ {-1};
    int32_t maxIdOfLabel_ {0};
    std::atomic<int64_t> restoreTimeCost_ {0};
    std::atomic<int32_t> successInsertLabelCnt_ {0};
    std::atomic<int32_t> failInsertLabelCnt_ {0};
    std::atomic<int32_t> duplicateLabelCnt_ {0};
    std::string taskId_;
    std::shared_ptr<NativeRdb::RdbStore> galleryRdb_;
    std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb_;
    std::unordered_map<std::string, std::unordered_set<int32_t>> albumAssetMap_;
    std::unordered_map<std::string, int32_t> albumIdCache_;

private:
    const std::string QUERY_LABEL_SQL = " \
        SELECT \
            image_collection.category_id, \
            image_collection.sub_label, \
            image_collection.prob, \
            image_collection.version, \
            gallery_media._id \
        FROM \
            image_collection \
        INNER JOIN gallery_media ON image_collection.hash = gallery_media.hash \
        GROUP BY image_collection.hash HAVING gallery_media._id IN (";

    const std::string QUERY_OCR_TEXT_SQL = "SELECT tab_analysis_ocr.file_id FROM tab_analysis_ocr WHERE ";
};
} // namespace OHOS::Media

#endif // CLASSIFY_RESTORE_H