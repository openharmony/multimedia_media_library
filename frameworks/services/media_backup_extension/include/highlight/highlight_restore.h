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

#ifndef HIGHLIGHT_RESTORE_H
#define HIGHLIGHT_RESTORE_H

#include <mutex>
#include <sstream>
#include <string>

#include "backup_const.h"
#include "nlohmann/json.hpp"
#include "rdb_store.h"

namespace OHOS::Media {
class HighlightRestore {
public:
    void Init(int32_t sceneCode, std::string taskId,
        std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb, std::shared_ptr<NativeRdb::RdbStore> galleryRdb);
    void RestoreAlbums();
    void RestoreMaps(std::vector<FileInfo> &fileInfos);
    void UpdateAlbums();

private:
    struct HighlightAlbumInfo {
        int32_t albumIdOld {-1};
        int32_t albumIdNew {-1};
        int32_t aiAlbumIdNew {-1};
        std::string subTitle;
        std::string albumName;
        int64_t minDateAdded {0};
        int64_t maxDateAdded {0};
        int32_t coverId {-1};
        std::string coverUri;
        int64_t generateTime {0};
        std::string clusterType;
        std::string clusterSubType;
        std::string clusterCondition;
        int32_t highlightStatus {-1};
        int32_t id {-1};
        std::vector<nlohmann::json> effectline;

        std::string ToString() const
        {
            std::stringstream ss;
            ss << "HighlightAlbumInfo["
                << "albumIdOld: " << albumIdOld << ", albumIdNew: " << albumIdNew << ", aiAlbumIdNew: " << aiAlbumIdNew
                << ", subTitle: " << subTitle << ", albumName: " << albumName
                << ", minDateAdded: " << minDateAdded << ", maxDateAdded: " << maxDateAdded
                << ", coverId: " << coverId << ", coverUri: " << coverUri << ", generateTime: " << generateTime
                << ", clusterType: " << clusterType << ", clusterSubType: " << clusterSubType
                << ", clusterCondition: " << clusterCondition
                << ", highlightStatus: " << highlightStatus << ", id: " << id
                << "]";
            return ss.str();
        }
    };

    void GetAlbumInfos();
    bool HasSameHighlightAlbum(HighlightAlbumInfo &info);
    void TransferClusterInfo(HighlightAlbumInfo &info);
    void InsertIntoAnalysisAlbum();
    NativeRdb::ValuesBucket GetAnalysisAlbumValuesBucket(const HighlightAlbumInfo &info, int32_t subType);
    void UpdateAlbumIds();
    void InsertIntoHighlightTables();
    void InsertIntoHighlightAlbum();
    void InsertIntoHighlightCoverAndPlayInfo();
    void UpdateHighlightIds();
    void BatchQueryPhoto(std::vector<FileInfo> &fileInfos);
    void UpdateMapInsertValues(std::vector<NativeRdb::ValuesBucket> &values, const FileInfo &fileInfo);
    void UpdateMapInsertValuesByStoryId(std::vector<NativeRdb::ValuesBucket> &values, const FileInfo &fileInfo,
        const std::string &storyId);
    nlohmann::json GetEffectline(const FileInfo &fileInfo);
    nlohmann::json GetEffectVideoTrack(const std::string &hashCode);
    NativeRdb::ValuesBucket GetMapInsertValue(int32_t albumId, int32_t fileId);
    int32_t BatchInsertWithRetry(const std::string &tableName, std::vector<NativeRdb::ValuesBucket> &values,
        int64_t &rowNum);
    void ReportHighlightRestoreTask();

private:
    int32_t sceneCode_ {-1};
    std::mutex counterMutex_;
    std::string taskId_;
    std::shared_ptr<NativeRdb::RdbStore> galleryRdb_;
    std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb_;
    std::vector<HighlightAlbumInfo> albumInfos_;
    std::unordered_map<std::string, int32_t> albumPhotoCounter_;
    std::atomic<int32_t> successCnt_ {0};
    std::atomic<int32_t> duplicateCnt_ {0};
    std::atomic<int32_t> failCnt_ {0};
    std::atomic<int32_t> tracksParseFailCnt_ {0};
};
} // namespace OHOS::Media

#endif // HIGHLIGHT_RESTORE_H