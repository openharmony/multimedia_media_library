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

#ifndef CLONE_HIGHLIGHT_SOURCE_H
#define CLONE_HIGHLIGHT_SOURCE_H

#include <string>

#include "location_db_sqls.h"
#include "result_set_utils.h"
#include "rdb_helper.h"
#include "backup_const_column.h"
#include "story_album_column.h"

namespace OHOS {
namespace Media {
enum class InsertType {
    PHOTOS = 0,
    ANALYSIS_ALBUM,
    ANALYSIS_PHOTO_MAP,
    TAB_HIGHLIGHT_ALBUM,
    TAB_HIGHLIGHT_COVER_INFO,
    TAB_HIGHLIGHT_PLAY_INFO,
    TAB_ANALYSIS_ASSET_SD_MAP,
    TAB_ANALYSIS_ALBUM_ASSET_MAP,
    TAB_ANALYSIS_LABEL,
    TAB_ANALYSIS_RECOMMENDATION,
    TAB_ANALYSIS_SALIENCY_DETECT
};

class CloneHighlightSource {
public:
    void Init(const std::string &path, const std::vector<std::string> &tableList);
    void Insert(const std::vector<std::string> &tableList,
        std::shared_ptr<NativeRdb::RdbStore> rdbPtr);
    void InsertByType(InsertType insertType, std::shared_ptr<NativeRdb::RdbStore> rdbPtr);
    void InsertPhoto(std::shared_ptr<NativeRdb::RdbStore> rdbPtr);
    void InsertAnalysisAlbum(std::shared_ptr<NativeRdb::RdbStore> rdbPtr);
    void InsertAnalysisPhotoMap(std::shared_ptr<NativeRdb::RdbStore> rdbPtr);
    void InsertHighlightAlbum(std::shared_ptr<NativeRdb::RdbStore> rdbPtr);
    void InsertHighlightCover(std::shared_ptr<NativeRdb::RdbStore> rdbPtr);
    void InsertHighlightPlayInfo(std::shared_ptr<NativeRdb::RdbStore> rdbPtr);
    void InsertSDMap(std::shared_ptr<NativeRdb::RdbStore> rdbPtr);
    void InsertAlbumMap(std::shared_ptr<NativeRdb::RdbStore> rdbPtr);
    void InsertTabAnalysisLabel(std::shared_ptr<NativeRdb::RdbStore> rdbPtr);
    void InsertTabAnalysisRecommendation(std::shared_ptr<NativeRdb::RdbStore> rdbPtr);
    void InsertTabAnalysisSaliency(std::shared_ptr<NativeRdb::RdbStore> rdbPtr);
    std::shared_ptr<NativeRdb::RdbStore> cloneStorePtr_;
};

class CloneHighlightOpenCall : public NativeRdb::RdbOpenCallback {
public:
    int32_t OnCreate(NativeRdb::RdbStore &rdbStore) override;
    int32_t OnUpgrade(NativeRdb::RdbStore &rdbStore, int oldVersion, int newVersion) override;
    void Init(const std::vector<std::string> &tableList);
    std::vector<std::string> createSqls_;
};
} // namespace Media
} // namespace OHOS
#endif // CLONE_HIGHLIGHT_SOURCE_H