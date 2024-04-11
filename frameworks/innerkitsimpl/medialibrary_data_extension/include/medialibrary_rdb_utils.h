/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIALIBRARY_RDB_UTILS_H
#define OHOS_MEDIALIBRARY_RDB_UTILS_H

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <map>

#include "rdb_store.h"
#include "userfile_manager_types.h"
namespace OHOS::Media {
#define EXPORT __attribute__ ((visibility ("default")))

struct AlbumCounts {
    int count;
    int hiddenCount;
    int imageCount;
    int videoCount;
};

class MediaLibraryRdbUtils {
public:
    EXPORT static void UpdateSystemAlbumInternal(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
        const std::vector<std::string> &subtypes = {});
    EXPORT static void UpdateUserAlbumInternal(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
        const std::vector<std::string> &userAlbumIds = {});
    EXPORT static void UpdateSourceAlbumInternal(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
        std::unordered_map<int32_t, int32_t> &updateResult, const std::vector<std::string> &sourceAlbumIds = {});
    static void UpdateUserAlbumByUri(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
        std::unordered_map<int32_t, int32_t> &updateResult, const std::vector<std::string> &uris);
    EXPORT static void UpdateAnalysisAlbumByUri(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
        std::unordered_map<int32_t, int32_t> &updateResult, const std::vector<std::string> &uris);
    static void UpdateSourceAlbumByUri(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
        std::unordered_map<int32_t, int32_t> &updateResult, const std::vector<std::string> &uris);

    static void AddQueryFilter(NativeRdb::AbsRdbPredicates &predicates);
    EXPORT static void UpdateHiddenAlbumInternal(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
        std::unordered_map<int32_t, int32_t> &updateResult);
    EXPORT static void UpdateAnalysisAlbumInternal(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
        std::unordered_map<int32_t, int32_t> &updateResult, const std::vector<std::string> &userAlbumIds = {},
        const std::vector<std::string> &fileIds = {});
    EXPORT static void UpdateAnalysisAlbumByFile(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
        const std::vector<std::string> &fileIds, const std::vector<int> &albumTypes);
    EXPORT static void UpdateAllAlbums(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
        std::unordered_map<int32_t, int32_t> &updateResult, const std::vector<std::string> &uris = {});

    EXPORT static int32_t RefreshAllAlbums(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
        std::function<void(PhotoAlbumType, PhotoAlbumSubType, int)> refreshProcessHandler,
        std::function<void()> refreshCallback);
    EXPORT static int32_t IsNeedRefreshByCheckTable(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
        bool &signal);

    EXPORT static void UpdateSystemAlbumCountInternal(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
        const std::vector<std::string> &subtypes = {});
    EXPORT static void UpdateUserAlbumCountInternal(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
        const std::vector<std::string> &userAlbumIds = {});
    EXPORT static void UpdateAnalysisAlbumCountInternal(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
        const std::vector<std::string> &subtypes = {});
    EXPORT static void UpdateAllAlbumsForCloud(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
    EXPORT static void UpdateAllAlbumsCountForCloud(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);

    EXPORT static bool IsNeedRefreshAlbum();
    EXPORT static void SetNeedRefreshAlbum(bool isNeedRefresh);
    EXPORT static bool IsInRefreshTask();
    EXPORT static int32_t GetAlbumIdsForPortrait(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
        std::vector<std::string> &portraitAlbumIds);
private:
    static std::atomic<bool> isNeedRefreshAlbum;
    static std::atomic<bool> isInRefreshTask;
};
} // namespace OHOS::Media
#endif // OHOS_MEDIALIBRARY_RDB_UTILS_H
