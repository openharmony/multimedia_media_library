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

#include "medialibrary_rdbstore.h"
#include "rdb_predicates.h"
#include "rdb_store.h"
#include "userfile_manager_types.h"
#include "datashare_values_bucket.h"
namespace OHOS::Media {
#define EXPORT __attribute__ ((visibility ("default")))

enum NotifyAlbumType : uint16_t {
    NO_NOTIFY = 0x00,
    SYS_ALBUM = 0x01,
    SYS_ALBUM_HIDDEN = 0X02,
    USER_ALBUM = 0X04,
    SOURCE_ALBUM = 0X08,
    ANA_ALBUM = 0X10,
};

struct AlbumCounts {
    int count;
    int hiddenCount;
    int imageCount;
    int videoCount;
};

class MediaLibraryRdbUtils {
public:
    EXPORT static void UpdateSystemAlbumInternal(const std::shared_ptr<MediaLibraryRdbStore> rdbStore,
        const std::vector<std::string> &subtypes = {}, bool shouldNotify = false);
    EXPORT static void UpdateUserAlbumInternal(const std::shared_ptr<MediaLibraryRdbStore> rdbStore,
        const std::vector<std::string> &userAlbumIds = {}, bool shouldNotify = false);
    EXPORT static void UpdateSourceAlbumInternal(const std::shared_ptr<MediaLibraryRdbStore> rdbStore,
        const std::vector<std::string> &sourceAlbumIds = {}, bool shouldNotify = false);
    static void UpdateUserAlbumByUri(const std::shared_ptr<MediaLibraryRdbStore> rdbStore,
        const std::vector<std::string> &uris, bool shouldNotify = false);
    EXPORT static void UpdateAnalysisAlbumByUri(const std::shared_ptr<MediaLibraryRdbStore> rdbStore,
        const std::vector<std::string> &uris);
    static void UpdateSourceAlbumByUri(const std::shared_ptr<MediaLibraryRdbStore> rdbStore,
        const std::vector<std::string> &uris, bool shouldNotify = false);

    static void AddQueryFilter(NativeRdb::AbsRdbPredicates &predicates);
    EXPORT static void UpdateSysAlbumHiddenState(const std::shared_ptr<MediaLibraryRdbStore> rdbStore,
        const std::vector<std::string> &subtypes = {});
    EXPORT static void UpdateAnalysisAlbumInternal(const std::shared_ptr<MediaLibraryRdbStore> rdbStore,
        const std::vector<std::string> &userAlbumIds = {}, const std::vector<std::string> &fileIds = {});
    EXPORT static void UpdateAnalysisAlbumByFile(const std::shared_ptr<MediaLibraryRdbStore> rdbStore,
        const std::vector<std::string> &fileIds, const std::vector<int> &albumTypes);
    EXPORT static void UpdateAllAlbums(std::shared_ptr<MediaLibraryRdbStore> rdbStore,
        const std::vector<std::string> &uris = {}, NotifyAlbumType type = NotifyAlbumType::NO_NOTIFY,
        bool isBackUpAndRestore = false);

    EXPORT static int32_t RefreshAllAlbums(const std::shared_ptr<MediaLibraryRdbStore> rdbStore,
        std::function<void(PhotoAlbumType, PhotoAlbumSubType, int)> refreshProcessHandler,
        std::function<void()> refreshCallback);
    EXPORT static int32_t IsNeedRefreshByCheckTable(const std::shared_ptr<MediaLibraryRdbStore> rdbStore,
        bool &signal);

    EXPORT static void UpdateSystemAlbumCountInternal(const std::shared_ptr<MediaLibraryRdbStore> rdbStore,
        const std::vector<std::string> &subtypes = {});
    EXPORT static void UpdateUserAlbumCountInternal(const std::shared_ptr<MediaLibraryRdbStore> rdbStore,
        const std::vector<std::string> &userAlbumIds = {});
    EXPORT static void UpdateAnalysisAlbumCountInternal(const std::shared_ptr<MediaLibraryRdbStore> rdbStore,
        const std::vector<std::string> &subtypes = {});
    EXPORT static void UpdateAllAlbumsForCloud(const std::shared_ptr<MediaLibraryRdbStore> rdbStore);
    EXPORT static void UpdateAllAlbumsCountForCloud(const std::shared_ptr<MediaLibraryRdbStore> rdbStore);

    EXPORT static bool IsNeedRefreshAlbum();
    EXPORT static void SetNeedRefreshAlbum(bool isNeedRefresh);
    EXPORT static bool IsInRefreshTask();
    EXPORT static int32_t GetAlbumIdsForPortrait(const std::shared_ptr<MediaLibraryRdbStore> rdbStore,
        std::vector<std::string> &portraitAlbumIds);
    EXPORT static int32_t GetAlbumSubtypeArgument(const NativeRdb::RdbPredicates &predicates);
    EXPORT static void AddVirtualColumnsOfDateType(std::vector<std::string>& columns);
    EXPORT static void AddQueryIndex(NativeRdb::AbsPredicates& predicates, const std::vector<std::string>& columns);
    EXPORT static bool HasDataToAnalysis(const std::shared_ptr<MediaLibraryRdbStore> rdbStore);
    EXPORT static int32_t UpdateTrashedAssetOnAlbum(const std::shared_ptr<MediaLibraryRdbStore> rdbStore,
        NativeRdb::RdbPredicates &predicates);
    EXPORT static int32_t UpdateOwnerAlbumId(const std::shared_ptr<MediaLibraryRdbStore> rdbStore,
        const std::vector<DataShare::DataShareValuesBucket> &values, std::vector<int32_t> &updateIds);
    EXPORT static int32_t UpdateRemovedAssetToTrash(const std::shared_ptr<MediaLibraryRdbStore> rdbStore,
        const std::vector<std::string> &whereIdArgs);
    EXPORT static int32_t UpdateThumbnailRelatedDataToDefault(const std::shared_ptr<MediaLibraryRdbStore> rdbStore,
        const int64_t fileId);
    EXPORT static void TransformAppId2TokenId(const std::shared_ptr<MediaLibraryRdbStore> &store);

private:
    static std::atomic<bool> isNeedRefreshAlbum;
    static std::atomic<bool> isInRefreshTask;
    static std::mutex sRefreshAlbumMutex_;
};
} // namespace OHOS::Media
#endif // OHOS_MEDIALIBRARY_RDB_UTILS_H
