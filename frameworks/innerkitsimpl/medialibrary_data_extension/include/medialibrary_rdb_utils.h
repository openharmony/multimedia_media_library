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

#include <memory>
#include <string>

#include "rdb_store.h"

namespace OHOS::Media {
#define EXPORT __attribute__ ((visibility ("default")))
class MediaLibraryRdbUtils {
public:
    EXPORT static void UpdateSystemAlbumInternal(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
        const std::vector<std::string> &subtypes = {});
    EXPORT static void UpdateUserAlbumInternal(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
        const std::vector<std::string> &userAlbumIds = {});
    EXPORT static void UpdateSourceAlbumInternal(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
        const std::vector<std::string> &sourceAlbumIds = {});

    static void AddQueryFilter(NativeRdb::AbsRdbPredicates &predicates);
    EXPORT static void UpdateHiddenAlbumInternal(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
    EXPORT static void UpdateAnalysisAlbumInternal(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
        const std::vector<std::string> &userAlbumIds = {});
    EXPORT static void UpdateAnalysisAlbumByFile(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
        const std::vector<std::string> &fileIds, const std::vector<int> &albumTypes);
    EXPORT static void UpdateAllAlbums(const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
};
} // namespace OHOS::Media
#endif // OHOS_MEDIALIBRARY_RDB_UTILS_H
