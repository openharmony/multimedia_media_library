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

#ifndef FRAMEWORKS_INNERKITSIMPL_MEDIALIBRARY_DATA_ABILITY_INCLUDE_MEDIALIBRARY_QUERY_OPERATIONS_H_
#define FRAMEWORKS_INNERKITSIMPL_MEDIALIBRARY_DATA_ABILITY_INCLUDE_MEDIALIBRARY_QUERY_OPERATIONS_H_

#include <string>

#include "data_ability_predicates.h"
#include "media_data_ability_const.h"
#include "medialibrary_query_db.h"
#include "rdb_store.h"

namespace OHOS {
namespace Media {
struct QueryData {
    std::string strQueryCondition;
    NativeRdb::DataAbilityPredicates predicates;
    std::string columns;
    std::string networkId;
};
class MediaLibraryQueryOperations {
public:
    static std::shared_ptr<NativeRdb::AbsSharedResultSet> HandleQueryOperations(const std::string &oprn,
        const QueryData &queryData, const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);

    static std::shared_ptr<NativeRdb::AbsSharedResultSet> HandleMediaVolume(
        const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
        const MediaLibraryQueryDb &queryDb);

private:
    static std::shared_ptr<NativeRdb::AbsSharedResultSet> QueryMediaVolumeInfoUtil(
        const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
        const MediaLibraryQueryDb &queryDb);
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_MEDIALIBRARY_DATA_ABILITY_INCLUDE_MEDIALIBRARY_QUERY_OPERATIONS_H_
