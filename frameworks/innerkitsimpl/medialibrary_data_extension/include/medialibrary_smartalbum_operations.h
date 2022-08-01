/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIALIBRARY_SMARTALBUM_OPERATIONS_H
#define OHOS_MEDIALIBRARY_SMARTALBUM_OPERATIONS_H

#include <string>
#include <variant>
#include <grp.h>
#include <securec.h>
#include <unistd.h>

#include "medialibrary_db_const.h"
#include "medialibrary_smartalbum_db.h"
#include "medialibrary_data_manager_utils.h"
#include "rdb_store.h"
#include "values_bucket.h"

namespace OHOS {
namespace Media {
class MediaLibrarySmartAlbumOperations {
public:
    int32_t HandleSmartAlbumOperations(const std::string &uri,
                                       const NativeRdb::ValuesBucket &values,
                                       const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_SMARTALBUM_OPERATIONS_H
