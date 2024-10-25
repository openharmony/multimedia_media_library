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

#ifndef FRAMEWORKS_INNERKITSIMPL_MEDIALIBRARY_DATA_ABILITY_INCLUDE_MEDIALIBRARY_DIR_OPERATIONS_H_
#define FRAMEWORKS_INNERKITSIMPL_MEDIALIBRARY_DATA_ABILITY_INCLUDE_MEDIALIBRARY_DIR_OPERATIONS_H_

#include <string>
#include <variant>
#include <grp.h>
#include <securec.h>
#include <unistd.h>
#include <unordered_map>

#include "dir_asset.h"
#include "datashare_values_bucket.h"
#include "medialibrary_command.h"
#include "medialibrary_db_const.h"
#include "rdb_store.h"
#include "rdb_utils.h"
#include "values_bucket.h"


namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
class MediaLibraryDirOperations {
public:
    EXPORT static int32_t HandleDirOperation(MediaLibraryCommand &cmd);
    EXPORT static int32_t CreateDirOperation(MediaLibraryCommand &cmd);
    EXPORT static int32_t TrashDirOperation(MediaLibraryCommand &cmd);
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_MEDIALIBRARY_DATA_ABILITY_INCLUDE_MEDIALIBRARY_DIR_OPERATIONS_H_
