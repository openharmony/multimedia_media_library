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

#ifndef FRAMEWORKS_INNERKITSIMPL_MEDIALIBRARY_DATA_ABILITY_INCLUDE_MEDIALIBRARY_DIR_DB_H_
#define FRAMEWORKS_INNERKITSIMPL_MEDIALIBRARY_DATA_ABILITY_INCLUDE_MEDIALIBRARY_DIR_DB_H_

#include <string>
#include "medialibrary_db_const.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "sys/stat.h"

namespace OHOS {
namespace Media {
using namespace OHOS::NativeRdb;
using namespace std;

class MediaLibraryDirDb {
public:
    MediaLibraryDirDb() = default;
    ~MediaLibraryDirDb() = default;
    int32_t DeleteDirInfo(const int32_t dirId, const shared_ptr<RdbStore> &rdbStore);
};
} // namespace Media
} // namespace OHOS

#endif  // FRAMEWORKS_INNERKITSIMPL_MEDIALIBRARY_DATA_ABILITY_INCLUDE_MEDIALIBRARY_DIR_DB_H_
