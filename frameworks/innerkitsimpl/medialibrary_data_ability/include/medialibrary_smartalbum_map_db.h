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

#ifndef OHOS_MEDIALIBRARY_SMARTALBUMMAP_DB_H
#define OHOS_MEDIALIBRARY_SMARTALBUMMAP_DB_H

#include <string>
#include "media_data_ability_const.h"
#include "media_log.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "sys/stat.h"

namespace OHOS {
namespace Media {
using namespace OHOS::NativeRdb;
using namespace std;

class MediaLibrarySmartAlbumMapDb {
public:
    MediaLibrarySmartAlbumMapDb() = default;
    ~MediaLibrarySmartAlbumMapDb() = default;
    int32_t DeleteSmartAlbumMapInfo(const int32_t albumId, const shared_ptr<RdbStore> &rdbStore);
    int32_t UpdateSmartAlbumMapInfo(const ValuesBucket &values, const shared_ptr<RdbStore> &rdbStore);
    int64_t InsertSmartAlbumMapInfo(const ValuesBucket &values, const shared_ptr<RdbStore> &rdbStore);
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_SMARTALBUMMAP_DB_H
