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

#ifndef OHOS_MEDIALIBRARY_ALBUM_OPERATIONS_H
#define OHOS_MEDIALIBRARY_ALBUM_OPERATIONS_H

#include <string>
#include <variant>
#include <grp.h>
#include <securec.h>
#include <unistd.h>

#include "album_asset.h"
#include "media_data_ability_const.h"
#include "medialibrary_album_db.h"
#include "medialibrary_data_ability_utils.h"
#include "rdb_store.h"
#include "values_bucket.h"

namespace OHOS {
namespace Media {
class MediaLibraryAlbumOperations {
public:
    int32_t HandleAlbumOperations(const std::string &uri, const NativeRdb::ValuesBucket &values,
                                  const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
    void ChangeGroupToMedia(const std::string &path);
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_ALBUM_OPERATIONS_H