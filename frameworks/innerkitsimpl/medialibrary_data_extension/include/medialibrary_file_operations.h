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

#ifndef OHOS_MEDIALIBRARY_FILE_OPERATIONS_H
#define OHOS_MEDIALIBRARY_FILE_OPERATIONS_H

#include <string>

#include "file_asset.h"
#include "media_data_ability_const.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_file_db.h"
#include "imedia_scanner_client.h"
#include "native_album_asset.h"
#include "rdb_store.h"
#include "values_bucket.h"
#include "datashare_values_bucket.h"
#include "rdb_utils.h"
#include "value_object.h"
#include "medialibrary_thumbnail.h"
#include "datashare_predicates.h"
#include "datashare_abs_result_set.h"
#include "result_set_bridge.h"

namespace OHOS {
namespace Media {
class MediaLibraryFileOperations {
public:
    int32_t HandleCreateAsset(const DataShare::DataShareValuesBucket &values,
                              const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
    int32_t HandleCloseAsset(std::string &actualUri, std::string &srcPath, const DataShare::DataShareValuesBucket &values,
                             const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
    int32_t HandleGetAlbumCapacity(const DataShare::DataShareValuesBucket &values,
                                const std::shared_ptr<RdbStore> &rdbStore);
    int32_t HandleFileOperation(const std::string &oprn, const DataShare::DataShareValuesBucket &values,
                                const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
                                const std::shared_ptr<MediaLibraryThumbnail> &mediaThumbnail);
    int32_t HandleModifyAsset(const std::string &rowNum, const std::string &srcPath,
                              const DataShare::DataShareValuesBucket &values,
                              const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
    int32_t HandleDeleteAsset(const std::string &rowNum, const std::string &srcPath,
                              const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
    int32_t HandleIsDirectoryAsset(const DataShare::DataShareValuesBucket &values,
                                   const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
    DataShare::DataShareValuesBucket UpdateBasicAssetDetails(int32_t mediaType,
                                                    const std::string &fileName,
                                                    const std::string &relPath,
                                                    const std::string &path);
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_FILE_OPERATIONS_H
