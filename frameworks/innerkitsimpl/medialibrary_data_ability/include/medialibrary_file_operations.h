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
#include "medialibrary_file_db.h"
#include "imedia_scanner_client.h"

#include "rdb_store.h"
#include "values_bucket.h"
#include "value_object.h"

namespace OHOS {
namespace Media {
class MediaLibraryFileOperations {
public:
    int32_t HandleCreateAsset(const OHOS::NativeRdb::ValuesBucket &values,
                              const std::shared_ptr<OHOS::NativeRdb::RdbStore> &rdbStore);
    int32_t HandleCloseAsset(std::string &srcPath, const OHOS::NativeRdb::ValuesBucket &values);
    int32_t HandleOpenAsset(const std::string &srcPath, const OHOS::NativeRdb::ValuesBucket &values);
    int32_t HandleFileOperation(const std::string &uri, const OHOS::NativeRdb::ValuesBucket &values,
                                const std::shared_ptr<OHOS::NativeRdb::RdbStore> &rdbStore);
    int32_t HandleModifyAsset(const std::string &rowNum, const std::string &srcPath,
                              const OHOS::NativeRdb::ValuesBucket &values,
                              const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
    int32_t HandleDeleteAsset(const std::string &rowNum, const std::string &srcPath,
                              const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
    std::string GetRowNum(std::string uri);
};

// Scanner callback objects
class ScanFileCallback : public IMediaScannerAppCallback {
public:
    ScanFileCallback() {}
    ~ScanFileCallback() {}
    void OnScanFinished(const int32_t status, const std::string &uri, const std::string &path) override;
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_FILE_OPERATIONS_H