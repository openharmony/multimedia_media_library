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

#ifndef OHOS_MEDIALIBRARY_BUNDLEPERMM_OPERATIONS_H
#define OHOS_MEDIALIBRARY_BUNDLEPERMM_OPERATIONS_H

#include <vector>

#include "datashare_values_bucket.h"
#include "medialibrary_command.h"
#include "values_bucket.h"
#include "medialibrary_rdb_transaction.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
using namespace OHOS::DataShare;
class UriPermissionOperations {
public:
    EXPORT static int32_t GetUriPermissionMode(const std::string &fileId, const std::string &bundleName,
        int32_t tableType, std::string &mode);
    EXPORT static int32_t CheckUriPermission(const std::string &fileUri, std::string mode);
    EXPORT static int32_t HandleUriPermOperations(MediaLibraryCommand &cmd);
    EXPORT static int32_t HandleUriPermInsert(MediaLibraryCommand &cmd);
    EXPORT static int32_t InsertBundlePermission(const int32_t &fileId, const std::string &bundleName,
        const std::string &mode, const std::string &tableName);
    EXPORT static int32_t DeleteBundlePermission(const std::string &fileId, const std::string &bundleName,
        const std::string &tableName);
    EXPORT static int32_t UpdateOperation(MediaLibraryCommand &cmd,
        std::shared_ptr<TransactionOperations> trans = nullptr);
    EXPORT static int32_t InsertOperation(MediaLibraryCommand &cmd);
    EXPORT static int32_t BatchInsertOperation(MediaLibraryCommand &cmd,
        std::vector<NativeRdb::ValuesBucket> &values,
        std::shared_ptr<TransactionOperations> trans = nullptr);
    EXPORT static int32_t DeleteOperation(MediaLibraryCommand &cmd);
    EXPORT static int32_t GrantUriPermission(MediaLibraryCommand &cmd,
        const std::vector<DataShareValuesBucket> &values);
    EXPORT static void DeleteAllTemporaryAsync();
};
} // Media
} // OHOS
#endif // OHOS_MEDIALIBRARY_BUNDLEPERMM_OPERATIONS_H