/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIALIBRARY_URI_SENSITIVE_OPERATIONS_H
#define OHOS_MEDIALIBRARY_URI_SENSITIVE_OPERATIONS_H

#include <vector>
#include <string>

#include "datashare_values_bucket.h"
#include "medialibrary_command.h"
#include "values_bucket.h"
#include "rdb_predicates.h"
#include "medialibrary_rdb_transaction.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
using namespace OHOS::DataShare;
class UriSensitiveOperations {
public:
    EXPORT static int32_t UpdateOperation(MediaLibraryCommand &cmd,
        NativeRdb::RdbPredicates &rdbPredicate, std::shared_ptr<TransactionOperations> trans = nullptr);
    EXPORT static int32_t InsertOperation(MediaLibraryCommand &cmd);
    EXPORT static int32_t BatchInsertOperation(MediaLibraryCommand &cmd,
        const std::vector<NativeRdb::ValuesBucket> &values,
        std::shared_ptr<TransactionOperations> trans = nullptr);
    EXPORT static int32_t DeleteOperation(MediaLibraryCommand &cmd);
    EXPORT static int32_t GrantUriSensitive(MediaLibraryCommand &cmd,
        const std::vector<DataShareValuesBucket> &values);
    EXPORT static void DeleteAllSensitiveAsync();
    EXPORT static int32_t QuerySensitiveType(const uint32_t &tokenId,
        const std::string &fileId);
    EXPORT static bool QueryForceSensitive(const uint32_t &tokenId,
        const std::string &fileId);
};
} // Media
} // OHOS
#endif // OHOS_MEDIALIBRARY_URI_SENSITIVE_OPERATIONS_H