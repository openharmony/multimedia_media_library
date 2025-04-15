/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef MEDIALIBRARY_FORMMAP_OPERATIONS_H
#define MEDIALIBRARY_FORMMAP_OPERATIONS_H

#include <memory>
#include <shared_mutex>
#include <string>
#include <vector>
#include <mutex>

#include "abs_shared_result_set.h"
#include "file_asset.h"
#include "medialibrary_asset_operations.h"
#include "medialibrary_command.h"
#include "rdb_predicates.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
using namespace OHOS::NativeRdb;
class MediaLibraryFormMapOperations : public MediaLibraryAssetOperations {
public:
    EXPORT static int32_t RemoveFormIdOperations(RdbPredicates &predicates);
    EXPORT static int32_t HandleStoreFormIdOperation(MediaLibraryCommand &cmd);
    EXPORT static void PublishedChange(const std::string newUri, const std::vector<int64_t> &formIds,
        const bool &isSave);
    EXPORT static void GetFormMapFormId(const std::string &uri, std::vector<int64_t> &formIds);
    EXPORT static void GetFormIdsByUris(const std::vector<std::string> &notifyUris,
        std::vector<int64_t> &formIds);
    EXPORT static std::string GetUriByFileId(const int32_t &fileId, const std::string &path);
    EXPORT static std::string GetFilePathById(const std::string &fileId);

private:
    EXPORT static void ModifyFormMapMessage(const std::string &uri, const int64_t &formId, const bool &isSave);
    EXPORT static bool CheckQueryIsInDb(const OperationObject &operationObject, const std::string &queryId);
    EXPORT static std::mutex mutex_;
};
} // namespace Media
} // namespace OHOS
#endif // MEDIALIBRARY_FORMMAP_OPERATIONS_H