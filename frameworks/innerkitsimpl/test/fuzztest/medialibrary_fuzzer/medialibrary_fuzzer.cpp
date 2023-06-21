/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "medialibrary_fuzzer.h"
#include <fcntl.h>
#include <vector>
#include "foundation/ability/ability_runtime/interfaces/kits/native/appkit/ability_runtime/context/context.h"
#include "datashare_helper.h"
#include "file_access_extension_info.h"
#include "file_access_framework_errno.h"
#include "file_access_helper.h"
#include "file_filter.h"
#include "iservice_registry.h"
#include "medialibrary_errno.h"
#include "media_library_manager.h"
#include "media_log.h"
#include "result_set_utils.h"
#include "scanner_utils.h"

using namespace OHOS;
using namespace OHOS::FileAccessFwk;
namespace OHOS {
namespace MediaLibrary {
bool InsertFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return false;
    }

    int32_t systemAbilityId = *(reinterpret_cast<const int32_t *>(data));
    Uri insertFileUri(std::string(reinterpret_cast<const char*>(data), size));
    std::string dataUri(std::string(reinterpret_cast<const char*>(data), size));
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket value;
    std::string selections = std::string(reinterpret_cast<const char*>(data), size);
    predicates.SetWhereClause(selections);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        return false;
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    if (remoteObj == nullptr) {
        return false;
    }
    auto helper = DataShare::DataShareHelper::Creator(remoteObj, dataUri);
    if (helper == nullptr) {
        return false;
    }
    helper->Insert(insertFileUri, value);
    return true;
}

bool MediaLibraryFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return false;
    }

    int32_t systemAbilityId = *(reinterpret_cast<const int32_t *>(data));
    Uri queryFileUri(std::string(reinterpret_cast<const char*>(data), size));
    std::string dataUri(std::string(reinterpret_cast<const char*>(data), size));
    DataShare::DataSharePredicates predicates;
    std::string selections = std::string(reinterpret_cast<const char*>(data), size);
    std::vector<string> columns;
    predicates.SetWhereClause(selections);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        return false;
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    if (remoteObj == nullptr) {
        return false;
    }
    auto helper = DataShare::DataShareHelper::Creator(remoteObj, dataUri);
    if (helper == nullptr) {
        return false;
    }
    helper->Query(queryFileUri, predicates, columns);
    return true;
}

bool DeleteFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return false;
    }

    int32_t systemAbilityId = *(reinterpret_cast<const int32_t *>(data));
    Uri deleteFileUri(std::string(reinterpret_cast<const char*>(data), size));
    std::string dataUri(std::string(reinterpret_cast<const char*>(data), size));
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket value;
    std::string selections = std::string(reinterpret_cast<const char*>(data), size);
    predicates.SetWhereClause(selections);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        return false;
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    if (remoteObj == nullptr) {
        return false;
    }
    auto helper = DataShare::DataShareHelper::Creator(remoteObj, dataUri);
    if (helper == nullptr) {
        return false;
    }
    helper->Delete(deleteFileUri, predicates);
    return true;
}

bool UpdateFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return false;
    }

    int32_t systemAbilityId = *(reinterpret_cast<const int32_t *>(data));
    Uri updateFileUri(std::string(reinterpret_cast<const char*>(data), size));
    std::string dataUri(std::string(reinterpret_cast<const char*>(data), size));
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket value;
    std::string selections = std::string(reinterpret_cast<const char*>(data), size);
    predicates.SetWhereClause(selections);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        return false;
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    if (remoteObj == nullptr) {
        return false;
    }
    auto helper = DataShare::DataShareHelper::Creator(remoteObj, dataUri);
    if (helper == nullptr) {
        return false;
    }
    helper->Update(updateFileUri, predicates, value);
    return true;
}

bool BatchInsertFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return false;
    }

    int32_t systemAbilityId = *(reinterpret_cast<const int32_t *>(data));
    Uri batchInsertFileUri(std::string(reinterpret_cast<const char*>(data), size));
    std::string dataUri(std::string(reinterpret_cast<const char*>(data), size));
    DataShare::DataSharePredicates predicates;
    std::string selections = std::string(reinterpret_cast<const char*>(data), size);
    std::vector<DataShareValuesBucket> values;
    predicates.SetWhereClause(selections);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        return false;
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    if (remoteObj == nullptr) {
        return false;
    }
    auto helper = DataShare::DataShareHelper::Creator(remoteObj, dataUri);
    if (helper == nullptr) {
        return false;
    }
    helper->BatchInsert(batchInsertFileUri, values);
    return true;
}

bool OpenFileFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return false;
    }

    int32_t systemAbilityId = *(reinterpret_cast<const int32_t *>(data));
    Uri openFileFileUri(std::string(reinterpret_cast<const char*>(data), size));
    std::string dataUri(std::string(reinterpret_cast<const char*>(data), size));
    DataShare::DataSharePredicates predicates;
    std::string selections = std::string(reinterpret_cast<const char*>(data), size);
    std::string mode;
    predicates.SetWhereClause(selections);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        return false;
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    if (remoteObj == nullptr) {
        return false;
    }
    auto helper = DataShare::DataShareHelper::Creator(remoteObj, dataUri);
    if (helper == nullptr) {
        return false;
    }
    helper->OpenFile(openFileFileUri, mode);
    return true;
}

bool GetFileTypesFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return false;
    }

    int32_t systemAbilityId = *(reinterpret_cast<const int32_t *>(data));
    Uri getFileTypesUri(std::string(reinterpret_cast<const char*>(data), size));
    std::string dataUri(std::string(reinterpret_cast<const char*>(data), size));
    DataShare::DataSharePredicates predicates;
    std::string selections = std::string(reinterpret_cast<const char*>(data), size);
    std::string mimeTypeFilter;
    predicates.SetWhereClause(selections);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        return false;
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    if (remoteObj == nullptr) {
        return false;
    }
    auto helper = DataShare::DataShareHelper::Creator(remoteObj, dataUri);
    if (helper == nullptr) {
        return false;
    }
    helper->GetFileTypes(getFileTypesUri, mimeTypeFilter);
    return true;
}

bool NotifyChangeFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size <= 0)) {
        return false;
    }

    int32_t systemAbilityId = *(reinterpret_cast<const int32_t *>(data));
    Uri notifyChangeUri(std::string(reinterpret_cast<const char*>(data), size));
    std::string dataUri(std::string(reinterpret_cast<const char*>(data), size));
    DataShare::DataSharePredicates predicates;
    std::string selections = std::string(reinterpret_cast<const char*>(data), size);
    predicates.SetWhereClause(selections);

    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        return false;
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    if (remoteObj == nullptr) {
        return false;
    }
    auto helper = DataShare::DataShareHelper::Creator(remoteObj, dataUri);
    if (helper == nullptr) {
        return false;
    }
    helper->NotifyChange(notifyChangeUri);
    return true;
}
} // namespace StorageManager
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::MediaLibrary::MediaLibraryFuzzTest(data, size);
    OHOS::MediaLibrary::InsertFuzzTest(data, size);
    OHOS::MediaLibrary::DeleteFuzzTest(data, size);
    OHOS::MediaLibrary::UpdateFuzzTest(data, size);
    OHOS::MediaLibrary::BatchInsertFuzzTest(data, size);
    OHOS::MediaLibrary::OpenFileFuzzTest(data, size);
    OHOS::MediaLibrary::GetFileTypesFuzzTest(data, size);
    OHOS::MediaLibrary::NotifyChangeFuzzTest(data, size);
    return 0;
}