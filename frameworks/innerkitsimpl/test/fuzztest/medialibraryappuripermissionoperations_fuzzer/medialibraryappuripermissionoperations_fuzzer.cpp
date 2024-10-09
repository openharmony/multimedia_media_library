/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "medialibraryappuripermissionoperations_fuzzer.h"

#include <cstdint>
#include <string>
#include <vector>

#include "medialibrary_app_uri_permission_operations.h"
#include "datashare_predicates.h"
#include "media_app_uri_permission_column.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "medialibrary_command.h"
#include "medialibrary_errno.h"
#include "medialibrary_operation.h"
#include "medialibrary_photo_operations.h"
#include "rdb_utils.h"
#include "userfile_manager_types.h"
#include "values_bucket.h"

namespace OHOS {
using namespace std;
using namespace DataShare;
const int32_t PERMISSION_DEFAULT = -1;
const int32_t URI_DEFAULT = 0;
const int32_t BatchInsertNumber = 5;
static inline string FuzzString(const uint8_t *data, size_t size)
{
    return {reinterpret_cast<const char*>(data), size};
}

static inline Media::MediaType FuzzMediaType(const uint8_t *data, size_t size)
{
    uint8_t length = static_cast<uint8_t>(Media::MediaType_FUZZER_LISTS.size());
    if (*data < length) {
        return Media::MediaType_FUZZER_LISTS[*data];
    }
    return Media::MediaType::MEDIA_TYPE_IMAGE;
}

static int FuzzPermissionType(const uint8_t *data, size_t size)
{
    vector<int> vecPermissionType;
    vecPermissionType.assign(Media::AppUriPermissionColumn::PERMISSION_TYPES_ALL.begin(),
        Media::AppUriPermissionColumn::PERMISSION_TYPES_ALL.end());
    vecPermissionType.push_back(PERMISSION_DEFAULT);
    uint8_t length = static_cast<uint8_t>(vecPermissionType.size());
    if (*data < length) {
        return vecPermissionType[*data];
    }
    return Media::AppUriPermissionColumn::PERMISSION_TEMPORARY_READ;
}

static int FuzzUriType(const uint8_t *data, size_t size)
{
    vector<int> vecUriType;
    vecUriType.assign(Media::AppUriPermissionColumn::URI_TYPES_ALL.begin(),
        Media::AppUriPermissionColumn::URI_TYPES_ALL.end());
    vecUriType.push_back(URI_DEFAULT);
    uint8_t length = static_cast<uint8_t>(vecUriType.size());
    if (*data < length) {
        return vecUriType[*data];
    }
    return Media::AppUriPermissionColumn::URI_PHOTO;
}

static int32_t CreatePhotoApi10(Media::MediaType mediaType, const string &displayName)
{
    Media::MediaLibraryCommand cmd(Media::OperationObject::FILESYSTEM_PHOTO, Media::OperationType::CREATE,
        Media::MediaLibraryApi::API_10);
    NativeRdb::ValuesBucket values;
    values.PutString(Media::MediaColumn::MEDIA_NAME, displayName);
    values.PutInt(Media::MediaColumn::MEDIA_TYPE, static_cast<int>(mediaType));
    cmd.SetValueBucket(values);
    int32_t ret = Media::MediaLibraryPhotoOperations::Create(cmd);
    return ret;
}

static void HandleInsertOperationFuzzer(string appId, int32_t photoId, int32_t permissionType, int32_t uriType)
{
    DataShareValuesBucket values;
    values.Put(Media::AppUriPermissionColumn::APP_ID, appId);
    values.Put(Media::AppUriPermissionColumn::FILE_ID, photoId);
    values.Put(Media::AppUriPermissionColumn::PERMISSION_TYPE, permissionType);
    values.Put(Media::AppUriPermissionColumn::URI_TYPE, uriType);
    Media::MediaLibraryCommand cmd(Media::OperationObject::MEDIA_APP_URI_PERMISSION, Media::OperationType::CREATE,
        Media::MediaLibraryApi::API_10);
    NativeRdb::ValuesBucket rdbValue = RdbDataShareAdapter::RdbUtils::ToValuesBucket(values);
    cmd.SetValueBucket(rdbValue);
    Media::MediaLibraryAppUriPermissionOperations::HandleInsertOperation(cmd);
}

static void DeleteOperationFuzzer(string appId, int32_t photoId, int32_t permissionType)
{
    DataSharePredicates predicates;
    predicates.And()->EqualTo(Media::AppUriPermissionColumn::APP_ID, appId);
    predicates.And()->EqualTo(Media::AppUriPermissionColumn::FILE_ID, photoId);
    predicates.And()->EqualTo(Media::AppUriPermissionColumn::PERMISSION_TYPE, permissionType);
    NativeRdb::RdbPredicates rdbPredicate = RdbDataShareAdapter::RdbUtils::ToPredicates(predicates,
        Media::AppUriPermissionColumn::APP_URI_PERMISSION_TABLE);
    Media::MediaLibraryAppUriPermissionOperations::DeleteOperation(rdbPredicate);
}

static void BatchInsertFuzzer(const uint8_t* data, size_t size)
{
    vector<DataShare::DataShareValuesBucket> dataShareValues;
    for (int32_t i = 0; i < BatchInsertNumber; i++) {
        DataShareValuesBucket value;
        string displayName = FuzzString(data, size);
        int32_t photoId = CreatePhotoApi10(FuzzMediaType(data, size), displayName);
        if (photoId < E_OK) {
            continue;
        }
        string appId = FuzzString(data, size);
        value.Put(Media::AppUriPermissionColumn::APP_ID, appId);
        value.Put(Media::AppUriPermissionColumn::FILE_ID, photoId);
        int32_t permissionType = FuzzPermissionType(data, size);
        value.Put(Media::AppUriPermissionColumn::PERMISSION_TYPE, permissionType);
        int32_t uriType = FuzzUriType(data, size);
        value.Put(Media::AppUriPermissionColumn::URI_TYPE, uriType);
        dataShareValues.push_back(value);
    }
    Media::MediaLibraryCommand cmd(Media::OperationObject::MEDIA_APP_URI_PERMISSION, Media::OperationType::CREATE,
        Media::MediaLibraryApi::API_10);
    Media::MediaLibraryAppUriPermissionOperations::BatchInsert(cmd, dataShareValues);
}

static void AppUriPermissionOperationsFuzzer(const uint8_t* data, size_t size)
{
    string displayName = FuzzString(data, size);
    int32_t photoId = CreatePhotoApi10(FuzzMediaType(data, size), displayName);
    if (photoId < E_OK) {
        return;
    }
    string appId = FuzzString(data, size);
    int32_t permissionType = FuzzPermissionType(data, size);
    int32_t uriType = FuzzUriType(data, size);

    HandleInsertOperationFuzzer(appId, photoId, permissionType, uriType);
    DeleteOperationFuzzer(appId, photoId, permissionType);
    BatchInsertFuzzer(data, size);
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::AppUriPermissionOperationsFuzzer(data, size);
    return 0;
}
