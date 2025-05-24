/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_PHOTO_ASSET_CUSTOM_RECORD_MANAGER_NAPI_H
#define INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_PHOTO_ASSET_CUSTOM_RECORD_MANAGER_NAPI_H

#include <vector>
#include <string>

#include "napi_base_context.h"
#include "napi_error.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "datashare_values_bucket.h"
#include "fetch_file_result_napi.h"
#include "file_asset_napi.h"

namespace OHOS::Media {
#define EXPORT __attribute__ ((visibility ("default")))
class PhotoAssetCustomRecordManager {
public:
    EXPORT PhotoAssetCustomRecordManager() = default;
    EXPORT ~PhotoAssetCustomRecordManager() = default;
    EXPORT static napi_value Init(napi_env env, napi_value exports);

private:
    EXPORT static napi_value Constructor(napi_env env, napi_callback_info info);
    EXPORT static void Destructor(napi_env env, void* nativeObject, void* finalizeHint);

    EXPORT static napi_value JSGetCustomRecordsInstance(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSCreateCustomRecords(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSGetCustomRecords(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSSetCustomRecords(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSRemoveCustomRecords(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSAddShareCount(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSAddLCDJumpCount(napi_env env, napi_callback_info info);

    static thread_local napi_ref constructor_;
private:
    static bool InitUserFileClient(napi_env env, napi_callback_info info);
};

enum class NapiCustromRecordColumns {
    FILE_ID,
    SHARE_COUNT,
    LCD_JUMP_COUNT,
};

class NapiCustromRecordStr {
public:
    static const std::string FILE_ID;
    static const std::string SHARE_COUNT;
    static const std::string LCD_JUMP_COUNT;
};

struct CustomRecordAsyncContext : public NapiError {
    size_t argc;
    napi_value argv[NAPI_ARGC_MAX];
    napi_async_work work;
    napi_deferred deferred;
    napi_ref callbackRef;

    PhotoAssetCustomRecordManager* objectInfo;
    OHOS::DataShare::DataSharePredicates predicates;
    std::vector<OHOS::DataShare::DataShareValuesBucket> valuesBuckets;
    std::vector<std::string> fetchColumn;
    int32_t userId_ = -1;
    ResultNapiType resultNapiType;
    std::vector<uint32_t> fileIds;
    std::vector<uint32_t> failFileIds;
    std::vector<PhotoAssetCustomRecord> updateRecords;
    std::unique_ptr<FetchResult<PhotoAssetCustomRecord>> fetchCustomRecordsResult;
};
}
#endif // INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_PHOTO_ASSET_CUSTOM_RECORD_MANAGER_NAPI_H