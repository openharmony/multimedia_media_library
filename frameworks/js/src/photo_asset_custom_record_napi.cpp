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
#define MLOG_TAG "PhotoAssetCustomRecordNapi"

#include "photo_asset_custom_record_napi.h"

#include "media_file_asset_columns.h"
#include "media_library_napi.h"
#include "media_smart_album_column.h"
#include "media_smart_map_column.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_napi_log.h"
#include "medialibrary_tracer.h"
#include "media_file_utils.h"
#include "userfile_client.h"
#include "media_file_uri.h"

using OHOS::HiviewDFX::HiLog;
using OHOS::HiviewDFX::HiLogLabel;

namespace OHOS {
namespace Media {
thread_local PhotoAssetCustomRecord *PhotoAssetCustomRecordNapi::cRecordData_ = nullptr;
thread_local napi_ref PhotoAssetCustomRecordNapi::constructor_ = nullptr;

napi_value PhotoAssetCustomRecordNapi::Init(napi_env env, napi_value exports)
{
    NapiClassInfo info = {
        .name = PHOTO_ASSET_CURSTOM_RECORDS_NAPI_CLASS_NAME,
        .ref = &constructor_,
        .constructor = Constructor,
        .props = {
            DECLARE_NAPI_GETTER("fileId", JSGetFileId),
            DECLARE_NAPI_GETTER("shareCount", JSGetShareCount),
            DECLARE_NAPI_GETTER("lcdJumpCount", JSGetLcdJumpCount),
        }
    };

    MediaLibraryNapiUtils::NapiDefineClass(env, exports, info);
    return exports;
}

void PhotoAssetCustomRecordNapi::SetCustomRecordNapiProperties()
{
    customRecordPtr = std::shared_ptr<PhotoAssetCustomRecord>(cRecordData_);
}

napi_value PhotoAssetCustomRecordNapi::Constructor(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        return result;
    }
    std::unique_ptr<PhotoAssetCustomRecordNapi> obj = std::make_unique<PhotoAssetCustomRecordNapi>();
    if (obj == nullptr) {
        return result;
    }
    obj->env_ = env;
    if (cRecordData_ != nullptr) {
        obj->SetCustomRecordNapiProperties();
    }
    status = napi_wrap(env, thisVar, reinterpret_cast<void *>(obj.get()),
    PhotoAssetCustomRecordNapi::Destructor, nullptr, nullptr);
    if (status == napi_ok) {
        obj.release();
        return thisVar;
    } else {
        NAPI_ERR_LOG("Failure wrapping js to native napi. status: %{public}d", status);
    }
    return result;
}

void PhotoAssetCustomRecordNapi::Destructor(napi_env env, void* nativeObject, void* finalizeHint)
{
    auto* photoAssetCustomRecordNapi = reinterpret_cast<PhotoAssetCustomRecordNapi*>(nativeObject);
    if (photoAssetCustomRecordNapi == nullptr) {
        NAPI_ERR_LOG("PhotoAssetCustomRecordNapi is nullptr");
        return;
    }
    delete photoAssetCustomRecordNapi;
    photoAssetCustomRecordNapi = nullptr;
}

napi_value PhotoAssetCustomRecordNapi::CreateCustomRecordNapi(napi_env env,
    unique_ptr<PhotoAssetCustomRecord> &cRecordata)
{
    if (cRecordata == nullptr) {
        return nullptr;
    }

    napi_value constructor;
    napi_ref constructorRef = constructor_;
    NAPI_CALL(env, napi_get_reference_value(env, constructorRef, &constructor));
    napi_value result = nullptr;
    cRecordData_ = cRecordata.release();
    NAPI_CALL(env, napi_new_instance(env, constructor, 0, nullptr, &result));
    cRecordData_ = nullptr;
    return result;
}

int32_t PhotoAssetCustomRecordNapi::GetFileId() const
{
    return customRecordPtr->GetFileId();
}

int32_t PhotoAssetCustomRecordNapi::GetShareCount() const
{
    return customRecordPtr->GetShareCount();
}

int32_t PhotoAssetCustomRecordNapi::GetLcdJumpCount() const
{
    return customRecordPtr->GetLcdJumpCount();
}

napi_value PhotoAssetCustomRecordNapi::JSGetFileId(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    PhotoAssetCustomRecordNapi* obj = nullptr;
    int32_t id;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        id = obj->GetFileId();
        status = napi_create_int32(env, id, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        }
    }

    return undefinedResult;
}

napi_value PhotoAssetCustomRecordNapi::JSGetShareCount(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    PhotoAssetCustomRecordNapi* obj = nullptr;
    int32_t id;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        id = obj->GetShareCount();
        status = napi_create_int32(env, id, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        }
    }

    return undefinedResult;
}

napi_value PhotoAssetCustomRecordNapi::JSGetLcdJumpCount(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    PhotoAssetCustomRecordNapi* obj = nullptr;
    int32_t id;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        id = obj->GetLcdJumpCount();
        status = napi_create_int32(env, id, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        }
    }

    return undefinedResult;
}
} // namespace Media
} // namespace OHOS