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
#define MLOG_TAG "ScannerNapi"

#include "media_scanner_napi.h"
#include "media_library_napi.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_napi_log.h"
#include "userfile_client.h"

using OHOS::HiviewDFX::HiLog;
using OHOS::HiviewDFX::HiLogLabel;
using namespace std;

namespace OHOS {
namespace Media {
thread_local napi_ref MediaScannerNapi::sConstructor_ = nullptr;

MediaScannerNapi::MediaScannerNapi()
    : env_(nullptr) {}

MediaScannerNapi::~MediaScannerNapi()
{}

napi_value MediaScannerNapi::Init(napi_env env, napi_value exports)
{
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    napi_property_descriptor scanner_props[] = {
        DECLARE_NAPI_FUNCTION("scanDir", ScanDir),
        DECLARE_NAPI_FUNCTION("scanFile", ScanFile)
    };

    napi_property_descriptor static_prop[] = {
        DECLARE_NAPI_STATIC_FUNCTION("getScannerInstance", GetMediaScannerInstance)
    };

    status = napi_define_class(env, SCANNER_HELPER_NAPI_CLASS_NAME.c_str(), NAPI_AUTO_LENGTH,
        MediaScannerNapiConstructor, nullptr, sizeof(scanner_props) / sizeof(scanner_props[PARAM0]),
        scanner_props, &ctorObj);
    if (status == napi_ok) {
        if (napi_create_reference(env, ctorObj, refCount, &sConstructor_) == napi_ok) {
            status = napi_set_named_property(env, exports, SCANNER_HELPER_NAPI_CLASS_NAME.c_str(), ctorObj);
            if (status == napi_ok && napi_define_properties(env, exports,
                sizeof(static_prop) / sizeof(static_prop[PARAM0]), static_prop) == napi_ok) {
                return exports;
            }
        }
    }
    return nullptr;
}

napi_value MediaScannerNapi::MediaScannerNapiConstructor(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);

    if (status == napi_ok && thisVar != nullptr) {
        unique_ptr<MediaScannerNapi> obj = make_unique<MediaScannerNapi>();
        if (obj != nullptr) {
            obj->env_ = env;

            obj->mediaScannerNapiCallbackObj_ = std::make_shared<MediaScannerNapiCallback>(env);
            if (obj->mediaScannerNapiCallbackObj_ == nullptr) {
                NAPI_ERR_LOG("[MediaScannerNapiConstructor] callback instance creation failed!");
                return result;
            }

            status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                               MediaScannerNapi::MediaScannerNapiDestructor, nullptr, nullptr);
            if (status == napi_ok) {
                obj.release();
                return thisVar;
            } else {
                NAPI_ERR_LOG("Failed to wrap the native media scanner client, status: %{private}d", status);
            }
        }
    }

    NAPI_INFO_LOG("[MediaScannerNapiConstructor] failed");
    return result;
}

void MediaScannerNapi::MediaScannerNapiDestructor(napi_env env, void *nativeObject, void *finalize_hint)
{
    MediaScannerNapi *scannerHelper = reinterpret_cast<MediaScannerNapi*>(nativeObject);
    if (scannerHelper != nullptr) {
        delete scannerHelper;
    }
}

napi_value MediaScannerNapi::GetMediaScannerInstance(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value ctor;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    status = napi_get_reference_value(env, sConstructor_, &ctor);
    if (status == napi_ok) {
        status = napi_new_instance(env, ctor, argc, argv, &result);
        if (status == napi_ok) {
            NAPI_INFO_LOG("[GetMediaScannerInstance] success");
            return result;
        } else {
            NAPI_ERR_LOG("[GetMediaScannerInstance] New instance could not be obtained, status: %{public}d", status);
        }
    }

    NAPI_ERR_LOG("[GetMediaScannerInstance] failed , status = %{public}d", status);
    napi_get_undefined(env, &result);
    return result;
}

void InvokeJSCallback(napi_env env, const int32_t errCode, const std::string &uri, napi_ref callbackRef)
{
    napi_value retVal = nullptr;
    napi_value results[ARGS_TWO] = {nullptr};
    napi_get_undefined(env, &results[PARAM0]);
    napi_create_object(env, &results[PARAM1]);

    napi_value jsStatus = 0;
    napi_create_int32(env, errCode, &jsStatus);
    napi_set_named_property(env, results[PARAM1], "status", jsStatus);

    napi_value jsUri = 0;
    napi_create_string_utf8(env, uri.c_str(), NAPI_AUTO_LENGTH, &jsUri);
    napi_set_named_property(env, results[PARAM1], "fileUri", jsUri);

    napi_value callback = nullptr;
    napi_get_reference_value(env, callbackRef, &callback);
    napi_call_function(env, nullptr, callback, ARGS_TWO, results, &retVal);
}

napi_value MediaScannerNapi::NapiScanUtils(napi_env env, napi_callback_info info, const string &scanType)
{
    char buffer[PATH_MAX];
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    MediaScannerNapi *obj = nullptr;
    string event = "";
    napi_ref callbackRef = nullptr;
    const int32_t refCount = 1;
    size_t res = 0;
    int32_t errCode = 0;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_TWO, "requires 2 parameters");

    NAPI_INFO_LOG("[MediaScannerNapi::NapiScanUtils] start");
    napi_get_undefined(env, &result);
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if (status == napi_ok && obj != nullptr) {
        if (argc == ARGS_TWO) {
            napi_valuetype valueType = napi_undefined;
            napi_typeof(env, argv[PARAM0], &valueType);
            if (valueType == napi_string) {
                napi_get_value_string_utf8(env, argv[PARAM0], buffer, PATH_MAX, &res);
                event = string(buffer);
            } else {
                NAPI_ERR_LOG("Invalid arg, valueType: %{public}d", valueType);
                return result;
            }
            napi_typeof(env, argv[PARAM1], &valueType);
            if (valueType == napi_function) {
                napi_create_reference(env, argv[PARAM1], refCount, &callbackRef);
            } else {
                NAPI_ERR_LOG("Invalid arg, valueType: %{public}d", valueType);
                return result;
            }
        }
        errCode = 0;
        DataShareScanBoardcast(event);

        if (errCode == 0) {
            obj->mediaScannerNapiCallbackObj_->SetToMap(event, callbackRef);
        } else {
            // Invoke JS callback functions based on results
            InvokeJSCallback(env, errCode, "", callbackRef);
        }
    }
    NAPI_INFO_LOG("[MediaScannerNapi::NapiScanUtils] end");
    return result;
}

napi_value MediaScannerNapi::ScanFile(napi_env env, napi_callback_info info)
{
    return NapiScanUtils(env, info, "FILE");
}

napi_value MediaScannerNapi::ScanDir(napi_env env, napi_callback_info info)
{
    return NapiScanUtils(env, info, "DIR");
}

void MediaScannerNapi::DataShareScanBoardcast(const std::string &event)
{
    NAPI_INFO_LOG("MediaScannerNapi::DataShareScanBoardcast start, event: %{public}s", event.c_str());
    Uri insertUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_BOARDCASTOPRN + "/" + MEDIA_SCAN_OPERATION);
    OHOS::DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, event);
    int index = UserFileClient::Insert(insertUri, valuesBucket);
    if (index < 0) {
        NAPI_ERR_LOG("[MediaScannerNapi::DataShareScanBoardcast return status %{public}d", index);
    } else {
        NAPI_INFO_LOG("[MediaScannerNapi::DataShareScanBoardcast success");
    }
}

int32_t MediaScannerNapiCallback::OnScanFinished(const int32_t status, const std::string &uri, const std::string &path)
{
    auto itr = scannerMap_.find(path);
    if (itr != scannerMap_.end()) {
        // Invoke JS callback functions based on results
        InvokeJSCallback(env_, status, uri, itr->second);
        scannerMap_.erase(path);
        NAPI_DEBUG_LOG("OnScanFinished exit");
    }

    return 0;
}

void MediaScannerNapiCallback::SetToMap(const std::string &path, const napi_ref &cbRef)
{
    scannerMap_.insert(std::make_pair(path, cbRef));
}
} // namespace Media
} // namespace OHOS
