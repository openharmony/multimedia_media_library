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

#define MLOG_TAG "MediaAssetEditDataNapi"

#include "media_asset_edit_data_napi.h"

#include "medialibrary_client_errno.h"
#include "medialibrary_errno.h"
#include "medialibrary_napi_log.h"

using namespace std;

namespace OHOS::Media {
static const string MEDIA_ASSET_EDIT_DATA_CLASS = "MediaAssetEditData";
thread_local napi_ref MediaAssetEditDataNapi::constructor_ = nullptr;

constexpr int32_t EDIT_DATA_MAX_LENGTH = 5 * 1024 * 1024;
constexpr int32_t EDIT_FORMAT_MAX_LENGTH = 256;

napi_value MediaAssetEditDataNapi::Init(napi_env env, napi_value exports)
{
    NapiClassInfo info = { .name = MEDIA_ASSET_EDIT_DATA_CLASS,
        .ref = &constructor_,
        .constructor = Constructor,
        .props = {
            DECLARE_NAPI_GETTER_SETTER("compatibleFormat", JSGetCompatibleFormat, JSSetCompatibleFormat),
            DECLARE_NAPI_GETTER_SETTER("formatVersion", JSGetFormatVersion, JSSetFormatVersion),
            DECLARE_NAPI_GETTER_SETTER("data", JSGetData, JSSetData),
        } };
    MediaLibraryNapiUtils::NapiDefineClass(env, exports, info);
    return exports;
}

napi_value MediaAssetEditDataNapi::Constructor(napi_env env, napi_callback_info info)
{
    if (!MediaLibraryNapiUtils::IsSystemApp()) {
        NapiError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "The constructor can be called only by system apps");
        return nullptr;
    }

    napi_value newTarget = nullptr;
    CHECK_ARGS(env, napi_get_new_target(env, info, &newTarget), JS_INNER_FAIL);
    CHECK_COND_RET(newTarget != nullptr, nullptr, "Failed to check new.target");

    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = { 0 };
    napi_value thisVar = nullptr;
    string compatibleFormat;
    string formatVersion;
    CHECK_ARGS(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr), JS_INNER_FAIL);
    CHECK_COND_WITH_MESSAGE(env, argc == ARGS_TWO, "Number of args is invalid");
    CHECK_ARGS_THROW_INVALID_PARAM(env,
        MediaLibraryNapiUtils::GetParamStringWithLength(env, argv[PARAM0], EDIT_FORMAT_MAX_LENGTH, compatibleFormat));
    CHECK_ARGS_THROW_INVALID_PARAM(env,
        MediaLibraryNapiUtils::GetParamStringWithLength(env, argv[PARAM1], EDIT_FORMAT_MAX_LENGTH, formatVersion));

    shared_ptr<MediaAssetEditData> editData = make_shared<MediaAssetEditData>(compatibleFormat, formatVersion);
    unique_ptr<MediaAssetEditDataNapi> obj = make_unique<MediaAssetEditDataNapi>();
    CHECK_COND(env, editData != nullptr && obj != nullptr, JS_INNER_FAIL);
    obj->editData_ = editData;
    CHECK_ARGS(env,
        napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
            MediaAssetEditDataNapi::Destructor, nullptr, nullptr),
        JS_INNER_FAIL);
    obj.release();
    return thisVar;
}

void MediaAssetEditDataNapi::Destructor(napi_env env, void* nativeObject, void* finalizeHint)
{
    auto* assetEditData = reinterpret_cast<MediaAssetEditDataNapi*>(nativeObject);
    if (assetEditData != nullptr) {
        delete assetEditData;
        assetEditData = nullptr;
    }
}

napi_value MediaAssetEditDataNapi::CreateMediaAssetEditData(napi_env env,
    const string& compatibleFormat, const string& formatVersion, const string& data)
{
    napi_value constructor = nullptr;
    napi_value instance = nullptr;
    napi_value argv[ARGS_TWO];
    CHECK_ARGS(env, napi_create_string_utf8(env, compatibleFormat.c_str(),
        NAPI_AUTO_LENGTH, &(argv[PARAM0])), JS_INNER_FAIL);
    CHECK_ARGS(env, napi_create_string_utf8(env, formatVersion.c_str(),
        NAPI_AUTO_LENGTH, &(argv[PARAM1])), JS_INNER_FAIL);
    CHECK_ARGS(env, napi_get_reference_value(env, constructor_, &constructor), JS_INNER_FAIL);
    CHECK_ARGS(env, napi_new_instance(env, constructor, ARGS_TWO, argv, &instance), JS_INNER_FAIL);
    CHECK_COND(env, instance != nullptr, JS_INNER_FAIL);

    MediaAssetEditDataNapi* assetEditData = nullptr;
    CHECK_ARGS(env, napi_unwrap(env, instance, reinterpret_cast<void**>(&assetEditData)), JS_INNER_FAIL);
    CHECK_COND(env, assetEditData != nullptr, JS_INNER_FAIL);
    assetEditData->SetData(data);
    return instance;
}

shared_ptr<MediaAssetEditData> MediaAssetEditDataNapi::GetMediaAssetEditData() const
{
    return editData_;
}

string MediaAssetEditDataNapi::GetCompatibleFormat() const
{
    return editData_->GetCompatibleFormat();
}

void MediaAssetEditDataNapi::SetCompatibleFormat(const string& compatibleFormat)
{
    editData_->SetCompatibleFormat(compatibleFormat);
}

string MediaAssetEditDataNapi::GetFormatVersion() const
{
    return editData_->GetFormatVersion();
}

void MediaAssetEditDataNapi::SetFormatVersion(const string& formatVersion)
{
    editData_->SetFormatVersion(formatVersion);
}

string MediaAssetEditDataNapi::GetData() const
{
    return editData_->GetData();
}

void MediaAssetEditDataNapi::SetData(const string& data)
{
    editData_->SetData(data);
}

napi_value MediaAssetEditDataNapi::JSGetCompatibleFormat(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    MediaAssetEditDataNapi* obj = nullptr;

    napi_get_undefined(env, &result);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return result;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if (status == napi_ok && obj != nullptr) {
        string compatibleFormat = obj->GetCompatibleFormat();
        napi_create_string_utf8(env, compatibleFormat.c_str(), NAPI_AUTO_LENGTH, &result);
    } else {
        NAPI_ERR_LOG("Failed to get compatibleFormat");
    }
    return result;
}

napi_value MediaAssetEditDataNapi::JSGetFormatVersion(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    MediaAssetEditDataNapi* obj = nullptr;

    napi_get_undefined(env, &result);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return result;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if (status == napi_ok && obj != nullptr) {
        string formatVersion = obj->GetFormatVersion();
        napi_create_string_utf8(env, formatVersion.c_str(), NAPI_AUTO_LENGTH, &result);
    } else {
        NAPI_ERR_LOG("Failed to get formatVersion");
    }
    return result;
}

napi_value MediaAssetEditDataNapi::JSGetData(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    MediaAssetEditDataNapi* obj = nullptr;

    napi_get_undefined(env, &result);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return result;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if (status == napi_ok && obj != nullptr) {
        string data = obj->GetData();
        napi_create_string_utf8(env, data.c_str(), NAPI_AUTO_LENGTH, &result);
    } else {
        NAPI_ERR_LOG("Failed to get data");
    }
    return result;
}

static napi_value GetStringArg(
    napi_env env, napi_callback_info info, MediaAssetEditDataNapi** obj, int maxLen, string& arg)
{
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE];
    napi_value thisVar = nullptr;
    napi_valuetype valueType = napi_undefined;
    CHECK_ARGS(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr), JS_INNER_FAIL);
    CHECK_COND(env, argc == ARGS_ONE && thisVar != nullptr, OHOS_INVALID_PARAM_CODE);
    CHECK_ARGS(env, napi_unwrap(env, thisVar, reinterpret_cast<void**>(obj)), JS_INNER_FAIL);
    CHECK_COND(env, obj != nullptr, OHOS_INVALID_PARAM_CODE);
    CHECK_COND(env, napi_typeof(env, argv[PARAM0], &valueType) == napi_ok && valueType == napi_string,
        OHOS_INVALID_PARAM_CODE);

    size_t res = 0;
    unique_ptr<char[]> buffer = make_unique<char[]>(maxLen);
    CHECK_COND(env, buffer != nullptr, JS_INNER_FAIL);
    CHECK_ARGS(env, napi_get_value_string_utf8(env, argv[PARAM0], buffer.get(), maxLen, &res), JS_INNER_FAIL);
    arg = string(buffer.get());
    RETURN_NAPI_TRUE(env);
}

napi_value MediaAssetEditDataNapi::JSSetCompatibleFormat(napi_env env, napi_callback_info info)
{
    MediaAssetEditDataNapi* obj = nullptr;
    string compatibleFormat;
    CHECK_NULLPTR_RET(GetStringArg(env, info, &obj, EDIT_FORMAT_MAX_LENGTH, compatibleFormat));
    obj->SetCompatibleFormat(compatibleFormat);
    RETURN_NAPI_UNDEFINED(env);
}

napi_value MediaAssetEditDataNapi::JSSetFormatVersion(napi_env env, napi_callback_info info)
{
    MediaAssetEditDataNapi* obj = nullptr;
    string formatVersion;
    CHECK_NULLPTR_RET(GetStringArg(env, info, &obj, EDIT_FORMAT_MAX_LENGTH, formatVersion));
    obj->SetFormatVersion(formatVersion);
    RETURN_NAPI_UNDEFINED(env);
}

napi_value MediaAssetEditDataNapi::JSSetData(napi_env env, napi_callback_info info)
{
    MediaAssetEditDataNapi* obj = nullptr;
    string data;
    CHECK_NULLPTR_RET(GetStringArg(env, info, &obj, EDIT_DATA_MAX_LENGTH, data));
    obj->SetData(data);
    RETURN_NAPI_UNDEFINED(env);
}
} // namespace OHOS::Media