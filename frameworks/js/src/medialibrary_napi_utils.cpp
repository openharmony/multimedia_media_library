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
#define MLOG_TAG "MediaLibraryNapiUtils"

#include "medialibrary_napi_utils.h"

#include "datashare_predicates_proxy.h"
#include "media_library_napi.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_errno.h"
#include "medialibrary_tracer.h"
#include "media_file_utils.h"
#include "photo_album_napi.h"
#include "smart_album_napi.h"

using namespace std;
using namespace OHOS::DataShare;

namespace OHOS {
namespace Media {
void MediaLibraryNapiUtils::GetNetworkIdAndFileIdFromUri(const string &uri, string &networkId, string &fileId)
{
    networkId = "";
    fileId = "-1";
    if (uri.empty()) {
        NAPI_ERR_LOG("input uri is empty");
        return;
    }
    size_t pos = uri.find(MEDIALIBRARY_DATA_ABILITY_PREFIX);
    if (pos == string::npos) {
        NAPI_ERR_LOG("invalid input uri: %{private}s", uri.c_str());
        return;
    }
    string tempUri = uri.substr(MEDIALIBRARY_DATA_ABILITY_PREFIX.length());
    if (tempUri.empty()) {
        NAPI_ERR_LOG("invalid input uri: %{private}s", uri.c_str());
        return;
    }
    pos = tempUri.find_first_of('/');
    if (pos != 0 && pos != string::npos) {
        networkId = tempUri.substr(0, pos);
    }

    pos = uri.rfind('/');
    if (pos != string::npos) {
        fileId = uri.substr(pos + 1);
    } else {
        NAPI_ERR_LOG("get file_id failed, uri: %{private}s", uri.c_str());
    }
}

napi_value MediaLibraryNapiUtils::NapiDefineClass(napi_env env, napi_value exports, const NapiClassInfo &info)
{
    napi_value ctorObj;
    NAPI_CALL(env, napi_define_class(env, info.name.c_str(), NAPI_AUTO_LENGTH, info.constructor, nullptr,
        info.props.size(), info.props.data(), &ctorObj));
    NAPI_CALL(env, napi_create_reference(env, ctorObj, NAPI_INIT_REF_COUNT, info.ref));
    NAPI_CALL(env, napi_set_named_property(env, exports, info.name.c_str(), ctorObj));
    return exports;
}

napi_value MediaLibraryNapiUtils::NapiAddStaticProps(napi_env env, napi_value exports,
    const vector<napi_property_descriptor> &staticProps)
{
    NAPI_CALL(env, napi_define_properties(env, exports, staticProps.size(), staticProps.data()));
    return exports;
}

napi_status MediaLibraryNapiUtils::GetUInt32(napi_env env, napi_value arg, uint32_t &value)
{
    napi_valuetype valueType = napi_undefined;
    CHECK_STATUS_RET(napi_typeof(env, arg, &valueType), "Failed to get type");
    CHECK_COND_RET(valueType == napi_number, napi_number_expected, "Type is not as expected number");
    CHECK_STATUS_RET(napi_get_value_uint32(env, arg, &value), "Failed to get uint32 value");
    return napi_ok;
}

napi_status MediaLibraryNapiUtils::GetInt32(napi_env env, napi_value arg, int32_t &value)
{
    napi_valuetype valueType = napi_undefined;
    CHECK_STATUS_RET(napi_typeof(env, arg, &valueType), "Failed to get type");
    CHECK_COND_RET(valueType == napi_number, napi_number_expected, "Type is not as expected number");
    CHECK_STATUS_RET(napi_get_value_int32(env, arg, &value), "Failed to get int32 value");
    return napi_ok;
}

napi_status MediaLibraryNapiUtils::GetParamBool(napi_env env, napi_value arg, bool &value)
{
    napi_valuetype valueType = napi_undefined;
    CHECK_STATUS_RET(napi_typeof(env, arg, &valueType), "Failed to get type");
    CHECK_COND_RET(valueType == napi_boolean, napi_boolean_expected, "Type is not as expected boolean");
    CHECK_STATUS_RET(napi_get_value_bool(env, arg, &value), "Failed to get param");
    return napi_ok;
}

napi_status MediaLibraryNapiUtils::GetUInt32Array(napi_env env, napi_value arg, vector<uint32_t> &result)
{
    uint32_t arraySize = 0;
    CHECK_COND_RET(IsArrayForNapiValue(env, arg, arraySize), napi_array_expected, "Failed to check array type");
    for (uint32_t i = 0; i < arraySize; i++) {
        napi_value val = nullptr;
        CHECK_STATUS_RET(napi_get_element(env, arg, i, &val), "Failed to get element");
        uint32_t value = 0;
        CHECK_STATUS_RET(GetUInt32(env, val, value), "Failed to get element value");
        result.push_back(value);
    }
    return napi_ok;
}

napi_status MediaLibraryNapiUtils::GetParamFunction(napi_env env, napi_value arg, napi_ref &callbackRef)
{
    napi_valuetype valueType = napi_undefined;
    CHECK_STATUS_RET(napi_typeof(env, arg, &valueType), "Failed to get type");
    CHECK_COND_RET(valueType == napi_function, napi_function_expected, "Type is not as expected function");
    CHECK_STATUS_RET(napi_create_reference(env, arg, NAPI_INIT_REF_COUNT, &callbackRef), "Failed to make callbackref");
    return napi_ok;
}

static napi_status GetParamStr(napi_env env, napi_value arg, const size_t size, string &result)
{
    size_t res = 0;
    unique_ptr<char[]> buffer = make_unique<char[]>(size);
    CHECK_COND_RET(buffer != nullptr, napi_invalid_arg, "Failed to alloc buffer for parameter");
    napi_valuetype valueType = napi_undefined;
    CHECK_STATUS_RET(napi_typeof(env, arg, &valueType), "Failed to get type");
    CHECK_COND_RET(valueType == napi_string, napi_string_expected, "Type is not as expected string");
    CHECK_STATUS_RET(napi_get_value_string_utf8(env, arg, buffer.get(), size, &res), "Failed to get string value");
    result = string(buffer.get());
    return napi_ok;
}

napi_status MediaLibraryNapiUtils::GetParamString(napi_env env, napi_value arg, string &result)
{
    CHECK_STATUS_RET(GetParamStr(env, arg, ARG_BUF_SIZE, result), "Failed to get string parameter");
    return napi_ok;
}

napi_status MediaLibraryNapiUtils::GetParamStringPathMax(napi_env env, napi_value arg, string &result)
{
    CHECK_STATUS_RET(GetParamStr(env, arg, PATH_MAX, result), "Failed to get string parameter");
    return napi_ok;
}

napi_status MediaLibraryNapiUtils::GetProperty(napi_env env, const napi_value arg, const string &propName,
    string &propValue)
{
    bool present = false;
    napi_value property = nullptr;
    CHECK_STATUS_RET(napi_has_named_property(env, arg, propName.c_str(), &present),
        "Failed to check property name");
    if (present) {
        CHECK_STATUS_RET(napi_get_named_property(env, arg, propName.c_str(), &property), "Failed to get property");
        CHECK_STATUS_RET(GetParamStringPathMax(env, property, propValue), "Failed to get string buffer");
    }
    return napi_ok;
}

napi_status MediaLibraryNapiUtils::GetArrayProperty(napi_env env, napi_value arg, const string &propName,
    vector<string> &array)
{
    bool present = false;
    CHECK_STATUS_RET(napi_has_named_property(env, arg, propName.c_str(), &present), "Failed to check property name");
    if (present) {
        uint32_t len = 0;
        napi_value property = nullptr;
        bool isArray = false;
        CHECK_STATUS_RET(napi_get_named_property(env, arg, propName.c_str(), &property),
            "Failed to get selectionArgs property");
        CHECK_STATUS_RET(napi_is_array(env, property, &isArray), "Failed to check array type");
        CHECK_COND_RET(isArray, napi_array_expected, "Expected array type");
        CHECK_STATUS_RET(napi_get_array_length(env, property, &len), "Failed to get array length");
        for (uint32_t i = 0; i < len; i++) {
            napi_value item = nullptr;
            string val = "";
            CHECK_STATUS_RET(napi_get_element(env, property, i, &item), "Failed to get array item");
            CHECK_STATUS_RET(GetParamStringPathMax(env, item, val), "Failed to get string buffer");
            array.push_back(val);
        }
    }
    return napi_ok;
}

void MediaLibraryNapiUtils::GenTypeMaskFromArray(const vector<uint32_t> types, string &typeMask)
{
    typeMask.resize(TYPE_MASK_STRING_SIZE, TYPE_MASK_BIT_DEFAULT);
    for (auto &type : types) {
        if ((type >= MEDIA_TYPE_FILE) && (type <= MEDIA_TYPE_AUDIO)) {
            typeMask[get<POS_TYPE_MASK_STRING_INDEX>(MEDIA_TYPE_TUPLE_VEC[type])] = TYPE_MASK_BIT_SET;
        }
    }
}

napi_status MediaLibraryNapiUtils::HasCallback(napi_env env, const size_t argc, const napi_value argv[],
    bool &isCallback)
{
    isCallback = false;
    if (argc < ARGS_ONE) {
        return napi_ok;
    }
    napi_valuetype valueType = napi_undefined;
    CHECK_STATUS_RET(napi_typeof(env, argv[argc - 1], &valueType), "Failed to get type");
    isCallback = (valueType == napi_function);
    return napi_ok;
}

napi_status MediaLibraryNapiUtils::hasFetchOpt(napi_env env, const napi_value arg, bool &hasFetchOpt)
{
    hasFetchOpt = false;
    napi_valuetype valueType = napi_undefined;
    CHECK_STATUS_RET(napi_typeof(env, arg, &valueType), "Failed to get type");
    if (valueType != napi_object) {
        hasFetchOpt = false;
        return napi_ok;
    }
    CHECK_STATUS_RET(napi_has_named_property(env, arg, "selections", &hasFetchOpt),
        "Failed to get property selections");
    return napi_ok;
}

void MediaLibraryNapiUtils::UriAddFragmentTypeMask(string &uri, const string &typeMask)
{
    if (!typeMask.empty()) {
        uri += "#" + URI_PARAM_KEY_TYPE + ":" + typeMask;
    }
}

void MediaLibraryNapiUtils::UriAddTableName(string &uri, const string tableName)
{
    if (!tableName.empty()) {
        uri += "/" + tableName;
    }
}

void MediaLibraryNapiUtils::UriRemoveAllFragment(string &uri)
{
    size_t fragIndex = uri.find_first_of('#');
    if (fragIndex != string::npos) {
        uri = uri.substr(0, fragIndex);
    }
}

string MediaLibraryNapiUtils::GetFileIdFromUri(const string &uri)
{
    string id = "-1";

    string temp = uri;
    UriRemoveAllFragment(temp);
    size_t pos = temp.rfind('/');
    if (pos != string::npos) {
        id = temp.substr(pos + 1);
    }

    return id;
}

MediaType MediaLibraryNapiUtils::GetMediaTypeFromUri(const string &uri)
{
    if (uri.find(MEDIALIBRARY_IMAGE_URI) != string::npos) {
        return MediaType::MEDIA_TYPE_IMAGE;
    } else if (uri.find(MEDIALIBRARY_VIDEO_URI) != string::npos) {
        return MediaType::MEDIA_TYPE_VIDEO;
    } else if (uri.find(MEDIALIBRARY_AUDIO_URI) != string::npos) {
        return MediaType::MEDIA_TYPE_AUDIO;
    } else if (uri.find(MEDIALIBRARY_FILE_URI) != string::npos) {
        return MediaType::MEDIA_TYPE_FILE;
    }
    return MediaType::MEDIA_TYPE_ALL;
}

template <class AsyncContext>
bool MediaLibraryNapiUtils::HandleSpecialPredicate(AsyncContext &context,
    shared_ptr<DataShareAbsPredicates> &predicate, bool isAlbum)
{
    constexpr int32_t FIELD_IDX = 0;
    constexpr int32_t VALUE_IDX = 1;
    vector<OperationItem> operations;
    auto &items = predicate->GetOperationList();
    for (auto &item : items) {
        // change uri ->file id
        // get networkid
        // replace networkid with file id
        if (static_cast<string>(item.GetSingle(FIELD_IDX)) == DEVICE_DB_NETWORK_ID) {
            if (item.operation != DataShare::EQUAL_TO || static_cast<string>(item.GetSingle(VALUE_IDX)).empty()) {
                NAPI_ERR_LOG("DEVICE_DB_NETWORK_ID predicates not support %{public}d", item.operation);
                return false;
            }
            context->networkId = static_cast<string>(item.GetSingle(VALUE_IDX));
            continue;
        }
        if (static_cast<string>(item.GetSingle(FIELD_IDX)) == MEDIA_DATA_DB_URI) {
            if (item.operation != DataShare::EQUAL_TO) {
                NAPI_ERR_LOG("MEDIA_DATA_DB_URI predicates not support %{public}d", item.operation);
                return false;
            }
            string uri = static_cast<string>(item.GetSingle(VALUE_IDX));
            UriRemoveAllFragment(uri);
            uri = MediaFileUtils::DealWithUriWithName(uri);
            string fileId;
            MediaLibraryNapiUtils::GetNetworkIdAndFileIdFromUri(uri, context->networkId, fileId);
            string field = isAlbum ? MEDIA_DATA_DB_BUCKET_ID : MEDIA_DATA_DB_ID;
            operations.push_back({item.operation, {field, fileId}});
            continue;
        }
        operations.push_back(item);
    }
    context->predicates = DataSharePredicates(move(operations));
    return true;
}

template <class AsyncContext>
napi_status MediaLibraryNapiUtils::GetAssetFetchOption(napi_env env, napi_value arg, AsyncContext &context)
{
    // Parse the argument into fetchOption if any
    CHECK_STATUS_RET(GetPredicate(env, arg, "predicates", context, false), "invalid predicate");
    CHECK_STATUS_RET(GetArrayProperty(env, arg, "fetchColumns", context->fetchColumn),
        "Failed to parse fetchColumn");
    return napi_ok;
}

template <class AsyncContext>
napi_status MediaLibraryNapiUtils::GetPredicate(napi_env env, const napi_value arg, const string &propName,
    AsyncContext &context, bool isAlbum)
{
    bool present = false;
    napi_value property = nullptr;
    CHECK_STATUS_RET(napi_has_named_property(env, arg, propName.c_str(), &present),
        "Failed to check property name");
    if (present) {
        CHECK_STATUS_RET(napi_get_named_property(env, arg, propName.c_str(), &property), "Failed to get property");
        shared_ptr<DataShareAbsPredicates> predicate = DataSharePredicatesProxy::GetNativePredicates(env, property);
        CHECK_COND_RET(HandleSpecialPredicate(context, predicate, isAlbum) == TRUE, napi_invalid_arg,
            "invalid predicate");
    }
    return napi_ok;
}

template <class AsyncContext>
napi_status MediaLibraryNapiUtils::ParseAssetFetchOptCallback(napi_env env, napi_callback_info info,
    AsyncContext &context)
{
    constexpr size_t minArgs = ARGS_ONE;
    constexpr size_t maxArgs = ARGS_TWO;
    CHECK_STATUS_RET(AsyncContextSetObjectInfo(env, info, context, minArgs, maxArgs),
        "Failed to get object info");
    CHECK_STATUS_RET(GetAssetFetchOption(env, context->argv[PARAM0], context), "Failed to get fetch option");
    CHECK_STATUS_RET(GetParamCallback(env, context), "Failed to get callback");
    return napi_ok;
}

template <class AsyncContext>
napi_status MediaLibraryNapiUtils::ParseAlbumFetchOptCallback(napi_env env, napi_callback_info info,
    AsyncContext &context)
{
    constexpr size_t minArgs = ARGS_ONE;
    constexpr size_t maxArgs = ARGS_TWO;
    CHECK_STATUS_RET(AsyncContextSetObjectInfo(env, info, context, minArgs, maxArgs),
        "Failed to get object info");
    // Parse the argument into fetchOption if any
    CHECK_STATUS_RET(GetPredicate(env, context->argv[PARAM0], "predicates", context, true), "invalid predicate");
    CHECK_STATUS_RET(GetParamCallback(env, context), "Failed to get callback");
    return napi_ok;
}

template <class AsyncContext>
void MediaLibraryNapiUtils::UpdateMediaTypeSelections(AsyncContext *context)
{
    constexpr int FIRST_MEDIA_TYPE = 0;
    constexpr int SECOND_MEDIA_TYPE = 1;
    if ((context->mediaTypes.size() != ARGS_ONE) && (context->mediaTypes.size() != ARGS_TWO)) {
        return;
    }
    DataShare::DataSharePredicates &predicates = context->predicates;
    predicates.BeginWrap();
    predicates.EqualTo(MEDIA_DATA_DB_MEDIA_TYPE, (int)context->mediaTypes[FIRST_MEDIA_TYPE]);
    if (context->mediaTypes.size() == ARGS_TWO) {
        predicates.Or()->EqualTo(MEDIA_DATA_DB_MEDIA_TYPE, (int)context->mediaTypes[SECOND_MEDIA_TYPE]);
    }
    predicates.EndWrap();
}

template <class AsyncContext>
napi_status MediaLibraryNapiUtils::AsyncContextSetObjectInfo(napi_env env, napi_callback_info info,
    AsyncContext &asyncContext, const size_t minArgs, const size_t maxArgs)
{
    napi_value thisVar = nullptr;
    asyncContext->argc = maxArgs;
    CHECK_STATUS_RET(napi_get_cb_info(env, info, &asyncContext->argc, &(asyncContext->argv[ARGS_ZERO]), &thisVar,
        nullptr), "Failed to get cb info");
    CHECK_COND_RET(((asyncContext->argc >= minArgs) && (asyncContext->argc <= maxArgs)), napi_invalid_arg,
        "Number of args is invalid");
    if (minArgs > 0) {
        CHECK_COND_RET(asyncContext->argv[ARGS_ZERO] != nullptr, napi_invalid_arg, "Argument list is empty");
    }
    CHECK_STATUS_RET(napi_unwrap(env, thisVar, reinterpret_cast<void **>(&asyncContext->objectInfo)),
        "Failed to unwrap thisVar");
    CHECK_COND_RET(asyncContext->objectInfo != nullptr, napi_invalid_arg, "Failed to get object info");
    return napi_ok;
}

template <class AsyncContext>
napi_status MediaLibraryNapiUtils::GetFetchOption(napi_env env, napi_value arg, AsyncContext &context)
{
    /* Parse the argument into fetchOption if any */
    bool hasOpt = false;
    CHECK_STATUS_RET(hasFetchOpt(env, arg, hasOpt), "Failed to get fetchopt");
    if (hasOpt) {
        CHECK_STATUS_RET(GetProperty(env, arg, "selections", context->selection), "Failed to parse selections");
        CHECK_STATUS_RET(GetProperty(env, arg, "order", context->order), "Failed to parse order");
        CHECK_STATUS_RET(GetArrayProperty(env, arg, "selectionArgs", context->selectionArgs),
            "Failed to parse selectionArgs");
        CHECK_STATUS_RET(GetProperty(env, arg, "uri", context->uri), "Failed to parse uri");
        CHECK_STATUS_RET(GetProperty(env, arg, "networkId", context->networkId), "Failed to parse networkId");
    }
    return napi_ok;
}

template <class AsyncContext>
napi_status MediaLibraryNapiUtils::GetParamCallback(napi_env env, AsyncContext &context)
{
    /* Parse the last argument into callbackref if any */
    bool isCallback = false;
    CHECK_STATUS_RET(HasCallback(env, context->argc, context->argv, isCallback), "Failed to check callback");
    if (isCallback) {
        CHECK_STATUS_RET(GetParamFunction(env, context->argv[context->argc - 1], context->callbackRef),
            "Failed to get callback");
    }
    return napi_ok;
}

template <class AsyncContext>
napi_status MediaLibraryNapiUtils::ParseArgsBoolCallBack(napi_env env, napi_callback_info info, AsyncContext &context,
    bool &param)
{
    constexpr size_t minArgs = ARGS_ONE;
    constexpr size_t maxArgs = ARGS_TWO;
    CHECK_STATUS_RET(AsyncContextSetObjectInfo(env, info, context, minArgs, maxArgs),
        "Failed to get object info");

    /* Parse the first argument into param */
    CHECK_STATUS_RET(GetParamBool(env, context->argv[ARGS_ZERO], param), "Failed to get parameter");
    CHECK_STATUS_RET(GetParamCallback(env, context), "Failed to get callback");
    return napi_ok;
}

template <class AsyncContext>
napi_status MediaLibraryNapiUtils::ParseArgsStringCallback(napi_env env, napi_callback_info info, AsyncContext &context,
    string &param)
{
    constexpr size_t minArgs = ARGS_ONE;
    constexpr size_t maxArgs = ARGS_TWO;
    CHECK_STATUS_RET(AsyncContextSetObjectInfo(env, info, context, minArgs, maxArgs),
        "Failed to get object info");

    CHECK_STATUS_RET(GetParamStringPathMax(env, context->argv[ARGS_ZERO], param), "Failed to get string argument");
    CHECK_STATUS_RET(GetParamCallback(env, context), "Failed to get callback");
    return napi_ok;
}

template <class AsyncContext>
napi_status MediaLibraryNapiUtils::ParseArgsNumberCallback(napi_env env, napi_callback_info info, AsyncContext &context,
    int32_t &value)
{
    constexpr size_t minArgs = ARGS_ONE;
    constexpr size_t maxArgs = ARGS_TWO;
    CHECK_STATUS_RET(AsyncContextSetObjectInfo(env, info, context, minArgs, maxArgs),
        "Failed to get object info");

    CHECK_STATUS_RET(GetInt32(env, context->argv[ARGS_ZERO], value), "Failed to get number argument");
    CHECK_STATUS_RET(GetParamCallback(env, context), "Failed to get callback");
    return napi_ok;
}

template <class AsyncContext>
napi_status MediaLibraryNapiUtils::ParseArgsOnlyCallBack(napi_env env, napi_callback_info info, AsyncContext &context)
{
    constexpr size_t minArgs = ARGS_ZERO;
    constexpr size_t maxArgs = ARGS_ONE;
    CHECK_STATUS_RET(AsyncContextSetObjectInfo(env, info, context, minArgs, maxArgs),
        "Failed to get object info");

    CHECK_STATUS_RET(GetParamCallback(env, context), "Failed to get callback");
    return napi_ok;
}

AssetType MediaLibraryNapiUtils::GetAssetType(MediaType type)
{
    AssetType result;

    switch (type) {
        case MEDIA_TYPE_AUDIO:
            result = ASSET_AUDIO;
            break;
        case MEDIA_TYPE_VIDEO:
            result = ASSET_VIDEO;
            break;
        case MEDIA_TYPE_IMAGE:
            result = ASSET_IMAGE;
            break;
        case MEDIA_TYPE_MEDIA:
            result = ASSET_MEDIA;
            break;
        default:
            result = ASSET_NONE;
            break;
    }

    return result;
}

void MediaLibraryNapiUtils::AppendFetchOptionSelection(string &selection, const string &newCondition)
{
    if (!newCondition.empty()) {
        if (!selection.empty()) {
            selection = "(" + selection + ") AND " + newCondition;
        } else {
            selection = newCondition;
        }
    }
}

string MediaLibraryNapiUtils::GetMediaTypeUri(MediaType mediaType)
{
    switch (mediaType) {
        case MEDIA_TYPE_AUDIO:
            return MEDIALIBRARY_AUDIO_URI;
        case MEDIA_TYPE_VIDEO:
            return MEDIALIBRARY_VIDEO_URI;
        case MEDIA_TYPE_IMAGE:
            return MEDIALIBRARY_IMAGE_URI;
        case MEDIA_TYPE_SMARTALBUM:
            return MEDIALIBRARY_SMARTALBUM_CHANGE_URI;
        case MEDIA_TYPE_DEVICE:
            return MEDIALIBRARY_DEVICE_URI;
        case MEDIA_TYPE_FILE:
        default:
            return MEDIALIBRARY_FILE_URI;
    }
}

int MediaLibraryNapiUtils::TransErrorCode(const string &Name, shared_ptr<DataShare::DataShareResultSet> resultSet)
{
    NAPI_ERR_LOG("interface: %{public}s, server return nullptr", Name.c_str());
    // Query can't return errorcode, so assume nullptr as permission deny
    if (resultSet == nullptr) {
        return JS_ERR_PERMISSION_DENIED;
    }
    return ERR_DEFAULT;
}

int MediaLibraryNapiUtils::TransErrorCode(const string &Name, int error)
{
    NAPI_ERR_LOG("interface: %{public}s, server errcode:%{public}d ", Name.c_str(), error);
    // Transfer Server error to napi error code
    if (error <= E_COMMON_START && error >= E_COMMON_END) {
        error = JS_INNER_FAIL;
    } else if (trans2JsError.count(error)) {
        error = trans2JsError.at(error);
    }
    return error;
}

void MediaLibraryNapiUtils::HandleError(napi_env env, int error, napi_value &errorObj, const string &Name)
{
    if (error == ERR_DEFAULT) {
        return;
    }

    string errMsg = "operation fail";
    if (jsErrMap.count(error) > 0) {
        errMsg = jsErrMap.at(error);
    }
    CreateNapiErrorObject(env, errorObj, error, errMsg);
    errMsg = Name + " " + errMsg;
    NAPI_ERR_LOG("Error: %{public}s, js errcode:%{public}d ", errMsg.c_str(), error);
}

void MediaLibraryNapiUtils::CreateNapiErrorObject(napi_env env, napi_value &errorObj, const int32_t errCode,
    const string errMsg)
{
    napi_status statusError;
    napi_value napiErrorCode = nullptr;
    napi_value napiErrorMsg = nullptr;
    statusError = napi_create_string_utf8(env, to_string(errCode).c_str(), NAPI_AUTO_LENGTH, &napiErrorCode);
    if (statusError == napi_ok) {
        statusError = napi_create_string_utf8(env, errMsg.c_str(), NAPI_AUTO_LENGTH, &napiErrorMsg);
        if (statusError == napi_ok) {
            statusError = napi_create_error(env, napiErrorCode, napiErrorMsg, &errorObj);
            if (statusError == napi_ok) {
                NAPI_DEBUG_LOG("napi_create_error success");
            }
        }
    }
}

void MediaLibraryNapiUtils::InvokeJSAsyncMethod(napi_env env, napi_deferred deferred, napi_ref callbackRef,
    napi_async_work work, const JSAsyncContextOutput &asyncContext)
{
    MediaLibraryTracer tracer;
    tracer.Start("InvokeJSAsyncMethod");

    napi_value retVal;
    napi_value callback = nullptr;

    /* Deferred is used when JS Callback method expects a promise value */
    if (deferred) {
        if (asyncContext.status) {
            napi_resolve_deferred(env, deferred, asyncContext.data);
        } else {
            napi_reject_deferred(env, deferred, asyncContext.error);
        }
    } else {
        napi_value result[ARGS_TWO];
        result[PARAM0] = asyncContext.error;
        result[PARAM1] = asyncContext.data;
        napi_get_reference_value(env, callbackRef, &callback);
        napi_call_function(env, nullptr, callback, ARGS_TWO, result, &retVal);
        napi_delete_reference(env, callbackRef);
    }
    napi_delete_async_work(env, work);
}

template <class AsyncContext>
napi_value MediaLibraryNapiUtils::NapiCreateAsyncWork(napi_env env, unique_ptr<AsyncContext> &asyncContext,
    const string &resourceName,  void (*execute)(napi_env, void *), void (*complete)(napi_env, napi_status, void *))
{
    napi_value result = nullptr;
    napi_value resource = nullptr;
    NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
    NAPI_CREATE_RESOURCE_NAME(env, resource, resourceName.c_str(), asyncContext);

    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, execute, complete,
        static_cast<void *>(asyncContext.get()), &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContext.release();

    return result;
}

tuple<bool, unique_ptr<char[]>, size_t> MediaLibraryNapiUtils::ToUTF8String(napi_env env, napi_value value)
{
    size_t strLen = 0;
    napi_status status = napi_get_value_string_utf8(env, value, nullptr, -1, &strLen);
    if (status != napi_ok) {
        NAPI_ERR_LOG("ToUTF8String get fail, %{public}d", status);
        return { false, nullptr, 0 };
    }

    size_t bufLen = strLen + 1;
    unique_ptr<char[]> str = make_unique<char[]>(bufLen);
    if (str == nullptr) {
        NAPI_ERR_LOG("ToUTF8String get memory fail");
        return { false, nullptr, 0 };
    }
    status = napi_get_value_string_utf8(env, value, str.get(), bufLen, &strLen);
    return make_tuple(status == napi_ok, move(str), strLen);
}

bool MediaLibraryNapiUtils::IsExistsByPropertyName(napi_env env, napi_value jsObject, const char *propertyName)
{
    bool result = false;
    if (napi_has_named_property(env, jsObject, propertyName, &result) == napi_ok) {
        return result;
    } else {
        NAPI_ERR_LOG("IsExistsByPropertyName not exist %{public}s", propertyName);
        return false;
    }
}

napi_value MediaLibraryNapiUtils::GetPropertyValueByName(napi_env env, napi_value jsObject, const char *propertyName)
{
    napi_value value = nullptr;
    if (IsExistsByPropertyName(env, jsObject, propertyName) == false) {
        NAPI_ERR_LOG("GetPropertyValueByName not exist %{public}s", propertyName);
        return nullptr;
    }
    if (napi_get_named_property(env, jsObject, propertyName, &value) != napi_ok) {
        NAPI_ERR_LOG("GetPropertyValueByName get fail %{public}s", propertyName);
        return nullptr;
    }
    return value;
}

bool MediaLibraryNapiUtils::CheckJSArgsTypeAsFunc(napi_env env, napi_value arg)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, arg, &valueType);
    return (valueType == napi_function);
}

bool MediaLibraryNapiUtils::IsArrayForNapiValue(napi_env env, napi_value param, uint32_t &arraySize)
{
    bool isArray = false;
    arraySize = 0;
    if ((napi_is_array(env, param, &isArray) != napi_ok) || (isArray == false)) {
        return false;
    }
    if (napi_get_array_length(env, param, &arraySize) != napi_ok) {
        return false;
    }
    return true;
}

napi_value MediaLibraryNapiUtils::GetInt32Arg(napi_env env, napi_value arg, int32_t &value)
{
    napi_valuetype valueType = napi_undefined;
    CHECK_ARGS(env, napi_typeof(env, arg, &valueType), JS_INNER_FAIL);
    if (valueType != napi_number) {
        NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return nullptr;
    }
    CHECK_ARGS(env, napi_get_value_int32(env, arg, &value), JS_INNER_FAIL);

    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_boolean(env, true, &result), JS_INNER_FAIL);
    return result;
}

void MediaLibraryNapiUtils::UriAppendKeyValue(string &uri, const string &key, const string &value)
{
    string uriKey = key + '=';
    if (uri.find(uriKey) != string::npos) {
        return;
    }

    char queryMark = (uri.find('?') == string::npos) ? '?' : '&';
    string append = queryMark + key + '=' + value;

    size_t posJ = uri.find('#');
    if (posJ == string::npos) {
        uri += append;
    } else {
        uri.insert(posJ, append);
    }
}

template bool MediaLibraryNapiUtils::HandleSpecialPredicate<unique_ptr<MediaLibraryAsyncContext>>(
    unique_ptr<MediaLibraryAsyncContext> &context, shared_ptr<DataShareAbsPredicates> &predicate, bool isAlbum);

template bool MediaLibraryNapiUtils::HandleSpecialPredicate<unique_ptr<AlbumNapiAsyncContext>>(
    unique_ptr<AlbumNapiAsyncContext> &context, shared_ptr<DataShareAbsPredicates> &predicate, bool isAlbum);

template bool MediaLibraryNapiUtils::HandleSpecialPredicate<unique_ptr<SmartAlbumNapiAsyncContext>>(
    unique_ptr<SmartAlbumNapiAsyncContext> &context, shared_ptr<DataShareAbsPredicates> &predicate, bool isAlbum);

template napi_status MediaLibraryNapiUtils::GetAssetFetchOption<unique_ptr<MediaLibraryAsyncContext>>(napi_env env,
    napi_value arg, unique_ptr<MediaLibraryAsyncContext> &context);

template napi_status MediaLibraryNapiUtils::GetAssetFetchOption<unique_ptr<PhotoAlbumNapiAsyncContext>>(napi_env env,
    napi_value arg, unique_ptr<PhotoAlbumNapiAsyncContext> &context);

template napi_status MediaLibraryNapiUtils::GetPredicate<unique_ptr<MediaLibraryAsyncContext>>(napi_env env,
    const napi_value arg, const string &propName, unique_ptr<MediaLibraryAsyncContext> &context, bool isAlbum);

template napi_status MediaLibraryNapiUtils::GetPredicate<unique_ptr<AlbumNapiAsyncContext>>(napi_env env,
    const napi_value arg, const string &propName, unique_ptr<AlbumNapiAsyncContext> &context, bool isAlbum);

template napi_status MediaLibraryNapiUtils::GetPredicate<unique_ptr<SmartAlbumNapiAsyncContext>>(napi_env env,
    const napi_value arg, const string &propName, unique_ptr<SmartAlbumNapiAsyncContext> &context, bool isAlbum);

template napi_status MediaLibraryNapiUtils::ParseAssetFetchOptCallback<unique_ptr<MediaLibraryAsyncContext>>(
    napi_env env, napi_callback_info info, unique_ptr<MediaLibraryAsyncContext> &context);

template napi_status MediaLibraryNapiUtils::ParseAssetFetchOptCallback<unique_ptr<AlbumNapiAsyncContext>>(
    napi_env env, napi_callback_info info, unique_ptr<AlbumNapiAsyncContext> &context);

template napi_status MediaLibraryNapiUtils::ParseAssetFetchOptCallback<unique_ptr<SmartAlbumNapiAsyncContext>>(
    napi_env env, napi_callback_info info, unique_ptr<SmartAlbumNapiAsyncContext> &context);

template napi_status MediaLibraryNapiUtils::ParseAlbumFetchOptCallback<unique_ptr<MediaLibraryAsyncContext>>(
    napi_env env, napi_callback_info info, unique_ptr<MediaLibraryAsyncContext> &context);

template void MediaLibraryNapiUtils::UpdateMediaTypeSelections<SmartAlbumNapiAsyncContext>(
    SmartAlbumNapiAsyncContext *context);

template void MediaLibraryNapiUtils::UpdateMediaTypeSelections<AlbumNapiAsyncContext>(
    AlbumNapiAsyncContext *context);

template void MediaLibraryNapiUtils::UpdateMediaTypeSelections<MediaLibraryAsyncContext>(
    MediaLibraryAsyncContext *context);

template napi_status MediaLibraryNapiUtils::ParseArgsStringCallback<unique_ptr<FileAssetAsyncContext>>(
    napi_env env, napi_callback_info info, unique_ptr<FileAssetAsyncContext> &context, string &param);

template napi_status MediaLibraryNapiUtils::ParseArgsStringCallback<unique_ptr<MediaLibraryAsyncContext>>(
    napi_env env, napi_callback_info info, unique_ptr<MediaLibraryAsyncContext> &context, string &param);

template napi_status MediaLibraryNapiUtils::ParseArgsStringCallback<unique_ptr<SmartAlbumNapiAsyncContext>>(
    napi_env env, napi_callback_info info, unique_ptr<SmartAlbumNapiAsyncContext> &context, string &param);

template napi_status MediaLibraryNapiUtils::GetParamCallback<unique_ptr<PhotoAlbumNapiAsyncContext>>(napi_env env,
    unique_ptr<PhotoAlbumNapiAsyncContext> &context);

template napi_status MediaLibraryNapiUtils::GetParamCallback<unique_ptr<SmartAlbumNapiAsyncContext>>(napi_env env,
    unique_ptr<SmartAlbumNapiAsyncContext> &context);

template napi_status MediaLibraryNapiUtils::ParseArgsBoolCallBack<unique_ptr<MediaLibraryAsyncContext>>(napi_env env,
    napi_callback_info info, unique_ptr<MediaLibraryAsyncContext> &context, bool &param);

template napi_status MediaLibraryNapiUtils::ParseArgsBoolCallBack<unique_ptr<FileAssetAsyncContext>>(napi_env env,
    napi_callback_info info, unique_ptr<FileAssetAsyncContext> &context, bool &param);

template napi_status MediaLibraryNapiUtils::AsyncContextSetObjectInfo<unique_ptr<PhotoAlbumNapiAsyncContext>>(
    napi_env env, napi_callback_info info, unique_ptr<PhotoAlbumNapiAsyncContext> &asyncContext, const size_t minArgs,
    const size_t maxArgs);

template napi_status MediaLibraryNapiUtils::AsyncContextSetObjectInfo<unique_ptr<SmartAlbumNapiAsyncContext>>(
    napi_env env, napi_callback_info info, unique_ptr<SmartAlbumNapiAsyncContext> &asyncContext, const size_t minArgs,
    const size_t maxArgs);

template napi_value MediaLibraryNapiUtils::NapiCreateAsyncWork<MediaLibraryAsyncContext>(napi_env env,
    unique_ptr<MediaLibraryAsyncContext> &asyncContext, const string &resourceName,
    void (*execute)(napi_env, void *), void (*complete)(napi_env, napi_status, void *));

template napi_value MediaLibraryNapiUtils::NapiCreateAsyncWork<FileAssetAsyncContext>(napi_env env,
    unique_ptr<FileAssetAsyncContext> &asyncContext, const string &resourceName,
    void (*execute)(napi_env, void *), void (*complete)(napi_env, napi_status, void *));

template napi_value MediaLibraryNapiUtils::NapiCreateAsyncWork<AlbumNapiAsyncContext>(napi_env env,
    unique_ptr<AlbumNapiAsyncContext> &asyncContext, const string &resourceName,
    void (*execute)(napi_env, void *), void (*complete)(napi_env, napi_status, void *));

template napi_value MediaLibraryNapiUtils::NapiCreateAsyncWork<PhotoAlbumNapiAsyncContext>(napi_env env,
    unique_ptr<PhotoAlbumNapiAsyncContext> &asyncContext, const string &resourceName,
    void (*execute)(napi_env, void *), void (*complete)(napi_env, napi_status, void *));

template napi_value MediaLibraryNapiUtils::NapiCreateAsyncWork<SmartAlbumNapiAsyncContext>(napi_env env,
    unique_ptr<SmartAlbumNapiAsyncContext> &asyncContext, const string &resourceName,
    void (*execute)(napi_env, void *), void (*complete)(napi_env, napi_status, void *));

template napi_status MediaLibraryNapiUtils::ParseArgsNumberCallback<unique_ptr<MediaLibraryAsyncContext>>(napi_env env,
    napi_callback_info info, unique_ptr<MediaLibraryAsyncContext> &context, int32_t &value);

template napi_status MediaLibraryNapiUtils::ParseArgsNumberCallback<unique_ptr<FileAssetAsyncContext>>(napi_env env,
    napi_callback_info info, unique_ptr<FileAssetAsyncContext> &context, int32_t &value);

template napi_status MediaLibraryNapiUtils::ParseArgsOnlyCallBack<unique_ptr<MediaLibraryAsyncContext>>(napi_env env,
    napi_callback_info info, unique_ptr<MediaLibraryAsyncContext> &context);

template napi_status MediaLibraryNapiUtils::ParseArgsOnlyCallBack<unique_ptr<FileAssetAsyncContext>>(napi_env env,
    napi_callback_info info, unique_ptr<FileAssetAsyncContext> &context);

template napi_status MediaLibraryNapiUtils::ParseArgsOnlyCallBack<unique_ptr<AlbumNapiAsyncContext>>(napi_env env,
    napi_callback_info info, unique_ptr<AlbumNapiAsyncContext> &context);
} // namespace Media
} // namespace OHOS
