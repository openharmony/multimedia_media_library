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

#include "basic/result_set.h"
#include "datashare_predicates.h"
#include "location_column.h"
#include "ipc_skeleton.h"
#include "js_proxy.h"
#include "highlight_album_napi.h"
#include "media_asset_change_request_napi.h"
#include "media_assets_change_request_napi.h"
#include "media_album_change_request_napi.h"
#include "media_asset_manager_napi.h"
#include "media_device_column.h"
#include "media_file_uri.h"
#include "media_file_utils.h"
#include "media_library_napi.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_tracer.h"
#include "moving_photo_napi.h"
#include "photo_album_napi.h"
#include "photo_map_column.h"
#include "smart_album_napi.h"
#include "tokenid_kit.h"
#include "userfile_client.h"
#include "vision_album_column.h"
#include "vision_column.h"
#include "vision_face_tag_column.h"

using namespace std;
using namespace OHOS::DataShare;

namespace OHOS {
namespace Media {
static const string EMPTY_STRING = "";
using json = nlohmann::json;
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

napi_status MediaLibraryNapiUtils::GetDouble(napi_env env, napi_value arg, double &value)
{
    napi_valuetype valueType = napi_undefined;
    CHECK_STATUS_RET(napi_typeof(env, arg, &valueType), "Failed to get type");
    CHECK_COND_RET(valueType == napi_number, napi_number_expected, "Type is not as expected number");
    CHECK_STATUS_RET(napi_get_value_double(env, arg, &value), "Failed to get double value");
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

napi_status MediaLibraryNapiUtils::GetParamStringWithLength(napi_env env, napi_value arg, int32_t maxLen,
    string &result)
{
    CHECK_STATUS_RET(GetParamStr(env, arg, maxLen, result), "Failed to get string parameter");
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

napi_status MediaLibraryNapiUtils::GetStringArray(napi_env env, napi_value arg, vector<string> &array)
{
    bool isArray = false;
    uint32_t len = 0;
    CHECK_STATUS_RET(napi_is_array(env, arg, &isArray), "Failed to check array type");
    CHECK_COND_RET(isArray, napi_array_expected, "Expected array type");
    CHECK_STATUS_RET(napi_get_array_length(env, arg, &len), "Failed to get array length");
    for (uint32_t i = 0; i < len; i++) {
        napi_value item = nullptr;
        string val;
        CHECK_STATUS_RET(napi_get_element(env, arg, i, &item), "Failed to get array item");
        CHECK_STATUS_RET(GetParamStringPathMax(env, item, val), "Failed to get string buffer");
        array.push_back(val);
    }
    return napi_ok;
}

napi_status MediaLibraryNapiUtils::GetArrayProperty(napi_env env, napi_value arg, const string &propName,
    vector<string> &array)
{
    bool present = false;
    CHECK_STATUS_RET(napi_has_named_property(env, arg, propName.c_str(), &present), "Failed to check property name");
    if (present) {
        napi_value property = nullptr;
        CHECK_STATUS_RET(napi_get_named_property(env, arg, propName.c_str(), &property),
            "Failed to get selectionArgs property");
        GetStringArray(env, property, array);
    }
    return napi_ok;
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

void MediaLibraryNapiUtils::UriAddTableName(string &uri, const string tableName)
{
    if (!tableName.empty()) {
        uri += "/" + tableName;
    }
}

string MediaLibraryNapiUtils::GetFileIdFromUri(const string &uri)
{
    string id = "-1";

    string temp = uri;
    MediaFileUri::RemoveAllFragment(temp);
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

static bool HandleSpecialDateTypePredicate(const OperationItem &item,
    vector<OperationItem> &operations, const FetchOptionType &fetchOptType)
{
    constexpr int32_t FIELD_IDX = 0;
    constexpr int32_t VALUE_IDX = 1;
    vector<string>dateTypes = { MEDIA_DATA_DB_DATE_ADDED, MEDIA_DATA_DB_DATE_TRASHED, MEDIA_DATA_DB_DATE_MODIFIED };
    string dateType = item.GetSingle(FIELD_IDX);
    auto it = find(dateTypes.begin(), dateTypes.end(), dateType);
    if (it != dateTypes.end() && item.operation != DataShare::ORDER_BY_ASC &&
        item.operation != DataShare::ORDER_BY_DESC) {
        dateType += "_s";
        operations.push_back({ item.operation, { dateType, static_cast<double>(item.GetSingle(VALUE_IDX)) } });
        return true;
    }
    return false;
}

template <class AsyncContext>
bool MediaLibraryNapiUtils::HandleSpecialPredicate(AsyncContext &context,
    shared_ptr<DataShareAbsPredicates> &predicate, const FetchOptionType &fetchOptType)
{
    constexpr int32_t FIELD_IDX = 0;
    constexpr int32_t VALUE_IDX = 1;
    vector<OperationItem> operations;
    auto &items = predicate->GetOperationList();
    for (auto &item : items) {
        if (item.singleParams.empty()) {
            operations.push_back(item);
            continue;
        }
        if (HandleSpecialDateTypePredicate(item, operations, fetchOptType)) {
            continue;
        }
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
            MediaFileUri::RemoveAllFragment(uri);
            MediaFileUri fileUri(uri);
            context->uri = uri;
            if ((fetchOptType != ALBUM_FETCH_OPT) && (!fileUri.IsApi10())) {
                fileUri = MediaFileUri(MediaFileUtils::GetRealUriFromVirtualUri(uri));
            }
            context->networkId = fileUri.GetNetworkId();
            string field = (fetchOptType == ALBUM_FETCH_OPT) ? PhotoAlbumColumns::ALBUM_ID : MEDIA_DATA_DB_ID;
            operations.push_back({ item.operation, { field, fileUri.GetFileId() } });
            continue;
        }
        if (static_cast<string>(item.GetSingle(FIELD_IDX)) == PENDING_STATUS) {
            // do not query pending files below API11
            continue;
        }
        if (LOCATION_PARAM_MAP.find(static_cast<string>(item.GetSingle(FIELD_IDX))) != LOCATION_PARAM_MAP.end()) {
            continue;
        }
        operations.push_back(item);
    }
    context->predicates = DataSharePredicates(move(operations));
    return true;
}

template <class AsyncContext>
bool MediaLibraryNapiUtils::GetLocationPredicate(AsyncContext &context,
    shared_ptr<DataShareAbsPredicates> &predicate)
{
    constexpr int32_t FIELD_IDX = 0;
    constexpr int32_t VALUE_IDX = 1;
    map<string, string> locationMap;
    auto &items = predicate->GetOperationList();
    for (auto &item : items) {
        if (item.singleParams.empty()) {
            continue;
        }
        if (LOCATION_PARAM_MAP.find(static_cast<string>(item.GetSingle(FIELD_IDX))) != LOCATION_PARAM_MAP.end()) {
            if (item.operation != DataShare::EQUAL_TO) {
                NAPI_ERR_LOG("location predicates not support %{public}d", item.operation);
                return false;
            }
            string param = static_cast<string>(item.GetSingle(FIELD_IDX));
            string value = static_cast<string>(item.GetSingle(VALUE_IDX));
            locationMap.insert(make_pair(param, value));
            if (param == DIAMETER) {
                continue;
            }
            if (LOCATION_PARAM_MAP.at(param).second == DataShare::GREATER_THAN_OR_EQUAL_TO) {
                context->predicates.GreaterThanOrEqualTo(LOCATION_PARAM_MAP.at(param).first, value);
                continue;
            }
            if (LOCATION_PARAM_MAP.at(param).second == DataShare::LESS_THAN) {
                context->predicates.LessThan(LOCATION_PARAM_MAP.at(param).first, value);
                continue;
            }
            if (LOCATION_PARAM_MAP.at(param).second == DataShare::EQUAL_TO) {
                context->predicates.EqualTo(LOCATION_PARAM_MAP.at(param).first, value);
                continue;
            }
        }
    }

    if (locationMap.count(DIAMETER) == 1 && locationMap.count(START_LATITUDE) == 1
        && locationMap.count(START_LONGITUDE) == 1) {
        // 0.5:Used for rounding down
        string latitudeIndex = "round((latitude - " + locationMap.at(START_LATITUDE) + ") / " +
            locationMap.at(DIAMETER) + " - 0.5)";
        string longitudeIndex = "round((longitude - " + locationMap.at(START_LONGITUDE) + ") / " +
            locationMap.at(DIAMETER) + " - 0.5)";
        string albumName = LATITUDE + "||'_'||" + LONGITUDE + "||'_'||" + latitudeIndex + "||'_'||" +
            longitudeIndex + " AS " + ALBUM_NAME;
        context->fetchColumn.push_back(albumName);
        string locationGroup = latitudeIndex + "," + longitudeIndex;
        context->predicates.GroupBy({ locationGroup });
    }
    return true;
}

template <class AsyncContext>
napi_status MediaLibraryNapiUtils::GetFetchOption(napi_env env, napi_value arg, const FetchOptionType &fetchOptType,
    AsyncContext &context)
{
    // Parse the argument into fetchOption if any
    CHECK_STATUS_RET(GetPredicate(env, arg, "predicates", context, fetchOptType), "invalid predicate");
    CHECK_STATUS_RET(GetArrayProperty(env, arg, "fetchColumns", context->fetchColumn),
        "Failed to parse fetchColumn");
    return napi_ok;
}

template <class AsyncContext>
napi_status MediaLibraryNapiUtils::GetAlbumFetchOption(napi_env env, napi_value arg,
    const FetchOptionType &fetchOptType, AsyncContext &context)
{
    // Parse the argument into AlbumFetchOption if any
    CHECK_STATUS_RET(GetPredicate(env, arg, "predicates", context, fetchOptType), "invalid predicate");
    return napi_ok;
}

template <class AsyncContext>
napi_status MediaLibraryNapiUtils::GetPredicate(napi_env env, const napi_value arg, const string &propName,
    AsyncContext &context, const FetchOptionType &fetchOptType)
{
    bool present = false;
    napi_value property = nullptr;
    CHECK_STATUS_RET(napi_has_named_property(env, arg, propName.c_str(), &present),
        "Failed to check property name");
    if (present) {
        CHECK_STATUS_RET(napi_get_named_property(env, arg, propName.c_str(), &property), "Failed to get property");
        JSProxy::JSProxy<DataShareAbsPredicates> *jsProxy = nullptr;
        napi_unwrap(env, property, reinterpret_cast<void **>(&jsProxy));
        shared_ptr<DataShareAbsPredicates> predicate = jsProxy->GetInstance();
        CHECK_COND_RET(HandleSpecialPredicate(context, predicate, fetchOptType) == TRUE, napi_invalid_arg,
            "invalid predicate");
        CHECK_COND_RET(GetLocationPredicate(context, predicate) == TRUE, napi_invalid_arg, "invalid predicate");
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
    CHECK_STATUS_RET(GetFetchOption(env, context->argv[PARAM0], ASSET_FETCH_OPT, context),
        "Failed to get fetch option");
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
    CHECK_STATUS_RET(GetPredicate(env, context->argv[PARAM0], "predicates", context, ALBUM_FETCH_OPT),
        "invalid predicate");
    context->predicates.And()->NotEqualTo(PhotoAlbumColumns::ALBUM_SUBTYPE, to_string(PhotoAlbumSubType::HIDDEN));
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
    CHECK_STATUS_RET(GetParamCallback(env, asyncContext), "Failed to get callback param!");
    return napi_ok;
}

template <class AsyncContext>
napi_status MediaLibraryNapiUtils::AsyncContextGetArgs(napi_env env, napi_callback_info info,
    AsyncContext &asyncContext, const size_t minArgs, const size_t maxArgs)
{
    asyncContext->argc = maxArgs;
    CHECK_STATUS_RET(napi_get_cb_info(env, info, &asyncContext->argc, &(asyncContext->argv[ARGS_ZERO]), nullptr,
        nullptr), "Failed to get cb info");
    CHECK_COND_RET(asyncContext->argc >= minArgs && asyncContext->argc <= maxArgs, napi_invalid_arg,
        "Number of args is invalid");
    if (minArgs > 0) {
        CHECK_COND_RET(asyncContext->argv[ARGS_ZERO] != nullptr, napi_invalid_arg, "Argument list is empty");
    }
    CHECK_STATUS_RET(GetParamCallback(env, asyncContext), "Failed to get callback param");
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
    return napi_ok;
}

template <class AsyncContext>
napi_status MediaLibraryNapiUtils::ParseArgsStringArrayCallback(napi_env env, napi_callback_info info,
    AsyncContext &context, vector<string> &array)
{
    constexpr size_t minArgs = ARGS_ONE;
    constexpr size_t maxArgs = ARGS_TWO;
    CHECK_STATUS_RET(AsyncContextSetObjectInfo(env, info, context, minArgs, maxArgs),
        "Failed to get object info");

    CHECK_STATUS_RET(GetStringArray(env, context->argv[ARGS_ZERO], array), "Failed to get string array");
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
    return napi_ok;
}

template <class AsyncContext>
napi_status MediaLibraryNapiUtils::ParseArgsOnlyCallBack(napi_env env, napi_callback_info info, AsyncContext &context)
{
    constexpr size_t minArgs = ARGS_ZERO;
    constexpr size_t maxArgs = ARGS_ONE;
    CHECK_STATUS_RET(AsyncContextSetObjectInfo(env, info, context, minArgs, maxArgs),
        "Failed to get object info");
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

    string errMsg = "System inner fail";
    int originalError = error;
    if (jsErrMap.count(error) > 0) {
        errMsg = jsErrMap.at(error);
    } else {
        error = JS_INNER_FAIL;
    }
    CreateNapiErrorObject(env, errorObj, error, errMsg);
    errMsg = Name + " " + errMsg;
    NAPI_ERR_LOG("Error: %{public}s, js errcode:%{public}d ", errMsg.c_str(), originalError);
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

napi_value MediaLibraryNapiUtils::AddDefaultAssetColumns(napi_env env, vector<string> &fetchColumn,
    function<bool(const string &columnName)> isValidColumn, NapiAssetType assetType,
    const PhotoAlbumSubType subType)
{
    auto validFetchColumns = MediaColumn::DEFAULT_FETCH_COLUMNS;
    if (assetType == TYPE_PHOTO) {
        validFetchColumns.insert(
            PhotoColumn::DEFAULT_FETCH_COLUMNS.begin(), PhotoColumn::DEFAULT_FETCH_COLUMNS.end());
    }
    switch (subType) {
        case PhotoAlbumSubType::FAVORITE:
            validFetchColumns.insert(MediaColumn::MEDIA_IS_FAV);
            break;
        case PhotoAlbumSubType::VIDEO:
            validFetchColumns.insert(MediaColumn::MEDIA_TYPE);
            break;
        case PhotoAlbumSubType::HIDDEN:
            validFetchColumns.insert(MediaColumn::MEDIA_HIDDEN);
            break;
        case PhotoAlbumSubType::TRASH:
            validFetchColumns.insert(MediaColumn::MEDIA_DATE_TRASHED);
            break;
        case PhotoAlbumSubType::SCREENSHOT:
        case PhotoAlbumSubType::CAMERA:
            validFetchColumns.insert(PhotoColumn::PHOTO_SUBTYPE);
            break;
        default:
            break;
    }
    for (const auto &column : fetchColumn) {
        if (column == PENDING_STATUS) {
            validFetchColumns.insert(MediaColumn::MEDIA_TIME_PENDING);
        } else if (isValidColumn(column)) {
            validFetchColumns.insert(column);
        } else if (column == MEDIA_DATA_DB_URI) {
            continue;
        } else if (DATE_TRANSITION_MAP.count(column) != 0) {
            validFetchColumns.insert(DATE_TRANSITION_MAP.at(column));
        } else {
            NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
            return nullptr;
        }
    }
    fetchColumn.assign(validFetchColumns.begin(), validFetchColumns.end());

    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_boolean(env, true, &result), JS_INNER_FAIL);
    return result;
}

int32_t MediaLibraryNapiUtils::GetUserAlbumPredicates(
    const int32_t albumId, DataSharePredicates &predicates, const bool hiddenOnly)
{
    string onClause = MediaColumn::MEDIA_ID + " = " + PhotoMap::ASSET_ID;
    predicates.InnerJoin(PhotoMap::TABLE)->On({ onClause });
    predicates.EqualTo(PhotoMap::ALBUM_ID, to_string(albumId));
    predicates.EqualTo(MediaColumn::MEDIA_DATE_TRASHED, to_string(0));
    predicates.EqualTo(MediaColumn::MEDIA_HIDDEN, to_string(hiddenOnly));
    predicates.EqualTo(MediaColumn::MEDIA_TIME_PENDING, to_string(0));
    return E_SUCCESS;
}

int32_t MediaLibraryNapiUtils::GetPortraitAlbumPredicates(const int32_t albumId, DataSharePredicates &predicates)
{
    string onClause = MediaColumn::MEDIA_ID + " = " + PhotoMap::ASSET_ID;
    vector<string> clauses = { onClause };
    predicates.InnerJoin(ANALYSIS_PHOTO_MAP_TABLE)->On(clauses);
    onClause = ALBUM_ID + " = " + PhotoMap::ALBUM_ID;
    clauses = { onClause };
    predicates.InnerJoin(ANALYSIS_ALBUM_TABLE)->On(clauses);
    string tempTable = "(SELECT " + GROUP_TAG + " FROM " + ANALYSIS_ALBUM_TABLE + " WHERE " + ALBUM_ID + " = " +
        to_string(albumId) + ") ag";
    onClause = "ag." + GROUP_TAG + " = " + ANALYSIS_ALBUM_TABLE + "." + GROUP_TAG;
    clauses = { onClause };
    predicates.InnerJoin(tempTable)->On(clauses);
    predicates.EqualTo(MediaColumn::MEDIA_DATE_TRASHED, to_string(0));
    predicates.EqualTo(MediaColumn::MEDIA_HIDDEN, to_string(0));
    predicates.EqualTo(MediaColumn::MEDIA_TIME_PENDING, to_string(0));
    predicates.Distinct();
    return E_SUCCESS;
}

int32_t MediaLibraryNapiUtils::GetAnalysisAlbumPredicates(const int32_t albumId, DataSharePredicates &predicates)
{
    string onClause = MediaColumn::MEDIA_ID + " = " + PhotoMap::ASSET_ID;
    predicates.InnerJoin(ANALYSIS_PHOTO_MAP_TABLE)->On({ onClause });
    predicates.EqualTo(PhotoMap::ALBUM_ID, to_string(albumId));
    predicates.EqualTo(MediaColumn::MEDIA_DATE_TRASHED, to_string(0));
    predicates.EqualTo(MediaColumn::MEDIA_HIDDEN, to_string(0));
    predicates.EqualTo(MediaColumn::MEDIA_TIME_PENDING, to_string(0));
    return E_SUCCESS;
}

int32_t MediaLibraryNapiUtils::GetAllLocationPredicates(DataSharePredicates &predicates)
{
    predicates.EqualTo(MediaColumn::MEDIA_DATE_TRASHED, to_string(0));
    predicates.EqualTo(MediaColumn::MEDIA_HIDDEN, to_string(0));
    predicates.EqualTo(MediaColumn::MEDIA_TIME_PENDING, to_string(0));
    predicates.And()->NotEqualTo(PhotoColumn::PHOTO_LATITUDE, to_string(0));
    predicates.And()->NotEqualTo(PhotoColumn::PHOTO_LONGITUDE, to_string(0));
    return E_SUCCESS;
}

static int32_t GetFavoritePredicates(DataSharePredicates &predicates, const bool hiddenOnly)
{
    predicates.BeginWrap();
    constexpr int32_t IS_FAVORITE = 1;
    predicates.EqualTo(MediaColumn::MEDIA_IS_FAV, to_string(IS_FAVORITE));
    predicates.And()->EqualTo(MediaColumn::MEDIA_DATE_TRASHED, to_string(0));
    predicates.And()->EqualTo(MediaColumn::MEDIA_HIDDEN, to_string(hiddenOnly));
    predicates.EqualTo(MediaColumn::MEDIA_TIME_PENDING, to_string(0));
    predicates.EndWrap();
    return E_SUCCESS;
}

static int32_t GetVideoPredicates(DataSharePredicates &predicates, const bool hiddenOnly)
{
    predicates.BeginWrap();
    predicates.EqualTo(MediaColumn::MEDIA_TYPE, to_string(MEDIA_TYPE_VIDEO));
    predicates.And()->EqualTo(MediaColumn::MEDIA_DATE_TRASHED, to_string(0));
    predicates.And()->EqualTo(MediaColumn::MEDIA_HIDDEN, to_string(hiddenOnly));
    predicates.EqualTo(MediaColumn::MEDIA_TIME_PENDING, to_string(0));
    predicates.EndWrap();
    return E_SUCCESS;
}

static int32_t GetHiddenPredicates(DataSharePredicates &predicates)
{
    predicates.BeginWrap();
    predicates.And()->EqualTo(MediaColumn::MEDIA_DATE_TRASHED, to_string(0));
    predicates.EqualTo(MediaColumn::MEDIA_HIDDEN, to_string(1));
    predicates.EqualTo(MediaColumn::MEDIA_TIME_PENDING, to_string(0));
    predicates.EndWrap();
    return E_SUCCESS;
}

static int32_t GetTrashPredicates(DataSharePredicates &predicates)
{
    predicates.BeginWrap();
    predicates.GreaterThan(MediaColumn::MEDIA_DATE_TRASHED, to_string(0));
    predicates.EndWrap();
    return E_SUCCESS;
}

static int32_t GetScreenshotPredicates(DataSharePredicates &predicates, const bool hiddenOnly)
{
    predicates.BeginWrap();
    predicates.EqualTo(PhotoColumn::PHOTO_SUBTYPE, to_string(static_cast<int32_t>(PhotoSubType::SCREENSHOT)));
    predicates.And()->EqualTo(MediaColumn::MEDIA_DATE_TRASHED, to_string(0));
    predicates.And()->EqualTo(MediaColumn::MEDIA_HIDDEN, to_string(hiddenOnly));
    predicates.EqualTo(MediaColumn::MEDIA_TIME_PENDING, to_string(0));
    predicates.EndWrap();
    return E_SUCCESS;
}

static int32_t GetCameraPredicates(DataSharePredicates &predicates, const bool hiddenOnly)
{
    predicates.BeginWrap();
    predicates.EqualTo(PhotoColumn::PHOTO_SUBTYPE, to_string(static_cast<int32_t>(PhotoSubType::CAMERA)));
    predicates.And()->EqualTo(MediaColumn::MEDIA_DATE_TRASHED, to_string(0));
    predicates.And()->EqualTo(MediaColumn::MEDIA_HIDDEN, to_string(hiddenOnly));
    predicates.EqualTo(MediaColumn::MEDIA_TIME_PENDING, to_string(0));
    predicates.EndWrap();
    return E_SUCCESS;
}

static int32_t GetAllImagesPredicates(DataSharePredicates &predicates, const bool hiddenOnly)
{
    predicates.BeginWrap();
    predicates.EqualTo(MediaColumn::MEDIA_TYPE, to_string(MEDIA_TYPE_IMAGE));
    predicates.And()->EqualTo(MediaColumn::MEDIA_DATE_TRASHED, to_string(0));
    predicates.And()->EqualTo(MediaColumn::MEDIA_HIDDEN, to_string(hiddenOnly));
    predicates.EqualTo(MediaColumn::MEDIA_TIME_PENDING, to_string(0));
    predicates.EndWrap();
    return E_SUCCESS;
}

int32_t MediaLibraryNapiUtils::GetSourceAlbumPredicates(const int32_t albumId, DataSharePredicates &predicates,
    const bool hiddenOnly)
{
    string onClause = MediaColumn::MEDIA_ID + " = " + PhotoMap::ASSET_ID;
    predicates.InnerJoin(PhotoMap::TABLE)->On({ onClause });
    predicates.EqualTo(PhotoMap::ALBUM_ID, to_string(albumId));
    predicates.EqualTo(PhotoColumn::PHOTO_SYNC_STATUS, to_string(static_cast<int32_t>(SyncStatusType::TYPE_VISIBLE)));
    predicates.EqualTo(MediaColumn::MEDIA_DATE_TRASHED, to_string(0));
    predicates.EqualTo(MediaColumn::MEDIA_HIDDEN, to_string(hiddenOnly));
    predicates.EqualTo(MediaColumn::MEDIA_TIME_PENDING, to_string(0));
    return E_SUCCESS;
}

int32_t MediaLibraryNapiUtils::GetSystemAlbumPredicates(const PhotoAlbumSubType subType,
    DataSharePredicates &predicates, const bool hiddenOnly)
{
    switch (subType) {
        case PhotoAlbumSubType::FAVORITE: {
            return GetFavoritePredicates(predicates, hiddenOnly);
        }
        case PhotoAlbumSubType::VIDEO: {
            return GetVideoPredicates(predicates, hiddenOnly);
        }
        case PhotoAlbumSubType::HIDDEN: {
            return GetHiddenPredicates(predicates);
        }
        case PhotoAlbumSubType::TRASH: {
            return GetTrashPredicates(predicates);
        }
        case PhotoAlbumSubType::SCREENSHOT: {
            return GetScreenshotPredicates(predicates, hiddenOnly);
        }
        case PhotoAlbumSubType::CAMERA: {
            return GetCameraPredicates(predicates, hiddenOnly);
        }
        case PhotoAlbumSubType::IMAGE: {
            return GetAllImagesPredicates(predicates, hiddenOnly);
        }
        default: {
            NAPI_ERR_LOG("Unsupported photo album subtype: %{public}d", subType);
            return E_INVALID_ARGUMENTS;
        }
    }
}

string MediaLibraryNapiUtils::ParseResultSet2JsonStr(shared_ptr<DataShare::DataShareResultSet> resultSet,
    const std::vector<std::string> &columns)
{
    json jsonArray = json::array();
    if (resultSet == nullptr) {
        return jsonArray.dump();
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        json jsonObject;
        for (uint32_t i = 0; i < columns.size(); i++) {
            string columnName = columns[i];
            jsonObject[columnName] = GetStringValueByColumn(resultSet, columnName);
        }
        jsonArray.push_back(jsonObject);
    }
    return jsonArray.dump();
}

string MediaLibraryNapiUtils::GetStringValueByColumn(shared_ptr<DataShare::DataShareResultSet> resultSet,
    const std::string columnName)
{
    int index;
    DataShare::DataType dataType;
    if (resultSet->GetColumnIndex(columnName, index) || resultSet->GetDataType(index, dataType)) {
        return EMPTY_STRING;
    }
    switch (dataType) {
        case DataShare::DataType::TYPE_INTEGER: {
            int intValue = -1;
            if (resultSet->GetInt(index, intValue) == NativeRdb::E_OK) {
                return to_string(intValue);
            }
            break;
        }
        case DataShare::DataType::TYPE_FLOAT: {
            double douValue = 0.0;
            if (resultSet->GetDouble(index, douValue) == NativeRdb::E_OK) {
                return to_string(douValue);
            }
            break;
        }
        case DataShare::DataType::TYPE_STRING: {
            std::string strValue;
            if (resultSet->GetString(index, strValue) == NativeRdb::E_OK) {
                return strValue;
            }
            break;
        }
        case DataShare::DataType::TYPE_BLOB: {
            std::vector<uint8_t> blobValue;
            if (resultSet->GetBlob(index, blobValue) == NativeRdb::E_OK) {
                std::string tempValue(blobValue.begin(), blobValue.end());
                return tempValue;
            }
            break;
        }
        default: {
            NAPI_ERR_LOG("Unsupported dataType: %{public}d", dataType);
            break;
        }
    }
    return EMPTY_STRING;
}

string MediaLibraryNapiUtils::TransferUri(const string &oldUri)
{
    MediaFileUri fileUri(oldUri);
    if (fileUri.IsApi10()) {
        return oldUri;
    }
    string fileId = fileUri.GetFileId();
    if (fileId.empty()) {
        return oldUri;
    }
    vector<string> columns = {
        PhotoColumn::MEDIA_FILE_PATH,
        PhotoColumn::MEDIA_NAME
    };
    string queryUri = MEDIALIBRARY_DATA_URI;
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PhotoColumn::MEDIA_ID, fileId);
    Uri uri(queryUri);
    int errCode = 0;
    shared_ptr<DataShare::DataShareResultSet> resultSet = UserFileClient::Query(uri,
        predicates, columns, errCode);
    if (resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        NAPI_ERR_LOG("Fail to query file asset!");
        return oldUri;
    }
    string extrUri = MediaFileUtils::GetExtraUri(GetStringValueByColumn(resultSet, PhotoColumn::MEDIA_NAME),
        GetStringValueByColumn(resultSet, PhotoColumn::MEDIA_FILE_PATH), false);
    return MediaFileUri (fileUri.GetMediaTypeFromUri(oldUri), fileId, "",
        MEDIA_API_VERSION_V10, extrUri).ToString();
}

string MediaLibraryNapiUtils::GetStringFetchProperty(napi_env env, napi_value arg, bool &err, bool &present,
    const string &propertyName)
{
    size_t res = 0;
    char buffer[PATH_MAX] = {0};
    napi_value property = nullptr;
    napi_has_named_property(env, arg, propertyName.c_str(), &present);
    if (present) {
        if ((napi_get_named_property(env, arg, propertyName.c_str(), &property) != napi_ok) ||
            (napi_get_value_string_utf8(env, property, buffer, PATH_MAX, &res) != napi_ok)) {
            NAPI_ERR_LOG("Could not get the string argument!");
            err = true;
            return "";
        } else {
            string str(buffer);
            present = false;
            return str;
        }
    }
    return "";
}

bool MediaLibraryNapiUtils::IsSystemApp()
{
    static bool isSys = Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(IPCSkeleton::GetSelfTokenID());
    return isSys;
}

NapiScopeHandler::NapiScopeHandler(napi_env env): env_(env)
{
    napi_status status = napi_open_handle_scope(env_, &scope_);
    if (status != napi_ok) {
        NAPI_ERR_LOG("Open Handler scope failed, status %{public}d", status);
        isValid_ = false;
    } else {
        isValid_ = true;
    }
}

NapiScopeHandler::~NapiScopeHandler()
{
    if (isValid_) {
        napi_status status = napi_close_handle_scope(env_, scope_);
        if (status != napi_ok) {
            NAPI_ERR_LOG("Close Handler scope failed, status %{public}d", status);
        }
    }
}

bool NapiScopeHandler::IsValid()
{
    return isValid_;
}

napi_value MediaLibraryNapiUtils::GetNapiValueArray(napi_env env, napi_value arg, vector<napi_value> &values)
{
    bool isArray = false;
    CHECK_ARGS(env, napi_is_array(env, arg, &isArray), JS_ERR_PARAMETER_INVALID);
    if (!isArray) {
        NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID, "Failed to check array type");
        return nullptr;
    }

    uint32_t len = 0;
    CHECK_ARGS(env, napi_get_array_length(env, arg, &len), JS_INNER_FAIL);
    if (len == 0) {
        napi_value result = nullptr;
        CHECK_ARGS(env, napi_get_boolean(env, true, &result), JS_INNER_FAIL);
        return result;
    }

    for (uint32_t i = 0; i < len; i++) {
        napi_value value = nullptr;
        CHECK_ARGS(env, napi_get_element(env, arg, i, &value), JS_INNER_FAIL);
        if (value == nullptr) {
            NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID, "Failed to get element");
            return nullptr;
        }
        values.push_back(value);
    }

    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_boolean(env, true, &result), JS_INNER_FAIL);
    return result;
}

napi_value MediaLibraryNapiUtils::GetStringArray(napi_env env, vector<napi_value> &napiValues, vector<string> &values)
{
    napi_valuetype valueType = napi_undefined;
    unique_ptr<char[]> buffer = make_unique<char[]>(PATH_MAX);
    for (const auto &napiValue : napiValues) {
        CHECK_ARGS(env, napi_typeof(env, napiValue, &valueType), JS_ERR_PARAMETER_INVALID);
        CHECK_COND(env, valueType == napi_string, JS_ERR_PARAMETER_INVALID);

        size_t res = 0;
        CHECK_ARGS(
            env, napi_get_value_string_utf8(env, napiValue, buffer.get(), PATH_MAX, &res), JS_ERR_PARAMETER_INVALID);
        values.emplace_back(buffer.get());
    }
    napi_value ret = nullptr;
    CHECK_ARGS(env, napi_get_boolean(env, true, &ret), JS_INNER_FAIL);
    return ret;
}

std::string GetUriFromAsset(const FileAssetNapi *obj)
{
    string displayName = obj->GetFileDisplayName();
    string filePath = obj->GetFilePath();
    return MediaFileUtils::GetUriByExtrConditions(PhotoColumn::PHOTO_URI_PREFIX, to_string(obj->GetFileId()),
        MediaFileUtils::GetExtraUri(displayName, filePath));
}

napi_value MediaLibraryNapiUtils::GetUriArrayFromAssets(
    napi_env env, vector<napi_value> &napiValues, vector<string> &values)
{
    FileAssetNapi *obj = nullptr;
    for (const auto &napiValue : napiValues) {
        CHECK_ARGS(env, napi_unwrap(env, napiValue, reinterpret_cast<void **>(&obj)), JS_INNER_FAIL);
        if (obj == nullptr) {
            NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID, "Failed to get asset napi object");
            return nullptr;
        }
        if ((obj->GetMediaType() != MEDIA_TYPE_IMAGE && obj->GetMediaType() != MEDIA_TYPE_VIDEO)) {
            NAPI_INFO_LOG("Skip invalid asset, mediaType: %{public}d", obj->GetMediaType());
            continue;
        }
        values.push_back(GetUriFromAsset(obj));
    }
    napi_value ret = nullptr;
    CHECK_ARGS(env, napi_get_boolean(env, true, &ret), JS_INNER_FAIL);
    return ret;
}

void MediaLibraryNapiUtils::FixSpecialDateType(string &selections)
{
    vector<string> dateTypes = { MEDIA_DATA_DB_DATE_ADDED, MEDIA_DATA_DB_DATE_TRASHED, MEDIA_DATA_DB_DATE_MODIFIED };
    for (string dateType : dateTypes) {
        string date2Second = dateType + "_s";
        auto pos = selections.find(dateType);
        while (pos != string::npos) {
            selections.replace(pos, dateType.length(), date2Second);
            pos = selections.find(dateType, pos + date2Second.length());
        }
    }
}

template bool MediaLibraryNapiUtils::HandleSpecialPredicate<unique_ptr<MediaLibraryAsyncContext>>(
    unique_ptr<MediaLibraryAsyncContext> &context, shared_ptr<DataShareAbsPredicates> &predicate,
    const FetchOptionType &fetchOptType);

template bool MediaLibraryNapiUtils::HandleSpecialPredicate<unique_ptr<AlbumNapiAsyncContext>>(
    unique_ptr<AlbumNapiAsyncContext> &context, shared_ptr<DataShareAbsPredicates> &predicate,
    const FetchOptionType &fetchOptType);

template bool MediaLibraryNapiUtils::HandleSpecialPredicate<unique_ptr<SmartAlbumNapiAsyncContext>>(
    unique_ptr<SmartAlbumNapiAsyncContext> &context, shared_ptr<DataShareAbsPredicates> &predicate,
    const FetchOptionType &fetchOptType);

template bool MediaLibraryNapiUtils::GetLocationPredicate<unique_ptr<MediaLibraryAsyncContext>>(
    unique_ptr<MediaLibraryAsyncContext> &context, shared_ptr<DataShareAbsPredicates> &predicate);

template bool MediaLibraryNapiUtils::GetLocationPredicate<unique_ptr<AlbumNapiAsyncContext>>(
    unique_ptr<AlbumNapiAsyncContext> &context, shared_ptr<DataShareAbsPredicates> &predicate);

template bool MediaLibraryNapiUtils::GetLocationPredicate<unique_ptr<SmartAlbumNapiAsyncContext>>(
    unique_ptr<SmartAlbumNapiAsyncContext> &context, shared_ptr<DataShareAbsPredicates> &predicate);

template napi_status MediaLibraryNapiUtils::GetFetchOption<unique_ptr<MediaLibraryAsyncContext>>(napi_env env,
    napi_value arg, const FetchOptionType &fetchOptType, unique_ptr<MediaLibraryAsyncContext> &context);

template napi_status MediaLibraryNapiUtils::GetFetchOption<unique_ptr<PhotoAlbumNapiAsyncContext>>(napi_env env,
    napi_value arg, const FetchOptionType &fetchOptType, unique_ptr<PhotoAlbumNapiAsyncContext> &context);

template napi_status MediaLibraryNapiUtils::GetAlbumFetchOption<unique_ptr<MediaLibraryAsyncContext>>(napi_env env,
    napi_value arg, const FetchOptionType &fetchOptType, unique_ptr<MediaLibraryAsyncContext> &context);

template napi_status MediaLibraryNapiUtils::GetAlbumFetchOption<unique_ptr<PhotoAlbumNapiAsyncContext>>(napi_env env,
    napi_value arg, const FetchOptionType &fetchOptType, unique_ptr<PhotoAlbumNapiAsyncContext> &context);

template napi_status MediaLibraryNapiUtils::GetPredicate<unique_ptr<MediaLibraryAsyncContext>>(napi_env env,
    const napi_value arg, const string &propName, unique_ptr<MediaLibraryAsyncContext> &context,
    const FetchOptionType &fetchOptType);

template napi_status MediaLibraryNapiUtils::GetPredicate<unique_ptr<AlbumNapiAsyncContext>>(napi_env env,
    const napi_value arg, const string &propName, unique_ptr<AlbumNapiAsyncContext> &context,
    const FetchOptionType &fetchOptType);

template napi_status MediaLibraryNapiUtils::GetPredicate<unique_ptr<SmartAlbumNapiAsyncContext>>(napi_env env,
    const napi_value arg, const string &propName, unique_ptr<SmartAlbumNapiAsyncContext> &context,
    const FetchOptionType &fetchOptType);

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

template napi_status MediaLibraryNapiUtils::ParseArgsStringCallback<unique_ptr<PhotoAlbumNapiAsyncContext>>(
    napi_env env, napi_callback_info info, unique_ptr<PhotoAlbumNapiAsyncContext> &context, string &param);

template napi_status MediaLibraryNapiUtils::ParseArgsStringCallback<unique_ptr<MediaAssetChangeRequestAsyncContext>>(
    napi_env env, napi_callback_info info, unique_ptr<MediaAssetChangeRequestAsyncContext> &context, string &param);

template napi_status MediaLibraryNapiUtils::ParseArgsStringCallback<unique_ptr<MediaAssetsChangeRequestAsyncContext>>(
    napi_env env, napi_callback_info info, unique_ptr<MediaAssetsChangeRequestAsyncContext> &context, string &param);

template napi_status MediaLibraryNapiUtils::ParseArgsStringCallback<unique_ptr<MediaAlbumChangeRequestAsyncContext>>(
    napi_env env, napi_callback_info info, unique_ptr<MediaAlbumChangeRequestAsyncContext> &context, string &param);

template napi_status MediaLibraryNapiUtils::ParseArgsStringCallback<unique_ptr<HighlightAlbumNapiAsyncContext>>(
    napi_env env, napi_callback_info info, unique_ptr<HighlightAlbumNapiAsyncContext> &context, string &param);

template napi_status MediaLibraryNapiUtils::ParseArgsStringArrayCallback<unique_ptr<MediaLibraryAsyncContext>>(
    napi_env env, napi_callback_info info, unique_ptr<MediaLibraryAsyncContext> &context, vector<string> &array);

template napi_status MediaLibraryNapiUtils::GetParamCallback<unique_ptr<PhotoAlbumNapiAsyncContext>>(napi_env env,
    unique_ptr<PhotoAlbumNapiAsyncContext> &context);

template napi_status MediaLibraryNapiUtils::GetParamCallback<unique_ptr<SmartAlbumNapiAsyncContext>>(napi_env env,
    unique_ptr<SmartAlbumNapiAsyncContext> &context);

template napi_status MediaLibraryNapiUtils::GetParamCallback<unique_ptr<MediaLibraryInitContext>>(napi_env env,
    unique_ptr<MediaLibraryInitContext> &context);

template napi_status MediaLibraryNapiUtils::ParseArgsBoolCallBack<unique_ptr<MediaLibraryAsyncContext>>(napi_env env,
    napi_callback_info info, unique_ptr<MediaLibraryAsyncContext> &context, bool &param);

template napi_status MediaLibraryNapiUtils::ParseArgsBoolCallBack<unique_ptr<FileAssetAsyncContext>>(napi_env env,
    napi_callback_info info, unique_ptr<FileAssetAsyncContext> &context, bool &param);

template napi_status MediaLibraryNapiUtils::ParseArgsBoolCallBack<unique_ptr<MediaAssetChangeRequestAsyncContext>>(
    napi_env env, napi_callback_info info, unique_ptr<MediaAssetChangeRequestAsyncContext> &context, bool &param);

template napi_status MediaLibraryNapiUtils::ParseArgsBoolCallBack<unique_ptr<MediaAssetsChangeRequestAsyncContext>>(
    napi_env env, napi_callback_info info, unique_ptr<MediaAssetsChangeRequestAsyncContext> &context, bool &param);

template napi_status MediaLibraryNapiUtils::AsyncContextSetObjectInfo<unique_ptr<PhotoAlbumNapiAsyncContext>>(
    napi_env env, napi_callback_info info, unique_ptr<PhotoAlbumNapiAsyncContext> &asyncContext, const size_t minArgs,
    const size_t maxArgs);

template napi_status MediaLibraryNapiUtils::AsyncContextSetObjectInfo<unique_ptr<SmartAlbumNapiAsyncContext>>(
    napi_env env, napi_callback_info info, unique_ptr<SmartAlbumNapiAsyncContext> &asyncContext, const size_t minArgs,
    const size_t maxArgs);

template napi_status MediaLibraryNapiUtils::AsyncContextGetArgs<unique_ptr<MediaAssetChangeRequestAsyncContext>>(
    napi_env env, napi_callback_info info, unique_ptr<MediaAssetChangeRequestAsyncContext>& asyncContext,
    const size_t minArgs, const size_t maxArgs);

template napi_status MediaLibraryNapiUtils::AsyncContextGetArgs<unique_ptr<MediaAssetsChangeRequestAsyncContext>>(
    napi_env env, napi_callback_info info, unique_ptr<MediaAssetsChangeRequestAsyncContext>& asyncContext,
    const size_t minArgs, const size_t maxArgs);

template napi_status MediaLibraryNapiUtils::AsyncContextGetArgs<unique_ptr<MediaAlbumChangeRequestAsyncContext>>(
    napi_env env, napi_callback_info info, unique_ptr<MediaAlbumChangeRequestAsyncContext>& asyncContext,
    const size_t minArgs, const size_t maxArgs);

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

template napi_value MediaLibraryNapiUtils::NapiCreateAsyncWork<MediaLibraryInitContext>(napi_env env,
    unique_ptr<MediaLibraryInitContext> &asyncContext, const string &resourceName,
    void (*execute)(napi_env, void *), void (*complete)(napi_env, napi_status, void *));

template napi_value MediaLibraryNapiUtils::NapiCreateAsyncWork<MediaAssetChangeRequestAsyncContext>(napi_env env,
    unique_ptr<MediaAssetChangeRequestAsyncContext> &asyncContext, const string &resourceName,
    void (*execute)(napi_env, void *), void (*complete)(napi_env, napi_status, void *));

template napi_value MediaLibraryNapiUtils::NapiCreateAsyncWork<MediaAssetsChangeRequestAsyncContext>(napi_env env,
    unique_ptr<MediaAssetsChangeRequestAsyncContext> &asyncContext, const string &resourceName,
    void (*execute)(napi_env, void *), void (*complete)(napi_env, napi_status, void *));

template napi_value MediaLibraryNapiUtils::NapiCreateAsyncWork<MediaAlbumChangeRequestAsyncContext>(napi_env env,
    unique_ptr<MediaAlbumChangeRequestAsyncContext> &asyncContext, const string &resourceName,
    void (*execute)(napi_env, void *), void (*complete)(napi_env, napi_status, void *));

template napi_value MediaLibraryNapiUtils::NapiCreateAsyncWork<HighlightAlbumNapiAsyncContext>(napi_env env,
    unique_ptr<HighlightAlbumNapiAsyncContext> &asyncContext, const string &resourceName,
    void (*execute)(napi_env, void *), void (*complete)(napi_env, napi_status, void *));

template napi_value MediaLibraryNapiUtils::NapiCreateAsyncWork<MovingPhotoAsyncContext>(napi_env env,
    unique_ptr<MovingPhotoAsyncContext> &asyncContext, const string &resourceName,
    void (*execute)(napi_env, void *), void (*complete)(napi_env, napi_status, void *));

template napi_value MediaLibraryNapiUtils::NapiCreateAsyncWork<MediaAssetManagerAsyncContext>(napi_env env,
    unique_ptr<MediaAssetManagerAsyncContext> &asyncContext, const string &resourceName,
    void (*execute)(napi_env, void *), void (*complete)(napi_env, napi_status, void *));

template napi_status MediaLibraryNapiUtils::ParseArgsNumberCallback<unique_ptr<MediaLibraryAsyncContext>>(napi_env env,
    napi_callback_info info, unique_ptr<MediaLibraryAsyncContext> &context, int32_t &value);

template napi_status MediaLibraryNapiUtils::ParseArgsNumberCallback<unique_ptr<FileAssetAsyncContext>>(napi_env env,
    napi_callback_info info, unique_ptr<FileAssetAsyncContext> &context, int32_t &value);

template napi_status MediaLibraryNapiUtils::ParseArgsNumberCallback<unique_ptr<MediaAlbumChangeRequestAsyncContext>>(
    napi_env env, napi_callback_info info, unique_ptr<MediaAlbumChangeRequestAsyncContext> &context, int32_t &value);

template napi_status MediaLibraryNapiUtils::ParseArgsNumberCallback<unique_ptr<HighlightAlbumNapiAsyncContext>>(
    napi_env env, napi_callback_info info, unique_ptr<HighlightAlbumNapiAsyncContext> &context, int32_t &value);

template napi_status MediaLibraryNapiUtils::ParseArgsOnlyCallBack<unique_ptr<MediaLibraryAsyncContext>>(napi_env env,
    napi_callback_info info, unique_ptr<MediaLibraryAsyncContext> &context);

template napi_status MediaLibraryNapiUtils::ParseArgsOnlyCallBack<unique_ptr<FileAssetAsyncContext>>(napi_env env,
    napi_callback_info info, unique_ptr<FileAssetAsyncContext> &context);

template napi_status MediaLibraryNapiUtils::ParseArgsOnlyCallBack<unique_ptr<AlbumNapiAsyncContext>>(napi_env env,
    napi_callback_info info, unique_ptr<AlbumNapiAsyncContext> &context);
} // namespace Media
} // namespace OHOS
