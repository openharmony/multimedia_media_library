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
#include "medialibrary_data_manager_utils.h"
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
    if (pos != std::string::npos) {
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
    const std::vector<napi_property_descriptor> &staticProps)
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

napi_status MediaLibraryNapiUtils::GetUInt32Array(napi_env env, napi_value arg, std::vector<uint32_t> &result)
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

static napi_status GetParamStr(napi_env env, napi_value arg, const size_t size, std::string &result)
{
    size_t res = 0;
    std::unique_ptr<char[]> buffer = std::make_unique<char[]>(size);
    CHECK_COND_RET(buffer != nullptr, napi_invalid_arg, "Failed to alloc buffer for parameter");
    napi_valuetype valueType = napi_undefined;
    CHECK_STATUS_RET(napi_typeof(env, arg, &valueType), "Failed to get type");
    CHECK_COND_RET(valueType == napi_string, napi_string_expected, "Type is not as expected string");
    CHECK_STATUS_RET(napi_get_value_string_utf8(env, arg, buffer.get(), size, &res), "Failed to get string value");
    result = std::string(buffer.get());
    return napi_ok;
}

napi_status MediaLibraryNapiUtils::GetParamString(napi_env env, napi_value arg, std::string &result)
{
    CHECK_STATUS_RET(GetParamStr(env, arg, ARG_BUF_SIZE, result), "Failed to get string parameter");
    return napi_ok;
}

napi_status MediaLibraryNapiUtils::GetParamStringPathMax(napi_env env, napi_value arg, std::string &result)
{
    CHECK_STATUS_RET(GetParamStr(env, arg, PATH_MAX, result), "Failed to get string parameter");
    return napi_ok;
}

napi_status MediaLibraryNapiUtils::GetProperty(napi_env env, const napi_value arg, const std::string &propName,
    std::string &propValue)
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

napi_status MediaLibraryNapiUtils::GetArrayProperty(napi_env env, napi_value arg, const std::string &propName,
    std::vector<std::string> &array)
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
            std::string val = "";
            CHECK_STATUS_RET(napi_get_element(env, property, i, &item), "Failed to get array item");
            CHECK_STATUS_RET(GetParamStringPathMax(env, item, val), "Failed to get string buffer");
            array.push_back(val);
        }
    }
    return napi_ok;
}

void MediaLibraryNapiUtils::GenTypeMaskFromArray(const std::vector<uint32_t> types, std::string &typeMask)
{
    typeMask.resize(TYPE_MASK_STRING_SIZE, TYPE_MASK_BIT_DEFAULT);
    for (auto &type : types) {
        if ((type >= MEDIA_TYPE_FILE) && (type <= MEDIA_TYPE_AUDIO)) {
            typeMask[std::get<POS_TYPE_MASK_STRING_INDEX>(MEDIA_TYPE_TUPLE_VEC[type])] = TYPE_MASK_BIT_SET;
        }
    }
}

napi_status MediaLibraryNapiUtils::hasCallback(napi_env env, const size_t argc, const napi_value argv[],
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

void MediaLibraryNapiUtils::UriAddFragmentTypeMask(std::string &uri, const std::string &typeMask)
{
    if (!typeMask.empty()) {
        uri += "#" + URI_PARAM_KEY_TYPE + ":" + typeMask;
    }
}

void MediaLibraryNapiUtils::UriRemoveAllFragment(std::string &uri)
{
    size_t fragIndex = uri.find_first_of('#');
    if (fragIndex != std::string::npos) {
        uri = uri.substr(0, fragIndex);
    }
}

std::string MediaLibraryNapiUtils::GetFileIdFromUri(const string &uri)
{
    string id = "-1";

    string temp = uri;
    UriRemoveAllFragment(temp);
    size_t pos = temp.rfind('/');
    if (pos != std::string::npos) {
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
    list<OperationItem> operList;
    for (auto item : predicate->GetOperationList()) {
        // change uri ->file id
        // get networkid
        // replace networkid with file id
        if (item.singleParams[FIELD_IDX].operator string() == MEDIA_DATA_DB_URI) {
            if (item.operation != DataShare::EQUAL_TO) {
                NAPI_ERR_LOG("MEDIA_DATA_DB_URI predicates not support %{public}d", item.operation);
                return false;
            }
            string uri = item.singleParams[VALUE_IDX].operator string();
            UriRemoveAllFragment(uri);
            string fileId;
            MediaLibraryNapiUtils::GetNetworkIdAndFileIdFromUri(uri, context->networkId, fileId);
            item.singleParams[FIELD_IDX] = isAlbum ? DataShare::DataSharePredicatesObject(MEDIA_DATA_DB_BUCKET_ID) :
                DataShare::DataSharePredicatesObject(MEDIA_DATA_DB_ID);
            item.singleParams[VALUE_IDX] = DataShare::DataSharePredicatesObject(fileId);
        }

        if (item.singleParams[FIELD_IDX].operator string() == DEVICE_DB_NETWORK_ID) {
            if (item.operation != DataShare::EQUAL_TO ||
                item.singleParams[VALUE_IDX].GetType() != DataShare::DataSharePredicatesObjectType::TYPE_STRING) {
                NAPI_ERR_LOG("DEVICE_DB_NETWORK_ID predicates not support %{public}d", item.operation);
                return false;
            }
            context->networkId = item.singleParams[VALUE_IDX].operator string();
            continue;
        }
        operList.push_back(item);
    }
    if (operList.size()) {
        context->predicates = DataSharePredicates(operList);
    }
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
napi_status MediaLibraryNapiUtils::GetPredicate(napi_env env, const napi_value arg, const std::string &propName,
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

template bool MediaLibraryNapiUtils::HandleSpecialPredicate<unique_ptr<MediaLibraryAsyncContext>>(
    unique_ptr<MediaLibraryAsyncContext> &context, shared_ptr<DataShareAbsPredicates> &predicate, bool isAlbum);

template bool MediaLibraryNapiUtils::HandleSpecialPredicate<unique_ptr<AlbumNapiAsyncContext>>(
    unique_ptr<AlbumNapiAsyncContext> &context, shared_ptr<DataShareAbsPredicates> &predicate, bool isAlbum);

template bool MediaLibraryNapiUtils::HandleSpecialPredicate<unique_ptr<SmartAlbumNapiAsyncContext>>(
    unique_ptr<SmartAlbumNapiAsyncContext> &context, shared_ptr<DataShareAbsPredicates> &predicate, bool isAlbum);

template napi_status MediaLibraryNapiUtils::GetAssetFetchOption<unique_ptr<MediaLibraryAsyncContext>>(napi_env env,
    napi_value arg, unique_ptr<MediaLibraryAsyncContext> &context);

template napi_status MediaLibraryNapiUtils::GetPredicate<unique_ptr<MediaLibraryAsyncContext>>(napi_env env,
    const napi_value arg, const std::string &propName, unique_ptr<MediaLibraryAsyncContext> &context, bool isAlbum);

template napi_status MediaLibraryNapiUtils::GetPredicate<unique_ptr<AlbumNapiAsyncContext>>(napi_env env,
    const napi_value arg, const std::string &propName, unique_ptr<AlbumNapiAsyncContext> &context, bool isAlbum);

template napi_status MediaLibraryNapiUtils::GetPredicate<unique_ptr<SmartAlbumNapiAsyncContext>>(napi_env env,
    const napi_value arg, const std::string &propName, unique_ptr<SmartAlbumNapiAsyncContext> &context, bool isAlbum);

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
} // namespace Media
} // namespace OHOS
