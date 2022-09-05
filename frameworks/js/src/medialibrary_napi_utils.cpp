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

namespace OHOS {
namespace Media {
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

napi_status MediaLibraryNapiUtils::GetParamNumber(napi_env env, napi_value arg, uint32_t &value)
{
    napi_valuetype valueType = napi_undefined;
    CHECK_STATUS_RET(napi_typeof(env, arg, &valueType), "Failed to get type");
    CHECK_COND_RET(valueType == napi_number, napi_number_expected, "Type is not as expected number");
    CHECK_STATUS_RET(napi_get_value_uint32(env, arg, &value), "Failed to get param");
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

napi_status MediaLibraryNapiUtils::GetParamNumberArray(napi_env env, napi_value arg, std::vector<uint32_t> &result)
{
    uint32_t arraySize = 0;
    CHECK_COND_RET(IsArrayForNapiValue(env, arg, arraySize), napi_array_expected, "Failed to check array type");
    for (uint32_t i = 0; i < arraySize; i++) {
        napi_value val = nullptr;
        CHECK_STATUS_RET(napi_get_element(env, arg, i, &val), "Failed to get element");
        uint32_t value = 0;
        CHECK_STATUS_RET(GetParamNumber(env, val, value), "Failed to get element value");
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
        size_t len = 0;
        napi_value property = nullptr;
        bool isArray = false;
        CHECK_STATUS_RET(napi_get_named_property(env, arg, propName.c_str(), &property),
            "Failed to get selectionArgs property");
        CHECK_STATUS_RET(napi_is_array(env, property, &isArray), "Failed to check array type");
        CHECK_COND_RET(isArray, napi_array_expected, "Expected array type");
        CHECK_STATUS_RET(napi_get_array_length(env, property, &len), "Failed to get array length");
        for (size_t i = 0; i < len; i++) {
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
} // namespace Media
} // namespace OHOS
