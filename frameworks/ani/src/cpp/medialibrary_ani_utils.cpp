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
#define MLOG_TAG "MediaLibraryAniUtils"

#include "medialibrary_ani_utils.h"

#include <cctype>
#include "accesstoken_kit.h"
#include "basic/result_set.h"
#include "datashare_predicates.h"
#include "file_asset_info_ani.h"
#include "location_column.h"
#include "ipc_skeleton.h"
#include "media_device_column.h"
#include "media_file_uri.h"
#include "media_file_utils.h"
#include "media_library_ani.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_ani_enum_comm.h"
#include "medialibrary_tracer.h"
#include "medialibrary_type_const.h"
#include "photo_album_ani.h"
#include "photo_map_column.h"
#include "tokenid_kit.h"
#include "userfile_client.h"
#include "vision_album_column.h"
#include "vision_column.h"
#include "vision_face_tag_column.h"
#include "vision_pose_column.h"
#include "vision_image_face_column.h"
#include "userfilemgr_uri.h"
#include <nlohmann/json.hpp>

using namespace std;
using namespace OHOS::DataShare;
using namespace OHOS::Security;

namespace OHOS {
namespace Media {
static constexpr int32_t FIELD_IDX = 0;
static constexpr int32_t VALUE_IDX = 1;
static const string EMPTY_STRING = "";
using json = nlohmann::json;

ani_boolean MediaLibraryAniUtils::isArray(ani_env *env, ani_object object)
{
    ani_boolean isArray = ANI_FALSE;
    ani_class cls {};
    static const std::string className = "Lescompat/Array;";
    CHECK_COND_RET(ANI_OK == env->FindClass(className.c_str(), &cls), isArray, "Can't find Lescompat/Array.");

    ani_static_method static_method {};
    CHECK_COND_RET(ANI_OK == env->Class_FindStaticMethod(cls, "isArray", nullptr, &static_method), isArray,
        "Can't find method isArray in Lescompat/Array.");

    CHECK_COND_RET(ANI_OK == env->Class_CallStaticMethod_Boolean(cls, static_method, &isArray, object),
        isArray, "Call method isArray failed.");

    return isArray;
}

ani_boolean MediaLibraryAniUtils::isUndefined(ani_env *env, ani_object object)
{
    ani_boolean isUndefined = ANI_TRUE;
    CHECK_COND_RET(ANI_OK == env->Reference_IsUndefined(object, &isUndefined), ANI_TRUE,
        "Call Reference_IsUndefined failed.");
    return isUndefined;
}

ani_status MediaLibraryAniUtils::GetBool(ani_env *env, ani_boolean arg, bool &value)
{
    value = (arg == ANI_TRUE);
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::GetBool(ani_env *env, ani_object arg, bool &value)
{
    CHECK_COND_RET(isUndefined(env, arg) != ANI_TRUE, ANI_ERROR, "invalid property.");

    ani_class cls {};
    static const std::string className = "Lstd/core/Boolean;";
    CHECK_STATUS_RET(env->FindClass(className.c_str(), &cls), "Can't find Lstd/core/Boolean.");

    ani_method method {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "valueOf", nullptr, &method),
        "Can't find method valueOf in Lstd/core/Boolean.");

    ani_boolean result = 0;
    CHECK_STATUS_RET(env->Object_CallMethod_Boolean(arg, method, &result), "Call method valueOf failed.");

    return GetBool(env, result, value);
}

ani_status MediaLibraryAniUtils::GetByte(ani_env *env, ani_byte arg, uint8_t &value)
{
    value = static_cast<uint8_t>(arg);
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::GetByte(ani_env *env, ani_object arg, uint8_t &value)
{
    CHECK_COND_RET(isUndefined(env, arg) != ANI_TRUE, ANI_ERROR, "invalid property.");

    ani_class cls {};
    static const std::string className = "Lstd/core/Byte;";
    CHECK_STATUS_RET(env->FindClass(className.c_str(), &cls), "Can't find Lstd/core/Byte.");

    ani_method method {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "byteValue", nullptr, &method),
        "Can't find method byteValue in Lstd/core/Byte.");

    ani_byte result;
    CHECK_STATUS_RET(env->Object_CallMethod_Byte(arg, method, &result), "Call method byteValue failed.");

    return GetByte(env, result, value);
}

ani_status MediaLibraryAniUtils::GetShort(ani_env *env, ani_short arg, int16_t &value)
{
    value = static_cast<int16_t>(arg);
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::GetShort(ani_env *env, ani_object arg, int16_t &value)
{
    CHECK_COND_RET(isUndefined(env, arg) != ANI_TRUE, ANI_ERROR, "invalid property.");

    ani_class cls {};
    static const std::string className = "Lstd/core/Short;";
    CHECK_STATUS_RET(env->FindClass(className.c_str(), &cls), "Can't find Lstd/core/Short.");

    ani_method method {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "shortValue", nullptr, &method),
        "Can't find method shortValue in Lstd/core/Short.");

    ani_short result;
    CHECK_STATUS_RET(env->Object_CallMethod_Short(arg, method, &result), "Call method shortValue failed.");

    return GetShort(env, result, value);
}

ani_status MediaLibraryAniUtils::GetInt32(ani_env *env, ani_int arg, int32_t &value)
{
    value = static_cast<int32_t>(arg);
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::GetInt32(ani_env *env, ani_object arg, int32_t &value)
{
    CHECK_COND_RET(isUndefined(env, arg) != ANI_TRUE, ANI_ERROR, "invalid property.");

    ani_class cls {};
    static const std::string className = "Lstd/core/Int;";
    CHECK_STATUS_RET(env->FindClass(className.c_str(), &cls), "Can't find Lstd/core/Int.");

    ani_method method {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "intValue", nullptr, &method),
        "Can't find method intValue in Lstd/core/Int.");

    ani_int result;
    CHECK_STATUS_RET(env->Object_CallMethod_Int(arg, method, &result), "Call method intValue failed.");

    return GetInt32(env, result, value);
}

ani_status MediaLibraryAniUtils::GetUint32(ani_env *env, ani_int arg, uint32_t &value)
{
    value = static_cast<uint32_t>(arg);
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::GetUint32(ani_env *env, ani_object arg, uint32_t &value)
{
    CHECK_COND_RET(isUndefined(env, arg) != ANI_TRUE, ANI_ERROR, "invalid property.");

    ani_class cls {};
    static const std::string className = "Lstd/core/Int;";
    CHECK_STATUS_RET(env->FindClass(className.c_str(), &cls), "Can't find Lstd/core/Int.");

    ani_method method {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "intValue", nullptr, &method),
        "Can't find method intValue in Lstd/core/Int.");

    ani_int result;
    CHECK_STATUS_RET(env->Object_CallMethod_Int(arg, method, &result), "Call method intValue failed.");
    return GetUint32(env, result, value);
}

ani_status MediaLibraryAniUtils::GetInt64(ani_env *env, ani_long arg, int64_t &value)
{
    value = static_cast<int64_t>(arg);
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::GetInt64(ani_env *env, ani_object arg, int64_t &value)
{
    CHECK_COND_RET(isUndefined(env, arg) != ANI_TRUE, ANI_ERROR, "invalid property.");

    ani_class cls {};
    static const std::string className = "Lstd/core/Int;";
    CHECK_STATUS_RET(env->FindClass(className.c_str(), &cls), "Can't find Lstd/core/Int.");

    ani_method method {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "longValue", nullptr, &method),
        "Can't find method longValue in Lstd/core/Int.");
    
    ani_long result;
    CHECK_STATUS_RET(env->Object_CallMethod_Long(arg, method, &result), "Call method longValue failed.");
    return GetInt64(env, result, value);
}

ani_status MediaLibraryAniUtils::GetFloat(ani_env *env, ani_float arg, float &value)
{
    value = static_cast<float>(arg);
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::GetFloat(ani_env *env, ani_object arg, float &value)
{
    CHECK_COND_RET(isUndefined(env, arg) != ANI_TRUE, ANI_ERROR, "invalid property.");

    ani_class cls {};
    static const std::string className = "Lstd/core/Float;";
    CHECK_STATUS_RET(env->FindClass(className.c_str(), &cls), "Can't find Lstd/core/Float.");

    ani_method method {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "floatValue", nullptr, &method),
        "Can't find method floatValue in Lstd/core/Float.");
    
    ani_float result;
    CHECK_STATUS_RET(env->Object_CallMethod_Float(arg, method, &result), "Call method floatValue failed.");
    return GetFloat(env, result, value);
}

ani_status MediaLibraryAniUtils::GetDouble(ani_env *env, ani_double arg, double &value)
{
    value = static_cast<double>(arg);
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::GetDouble(ani_env *env, ani_object arg, double &value)
{
    CHECK_COND_RET(isUndefined(env, arg) != ANI_TRUE, ANI_ERROR, "invalid property.");

    ani_class cls {};
    static const std::string className = "Lstd/core/Double;";
    CHECK_STATUS_RET(env->FindClass(className.c_str(), &cls), "Can't find Lstd/core/Double.");

    ani_method method {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "doubleValue", nullptr, &method),
        "Can't find method doubleValue in Lstd/core/Double.");
    
    ani_double result;
    CHECK_STATUS_RET(env->Object_CallMethod_Double(arg, method, &result), "Call method doubleValue failed.");
    return GetDouble(env, result, value);
}

ani_status MediaLibraryAniUtils::GetString(ani_env *env, ani_string arg, std::string &str)
{
    CHECK_COND_RET(arg != nullptr, ANI_INVALID_ARGS, "GetString invalid arg");

    ani_size srcSize = 0;
    CHECK_STATUS_RET(env->String_GetUTF8Size(arg, &srcSize), "String_GetUTF8Size failed");

    std::vector<char> buffer(srcSize + 1);
    ani_size dstSize = 0;
    CHECK_STATUS_RET(env->String_GetUTF8SubString(arg, 0, srcSize, buffer.data(), buffer.size(), &dstSize),
        "String_GetUTF8SubString failed");

    str.assign(buffer.data(), dstSize);
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::GetString(ani_env *env, ani_object arg, std::string &str)
{
    CHECK_COND_RET(isUndefined(env, arg) != ANI_TRUE, ANI_ERROR, "invalid property.");

    return GetString(env, static_cast<ani_string>(arg), str);
}

ani_status MediaLibraryAniUtils::ToAniString(ani_env *env, const std::string &str, ani_string &aniStr)
{
    CHECK_STATUS_RET(env->String_NewUTF8(str.c_str(), str.size(), &aniStr), "String_NewUTF8 failed");
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::ToAniInt(ani_env *env, const std::int32_t &int32, ani_int &aniInt)
{
    aniInt = static_cast<ani_int>(int32);
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::ToAniLong(ani_env *env, const std::int64_t &int64, ani_long &aniLong)
{
    aniLong = static_cast<ani_long>(int64);
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::ToAniDouble(ani_env *env, const double &arg, ani_double &aniDouble)
{
    aniDouble = static_cast<ani_double>(arg);
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::GetParamStringWithLength(ani_env *env, ani_string arg, int32_t maxLen,
    std::string &str)
{
    ani_size srcSize = 0;
    CHECK_STATUS_RET(env->String_GetUTF8Size(arg, &srcSize), "String_GetUTF8Size failed");
    if (static_cast<int32_t>(srcSize) > maxLen) {
        ANI_ERR_LOG("Invalid string length: %{public}zu, maxLen: %{public}d", srcSize, maxLen);
        return ANI_INVALID_ARGS;
    }
    return GetString(env, arg, str);
}

ani_status MediaLibraryAniUtils::GetParamStringPathMax(ani_env *env, ani_string arg, std::string &str)
{
    return GetParamStringWithLength(env, arg, PATH_MAX, str);
}

ani_status MediaLibraryAniUtils::GetParamStringPathMax(ani_env *env, ani_object arg, std::string &str)
{
    CHECK_COND_RET(isUndefined(env, arg) != ANI_TRUE, ANI_ERROR, "invalid property.");
    return GetParamStringWithLength(env, static_cast<ani_string>(arg), PATH_MAX, str);
}

ani_status MediaLibraryAniUtils::ToAniBooleanObject(ani_env *env, bool src, ani_object &aniObj)
{
    static const char *className = "Lstd/core/Boolean;";
    ani_class cls {};
    CHECK_STATUS_RET(env->FindClass(className, &cls), "Failed to find class: %{public}s", className);

    ani_method ctor {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<ctor>", "Z:V", &ctor), "Failed to find method: ctor");

    ani_boolean aniBool = src ? ANI_TRUE : ANI_FALSE;
    CHECK_STATUS_RET(env->Object_New(cls, ctor, &aniObj, aniBool), "New bool Object Fail");
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::ToAniIntObject(ani_env *env, int32_t src, ani_object &aniObj)
{
    static const char *className = "Lstd/core/Int;";
    ani_class cls {};
    CHECK_STATUS_RET(env->FindClass(className, &cls), "Failed to find class: %{public}s", className);

    ani_method ctor {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<ctor>", "I:V", &ctor), "Failed to find method: ctor");

    CHECK_STATUS_RET(env->Object_New(cls, ctor, &aniObj, static_cast<ani_int>(src)), "New int32 Object Fail");
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::ToAniDoubleObject(ani_env *env, double src, ani_object &aniObj)
{
    static const char *className = "Lstd/core/Double;";
    ani_class cls {};
    CHECK_STATUS_RET(env->FindClass(className, &cls), "Failed to find class: %{public}s", className);

    ani_method ctor {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<ctor>", "D:V", &ctor), "Failed to find method: ctor");

    CHECK_STATUS_RET(env->Object_New(cls, ctor, &aniObj, static_cast<ani_double>(src)), "New double Object Fail");
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::ToAniLongObject(ani_env *env, int64_t src, ani_object &aniObj)
{
    static const char *className = "Lescompat/BigInt;";
    ani_class cls {};
    CHECK_STATUS_RET(env->FindClass(className, &cls), "Failed to find class: %{public}s", className);

    ani_method ctor {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<ctor>", "J:V", &ctor), "Failed to find method: ctor");

    CHECK_STATUS_RET(env->Object_New(cls, ctor, &aniObj, static_cast<ani_long>(src)), "New int64_t Object Fail");
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::GetUint32Array(ani_env *env, ani_object arg, std::vector<uint32_t> &array)
{
    CHECK_COND_RET(isUndefined(env, arg) != ANI_TRUE, ANI_ERROR, "invalid property.");
    CHECK_COND_RET(isArray(env, arg) == ANI_TRUE, ANI_ERROR, "invalid parameter.");

    ani_double length;
    CHECK_STATUS_RET(env->Object_GetPropertyByName_Double(arg, "length", &length),
        "Call method <get>length failed.");

    for (int i = 0; i < static_cast<ani_int>(length); i++) {
        ani_ref value;
        CHECK_STATUS_RET(env->Object_CallMethodByName_Ref(arg, "$_get", "I:Lstd/core/Object;", &value, (ani_int)i),
            "Call method $_get failed.");

        uint32_t uValue = 0;
        CHECK_STATUS_RET(GetUint32(env, (ani_object)value, uValue), "Call method GetUint32 failed.");

        array.emplace_back(uValue);
    }
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::ToAniInt32Array(ani_env *env, const std::vector<uint32_t> &array,
    ani_object &aniArray)
{
    ani_class cls {};
    static const std::string className = "Lescompat/Array;";
    CHECK_STATUS_RET(env->FindClass(className.c_str(), &cls), "Can't find Lescompat/Array.");

    ani_method arrayConstructor {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<ctor>", "I:V;", &arrayConstructor),
        "Can't find method <ctor> in Lescompat/Array.");

    CHECK_STATUS_RET(env->Object_New(cls, arrayConstructor, &aniArray, array.size()), "Call method <ctor> failed.");

    ani_method setMethod {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "$_set", "ILstd/core/Object;:V", &setMethod),
        "Can't find method $_set in Lescompat/Array.");

    for (size_t i = 0; i < array.size(); i++) {
        ani_int aniInt = static_cast<ani_int>(array[i]);
        CHECK_STATUS_RET(env->Object_CallMethod_Void(aniArray, setMethod, (ani_int)i, aniInt),
            "Call method $_set failed.");
    }
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::GetStringArray(ani_env *env, ani_object arg, std::vector<std::string> &array)
{
    CHECK_COND_RET(isUndefined(env, arg) != ANI_TRUE, ANI_ERROR, "invalid property.");
    CHECK_COND_RET(isArray(env, arg) == ANI_TRUE, ANI_ERROR, "invalid parameter.");

    ani_double length;
    CHECK_STATUS_RET(env->Object_GetPropertyByName_Double(arg, "length", &length),
        "Call method <get>length failed.");

    for (int i = 0; i < static_cast<ani_int>(length); i++) {
        ani_ref value {};
        CHECK_STATUS_RET(env->Object_CallMethodByName_Ref(arg, "$_get", "I:Lstd/core/Object;", &value, (ani_int)i),
            "Call method $_get failed.");

        std::string sValue;
        CHECK_STATUS_RET(GetString(env, (ani_object)value, sValue), "Call GetString failed.");
        array.emplace_back(sValue);
    }
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::ToAniStringArray(ani_env *env, const std::vector<std::string> &array,
    ani_object &aniArray)
{
    ani_class cls {};
    static const std::string className = "Lescompat/Array;";
    CHECK_STATUS_RET(env->FindClass(className.c_str(), &cls), "Can't find Lescompat/Array.");

    ani_method arrayConstructor {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<ctor>", "I:V", &arrayConstructor),
        "Can't find method <ctor> in Lescompat/Array.");

    CHECK_STATUS_RET(env->Object_New(cls, arrayConstructor, &aniArray, array.size()), "Call method <ctor> failed.");

    ani_method setMethod {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "$_set", "ILstd/core/Object;:V", &setMethod),
        "Can't find method $_set in Lescompat/Array.");

    for (size_t i = 0; i < array.size(); i++) {
        ani_string aniString {};
        CHECK_STATUS_RET(ToAniString(env, array[i], aniString), "ToAniString failed");
        CHECK_STATUS_RET(env->Object_CallMethod_Void(aniArray, setMethod, (ani_int)i, aniString),
            "Call method $_set failed.");
    }
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::GetProperty(ani_env *env, ani_object arg, const std::string &propName,
    std::string &propValue)
{
    ani_object propObj;
    CHECK_STATUS_RET(GetProperty(env, arg, propName, propObj), "GetProperty failed.");
    CHECK_STATUS_RET(GetString(env, propObj, propValue), "GetString failed.");
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::GetProperty(ani_env *env, ani_object arg, const std::string &propName,
    ani_object &propObj)
{
    ani_ref propRef;
    CHECK_STATUS_RET(env->Object_GetPropertyByName_Ref(arg, propName.c_str(), &propRef),
        "Object_GetPropertyByName_Ref failed.");
    propObj = static_cast<ani_object>(propRef);
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::GetArrayProperty(ani_env *env, ani_object arg, const std::string &propName,
    std::vector<std::string> &array)
{
    ani_object property;
    CHECK_STATUS_RET(GetProperty(env, arg, propName, property), "GetProperty failed.");
    CHECK_STATUS_RET(GetStringArray(env, property, array), "GetStringArray failed.");
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::GetArrayBuffer(ani_env *env, ani_object arg, std::unique_ptr<uint8_t[]> &buffer,
    size_t &size)
{
    CHECK_COND_RET(isUndefined(env, arg) != ANI_TRUE, ANI_ERROR, "invalid property.");
    ani_int length;
    CHECK_STATUS_RET(env->Object_CallMethodByName_Int(arg, "getByteLength", nullptr, &length),
        "GetArrayBuffer Object_CallMethodByName_Int failed.");
    size = static_cast<size_t>(length);
    buffer = std::make_unique<uint8_t[]>(size);
    for (int i = 0; i < static_cast<int>(size); ++i) {
        ani_byte value {};
        CHECK_STATUS_RET(env->Object_CallMethodByName_Byte(arg, "at", nullptr, &value, static_cast<ani_int>(i)),
            "GetArrayBuffer Call method at failed.");
        CHECK_STATUS_RET(GetByte(env, value, buffer[i]), "GetArrayBuffer GetByte failed.");
    }
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::GetOptionalStringPathMaxField(ani_env *env, ani_object src,
    const std::string &fieldName, std::string &value)
{
    ani_ref field_ref;
    if (ANI_OK != env->Object_GetPropertyByName_Ref(src, fieldName.c_str(), &field_ref)) {
        ANI_ERR_LOG("Object_GetPropertyByName_Ref %{public}s Failed", fieldName.c_str());
        return ANI_INVALID_ARGS;
    }

    ani_boolean isUndefined;
    env->Reference_IsUndefined(field_ref, &isUndefined);
    if (isUndefined) {
        ANI_INFO_LOG("%{public}s is undefined", fieldName.c_str());
        return ANI_NOT_FOUND;
    }

    MediaLibraryAniUtils::GetParamStringPathMax(env, static_cast<ani_string>(field_ref), value);
    ANI_INFO_LOG("%{public}s Get %{public}s: %{public}s", __func__, fieldName.c_str(), value.c_str());
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::GetOptionalEnumInt32Field(ani_env *env, ani_object src, const std::string &fieldName,
    int32_t &value)
{
    ani_ref field_ref;
    if (ANI_OK != env->Object_GetPropertyByName_Ref(src, fieldName.c_str(), &field_ref)) {
        ANI_ERR_LOG("Object_GetPropertyByName_Ref %{public}s Failed", fieldName.c_str());
        return ANI_INVALID_ARGS;
    }

    ani_boolean isUndefined;
    env->Reference_IsUndefined(field_ref, &isUndefined);
    if (isUndefined) {
        ANI_INFO_LOG("%{public}s is undefined", fieldName.c_str());
        return ANI_NOT_FOUND;
    }

    ani_int enum_value {};
    CHECK_STATUS_RET(env->EnumItem_GetValue_Int(static_cast<ani_enum_item>(field_ref), &enum_value),
        "EnumItem_GetValue_Int failed");
    CHECK_STATUS_RET(GetInt32(env, enum_value, value), "GetInt32 failed");
    ANI_INFO_LOG("%{public}s Get %{public}s: %{public}d", __func__, fieldName.c_str(), value);
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::GetOptionalEnumStringField(ani_env *env, ani_object src, const std::string &fieldName,
    std::string &value)
{
    ani_ref field_ref;
    if (ANI_OK != env->Object_GetPropertyByName_Ref(src, fieldName.c_str(), &field_ref)) {
        ANI_ERR_LOG("Object_GetPropertyByName_Ref %{public}s Failed", fieldName.c_str());
        return ANI_INVALID_ARGS;
    }

    ani_boolean isUndefined;
    env->Reference_IsUndefined(field_ref, &isUndefined);
    if (isUndefined) {
        ANI_INFO_LOG("%{public}s is undefined", fieldName.c_str());
        return ANI_NOT_FOUND;
    }

    ani_string aniString {};
    CHECK_STATUS_RET(env->EnumItem_GetValue_String(static_cast<ani_enum_item>(field_ref), &aniString),
        "EnumItem_GetValue_String failed");
    CHECK_STATUS_RET(GetString(env, aniString, value), "GetString failed");
    ANI_INFO_LOG("%{public}s Get %{public}s: %{public}s", __func__, fieldName.c_str(), value.c_str());
    return ANI_OK;
}

std::unordered_map<std::string, std::variant<int32_t, bool, std::string>> MediaLibraryAniUtils::GetCreateOptions(
    ani_env *env, ani_object src)
{
    std::unordered_map<std::string, std::variant<int32_t, bool, std::string>> result;
    std::string title;
    if (ANI_OK == GetOptionalStringPathMaxField(env, src, "title", title)) {
        result[PhotoColumn::MEDIA_TITLE] = title;
    }

    int32_t subtype;
    if (ANI_OK == GetOptionalEnumInt32Field(env, src, "subtype", subtype)) {
        result[PhotoColumn::PHOTO_SUBTYPE] = subtype;
    }
    return result;
}

std::unordered_map<std::string, std::variant<int32_t, bool, std::string>> MediaLibraryAniUtils::GetPhotoCreateOptions(
    ani_env *env, ani_object src)
{
    std::unordered_map<std::string, std::variant<int32_t, bool, std::string>> result;
    std::string cameraShotKey;
    if (ANI_OK == GetOptionalStringPathMaxField(env, src, "cameraShotKey", cameraShotKey)) {
        result[PhotoColumn::CAMERA_SHOT_KEY] = cameraShotKey;
    }

    int32_t subtype;
    if (ANI_OK == GetOptionalEnumInt32Field(env, src, "subtype", subtype)) {
        result[PhotoColumn::PHOTO_SUBTYPE] = subtype;
    }
    return result;
}

bool MediaLibraryAniUtils::IsSystemApp()
{
    static bool isSys = AccessToken::TokenIdKit::IsSystemAppByFullTokenID(OHOS::IPCSkeleton::GetSelfTokenID());
    return isSys;
}

static std::string GetUriFromAsset(const std::shared_ptr<FileAsset> &fileAsset)
{
    std::string displayName = fileAsset->GetDisplayName();
    std::string filePath = fileAsset->GetPath();
    return MediaFileUtils::GetUriByExtrConditions(PhotoColumn::PHOTO_URI_PREFIX, to_string(fileAsset->GetId()),
        MediaFileUtils::GetExtraUri(displayName, filePath));
}

ani_status MediaLibraryAniUtils::GetUriArrayFromAssets(ani_env *env, ani_object arg, std::vector<std::string> &array)
{
    CHECK_COND_RET(isUndefined(env, arg) != ANI_TRUE, ANI_ERROR, "invalid property.");
    CHECK_COND_RET(isArray(env, arg) == ANI_TRUE, ANI_ERROR, "invalid parameter.");

    ani_double length;
    CHECK_STATUS_RET(env->Object_GetPropertyByName_Double(arg, "length", &length),
        "Call method <get>length failed.");

    for (ani_int i = 0; i < static_cast<ani_int>(length); i++) {
        ani_ref asset {};
        CHECK_STATUS_RET(env->Object_CallMethodByName_Ref(arg, "$_get", "I:Lstd/core/Object;", &asset, i),
            "Call method $_get failed.");

        FileAssetAni *obj = FileAssetAni::Unwrap(env, static_cast<ani_object>(asset));
        if (obj == nullptr || obj->GetFileAssetInstance() == nullptr) {
            AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID, "Failed to get asset ani object");
            return ANI_INVALID_ARGS;
        }
        MediaType mediaType = obj->GetFileAssetInstance()->GetMediaType();
        if ((mediaType != MEDIA_TYPE_IMAGE && mediaType != MEDIA_TYPE_VIDEO)) {
            ANI_INFO_LOG("Skip invalid asset, mediaType: %{public}d", mediaType);
            continue;
        }
        array.push_back(GetUriFromAsset(obj->GetFileAssetInstance()));
    }
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::ToFileAssetInfoAniArray(ani_env *env, std::vector<std::unique_ptr<FileAsset>> &array,
    ani_object &aniArray)
{
    ani_class cls {};
    static const std::string className = "Lescompat/Array;";
    CHECK_STATUS_RET(env->FindClass(className.c_str(), &cls), "Can't find Lescompat/Array.");

    ani_method method {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<ctor>", "I:V", &method),
        "Can't find method <ctor> in Lescompat/Array.");

    CHECK_STATUS_RET(env->Object_New(cls, method, &aniArray, array.size()), "Call method <ctor> failed.");

    ani_method setMethod {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "$_set", "ILstd/core/Object;:V", &setMethod),
        "Can't find method set in Lescompat/Array.");

    for (size_t i = 0; i < array.size(); ++i) {
        ani_object fileAssetObj = FileAssetInfo::ToFileAssetInfoObject(env, std::move(array[i]));
        CHECK_COND_RET(fileAssetObj != nullptr, ANI_ERROR, "CreateFileAssetObj failed");
        CHECK_STATUS_RET(env->Object_CallMethod_Void(aniArray, setMethod, (ani_int)i, fileAssetObj),
            "Call method $_set failed.");
    }
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::ToFileAssetAniArray(ani_env *env, std::vector<std::unique_ptr<FileAsset>> &array,
    ani_object &aniArray)
{
    ani_class cls {};
    static const std::string className = "Lescompat/Array;";
    CHECK_STATUS_RET(env->FindClass(className.c_str(), &cls), "Can't find Lescompat/Array.");

    ani_method method {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<ctor>", "I:V", &method),
        "Can't find method <ctor> in Lescompat/Array.");

    CHECK_STATUS_RET(env->Object_New(cls, method, &aniArray, array.size()), "Call method <ctor> failed.");

    ani_method setMethod {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "$_set", "ILstd/core/Object;:V", &setMethod),
        "Can't find method set in Lescompat/Array.");

    for (size_t i = 0; i < array.size(); ++i) {
        auto fileAssetAni = FileAssetAni::CreateFileAsset(env, array[i]);
        ani_object value = FileAssetAni::Wrap(env, fileAssetAni);
        CHECK_COND_RET(value != nullptr, ANI_ERROR, "CreatePhotoAsset failed");
        CHECK_STATUS_RET(env->Object_CallMethod_Void(aniArray, setMethod, (ani_int)i, value),
            "Call method $_set failed.");
    }
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::ToFileAssetAniPtr(ani_env *env, std::unique_ptr<FetchResult<FileAsset>> fileAsset,
    ani_object &aniPtr)
{
    if (fileAsset == nullptr) {
        ANI_ERR_LOG("fileAsset is nullptr");
        return ANI_ERROR;
    }
    aniPtr = FetchFileResultAni::CreateFetchFileResult(env, move(fileAsset));
    if (aniPtr == nullptr) {
        ANI_ERR_LOG("FetchFileResultAni::CreateFetchFileResult failed");
        return ANI_ERROR;
    }
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::GetPhotoAlbumAniArray(ani_env *env, ani_object arg, std::vector<PhotoAlbumAni*> &array)
{
    CHECK_COND_RET(isUndefined(env, arg) != ANI_TRUE, ANI_ERROR, "invalid property.");
    CHECK_COND_RET(isArray(env, arg) == ANI_TRUE, ANI_ERROR, "invalid parameter.");

    ani_double length;
    CHECK_STATUS_RET(env->Object_GetPropertyByName_Double(arg, "length", &length),
        "Call method <get>length failed.");

    for (int i = 0; i < static_cast<ani_int>(length); i++) {
        ani_ref value {};
        CHECK_STATUS_RET(env->Object_CallMethodByName_Ref(arg, "$_get", "I:Lstd/core/Object;", &value, (ani_int)i),
            "Call method $_get failed.");

        array.emplace_back(PhotoAlbumAni::UnwrapPhotoAlbumObject(env, (ani_object)value));
    }
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::ToPhotoAlbumAniArray(ani_env *env, std::vector<unique_ptr<PhotoAlbum>> &array,
    ani_object &aniArray)
{
    ani_class cls {};
    static const std::string className = "Lescompat/Array;";
    CHECK_STATUS_RET(env->FindClass(className.c_str(), &cls), "Can't find Lescompat/Array.");

    ani_method method {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<ctor>", "I:V", &method),
        "Can't find method <ctor> in Lescompat/Array.");

    CHECK_STATUS_RET(env->Object_New(cls, method, &aniArray, array.size()), "Call method <ctor> failed.");

    ani_method setMethod {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "$_set", "ILstd/core/Object;:V", &setMethod),
        "Can't find method set in Lescompat/Array.");

    for (size_t i = 0; i < array.size(); i++) {
        ani_object value = PhotoAlbumAni::CreatePhotoAlbumAni(env, array[i]);
        CHECK_COND_RET(value != nullptr, ANI_ERROR, "CreatePhotoAlbum failed");
        CHECK_STATUS_RET(env->Object_CallMethod_Void(aniArray, setMethod, (ani_int)i, value),
            "Call method $_set failed.");
    }
    return ANI_OK;
}

template <class AniContext>
ani_status MediaLibraryAniUtils::GetFetchOption(ani_env *env, ani_object fetchOptions, FetchOptionType fetchOptType,
    AniContext &context)
{
    // Parse the argument into fetchOption if any
    CHECK_STATUS_RET(GetPredicate(env, fetchOptions, "predicates", context, fetchOptType), "invalid predicate");
    CHECK_STATUS_RET(GetArrayProperty(env, fetchOptions, "fetchColumns", context->fetchColumn),
        "Failed to parse fetchColumn");
    return ANI_OK;
}

DataSharePredicates* MediaLibraryAniUtils::UnwrapPredicate(ani_env *env, const ani_object predicates)
{
    ani_class cls {};
    static const std::string className = "L@ohos/data/dataSharePredicates/dataSharePredicates/DataSharePredicates;";
    CHECK_COND_RET(env->FindClass(className.c_str(), &cls) == ANI_OK, nullptr, "Can't find class DataSharePredicates");

    ani_method getMethod {};
    CHECK_COND_RET(env->Class_FindMethod(cls, "getNativePtr", nullptr, &getMethod) == ANI_OK, nullptr,
        "Can't find method getNativePtr");

    ani_long nativePtr = 0;
    CHECK_COND_RET(env->Object_CallMethod_Long(predicates, getMethod, &nativePtr) == ANI_OK, nullptr,
        "Call getNativePtr fail");
    CHECK_COND_RET(nativePtr != 0, nullptr, "Invalid nativePtr: 0");
    return reinterpret_cast<DataSharePredicates*>(nativePtr);
}

template <class AniContext>
ani_status MediaLibraryAniUtils::GetPredicate(ani_env *env, const ani_object fetchOptions, const std::string &propName,
    AniContext &context, FetchOptionType fetchOptType)
{
    ani_object property {};
    CHECK_STATUS_RET(GetProperty(env, fetchOptions, propName, property), "GetProperty predicates fail");

    DataSharePredicates* predicate = MediaLibraryAniUtils::UnwrapPredicate(env, property);
    CHECK_COND_RET(predicate != nullptr, ANI_INVALID_ARGS, "UnwrapPredicate fail");
    CHECK_COND_RET(HandleSpecialPredicate(context, predicate, fetchOptType), ANI_INVALID_ARGS, "invalid predicate");
    CHECK_COND_RET(GetLocationPredicate(context, predicate), ANI_INVALID_ARGS, "invalid predicate");
    return ANI_OK;
}

static bool HandleSpecialDateTypePredicate(const OperationItem &item,
    vector<OperationItem> &operations, const FetchOptionType &fetchOptType)
{
    vector<string> dateTypes = { MEDIA_DATA_DB_DATE_ADDED, MEDIA_DATA_DB_DATE_TRASHED, MEDIA_DATA_DB_DATE_MODIFIED,
        MEDIA_DATA_DB_DATE_TAKEN};
    string dateType = item.GetSingle(FIELD_IDX);
    auto it = find(dateTypes.begin(), dateTypes.end(), dateType);
    if (it != dateTypes.end() && item.operation != DataShare::ORDER_BY_ASC &&
        item.operation != DataShare::ORDER_BY_DESC) {
        dateType += "_s";
        operations.push_back({ item.operation, { dateType, static_cast<double>(item.GetSingle(VALUE_IDX)) } });
        return true;
    }
    if (DATE_TRANSITION_MAP.count(dateType) != 0) {
        dateType = DATE_TRANSITION_MAP.at(dateType);
        operations.push_back({ item.operation, { dateType, static_cast<double>(item.GetSingle(VALUE_IDX)) } });
        return true;
    }
    return false;
}

template <class AniContext>
ani_status MediaLibraryAniUtils::ParsePredicates(ani_env *env, const ani_object predicate, AniContext &context,
    FetchOptionType fetchOptType)
{
    DataSharePredicates* nativePredicate = MediaLibraryAniUtils::UnwrapPredicate(env, predicate);
    CHECK_COND_RET(predicate != nullptr, ANI_INVALID_ARGS, "UnwrapPredicate fail");
    CHECK_COND_RET(HandleSpecialPredicate(context, nativePredicate, fetchOptType), ANI_INVALID_ARGS,
        "invalid predicate");
    CHECK_COND_RET(GetLocationPredicate(context, nativePredicate), ANI_INVALID_ARGS, "invalid predicate");
    return ANI_OK;
}

template <class AniContext>
bool MediaLibraryAniUtils::HandleSpecialPredicate(AniContext &context,
    DataSharePredicates *predicate, FetchOptionType fetchOptType)
{
    if (predicate == nullptr) {
        ANI_ERR_LOG("predicate is null");
        return false;
    }
    vector<OperationItem> operations;
    if (!ProcessPredicateItems(context, predicate->GetOperationList(), operations, fetchOptType)) {
        return false;
    }
    context->predicates = DataSharePredicates(move(operations));
    return true;
}

template <class AniContext>
bool MediaLibraryAniUtils::ProcessPredicateItems(AniContext& context, const vector<OperationItem>& items,
    vector<OperationItem>& operations, FetchOptionType fetchOptType)
{
    for (auto& item : items) {
        if (item.singleParams.empty()) {
            operations.push_back(item);
            continue;
        }
        if (HandleSpecialDateTypePredicate(item, operations, fetchOptType)) {
            continue;
        }
        if (!HandleSpecialField(context, item, operations, fetchOptType)) {
            return false;
        }
    }
    return true;
}

template <class AniContext>
bool MediaLibraryAniUtils::HandleSpecialField(AniContext& context, const OperationItem& item,
    vector<OperationItem>& operations, FetchOptionType fetchOptType)
{
    const string& field = static_cast<string>(item.GetSingle(FIELD_IDX));
    const string& value = static_cast<string>(item.GetSingle(VALUE_IDX));
    if (field == DEVICE_DB_NETWORK_ID) {
        return HandleNetworkIdField(context, item, value);
    }
    if (field == MEDIA_DATA_DB_URI) {
        return HandleUriField(context, item, value, operations, fetchOptType);
    }
    if (field == PENDING_STATUS || LOCATION_PARAM_MAP.count(field)) {
        return true;
    }
    operations.push_back(item);
    return true;
}

template <class AniContext>
bool MediaLibraryAniUtils::HandleNetworkIdField(AniContext& context, const OperationItem& item, const string& value)
{
    if (item.operation != DataShare::EQUAL_TO || value.empty()) {
        ANI_ERR_LOG("DEVICE_DB_NETWORK_ID predicates not support %{public}d", item.operation);
        return false;
    }
    context->networkId = value;
    return true;
}

template <class AniContext>
bool MediaLibraryAniUtils::HandleUriField(AniContext& context, const OperationItem& item,
    const string& uriValue, vector<OperationItem>& operations, FetchOptionType fetchOptType)
{
    if (item.operation != DataShare::EQUAL_TO) {
        ANI_ERR_LOG("MEDIA_DATA_DB_URI predicates not support %{public}d", item.operation);
        return false;
    }
    string uri = uriValue;
    MediaFileUri::RemoveAllFragment(uri);
    MediaFileUri fileUri(uri);
    context->uri = uri;
    if ((fetchOptType != ALBUM_FETCH_OPT) && (!fileUri.IsApi10())) {
        fileUri = MediaFileUri(MediaFileUtils::GetRealUriFromVirtualUri(uri));
    }
    context->networkId = fileUri.GetNetworkId();
    string field = (fetchOptType == ALBUM_FETCH_OPT) ? PhotoAlbumColumns::ALBUM_ID : MEDIA_DATA_DB_ID;
    operations.push_back({ item.operation, { field, fileUri.GetFileId() } });
    return true;
}

template <class AniContext>
bool MediaLibraryAniUtils::GetLocationPredicate(AniContext &context, DataSharePredicates *predicate)
{
    map<string, string> locationMap;
    auto &items = predicate->GetOperationList();
    for (auto &item : items) {
        if (item.singleParams.empty()) {
            continue;
        }
        if (LOCATION_PARAM_MAP.find(static_cast<string>(item.GetSingle(FIELD_IDX))) != LOCATION_PARAM_MAP.end()) {
            if (item.operation != DataShare::EQUAL_TO) {
                ANI_ERR_LOG("location predicates not support %{public}d", item.operation);
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

int MediaLibraryAniUtils::TransErrorCode(const string &Name, shared_ptr<DataShare::DataShareResultSet> resultSet)
{
    ANI_ERR_LOG("interface: %{public}s, server return nullptr", Name.c_str());
    // Query can't return errorcode, so assume nullptr as permission deny
    if (resultSet == nullptr) {
        return JS_ERR_PERMISSION_DENIED;
    }
    return ERR_DEFAULT;
}

int MediaLibraryAniUtils::TransErrorCode(const string &Name, int error)
{
    ANI_ERR_LOG("interface: %{public}s, server errcode:%{public}d ", Name.c_str(), error);
    // Transfer Server error to JS error code
    if (error <= E_COMMON_START && error >= E_COMMON_END) {
        error = JS_INNER_FAIL;
    } else if (error == E_PERMISSION_DENIED) {
        error = OHOS_PERMISSION_DENIED_CODE;
    } else if (trans2JsError.count(error)) {
        error = trans2JsError.at(error);
    }
    return error;
}

void MediaLibraryAniUtils::HandleError(ani_env *env, int error, ani_object &errorObj, const std::string &Name)
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
    CreateAniErrorObject(env, errorObj, error, errMsg);
    errMsg = Name + " " + errMsg;
    ANI_ERR_LOG("Error: %{public}s, js errcode:%{public}d ", errMsg.c_str(), originalError);
}

void MediaLibraryAniUtils::CreateAniErrorObject(ani_env *env, ani_object &errorObj, const int32_t errCode,
    const string &errMsg)
{
    static const std::string className = "L@ohos/file/photoAccessHelper/MediaLibraryAniError;";
    ani_class cls {};
    ani_status status = env->FindClass(className.c_str(), &cls);
    if (status != ANI_OK) {
        ANI_ERR_LOG("Can't find class %{public}s", className.c_str());
        return;
    }

    ani_method ctor {};
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "DLstd/core/String;:V", &ctor)) {
        ANI_ERR_LOG("Can't find <ctor> from class %{public}s", className.c_str());
        return;
    }

    ani_string error_msg {};
    if (ANI_OK != MediaLibraryAniUtils::ToAniString(env, errMsg, error_msg)) {
        ANI_ERR_LOG("Call ToAniString function failed.");
        return;
    }

    if (ANI_OK != env->Object_New(cls, ctor, &errorObj, (ani_double)errCode, error_msg)) {
        ANI_ERR_LOG("New MediaLibraryAniError object failed.");
        return;
    }
    return;
}

string MediaLibraryAniUtils::GetStringValueByColumn(shared_ptr<DataShare::DataShareResultSet> resultSet,
    const std::string columnName)
{
    int index;
    DataShare::DataType dataType;
    if (resultSet->GetColumnIndex(columnName, index) || resultSet->GetDataType(index, dataType)) {
        return EMPTY_STRING;
    }
    switch (dataType) {
        case DataShare::DataType::TYPE_INTEGER: {
            int64_t intValue = -1;
            if (resultSet->GetLong(index, intValue) == NativeRdb::E_OK) {
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
            break;
        }
    }
    return EMPTY_STRING;
}

string MediaLibraryAniUtils::ParseResultSet2JsonStr(shared_ptr<DataShare::DataShareResultSet> resultSet,
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

string MediaLibraryAniUtils::ParseAnalysisFace2JsonStr(shared_ptr<DataShare::DataShareResultSet> resultSet,
    const vector<string> &columns)
{
    json jsonArray = json::array();
    if (resultSet == nullptr) {
        return jsonArray.dump();
    }
 
    Uri uri(PAH_QUERY_ANA_PHOTO_ALBUM);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(ALBUM_SUBTYPE, to_string(PhotoAlbumSubType::PORTRAIT))->And()->IsNotNull(TAG_ID);
    vector<string> albumColumns = { ALBUM_ID, TAG_ID };
    int errCode = 0;
    shared_ptr<DataShare::DataShareResultSet> albumSet = UserFileClient::Query(uri, predicates, albumColumns, errCode);
 
    unordered_map<string, string> tagIdToAlbumIdMap;
    if (albumSet != nullptr) {
        while (albumSet->GoToNextRow() == NativeRdb::E_OK) {
            tagIdToAlbumIdMap[GetStringValueByColumn(albumSet, TAG_ID)] = GetStringValueByColumn(albumSet, ALBUM_ID);
        }
    }
 
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        json jsonObject;
        for (uint32_t i = 0; i < columns.size(); i++) {
            string columnName = columns[i];
            string columnValue = GetStringValueByColumn(resultSet, columnName);
            jsonObject[columnName] = columnValue;
            if (columnName == TAG_ID) {
                jsonObject[ALBUM_URI] = PhotoAlbumColumns::ANALYSIS_ALBUM_URI_PREFIX + tagIdToAlbumIdMap[columnValue];
            }
        }
        jsonArray.push_back(jsonObject);
    }
 
    return jsonArray.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

void MediaLibraryAniUtils::UriAppendKeyValue(string &uri, const string &key, const string &value)
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

ani_status MediaLibraryAniUtils::AddDefaultAssetColumns(ani_env *env, vector<string> &fetchColumn,
    function<bool(const string &columnName)> isValidColumn, AniAssetType assetType,
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
            AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
            return ANI_INVALID_ARGS;
        }
    }
    fetchColumn.assign(validFetchColumns.begin(), validFetchColumns.end());
    return ANI_OK;
}

inline void SetDefaultPredicatesCondition(DataSharePredicates &predicates, const int32_t dateTrashed,
    const bool isHidden, const int32_t timePending, const bool isTemp)
{
    predicates.EqualTo(MediaColumn::MEDIA_DATE_TRASHED, to_string(dateTrashed));
    predicates.EqualTo(MediaColumn::MEDIA_HIDDEN, to_string(isHidden));
    predicates.EqualTo(MediaColumn::MEDIA_TIME_PENDING, to_string(timePending));
    predicates.EqualTo(PhotoColumn::PHOTO_IS_TEMP, to_string(isTemp));
    predicates.EqualTo(PhotoColumn::PHOTO_BURST_COVER_LEVEL,
        to_string(static_cast<int32_t>(BurstCoverLevelType::COVER)));
}

static int32_t GetFavoritePredicates(DataSharePredicates &predicates, const bool hiddenOnly)
{
    predicates.BeginWrap();
    constexpr int32_t IS_FAVORITE = 1;
    predicates.EqualTo(MediaColumn::MEDIA_IS_FAV, to_string(IS_FAVORITE));
    SetDefaultPredicatesCondition(predicates, 0, hiddenOnly, 0, false);
    predicates.EndWrap();
    return E_SUCCESS;
}

static int32_t GetVideoPredicates(DataSharePredicates &predicates, const bool hiddenOnly)
{
    predicates.BeginWrap();
    predicates.EqualTo(MediaColumn::MEDIA_TYPE, to_string(MEDIA_TYPE_VIDEO));
    SetDefaultPredicatesCondition(predicates, 0, hiddenOnly, 0, false);
    predicates.EndWrap();
    return E_SUCCESS;
}

static int32_t GetHiddenPredicates(DataSharePredicates &predicates)
{
    predicates.BeginWrap();
    SetDefaultPredicatesCondition(predicates, 0, 1, 0, false);
    predicates.EndWrap();
    return E_SUCCESS;
}

static int32_t GetTrashPredicates(DataSharePredicates &predicates)
{
    predicates.BeginWrap();
    predicates.GreaterThan(MediaColumn::MEDIA_DATE_TRASHED, to_string(0));
    predicates.EqualTo(PhotoColumn::PHOTO_BURST_COVER_LEVEL,
        to_string(static_cast<int32_t>(BurstCoverLevelType::COVER)));
    predicates.EndWrap();
    return E_SUCCESS;
}

static int32_t GetScreenshotPredicates(DataSharePredicates &predicates, const bool hiddenOnly)
{
    predicates.BeginWrap();
    predicates.EqualTo(PhotoColumn::PHOTO_SUBTYPE, to_string(static_cast<int32_t>(PhotoSubType::SCREENSHOT)));
    SetDefaultPredicatesCondition(predicates, 0, hiddenOnly, 0, false);
    predicates.EndWrap();
    return E_SUCCESS;
}

static int32_t GetCameraPredicates(DataSharePredicates &predicates, const bool hiddenOnly)
{
    predicates.BeginWrap();
    predicates.EqualTo(PhotoColumn::PHOTO_SUBTYPE, to_string(static_cast<int32_t>(PhotoSubType::CAMERA)));
    SetDefaultPredicatesCondition(predicates, 0, hiddenOnly, 0, false);
    predicates.EndWrap();
    return E_SUCCESS;
}

static int32_t GetAllImagesPredicates(DataSharePredicates &predicates, const bool hiddenOnly)
{
    predicates.BeginWrap();
    predicates.EqualTo(MediaColumn::MEDIA_TYPE, to_string(MEDIA_TYPE_IMAGE));
    SetDefaultPredicatesCondition(predicates, 0, hiddenOnly, 0, false);
    predicates.EndWrap();
    return E_SUCCESS;
}

static int32_t GetCloudEnhancementPredicates(DataSharePredicates &predicates, const bool hiddenOnly)
{
    predicates.BeginWrap();
    predicates.EqualTo(MediaColumn::MEDIA_TYPE, to_string(MEDIA_TYPE_IMAGE));
    predicates.EqualTo(PhotoColumn::PHOTO_STRONG_ASSOCIATION,
        to_string(static_cast<int32_t>(StrongAssociationType::CLOUD_ENHANCEMENT)));
    SetDefaultPredicatesCondition(predicates, 0, hiddenOnly, 0, false);
    predicates.EndWrap();
    return E_SUCCESS;
}

int32_t MediaLibraryAniUtils::GetSystemAlbumPredicates(const PhotoAlbumSubType subType,
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
        case PhotoAlbumSubType::CLOUD_ENHANCEMENT: {
            return GetCloudEnhancementPredicates(predicates, hiddenOnly);
        }
        default: {
            ANI_ERR_LOG("Unsupported photo album subtype: %{public}d", subType);
            return E_INVALID_ARGUMENTS;
        }
    }
}

int32_t MediaLibraryAniUtils::GetUserAlbumPredicates(
    const int32_t albumId, DataSharePredicates &predicates, const bool hiddenOnly)
{
    predicates.EqualTo(PhotoColumn::PHOTO_OWNER_ALBUM_ID, to_string(albumId));
    SetDefaultPredicatesCondition(predicates, 0, hiddenOnly, 0, false);
    return E_SUCCESS;
}

int32_t MediaLibraryAniUtils::GetAnalysisAlbumPredicates(const int32_t albumId, DataSharePredicates &predicates)
{
    string onClause = MediaColumn::MEDIA_ID + " = " + PhotoMap::ASSET_ID;
    predicates.InnerJoin(ANALYSIS_PHOTO_MAP_TABLE)->On({ onClause });
    predicates.EqualTo(PhotoMap::ALBUM_ID, to_string(albumId));
    SetDefaultPredicatesCondition(predicates, 0, 0, 0, false);
    return E_SUCCESS;
}

int32_t MediaLibraryAniUtils::GetFeaturedSinglePortraitAlbumPredicates(
    const int32_t albumId, DataSharePredicates &predicates)
{
    string onClause = PhotoColumn::PHOTOS_TABLE + "." + MediaColumn::MEDIA_ID + " = " +
        ANALYSIS_PHOTO_MAP_TABLE + "." + PhotoMap::ASSET_ID;
    predicates.InnerJoin(ANALYSIS_PHOTO_MAP_TABLE)->On({ onClause });

    constexpr int32_t minSize = 224;
    string imgHeightColumn = PhotoColumn::PHOTOS_TABLE + "." + PhotoColumn::PHOTO_HEIGHT;
    string imgWidthColumn = PhotoColumn::PHOTOS_TABLE + "." + PhotoColumn::PHOTO_WIDTH;
    string imgFaceHeightColumn = VISION_IMAGE_FACE_TABLE + "." + SCALE_HEIGHT;
    string imgFaceWidthColumn = VISION_IMAGE_FACE_TABLE + "." + SCALE_WIDTH;
    string imgFaceHeightClause = "( " + imgFaceHeightColumn + " > " + to_string(minSize) +
        " OR ( " + imgFaceHeightColumn + " <= 1.0 " + " AND " + imgFaceHeightColumn + " * " + imgHeightColumn +
        " > " + to_string(minSize) + " ) )";
    string imgFaceWidthClause = "( " + imgFaceWidthColumn + " > " + to_string(minSize) +
        " OR ( " + imgFaceWidthColumn + " <= 1.0 " + " AND " + imgFaceWidthColumn + " * " + imgWidthColumn +
        " > " + to_string(minSize) + " ) )";
    string imgFaceOcclusionClause = "( " + VISION_IMAGE_FACE_TABLE + "." + FACE_OCCLUSION + " = 0 OR " +
        VISION_IMAGE_FACE_TABLE + "." + FACE_OCCLUSION + " IS NULL )";
    string portraitRotationLimit = "BETWEEN -30 AND 30";
    onClause = PhotoColumn::PHOTOS_TABLE + "." + MediaColumn::MEDIA_ID + " = " + VISION_IMAGE_FACE_TABLE + "." +
        MediaColumn::MEDIA_ID + " AND " + VISION_IMAGE_FACE_TABLE + "." + TOTAL_FACES + " = 1 AND " +
        imgFaceHeightClause + " AND " + imgFaceWidthClause + " AND " + imgFaceOcclusionClause + " AND " +
        VISION_IMAGE_FACE_TABLE + "." + PITCH + " " + portraitRotationLimit + " AND " +
        VISION_IMAGE_FACE_TABLE + "." + YAW + " " + portraitRotationLimit + " AND " +
        VISION_IMAGE_FACE_TABLE + "." + ROLL + " " + portraitRotationLimit;
    predicates.InnerJoin(VISION_IMAGE_FACE_TABLE)->On({ onClause });

    string portraitType = "IN ( 1, 2 )";
    onClause = PhotoColumn::PHOTOS_TABLE + "." + MediaColumn::MEDIA_ID + " = " + VISION_POSE_TABLE + "." +
        MediaColumn::MEDIA_ID + " AND " + VISION_POSE_TABLE + "." + POSE_TYPE + " " + portraitType;
    predicates.InnerJoin(VISION_POSE_TABLE)->On({ onClause });

    predicates.EqualTo(PhotoMap::ALBUM_ID, to_string(albumId));
    SetDefaultPredicatesCondition(predicates, 0, 0, 0, false);
    return E_SUCCESS;
}

int32_t MediaLibraryAniUtils::GetPortraitAlbumPredicates(const int32_t albumId, DataSharePredicates &predicates)
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
    SetDefaultPredicatesCondition(predicates, 0, 0, 0, false);
    predicates.Distinct();
    return E_SUCCESS;
}

int32_t MediaLibraryAniUtils::GetAllLocationPredicates(DataSharePredicates &predicates)
{
    SetDefaultPredicatesCondition(predicates, 0, 0, 0, false);
    predicates.And()->NotEqualTo(PhotoColumn::PHOTO_LATITUDE, to_string(0));
    predicates.And()->NotEqualTo(PhotoColumn::PHOTO_LONGITUDE, to_string(0));
    return E_SUCCESS;
}

int32_t MediaLibraryAniUtils::GetSourceAlbumPredicates(const int32_t albumId, DataSharePredicates &predicates,
    const bool hiddenOnly)
{
    predicates.EqualTo(PhotoColumn::PHOTO_OWNER_ALBUM_ID, to_string(albumId));
    predicates.EqualTo(PhotoColumn::PHOTO_SYNC_STATUS, to_string(static_cast<int32_t>(SyncStatusType::TYPE_VISIBLE)));
    SetDefaultPredicatesCondition(predicates, 0, hiddenOnly, 0, false);
    return E_SUCCESS;
}

bool MediaLibraryAniUtils::IsFeaturedSinglePortraitAlbum(
    std::string albumName, DataShare::DataSharePredicates &predicates)
{
    bool isFeaturedSinglePortrait = false;
    int portraitAlbumId = 0;
    if (albumName.compare(to_string(portraitAlbumId)) != 0) {
        return isFeaturedSinglePortrait;
    }

    DataSharePredicates featuredSinglePortraitPredicates;
    std::vector<OperationItem> operationList = predicates.GetOperationList();
    for (auto& operationItem : operationList) {
        switch (operationItem.operation) {
            case OHOS::DataShare::OperationType::LIKE : {
                std::string field = std::get<string>(operationItem.singleParams[0]);
                std::string value = std::get<string>(operationItem.singleParams[1]);
                if (field.compare("FeaturedSinglePortrait") == 0 && value.compare("true") == 0) {
                    isFeaturedSinglePortrait = true;
                } else {
                    featuredSinglePortraitPredicates.Like(field, value);
                }
                break;
            }
            case OHOS::DataShare::OperationType::ORDER_BY_DESC : {
                featuredSinglePortraitPredicates.OrderByDesc(operationItem.GetSingle(0));
                break;
            }
            case OHOS::DataShare::OperationType::LIMIT : {
                featuredSinglePortraitPredicates.Limit(operationItem.GetSingle(0), operationItem.GetSingle(1));
                break;
            }
            default: {
                break;
            }
        }
    }

    if (isFeaturedSinglePortrait) {
        predicates = featuredSinglePortraitPredicates;
    }
    return isFeaturedSinglePortrait;
}

ani_status MediaLibraryAniUtils::FindClass(ani_env *env, const std::string &className, ani_class *cls)
{
    CHECK_STATUS_RET(env->FindClass(className.c_str(), cls), "Can't find class");
    return ANI_OK;
}

ani_status MediaLibraryAniUtils::FindClassMethod(ani_env *env, const std::string &className,
    const std::string &methodName, ani_method *method)
{
    ani_class cls {};
    CHECK_STATUS_RET(MediaLibraryAniUtils::FindClass(env, className, &cls), "Can't find class");
    CHECK_STATUS_RET(env->Class_FindMethod(cls, methodName.c_str(), nullptr, method), "Can't find method");

    return ANI_OK;
}

template ani_status MediaLibraryAniUtils::GetFetchOption<unique_ptr<MediaLibraryAsyncContext>>(ani_env *env,
    ani_object fetchOptions, FetchOptionType fetchOptType, unique_ptr<MediaLibraryAsyncContext> &context);

template ani_status MediaLibraryAniUtils::GetFetchOption<unique_ptr<PhotoAlbumAniContext>>(ani_env *env,
    ani_object fetchOptions, FetchOptionType fetchOptType, unique_ptr<PhotoAlbumAniContext> &context);

template ani_status MediaLibraryAniUtils::GetPredicate<unique_ptr<PhotoAlbumAniContext>>(ani_env *env,
    const ani_object fetchOptions, const std::string &propName, unique_ptr<PhotoAlbumAniContext> &context,
    FetchOptionType fetchOptType);

template ani_status MediaLibraryAniUtils::ParsePredicates<unique_ptr<MediaLibraryAsyncContext>>(ani_env *env,
    const ani_object predicate, unique_ptr<MediaLibraryAsyncContext> &context, FetchOptionType fetchOptType);

template bool MediaLibraryAniUtils::HandleSpecialPredicate<unique_ptr<PhotoAlbumAniContext>>(
    unique_ptr<PhotoAlbumAniContext> &context, DataSharePredicates *predicate, FetchOptionType fetchOptType);

template bool MediaLibraryAniUtils::ProcessPredicateItems<unique_ptr<PhotoAlbumAniContext>>(
    unique_ptr<PhotoAlbumAniContext> &context, const vector<OperationItem>& items, vector<OperationItem>& operations,
    FetchOptionType fetchOptType);

template bool MediaLibraryAniUtils::HandleSpecialField<unique_ptr<PhotoAlbumAniContext>>(
    unique_ptr<PhotoAlbumAniContext> &context, const OperationItem& item, vector<OperationItem>& operations,
    FetchOptionType fetchOptType);

template bool MediaLibraryAniUtils::HandleNetworkIdField<unique_ptr<PhotoAlbumAniContext>>(
    unique_ptr<PhotoAlbumAniContext> &context, const OperationItem& item, const string& value);

template bool MediaLibraryAniUtils::HandleUriField<unique_ptr<PhotoAlbumAniContext>>(
    unique_ptr<PhotoAlbumAniContext> &context, const OperationItem& item, const string& uriValue,
    vector<OperationItem>& operations, FetchOptionType fetchOptType);

template bool MediaLibraryAniUtils::GetLocationPredicate<unique_ptr<PhotoAlbumAniContext>>(
    unique_ptr<PhotoAlbumAniContext> &context, DataSharePredicates *predicate);
} // namespace Media
} // namespace OHOS