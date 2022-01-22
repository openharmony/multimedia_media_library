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

#include "media_library_napi.h"
#include "hilog/log.h"
#include "smart_album_napi.h"
#include "file_ex.h"
#include "permission/permission_kit.h"

using OHOS::HiviewDFX::HiLog;
using OHOS::HiviewDFX::HiLogLabel;
using namespace std;
using namespace OHOS::AppExecFwk;
using namespace OHOS::NativeRdb;

namespace {
    constexpr HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN, "MediaLibraryNapi"};
}

namespace OHOS {
namespace Media {
const std::string MediaLibraryNapi::PERMISSION_NAME_READ_MEDIA = "ohos.permission.READ_MEDIA";
const std::string MediaLibraryNapi::PERMISSION_NAME_WRITE_MEDIA = "ohos.permission.WRITE_MEDIA";
unique_ptr<ChangeListenerNapi> g_listObj = nullptr;
bool g_isNewApi = false;

napi_ref MediaLibraryNapi::sConstructor_ = nullptr;
std::shared_ptr<AppExecFwk::DataAbilityHelper> MediaLibraryNapi::sAbilityHelper_ = nullptr;
napi_ref MediaLibraryNapi::sMediaTypeEnumRef_ = nullptr;
napi_ref MediaLibraryNapi::sFileKeyEnumRef_ = nullptr;
using CompleteCallback = napi_async_complete_callback;
using Context = MediaLibraryAsyncContext* ;

MediaLibraryNapi::MediaLibraryNapi()
    : mediaLibrary_(nullptr), env_(nullptr), wrapper_(nullptr) {}

MediaLibraryNapi::~MediaLibraryNapi()
{
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }

    if (sAbilityHelper_ != nullptr) {
        sAbilityHelper_->Release();
        sAbilityHelper_ = nullptr;
    }
}

void MediaLibraryNapi::MediaLibraryNapiDestructor(napi_env env, void *nativeObject, void *finalize_hint)
{
    MediaLibraryNapi *mediaLibrary = reinterpret_cast<MediaLibraryNapi*>(nativeObject);
    if (mediaLibrary != nullptr) {
        mediaLibrary->~MediaLibraryNapi();
    }
}

napi_value MediaLibraryNapi::Init(napi_env env, napi_value exports)
{
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;
    napi_property_descriptor media_library_properties[] = {
        DECLARE_NAPI_FUNCTION("getMediaAssets", GetMediaAssets),
        DECLARE_NAPI_FUNCTION("getAudioAssets", GetAudioAssets),
        DECLARE_NAPI_FUNCTION("getVideoAssets", GetVideoAssets),
        DECLARE_NAPI_FUNCTION("getImageAssets", GetImageAssets),
        DECLARE_NAPI_FUNCTION("getVideoAlbums", GetVideoAlbums),
        DECLARE_NAPI_FUNCTION("getImageAlbums", GetImageAlbums),
        DECLARE_NAPI_FUNCTION("createVideoAsset", CreateVideoAsset),
        DECLARE_NAPI_FUNCTION("createImageAsset", CreateImageAsset),
        DECLARE_NAPI_FUNCTION("createAudioAsset", CreateAudioAsset),
        DECLARE_NAPI_FUNCTION("createAlbum", CreateAlbum),
        DECLARE_NAPI_FUNCTION("getPublicDirectory", JSGetPublicDirectory),
        DECLARE_NAPI_FUNCTION("getFileAssets", JSGetFileAssets),
        DECLARE_NAPI_FUNCTION("getAlbums", JSGetAlbums),
        DECLARE_NAPI_FUNCTION("createAsset", JSCreateAsset),
        DECLARE_NAPI_FUNCTION("deleteAsset", JSDeleteAsset),
        DECLARE_NAPI_FUNCTION("on", JSOnCallback),
        DECLARE_NAPI_FUNCTION("off", JSOffCallback),
        DECLARE_NAPI_FUNCTION("release", JSRelease),
        DECLARE_NAPI_FUNCTION("getPrivateAlbum", JSGetPrivateAlbum),
        DECLARE_NAPI_FUNCTION("createSmartAlbum", JSCreateSmartAlbum),
        DECLARE_NAPI_FUNCTION("deleteSmartAlbum", JSDeleteSmartAlbum)
    };
    napi_property_descriptor static_prop[] = {
        DECLARE_NAPI_STATIC_FUNCTION("getMediaLibrary", GetMediaLibraryNewInstance),
        DECLARE_NAPI_STATIC_FUNCTION("getMediaLibraryHelper", GetMediaLibraryOldInstance),
        DECLARE_NAPI_PROPERTY("MediaType", CreateMediaTypeEnum(env)),
        DECLARE_NAPI_PROPERTY("FileKey", CreateFileKeyEnum(env)),
        DECLARE_NAPI_PROPERTY("DirectoryType", CreateDirectoryTypeEnum(env)),
        DECLARE_NAPI_PROPERTY("PrivateAlbumType", CreatePrivateAlbumTypeEnum(env))
    };
    status = napi_define_class(env, MEDIA_LIB_NAPI_CLASS_NAME.c_str(), NAPI_AUTO_LENGTH, MediaLibraryNapiConstructor,
                               nullptr, sizeof(media_library_properties) / sizeof(media_library_properties[PARAM0]),
                               media_library_properties, &ctorObj);
    if (status == napi_ok) {
        if (napi_create_reference(env, ctorObj, refCount, &sConstructor_) == napi_ok) {
            status = napi_set_named_property(env, exports, MEDIA_LIB_NAPI_CLASS_NAME.c_str(), ctorObj);
            if (status == napi_ok && napi_define_properties(env, exports,
                sizeof(static_prop) / sizeof(static_prop[PARAM0]), static_prop) == napi_ok) {
                return exports;
            }
        }
    }
    return nullptr;
}

std::string GetPackageName(napi_env env, int& userId)
{
    napi_value global = nullptr;
    NAPI_CALL(env, napi_get_global(env, &global));

    napi_value abilityObj = nullptr;
    NAPI_CALL(env, napi_get_named_property(env, global, "ability", &abilityObj));

    AppExecFwk::Ability *ability = nullptr;
    NAPI_CALL(env, napi_get_value_external(env, abilityObj, (void **)&ability));

    if (ability != nullptr) {
        userId = (ability->GetAbilityInfo())->applicationInfo.uid;
        return ability->GetBundleName();
    }
    return "";
}

bool CheckUserGrantedPermission(napi_env env, const std::string& permissionName)
{
    if (!FileExists("/data/local/tmp/media_permission")) {
        return true;
    }
    int userId = -1;
    std::string bundleName = GetPackageName(env, userId);
    HiLog::Debug(LABEL, "CheckUserGrantedPermission --- bundleName is %{public}s, userId is %{public}d ",
        bundleName.c_str(), userId);
    return (Security::Permission::PermissionKit::VerifyPermission(bundleName,
        permissionName, userId) == Security::Permission::PermissionState::PERMISSION_GRANTED);
}

shared_ptr<AppExecFwk::DataAbilityHelper> MediaLibraryNapi::GetDataAbilityHelper(napi_env env)
{
    napi_value global = nullptr;
    NAPI_CALL(env, napi_get_global(env, &global));

    napi_value abilityObj = nullptr;
    NAPI_CALL(env, napi_get_named_property(env, global, "ability", &abilityObj));

    AppExecFwk::Ability *ability = nullptr;
    NAPI_CALL(env, napi_get_value_external(env, abilityObj, (void **)&ability));

    string strUri = MEDIALIBRARY_DATA_URI;

    return AppExecFwk::DataAbilityHelper::Creator(ability->GetContext(), make_shared<Uri>(strUri));
}

// Constructor callback
napi_value MediaLibraryNapi::MediaLibraryNapiConstructor(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        HiLog::Error(LABEL, "Error while obtaining js environment information");
        return result;
    }

    unique_ptr<MediaLibraryNapi> obj = make_unique<MediaLibraryNapi>();
    if (obj != nullptr) {
        obj->env_ = env;
        obj->mediaLibrary_ = IMediaLibraryClient::GetMediaLibraryClientInstance();
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, obj->mediaLibrary_, result, "MediaLibrary instance creation failed");

        if (g_isNewApi) {
            // Initialize the ChangeListener object
            if (g_listObj == nullptr) {
                g_listObj = make_unique<ChangeListenerNapi>(env);
            }

            if (obj->sAbilityHelper_ == nullptr) {
                obj->sAbilityHelper_ = GetDataAbilityHelper(env);
                CHECK_NULL_PTR_RETURN_UNDEFINED(env, obj->sAbilityHelper_, result, "Helper creation failed");
            }
        }

        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                           MediaLibraryNapi::MediaLibraryNapiDestructor, nullptr, &(obj->wrapper_));
        if (status == napi_ok) {
            obj.release();
            return thisVar;
        } else {
            HiLog::Error(LABEL, "Failed to wrap the native media lib client object with JS");
        }
    }

    return result;
}

napi_value MediaLibraryNapi::GetMediaLibraryNewInstance(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value ctor;
    HiLog::Debug(LABEL, "GetMediaLibraryNewInstance IN");
    status = napi_get_reference_value(env, sConstructor_, &ctor);
    if (status == napi_ok) {
        g_isNewApi = true;
        status = napi_new_instance(env, ctor, 0, nullptr, &result);
        if (status == napi_ok) {
            return result;
        } else {
            HiLog::Error(LABEL, "New instance could not be obtained");
        }
    } else {
            HiLog::Error(LABEL, "status != napi_ok");
    }

    napi_get_undefined(env, &result);
    HiLog::Debug(LABEL, "GetMediaLibraryNewInstance OUT");
    return result;
}

napi_value MediaLibraryNapi::GetMediaLibraryOldInstance(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value ctor;

    status = napi_get_reference_value(env, sConstructor_, &ctor);
    if (status == napi_ok) {
        g_isNewApi = false;
        status = napi_new_instance(env, ctor, 0, nullptr, &result);
        if (status == napi_ok) {
            return result;
        } else {
            HiLog::Error(LABEL, "New instance could not be obtained");
        }
    }

    napi_get_undefined(env, &result);
    return result;
}

static napi_status AddIntegerNamedProperty(napi_env env, napi_value object,
    const string &name, int32_t enumValue)
{
    napi_status status;
    napi_value enumNapiValue;

    status = napi_create_int32(env, enumValue, &enumNapiValue);
    if (status == napi_ok) {
        status = napi_set_named_property(env, object, name.c_str(), enumNapiValue);
    }

    return status;
}

napi_value MediaLibraryNapi::CreateMediaTypeEnum(napi_env env)
{
    napi_value result = nullptr;
    napi_status status;
    string propName;
    int refCount = 1;

    status = napi_create_object(env, &result);
    if (status == napi_ok) {
        for (unsigned int i = MEDIA_TYPE_DEFAULT; i < mediaTypesEnum.size(); i++) {
            propName = mediaTypesEnum[i];
            status = AddIntegerNamedProperty(env, result, propName, i);
            if (status != napi_ok) {
                HiLog::Error(LABEL, "Failed to add named prop!");
                break;
            }
            propName.clear();
        }
    }
    if (status == napi_ok) {
        // The reference count is for creating Media Type Enum Reference
        status = napi_create_reference(env, result, refCount, &sMediaTypeEnumRef_);
        if (status == napi_ok) {
            return result;
        }
    }
    HiLog::Error(LABEL, "Failed to created object for media type enum!");

    napi_get_undefined(env, &result);
    return result;
}

napi_value MediaLibraryNapi::CreateDirectoryTypeEnum(napi_env env)
{
    napi_value result = nullptr;
    napi_status status;
    string propName;
    int refCount = 1;

    status = napi_create_object(env, &result);
    if (status == napi_ok) {
        for (unsigned int i = 0; i < directoryEnum.size(); i++) {
            propName = directoryEnum[i];
            status = AddIntegerNamedProperty(env, result, propName, i);
            if (status != napi_ok) {
                HiLog::Error(LABEL, "Failed to add named prop!");
                break;
            }
            propName.clear();
        }
    }
    if (status == napi_ok) {
        // The reference count is for creating Media Type Enum Reference
        status = napi_create_reference(env, result, refCount, &sMediaTypeEnumRef_);
        if (status == napi_ok) {
            return result;
        }
    }
    HiLog::Error(LABEL, "Failed to created object for directory enum!");

    napi_get_undefined(env, &result);
    return result;
}

static napi_status AddStringNamedProperty(napi_env env, napi_value object,
    const string &name, string enumValue)
{
    napi_status status;
    napi_value enumNapiValue;

    status = napi_create_string_utf8(env, enumValue.c_str(), NAPI_AUTO_LENGTH, &enumNapiValue);
    if (status == napi_ok) {
        status = napi_set_named_property(env, object, name.c_str(), enumNapiValue);
    }

    return status;
}

napi_value MediaLibraryNapi::CreateFileKeyEnum(napi_env env)
{
    napi_value result = nullptr;
    napi_status status;
    string propName;
    int refCount = 1;

    status = napi_create_object(env, &result);
    if (status == napi_ok) {
        for (unsigned int i = 0; i < fileKeyEnum.size(); i++) {
            propName = fileKeyEnum[i];
            status = AddStringNamedProperty(env, result, propName, fileKeyEnumValues[i]);
            if (status != napi_ok) {
                HiLog::Error(LABEL, "Failed to add named prop!");
                break;
            }
            propName.clear();
        }
    }

    if (status == napi_ok) {
        // The reference count is for creating File Key Enum Reference
        status = napi_create_reference(env, result, refCount, &sFileKeyEnumRef_);
        if (status == napi_ok) {
            return result;
        }
    }
    HiLog::Error(LABEL, "Failed to created object for file key enum!");

    napi_get_undefined(env, &result);
    return result;
}

napi_value MediaLibraryNapi::CreatePrivateAlbumTypeEnum(napi_env env)
{
    napi_value result = nullptr;
    napi_status status;
    string propName;
    int refCount = 1;

    status = napi_create_object(env, &result);
    if (status == napi_ok) {
        for (unsigned int i = 0; i < privateAlbumTypeNameEnum.size(); i++) {
            propName = privateAlbumTypeNameEnum[i];
            status = AddIntegerNamedProperty(env, result, propName, i);
            if (status != napi_ok) {
                HiLog::Error(LABEL, "Failed to add named prop!");
                break;
            }
            propName.clear();
        }
    }

    if (status == napi_ok) {
        // The reference count is for creating File Key Enum Reference
        status = napi_create_reference(env, result, refCount, &sFileKeyEnumRef_);
        if (status == napi_ok) {
            return result;
        }
    }
    HiLog::Error(LABEL, "Failed to created object for file key enum!");

    napi_get_undefined(env, &result);
    return result;
}

IMediaLibraryClient* MediaLibraryNapi::GetMediaLibClientInstance()
{
    IMediaLibraryClient *ins = this->mediaLibrary_;
    return ins;
}

static void GetFetchOptionsParam(napi_env env, napi_value arg, const MediaLibraryAsyncContext &context, bool &err)
{
    MediaLibraryAsyncContext *asyncContext = const_cast<MediaLibraryAsyncContext *>(&context);
    char buffer[PATH_MAX];
    size_t res = 0;
    uint32_t len = 0;
    napi_value property = nullptr;
    napi_value stringItem = nullptr;
    bool present = false;

    napi_has_named_property(env, arg, "selections", &present);
    if (present) {
        if (napi_get_named_property(env, arg, "selections", &property) != napi_ok
            || napi_get_value_string_utf8(env, property, buffer, PATH_MAX, &res) != napi_ok) {
            HiLog::Error(LABEL, "Could not get the string argument!");
            err = true;
            return;
        } else {
            asyncContext->selection = buffer;
            CHECK_IF_EQUAL(memset_s(buffer, PATH_MAX, 0, sizeof(buffer)) == 0, "Memset for buffer failed");
        }
        present = false;
    }

    napi_has_named_property(env, arg, "order", &present);
    if (present) {
        if (napi_get_named_property(env, arg, "order", &property) != napi_ok
            || napi_get_value_string_utf8(env, property, buffer, PATH_MAX, &res) != napi_ok) {
            HiLog::Error(LABEL, "Could not get the string argument!");
            err = true;
            return;
        } else {
            asyncContext->order = buffer;
            CHECK_IF_EQUAL(memset_s(buffer, PATH_MAX, 0, sizeof(buffer)) == 0, "Memset for buffer failed");
        }
        present = false;
    }

    napi_has_named_property(env, arg, "selectionArgs", &present);
    if (present && napi_get_named_property(env, arg, "selectionArgs", &property) == napi_ok) {
        napi_get_array_length(env, property, &len);
        for (size_t i = 0; i < len; i++) {
            napi_get_element(env, property, i, &stringItem);
            napi_get_value_string_utf8(env, stringItem, buffer, PATH_MAX, &res);
            asyncContext->selectionArgs.push_back(string(buffer));
            CHECK_IF_EQUAL(memset_s(buffer, PATH_MAX, 0, sizeof(buffer)) == 0, "Memset for buffer failed");
        }
    } else {
        HiLog::Error(LABEL, "Could not get the string argument!");
        err = true;
    }
}

static napi_value ConvertJSArgsToNative(napi_env env, size_t argc, const napi_value argv[],
    MediaLibraryAsyncContext &asyncContext)
{
    string str = "";
    vector<string> strArr;
    string order = "";
    bool err = false;
    const int32_t refCount = 1;
    napi_value result;
    auto context = &asyncContext;

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (i == PARAM0 && valueType == napi_object) {
            GetFetchOptionsParam(env, argv[PARAM0], asyncContext, err);
        } else if (i == PARAM0 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else if (i == PARAM1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
        if (err) {
            HiLog::Error(LABEL, "fetch options retrieval failed");
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }

    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}

static void MediaAssetsAsyncCallbackComplete(napi_env env, napi_status status,
                                             MediaLibraryAsyncContext *context)
{
    napi_value mediaArray = nullptr;
    napi_value mAsset = nullptr;

    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = true;
    napi_get_undefined(env, &jsContext->error);
    if (!context->mediaAssets.empty()) {
        size_t len = context->mediaAssets.size();
        if (napi_create_array(env, &mediaArray) == napi_ok) {
            size_t i = 0;
            for (; i < len; i++) {
                mAsset = MediaAssetNapi::CreateMediaAsset(env, *(context->mediaAssets[i]),
                    *(context->objectInfo->GetMediaLibClientInstance()));
                if (mAsset == nullptr || napi_set_element(env, mediaArray, i, mAsset) != napi_ok) {
                    HiLog::Error(LABEL, "Failed to get media asset napi object");
                    napi_get_undefined(env, &jsContext->data);
                    break;
                }
            }
            if (i == len) {
                jsContext->data = mediaArray;
            }
        } else {
            napi_get_undefined(env, &jsContext->data);
        }
    } else {
        HiLog::Error(LABEL, "No media assets found!");
        napi_get_undefined(env, &jsContext->data);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value MediaLibraryNapi::GetMediaAssets(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value resource = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_TWO, "requires 2 parameters maximum");

    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (!(status == napi_ok && asyncContext->objectInfo != nullptr)) {
        return result;
    }
        result = ConvertJSArgsToNative(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "GetMediaAssets");

        status = napi_create_async_work(
            env, nullptr, resource,
            [](napi_env env, void* data) {
                MediaLibraryAsyncContext* context = static_cast<MediaLibraryAsyncContext*>(data);
                context->mediaAssets = context->objectInfo->mediaLibrary_->GetMediaAssets(context->selection,
                                                                                          context->selectionArgs);
                context->status = 0;
            },
        reinterpret_cast<CompleteCallback>(MediaAssetsAsyncCallbackComplete),
        static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
    }
    return result;
}

static void AudioAssetsAsyncCallbackComplete(napi_env env, napi_status status,
                                             MediaLibraryAsyncContext *context)
{
    napi_value audioArray = nullptr;
    napi_value aAsset = nullptr;

    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = true;
    napi_get_undefined(env, &jsContext->error);
    if (!context->audioAssets.empty()) {
        size_t len = context->audioAssets.size();
        if (napi_create_array(env, &audioArray) == napi_ok) {
            size_t i = 0;
            for (; i < len; i++) {
                aAsset = AudioAssetNapi::CreateAudioAsset(env, *(context->audioAssets[i]),
                                                          *(context->objectInfo->GetMediaLibClientInstance()));
                if (aAsset == nullptr || napi_set_element(env, audioArray, i, aAsset) != napi_ok) {
                    HiLog::Error(LABEL, "Failed to get audio asset napi object");
                    napi_get_undefined(env, &jsContext->data);
                    break;
                }
            }
            if (i == len) {
                jsContext->data = audioArray;
            }
        } else {
            napi_get_undefined(env, &jsContext->data);
        }
    } else {
        HiLog::Error(LABEL, "No audio assets found!");
        napi_get_undefined(env, &jsContext->data);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value MediaLibraryNapi::GetAudioAssets(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value resource = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_TWO, "requires 2 parameters maximum");

    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (!(status == napi_ok && asyncContext->objectInfo != nullptr)) {
        return result;
    }
        result = ConvertJSArgsToNative(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "GetAudioAssets");

        status = napi_create_async_work(
            env, nullptr, resource,
            [](napi_env env, void* data) {
                MediaLibraryAsyncContext* context = static_cast<MediaLibraryAsyncContext*>(data);
                context->audioAssets = context->objectInfo->mediaLibrary_->GetAudioAssets(context->selection,
                                                                                          context->selectionArgs);
                context->status = 0;
            },
        reinterpret_cast<CompleteCallback>(AudioAssetsAsyncCallbackComplete),
        static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
    }
    return result;
}

static void VideoAssetsAsyncCallbackComplete(napi_env env, napi_status status,
                                             MediaLibraryAsyncContext *context)
{
    napi_value videoArray = nullptr;
    napi_value vAsset = nullptr;

    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = true;
    napi_get_undefined(env, &jsContext->error);
    if (!context->videoAssets.empty()) {
        size_t len = context->videoAssets.size();
        if (napi_create_array(env, &videoArray) == napi_ok) {
            size_t i = 0;
            for (; i < len; i++) {
                vAsset = VideoAssetNapi::CreateVideoAsset(env, *(context->videoAssets[i]),
                                                          *(context->objectInfo->GetMediaLibClientInstance()));
                if (vAsset == nullptr || napi_set_element(env, videoArray, i, vAsset) != napi_ok) {
                    HiLog::Error(LABEL, "Failed to get video asset napi object");
                    napi_get_undefined(env, &jsContext->data);
                    break;
                }
            }
            if (i == len) {
                jsContext->data = videoArray;
            }
        } else {
            napi_get_undefined(env, &jsContext->data);
        }
    } else {
        HiLog::Error(LABEL, "No video assets found!");
        napi_get_undefined(env, &jsContext->data);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value MediaLibraryNapi::GetVideoAssets(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value resource = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_TWO, "requires 2 parameters maximum");

    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (!(status == napi_ok && asyncContext->objectInfo != nullptr)) {
        return result;
    }
        result = ConvertJSArgsToNative(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "GetVideoAssets");

        status = napi_create_async_work(
            env, nullptr, resource,
            [](napi_env env, void* data) {
                MediaLibraryAsyncContext* context = static_cast<MediaLibraryAsyncContext*>(data);
                context->videoAssets = context->objectInfo->mediaLibrary_->GetVideoAssets(context->selection,
                                                                                          context->selectionArgs);
                context->status = 0;
            },
        reinterpret_cast<CompleteCallback>(VideoAssetsAsyncCallbackComplete),
        static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
    }
    return result;
}

static void ImageAssetsAsyncCallbackComplete(napi_env env, napi_status status,
                                             MediaLibraryAsyncContext *context)
{
    napi_value imageArray = nullptr;
    napi_value iAsset = nullptr;

    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = true;
    napi_get_undefined(env, &jsContext->error);
    if (!context->imageAssets.empty()) {
        size_t len = context->imageAssets.size();
        if (napi_create_array(env, &imageArray) == napi_ok) {
            size_t i = 0;
            for (; i < len; i++) {
                iAsset = ImageAssetNapi::CreateImageAsset(env, *(context->imageAssets[i]),
                                                          *(context->objectInfo->GetMediaLibClientInstance()));
                if (iAsset == nullptr || napi_set_element(env, imageArray, i, iAsset) != napi_ok) {
                    HiLog::Error(LABEL, "Failed to get image asset napi object");
                    napi_get_undefined(env, &jsContext->data);
                    break;
                }
            }
            if (i == len) {
                jsContext->data = imageArray;
            }
        } else {
            napi_get_undefined(env, &jsContext->data);
        }
    } else {
        HiLog::Error(LABEL, "No image assets found!");
        napi_get_undefined(env, &jsContext->data);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value MediaLibraryNapi::GetImageAssets(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value resource = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_TWO, "requires 2 parameters maximum");

    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = ConvertJSArgsToNative(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "GetImageAssets");

        status = napi_create_async_work(
            env, nullptr, resource,
            [](napi_env env, void* data) {
                MediaLibraryAsyncContext* context = static_cast<MediaLibraryAsyncContext*>(data);
                context->imageAssets = context->objectInfo->mediaLibrary_->GetImageAssets(context->selection,
                                                                                          context->selectionArgs);
                context->status = 0;
            },
            reinterpret_cast<CompleteCallback>(ImageAssetsAsyncCallbackComplete),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}

static void AlbumAssetsAsyncCallbackComplete(napi_env env, napi_status status,
                                             MediaLibraryAsyncContext *context)
{
    napi_value albumArray = nullptr;
    napi_value albumAsset = nullptr;

    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = true;
    napi_get_undefined(env, &jsContext->error);
    if (!context->albumAssets.empty() && (napi_create_array(env, &albumArray) == napi_ok)) {
        size_t len = context->albumAssets.size();
        size_t i = 0;
        for (; i < len; i++) {
            string path = ALBUM_ROOT_PATH;
            if (!context->selection.empty()) {
                path = "/" + context->selection;
            }
            albumAsset = AlbumAssetNapi::CreateAlbumAsset(env, context->albumType, path,
                *(context->albumAssets[i]), *(context->objectInfo->GetMediaLibClientInstance()));
            if (albumAsset == nullptr || napi_set_element(env, albumArray, i, albumAsset) != napi_ok) {
                HiLog::Error(LABEL, "Failed to get album asset napi object");
                napi_get_undefined(env, &jsContext->data);
                break;
            }
        }
        if (i == len) {
            jsContext->data = albumArray;
        }
    } else {
        HiLog::Error(LABEL, "No album assets found!");
        napi_get_undefined(env, &jsContext->data);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value MediaLibraryNapi::GetVideoAlbums(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value resource = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc >= ARGS_ONE, "requires 1 parameter minimum");

    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = ConvertJSArgsToNative(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "GetVideoAlbums");

        status = napi_create_async_work(
            env, nullptr, resource,
            [](napi_env env, void* data) {
                MediaLibraryAsyncContext* context = static_cast<MediaLibraryAsyncContext*>(data);
                context->albumAssets =
                    context->objectInfo->mediaLibrary_->GetVideoAlbumAssets(context->selection,
                                                                            context->selectionArgs);
                context->albumType = TYPE_VIDEO_ALBUM;
                context->status = 0;
            },
            reinterpret_cast<CompleteCallback>(AlbumAssetsAsyncCallbackComplete),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}

napi_value MediaLibraryNapi::GetImageAlbums(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value resource = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc >= ARGS_ONE, "requires 1 parameter minimum");

    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = ConvertJSArgsToNative(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "GetImageAlbums");

        status = napi_create_async_work(
            env, nullptr, resource,
            [](napi_env env, void* data) {
                MediaLibraryAsyncContext* context = static_cast<MediaLibraryAsyncContext*>(data);
                context->albumAssets =
                    context->objectInfo->mediaLibrary_->GetImageAlbumAssets(context->selection,
                                                                            context->selectionArgs);
                context->albumType = TYPE_IMAGE_ALBUM;
                context->status = 0;
            },
            reinterpret_cast<CompleteCallback>(AlbumAssetsAsyncCallbackComplete),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}

napi_value GetAssetJSObject(napi_env env, NapiAssetType type, IMediaLibraryClient &mediaLibrary)
{
    napi_value assetObj = nullptr;

    switch (type) {
        case TYPE_AUDIO: {
            unique_ptr<AudioAsset> audioObj = make_unique<AudioAsset>();
            assetObj = AudioAssetNapi::CreateAudioAsset(env, *(audioObj), mediaLibrary);
            break;
        }
        case TYPE_VIDEO: {
            unique_ptr<VideoAsset> videoObj = make_unique<VideoAsset>();
            assetObj = VideoAssetNapi::CreateVideoAsset(env, *(videoObj), mediaLibrary);
            break;
        }
        case TYPE_IMAGE: {
            unique_ptr<ImageAsset> imageObj = make_unique<ImageAsset>();
            assetObj = ImageAssetNapi::CreateImageAsset(env, *(imageObj), mediaLibrary);
            break;
        }
        case TYPE_ALBUM: {
            unique_ptr<AlbumAsset> albumObj = make_unique<AlbumAsset>();
            assetObj = AlbumAssetNapi::CreateAlbumAsset(env, TYPE_NONE, "", *(albumObj), mediaLibrary);
            break;
        }
        default:
            HiLog::Error(LABEL, "Wrong media type");
            break;
    }

    if (assetObj == nullptr) {
        HiLog::Error(LABEL, "No assets obtained");
        napi_get_undefined(env, &assetObj);
    }

    return assetObj;
}

void CreateAssetAsyncCbComplete(napi_env env, napi_status status,
                                MediaLibraryAsyncContext *context)
{
    if (context != nullptr) {
        unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
        jsContext->status = true;
        napi_get_undefined(env, &jsContext->error);
        jsContext->data = GetAssetJSObject(env, context->assetType,
                                           *(context->objectInfo->GetMediaLibClientInstance()));

        if (context->work != nullptr) {
            MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                       context->work, *jsContext);
        }
        delete context;
    } else {
        HiLog::Error(LABEL, "Async context is null");
    }
}

void CreateAsyncWork(napi_env env, napi_value resource,
                     const MediaLibraryAsyncContext& mediaLibContext,
                     NapiAssetType type, bool &err)
{
    napi_status status;
    MediaLibraryAsyncContext* asyncContext = const_cast<MediaLibraryAsyncContext *>(&mediaLibContext);
    asyncContext->assetType = type;

    status = napi_create_async_work(
        env, nullptr, resource,
        [](napi_env env, void* data) {},
        reinterpret_cast<CompleteCallback>(CreateAssetAsyncCbComplete),
        (void*)asyncContext, &asyncContext->work);
    if (status != napi_ok) {
        err = true;
    } else {
        napi_queue_async_work(env, asyncContext->work);
    }
}

napi_value MediaLibraryNapi::CreateAudioAsset(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    bool err = false;
    napi_value resource = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_ONE, "requires 1 parameter maximum");

    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = ConvertJSArgsToNative(env, argc, argv, *asyncContext);
        ASSERT_NULLPTR_CHECK(env, result);

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "CreateAudioAsset");

        CreateAsyncWork(env, resource, *(asyncContext.get()), TYPE_AUDIO, err);
        if (!err) {
            asyncContext.release();
        } else {
            napi_get_undefined(env, &result);
        }
    }

    return result;
}

napi_value MediaLibraryNapi::CreateVideoAsset(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    bool err = false;
    napi_value resource = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_ONE, "requires 1 parameter maximum");

    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = ConvertJSArgsToNative(env, argc, argv, *asyncContext);
        ASSERT_NULLPTR_CHECK(env, result);

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "CreateVideoAsset");

        CreateAsyncWork(env, resource, *(asyncContext.get()), TYPE_VIDEO, err);
        if (!err) {
            asyncContext.release();
        } else {
            napi_get_undefined(env, &result);
        }
    }

    return result;
}

napi_value MediaLibraryNapi::CreateImageAsset(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    bool err = false;
    napi_value resource = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_ONE, "requires 1 parameter maximum");

    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = ConvertJSArgsToNative(env, argc, argv, *asyncContext);
        ASSERT_NULLPTR_CHECK(env, result);

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "CreateImageAsset");

        CreateAsyncWork(env, resource, *(asyncContext.get()), TYPE_IMAGE, err);
        if (!err) {
            asyncContext.release();
        } else {
            napi_get_undefined(env, &result);
        }
    }

    return result;
}

napi_value MediaLibraryNapi::CreateAlbum(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    bool err = false;
    napi_value resource = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc <= ARGS_ONE, "requires 1 parameter maximum");

    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = ConvertJSArgsToNative(env, argc, argv, *asyncContext);
        ASSERT_NULLPTR_CHECK(env, result);

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "CreateAlbum");

        CreateAsyncWork(env, resource, *(asyncContext.get()), TYPE_ALBUM, err);
        if (!err) {
            asyncContext.release();
        } else {
            napi_get_undefined(env, &result);
        }
    }

    return result;
}
static void GetPublicDirectoryCallbackComplete(napi_env env, napi_status status,
                                               MediaLibraryAsyncContext *context)
{
    HiLog::Debug(LABEL, "GetPublicDirectoryCompleteCallback IN");
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    unsigned int dirIndex = context->dirType;
    if (context->error == ERR_DEFAULT) {
        HiLog::Debug(LABEL, "GetPublicDirectoryCompleteCallback dirIndex < directoryEnumValues.size()");
        
        napi_create_string_utf8(env, directoryEnumValues[dirIndex].c_str(), NAPI_AUTO_LENGTH, &jsContext->data);
        jsContext->status = true;
        napi_get_undefined(env, &jsContext->error);
    } else {
        HiLog::Debug(LABEL, "dirIndex is illegal");
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, context->error, "dirIndex is illegal");
        napi_get_undefined(env, &jsContext->data);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    HiLog::Debug(LABEL, "GetPublicDirectoryCompleteCallback OUT");
    delete context;
}

napi_value MediaLibraryNapi::JSGetPublicDirectory(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0}, thisVar = nullptr, resource = nullptr;
    const int32_t refCount = 1;
    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");

    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        for (size_t i = PARAM0; i < argc; i++) {
            napi_valuetype valueType = napi_undefined;
            napi_typeof(env, argv[i], &valueType);

            if (i == PARAM0 && valueType == napi_number) {
                napi_get_value_int32(env, argv[i], &asyncContext->dirType);
            } else if (i == PARAM1 && valueType == napi_function) {
                napi_create_reference(env, argv[i], refCount, &asyncContext->callbackRef);
                break;
            } else {
                NAPI_ASSERT(env, false, "type mismatch");
            }
        }

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSGetPublicDirectory");

        status = napi_create_async_work(
            env, nullptr, resource,
            [](napi_env env, void* data) {
                auto context = static_cast<MediaLibraryAsyncContext*>(data);
                if (!CheckUserGrantedPermission(env, PERMISSION_NAME_READ_MEDIA)) {
                    context->error = ERR_PERMISSION_DENIED;
                    return;
                }
                unsigned int dirIndex = context->dirType;
                if (dirIndex < directoryEnumValues.size()) {
                    context->directoryRelativePath = directoryEnumValues[dirIndex];
                } else {
                    context->error = ERR_INVALID_OUTPUT;
                }
            },
            reinterpret_cast<CompleteCallback>(GetPublicDirectoryCallbackComplete),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}

static void GetFileAssetsExecute(MediaLibraryAsyncContext *context)
{
    vector<string> columns;
    NativeRdb::DataAbilityPredicates predicates;

    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> ? ";
    MediaLibraryNapiUtils::UpdateFetchOptionSelection(context->selection, prefix);
    context->selectionArgs.insert(context->selectionArgs.begin(), to_string(MEDIA_TYPE_ALBUM));

    string trashPrefix = MEDIA_DATA_DB_DATE_TRASHED + " = ? ";
    MediaLibraryNapiUtils::UpdateFetchOptionSelection(context->selection, trashPrefix);
    context->selectionArgs.insert(context->selectionArgs.begin(), "0");

    predicates.SetWhereClause(context->selection);
    predicates.SetWhereArgs(context->selectionArgs);
    predicates.SetOrder(context->order);

    Uri uri(MEDIALIBRARY_DATA_URI);
    shared_ptr<AbsSharedResultSet> resultSet;

    if (context->objectInfo->sAbilityHelper_ == nullptr
        || ((resultSet = context->objectInfo->sAbilityHelper_->Query(uri, columns, predicates)) == nullptr)) {
        context->error = ERR_INVALID_OUTPUT;
        HiLog::Error(LABEL, "Query for get fileAssets failed");
    } else {
        // Create FetchResult object using the contents of resultSet
        context->fetchFileResult = make_unique<FetchResult>(move(resultSet));
    }
}

static void GetFileAssetsAsyncCallbackComplete(napi_env env, napi_status status,
                                               MediaLibraryAsyncContext *context)
{
    napi_value fileResult = nullptr;

    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    napi_get_undefined(env, &jsContext->data);

    if (context->error != ERR_DEFAULT) {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, context->error,
            "Query for get fileAssets failed");
    } else {
        // Create FetchResult object using the contents of resultSet
        if (context->fetchFileResult != nullptr) {
            fileResult = FetchFileResultNapi::CreateFetchFileResult(env, *(context->fetchFileResult));
            if (fileResult == nullptr) {
                MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
                    "Failed to create js object for Fetch File Result");
            } else {
                jsContext->data = fileResult;
                jsContext->status = true;
                napi_get_undefined(env, &jsContext->error);
            }
        } else {
            HiLog::Error(LABEL, "No fetch file result found!");
            MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
                "Failed to obtain Fetch File Result");
        }
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value MediaLibraryNapi::JSGetFileAssets(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");

    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = ConvertJSArgsToNative(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSGetFileAssets");

        status = napi_create_async_work(
            env, nullptr, resource,
            [](napi_env env, void* data) {
                auto context = static_cast<MediaLibraryAsyncContext*>(data);
                if (!CheckUserGrantedPermission(env, PERMISSION_NAME_READ_MEDIA)) {
                    HiLog::Error(LABEL, "Process do not have permission of read media!");
                    context->error = ERR_PERMISSION_DENIED;
                    return;
                }
                GetFileAssetsExecute(context);
            },
            reinterpret_cast<CompleteCallback>(GetFileAssetsAsyncCallbackComplete),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}

variant<int, string> GetValFromColumn(string columnName,
    shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet)
{
    HiLog::Error(LABEL, "columnName = %{public}s", columnName.c_str());
    int index;
    variant<int, string> cellValue;
    NativeRdb::ColumnType type;
    int integerVal;
    string stringVal;

    resultSet->GetColumnIndex(columnName, index);
    resultSet->GetColumnType(index, type);
    switch (type) {
        case NativeRdb::ColumnType::TYPE_STRING:
            HiLog::Error(LABEL, "TYPE_STRING");
            resultSet->GetString(index, stringVal);
            cellValue = stringVal;
            break;
        case NativeRdb::ColumnType::TYPE_INTEGER:
            HiLog::Error(LABEL, "TYPE_INTEGER");
            resultSet->GetInt(index, integerVal);
            cellValue = integerVal;
            break;
        default:
            HiLog::Error(LABEL, "No type");
            cellValue = "Notype";
            break;
    }

    return cellValue;
}

static void GetResultDataExecute(MediaLibraryAsyncContext *context)
{
    HiLog::Error(LABEL, "GetResultDataExecute IN");
    NativeRdb::DataAbilityPredicates predicates;
    if (context->objectInfo->sAbilityHelper_ == nullptr) {
        context->error = ERR_INVALID_OUTPUT;
    }
    predicates.SetWhereClause(context->selection);
    predicates.SetWhereArgs(context->selectionArgs);
    if (!context->order.empty()) {
        predicates.SetOrder(context->order);
    }

    vector<string> columns;
    Uri uri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_ALBUMOPRN_QUERYALBUM);
    shared_ptr<NativeRdb::AbsSharedResultSet> resultSet = context->objectInfo->sAbilityHelper_->Query(
        uri, columns, predicates);
    HiLog::Error(LABEL, "GetResultData resultSet");
    if (resultSet != nullptr) {
        HiLog::Error(LABEL, "GetResultData resultSet != nullptr");
        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            unique_ptr<AlbumAsset> albumData = make_unique<AlbumAsset>();
            if (albumData != nullptr) {
                // Get album id index and value
                albumData->SetAlbumId(get<int32_t>(GetValFromColumn(MEDIA_DATA_DB_ID, resultSet)));
                HiLog::Error(LABEL, "MEDIA_DATA_DB_BUCKET_ID");
                // Get album title index and value
                albumData->SetAlbumName(get<string>(GetValFromColumn(MEDIA_DATA_DB_TITLE, resultSet)));
                HiLog::Error(LABEL, "MEDIA_DATA_DB_BUCKET_NAME");
                // Get album asset count index and value
                albumData->SetCount(get<int32_t>(GetValFromColumn(MEDIA_DATA_DB_COUNT, resultSet)));
                HiLog::Error(LABEL, "MEDIA_DATA_DB_ID");
            }
            // Add to album array
            context->albumNativeArray.push_back(move(albumData));
        }
        HiLog::Error(LABEL, "GetResultDataExecute OUT");
    }
}

static void AlbumsAsyncCallbackComplete(napi_env env, napi_status status,
                                        MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    napi_get_undefined(env, &jsContext->error);
    HiLog::Error(LABEL, "AlbumsAsyncCallbackComplete");
    if (context->error != ERR_DEFAULT) {
        napi_get_undefined(env, &jsContext->data);
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, context->error,
            "Query for get fileAssets failed");
    } else {
        if (context->albumNativeArray.empty()) {
        HiLog::Error(LABEL, "AlbumsAsyncCallbackComplete 1");
        napi_get_undefined(env, &jsContext->data);
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
            "No albums found");
        } else {
            napi_value albumArray = nullptr;
            napi_create_array(env, &albumArray);
            for (size_t i = 0; i < context->albumNativeArray.size(); i++) {
                napi_value albumNapiObj = AlbumNapi::CreateAlbumNapi(env, *(context->albumNativeArray[i]),
                    context->objectInfo->sAbilityHelper_);
                napi_set_element(env, albumArray, i, albumNapiObj);
            }
            jsContext->status = true;
            HiLog::Error(LABEL, "AlbumsAsyncCallbackComplete 2");
            napi_get_undefined(env, &jsContext->error);
            jsContext->data = albumArray;
        }
    }
    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value MediaLibraryNapi::JSGetAlbums(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;

    HiLog::Error(LABEL, "JSGetAlbums");
    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");
    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = ConvertJSArgsToNative(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSGetAlbums");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<MediaLibraryAsyncContext*>(data);
                if (!CheckUserGrantedPermission(env, PERMISSION_NAME_READ_MEDIA)) {
                    HiLog::Error(LABEL, "Process do not have permission of read media!");
                    context->error = ERR_PERMISSION_DENIED;
                    return;
                }
                GetResultDataExecute(context);
            },
            reinterpret_cast<CompleteCallback>(AlbumsAsyncCallbackComplete),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}

static void getFileAssetById(int32_t id, const string& selfId, MediaLibraryAsyncContext *context)
{
    vector<string> columns;
    NativeRdb::DataAbilityPredicates predicates;

    predicates.EqualTo(MEDIA_DATA_DB_ID, to_string(id));

    Uri uri(MEDIALIBRARY_DATA_URI);
    shared_ptr<AbsSharedResultSet> resultSet;

    if (context->objectInfo->sAbilityHelper_ != nullptr
        && ((resultSet = context->objectInfo->sAbilityHelper_->Query(uri, columns, predicates)) != nullptr)) {
        // Create FetchResult object using the contents of resultSet
        context->fetchFileResult = make_unique<FetchResult>(move(resultSet));
        HiLog::Debug(LABEL, "getFileAssetById context->fetchFileResult");
        if (context->fetchFileResult != nullptr && context->fetchFileResult->GetCount() >= 1) {
            HiLog::Debug(LABEL, "getFileAssetById fetchFileResult->GetCount() >= 1");
            context->fileAsset = context->fetchFileResult->GetFirstObject();
        }
    }
}

static void JSCreateAssetCompleteCallback(napi_env env, napi_status status,
                                          MediaLibraryAsyncContext *context)
{
    HiLog::Debug(LABEL, "JSCreateAssetCompleteCallback IN");

    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    napi_value jsFileAsset = nullptr;

    if (context->error == ERR_DEFAULT) {
        HiLog::Debug(LABEL, "JSCreateAssetCompleteCallback context->error == ERR_DEFAULT");
        if (context->fileAsset == nullptr) {
            MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
                "Obtain file asset failed");
            napi_get_undefined(env, &jsContext->data);
        } else {
            jsFileAsset = FileAssetNapi::CreateFileAsset(env, *(context->fileAsset));
            if (jsFileAsset == nullptr) {
                HiLog::Error(LABEL, "Failed to get file asset napi object");
                napi_get_undefined(env, &jsContext->data);
                MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_MEM_ALLOCATION,
                    "Failed to create js object for FileAsset");
            } else {
                HiLog::Debug(LABEL, "JSCreateAssetCompleteCallback jsFileAsset != nullptr");
                jsContext->data = jsFileAsset;
                napi_get_undefined(env, &jsContext->error);
                jsContext->status = true;
            }
        }
    } else {
        HiLog::Debug(LABEL, "JSCreateAssetCompleteCallback context->error != ERR_DEFAULT");
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, context->error,
            "File asset creation failed");
        napi_get_undefined(env, &jsContext->data);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    HiLog::Debug(LABEL, "JSCreateAssetCompleteCallback OUT");
    delete context;
}

static bool CheckTitlePrams(const string& title)
{
    if (title.empty()) {
        HiLog::Debug(LABEL, "CheckRelativePathPrams title is empty");
        return false;
    }
    return true;
}

static string GetFirstDirName(const string& relativePath)
{
    string firstDirName = "";
    if (!relativePath.empty()) {
        string::size_type pos = relativePath.find_first_of('/');
        if (pos == relativePath.length()) {
            MEDIA_ERR_LOG("relativePath is first dir");
            return relativePath;
        }
        firstDirName = relativePath.substr(0, pos + 1);
        HiLog::Debug(LABEL, "firstDirName substr = %{public}s", firstDirName.c_str());
    }
    HiLog::Debug(LABEL, "firstDirName = %{public}s", firstDirName.c_str());
    return firstDirName;
}

static bool IsDirectory(const string& dirName)
{
    struct stat statInfo {};
    if (stat((MEDIA_DATA_Path + dirName).c_str(), &statInfo) == SUCCESS) {
        if (statInfo.st_mode & S_IFDIR) {
            return true;
        }
    }

    return false;
}

static bool CheckRelativePathPrams(const string& relativePath)
{
    if (relativePath.empty()) {
        HiLog::Debug(LABEL, "CheckRelativePathPrams relativePath is empty");
        return false;
    }

    if (IsDirectory(relativePath)) {
        HiLog::Debug(LABEL, "CheckRelativePathPrams relativePath exist return true");
        return true;
    }
    
    string firstDirName = GetFirstDirName(relativePath);
    if (!firstDirName.empty() && IsDirectory(firstDirName)) {
        HiLog::Debug(LABEL, "CheckRelativePathPrams firstDirName exist return true");
        return true;
    }
    
    if (!firstDirName.empty()) {
        for (unsigned int i = 0; i < directoryEnumValues.size(); i++) {
            HiLog::Debug(LABEL, "directoryEnumValues%{public}d = %{public}s", i, directoryEnumValues[i].c_str());
            if (!strcmp(firstDirName.c_str(), directoryEnumValues[i].c_str())) {
                return true;
            }
        }
        HiLog::Debug(LABEL, "firstDirName = %{public}s", firstDirName.c_str());
    }
    HiLog::Debug(LABEL, "CheckRelativePathPrams return false");
    return false;
}

napi_value GetJSArgsForCreateAsset(napi_env env, size_t argc, const napi_value argv[],
                                   MediaLibraryAsyncContext &asyncContext)
{
    const int32_t refCount = 1;
    napi_value result = nullptr;
    auto context = &asyncContext;
    int32_t fileMediaType = 0;
    size_t res = 0;
    char relativePathBuffer[PATH_MAX];
    char titleBuffer[PATH_MAX];
    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == PARAM0 && valueType == napi_number) {
            napi_get_value_int32(env, argv[i], &fileMediaType);
        } else if (i == PARAM1 && valueType == napi_string) {
            napi_get_value_string_utf8(env, argv[i], titleBuffer, PATH_MAX, &res);
            HiLog::Debug(LABEL, "displayName = %{public}s", string(titleBuffer).c_str());
        } else if (i == PARAM2 && valueType == napi_string) {
            napi_get_value_string_utf8(env, argv[i], relativePathBuffer, PATH_MAX, &res);
            HiLog::Debug(LABEL, "relativePath = %{public}s", string(relativePathBuffer).c_str());
        } else if (i == PARAM3 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }

    if (!CheckTitlePrams(string(titleBuffer))) {
        NAPI_ASSERT(env, false, "displayName prams invalid");
    }

    if (!CheckRelativePathPrams(string(relativePathBuffer))) {
        NAPI_ASSERT(env, false, "relativePath prams invalid");
    }

    context->valuesBucket.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, fileMediaType);
    context->valuesBucket.PutString(MEDIA_DATA_DB_NAME, string(titleBuffer));
    context->valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, string(relativePathBuffer));
    HiLog::Debug(LABEL, "GetJSArgsForCreateAsset END");
    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}

napi_value MediaLibraryNapi::JSCreateAsset(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_FORE;
    napi_value argv[ARGS_FORE] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_THREE || argc == ARGS_FORE), "requires 4 parameters maximum");

    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForCreateAsset(env, argc, argv, *asyncContext);
        ASSERT_NULLPTR_CHECK(env, result);
        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSCreateAsset");
        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<MediaLibraryAsyncContext*>(data);
                if (!CheckUserGrantedPermission(env, PERMISSION_NAME_WRITE_MEDIA)) {
                    HiLog::Error(LABEL, "Process do not have permission of read media!");
                    context->error = ERR_PERMISSION_DENIED;
                    return;
                }
                if (context->objectInfo->sAbilityHelper_ != nullptr) {
                    Uri createFileUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_CREATEASSET);
                    int index = context->objectInfo->sAbilityHelper_->Insert(createFileUri, context->valuesBucket);
                    if (index < 0) {
                        context->error = index;
                    } else {
                        HiLog::Debug(LABEL, "JSCreateAssetCompleteCallback File asset creation success");
                        getFileAssetById(index, "", context);
                    }
                } else {
                    HiLog::Debug(LABEL, "JSCreateAssetCompleteCallback File asset creation failed");
                    context->error = ERR_INVALID_OUTPUT;
                }
            },
            reinterpret_cast<CompleteCallback>(JSCreateAssetCompleteCallback),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}

static void JSModifyAssetCompleteCallback(napi_env env, napi_status status,
                                          MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    if (context->objectInfo->sAbilityHelper_ != nullptr) {
        string abilityUri = MEDIALIBRARY_DATA_URI;
        Uri updateAssetUri(abilityUri + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_MODIFYASSET);

        NativeRdb::ValueObject valueObject;
        string notifyUri;
        context->valuesBucket.GetObject(MEDIA_DATA_DB_URI, valueObject);
        valueObject.GetString(notifyUri);
        size_t index = notifyUri.rfind('/');
        if (index != string::npos) {
            notifyUri = notifyUri.substr(0, index);
        }

        int retVal = context->objectInfo->sAbilityHelper_->Insert(updateAssetUri,
            context->valuesBucket);
        if (retVal < 0) {
            MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, retVal,
                "File asset modification failed");
            napi_get_undefined(env, &jsContext->data);
        } else {
            napi_create_int32(env, retVal, &jsContext->data);
            jsContext->status = true;
            napi_get_undefined(env, &jsContext->error);
            Uri modifyNotify(notifyUri);
            context->objectInfo->sAbilityHelper_->NotifyChange(modifyNotify);
        }
    } else {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
            "Ability helper is null");
        napi_get_undefined(env, &jsContext->data);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value GetJSArgsForModifyAsset(napi_env env, size_t argc, const napi_value argv[],
                                   MediaLibraryAsyncContext &asyncContext)
{
    const int32_t refCount = 1;
    napi_value result = nullptr;
    auto context = &asyncContext;
    FileAssetNapi *fileAssetObj = nullptr;
    size_t res = 0;
    char buffer[PATH_MAX];

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (i == PARAM0 && valueType == napi_string) {
            napi_get_value_string_utf8(env, argv[i], buffer, PATH_MAX, &res);
        } else if (i == PARAM1 && valueType == napi_object) {
            napi_unwrap(env, argv[i], reinterpret_cast<void**>(&fileAssetObj));
        } else if (i == PARAM2 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }

    context->valuesBucket.PutString(MEDIA_DATA_DB_URI, string(buffer));

    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}

napi_value MediaLibraryNapi::JSModifyAsset(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_THREE;
    napi_value argv[ARGS_THREE] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_TWO || argc == ARGS_THREE), "requires 2 parameters maximum");

    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForModifyAsset(env, argc, argv, *asyncContext);
        ASSERT_NULLPTR_CHECK(env, result);

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSModifyAsset");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<MediaLibraryAsyncContext*>(data);
                if (!CheckUserGrantedPermission(env, PERMISSION_NAME_WRITE_MEDIA)) {
                    HiLog::Error(LABEL, "Process do not have permission of read media!");
                    context->error = ERR_PERMISSION_DENIED;
                    return;
                }
            },
            reinterpret_cast<CompleteCallback>(JSModifyAssetCompleteCallback),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}

static void JSDeleteAssetExecute(MediaLibraryAsyncContext *context)
{
    if (context->objectInfo->sAbilityHelper_ != nullptr) {
        string abilityUri = MEDIALIBRARY_DATA_URI;
        Uri deleteAssetUri(abilityUri + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_DELETEASSET);

        NativeRdb::ValueObject valueObject;
        string notifyUri;
        string mediaType;
        context->valuesBucket.GetObject(MEDIA_DATA_DB_URI, valueObject);
        valueObject.GetString(notifyUri);
        size_t index = notifyUri.rfind('/');
        if (index != string::npos) {
            notifyUri = notifyUri.substr(0, index);
            size_t indexType = notifyUri.rfind('/');
            if (indexType != string::npos) {
                mediaType = notifyUri.substr(indexType + 1);
            }
        }
        notifyUri = MEDIALIBRARY_DATA_URI + "/" + mediaType;
        HiLog::Error(LABEL, "JSDeleteAssetExcute notifyUri = %{public}s", notifyUri.c_str());
        int retVal = context->objectInfo->sAbilityHelper_->Insert(deleteAssetUri,
            context->valuesBucket);
        if (retVal < 0) {
            context->error = retVal;
        } else {
            context->retVal = retVal;
            Uri deleteNotify(notifyUri);
            context->objectInfo->sAbilityHelper_->NotifyChange(deleteNotify);
        }
    } else {
        context->error = ERR_INVALID_OUTPUT;
    }
}

static void JSDeleteAssetCompleteCallback(napi_env env, napi_status status,
                                          MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    if (context->error == ERR_DEFAULT) {
        HiLog::Debug(LABEL, "Delete result = %{public}d", context->retVal);
        napi_create_int32(env, context->retVal, &jsContext->data);
        napi_get_undefined(env, &jsContext->error);
        jsContext->status = true;
    } else {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, context->error,
            "Ability helper is null");
        napi_get_undefined(env, &jsContext->data);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value GetJSArgsForDeleteAsset(napi_env env, size_t argc, const napi_value argv[],
                                   MediaLibraryAsyncContext &asyncContext)
{
    const int32_t refCount = 1;
    napi_value result = nullptr;
    auto context = &asyncContext;
    size_t res = 0;
    char buffer[PATH_MAX];

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (i == PARAM0 && valueType == napi_string) {
            napi_get_value_string_utf8(env, argv[i], buffer, PATH_MAX, &res);
        } else if (i == PARAM1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }

    context->valuesBucket.PutString(MEDIA_DATA_DB_URI, string(buffer));

    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}

napi_value MediaLibraryNapi::JSDeleteAsset(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");

    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForDeleteAsset(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSDeleteAsset");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<MediaLibraryAsyncContext*>(data);
                if (!CheckUserGrantedPermission(env, PERMISSION_NAME_WRITE_MEDIA)) {
                    HiLog::Error(LABEL, "Process do not have permission of read media!");
                    context->error = ERR_PERMISSION_DENIED;
                    return;
                }
                JSDeleteAssetExecute(context);
            },
            reinterpret_cast<CompleteCallback>(JSDeleteAssetCompleteCallback),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}

static void JSOpenAssetCompleteCallback(napi_env env, napi_status status,
                                        MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    if (context->objectInfo->sAbilityHelper_ != nullptr) {
        NativeRdb::ValueObject valueObject;
        string fileUri = "";
        string mode = MEDIA_FILEMODE_READONLY;

        if (context->valuesBucket.GetObject(MEDIA_DATA_DB_URI, valueObject)) {
            valueObject.GetString(fileUri);
        }

        if (context->valuesBucket.GetObject(MEDIA_FILEMODE, valueObject)) {
            valueObject.GetString(mode);
        }

        Uri openFileUri(fileUri);
        int32_t retVal = context->objectInfo->sAbilityHelper_->OpenFile(openFileUri, mode);
        if (retVal <= 0) {
            MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, retVal,
                "File open asset failed");
            napi_get_undefined(env, &jsContext->data);
        } else {
            napi_create_int32(env, retVal, &jsContext->data);
            napi_get_undefined(env, &jsContext->error);
            jsContext->status = true;
        }
    } else {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
            "Ability helper is null");
        napi_get_undefined(env, &jsContext->data);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value GetJSArgsForOpenAsset(napi_env env, size_t argc, const napi_value argv[],
                                 MediaLibraryAsyncContext &asyncContext)
{
    const int32_t refCount = 1;
    napi_value result = nullptr;
    auto context = &asyncContext;
    size_t res = 0;
    char buffer1[PATH_MAX], buffer2[SIZE];

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (i == PARAM0 && valueType == napi_string) {
            napi_get_value_string_utf8(env, argv[i], buffer1, PATH_MAX, &res);
        } else if (i == PARAM1 && valueType == napi_string) {
            napi_get_value_string_utf8(env, argv[i], buffer2, SIZE, &res);
        } else if (i == PARAM2 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }

    context->valuesBucket.PutString(MEDIA_DATA_DB_URI, string(buffer1));
    context->valuesBucket.PutString(MEDIA_FILEMODE, string(buffer2));

    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}

napi_value MediaLibraryNapi::JSOpenAsset(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_THREE;
    napi_value argv[ARGS_THREE] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_TWO || argc == ARGS_THREE), "requires 3 parameters maximum");

    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForOpenAsset(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSOpenAsset");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<MediaLibraryAsyncContext *>(data);
                if (!CheckUserGrantedPermission(env, PERMISSION_NAME_READ_MEDIA)) {
                    HiLog::Error(LABEL, "Process do not have permission of read media!");
                    context->error = ERR_PERMISSION_DENIED;
                    return;
                }
            },
            reinterpret_cast<CompleteCallback>(JSOpenAssetCompleteCallback),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}

static void JSCloseAssetCompleteCallback(napi_env env, napi_status status,
                                         MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    if (context->objectInfo->sAbilityHelper_ != nullptr) {
        string abilityUri = MEDIALIBRARY_DATA_URI;
        Uri closeAssetUri(abilityUri + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_CLOSEASSET);
        ValueObject valueObject;
        int fd = 0;

        if (context->valuesBucket.GetObject(MEDIA_FILEDESCRIPTOR, valueObject)) {
            valueObject.GetInt(fd);
        }

        int32_t retVal = close(fd);
        if ((retVal == DATA_ABILITY_SUCCESS) && (context->objectInfo->sAbilityHelper_->Insert(closeAssetUri,
            context->valuesBucket) == DATA_ABILITY_SUCCESS)) {
            napi_create_int32(env, DATA_ABILITY_SUCCESS, &jsContext->data);
            napi_get_undefined(env, &jsContext->error);
            jsContext->status = true;
        } else {
            HiLog::Error(LABEL, "negative ret");
            MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, retVal,
                "File close asset failed");
            napi_get_undefined(env, &jsContext->data);
        }
    } else {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
            "Ability helper is null");
        napi_get_undefined(env, &jsContext->data);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value GetJSArgsForCloseAsset(napi_env env, size_t argc, const napi_value argv[],
                                  MediaLibraryAsyncContext &asyncContext)
{
    const int32_t refCount = 1;
    napi_value result = nullptr;
    auto context = &asyncContext;
    size_t res = 0;
    char buffer[PATH_MAX];
    int32_t fd = 0;

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (i == PARAM0 && valueType == napi_string) {
            napi_get_value_string_utf8(env, argv[i], buffer, PATH_MAX, &res);
        } else if (i == PARAM1 && valueType == napi_number) {
            napi_get_value_int32(env, argv[i], &fd);
        } else if (i == PARAM2 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }

    context->valuesBucket.PutString(MEDIA_DATA_DB_URI, string(buffer));
    context->valuesBucket.PutInt(MEDIA_FILEDESCRIPTOR, fd);

    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}

napi_value MediaLibraryNapi::JSCloseAsset(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_THREE;
    napi_value argv[ARGS_THREE] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_TWO || argc == ARGS_THREE), "requires 3 parameters maximum");

    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForCloseAsset(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSCloseAsset");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<MediaLibraryAsyncContext *>(data);
                if (!CheckUserGrantedPermission(env, PERMISSION_NAME_READ_MEDIA)) {
                    HiLog::Error(LABEL, "Process do not have permission of read media!");
                    context->error = ERR_PERMISSION_DENIED;
                    return;
                }
            },
            reinterpret_cast<CompleteCallback>(JSCloseAssetCompleteCallback),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}

static void JSCreateAlbumCompleteCallback(napi_env env, napi_status status,
                                          MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    if (context->objectInfo->sAbilityHelper_ != nullptr) {
        string abilityUri = MEDIALIBRARY_DATA_URI;
        Uri createAlbumUri(abilityUri + "/" + MEDIA_ALBUMOPRN + "/" + MEDIA_ALBUMOPRN_CREATEALBUM);

        int albumId = context->objectInfo->sAbilityHelper_->Insert(createAlbumUri,
            context->valuesBucket);
        if (albumId < 0) {
            MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, albumId,
                "Create Album failed");
            napi_get_undefined(env, &jsContext->data);
        } else {
            napi_create_int32(env, albumId, &jsContext->data);
            napi_get_undefined(env, &jsContext->error);
            jsContext->status = true;
        }
    } else {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
            "Ability helper is null");
        napi_get_undefined(env, &jsContext->data);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }

    delete context;
}

napi_value GetJSArgsForCreateAlbum(napi_env env, size_t argc, const napi_value argv[],
    MediaLibraryAsyncContext &asyncContext)
{
    const int32_t refCount = 1;
    napi_value result = nullptr;
    auto context = &asyncContext;
    AlbumNapi *albumNapiObj = nullptr;

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (i == PARAM0 && valueType == napi_object) {
            napi_unwrap(env, argv[i], reinterpret_cast<void**>(&albumNapiObj));
        } else if (i == PARAM1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }

    context->valuesBucket.PutString(MEDIA_DATA_DB_FILE_PATH, albumNapiObj->GetAlbumPath());

    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}

napi_value MediaLibraryNapi::JSCreateAlbum(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");

    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForCreateAlbum(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSCreateAlbum");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<MediaLibraryAsyncContext *>(data);
                if (!CheckUserGrantedPermission(env, PERMISSION_NAME_WRITE_MEDIA)) {
                    HiLog::Error(LABEL, "Process do not have permission of read media!");
                    context->error = ERR_PERMISSION_DENIED;
                    return;
                }
            },
            reinterpret_cast<CompleteCallback>(JSCreateAlbumCompleteCallback),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}

static void JSModifyAlbumCompleteCallback(napi_env env, napi_status status,
                                          MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    if (context->objectInfo->sAbilityHelper_ != nullptr) {
        string abilityUri = MEDIALIBRARY_DATA_URI;
        Uri modifyAlbumUri(abilityUri + "/" + MEDIA_ALBUMOPRN + "/" + MEDIA_ALBUMOPRN_MODIFYALBUM);

        int retVal = context->objectInfo->sAbilityHelper_->Insert(modifyAlbumUri,
            context->valuesBucket);
        if (retVal < 0) {
            MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, retVal,
                "Modify Album failed");
            napi_get_undefined(env, &jsContext->data);
        } else {
            napi_create_int32(env, retVal, &jsContext->data);
            napi_get_undefined(env, &jsContext->error);
            jsContext->status = true;
        }
    } else {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
            "Ability helper is null");
        napi_get_undefined(env, &jsContext->data);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value GetJSArgsForModifyAlbum(napi_env env, size_t argc, const napi_value argv[],
    MediaLibraryAsyncContext &asyncContext)
{
    const int32_t refCount = 1;
    napi_value result = nullptr;
    auto context = &asyncContext;
    AlbumNapi *albumNapiObj = nullptr;
    int32_t albumId = 0;

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (i == PARAM0 && valueType == napi_number) {
            napi_get_value_int32(env, argv[i], &albumId);
        } else if (i == PARAM1 && valueType == napi_object) {
            napi_unwrap(env, argv[i], reinterpret_cast<void**>(&albumNapiObj));
        } else if (i == PARAM2 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }

    context->valuesBucket.PutInt(MEDIA_DATA_DB_ID, albumId);
    context->valuesBucket.PutString(MEDIA_DATA_DB_BUCKET_NAME, albumNapiObj->GetAlbumName());

    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}

napi_value MediaLibraryNapi::JSModifyAlbum(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_THREE;
    napi_value argv[ARGS_THREE] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_TWO || argc == ARGS_THREE), "requires 3 parameters maximum");

    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForModifyAlbum(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSModifyAlbum");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<MediaLibraryAsyncContext *>(data);
                if (!CheckUserGrantedPermission(env, PERMISSION_NAME_WRITE_MEDIA)) {
                    HiLog::Error(LABEL, "Process do not have permission of read media!");
                    context->error = ERR_PERMISSION_DENIED;
                    return;
                }
            },
            reinterpret_cast<CompleteCallback>(JSModifyAlbumCompleteCallback),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}

static void JSDeleteAlbumCompleteCallback(napi_env env, napi_status status,
                                          MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    if (context->objectInfo->sAbilityHelper_ != nullptr) {
        string abilityUri = MEDIALIBRARY_DATA_URI;
        Uri deleteAlbumUri(abilityUri + "/" + MEDIA_ALBUMOPRN + "/" + MEDIA_ALBUMOPRN_DELETEALBUM);

        int retVal = context->objectInfo->sAbilityHelper_->Insert(deleteAlbumUri,
            context->valuesBucket);
        if (retVal < 0) {
            MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, retVal,
                "Delete Album failed");
            napi_get_undefined(env, &jsContext->data);
        } else {
            napi_create_int32(env, retVal, &jsContext->data);
            napi_get_undefined(env, &jsContext->error);
            jsContext->status = true;
        }
    } else {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
            "Ability helper is null");
        napi_get_undefined(env, &jsContext->data);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value GetJSArgsForDeleteAlbum(napi_env env, size_t argc, const napi_value argv[],
    MediaLibraryAsyncContext &asyncContext)
{
    const int32_t refCount = 1;
    napi_value result = nullptr;
    auto context = &asyncContext;
    int32_t albumId = 0;

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (i == PARAM0 && valueType == napi_number) {
            napi_get_value_int32(env, argv[i], &albumId);
        } else if (i == PARAM1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }

    context->valuesBucket.PutInt(MEDIA_DATA_DB_ID, albumId);

    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}

napi_value MediaLibraryNapi::JSDeleteAlbum(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");

    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForDeleteAlbum(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSDeleteAlbum");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<MediaLibraryAsyncContext *>(data);
                if (!CheckUserGrantedPermission(env, PERMISSION_NAME_WRITE_MEDIA)) {
                    HiLog::Error(LABEL, "Process do not have permission of read media!");
                    context->error = ERR_PERMISSION_DENIED;
                    return;
                }
            },
            reinterpret_cast<CompleteCallback>(JSDeleteAlbumCompleteCallback),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}

void ChangeListenerNapi::OnChange(const MediaChangeListener &listener, const napi_ref cbRef)
{
    napi_value result[ARGS_TWO] = {nullptr};
    napi_value callback = nullptr;
    napi_value retVal = nullptr;
    string propName = "mediaType";

    napi_get_undefined(env_, &result[PARAM0]);
    napi_get_undefined(env_, &result[PARAM1]);
    napi_get_reference_value(env_, cbRef, &callback);
    napi_call_function(env_, nullptr, callback, ARGS_TWO, result, &retVal);
}

void MediaLibraryNapi::RegisterChangeByType(string type, const ChangeListenerNapi &listenerObj)
{
    ChangeListenerNapi *listObj = const_cast<ChangeListenerNapi *>(&listenerObj);
    if (type.compare(AUDIO_LISTENER) == 0) {
        listObj->audioDataObserver_ = new(nothrow) MediaObserver(*listObj, MEDIA_TYPE_AUDIO);
        Uri onCbURI(MEDIALIBRARY_AUDIO_URI);
        sAbilityHelper_->RegisterObserver(onCbURI, listObj->audioDataObserver_);
        HiLog::Error(LABEL, "subscribeList_ = %{public}s", type.c_str());
    } else if (type.compare(VIDEO_LISTENER) == 0) {
        listObj->videoDataObserver_ = new(nothrow) MediaObserver(*listObj, MEDIA_TYPE_VIDEO);
        Uri onCbURI(MEDIALIBRARY_VIDEO_URI);
        sAbilityHelper_->RegisterObserver(onCbURI, listObj->videoDataObserver_);
        HiLog::Error(LABEL, "subscribeList_ = %{public}s", type.c_str());
    } else if (type.compare(IMAGE_LISTENER) == 0) {
        listObj->imageDataObserver_ = new(nothrow) MediaObserver(*listObj, MEDIA_TYPE_IMAGE);
        Uri onCbURI(MEDIALIBRARY_IMAGE_URI);
        sAbilityHelper_->RegisterObserver(onCbURI, listObj->imageDataObserver_);
        HiLog::Error(LABEL, "subscribeList_ = %{public}s", type.c_str());
    } else if (type.compare(FILE_LISTENER) == 0) {
        listObj->fileDataObserver_ = new(nothrow) MediaObserver(*listObj, MEDIA_TYPE_FILE);
        Uri onCbURI(MEDIALIBRARY_FILE_URI);
        sAbilityHelper_->RegisterObserver(onCbURI, listObj->fileDataObserver_);
        HiLog::Error(LABEL, "subscribeList_ = %{public}s", type.c_str());
    } else if (type.compare(SMARTALBUM_LISTENER) == 0) {
        listObj->smartAlbumDataObserver_ = new(nothrow) MediaObserver(*listObj, MEDIA_TYPE_SMARTALBUM);
        Uri onCbURI(MEDIALIBRARY_SMARTALBUM_CHANGE_URI);
        sAbilityHelper_->RegisterObserver(onCbURI, listObj->smartAlbumDataObserver_);
        HiLog::Error(LABEL, "subscribeList_ = %{public}s", type.c_str());
    } else if (type.compare(FILE_LISTENER) == 0) {
        listObj->deviceDataObserver_ = new(nothrow) MediaObserver(*listObj, MEDIA_TYPE_DEVICE);
        Uri onCbURI(MEDIALIBRARY_DEVICE_URI);
        sAbilityHelper_->RegisterObserver(onCbURI, listObj->deviceDataObserver_);
        HiLog::Error(LABEL, "subscribeList_ = %{public}s", type.c_str());
    } else {
        HiLog::Error(LABEL, "Media Type mismatch!");
        return;
    }
}

void MediaLibraryNapi::RegisterChange(napi_env env, const ChangeListenerNapi &listObj)
{
    if (subscribeList_.empty()) {
        HiLog::Error(LABEL, "No types are received for subscribe");
        return;
    }

    for (string type : subscribeList_) {
        RegisterChangeByType(type, listObj);
    }
}

napi_value MediaLibraryNapi::JSOnCallback(napi_env env, napi_callback_info info)
{
    napi_value undefinedResult = nullptr;
    size_t argCount = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {nullptr};
    napi_value thisVar = nullptr;
    size_t res = 0;
    uint32_t len = 0;
    char buffer[SIZE];
    string strItem;
    const int32_t refCount = 1;
    napi_value stringItem = nullptr;
    MediaLibraryNapi *obj = nullptr;
    napi_status status;

    napi_get_undefined(env, &undefinedResult);

    GET_JS_ARGS(env, info, argCount, argv, thisVar);
    NAPI_ASSERT(env, argCount == ARGS_TWO, "requires 2 parameters");

    if (thisVar == nullptr || argv[PARAM0] == nullptr || argv[PARAM1] == nullptr) {
        HiLog::Error(LABEL, "Failed to retrieve details about the callback");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if (status == napi_ok && obj != nullptr) {
        napi_valuetype valueType = napi_undefined;
        bool boolResult = false;
        if (napi_is_array(env, argv[PARAM0], &boolResult) != napi_ok || boolResult == false
            || napi_typeof(env, argv[PARAM1], &valueType) != napi_ok || valueType != napi_function) {
            return undefinedResult;
        }

        napi_get_array_length(env, argv[PARAM0], &len);
        for (size_t i = 0; i < len; i++) {
            napi_get_element(env, argv[PARAM0], i, &stringItem);
            napi_get_value_string_utf8(env, stringItem, buffer, SIZE, &res);
            strItem = string(buffer);
            obj->subscribeList_.push_back(strItem);
            if (memset_s(buffer, SIZE, 0, sizeof(buffer)) != 0) {
                HiLog::Error(LABEL, "Memset for buffer failed");
                return undefinedResult;
            }
        }

        napi_create_reference(env, argv[PARAM1], refCount, &g_listObj->cbOnRef_);

        obj->RegisterChange(env, *g_listObj);
    }

    return undefinedResult;
}

void MediaLibraryNapi::UnregisterChangeByType(string type, const ChangeListenerNapi &listenerObj)
{
    ChangeListenerNapi *listObj = const_cast<ChangeListenerNapi *>(&listenerObj);
    MediaType mediaType;
    if (type.compare(AUDIO_LISTENER) == 0) {
        CHECK_NULL_PTR_RETURN_VOID(listObj->audioDataObserver_, "Failed to obtain audio data observer");

        mediaType = MEDIA_TYPE_AUDIO;
        Uri offCbURI(MEDIALIBRARY_AUDIO_URI);
        sAbilityHelper_->UnregisterObserver(offCbURI, listObj->audioDataObserver_);

        delete listObj->audioDataObserver_;
        listObj->audioDataObserver_ = nullptr;
    } else if (type.compare(VIDEO_LISTENER) == 0) {
        CHECK_NULL_PTR_RETURN_VOID(listObj->videoDataObserver_, "Failed to obtain video data observer");

        mediaType = MEDIA_TYPE_VIDEO;
        Uri offCbURI(MEDIALIBRARY_VIDEO_URI);
        sAbilityHelper_->UnregisterObserver(offCbURI, listObj->videoDataObserver_);

        delete listObj->videoDataObserver_;
        listObj->videoDataObserver_ = nullptr;
    } else if (type.compare(IMAGE_LISTENER) == 0) {
        CHECK_NULL_PTR_RETURN_VOID(listObj->imageDataObserver_, "Failed to obtain image data observer");

        mediaType = MEDIA_TYPE_IMAGE;
        Uri offCbURI(MEDIALIBRARY_IMAGE_URI);
        sAbilityHelper_->UnregisterObserver(offCbURI, listObj->imageDataObserver_);

        delete listObj->imageDataObserver_;
        listObj->imageDataObserver_ = nullptr;
    } else if (type.compare(FILE_LISTENER) == 0) {
        CHECK_NULL_PTR_RETURN_VOID(listObj->fileDataObserver_, "Failed to obtain file data observer");

        mediaType = MEDIA_TYPE_FILE;
        Uri offCbURI(MEDIALIBRARY_FILE_URI);
        sAbilityHelper_->UnregisterObserver(offCbURI, listObj->fileDataObserver_);

        delete listObj->fileDataObserver_;
        listObj->fileDataObserver_ = nullptr;
    } else {
        return;
    }

    if (listObj->cbOffRef_ != nullptr) {
        MediaChangeListener listener;
        listener.mediaType = mediaType;
        listObj->OnChange(listener, listObj->cbOffRef_);
    }
}

void MediaLibraryNapi::UnregisterChange(napi_env env, const ChangeListenerNapi &listenerObj)
{
    if (unsubscribeList_.empty()) {
        HiLog::Error(LABEL, "No types are received for unsubscribe");
        return;
    }

    for (string type : unsubscribeList_) {
        UnregisterChangeByType(type, listenerObj);
    }
}

napi_value MediaLibraryNapi::JSOffCallback(napi_env env, napi_callback_info info)
{
    napi_value undefinedResult = nullptr;
    size_t argCount = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {nullptr};
    napi_value thisVar = nullptr;
    size_t res = 0;
    uint32_t len = 0;
    char buffer[SIZE];
    const int32_t refCount = 1;
    napi_value stringItem = nullptr;
    MediaLibraryNapi *obj = nullptr;
    napi_status status;

    napi_get_undefined(env, &undefinedResult);

    GET_JS_ARGS(env, info, argCount, argv, thisVar);
    NAPI_ASSERT(env, argCount <= ARGS_TWO, "requires 2 parameters maximum");

    if (thisVar == nullptr || argv[PARAM0] == nullptr) {
        HiLog::Error(LABEL, "Failed to retrieve details about the callback");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if (status == napi_ok && obj != nullptr) {
        napi_valuetype valueType = napi_undefined;
        bool boolResult = false;
        if (napi_is_array(env, argv[PARAM0], &boolResult) != napi_ok || boolResult == false) {
            return undefinedResult;
        }

        napi_get_array_length(env, argv[PARAM0], &len);
        for (size_t i = 0; i < len; i++) {
            napi_get_element(env, argv[PARAM0], i, &stringItem);
            napi_get_value_string_utf8(env, stringItem, buffer, SIZE, &res);
            obj->unsubscribeList_.push_back(string(buffer));
            if (memset_s(buffer, SIZE, 0, sizeof(buffer)) != 0) {
                HiLog::Error(LABEL, "Memset for buffer failed");
                return undefinedResult;
            }
        }

        if (argCount == ARGS_TWO) {
            if (napi_typeof(env, argv[PARAM1], &valueType) != napi_ok || valueType != napi_function
                || g_listObj == nullptr) {
                return undefinedResult;
            }

            napi_create_reference(env, argv[PARAM1], refCount, &g_listObj->cbOffRef_);
        }

        obj->UnregisterChange(env, *g_listObj);
    }

    return undefinedResult;
}

static void JSReleaseCompleteCallback(napi_env env, napi_status status,
                                      MediaLibraryAsyncContext *context)
{
    HiLog::Error(LABEL, "JSReleaseCompleteCallback in");

    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    HiLog::Error(LABEL, "JSReleaseCompleteCallback end");
    if (context->objectInfo != nullptr) {
        HiLog::Error(LABEL, "JSReleaseCompleteCallback context->objectInfo != nullptr");
        context->objectInfo->~MediaLibraryNapi();
        jsContext->status = true;
    } else {
        HiLog::Error(LABEL, "JSReleaseCompleteCallback context->objectInfo == nullptr");
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
            "Ability helper is null");
        napi_get_undefined(env, &jsContext->data);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    HiLog::Error(LABEL, "JSReleaseCompleteCallback end");
    delete context;
}

napi_value MediaLibraryNapi::JSRelease(napi_env env, napi_callback_info info)
{
    HiLog::Error(LABEL, "JSRelease in");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;
    int32_t refCount = 1;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == 0), "requires 1 parameters maximum");
    HiLog::Error(LABEL, "NAPI_ASSERT end");
    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        if (argc == PARAM1) {
            napi_valuetype valueType = napi_undefined;
            napi_typeof(env, argv[PARAM0], &valueType);
            if (valueType == napi_function) {
                napi_create_reference(env, argv[PARAM0], refCount, &asyncContext->callbackRef);
            }
        }
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSRelease");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {},
            reinterpret_cast<CompleteCallback>(JSReleaseCompleteCallback),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }
    HiLog::Error(LABEL, "JSRelease end");
    return result;
}

static int32_t GetAlbumCapacity(MediaLibraryAsyncContext *context)
{
    string abilityUri = MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_GETALBUMCAPACITY;
    Uri getAlbumCapacityUri(abilityUri);
    HiLog::Error(LABEL, "GetAlbumCapacity getAlbumCapacityUri = %{public}s", abilityUri.c_str());

    return context->objectInfo->sAbilityHelper_->Insert(getAlbumCapacityUri, context->valuesBucket);
}

static void GetFavSmartAlbumExecute(MediaLibraryAsyncContext *context)
{
    HiLog::Error(LABEL, "GetFavSmartAlbum IN");
    context->smartAlbumData = make_unique<SmartAlbumAsset>();

    context->smartAlbumData->SetAlbumId(FAVORIT_SMART_ALBUM_ID);
    HiLog::Error(LABEL, "SMARTALBUM_DB_ID = %{public}d", context->smartAlbumData->GetAlbumId());
    context->smartAlbumData->SetAlbumName(FAVORIT_SMART_ALBUM_NAME);
    HiLog::Error(LABEL, "SMARTALBUM_DB_NAME = %{public}s", (context->smartAlbumData->GetAlbumName()).c_str());
    context->valuesBucket.PutBool(MEDIA_DATA_DB_IS_FAV, true);
    context->valuesBucket.PutBool(MEDIA_DATA_DB_IS_TRASH, false);
    context->smartAlbumData->SetAlbumCapacity(GetAlbumCapacity(context));
    HiLog::Error(LABEL, "AlbumCapacity = %{public}d", context->smartAlbumData->GetAlbumCapacity());
    context->smartAlbumData->SetAlbumPrivateType(TYPE_FAVORITE);
    HiLog::Error(LABEL, "GetFavSmartAlbum OUT");
}

static void GetTrashSmartAlbumExecute(MediaLibraryAsyncContext *context)
{
    HiLog::Error(LABEL, "GetTrashSmartAlbumExecute IN");
    context->smartAlbumData = make_unique<SmartAlbumAsset>();

    context->smartAlbumData->SetAlbumId(TRASH_SMART_ALBUM_ID);
    HiLog::Error(LABEL, "SMARTALBUM_DB_ID = %{public}d", context->smartAlbumData->GetAlbumId());
    context->smartAlbumData->SetAlbumName(TRASH_SMART_ALBUM_NAME);
    HiLog::Error(LABEL, "SMARTALBUM_DB_NAME = %{public}s", (context->smartAlbumData->GetAlbumName()).c_str());
    context->valuesBucket.PutBool(MEDIA_DATA_DB_IS_FAV, false);
    context->valuesBucket.PutBool(MEDIA_DATA_DB_IS_TRASH, true);
    context->smartAlbumData->SetAlbumCapacity(GetAlbumCapacity(context));
    HiLog::Error(LABEL, "AlbumCapacity = %{public}d", context->smartAlbumData->GetAlbumCapacity());
    context->smartAlbumData->SetAlbumPrivateType(TYPE_TRASH);
    HiLog::Error(LABEL, "GetTrashSmartAlbumExecute OUT");
}

static void GetAllSmartAlbumResultDataExecute(MediaLibraryAsyncContext *context)
{
    HiLog::Error(LABEL, "GetSmartAlbumResultData");
    NativeRdb::DataAbilityPredicates predicates;
    if (context->objectInfo->sAbilityHelper_ == nullptr) {
        context->error = ERR_INVALID_OUTPUT;
    }
    if (context->privateAlbumType == TYPE_FAVORITE) {
        GetFavSmartAlbumExecute(context);
    }
    if (context->privateAlbumType == TYPE_TRASH) {
        GetTrashSmartAlbumExecute(context);
    }

    vector<string> columns;
    Uri uri(MEDIALIBRARY_DATA_URI + "/"
            + MEDIA_ALBUMOPRN_QUERYALBUM + "/"
            + SMARTABLUMASSETS_VIEW_NAME);
    shared_ptr<NativeRdb::AbsSharedResultSet> resultSet = context->objectInfo->sAbilityHelper_->Query(
        uri, columns, predicates);
    HiLog::Error(LABEL, "AllSmartAlbum resultSet");
    if (resultSet != nullptr) {
        HiLog::Error(LABEL, "AllSmartAlbum resultSet != nullptr");
        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            unique_ptr<SmartAlbumAsset> albumData = make_unique<SmartAlbumAsset>();
            if (albumData != nullptr) {
                albumData->SetAlbumId(get<int32_t>(GetValFromColumn(SMARTALBUM_DB_ID, resultSet)));
                HiLog::Error(LABEL, "AllSmartAlbum SMARTALBUM_DB_ID = %{public}d", albumData->GetAlbumId());
                albumData->SetAlbumName(get<string>(GetValFromColumn(SMARTALBUM_DB_NAME, resultSet)));
                albumData->SetAlbumCapacity(get<int32_t>(GetValFromColumn(SMARTABLUMASSETS_ALBUMCAPACITY, resultSet)));
                HiLog::Error(LABEL, "AllSmartAlbum SMARTABLUMASSETS_ALBUMCAPACITY");
            }
            context->privateSmartAlbumNativeArray.push_back(move(albumData));
        }
    }
}
static void GetSmartAlbumResultDataExecute(MediaLibraryAsyncContext *context)
{
    NativeRdb::DataAbilityPredicates predicates;
    if (context->objectInfo->sAbilityHelper_ == nullptr) {
        context->error = ERR_INVALID_OUTPUT;
    }
    predicates.SetWhereClause(context->selection);
    predicates.SetWhereArgs(context->selectionArgs);
    if (!context->order.empty()) {
        predicates.SetOrder(context->order);
    }
    vector<string> columns;
    Uri uri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_ALBUMOPRN_QUERYALBUM + "/" + SMARTABLUMASSETS_VIEW_NAME);
    shared_ptr<NativeRdb::AbsSharedResultSet> resultSet = context->objectInfo->sAbilityHelper_->Query(
        uri, columns, predicates);
    if (resultSet != nullptr) {
        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            unique_ptr<SmartAlbumAsset> albumData = make_unique<SmartAlbumAsset>();
            if (albumData != nullptr) {
                albumData->SetAlbumId(get<int32_t>(GetValFromColumn(SMARTALBUM_DB_ID, resultSet)));
                albumData->SetAlbumName(get<string>(GetValFromColumn(SMARTALBUM_DB_NAME, resultSet)));
                int32_t count = 0;
                albumData->SetAlbumCapacity(count);
                albumData->SetAlbumUri(MEDIALIBRARY_SMART_URI + "/"
                    + std::to_string(get<int32_t>(GetValFromColumn(SMARTALBUM_DB_ID, resultSet))));
            }
            context->smartAlbumNativeArray.push_back(move(albumData));
        }
    }
}
static void GetPrivateAlbumCallbackComplete(napi_env env, napi_status status,
                                            MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    napi_get_undefined(env, &jsContext->error);
    if (context->error != ERR_DEFAULT) {
        napi_get_undefined(env, &jsContext->data);
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, context->error,
            "Query for get fileAssets failed");
    } else {
        if (context->smartAlbumData != nullptr) {
            jsContext->status = true;
            napi_value albumArray = nullptr;
            napi_create_array(env, &albumArray);
            napi_value albumNapiObj = SmartAlbumNapi::CreateSmartAlbumNapi(env, *context->smartAlbumData,
                context->objectInfo->sAbilityHelper_);
            napi_set_element(env, albumArray, 0, albumNapiObj);
            napi_get_undefined(env, &jsContext->error);
            jsContext->data = albumArray;
        } else if (!context->privateSmartAlbumNativeArray.empty()) {
            jsContext->status = true;
            napi_value albumArray = nullptr;
            napi_create_array(env, &albumArray);
            for (size_t i = 0; i < context->privateSmartAlbumNativeArray.size(); i++) {
                napi_value albumNapiObj = SmartAlbumNapi::CreateSmartAlbumNapi(env,
                    *(context->privateSmartAlbumNativeArray[i]),
                    context->objectInfo->sAbilityHelper_);
                napi_set_element(env, albumArray, i, albumNapiObj);
            }
            napi_get_undefined(env, &jsContext->error);
            jsContext->data = albumArray;
        } else {
            HiLog::Error(LABEL, "No fetch file result found!");
            napi_get_undefined(env, &jsContext->data);
            MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
                "Failed to obtain Fetch File Result");
        }
    }
    HiLog::Error(LABEL, "GetPrivateAlbumCallbackComplete");
    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}
napi_value MediaLibraryNapi::JSGetPrivateAlbum(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;
    const int32_t refCount = 1;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");
    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        for (size_t i = PARAM0; i < argc; i++) {
            napi_valuetype valueType = napi_undefined;
            napi_typeof(env, argv[i], &valueType);
            if (i == PARAM0 && valueType == napi_number) {
                napi_get_value_int32(env, argv[i], &asyncContext->privateAlbumType);
            } else if (i == PARAM1 && valueType == napi_function) {
                napi_create_reference(env, argv[i], refCount, &asyncContext->callbackRef);
                break;
            } else {
                NAPI_ASSERT(env, false, "type mismatch");
            }
        }
        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSGetPublicDirectory");
        status = napi_create_async_work(
            env, nullptr, resource,
            [](napi_env env, void* data) {
                auto context = static_cast<MediaLibraryAsyncContext *>(data);
                if (!CheckUserGrantedPermission(env, PERMISSION_NAME_READ_MEDIA)) {
                    HiLog::Error(LABEL, "Process do not have permission of read media!");
                    context->error = ERR_PERMISSION_DENIED;
                    return;
                }
                GetAllSmartAlbumResultDataExecute(context);
            },
            reinterpret_cast<CompleteCallback>(GetPrivateAlbumCallbackComplete),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }
    return result;
}
napi_value GetJSArgsForCreateSmartAlbum(napi_env env, size_t argc, const napi_value argv[],
                                        MediaLibraryAsyncContext &asyncContext)
{
    const int32_t refCount = 1;
    napi_value result = nullptr;
    auto context = &asyncContext;
    size_t res = 0;
    char buffer[PATH_MAX];
    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");
    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == PARAM0 && valueType == napi_string) {
            napi_get_value_string_utf8(env, argv[i], buffer, PATH_MAX, &res);
        } else if (i == PARAM1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }
    context->valuesBucket.PutString(SMARTALBUM_DB_NAME, string(buffer));
    napi_get_boolean(env, true, &result);
    return result;
}
static void JSCreateSmartAlbumCompleteCallback(napi_env env, napi_status status,
                                               MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    if (context->error == ERR_DEFAULT) {
        if (context->smartAlbumNativeArray.empty()) {
            HiLog::Error(LABEL, "JSCreateSmartAlbumCompleteCallback 1");
            napi_get_undefined(env, &jsContext->data);
            MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
                "No albums found");
        } else {
            jsContext->status = true;
            napi_value albumNapiObj = SmartAlbumNapi::CreateSmartAlbumNapi(env, *(context->smartAlbumNativeArray[0]),
                                                                           context->objectInfo->sAbilityHelper_);
            jsContext->data = albumNapiObj;
            HiLog::Error(LABEL, "JSCreateSmartAlbumCompleteCallback 2 ");
            napi_get_undefined(env, &jsContext->error);
        }
    } else {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, context->error,
            "File asset creation failed");
        napi_get_undefined(env, &jsContext->data);
    }
    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}
napi_value MediaLibraryNapi::JSCreateSmartAlbum(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0}, thisVar = nullptr, resource = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");
    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForCreateSmartAlbum(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");
        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSDeleteAsset");
        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void *data) {
                auto context = static_cast<MediaLibraryAsyncContext *>(data);
                if (!CheckUserGrantedPermission(env, PERMISSION_NAME_WRITE_MEDIA)) {
                    HiLog::Error(LABEL, "Process do not have permission of read media!");
                    context->error = ERR_PERMISSION_DENIED;
                    return;
                }
                if (context->objectInfo->sAbilityHelper_ != nullptr) {
                    string abilityUri = MEDIALIBRARY_DATA_URI;
                    Uri CreateSmartAlbumUri(abilityUri + "/" + MEDIA_SMARTALBUMOPRN + "/" +
                        MEDIA_SMARTALBUMOPRN_CREATEALBUM);
                    int retVal = context->objectInfo->sAbilityHelper_->Insert(CreateSmartAlbumUri,
                        context->valuesBucket);
                    if (retVal > 0) {
                        context->selection = SMARTALBUM_DB_ID + " = ?";
                        context->selectionArgs = {std::to_string(retVal)};
                        context->retVal = retVal;
                        GetSmartAlbumResultDataExecute(context);
                    } else {
                        context->error = retVal;
                    }
                } else {
                    context->error = ERR_INVALID_OUTPUT;
                }
            },
            reinterpret_cast<CompleteCallback>(JSCreateSmartAlbumCompleteCallback),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }
    return result;
}
napi_value GetJSArgsForDeleteSmartAlbum(napi_env env, size_t argc, const napi_value argv[],
                                        MediaLibraryAsyncContext &asyncContext)
{
    const int32_t refCount = 1;
    napi_value result = nullptr;
    auto context = &asyncContext;
    size_t res = 0;
    char buffer[PATH_MAX];
    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");
    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == PARAM0 && valueType == napi_string) {
            napi_get_value_string_utf8(env, argv[i], buffer, PATH_MAX, &res);
        } else if (i == PARAM1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }
    std::string coverUri = string(buffer);
    std::string strRow;
    string::size_type pos = coverUri.find_last_of('/');
    strRow = coverUri.substr(pos + 1);
    context->valuesBucket.PutInt(SMARTALBUM_DB_ID, std::stoi(strRow));
    napi_get_boolean(env, true, &result);
    return result;
}
static void JSDeleteSmartAlbumCompleteCallback(napi_env env, napi_status status,
                                               MediaLibraryAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    if (context->error == ERR_DEFAULT) {
        napi_create_int32(env, context->retVal, &jsContext->data);
        napi_get_undefined(env, &jsContext->error);
        jsContext->status = true;
    } else {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, context->error,
            "Ability helper is null");
        napi_get_undefined(env, &jsContext->data);
    }
    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}
static void JSDeleteSmartAlbumExecute(MediaLibraryAsyncContext *context)
{
    if (context->objectInfo->sAbilityHelper_ != nullptr) {
        string abilityUri = MEDIALIBRARY_DATA_URI;
        Uri DeleteSmartAlbumUri(abilityUri + "/" + MEDIA_SMARTALBUMOPRN + "/" + MEDIA_SMARTALBUMOPRN_DELETEALBUM);
        int retVal = context->objectInfo->sAbilityHelper_->Insert(DeleteSmartAlbumUri,
            context->valuesBucket);
        HiLog::Error(LABEL, "JSDeleteSmartAlbumCompleteCallback retVal = %{public}d", retVal);
        if (retVal < 0) {
            context->error = retVal;
        } else {
            context->retVal = retVal;
        }
    } else {
        context->error = ERR_INVALID_OUTPUT;
    }
}
napi_value MediaLibraryNapi::JSDeleteSmartAlbum(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");
    napi_get_undefined(env, &result);
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForDeleteSmartAlbum(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");
        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSDeleteAsset");
        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<MediaLibraryAsyncContext *>(data);
                if (!CheckUserGrantedPermission(env, PERMISSION_NAME_WRITE_MEDIA)) {
                    HiLog::Error(LABEL, "Process do not have permission of read media!");
                    context->error = ERR_PERMISSION_DENIED;
                    return;
                }
                JSDeleteSmartAlbumExecute(context);
            },
            reinterpret_cast<CompleteCallback>(JSDeleteSmartAlbumCompleteCallback),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }
    return result;
}
} // namespace Media
} // namespace OHOS
