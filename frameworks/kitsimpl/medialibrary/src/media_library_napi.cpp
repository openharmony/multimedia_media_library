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
#include "uv.h"
#include "string_ex.h"

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
unique_ptr<ChangeListenerNapi> g_listObj = nullptr;
bool g_isNewApi = false;
const int32_t NUM_2 = 2;
const int32_t NUM_3 = 3;

static map<string, ListenerType> ListenerTypeMaps = {
    {"audioChange", AUDIO_LISTENER},
    {"videoChange", VIDEO_LISTENER},
    {"imageChange", IMAGE_LISTENER},
    {"fileChange", FILE_LISTENER},
    {"albumChange", ALBUM_LISTENER},
    {"deviceChange", DEVICE_LISTENER},
    {"remoteFileChange", REMOTEFILE_LISTENER}
};

napi_ref MediaLibraryNapi::sConstructor_ = nullptr;
std::shared_ptr<AppExecFwk::DataAbilityHelper> MediaLibraryNapi::sAbilityHelper_ = nullptr;
napi_ref MediaLibraryNapi::sMediaTypeEnumRef_ = nullptr;
napi_ref MediaLibraryNapi::sFileKeyEnumRef_ = nullptr;
using CompleteCallback = napi_async_complete_callback;
using Context = MediaLibraryAsyncContext* ;
bool MediaLibraryNapi::isStageMode_ = false;

MediaLibraryNapi::MediaLibraryNapi()
    : mediaLibrary_(nullptr), env_(nullptr), wrapper_(nullptr) {}

MediaLibraryNapi::~MediaLibraryNapi()
{
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
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
        DECLARE_NAPI_FUNCTION("deleteSmartAlbum", JSDeleteSmartAlbum),
        DECLARE_NAPI_FUNCTION("getActivePeers", JSGetActivePeers),
        DECLARE_NAPI_FUNCTION("getAllPeers", JSGetAllPeers)
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

shared_ptr<AppExecFwk::DataAbilityHelper> MediaLibraryNapi::GetDataAbilityHelper(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    string strUri = MEDIALIBRARY_DATA_URI;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    std::shared_ptr<AppExecFwk::DataAbilityHelper> dataAbilityHelper = nullptr;

    napi_status status = OHOS::AbilityRuntime::IsStageContext(env, argv[0], isStageMode_);
    if (status != napi_ok) {
        HiLog::Info(LABEL, "argv[0] is not a context");
        auto ability = OHOS::AbilityRuntime::GetCurrentAbility(env);
        if (ability == nullptr) {
            HiLog::Error(LABEL, "Failed to get native context instance");
            return nullptr;
        }
        HiLog::Info(LABEL, "FA Model: ability = %{public}p strUir = %{public}s", ability, strUri.c_str());
        dataAbilityHelper = DataAbilityHelper::Creator(ability->GetContext(), std::make_shared<Uri>(strUri));
    } else {
        HiLog::Info(LABEL, "argv[0] is a context");
        if (isStageMode_) {
            auto context = OHOS::AbilityRuntime::GetStageModeContext(env, argv[0]);
            if (context == nullptr) {
                HiLog::Error(LABEL, "Failed to get native context instance");
                return nullptr;
            }
            HiLog::Info(LABEL, "Stage Model: context = %{public}p strUri = %{public}s", context.get(), strUri.c_str());
            dataAbilityHelper = DataAbilityHelper::Creator(context, std::make_shared<Uri>(strUri));
        } else {
            auto ability = OHOS::AbilityRuntime::GetCurrentAbility(env);
            if (ability == nullptr) {
                HiLog::Error(LABEL, "Failed to get native context instance");
                return nullptr;
            }
            HiLog::Info(LABEL, "FA Model: ability = %{public}p strUri = %{public}s", ability, strUri.c_str());
            dataAbilityHelper = DataAbilityHelper::Creator(ability->GetContext(), std::make_shared<Uri>(strUri));
        }
    }
    return dataAbilityHelper;
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
                obj->sAbilityHelper_ = GetDataAbilityHelper(env, info);
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
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    HiLog::Debug(LABEL, "GetMediaLibraryNewInstance IN");
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    status = napi_get_reference_value(env, sConstructor_, &ctor);
    if (status == napi_ok) {
        g_isNewApi = true;
        status = napi_new_instance(env, ctor, argc, argv, &result);
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
static void DealWithCommonParam(napi_env env, napi_value arg,
    const MediaLibraryAsyncContext &context, bool &err, bool &present)
{
    MediaLibraryAsyncContext *asyncContext = const_cast<MediaLibraryAsyncContext *>(&context);
    char buffer[PATH_MAX];
    size_t res = 0;
    napi_value property = nullptr;
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

    napi_has_named_property(env, arg, "uri", &present);
    if (present) {
        if (napi_get_named_property(env, arg, "uri", &property) != napi_ok) {
            HiLog::Error(LABEL, "Could not get the uri property!");
            err = true;
            return;
        }
        if (napi_get_value_string_utf8(env, property, buffer, PATH_MAX, &res) != napi_ok) {
            HiLog::Error(LABEL, "Could not get the string argument!");
            err = true;
            return;
        }
        asyncContext->uri = buffer;
        CHECK_IF_EQUAL(memset_s(buffer, PATH_MAX, 0, sizeof(buffer)) == 0, "Memset for buffer failed");
        present = false;
    }

    napi_has_named_property(env, arg, "networkId", &present);
    if (present) {
        if (napi_get_named_property(env, arg, "networkId", &property) != napi_ok
            || napi_get_value_string_utf8(env, property, buffer, PATH_MAX, &res) != napi_ok) {
            HiLog::Error(LABEL, "Could not get the networkId string argument!");
            err = true;
            return;
        } else {
            asyncContext->networkId = buffer;
            CHECK_IF_EQUAL(memset_s(buffer, PATH_MAX, 0, sizeof(buffer)) == 0, "Memset for buffer failed");
        }
        present = false;
    }
}
static void GetFetchOptionsParam(napi_env env, napi_value arg, const MediaLibraryAsyncContext &context, bool &err)
{
    MediaLibraryAsyncContext *asyncContext = const_cast<MediaLibraryAsyncContext *>(&context);
    char buffer[PATH_MAX];
    uint32_t len = 0;
    size_t res = 0;
    napi_value property = nullptr, stringItem = nullptr;
    bool present = false;
    DealWithCommonParam(env, arg, context, err, present);
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
            string path = ROOT_MEDIA_DIR;
            if (!context->selection.empty()) {
                path = context->selection;
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
                napi_get_value_uint32(env, argv[i], &asyncContext->dirType);
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
    if (!context->uri.empty()) {
        HiLog::Info(LABEL, "context->uri is = %{private}s", context->uri.c_str());
        context->networkId = MediaLibraryDataAbilityUtils::GetNetworkIdFromUri(context->uri);
        string fileId = MediaLibraryDataAbilityUtils::GetIdFromUri(context->uri);
        if (!fileId.empty()) {
            string idPrefix = MEDIA_DATA_DB_ID + " = ? ";
            MediaLibraryNapiUtils::UpdateFetchOptionSelection(context->selection, idPrefix);
            context->selectionArgs.insert(context->selectionArgs.begin(), fileId);
        }
    }
    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> ? ";
    MediaLibraryNapiUtils::UpdateFetchOptionSelection(context->selection, prefix);
    context->selectionArgs.insert(context->selectionArgs.begin(), to_string(MEDIA_TYPE_ALBUM));

    string trashPrefix = MEDIA_DATA_DB_DATE_TRASHED + " = ? ";
    MediaLibraryNapiUtils::UpdateFetchOptionSelection(context->selection, trashPrefix);
    context->selectionArgs.insert(context->selectionArgs.begin(), "0");

    predicates.SetWhereClause(context->selection);
    predicates.SetWhereArgs(context->selectionArgs);
    predicates.SetOrder(context->order);
    
    string queryUri = MEDIALIBRARY_DATA_URI;
    if (!context->networkId.empty()) {
        queryUri = MEDIALIBRARY_DATA_ABILITY_PREFIX + context->networkId + MEDIALIBRARY_DATA_URI_IDENTIFIER;
    }
    HiLog::Debug(LABEL, "queryUri is = %{public}s", queryUri.c_str());
    Uri uri(queryUri);
    shared_ptr<AbsSharedResultSet> resultSet;

    if (context->objectInfo->sAbilityHelper_ != nullptr) {
        resultSet = context->objectInfo->sAbilityHelper_->Query(uri, columns, predicates);
        if (resultSet != nullptr) {
            // Create FetchResult object using the contents of resultSet
            context->fetchFileResult = make_unique<FetchResult>(move(resultSet));
            context->fetchFileResult->networkId_ = context->networkId;
            return;
        } else {
            HiLog::Error(LABEL, "Query for get fileAssets failed");
        }
    }
    context->error = ERR_INVALID_OUTPUT;
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
            fileResult = FetchFileResultNapi::CreateFetchFileResult(env, *(context->fetchFileResult),
                                                                    context->objectInfo->sAbilityHelper_);
            if (context->fetchFileResult->GetCount() < 0) {
                MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_MEM_ALLOCATION,
                                                             "find no data by options");
            } else if (fileResult == nullptr) {
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
static string getNetworkId(const string& selfId)
{
    return "";
}

static string GetFileMediaTypeUri(MediaType mediaType, const string& networkId)
{
    string uri = MEDIALIBRARY_DATA_ABILITY_PREFIX + networkId + MEDIALIBRARY_DATA_URI_IDENTIFIER;
    switch (mediaType) {
        case MEDIA_TYPE_AUDIO:
            return uri + MEDIALIBRARY_TYPE_AUDIO_URI;
            break;
        case MEDIA_TYPE_VIDEO:
            return uri + MEDIALIBRARY_TYPE_VIDEO_URI;
            break;
        case MEDIA_TYPE_IMAGE:
            return uri + MEDIALIBRARY_TYPE_IMAGE_URI;
            break;
        case MEDIA_TYPE_ALBUM:
            return uri + MEDIALIBRARY_TYPE_ALBUM_URI;
            break;
        case MEDIA_TYPE_SMARTALBUM:
            return uri + MEDIALIBRARY_TYPE_SMART_URI;
            break;
        case MEDIA_TYPE_FILE:
        default:
            return uri + MEDIALIBRARY_TYPE_FILE_URI;
            break;
    }
}

using ValVariant = variant<int, int64_t, string>;
ValVariant GetValFromColumn(string columnName, shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet,
    ResultSetDataType type)
{
    HiLog::Error(LABEL, "columnName = %{public}s", columnName.c_str());
    int index;
    ValVariant cellValue;
    int integerVal;
    string stringVal;
    int64_t longVaL;

    resultSet->GetColumnIndex(columnName, index);
    switch (type) {
        case TYPE_STRING:
            resultSet->GetString(index, stringVal);
            cellValue = stringVal;
            break;
        case TYPE_INT32:
            resultSet->GetInt(index, integerVal);
            cellValue = integerVal;
            break;
        case TYPE_INT64:
            resultSet->GetLong(index, longVaL);
            cellValue = longVaL;
            break;
        default:
            HiLog::Error(LABEL, "No type");
            cellValue = "Notype";
            break;
    }
    return cellValue;
}

static void SetAlbumCoverUri(MediaLibraryAsyncContext *context, unique_ptr<AlbumAsset> &album)
{
    NativeRdb::DataAbilityPredicates predicates;
    predicates.EqualTo(MEDIA_DATA_DB_BUCKET_ID, std::to_string(album->GetAlbumId()));
    predicates.OrderByDesc(MEDIA_DATA_DB_DATE_ADDED);
    predicates.Limit(1);
    vector<string> columns;
    string queryUri = MEDIALIBRARY_DATA_URI;
    if (!context->networkId.empty()) {
        queryUri = MEDIALIBRARY_DATA_ABILITY_PREFIX + context->networkId + MEDIALIBRARY_DATA_URI_IDENTIFIER;
        HiLog::Debug(LABEL, "querycoverUri is = %{public}s", queryUri.c_str());
    }
    Uri uri(queryUri);
    shared_ptr<NativeRdb::AbsSharedResultSet> resultSet = context->objectInfo->sAbilityHelper_->Query(
        uri, columns, predicates);
    unique_ptr<FetchResult> fetchFileResult = make_unique<FetchResult>(move(resultSet));
    fetchFileResult->networkId_ = context->networkId;
    unique_ptr<FileAsset> fileAsset = fetchFileResult->GetFirstObject();
    string coverUri = fileAsset->GetUri();
    album->SetCoverUri(coverUri);
    HiLog::Debug(LABEL, "coverUri is = %{public}s", album->GetCoverUri().c_str());
}

void SetAlbumData(AlbumAsset* albumData, shared_ptr<NativeRdb::AbsSharedResultSet> resultSet,
    string networkId)
{
    // Get album id index and value
    albumData->SetAlbumId(get<int32_t>(GetValFromColumn(MEDIA_DATA_DB_BUCKET_ID, resultSet, TYPE_INT32)));

    // Get album title index and value
    albumData->SetAlbumName(get<string>(GetValFromColumn(MEDIA_DATA_DB_TITLE, resultSet, TYPE_STRING)));

    // Get album asset count index and value
    albumData->SetCount(get<int32_t>(GetValFromColumn(MEDIA_DATA_DB_COUNT, resultSet, TYPE_INT32)));
    albumData->SetAlbumUri(GetFileMediaTypeUri(MEDIA_TYPE_ALBUM, networkId) +
        "/" + to_string(albumData->GetAlbumId()));
    // Get album relativePath index and value
    albumData->SetAlbumRelativePath(get<string>(GetValFromColumn(MEDIA_DATA_DB_RELATIVE_PATH,
                                                                 resultSet, TYPE_STRING)));
    albumData->SetAlbumDateModified(get<int64_t>(GetValFromColumn(MEDIA_DATA_DB_DATE_MODIFIED,
                                                                  resultSet, TYPE_INT64)));
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
    string queryUri = MEDIALIBRARY_DATA_URI + "/" + MEDIA_ALBUMOPRN_QUERYALBUM;
    if (!context->networkId.empty()) {
        queryUri = MEDIALIBRARY_DATA_ABILITY_PREFIX + context->networkId +
            MEDIALIBRARY_DATA_URI_IDENTIFIER + "/" + MEDIA_ALBUMOPRN_QUERYALBUM;
        HiLog::Debug(LABEL, "queryAlbumUri is = %{public}s", queryUri.c_str());
    }
    Uri uri(queryUri);
    shared_ptr<NativeRdb::AbsSharedResultSet> resultSet = context->objectInfo->sAbilityHelper_->Query(
        uri, columns, predicates);

    if (resultSet == nullptr) {
        HiLog::Error(LABEL, "GetResultData resultSet is nullptr");
        return;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        unique_ptr<AlbumAsset> albumData = make_unique<AlbumAsset>();
        if (albumData != nullptr) {
            SetAlbumData(albumData.get(), resultSet, context->networkId);
            SetAlbumCoverUri(context, albumData);
        }
        context->albumNativeArray.push_back(move(albumData));
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
            napi_value albumNoArray = nullptr;
            napi_create_array(env, &albumNoArray);
            jsContext->status = true;
            napi_get_undefined(env, &jsContext->error);
            jsContext->data = albumNoArray;
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

static void getFileAssetById(int32_t id, const string& networkId, MediaLibraryAsyncContext *context)
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
        context->fetchFileResult->networkId_ = networkId;
        HiLog::Debug(LABEL, "getFileAssetById context->fetchFileResult");
        if (context->fetchFileResult != nullptr && context->fetchFileResult->GetCount() >= 1) {
            HiLog::Debug(LABEL, "getFileAssetById fetchFileResult->GetCount() >= 1");
            context->fileAsset = context->fetchFileResult->GetFirstObject();

            Media::MediaType mediaType = context->fileAsset->GetMediaType();
            string notifyUri = MediaLibraryNapiUtils::GetMediaTypeUri(mediaType);
            Uri modifyNotify(notifyUri);
            context->objectInfo->sAbilityHelper_->NotifyChange(modifyNotify);
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
        if (context->fileAsset == nullptr) {
            MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
                "Obtain file asset failed");
            napi_get_undefined(env, &jsContext->data);
        } else {
            jsFileAsset = FileAssetNapi::CreateFileAsset(env, *(context->fileAsset),
                                                         context->objectInfo->sAbilityHelper_);
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
        HiLog::Debug(LABEL, "JSCreateAssetCompleteCallback context->error %{public}d", context->error);
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

static bool CheckTitlePrams(MediaLibraryAsyncContext *context)
{
    ValueObject valueObject;
    string title = "";
    if (context->valuesBucket.GetObject(MEDIA_DATA_DB_NAME, valueObject)) {
        valueObject.GetString(title);
    }
    if (title.empty()) {
        HiLog::Debug(LABEL, "CheckTitlePrams title is empty");
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
    if (stat((ROOT_MEDIA_DIR + dirName).c_str(), &statInfo) == SUCCESS) {
        if (statInfo.st_mode & S_IFDIR) {
            return true;
        }
    }

    return false;
}

static bool CheckTypeOfType(const std::string& firstDirName, int32_t fileMediaType)
{
    HiLog::Debug(LABEL, "CheckTypeOfType IN");
    // "CDSA/"
    if (!strcmp(firstDirName.c_str(), directoryEnumValues[0].c_str())) {
        if (fileMediaType == MEDIA_TYPE_IMAGE || fileMediaType == MEDIA_TYPE_VIDEO) {
            return true;
        } else {
            return false;
        }
    }
    // "Movies/"
    if (!strcmp(firstDirName.c_str(), directoryEnumValues[1].c_str())) {
        if (fileMediaType == MEDIA_TYPE_VIDEO) {
            return true;
        } else {
            return false;
        }
    }
    if (!strcmp(firstDirName.c_str(), directoryEnumValues[NUM_2].c_str())) {
        if (fileMediaType == MEDIA_TYPE_IMAGE || fileMediaType == MEDIA_TYPE_VIDEO) {
            HiLog::Debug(LABEL, "CheckTypeOfType RETURN TRUE");
            return true;
        } else {
            HiLog::Debug(LABEL, "CheckTypeOfType RETURN FALSE");
                return false;
        }
    }
    if (!strcmp(firstDirName.c_str(), directoryEnumValues[NUM_3].c_str())) {
        if (fileMediaType == MEDIA_TYPE_AUDIO) {
            return true;
        } else {
            return false;
        }
    }
    HiLog::Debug(LABEL, "CheckTypeOfType END");
    return true;
}
static bool CheckRelativePathPrams(MediaLibraryAsyncContext *context)
{
    ValueObject valueObject;
    string relativePath = "";
    if (context->valuesBucket.GetObject(MEDIA_DATA_DB_RELATIVE_PATH, valueObject)) {
        valueObject.GetString(relativePath);
    }
    int32_t fileMediaType = 0;
    context->valuesBucket.GetObject(MEDIA_DATA_DB_MEDIA_TYPE, valueObject);
    valueObject.GetInt(fileMediaType);
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
        HiLog::Debug(LABEL, "firstDirName = %{public}s", firstDirName.c_str());
        for (unsigned int i = 0; i < directoryEnumValues.size(); i++) {
            HiLog::Debug(LABEL, "directoryEnumValues%{public}d = %{public}s", i, directoryEnumValues[i].c_str());
            if (!strcmp(firstDirName.c_str(), directoryEnumValues[i].c_str())) {
                return CheckTypeOfType(firstDirName, fileMediaType);
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
    HiLog::Debug(LABEL, "GetJSArgsForCreateAsset IN %{public}zu", argc);
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
            HiLog::Debug(LABEL, "type mismatch");
            return result;
    }
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
                if (!CheckTitlePrams(context)) {
                    context->error = ERR_DISPLAY_NAME_INVALID;
                    return;
                }
                if (!CheckRelativePathPrams(context)) {
                    context->error = ERR_RELATIVE_PATH_NOT_EXIST_OR_INVALID;
                    return;
                }
                if (context->objectInfo->sAbilityHelper_ != nullptr) {
                    Uri createFileUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_CREATEASSET);
                    int index = context->objectInfo->sAbilityHelper_->Insert(createFileUri, context->valuesBucket);
                    if (index < 0) {
                        context->error = index;
                    } else {
                        getFileAssetById(index, "", context);
                    }
                } else {
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
            env, nullptr, resource, [](napi_env env, void* data) {},
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
            env, nullptr, resource, [](napi_env env, void* data) {},
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
        if (retVal == DATA_ABILITY_SUCCESS) {
            retVal = context->objectInfo->sAbilityHelper_->Insert(closeAssetUri, context->valuesBucket);
            if (retVal == DATA_ABILITY_SUCCESS) {
                napi_create_int32(env, DATA_ABILITY_SUCCESS, &jsContext->data);
                napi_get_undefined(env, &jsContext->error);
                jsContext->status = true;
            }
        }
        if (retVal != DATA_ABILITY_SUCCESS) {
            HiLog::Error(LABEL, "negative ret %{public}d", retVal);
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
            env, nullptr, resource, [](napi_env env, void* data) {},
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
            env, nullptr, resource, [](napi_env env, void* data) {},
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
            env, nullptr, resource, [](napi_env env, void* data) {},
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
            env, nullptr, resource, [](napi_env env, void* data) {},
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
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr) {
        return;
    }

    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        return;
    }

    UvChangeMsg *msg = new (std::nothrow) UvChangeMsg(env_, cbRef);
    if (msg == nullptr) {
        delete work;
        return;
    }
    work->data = reinterpret_cast<void *>(msg);

    int ret = uv_queue_work(loop, work, [](uv_work_t *w) {}, [](uv_work_t *w, int s) {
            // js thread
            if (w == nullptr) {
                return;
            }

            UvChangeMsg *msg = reinterpret_cast<UvChangeMsg *>(w->data);
            do {
                if (msg == nullptr) {
                    HiLog::Error(LABEL, "UvChangeMsg is null");
                    break;
                }
                napi_env env = msg->env_;
                napi_value result[ARGS_TWO] = { nullptr };
                napi_get_undefined(env, &result[PARAM0]);
                napi_get_undefined(env, &result[PARAM1]);
                napi_value jsCallback = nullptr;
                napi_status status = napi_get_reference_value(env, msg->ref_, &jsCallback);
                if (status != napi_ok) {
                    HiLog::Error(LABEL, "Create reference fail");
                    break;
                }
                napi_value retVal = nullptr;
                napi_call_function(env, nullptr, jsCallback, ARGS_TWO, result, &retVal);
                if (status != napi_ok) {
                    HiLog::Error(LABEL, "CallJs napi_call_function fail");
                    break;
                }
            } while (0);
            delete msg;
            delete w;
        }
    );
    if (ret != 0) {
        HiLog::Error(LABEL, "Failed to execute libuv work queue");
        delete msg;
        delete work;
    }
}

int32_t MediaLibraryNapi::GetListenerType(const std::string &str) const
{
    auto iter = ListenerTypeMaps.find(str);
    if (iter == ListenerTypeMaps.end()) {
        HiLog::Error(LABEL, "Invalid Listener Type %{public}s", str.c_str());
        return INVALID_LISTENER;
    }

    return iter->second;
}

void MediaLibraryNapi::RegisterChange(napi_env env, const std::string &type, ChangeListenerNapi &listObj)
{
    HiLog::Info(LABEL, "Register change type = %{public}s", type.c_str());

    int32_t typeEnum = GetListenerType(type);
    switch (typeEnum) {
        case AUDIO_LISTENER:
            listObj.audioDataObserver_ = new(nothrow) MediaObserver(listObj, MEDIA_TYPE_AUDIO);
            sAbilityHelper_->RegisterObserver(Uri(MEDIALIBRARY_AUDIO_URI), listObj.audioDataObserver_);
            break;
        case VIDEO_LISTENER:
            listObj.videoDataObserver_ = new(nothrow) MediaObserver(listObj, MEDIA_TYPE_VIDEO);
            sAbilityHelper_->RegisterObserver(Uri(MEDIALIBRARY_VIDEO_URI), listObj.videoDataObserver_);
            break;
        case IMAGE_LISTENER:
            listObj.imageDataObserver_ = new(nothrow) MediaObserver(listObj, MEDIA_TYPE_IMAGE);
            sAbilityHelper_->RegisterObserver(Uri(MEDIALIBRARY_IMAGE_URI), listObj.imageDataObserver_);
            break;
        case FILE_LISTENER:
            listObj.fileDataObserver_ = new(nothrow) MediaObserver(listObj, MEDIA_TYPE_FILE);
            sAbilityHelper_->RegisterObserver(Uri(MEDIALIBRARY_FILE_URI), listObj.fileDataObserver_);
            break;
        case SMARTALBUM_LISTENER:
            listObj.smartAlbumDataObserver_ = new(nothrow) MediaObserver(listObj, MEDIA_TYPE_SMARTALBUM);
            sAbilityHelper_->RegisterObserver(Uri(MEDIALIBRARY_SMARTALBUM_CHANGE_URI),
                                              listObj.smartAlbumDataObserver_);
            break;
        case DEVICE_LISTENER:
            listObj.deviceDataObserver_ = new(nothrow) MediaObserver(listObj, MEDIA_TYPE_DEVICE);
            sAbilityHelper_->RegisterObserver(Uri(MEDIALIBRARY_DEVICE_URI), listObj.deviceDataObserver_);
            break;
        case REMOTEFILE_LISTENER:
            listObj.remoteFileDataObserver_ = new(nothrow) MediaObserver(listObj, MEDIA_TYPE_REMOTEFILE);
            sAbilityHelper_->RegisterObserver(Uri(MEDIALIBRARY_REMOTEFILE_URI), listObj.remoteFileDataObserver_);
            break;
        case ALBUM_LISTENER:
            listObj.albumDataObserver_ = new(nothrow) MediaObserver(listObj, MEDIA_TYPE_ALBUM);
            sAbilityHelper_->RegisterObserver(Uri(MEDIALIBRARY_ALBUM_URI), listObj.albumDataObserver_);
            break;
        default:
            HiLog::Error(LABEL, "Invalid Media Type!");
    }
}

napi_value MediaLibraryNapi::JSOnCallback(napi_env env, napi_callback_info info)
{
    napi_value undefinedResult = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {nullptr};
    napi_value thisVar = nullptr;
    size_t res = 0;
    char buffer[SIZE];
    string type;
    const int32_t refCount = 1;
    MediaLibraryNapi *obj = nullptr;
    napi_status status;

    napi_get_undefined(env, &undefinedResult);

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_TWO, "requires 2 parameters");

    if (thisVar == nullptr || argv[PARAM0] == nullptr || argv[PARAM1] == nullptr) {
        HiLog::Error(LABEL, "Failed to retrieve details about the callback");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if (status == napi_ok && obj != nullptr) {
        napi_valuetype valueType = napi_undefined;
        if (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_string ||
            napi_typeof(env, argv[PARAM1], &valueType) != napi_ok || valueType != napi_function) {
            return undefinedResult;
        }

        if (napi_get_value_string_utf8(env, argv[PARAM0], buffer, SIZE, &res) != napi_ok) {
            HiLog::Error(LABEL, "Failed to get value string utf8 for type");
            return undefinedResult;
        }
        type = string(buffer);

        napi_create_reference(env, argv[PARAM1], refCount, &g_listObj->cbOnRef_);

        obj->RegisterChange(env, type, *g_listObj);
    }

    return undefinedResult;
}

void MediaLibraryNapi::UnregisterChange(napi_env env, const string &type, ChangeListenerNapi &listObj)
{
    HiLog::Info(LABEL, "Unregister change type = %{public}s", type.c_str());

    MediaType mediaType;
    int32_t typeEnum = GetListenerType(type);

    switch (typeEnum) {
        case AUDIO_LISTENER:
            CHECK_NULL_PTR_RETURN_VOID(listObj.audioDataObserver_, "Failed to obtain audio data observer");

            mediaType = MEDIA_TYPE_AUDIO;
            sAbilityHelper_->UnregisterObserver(Uri(MEDIALIBRARY_AUDIO_URI), listObj.audioDataObserver_);

            delete listObj.audioDataObserver_;
            listObj.audioDataObserver_ = nullptr;
            break;
        case VIDEO_LISTENER:
            CHECK_NULL_PTR_RETURN_VOID(listObj.videoDataObserver_, "Failed to obtain video data observer");

            mediaType = MEDIA_TYPE_VIDEO;
            sAbilityHelper_->UnregisterObserver(Uri(MEDIALIBRARY_VIDEO_URI), listObj.videoDataObserver_);

            delete listObj.videoDataObserver_;
            listObj.videoDataObserver_ = nullptr;
            break;
        case IMAGE_LISTENER:
            CHECK_NULL_PTR_RETURN_VOID(listObj.imageDataObserver_, "Failed to obtain image data observer");

            mediaType = MEDIA_TYPE_IMAGE;
            sAbilityHelper_->UnregisterObserver(Uri(MEDIALIBRARY_IMAGE_URI), listObj.imageDataObserver_);

            delete listObj.imageDataObserver_;
            listObj.imageDataObserver_ = nullptr;
            break;
        case FILE_LISTENER:
            CHECK_NULL_PTR_RETURN_VOID(listObj.fileDataObserver_, "Failed to obtain file data observer");

            mediaType = MEDIA_TYPE_FILE;
            sAbilityHelper_->UnregisterObserver(Uri(MEDIALIBRARY_FILE_URI), listObj.fileDataObserver_);

            delete listObj.fileDataObserver_;
            listObj.fileDataObserver_ = nullptr;
            break;
        case SMARTALBUM_LISTENER:
            CHECK_NULL_PTR_RETURN_VOID(listObj.smartAlbumDataObserver_, "Failed to obtain smart album data observer");

            mediaType = MEDIA_TYPE_SMARTALBUM;
            sAbilityHelper_->UnregisterObserver(Uri(MEDIALIBRARY_SMARTALBUM_CHANGE_URI),
                                                listObj.smartAlbumDataObserver_);

            delete listObj.smartAlbumDataObserver_;
            listObj.smartAlbumDataObserver_ = nullptr;
            break;
        case DEVICE_LISTENER:
            CHECK_NULL_PTR_RETURN_VOID(listObj.deviceDataObserver_, "Failed to obtain device data observer");

            mediaType = MEDIA_TYPE_DEVICE;
            sAbilityHelper_->UnregisterObserver(Uri(MEDIALIBRARY_DEVICE_URI), listObj.deviceDataObserver_);

            delete listObj.deviceDataObserver_;
            listObj.deviceDataObserver_ = nullptr;
            break;
        case REMOTEFILE_LISTENER:
            CHECK_NULL_PTR_RETURN_VOID(listObj.remoteFileDataObserver_, "Failed to obtain remote file data observer");

            mediaType = MEDIA_TYPE_REMOTEFILE;
            sAbilityHelper_->UnregisterObserver(Uri(MEDIALIBRARY_REMOTEFILE_URI), listObj.remoteFileDataObserver_);

            delete listObj.remoteFileDataObserver_;
            listObj.remoteFileDataObserver_ = nullptr;
            break;
        case ALBUM_LISTENER:
            CHECK_NULL_PTR_RETURN_VOID(listObj.albumDataObserver_, "Failed to obtain album data observer");

            mediaType = MEDIA_TYPE_ALBUM;
            sAbilityHelper_->UnregisterObserver(Uri(MEDIALIBRARY_REMOTEFILE_URI), listObj.albumDataObserver_);

            delete listObj.albumDataObserver_;
            listObj.albumDataObserver_ = nullptr;
            break;
        default:
            HiLog::Error(LABEL, "Invalid Media Type");
            return;
    }

    if (listObj.cbOffRef_ != nullptr) {
        MediaChangeListener listener;
        listener.mediaType = mediaType;
        listObj.OnChange(listener, listObj.cbOffRef_);
    }
}

napi_value MediaLibraryNapi::JSOffCallback(napi_env env, napi_callback_info info)
{
    napi_value undefinedResult = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {nullptr};
    napi_value thisVar = nullptr;
    size_t res = 0;
    char buffer[SIZE];
    const int32_t refCount = 1;
    string type;
    MediaLibraryNapi *obj = nullptr;
    napi_status status;

    napi_get_undefined(env, &undefinedResult);

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, ARGS_ONE <= argc && argc<= ARGS_TWO, "requires one or two parameters");

    if (thisVar == nullptr || argv[PARAM0] == nullptr) {
        HiLog::Error(LABEL, "Failed to retrieve details about the callback");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if (status == napi_ok && obj != nullptr) {
        napi_valuetype valueType = napi_undefined;
        if (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_string) {
            return undefinedResult;
        }

        if (napi_get_value_string_utf8(env, argv[PARAM0], buffer, SIZE, &res) != napi_ok) {
            HiLog::Error(LABEL, "Failed to get value string utf8 for type");
            return undefinedResult;
        }
        type = string(buffer);

        if (argc == ARGS_TWO) {
            if (napi_typeof(env, argv[PARAM1], &valueType) != napi_ok || valueType != napi_function ||
                g_listObj == nullptr) {
                return undefinedResult;
            }

            napi_create_reference(env, argv[PARAM1], refCount, &g_listObj->cbOffRef_);
        }

        obj->UnregisterChange(env, type, *g_listObj);
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
        napi_create_int32(env, SUCCESS, &jsContext->data);
        jsContext->status = true;
        napi_get_undefined(env, &jsContext->error);
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
    HiLog::Error(LABEL, "NAPI_ASSERT begin %{public}zu", argc);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_ZERO), "requires 1 parameters maximum");
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
        return;
    }
    if (context->privateAlbumType == TYPE_TRASH) {
        GetTrashSmartAlbumExecute(context);
        return;
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
                albumData->SetAlbumId(get<int32_t>(GetValFromColumn(SMARTALBUM_DB_ID, resultSet, TYPE_INT32)));
                HiLog::Error(LABEL, "AllSmartAlbum SMARTALBUM_DB_ID = %{public}d", albumData->GetAlbumId());
                albumData->SetAlbumName(get<string>(GetValFromColumn(SMARTALBUM_DB_NAME, resultSet, TYPE_STRING)));
                albumData->SetAlbumCapacity(get<int32_t>(GetValFromColumn(SMARTABLUMASSETS_ALBUMCAPACITY,
                                                                          resultSet, TYPE_INT32)));
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
                albumData->SetAlbumId(get<int32_t>(GetValFromColumn(SMARTALBUM_DB_ID, resultSet, TYPE_INT32)));
                albumData->SetAlbumName(get<string>(GetValFromColumn(SMARTALBUM_DB_NAME, resultSet, TYPE_STRING)));
                albumData->SetAlbumCapacity(get<int32_t>(GetValFromColumn(SMARTABLUMASSETS_ALBUMCAPACITY,
                                                                          resultSet, TYPE_INT32)));
                albumData->SetAlbumUri(GetFileMediaTypeUri(MEDIA_TYPE_SMARTALBUM,
                    getNetworkId(get<string>(GetValFromColumn(SMARTALBUM_DB_SELF_ID, resultSet, TYPE_STRING))))
                    + "/" + to_string(albumData->GetAlbumId()));
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
            napi_value albumNapiObj = SmartAlbumNapi::CreateSmartAlbumNapi(env, *(context->smartAlbumData),
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

static napi_status SetValueUtf8String(const napi_env& env, const char* fieldStr, const char* str, napi_value& result)
{
    napi_value value;
    napi_status status = napi_create_string_utf8(env, str, NAPI_AUTO_LENGTH, &value);
    if (status != napi_ok) {
        HiLog::Error(LABEL, "Set value create utf8 string error! field: %{public}s", fieldStr);
        return status;
    }
    status = napi_set_named_property(env, result, fieldStr, value);
    if (status != napi_ok) {
        HiLog::Error(LABEL, "Set utf8 string named property error! field: %{public}s", fieldStr);
    }
    return status;
}

static napi_status SetValueInt32(const napi_env& env, const char* fieldStr, const int intValue, napi_value& result)
{
    napi_value value;
    napi_status status = napi_create_int32(env, intValue, &value);
    if (status != napi_ok) {
        HiLog::Error(LABEL, "Set value create int32 error! field: %{public}s", fieldStr);
        return status;
    }
    status = napi_set_named_property(env, result, fieldStr, value);
    if (status != napi_ok) {
        HiLog::Error(LABEL, "Set int32 named property error! field: %{public}s", fieldStr);
    }
    return status;
}

static napi_status SetValueBool(const napi_env& env, const char* fieldStr, const bool boolvalue, napi_value& result)
{
    napi_value value = nullptr;
    napi_status status = napi_get_boolean(env, boolvalue, &value);
    if (status != napi_ok) {
        HiLog::Error(LABEL, "Set value create boolean error! field: %{public}s", fieldStr);
        return status;
    }
    status = napi_set_named_property(env, result, fieldStr, value);
    if (status != napi_ok) {
        HiLog::Error(LABEL, "Set boolean named property error! field: %{public}s", fieldStr);
    }
    return status;
}

static void PeerInfoToJsArray(const napi_env &env, const std::vector<unique_ptr<PeerInfo>> &vecPeerInfo,
    const int32_t idx, napi_value &arrayResult)
{
    if (idx >= (int32_t) vecPeerInfo.size()) {
        return;
    }
    auto info = vecPeerInfo[idx].get();
    if (info == nullptr) {
        return;
    }
    napi_value result = nullptr;
    napi_create_object(env, &result);
    SetValueUtf8String(env, "deviceName", info->deviceName.c_str(), result);
    SetValueUtf8String(env, "networkId", info->networkId.c_str(), result);
    SetValueInt32(env, "deviceTypeId", (int) info->deviceTypeId, result);
    SetValueBool(env, "isOnline", info->isOnline, result);

    napi_status status = napi_set_element(env, arrayResult, idx, result);
    if (status != napi_ok) {
        HiLog::Error(LABEL, "PeerInfo To JsArray set element error: %d", status);
    }
}

void JSGetActivePeersCompleteCallback(napi_env env, napi_status status,
    MediaLibraryAsyncContext *context)
{
    napi_value jsPeerInfoArray = nullptr;

    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    napi_get_undefined(env, &jsContext->data);

    vector<std::string> columns;
    NativeRdb::DataAbilityPredicates predicates;
    std::string strQueryCondition = DEVICE_DB_DATE_MODIFIED + " = 0";
    predicates.SetWhereClause(strQueryCondition);
    predicates.SetWhereArgs(context->selectionArgs);

    Uri uri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_DEVICE_QUERYACTIVEDEVICE);
    shared_ptr<NativeRdb::AbsSharedResultSet> resultSet = context->objectInfo->sAbilityHelper_->Query(
        uri, columns, predicates);

    if (resultSet == nullptr) {
        HiLog::Error(LABEL, "JSGetActivePeers resultSet is null");
        delete context;
        return;
    }

    vector<unique_ptr<PeerInfo>> peerInfoArray;
    HiLog::Error(LABEL, "JSGetActivePeers resultSet != nullptr");
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        unique_ptr<PeerInfo> peerInfo = make_unique<PeerInfo>();
        if (peerInfo != nullptr) {
            peerInfo->deviceName = get<string>(GetValFromColumn(DEVICE_DB_NAME, resultSet, TYPE_STRING));
            peerInfo->networkId = get<string>(GetValFromColumn(DEVICE_DB_NETWORK_ID, resultSet, TYPE_STRING));
            peerInfo->deviceTypeId = (DistributedHardware::DmDeviceType)
                                     (get<int32_t>(GetValFromColumn(DEVICE_DB_TYPE, resultSet, TYPE_INT32)));
            peerInfo->isOnline = true;
            peerInfoArray.push_back(move(peerInfo));
        }
    }

    if (!peerInfoArray.empty() && (napi_create_array(env, &jsPeerInfoArray) == napi_ok)) {
        for (size_t i = 0; i < peerInfoArray.size(); ++i) {
            PeerInfoToJsArray(env, peerInfoArray, i, jsPeerInfoArray);
        }

        jsContext->data = jsPeerInfoArray;
        napi_get_undefined(env, &jsContext->error);
        jsContext->status = true;
    } else {
        HiLog::Debug(LABEL, "No peer info found!");
        napi_get_undefined(env, &jsContext->data);
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
            "Failed to obtain peer info array from DB");
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

void JSGetAllPeersCompleteCallback(napi_env env, napi_status status,
    MediaLibraryAsyncContext *context)
{
    napi_value jsPeerInfoArray = nullptr;

    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    napi_get_undefined(env, &jsContext->data);

    vector<string> columns;
    NativeRdb::DataAbilityPredicates predicates;
    predicates.SetWhereClause(context->selection);
    predicates.SetWhereArgs(context->selectionArgs);

    Uri uri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_DEVICE_QUERYALLDEVICE);
    shared_ptr<NativeRdb::AbsSharedResultSet> resultSet = context->objectInfo->sAbilityHelper_->Query(
        uri, columns, predicates);

    if (resultSet == nullptr) {
        HiLog::Error(LABEL, "JSGetAllPeers resultSet is null");
        delete context;
        return;
    }

    vector<unique_ptr<PeerInfo>> peerInfoArray;
    HiLog::Error(LABEL, "JSGetAllPeers resultSet != nullptr");
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        unique_ptr<PeerInfo> peerInfo = make_unique<PeerInfo>();
        if (peerInfo != nullptr) {
            peerInfo->deviceName = get<string>(GetValFromColumn(DEVICE_DB_NAME, resultSet, TYPE_STRING));
            peerInfo->networkId = get<string>(GetValFromColumn(DEVICE_DB_NETWORK_ID, resultSet, TYPE_STRING));
            peerInfo->deviceTypeId = (DistributedHardware::DmDeviceType)
                                     (get<int32_t>(GetValFromColumn(DEVICE_DB_TYPE, resultSet, TYPE_INT32)));
            peerInfo->isOnline = (get<int32_t>(GetValFromColumn(DEVICE_DB_DATE_MODIFIED, resultSet, TYPE_INT32)) == 0);
            peerInfoArray.push_back(move(peerInfo));
        }
    }

    if (!peerInfoArray.empty() && (napi_create_array(env, &jsPeerInfoArray) == napi_ok)) {
        for (size_t i = 0; i < peerInfoArray.size(); ++i) {
            PeerInfoToJsArray(env, peerInfoArray, i, jsPeerInfoArray);
        }

        jsContext->data = jsPeerInfoArray;
        napi_get_undefined(env, &jsContext->error);
        jsContext->status = true;
    } else {
        HiLog::Debug(LABEL, "No peer info found!");
        napi_get_undefined(env, &jsContext->data);
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
            "Failed to obtain peer info array from DB");
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value MediaLibraryNapi::JSGetActivePeers(napi_env env, napi_callback_info info)
{
    HiLog::Error(LABEL, "JSGetActivePeers in");
    napi_status status;
    napi_value result = nullptr;
    const int32_t refCount = 1;
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
        if (argc == ARGS_ONE) {
            GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef);
        }

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSGetActivePeers");
        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {},
            reinterpret_cast<CompleteCallback>(JSGetActivePeersCompleteCallback),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }
    HiLog::Error(LABEL, "JSGetActivePeers end");
    return result;
}

napi_value MediaLibraryNapi::JSGetAllPeers(napi_env env, napi_callback_info info)
{
    HiLog::Error(LABEL, "JSGetAllPeers in");
    napi_status status;
    napi_value result = nullptr;
    const int32_t refCount = 1;
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
        if (argc == ARGS_ONE) {
            GET_JS_ASYNC_CB_REF(env, argv[PARAM0], refCount, asyncContext->callbackRef);
        }

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSGetAllPeers");
        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {},
            reinterpret_cast<CompleteCallback>(JSGetAllPeersCompleteCallback),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }
    HiLog::Error(LABEL, "JSGetAllPeers end");
    return result;
}
} // namespace Media
} // namespace OHOS
