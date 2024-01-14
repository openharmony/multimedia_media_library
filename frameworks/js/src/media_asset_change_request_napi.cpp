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

#define MLOG_TAG "MediaAssetChangeRequestNapi"

#include "media_asset_change_request_napi.h"

#include <fcntl.h>
#include <functional>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <unordered_map>
#include <unordered_set>

#include "ability_context.h"
#include "access_token.h"
#include "accesstoken_kit.h"
#include "delete_callback.h"
#include "directory_ex.h"
#include "file_uri.h"
#include "ipc_skeleton.h"
#include "js_native_api.h"
#include "js_native_api_types.h"
#include "media_asset_edit_data_napi.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_errno.h"
#include "medialibrary_napi_log.h"
#include "medialibrary_tracer.h"
#include "modal_ui_extension_config.h"
#ifdef ABILITY_CAMERA_SUPPORT
#include "output/deferred_photo_proxy_napi.h"
#endif
#include "permission_utils.h"
#include "ui_content.h"
#include "unique_fd.h"
#include "userfile_client.h"
#include "userfile_manager_types.h"
#include "want.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS::Media {
static const string MEDIA_ASSET_CHANGE_REQUEST_CLASS = "MediaAssetChangeRequest";
thread_local napi_ref MediaAssetChangeRequestNapi::constructor_ = nullptr;

constexpr int64_t CREATE_ASSET_REQUEST_PENDING = -4;

constexpr int32_t YES = 1;
constexpr int32_t NO = 0;

constexpr int32_t USER_COMMENT_MAX_LEN = 420;
constexpr int32_t MAX_DELETE_NUMBER = 300;

const std::string SUBTYPE = "subType";
const std::string PAH_SUBTYPE = "subtype";
const std::string CAMERA_SHOT_KEY = "cameraShotKey";
const std::map<std::string, std::string> PHOTO_CREATE_OPTIONS_PARAM = { { SUBTYPE, PhotoColumn::PHOTO_SUBTYPE },
    { CAMERA_SHOT_KEY, PhotoColumn::CAMERA_SHOT_KEY }, { PAH_SUBTYPE, PhotoColumn::PHOTO_SUBTYPE } };

const std::string TITLE = "title";
const std::map<std::string, std::string> CREATE_OPTIONS_PARAM = { { TITLE, PhotoColumn::MEDIA_TITLE } };

const std::string DEFAULT_TITLE_TIME_FORMAT = "%Y%m%d_%H%M%S";
const std::string DEFAULT_TITLE_IMG_PREFIX = "IMG_";
const std::string DEFAULT_TITLE_VIDEO_PREFIX = "VID_";

napi_value MediaAssetChangeRequestNapi::Init(napi_env env, napi_value exports)
{
    NapiClassInfo info = { .name = MEDIA_ASSET_CHANGE_REQUEST_CLASS,
        .ref = &constructor_,
        .constructor = Constructor,
        .props = {
            DECLARE_NAPI_STATIC_FUNCTION("createAssetRequest", JSCreateAssetRequest),
            DECLARE_NAPI_STATIC_FUNCTION("createImageAssetRequest", JSCreateImageAssetRequest),
            DECLARE_NAPI_STATIC_FUNCTION("createVideoAssetRequest", JSCreateVideoAssetRequest),
            DECLARE_NAPI_STATIC_FUNCTION("deleteAssets", JSDeleteAssets),
            DECLARE_NAPI_FUNCTION("getAsset", JSGetAsset),
            DECLARE_NAPI_FUNCTION("setEditData", JSSetEditData),
            DECLARE_NAPI_FUNCTION("setFavorite", JSSetFavorite),
            DECLARE_NAPI_FUNCTION("setHidden", JSSetHidden),
            DECLARE_NAPI_FUNCTION("setTitle", JSSetTitle),
            DECLARE_NAPI_FUNCTION("setUserComment", JSSetUserComment),
            DECLARE_NAPI_FUNCTION("getWriteCacheHandler", JSGetWriteCacheHandler),
            DECLARE_NAPI_FUNCTION("setLocation", JSSetLocation),
            DECLARE_NAPI_FUNCTION("addResource", JSAddResource),
        } };
    MediaLibraryNapiUtils::NapiDefineClass(env, exports, info);
    return exports;
}

napi_value MediaAssetChangeRequestNapi::Constructor(napi_env env, napi_callback_info info)
{
    napi_value newTarget = nullptr;
    CHECK_ARGS(env, napi_get_new_target(env, info, &newTarget), JS_INNER_FAIL);
    CHECK_COND_RET(newTarget != nullptr, nullptr, "Failed to check new.target");

    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = { 0 };
    napi_value thisVar = nullptr;
    napi_valuetype valueType;
    FileAssetNapi* fileAssetNapi;
    CHECK_ARGS(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr), JS_INNER_FAIL);
    CHECK_COND_WITH_MESSAGE(env, argc == ARGS_ONE, "Number of args is invalid");
    CHECK_ARGS(env, napi_typeof(env, argv[PARAM0], &valueType), JS_INNER_FAIL);
    CHECK_COND_WITH_MESSAGE(env, valueType == napi_object, "Invalid argument type");
    CHECK_ARGS(env, napi_unwrap(env, argv[PARAM0], reinterpret_cast<void**>(&fileAssetNapi)), JS_INNER_FAIL);
    CHECK_COND_WITH_MESSAGE(env, fileAssetNapi != nullptr, "Failed to get FileAssetNapi object");

    auto fileAssetPtr = fileAssetNapi->GetFileAssetInstance();
    CHECK_COND_WITH_MESSAGE(env, fileAssetPtr != nullptr, "fileAsset is null");
    CHECK_COND_WITH_MESSAGE(env,
        fileAssetPtr->GetResultNapiType() == ResultNapiType::TYPE_PHOTOACCESS_HELPER &&
            (fileAssetPtr->GetMediaType() == MEDIA_TYPE_IMAGE || fileAssetPtr->GetMediaType() == MEDIA_TYPE_VIDEO),
        "Unsupported type of fileAsset");

    unique_ptr<MediaAssetChangeRequestNapi> obj = make_unique<MediaAssetChangeRequestNapi>();
    CHECK_COND(env, obj != nullptr, JS_INNER_FAIL);
    obj->fileAsset_ = fileAssetPtr;
    CHECK_ARGS(env,
        napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()), MediaAssetChangeRequestNapi::Destructor, nullptr,
            nullptr),
        JS_INNER_FAIL);
    obj.release();
    return thisVar;
}

void MediaAssetChangeRequestNapi::Destructor(napi_env env, void* nativeObject, void* finalizeHint)
{
    auto* assetChangeRequest = reinterpret_cast<MediaAssetChangeRequestNapi*>(nativeObject);
    if (assetChangeRequest == nullptr) {
        return;
    }

    string cacheFileName = assetChangeRequest->cacheFileName_;
    if (!cacheFileName.empty()) {
        string uri = PhotoColumn::PHOTO_CACHE_URI_PREFIX + cacheFileName;
        MediaFileUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
        Uri deleteCacheUri(uri);
        DataShare::DataSharePredicates predicates;
        int32_t ret = UserFileClient::Delete(deleteCacheUri, predicates);
        if (ret < 0) {
            NAPI_WARN_LOG("Failed to delete cache: %{private}s", cacheFileName.c_str());
        }
    }

    delete assetChangeRequest;
    assetChangeRequest = nullptr;
}

shared_ptr<FileAsset> MediaAssetChangeRequestNapi::GetFileAssetInstance() const
{
    return fileAsset_;
}

#ifdef ABILITY_CAMERA_SUPPORT
sptr<CameraStandard::DeferredPhotoProxy> MediaAssetChangeRequestNapi::GetPhotoProxyObj()
{
    return photoProxy_;
}
#endif

void MediaAssetChangeRequestNapi::RecordChangeOperation(AssetChangeOperation changeOperation)
{
    if ((changeOperation == AssetChangeOperation::GET_WRITE_CACHE_HANDLER ||
            changeOperation == AssetChangeOperation::ADD_RESOURCE) &&
        Contains(AssetChangeOperation::CREATE_FROM_SCRATCH)) {
        assetChangeOperations_.insert(assetChangeOperations_.begin() + 1, changeOperation);
        return;
    }
    assetChangeOperations_.push_back(changeOperation);
}

bool MediaAssetChangeRequestNapi::Contains(AssetChangeOperation changeOperation) const
{
    return std::find(assetChangeOperations_.begin(), assetChangeOperations_.end(), changeOperation) !=
           assetChangeOperations_.end();
}

bool MediaAssetChangeRequestNapi::CheckChangeOperations(napi_env env)
{
    if (assetChangeOperations_.empty()) {
        NapiError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "None request to apply");
        return false;
    }

    bool isCreateFromScratch = Contains(AssetChangeOperation::CREATE_FROM_SCRATCH);
    bool isCreateFromUri = Contains(AssetChangeOperation::CREATE_FROM_URI);
    bool containsEdit = Contains(AssetChangeOperation::SET_EDIT_DATA);
    bool containsGetHandler = Contains(AssetChangeOperation::GET_WRITE_CACHE_HANDLER);
    bool containsAddResource = Contains(AssetChangeOperation::ADD_RESOURCE);
    if ((isCreateFromScratch || containsEdit) && !containsGetHandler && !containsAddResource) {
        NapiError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "Cannot create or edit asset without data to write");
        return false;
    }

    if (containsEdit && (isCreateFromScratch || isCreateFromUri)) {
        NapiError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "Cannot create together with edit");
        return false;
    }

    auto fileAsset = GetFileAssetInstance();
    if (fileAsset == nullptr) {
        NapiError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "fileAsset is null");
        return false;
    }

    if (fileAsset->GetTimePending() == 0 && (containsGetHandler || containsAddResource) && !containsEdit) {
        NapiError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "Cannot edit asset without setEditData");
        return false;
    }

    AssetChangeOperation firstOperation = assetChangeOperations_.front();
    if (fileAsset->GetId() <= 0 && firstOperation != AssetChangeOperation::CREATE_FROM_SCRATCH &&
        firstOperation != AssetChangeOperation::CREATE_FROM_URI) {
        NapiError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "Invalid asset change request");
        return false;
    }

    return true;
}

void MediaAssetChangeRequestNapi::SetCacheFileName(string& fileName)
{
    cacheFileName_ = fileName;
}

string MediaAssetChangeRequestNapi::GetFileRealPath() const
{
    return realPath_;
}

AddResourceMode MediaAssetChangeRequestNapi::GetAddResourceMode() const
{
    return addResourceMode_;
}

void* MediaAssetChangeRequestNapi::GetDataBuffer() const
{
    return dataBuffer_;
}

size_t MediaAssetChangeRequestNapi::GetDataBufferSize() const
{
    return dataBufferSize_;
}

napi_value MediaAssetChangeRequestNapi::JSGetAsset(napi_env env, napi_callback_info info)
{
    auto asyncContext = make_unique<MediaAssetChangeRequestAsyncContext>();
    CHECK_ARGS_THROW_INVALID_PARAM(env,
        MediaLibraryNapiUtils::AsyncContextSetObjectInfo(env, info, asyncContext, ARGS_ZERO, ARGS_ZERO));

    auto changeRequest = asyncContext->objectInfo;
    auto fileAsset = changeRequest->GetFileAssetInstance();
    CHECK_COND(env, fileAsset != nullptr, JS_INNER_FAIL);
    if (fileAsset->GetId() > 0) {
        return FileAssetNapi::CreatePhotoAsset(env, fileAsset);
    }

    // FileAsset object has not been actually created, return null.
    napi_value nullValue;
    napi_get_null(env, &nullValue);
    return nullValue;
}

static bool HasWritePermission()
{
    AccessTokenID tokenCaller = IPCSkeleton::GetSelfTokenID();
    int result = AccessTokenKit::VerifyAccessToken(tokenCaller, PERM_WRITE_IMAGEVIDEO);
    return result == PermissionState::PERMISSION_GRANTED;
}

static napi_status CheckCreateOption(MediaAssetChangeRequestAsyncContext& context)
{
    bool isValid = false;
    int32_t subtype = context.valuesBucket.Get(PhotoColumn::PHOTO_SUBTYPE, isValid);
    string cameraShotKey = context.valuesBucket.Get(PhotoColumn::CAMERA_SHOT_KEY, isValid);
    if (isValid) {
        if (cameraShotKey.size() < CAMERA_SHOT_KEY_SIZE) {
            NAPI_ERR_LOG("cameraShotKey is not null but is less than CAMERA_SHOT_KEY_SIZE");
            return napi_invalid_arg;
        }
        if (subtype == static_cast<int32_t>(PhotoSubType::SCREENSHOT)) {
            NAPI_ERR_LOG("cameraShotKey is not null with subtype is SCREENSHOT");
            return napi_invalid_arg;
        } else {
            context.valuesBucket.Put(PhotoColumn::PHOTO_SUBTYPE, static_cast<int32_t>(PhotoSubType::CAMERA));
        }
    }
    return napi_ok;
}

static napi_status ParseAssetCreateOptions(napi_env env, napi_value arg, MediaAssetChangeRequestAsyncContext& context,
    const map<string, string>& createOptionsMap, bool needCheck)
{
    for (const auto& iter : createOptionsMap) {
        string param = iter.first;
        bool present = false;
        napi_status result = napi_has_named_property(env, arg, param.c_str(), &present);
        CHECK_COND_RET(result == napi_ok, result, "Failed to check named property");
        if (!present) {
            continue;
        }
        napi_value value;
        result = napi_get_named_property(env, arg, param.c_str(), &value);
        CHECK_COND_RET(result == napi_ok, result, "Failed to get named property");
        napi_valuetype valueType = napi_undefined;
        result = napi_typeof(env, value, &valueType);
        CHECK_COND_RET(result == napi_ok, result, "Failed to get value type");
        if (valueType == napi_number) {
            int32_t number = 0;
            result = napi_get_value_int32(env, value, &number);
            CHECK_COND_RET(result == napi_ok, result, "Failed to get int32_t");
            context.valuesBucket.Put(iter.second, number);
        } else if (valueType == napi_boolean) {
            bool isTrue = false;
            result = napi_get_value_bool(env, value, &isTrue);
            CHECK_COND_RET(result == napi_ok, result, "Failed to get bool");
            context.valuesBucket.Put(iter.second, isTrue);
        } else if (valueType == napi_string) {
            char buffer[ARG_BUF_SIZE];
            size_t res = 0;
            result = napi_get_value_string_utf8(env, value, buffer, ARG_BUF_SIZE, &res);
            CHECK_COND_RET(result == napi_ok, result, "Failed to get string");
            context.valuesBucket.Put(iter.second, string(buffer));
        } else if (valueType == napi_undefined || valueType == napi_null) {
            continue;
        } else {
            NAPI_ERR_LOG("valueType %{public}d is unaccepted", static_cast<int>(valueType));
            return napi_invalid_arg;
        }
    }
    return needCheck ? CheckCreateOption(context) : napi_ok;
}

static napi_value ParseArgsCreateAssetSystem(
    napi_env env, napi_callback_info info, unique_ptr<MediaAssetChangeRequestAsyncContext>& context)
{
    // Parse displayName.
    string displayName;
    MediaType mediaType;
    CHECK_COND_WITH_MESSAGE(env,
        MediaLibraryNapiUtils::GetParamStringPathMax(env, context->argv[PARAM1], displayName) == napi_ok,
        "Failed to get displayName");
    CHECK_COND_WITH_MESSAGE(env, MediaFileUtils::CheckDisplayName(displayName) == E_OK, "Failed to check displayName");
    mediaType = MediaFileUtils::GetMediaType(displayName);
    CHECK_COND_WITH_MESSAGE(env, mediaType == MEDIA_TYPE_IMAGE || mediaType == MEDIA_TYPE_VIDEO, "Invalid file type");
    context->valuesBucket.Put(MEDIA_DATA_DB_NAME, displayName);
    context->valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, static_cast<int32_t>(mediaType));

    // Parse options if exists.
    if (context->argc == ARGS_THREE) {
        napi_valuetype valueType;
        napi_value createOptionsNapi = context->argv[PARAM2];
        CHECK_COND_WITH_MESSAGE(
            env, napi_typeof(env, createOptionsNapi, &valueType) == napi_ok, "Failed to get napi type");
        if (valueType != napi_object) {
            NAPI_ERR_LOG("Napi type is wrong in PhotoCreateOptions");
            return nullptr;
        }

        CHECK_COND_WITH_MESSAGE(env,
            ParseAssetCreateOptions(env, createOptionsNapi, *context, PHOTO_CREATE_OPTIONS_PARAM, true) == napi_ok,
            "Parse PhotoCreateOptions failed");
    }
    RETURN_NAPI_TRUE(env);
}

static napi_value ParseArgsCreateAssetCommon(
    napi_env env, napi_callback_info info, unique_ptr<MediaAssetChangeRequestAsyncContext>& context)
{
    // Parse photoType.
    MediaType mediaType;
    int32_t type = 0;
    CHECK_COND_WITH_MESSAGE(
        env, napi_get_value_int32(env, context->argv[PARAM1], &type) == napi_ok, "Failed to get photoType");
    mediaType = static_cast<MediaType>(type);
    CHECK_COND_WITH_MESSAGE(env, mediaType == MEDIA_TYPE_IMAGE || mediaType == MEDIA_TYPE_VIDEO, "Invalid photoType");

    // Parse extension.
    string extension;
    CHECK_COND_WITH_MESSAGE(env,
        MediaLibraryNapiUtils::GetParamStringPathMax(env, context->argv[PARAM2], extension) == napi_ok,
        "Failed to get extension");
    CHECK_COND_WITH_MESSAGE(
        env, mediaType == MediaFileUtils::GetMediaType("." + extension), "Failed to check extension");
    context->valuesBucket.Put(ASSET_EXTENTION, extension);
    context->valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, static_cast<int32_t>(mediaType));

    // Parse options if exists.
    if (context->argc == ARGS_FOUR) {
        napi_valuetype valueType;
        napi_value createOptionsNapi = context->argv[PARAM3];
        CHECK_COND_WITH_MESSAGE(
            env, napi_typeof(env, createOptionsNapi, &valueType) == napi_ok, "Failed to get napi type");
        if (valueType != napi_object) {
            NAPI_ERR_LOG("Napi type is wrong in CreateOptions");
            return nullptr;
        }

        CHECK_COND_WITH_MESSAGE(env,
            ParseAssetCreateOptions(env, createOptionsNapi, *context, CREATE_OPTIONS_PARAM, false) == napi_ok,
            "Parse CreateOptions failed");
    }

    bool isValid = false;
    string title = context->valuesBucket.Get(PhotoColumn::MEDIA_TITLE, isValid);
    if (!isValid) {
        title = mediaType == MEDIA_TYPE_IMAGE ? DEFAULT_TITLE_IMG_PREFIX : DEFAULT_TITLE_VIDEO_PREFIX;
        title += MediaFileUtils::StrCreateTime(DEFAULT_TITLE_TIME_FORMAT, MediaFileUtils::UTCTimeSeconds());
        context->valuesBucket.Put(PhotoColumn::MEDIA_TITLE, title);
    }

    string displayName = title + "." + extension;
    CHECK_COND_WITH_MESSAGE(env, MediaFileUtils::CheckDisplayName(displayName) == E_OK, "Failed to check displayName");
    context->valuesBucket.Put(MEDIA_DATA_DB_NAME, displayName);
    RETURN_NAPI_TRUE(env);
}

static napi_value ParseArgsCreateAsset(
    napi_env env, napi_callback_info info, unique_ptr<MediaAssetChangeRequestAsyncContext>& context)
{
    constexpr size_t minArgs = ARGS_TWO;
    constexpr size_t maxArgs = ARGS_FOUR;
    CHECK_COND_WITH_MESSAGE(env,
        MediaLibraryNapiUtils::AsyncContextGetArgs(env, info, context, minArgs, maxArgs) == napi_ok,
        "Failed to get args");
    CHECK_COND(env, MediaAssetChangeRequestNapi::InitUserFileClient(env, info), JS_INNER_FAIL);

    napi_valuetype valueType;
    CHECK_COND_WITH_MESSAGE(
        env, napi_typeof(env, context->argv[PARAM1], &valueType) == napi_ok, "Failed to get napi type");
    if (valueType == napi_string) {
        if (!MediaLibraryNapiUtils::IsSystemApp()) {
            NapiError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
            return nullptr;
        }
        CHECK_COND_WITH_MESSAGE(env, context->argc <= ARGS_THREE, "Number of args is invalid");
        return ParseArgsCreateAssetSystem(env, info, context);
    } else if (valueType == napi_number) {
        return ParseArgsCreateAssetCommon(env, info, context);
    } else {
        NAPI_ERR_LOG("param type %{public}d is invalid", static_cast<int32_t>(valueType));
        return nullptr;
    }
}

napi_value MediaAssetChangeRequestNapi::JSCreateAssetRequest(napi_env env, napi_callback_info info)
{
    auto asyncContext = make_unique<MediaAssetChangeRequestAsyncContext>();
    CHECK_COND_WITH_MESSAGE(env, ParseArgsCreateAsset(env, info, asyncContext), "Failed to parse args");

    bool isValid = false;
    string displayName = asyncContext->valuesBucket.Get(MEDIA_DATA_DB_NAME, isValid);
    auto emptyFileAsset = make_unique<FileAsset>();
    emptyFileAsset->SetDisplayName(displayName);
    emptyFileAsset->SetTitle(MediaFileUtils::GetTitleFromDisplayName(displayName));
    emptyFileAsset->SetMediaType(MediaFileUtils::GetMediaType(displayName));
    emptyFileAsset->SetTimePending(CREATE_ASSET_REQUEST_PENDING);
    emptyFileAsset->SetResultNapiType(ResultNapiType::TYPE_PHOTOACCESS_HELPER);
    napi_value fileAssetNapi = FileAssetNapi::CreateFileAsset(env, emptyFileAsset);
    CHECK_COND(env, fileAssetNapi != nullptr, JS_INNER_FAIL);

    napi_value constructor = nullptr;
    napi_value instance = nullptr;
    CHECK_ARGS(env, napi_get_reference_value(env, constructor_, &constructor), JS_INNER_FAIL);
    CHECK_ARGS(env, napi_new_instance(env, constructor, 1, &fileAssetNapi, &instance), JS_INNER_FAIL);
    CHECK_COND(env, instance != nullptr, JS_INNER_FAIL);

    MediaAssetChangeRequestNapi* changeRequest = nullptr;
    CHECK_ARGS(env, napi_unwrap(env, instance, reinterpret_cast<void**>(&changeRequest)), JS_INNER_FAIL);
    CHECK_COND(env, changeRequest != nullptr, JS_INNER_FAIL);
    changeRequest->creationValuesBucket_ = std::move(asyncContext->valuesBucket);
    changeRequest->RecordChangeOperation(AssetChangeOperation::CREATE_FROM_SCRATCH);
    return instance;
}

static napi_value ParseFileUri(napi_env env, napi_value arg, MediaType mediaType,
    unique_ptr<MediaAssetChangeRequestAsyncContext>& context)
{
    string fileUriStr;
    CHECK_COND_WITH_MESSAGE(
        env, MediaLibraryNapiUtils::GetParamStringPathMax(env, arg, fileUriStr) == napi_ok, "Failed to get fileUri");
    AppFileService::ModuleFileUri::FileUri fileUri(fileUriStr);
    string path = fileUri.GetRealPath();
    CHECK_COND(env, PathToRealPath(path, context->realPath), JS_ERR_NO_SUCH_FILE);

    CHECK_COND_WITH_MESSAGE(env, mediaType == MediaFileUtils::GetMediaType(context->realPath), "Invalid file type");
    string fileName = MediaFileUtils::GetFileName(context->realPath);
    CHECK_COND_WITH_MESSAGE(env, MediaFileUtils::CheckDisplayName(fileName) == E_OK, "Invalid fileName");
    RETURN_NAPI_TRUE(env);
}

static napi_value ParseArgsCreateAssetFromFileUri(napi_env env, napi_callback_info info, MediaType mediaType,
    unique_ptr<MediaAssetChangeRequestAsyncContext>& context)
{
    CHECK_COND_WITH_MESSAGE(env,
        MediaLibraryNapiUtils::AsyncContextGetArgs(env, info, context, ARGS_TWO, ARGS_TWO) == napi_ok,
        "Failed to get args");
    CHECK_COND(env, MediaAssetChangeRequestNapi::InitUserFileClient(env, info), JS_INNER_FAIL);
    return ParseFileUri(env, context->argv[PARAM1], mediaType, context);
}

napi_value MediaAssetChangeRequestNapi::CreateAssetRequestFromRealPath(napi_env env, const string& realPath)
{
    string displayName = MediaFileUtils::GetFileName(realPath);
    string title = MediaFileUtils::GetTitleFromDisplayName(displayName);
    MediaType mediaType = MediaFileUtils::GetMediaType(displayName);
    auto emptyFileAsset = make_unique<FileAsset>();
    emptyFileAsset->SetDisplayName(displayName);
    emptyFileAsset->SetTitle(title);
    emptyFileAsset->SetMediaType(mediaType);
    emptyFileAsset->SetTimePending(CREATE_ASSET_REQUEST_PENDING);
    emptyFileAsset->SetResultNapiType(ResultNapiType::TYPE_PHOTOACCESS_HELPER);
    napi_value fileAssetNapi = FileAssetNapi::CreateFileAsset(env, emptyFileAsset);
    CHECK_COND(env, fileAssetNapi != nullptr, JS_INNER_FAIL);

    napi_value constructor = nullptr;
    napi_value instance = nullptr;
    CHECK_ARGS(env, napi_get_reference_value(env, constructor_, &constructor), JS_INNER_FAIL);
    CHECK_ARGS(env, napi_new_instance(env, constructor, 1, &fileAssetNapi, &instance), JS_INNER_FAIL);
    CHECK_COND(env, instance != nullptr, JS_INNER_FAIL);

    MediaAssetChangeRequestNapi* changeRequest = nullptr;
    CHECK_ARGS(env, napi_unwrap(env, instance, reinterpret_cast<void**>(&changeRequest)), JS_INNER_FAIL);
    CHECK_COND(env, changeRequest != nullptr, JS_INNER_FAIL);
    changeRequest->realPath_ = realPath;
    changeRequest->creationValuesBucket_.Put(MEDIA_DATA_DB_NAME, displayName);
    changeRequest->creationValuesBucket_.Put(ASSET_EXTENTION, MediaFileUtils::GetExtensionFromPath(displayName));
    changeRequest->creationValuesBucket_.Put(MEDIA_DATA_DB_MEDIA_TYPE, static_cast<int32_t>(mediaType));
    changeRequest->creationValuesBucket_.Put(PhotoColumn::MEDIA_TITLE, title);
    changeRequest->RecordChangeOperation(AssetChangeOperation::CREATE_FROM_URI);
    return instance;
}

napi_value MediaAssetChangeRequestNapi::JSCreateImageAssetRequest(napi_env env, napi_callback_info info)
{
    auto asyncContext = make_unique<MediaAssetChangeRequestAsyncContext>();
    CHECK_COND_WITH_MESSAGE(env, ParseArgsCreateAssetFromFileUri(env, info, MediaType::MEDIA_TYPE_IMAGE, asyncContext),
        "Failed to parse args");
    return CreateAssetRequestFromRealPath(env, asyncContext->realPath);
}

napi_value MediaAssetChangeRequestNapi::JSCreateVideoAssetRequest(napi_env env, napi_callback_info info)
{
    auto asyncContext = make_unique<MediaAssetChangeRequestAsyncContext>();
    CHECK_COND_WITH_MESSAGE(env, ParseArgsCreateAssetFromFileUri(env, info, MediaType::MEDIA_TYPE_VIDEO, asyncContext),
        "Failed to parse args");
    return CreateAssetRequestFromRealPath(env, asyncContext->realPath);
}

static napi_value initDeleteRequest(napi_env env, MediaAssetChangeRequestAsyncContext& context,
    OHOS::AAFwk::Want& request, shared_ptr<DeleteCallback>& callback)
{
    request.SetElementName(DELETE_UI_PACKAGE_NAME, DELETE_UI_EXT_ABILITY_NAME);
    request.SetParam(DELETE_UI_EXTENSION_TYPE, DELETE_UI_REQUEST_TYPE);

    CHECK_COND(env, !context.appName.empty(), JS_INNER_FAIL);
    request.SetParam(DELETE_UI_APPNAME, context.appName);

    request.SetParam(DELETE_UI_URIS, context.uris);
    callback->SetUris(context.uris);

    napi_valuetype valueType = napi_undefined;
    CHECK_COND_WITH_MESSAGE(env, context.argc >= ARGS_THREE && context.argc <= ARGS_FOUR, "Failed to check args");
    napi_value func = context.argv[PARAM1];
    CHECK_ARGS(env, napi_typeof(env, func, &valueType), JS_INNER_FAIL);
    CHECK_COND_WITH_MESSAGE(env, valueType == napi_function, "Failed to check args");
    callback->SetFunc(func);
    RETURN_NAPI_TRUE(env);
}

static napi_value ParseArgsDeleteAssets(
    napi_env env, napi_callback_info info, unique_ptr<MediaAssetChangeRequestAsyncContext>& context)
{
    constexpr size_t minArgs = ARGS_THREE;
    constexpr size_t maxArgs = ARGS_FOUR;
    CHECK_COND_WITH_MESSAGE(env,
        MediaLibraryNapiUtils::AsyncContextGetArgs(env, info, context, minArgs, maxArgs) == napi_ok,
        "Failed to get args");
    CHECK_COND(env, MediaAssetChangeRequestNapi::InitUserFileClient(env, info), JS_INNER_FAIL);

    napi_valuetype valueType = napi_undefined;
    CHECK_ARGS(env, napi_typeof(env, context->argv[PARAM1], &valueType), JS_INNER_FAIL);
    CHECK_COND(env, valueType == napi_function, JS_INNER_FAIL);

    vector<string> uris;
    vector<napi_value> napiValues;
    CHECK_NULLPTR_RET(MediaLibraryNapiUtils::GetNapiValueArray(env, context->argv[PARAM2], napiValues));
    CHECK_COND_WITH_MESSAGE(env, !napiValues.empty(), "array is empty");
    CHECK_ARGS(env, napi_typeof(env, napiValues.front(), &valueType), JS_INNER_FAIL);
    if (valueType == napi_string) { // array of asset uri
        CHECK_NULLPTR_RET(MediaLibraryNapiUtils::GetStringArray(env, napiValues, uris));
    } else if (valueType == napi_object) { // array of asset object
        CHECK_NULLPTR_RET(MediaLibraryNapiUtils::GetUriArrayFromAssets(env, napiValues, uris));
    } else {
        NapiError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "Invalid type");
        return nullptr;
    }

    CHECK_COND_WITH_MESSAGE(env, !uris.empty(), "Failed to check empty array");
    for (const auto& uri : uris) {
        CHECK_COND(env, uri.find(PhotoColumn::PHOTO_URI_PREFIX) != string::npos, JS_E_URI);
    }

    context->predicates.In(PhotoColumn::MEDIA_ID, uris);
    context->valuesBucket.Put(PhotoColumn::MEDIA_DATE_TRASHED, MediaFileUtils::UTCTimeSeconds());
    context->uris.assign(uris.begin(), uris.end());
    RETURN_NAPI_TRUE(env);
}

static void DeleteAssetsExecute(napi_env env, void* data)
{
    auto* context = static_cast<MediaAssetChangeRequestAsyncContext*>(data);
    string trashUri = PAH_TRASH_PHOTO;
    MediaLibraryNapiUtils::UriAppendKeyValue(trashUri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri updateAssetUri(trashUri);
    int32_t changedRows = UserFileClient::Update(updateAssetUri, context->predicates, context->valuesBucket);
    if (changedRows < 0) {
        context->SaveError(changedRows);
        NAPI_ERR_LOG("Failed to delete assets, err: %{public}d", changedRows);
    }
}

static void DeleteAssetsCompleteCallback(napi_env env, napi_status status, void* data)
{
    auto* context = static_cast<MediaAssetChangeRequestAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    auto jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    napi_get_undefined(env, &jsContext->data);
    napi_get_undefined(env, &jsContext->error);
    if (context->error == ERR_DEFAULT) {
        jsContext->status = true;
    } else {
        context->HandleError(env, jsContext->error);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(
            env, context->deferred, context->callbackRef, context->work, *jsContext);
    }
    delete context;
}

napi_value MediaAssetChangeRequestNapi::JSDeleteAssets(napi_env env, napi_callback_info info)
{
    auto asyncContext = make_unique<MediaAssetChangeRequestAsyncContext>();
    CHECK_COND_WITH_MESSAGE(env, ParseArgsDeleteAssets(env, info, asyncContext), "Failed to parse args");
    if (MediaLibraryNapiUtils::IsSystemApp()) {
        return MediaLibraryNapiUtils::NapiCreateAsyncWork(
            env, asyncContext, "ChangeRequestDeleteAssets", DeleteAssetsExecute, DeleteAssetsCompleteCallback);
    }

    // Deletion control by ui extension
    CHECK_COND(env, HasWritePermission(), OHOS_PERMISSION_DENIED_CODE);
    CHECK_COND_WITH_MESSAGE(
        env, asyncContext->uris.size() <= MAX_DELETE_NUMBER, "No more than 300 assets can be deleted at one time");
    auto context = OHOS::AbilityRuntime::GetStageModeContext(env, asyncContext->argv[PARAM0]);
    CHECK_COND_WITH_MESSAGE(env, context != nullptr, "Failed to get stage mode context");
    auto abilityContext = OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::AbilityContext>(context);
    CHECK_COND(env, abilityContext != nullptr, JS_INNER_FAIL);
    auto abilityInfo = abilityContext->GetAbilityInfo();
    abilityContext->GetResourceManager()->GetStringById(abilityInfo->labelId, asyncContext->appName);
    auto uiContent = abilityContext->GetUIContent();
    CHECK_COND(env, uiContent != nullptr, JS_INNER_FAIL);

    auto callback = std::make_shared<DeleteCallback>(env, uiContent);
    OHOS::Ace::ModalUIExtensionCallbacks extensionCallback = {
        std::bind(&DeleteCallback::OnRelease, callback, std::placeholders::_1),
        std::bind(&DeleteCallback::OnResult, callback, std::placeholders::_1, std::placeholders::_2),
        std::bind(&DeleteCallback::OnReceive, callback, std::placeholders::_1),
        std::bind(
            &DeleteCallback::OnError, callback, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3),
    };
    OHOS::Ace::ModalUIExtensionConfig config;
    config.isProhibitBack = true;
    OHOS::AAFwk::Want request;
    CHECK_COND(env, initDeleteRequest(env, *asyncContext, request, callback), JS_INNER_FAIL);

    int32_t sessionId = uiContent->CreateModalUIExtension(request, extensionCallback, config);
    CHECK_COND(env, sessionId != 0, JS_INNER_FAIL);
    callback->SetSessionId(sessionId);
    RETURN_NAPI_UNDEFINED(env);
}

napi_value MediaAssetChangeRequestNapi::JSSetEditData(napi_env env, napi_callback_info info)
{
    if (!MediaLibraryNapiUtils::IsSystemApp()) {
        NapiError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return nullptr;
    }

    auto asyncContext = make_unique<MediaAssetChangeRequestAsyncContext>();
    CHECK_COND_WITH_MESSAGE(env,
        MediaLibraryNapiUtils::AsyncContextSetObjectInfo(env, info, asyncContext, ARGS_ONE, ARGS_ONE) == napi_ok,
        "Failed to get object info");

    auto changeRequest = asyncContext->objectInfo;
    napi_value arg = asyncContext->argv[PARAM0];
    napi_valuetype valueType;
    MediaAssetEditDataNapi* editDataNapi;
    CHECK_ARGS(env, napi_typeof(env, arg, &valueType), JS_INNER_FAIL);
    CHECK_COND_WITH_MESSAGE(env, valueType == napi_object, "Invalid argument type");
    CHECK_ARGS(env, napi_unwrap(env, arg, reinterpret_cast<void**>(&editDataNapi)), JS_INNER_FAIL);
    CHECK_COND_WITH_MESSAGE(env, editDataNapi != nullptr, "Failed to get MediaAssetEditDataNapi object");

    shared_ptr<MediaAssetEditData> editData = editDataNapi->GetMediaAssetEditData();
    CHECK_COND_WITH_MESSAGE(env, editData != nullptr, "editData is null");
    CHECK_COND_WITH_MESSAGE(env, !editData->GetCompatibleFormat().empty(), "Invalid compatibleFormat");
    CHECK_COND_WITH_MESSAGE(env, !editData->GetFormatVersion().empty(), "Invalid formatVersion");
    CHECK_COND_WITH_MESSAGE(env, !editData->GetData().empty(), "Invalid data");
    changeRequest->editData_ = editData;
    changeRequest->RecordChangeOperation(AssetChangeOperation::SET_EDIT_DATA);
    RETURN_NAPI_UNDEFINED(env);
}

napi_value MediaAssetChangeRequestNapi::JSSetFavorite(napi_env env, napi_callback_info info)
{
    if (!MediaLibraryNapiUtils::IsSystemApp()) {
        NapiError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return nullptr;
    }

    auto asyncContext = make_unique<MediaAssetChangeRequestAsyncContext>();
    bool isFavorite;
    CHECK_COND_WITH_MESSAGE(env,
        MediaLibraryNapiUtils::ParseArgsBoolCallBack(env, info, asyncContext, isFavorite) == napi_ok,
        "Failed to parse args");
    CHECK_COND_WITH_MESSAGE(env, asyncContext->argc == ARGS_ONE, "Number of args is invalid");

    auto changeRequest = asyncContext->objectInfo;
    CHECK_COND(env, changeRequest->GetFileAssetInstance() != nullptr, JS_INNER_FAIL);
    changeRequest->GetFileAssetInstance()->SetFavorite(isFavorite);
    changeRequest->RecordChangeOperation(AssetChangeOperation::SET_FAVORITE);
    RETURN_NAPI_UNDEFINED(env);
}

napi_value MediaAssetChangeRequestNapi::JSSetHidden(napi_env env, napi_callback_info info)
{
    if (!MediaLibraryNapiUtils::IsSystemApp()) {
        NapiError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return nullptr;
    }

    auto asyncContext = make_unique<MediaAssetChangeRequestAsyncContext>();
    bool isHidden;
    CHECK_COND_WITH_MESSAGE(env,
        MediaLibraryNapiUtils::ParseArgsBoolCallBack(env, info, asyncContext, isHidden) == napi_ok,
        "Failed to parse args");
    CHECK_COND_WITH_MESSAGE(env, asyncContext->argc == ARGS_ONE, "Number of args is invalid");

    auto changeRequest = asyncContext->objectInfo;
    CHECK_COND(env, changeRequest->GetFileAssetInstance() != nullptr, JS_INNER_FAIL);
    changeRequest->GetFileAssetInstance()->SetHidden(isHidden);
    changeRequest->RecordChangeOperation(AssetChangeOperation::SET_HIDDEN);
    RETURN_NAPI_UNDEFINED(env);
}

napi_value MediaAssetChangeRequestNapi::JSSetTitle(napi_env env, napi_callback_info info)
{
    auto asyncContext = make_unique<MediaAssetChangeRequestAsyncContext>();
    string title;
    CHECK_COND_WITH_MESSAGE(env,
        MediaLibraryNapiUtils::ParseArgsStringCallback(env, info, asyncContext, title) == napi_ok,
        "Failed to parse args");
    CHECK_COND_WITH_MESSAGE(env, asyncContext->argc == ARGS_ONE, "Number of args is invalid");

    auto changeRequest = asyncContext->objectInfo;
    auto fileAsset = changeRequest->GetFileAssetInstance();
    CHECK_COND(env, fileAsset != nullptr, JS_INNER_FAIL);
    string extension = MediaFileUtils::SplitByChar(fileAsset->GetDisplayName(), '.');
    string displayName = title + "." + extension;
    CHECK_COND_WITH_MESSAGE(env, MediaFileUtils::CheckDisplayName(displayName) == E_OK, "Invalid title");

    fileAsset->SetTitle(title);
    fileAsset->SetDisplayName(displayName);
    changeRequest->RecordChangeOperation(AssetChangeOperation::SET_TITLE);

    // Merge the creation and SET_TITLE operations.
    if (changeRequest->Contains(AssetChangeOperation::CREATE_FROM_SCRATCH) ||
        changeRequest->Contains(AssetChangeOperation::CREATE_FROM_URI)) {
        changeRequest->creationValuesBucket_.valuesMap[MEDIA_DATA_DB_NAME] = displayName;
        changeRequest->creationValuesBucket_.valuesMap[PhotoColumn::MEDIA_TITLE] = title;
    }
    RETURN_NAPI_UNDEFINED(env);
}

napi_value MediaAssetChangeRequestNapi::JSSetLocation(napi_env env, napi_callback_info info)
{
    if (!MediaLibraryNapiUtils::IsSystemApp()) {
        NapiError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return nullptr;
    }
    auto asyncContext = make_unique<MediaAssetChangeRequestAsyncContext>();
    double latitude;
    double longitude;
    MediaLibraryNapiUtils::AsyncContextSetObjectInfo(env, info, asyncContext, ARGS_TWO, ARGS_TWO);
    MediaLibraryNapiUtils::GetDouble(env, asyncContext->argv[0], latitude);
    MediaLibraryNapiUtils::GetDouble(env, asyncContext->argv[1], longitude);
    asyncContext->objectInfo->fileAsset_->SetLongitude(longitude);
    asyncContext->objectInfo->fileAsset_->SetLatitude(latitude);
    asyncContext->objectInfo->assetChangeOperations_.push_back(AssetChangeOperation::SET_LOCATION);
    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_undefined(env, &result), JS_INNER_FAIL);
    return result;
}

#ifdef ABILITY_CAMERA_SUPPORT
static int SaveImage(const string &fileName, void *output, size_t writeSize)
{
    Uri fileUri(fileName);
    int fd = UserFileClient::OpenFile(fileUri, "rw");
    if (fd < 0) {
        NAPI_ERR_LOG("fd.Get() < 0 fd %{public}d status %{public}d", fd, errno);
        return E_ERR;
    }

    int ret = write(fd, output, writeSize);
    close(fd);
    if (ret < 0) {
        NAPI_ERR_LOG("write err %{public}d", errno);
        return ret;
    }
    return E_OK;
}

static int SavePhotoProxyImage(const string &fileUri, sptr<CameraStandard::DeferredPhotoProxy> photoProxyPtr)
{
    void* imageAddr = photoProxyPtr->GetFileDataAddr();
    size_t imageSize = photoProxyPtr->GetFileSize();
    if (imageAddr == nullptr || imageSize == 0) {
        NAPI_ERR_LOG("imageAddr is nullptr or imageSize(%{public}zu)==0", imageSize);
        return E_ERR;
    }
    return SaveImage(fileUri, imageAddr, imageSize);
}
#endif

napi_value MediaAssetChangeRequestNapi::JSSetUserComment(napi_env env, napi_callback_info info)
{
    if (!MediaLibraryNapiUtils::IsSystemApp()) {
        NapiError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return nullptr;
    }

    auto asyncContext = make_unique<MediaAssetChangeRequestAsyncContext>();
    string userComment;
    CHECK_COND_WITH_MESSAGE(env,
        MediaLibraryNapiUtils::ParseArgsStringCallback(env, info, asyncContext, userComment) == napi_ok,
        "Failed to parse args");
    CHECK_COND_WITH_MESSAGE(env, asyncContext->argc == ARGS_ONE, "Number of args is invalid");
    CHECK_COND_WITH_MESSAGE(env, userComment.length() <= USER_COMMENT_MAX_LEN, "user comment too long");

    auto changeRequest = asyncContext->objectInfo;
    CHECK_COND(env, changeRequest->GetFileAssetInstance() != nullptr, JS_INNER_FAIL);
    changeRequest->GetFileAssetInstance()->SetUserComment(userComment);
    changeRequest->RecordChangeOperation(AssetChangeOperation::SET_USER_COMMENT);
    RETURN_NAPI_UNDEFINED(env);
}

static int32_t OpenWriteCacheHandler(MediaAssetChangeRequestAsyncContext& context)
{
    auto changeRequest = context.objectInfo;
    auto fileAsset = changeRequest->GetFileAssetInstance();
    if (fileAsset == nullptr) {
        context.SaveError(E_FAIL);
        NAPI_ERR_LOG("fileAsset is null");
        return E_FAIL;
    }

    string extension = MediaFileUtils::GetExtensionFromPath(fileAsset->GetDisplayName());
    string cacheFileName = to_string(MediaFileUtils::UTCTimeNanoSeconds()) + "." + extension;
    string uri = PhotoColumn::PHOTO_CACHE_URI_PREFIX + cacheFileName;
    MediaFileUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri openCacheUri(uri);
    int32_t ret = UserFileClient::OpenFile(openCacheUri, MEDIA_FILEMODE_WRITEONLY);
    if (ret == E_PERMISSION_DENIED) {
        context.error = OHOS_PERMISSION_DENIED_CODE;
        NAPI_ERR_LOG("Open cache file failed, permission denied");
        return ret;
    }
    if (ret < 0) {
        context.SaveError(ret);
        NAPI_ERR_LOG("Open cache file failed, ret: %{public}d", ret);
    }
    changeRequest->SetCacheFileName(cacheFileName);
    return ret;
}

static void GetWriteCacheHandlerExecute(napi_env env, void* data)
{
    auto* context = static_cast<MediaAssetChangeRequestAsyncContext*>(data);
    int32_t ret = OpenWriteCacheHandler(*context);
    if (ret < 0) {
        NAPI_ERR_LOG("Failed to open write cache handler, ret: %{public}d", ret);
        return;
    }
    context->fd = ret;
    context->objectInfo->RecordChangeOperation(AssetChangeOperation::GET_WRITE_CACHE_HANDLER);
}

static void GetWriteCacheHandlerCompleteCallback(napi_env env, napi_status status, void* data)
{
    auto* context = static_cast<MediaAssetChangeRequestAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    auto jsContext = make_unique<JSAsyncContextOutput>();
    if (context->error == ERR_DEFAULT) {
        napi_create_int32(env, context->fd, &jsContext->data);
        napi_get_undefined(env, &jsContext->error);
        jsContext->status = true;
    } else {
        context->HandleError(env, jsContext->error);
        napi_get_undefined(env, &jsContext->data);
        jsContext->status = false;
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(
            env, context->deferred, context->callbackRef, context->work, *jsContext);
    }
    delete context;
}

static napi_value CheckWriteOperation(napi_env env, MediaAssetChangeRequestNapi* changeRequest)
{
    if (changeRequest == nullptr) {
        NapiError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "changeRequest is null");
        return nullptr;
    }

    if (changeRequest->Contains(AssetChangeOperation::CREATE_FROM_URI) ||
        changeRequest->Contains(AssetChangeOperation::GET_WRITE_CACHE_HANDLER) ||
        changeRequest->Contains(AssetChangeOperation::ADD_RESOURCE)) {
        NapiError::ThrowError(env, JS_E_OPERATION_NOT_SUPPORT,
            "The previous asset creation/modification request has not been applied");
        return nullptr;
    }
    RETURN_NAPI_TRUE(env);
}

napi_value MediaAssetChangeRequestNapi::JSGetWriteCacheHandler(napi_env env, napi_callback_info info)
{
    auto asyncContext = make_unique<MediaAssetChangeRequestAsyncContext>();
    CHECK_COND_WITH_MESSAGE(env,
        MediaLibraryNapiUtils::AsyncContextSetObjectInfo(env, info, asyncContext, ARGS_ZERO, ARGS_ONE) == napi_ok,
        "Failed to get object info");

    auto changeRequest = asyncContext->objectInfo;
    auto fileAsset = changeRequest->GetFileAssetInstance();
    CHECK_COND(env, fileAsset != nullptr, JS_INNER_FAIL);
    CHECK_COND(env, CheckWriteOperation(env, changeRequest), JS_E_OPERATION_NOT_SUPPORT);
    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "ChangeRequestGetWriteCacheHandler",
        GetWriteCacheHandlerExecute, GetWriteCacheHandlerCompleteCallback);
}

napi_value MediaAssetChangeRequestNapi::JSAddResource(napi_env env, napi_callback_info info)
{
    auto asyncContext = make_unique<MediaAssetChangeRequestAsyncContext>();
    CHECK_COND_WITH_MESSAGE(env,
        MediaLibraryNapiUtils::AsyncContextSetObjectInfo(env, info, asyncContext, ARGS_TWO, ARGS_TWO) == napi_ok,
        "Failed to get object info");
    auto changeRequest = asyncContext->objectInfo;
    auto fileAsset = changeRequest->GetFileAssetInstance();
    CHECK_COND(env, fileAsset != nullptr, JS_INNER_FAIL);
    CHECK_COND(env, CheckWriteOperation(env, changeRequest), JS_E_OPERATION_NOT_SUPPORT);

    int32_t resourceType = -1;
    CHECK_COND_WITH_MESSAGE(env,
        MediaLibraryNapiUtils::GetInt32(env, asyncContext->argv[PARAM0], resourceType) == napi_ok,
        "Failed to get resourceType");
    CHECK_COND_WITH_MESSAGE(env, resourceType == static_cast<int>(fileAsset->GetMediaType()) ||
        resourceType == static_cast<int>(ResourceType::PHOTO_PROXY), "Failed to check resourceType");

    napi_valuetype valueType;
    napi_value value = asyncContext->argv[PARAM1];
    CHECK_COND_WITH_MESSAGE(env, napi_typeof(env, value, &valueType) == napi_ok, "Failed to get napi type");
    if (valueType == napi_string) {
        // addResource by file uri
        CHECK_COND(env, ParseFileUri(env, value, fileAsset->GetMediaType(), asyncContext), OHOS_INVALID_PARAM_CODE);
        changeRequest->realPath_ = asyncContext->realPath;
        changeRequest->addResourceMode_ = AddResourceMode::FILE_URI;
    } else {
        // addResource by data buffer
        bool isArrayBuffer = false;
        CHECK_COND_WITH_MESSAGE(env, napi_is_arraybuffer(env, value, &isArrayBuffer) == napi_ok,
            "Failed to check data type");
        if (isArrayBuffer) {
            CHECK_COND_WITH_MESSAGE(env, napi_get_arraybuffer_info(env, value, &(changeRequest->dataBuffer_),
                &(changeRequest->dataBufferSize_)) == napi_ok, "Failed to get data buffer");
            CHECK_COND_WITH_MESSAGE(env, changeRequest->dataBufferSize_ > 0, "Failed to check size of data buffer");
            changeRequest->addResourceMode_ = AddResourceMode::DATA_BUFFER;
        } else {
            // addResource by photoProxy
            if (!MediaLibraryNapiUtils::IsSystemApp()) {
                NapiError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
                RETURN_NAPI_UNDEFINED(env);
            }
            #ifdef ABILITY_CAMERA_SUPPORTED
            CameraStandard::DeferredPhotoProxyNapi* napiPhotoProxyPtr = nullptr;
            CHECK_ARGS(env, napi_unwrap(env, asyncContext->argv[PARAM1], reinterpret_cast<void**>(&napiPhotoProxyPtr)),
                JS_INNER_FAIL);
            changeRequest->photoProxy_ = napiPhotoProxyPtr->deferredPhotoProxy_;
            changeRequest->addResourceMode_ = AddResourceMode::PHOTO_PROXY;
            #endif
        }
    }

    changeRequest->RecordChangeOperation(AssetChangeOperation::ADD_RESOURCE);
    RETURN_NAPI_UNDEFINED(env);
}

void MediaAssetChangeRequestNapi::SetNewFileAsset(int32_t id, const string& uri)
{
    fileAsset_->SetId(id);
    fileAsset_->SetUri(uri);
    fileAsset_->SetTimePending(0);
}

static bool IsCreation(MediaAssetChangeRequestAsyncContext& context)
{
    auto assetChangeOperations = context.assetChangeOperations;
    bool isCreateFromScratch = std::find(assetChangeOperations.begin(), assetChangeOperations.end(),
                                         AssetChangeOperation::CREATE_FROM_SCRATCH) != assetChangeOperations.end();
    bool isCreateFromUri = std::find(assetChangeOperations.begin(), assetChangeOperations.end(),
                                     AssetChangeOperation::CREATE_FROM_URI) != assetChangeOperations.end();
    return isCreateFromScratch || isCreateFromUri;
}

int32_t MediaAssetChangeRequestNapi::CopyFileToMediaLibrary(const UniqueFd& destFd)
{
    CHECK_COND_RET(!realPath_.empty(), E_FAIL, "Failed to check realPath_");
    UniqueFd srcFd(open(realPath_.c_str(), O_RDONLY));
    if (srcFd.Get() < 0) {
        NAPI_ERR_LOG("Failed to open %{private}s, errno=%{public}d", realPath_.c_str(), errno);
        return srcFd.Get();
    }

    struct stat statSrc {};
    int32_t status = fstat(srcFd.Get(), &statSrc);
    if (status != 0) {
        NAPI_ERR_LOG("Failed to get file stat, errno=%{public}d", errno);
        return status;
    }

    constexpr size_t bufferSize = 2048;
    char buffer[bufferSize];
    size_t bytesRead;
    size_t bytesWritten;
    while ((bytesRead = read(srcFd.Get(), buffer, bufferSize)) > 0) {
        bytesWritten = write(destFd.Get(), buffer, bytesRead);
        if (bytesWritten != bytesRead) {
            NAPI_ERR_LOG("Failed to copy file from srcFd=%{private}d to destFd=%{private}d", srcFd.Get(), destFd.Get());
            return E_HAS_FS_ERROR;
        }
    }
    return E_OK;
}

int32_t MediaAssetChangeRequestNapi::CopyDataBufferToMediaLibrary(const UniqueFd& destFd)
{
    size_t offset = 0;
    size_t length = dataBufferSize_;
    while (offset < length) {
        ssize_t written = write(destFd.Get(), (char*)dataBuffer_ + offset, length - offset);
        if (written < 0) {
            NAPI_ERR_LOG("Failed to copy data buffer, return %{public}d", static_cast<int>(written));
            return written;
        }
        offset += written;
    }
    return E_OK;
}

int32_t MediaAssetChangeRequestNapi::CopyToMediaLibrary(AddResourceMode mode)
{
    CHECK_COND_RET(fileAsset_ != nullptr, E_FAIL, "Failed to check fileAsset_");
    bool isValid = false;
    string title = creationValuesBucket_.Get(PhotoColumn::MEDIA_TITLE, isValid);
    CHECK_COND_RET(isValid, E_FAIL, "Failed to get title");
    string extension = creationValuesBucket_.Get(ASSET_EXTENTION, isValid);
    CHECK_COND_RET(isValid && MediaFileUtils::CheckDisplayName(title + "." + extension) == E_OK, E_FAIL,
        "Failed to check displayName");
    creationValuesBucket_.valuesMap.erase(MEDIA_DATA_DB_NAME);

    string uri = PAH_CREATE_PHOTO_COMPONENT; // create asset by security component
    MediaLibraryNapiUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri createAssetUri(uri);
    string assetUri;
    int id = UserFileClient::InsertExt(createAssetUri, creationValuesBucket_, assetUri);
    CHECK_COND_RET(id >= 0, id, "Failed to create asset by security component");

    AppFileService::ModuleFileUri::FileUri fileUri(assetUri);
    UniqueFd destFd(open(fileUri.GetRealPath().c_str(), O_WRONLY));
    if (destFd.Get() < 0) {
        NAPI_ERR_LOG("Failed to open %{private}s, errno=%{public}d", assetUri.c_str(), errno);
        return destFd.Get();
    }

    int32_t ret = E_ERR;
    if (mode == AddResourceMode::FILE_URI) {
        ret = CopyFileToMediaLibrary(destFd);
    } else if (mode == AddResourceMode::DATA_BUFFER) {
        ret = CopyDataBufferToMediaLibrary(destFd);
    } else {
        NAPI_ERR_LOG("Invalid mode: %{public}d", mode);
        return ret;
    }

    if (ret == E_OK) {
        SetNewFileAsset(id, assetUri);
    }
    return ret;
}

static bool CreateBySecurityComponent(MediaAssetChangeRequestAsyncContext& context)
{
    bool isCreation = IsCreation(context);
    if (!isCreation) {
        context.error = OHOS_PERMISSION_DENIED_CODE;
        NAPI_ERR_LOG("Cannot edit asset without write permission");
        return false;
    }

    int32_t ret = E_FAIL;
    auto assetChangeOperations = context.assetChangeOperations;
    bool isCreateFromUri = std::find(assetChangeOperations.begin(), assetChangeOperations.end(),
                                     AssetChangeOperation::CREATE_FROM_URI) != assetChangeOperations.end();
    auto changeRequest = context.objectInfo;
    if (isCreateFromUri) {
        ret = changeRequest->CopyToMediaLibrary(AddResourceMode::FILE_URI);
    } else {
        ret = changeRequest->CopyToMediaLibrary(changeRequest->GetAddResourceMode());
    }

    if (ret < 0) {
        context.SaveError(ret);
        NAPI_ERR_LOG("Failed to create asset by security component, ret: %{public}d", ret);
        return false;
    }
    return true;
}

int32_t MediaAssetChangeRequestNapi::PutMediaAssetEditData(DataShare::DataShareValuesBucket& valuesBucket)
{
    // If there is no editData, return ok for compatibility with api10 in the following situation.
    // (1) get an asset by createAsset in api10;
    // (2) new a MediaAssetChangeRequest and then write data by getWriteCacheHandler or addResource.
    if (editData_ == nullptr) {
        return E_OK;
    }

    string compatibleFormat = editData_->GetCompatibleFormat();
    CHECK_COND_RET(!compatibleFormat.empty(), E_FAIL, "Failed to check compatibleFormat");
    string formatVersion = editData_->GetFormatVersion();
    CHECK_COND_RET(!formatVersion.empty(), E_FAIL, "Failed to check formatVersion");
    string data = editData_->GetData();
    CHECK_COND_RET(!data.empty(), E_FAIL, "Failed to check data");

    valuesBucket.Put(COMPATIBLE_FORMAT, compatibleFormat);
    valuesBucket.Put(FORMAT_VERSION, formatVersion);
    valuesBucket.Put(EDIT_DATA, data);
    return E_OK;
}

int32_t MediaAssetChangeRequestNapi::SubmitCache(bool isCreation)
{
    CHECK_COND_RET(fileAsset_ != nullptr, E_FAIL, "Failed to check fileAsset_");
    CHECK_COND_RET(MediaFileUtils::CheckDisplayName(cacheFileName_) == E_OK, E_FAIL, "Failed to check cacheFileName_");

    string uri = PAH_SUBMIT_CACHE;
    MediaLibraryNapiUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri submitCacheUri(uri);

    string assetUri;
    int32_t ret;
    if (isCreation) {
        bool isValid = false;
        string displayName = creationValuesBucket_.Get(MEDIA_DATA_DB_NAME, isValid);
        CHECK_COND_RET(
            isValid && MediaFileUtils::CheckDisplayName(displayName) == E_OK, E_FAIL, "Failed to check displayName");
        creationValuesBucket_.Put(CACHE_FILE_NAME, cacheFileName_);
        ret = UserFileClient::InsertExt(submitCacheUri, creationValuesBucket_, assetUri);
    } else {
        DataShare::DataShareValuesBucket valuesBucket;
        valuesBucket.Put(PhotoColumn::MEDIA_ID, fileAsset_->GetId());
        valuesBucket.Put(CACHE_FILE_NAME, cacheFileName_);
        ret = PutMediaAssetEditData(valuesBucket);
        CHECK_COND_RET(ret == E_OK, ret, "Failed to put editData");
        ret = UserFileClient::Insert(submitCacheUri, valuesBucket);
    }

    if (ret > 0 && isCreation) {
        SetNewFileAsset(ret, assetUri);
    }
    cacheFileName_.clear();
    return ret;
}

static bool SubmitCacheExecute(MediaAssetChangeRequestAsyncContext& context)
{
    bool isCreation = IsCreation(context);
    auto changeRequest = context.objectInfo;
    int32_t ret = changeRequest->SubmitCache(isCreation);
    if (ret < 0) {
        context.SaveError(ret);
        NAPI_ERR_LOG("Failed to write cache, ret: %{public}d", ret);
        return false;
    }
    return true;
}

static bool WriteCacheByArrayBuffer(MediaAssetChangeRequestAsyncContext& context, UniqueFd& destFd)
{
    auto changeRequest = context.objectInfo;
    size_t offset = 0;
    size_t length = changeRequest->GetDataBufferSize();
    void* dataBuffer = changeRequest->GetDataBuffer();
    while (offset < length) {
        ssize_t written = write(destFd.Get(), (char*)dataBuffer + offset, length - offset);
        if (written < 0) {
            context.SaveError(written);
            NAPI_ERR_LOG("Failed to write data buffer to cache file, return %{public}d", static_cast<int>(written));
            return false;
        }
        offset += written;
    }
    return true;
}

static bool SendToCacheFile(MediaAssetChangeRequestAsyncContext& context, UniqueFd& destFd)
{
    auto changeRequest = context.objectInfo;
    string realPath = changeRequest->GetFileRealPath();
    UniqueFd srcFd(open(realPath.c_str(), O_RDONLY));
    if (srcFd.Get() < 0) {
        context.SaveError(srcFd.Get());
        NAPI_ERR_LOG("Failed to open file, errno=%{public}d", errno);
        return false;
    }

    struct stat statSrc {};
    int32_t status = fstat(srcFd.Get(), &statSrc);
    if (status != 0) {
        context.SaveError(status);
        NAPI_ERR_LOG("Failed to get file stat, errno=%{public}d", errno);
        return false;
    }

    off_t offset = 0;
    off_t fileSize = statSrc.st_size;
    while (offset < fileSize) {
        ssize_t sent = sendfile(destFd.Get(), srcFd.Get(), &offset, fileSize - offset);
        if (sent < 0) {
            context.SaveError(sent);
            NAPI_ERR_LOG("Failed to sendfile with errno=%{public}d, srcFd=%{private}d, destFd=%{private}d", errno,
                srcFd.Get(), destFd.Get());
            return false;
        }
    }
    return true;
}

static bool CreateFromFileUriExecute(MediaAssetChangeRequestAsyncContext& context)
{
    if (!HasWritePermission()) {
        return CreateBySecurityComponent(context);
    }

    int32_t cacheFd = OpenWriteCacheHandler(context);
    if (cacheFd < 0) {
        NAPI_ERR_LOG("Failed to open write cache handler, err: %{public}d", cacheFd);
        return false;
    }

    UniqueFd uniqueFd(cacheFd);
    if (!SendToCacheFile(context, uniqueFd)) {
        NAPI_ERR_LOG("Faild to write cache file");
        return false;
    }
    return SubmitCacheExecute(context);
}

static bool AddPhotoProxyResourceExecute(MediaAssetChangeRequestAsyncContext& context)
{
    #ifdef ABILITY_CAMERA_SUPPORT
    string uri = PAH_ADD_IMAGE;
    MediaLibraryNapiUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri updateAssetUri(uri);

    auto fileAsset = context.objectInfo->GetFileAssetInstance();
    std::string fileUri = fileAsset->GetUri();
    DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause(PhotoColumn::MEDIA_ID + " = ? ");
    predicates.SetWhereArgs({ to_string(fileAsset->GetId()) });

    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(PhotoColumn::PHOTO_ID, context.objectInfo->GetPhotoProxyObj()->GetPhotoId());
    NAPI_INFO_LOG("photoId: %{public}s", context.objectInfo->GetPhotoProxyObj()->GetPhotoId().c_str());
    valuesBucket.Put(PhotoColumn::PHOTO_DEFERRED_PROC_TYPE,
        context.objectInfo->GetPhotoProxyObj()->GetDeferredProcType());
    valuesBucket.Put(MediaColumn::MEDIA_ID, fileAsset->GetId());
    int32_t changedRows = UserFileClient::Update(updateAssetUri, predicates, valuesBucket);
    if (changedRows < 0) {
        context.SaveError(changedRows);
        NAPI_ERR_LOG("Failed to set, err: %{public}d", changedRows);
        return false;
    }

    int err = SavePhotoProxyImage(fileUri, context.objectInfo->GetPhotoProxyObj());
    if (err < 0) {
        context.SaveError(err);
        NAPI_ERR_LOG("Failed to saveImage , err: %{public}d", err);
        return false;
    }
    #endif
    return true;
}

static bool AddResourceExecute(MediaAssetChangeRequestAsyncContext& context)
{
    if (!HasWritePermission()) {
        return CreateBySecurityComponent(context);
    }

    AddResourceMode mode = context.objectInfo->GetAddResourceMode();
    if (mode == AddResourceMode::PHOTO_PROXY) {
        return AddPhotoProxyResourceExecute(context);
    }

    int32_t cacheFd = OpenWriteCacheHandler(context);
    if (cacheFd < 0) {
        NAPI_ERR_LOG("Failed to open write cache handler, err: %{public}d", cacheFd);
        return false;
    }
    UniqueFd uniqueFd(cacheFd);

    bool isWriteSuccess = false;
    if (mode == AddResourceMode::DATA_BUFFER) {
        isWriteSuccess = WriteCacheByArrayBuffer(context, uniqueFd);
    } else if (mode == AddResourceMode::FILE_URI) {
        isWriteSuccess = SendToCacheFile(context, uniqueFd);
    } else {
        context.SaveError(E_FAIL);
        NAPI_ERR_LOG("Unsupported addResource mode");
    }

    if (!isWriteSuccess) {
        NAPI_ERR_LOG("Faild to write cache file");
        return false;
    }
    return SubmitCacheExecute(context);
}

static bool UpdateAssetProperty(MediaAssetChangeRequestAsyncContext& context, string uri,
    DataShare::DataSharePredicates& predicates, DataShare::DataShareValuesBucket& valuesBucket)
{
    MediaLibraryNapiUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri updateAssetUri(uri);
    int32_t changedRows = UserFileClient::Update(updateAssetUri, predicates, valuesBucket);
    if (changedRows < 0) {
        context.SaveError(changedRows);
        NAPI_ERR_LOG("Failed to update property of asset, err: %{public}d", changedRows);
        return false;
    }
    return true;
}

static bool SetFavoriteExecute(MediaAssetChangeRequestAsyncContext& context)
{
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    auto fileAsset = context.objectInfo->GetFileAssetInstance();
    predicates.EqualTo(PhotoColumn::MEDIA_ID, to_string(fileAsset->GetId()));
    valuesBucket.Put(PhotoColumn::MEDIA_IS_FAV, fileAsset->IsFavorite() ? YES : NO);
    return UpdateAssetProperty(context, PAH_UPDATE_PHOTO, predicates, valuesBucket);
}

static bool SetHiddenExecute(MediaAssetChangeRequestAsyncContext& context)
{
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    auto fileAsset = context.objectInfo->GetFileAssetInstance();
    vector<string> assetUriArray(1, fileAsset->GetUri());
    predicates.In(PhotoColumn::MEDIA_ID, assetUriArray);
    valuesBucket.Put(PhotoColumn::MEDIA_HIDDEN, fileAsset->IsHidden() ? YES : NO);
    return UpdateAssetProperty(context, PAH_HIDE_PHOTOS, predicates, valuesBucket);
}

static bool SetTitleExecute(MediaAssetChangeRequestAsyncContext& context)
{
    // In the scenario of creation, the new title will be applied when the asset is created.
    AssetChangeOperation firstOperation = context.assetChangeOperations.front();
    if (firstOperation == AssetChangeOperation::CREATE_FROM_SCRATCH ||
        firstOperation == AssetChangeOperation::CREATE_FROM_URI) {
        return true;
    }

    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    auto fileAsset = context.objectInfo->GetFileAssetInstance();
    predicates.EqualTo(PhotoColumn::MEDIA_ID, to_string(fileAsset->GetId()));
    valuesBucket.Put(PhotoColumn::MEDIA_TITLE, fileAsset->GetTitle());
    return UpdateAssetProperty(context, PAH_UPDATE_PHOTO, predicates, valuesBucket);
}

static bool SetUserCommentExecute(MediaAssetChangeRequestAsyncContext& context)
{
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    auto fileAsset = context.objectInfo->GetFileAssetInstance();
    predicates.EqualTo(PhotoColumn::MEDIA_ID, to_string(fileAsset->GetId()));
    valuesBucket.Put(PhotoColumn::PHOTO_USER_COMMENT, fileAsset->GetUserComment());
    return UpdateAssetProperty(context, PAH_EDIT_USER_COMMENT_PHOTO, predicates, valuesBucket);
}

static bool SetPhotoQualityExecute(MediaAssetChangeRequestAsyncContext& context)
{
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    auto fileAsset = context.objectInfo->GetFileAssetInstance();
    predicates.EqualTo(PhotoColumn::MEDIA_ID, to_string(fileAsset->GetId()));
    std::pair<std::string, int> photoQuality = fileAsset->GetPhotoIdAndQuality();
    valuesBucket.Put(PhotoColumn::PHOTO_ID, photoQuality.first);
    valuesBucket.Put(PhotoColumn::PHOTO_QUALITY, photoQuality.second);
    return UpdateAssetProperty(context, PAH_SET_PHOTO_QUALITY, predicates, valuesBucket);
}

static bool SetLocationExecute(MediaAssetChangeRequestAsyncContext& context)
{
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    auto fileAsset = context.objectInfo->GetFileAssetInstance();
    predicates.EqualTo(PhotoColumn::MEDIA_ID, to_string(fileAsset->GetId()));
    valuesBucket.Put(PhotoColumn::PHOTO_LATITUDE, fileAsset->GetLatitude());
    valuesBucket.Put(PhotoColumn::PHOTO_LONGITUDE, fileAsset->GetLongitude());
    return UpdateAssetProperty(context, PAH_SET_LOCATION, predicates, valuesBucket);
}

static const unordered_map<AssetChangeOperation, bool (*)(MediaAssetChangeRequestAsyncContext&)> EXECUTE_MAP = {
    { AssetChangeOperation::CREATE_FROM_URI, CreateFromFileUriExecute },
    { AssetChangeOperation::GET_WRITE_CACHE_HANDLER, SubmitCacheExecute },
    { AssetChangeOperation::ADD_RESOURCE, AddResourceExecute },
    { AssetChangeOperation::SET_FAVORITE, SetFavoriteExecute },
    { AssetChangeOperation::SET_HIDDEN, SetHiddenExecute },
    { AssetChangeOperation::SET_TITLE, SetTitleExecute },
    { AssetChangeOperation::SET_USER_COMMENT, SetUserCommentExecute },
    { AssetChangeOperation::SET_PHOTO_QUALITY_AND_PHOTOID, SetPhotoQualityExecute },
    { AssetChangeOperation::SET_LOCATION, SetLocationExecute },
};

static void ApplyAssetChangeRequestExecute(napi_env env, void* data)
{
    auto* context = static_cast<MediaAssetChangeRequestAsyncContext*>(data);
    unordered_set<AssetChangeOperation> appliedOperations;
    for (const auto& changeOperation : context->assetChangeOperations) {
        // Keep the final result of each operation, and commit it only once.
        if (appliedOperations.find(changeOperation) != appliedOperations.end()) {
            continue;
        }

        bool valid = false;
        auto iter = EXECUTE_MAP.find(changeOperation);
        if (iter != EXECUTE_MAP.end()) {
            valid = iter->second(*context);
        } else if (changeOperation == AssetChangeOperation::CREATE_FROM_SCRATCH ||
                   changeOperation == AssetChangeOperation::SET_EDIT_DATA) {
            // Perform CREATE_FROM_SCRATCH and SET_EDIT_DATA during GET_WRITE_CACHE_HANDLER or ADD_RESOURCE.
            valid = true;
        } else {
            NAPI_ERR_LOG("Invalid asset change operation: %{public}d", changeOperation);
            context->error = OHOS_INVALID_PARAM_CODE;
            return;
        }

        if (!valid) {
            NAPI_ERR_LOG("Failed to apply asset change request, operation: %{public}d", changeOperation);
            return;
        }
        appliedOperations.insert(changeOperation);
    }
}

static void ApplyAssetChangeRequestCompleteCallback(napi_env env, napi_status status, void* data)
{
    auto* context = static_cast<MediaAssetChangeRequestAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    auto jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    napi_get_undefined(env, &jsContext->data);
    napi_get_undefined(env, &jsContext->error);
    if (context->error == ERR_DEFAULT) {
        jsContext->status = true;
    } else {
        context->HandleError(env, jsContext->error);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(
            env, context->deferred, context->callbackRef, context->work, *jsContext);
    }
    delete context;
}

napi_value MediaAssetChangeRequestNapi::ApplyChanges(napi_env env, napi_callback_info info)
{
    constexpr size_t minArgs = ARGS_ONE;
    constexpr size_t maxArgs = ARGS_TWO;
    auto asyncContext = make_unique<MediaAssetChangeRequestAsyncContext>();
    CHECK_COND_WITH_MESSAGE(env,
        MediaLibraryNapiUtils::AsyncContextGetArgs(env, info, asyncContext, minArgs, maxArgs) == napi_ok,
        "Failed to get args");
    asyncContext->objectInfo = this;

    CHECK_COND_WITH_MESSAGE(env, CheckChangeOperations(env), "Failed to check asset change request operations");
    asyncContext->assetChangeOperations = assetChangeOperations_;
    assetChangeOperations_.clear();
    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "ApplyMediaAssetChangeRequest",
        ApplyAssetChangeRequestExecute, ApplyAssetChangeRequestCompleteCallback);
}
} // namespace OHOS::Media