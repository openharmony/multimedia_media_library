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

#include "media_library_ani.h"

#include <iostream>
#include <string>
#include <array>
#include <mutex>
#include <thread>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "album_operation_uri.h"
#include "ani.h"
#include "ani_class_name.h"
#include "data_secondary_directory_uri.h"
#include "directory_ex.h"
#include "file_asset_ani.h"
#include "form_map.h"
#include "ipc_skeleton.h"
#include "medialibrary_ani_log.h"
#include "medialibrary_tracer.h"
#include "media_app_uri_permission_column.h"
#include "media_app_uri_sensitive_column.h"
#include "media_change_request_ani.h"
#include "medialibrary_ani_utils.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_ani_enum_comm.h"
#include "media_file_utils.h"
#include "media_file_uri.h"
#include "media_ani_native_impl.h"
#include "permission_utils.h"
#include "safe_map.h"
#include "search_column.h"
#include "securec.h"
#include "story_album_column.h"
#include "userfilemgr_uri.h"
#include "userfile_client.h"
#include "vision_column.h"
#include "user_photography_info_column.h"

using namespace OHOS::DataShare;

namespace OHOS {
namespace Media {
using ChangeType = AAFwk::ChangeInfo::ChangeType;
thread_local std::unique_ptr<ChangeListenerAni> g_listObj = nullptr;

static SafeMap<int32_t, std::shared_ptr<ThumbnailBatchGenerateObserver>> thumbnailGenerateObserverMap;
static SafeMap<int32_t, std::shared_ptr<ThumbnailGenerateHandler>> thumbnailGenerateHandlerMap;
static std::atomic<int32_t> requestIdCounter_ = 0;
static std::atomic<int32_t> requestIdCallback_ = 0;

const int32_t SECOND_ENUM = 2;
const int32_t THIRD_ENUM = 3;
const int32_t FORMID_MAX_LEN = 19;
const int64_t MAX_INT64 = 9223372036854775807;
const int32_t MAX_QUERY_LIMIT = 15;
constexpr int32_t DEFAULT_ALBUM_COUNT = 1;

mutex MediaLibraryAni::sUserFileClientMutex_;
mutex MediaLibraryAni::sOnOffMutex_;
mutex ChangeListenerAni::sWorkerMutex_;
string ChangeListenerAni::trashAlbumUri_;

const std::string SUBTYPE = "subType";
const std::string PAH_SUBTYPE = "subtype";
const std::string TITLE = "title";
const std::string CAMERA_SHOT_KEY = "cameraShotKey";
const std::map<std::string, std::string> PHOTO_CREATE_OPTIONS_PARAM = {
    { SUBTYPE, PhotoColumn::PHOTO_SUBTYPE },
    { CAMERA_SHOT_KEY, PhotoColumn::CAMERA_SHOT_KEY },
    { PAH_SUBTYPE, PhotoColumn::PHOTO_SUBTYPE }
};
const std::map<std::string, std::string> CREATE_OPTIONS_PARAM = {
    { TITLE, MediaColumn::MEDIA_TITLE }
};
const std::string EXTENSION = "fileNameExtension";
const std::string PHOTO_TYPE = "photoType";
const std::string PHOTO_SUB_TYPE = "subtype";
const std::string CONFIRM_BOX_BUNDLE_NAME = "bundleName";
const std::string CONFIRM_BOX_APP_NAME = "appName";
const std::string CONFIRM_BOX_APP_ID = "appId";
const std::string TOKEN_ID = "tokenId";

void ChangeListenerAni::OnChange(MediaChangeListener &listener, const ani_ref cbRef)
{
    UvChangeMsg *msg = new (std::nothrow) UvChangeMsg(env_, cbRef, listener.changeInfo, listener.strUri);
    if (msg == nullptr) {
        return;
    }
    if (!listener.changeInfo.uris_.empty()) {
        if (listener.changeInfo.changeType_ == DataShare::DataShareObserver::ChangeType::OTHER) {
            ANI_ERR_LOG("changeInfo.changeType_ is other");
            delete msg;
            return;
        }
        if (msg->changeInfo_.size_ > 0) {
            msg->data_ = (uint8_t *)malloc(msg->changeInfo_.size_);
            if (msg->data_ == nullptr) {
                ANI_ERR_LOG("new msg->data failed");
                delete msg;
                return;
            }
            int copyRet = memcpy_s(msg->data_, msg->changeInfo_.size_, msg->changeInfo_.data_, msg->changeInfo_.size_);
            if (copyRet != 0) {
                ANI_ERR_LOG("Parcel data copy failed, err = %{public}d", copyRet);
            }
        }
    }

    std::thread worker(ExecuteThreadWork, env_, msg);
    worker.join();
    if (msg->data_ != nullptr) {
        free(msg->data_);
    }
    delete msg;
}

void ChangeListenerAni::ExecuteThreadWork(ani_env *env, UvChangeMsg *msg)
{
    lock_guard<mutex> lock(sWorkerMutex_);
    CHECK_NULL_PTR_RETURN_VOID(env, "env is nullptr");
    CHECK_IF_EQUAL(msg != nullptr, "UvChangeMsg is null");

    ani_vm *etsVm {};
    CHECK_IF_EQUAL(env->GetVM(&etsVm) == ANI_OK, "Get etsVm fail");

    ani_env *etsEnv {};
    ani_option interopEnabled {"--interop=disable", nullptr};
    ani_options aniArgs {1, &interopEnabled};
    CHECK_IF_EQUAL(etsVm->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &etsEnv) == ANI_OK, "AttachCurrentThread fail");

    ani_object result = SolveOnChange(etsEnv, msg);
    CHECK_IF_EQUAL(result != nullptr, "SolveOnChange return nullptr");

    std::vector<ani_ref> args = {reinterpret_cast<ani_ref>(result)};
    ani_fn_object callback = static_cast<ani_fn_object>(msg->ref_);
    CHECK_IF_EQUAL(etsEnv->FunctionalObject_Call(callback, args.size(), args.data(), nullptr) == ANI_OK,
        "Failed to execute callback");

    CHECK_IF_EQUAL(etsVm->DetachCurrentThread() == ANI_OK, "DetachCurrentThread fail");
}

static ani_status SetValueInt32(ani_env *env, const char *fieldStr, const int intValue, ani_object &result)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    ani_int value = static_cast<ani_int>(intValue);
    CHECK_STATUS_RET(env->Object_SetPropertyByName_Int(result, fieldStr, value),
        "Set int32 named property error! field: %{public}s", fieldStr);
    return ANI_OK;
}

static ani_status SetValueArray(ani_env *env, const char *fieldStr, const std::list<Uri> list, ani_object &result)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    ani_class cls {};
    static const std::string className = "Lescompat/Array;";
    CHECK_STATUS_RET(env->FindClass(className.c_str(), &cls), "Can't find Lescompat/Array");

    ani_method arrayConstructor {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<ctor>", "I:V", &arrayConstructor),
        "Can't find method <ctor> in Lescompat/Array");

    ani_object aniArray {};
    CHECK_STATUS_RET(env->Object_New(cls, arrayConstructor, &aniArray, list.size()), "New aniArray failed");

    ani_method setMethod {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "$_set", "ILstd/core/Object;:V", &setMethod),
        "Can't find method $_set in Lescompat/Array.");

    ani_int elementIndex = 0;
    for (auto uri : list) {
        ani_string uriRet {};
        CHECK_STATUS_RET(MediaLibraryAniUtils::ToAniString(env, uri.ToString(), uriRet), "ToAniString fail");
        CHECK_STATUS_RET(env->Object_CallMethod_Void(aniArray, setMethod, elementIndex++, uriRet),
            "Call method $_set failed.");
    }
    ani_ref propRef = static_cast<ani_ref>(aniArray);
    CHECK_STATUS_RET(env->Object_SetPropertyByName_Ref(result, fieldStr, propRef),
        "Set array named property error! field: %{public}s", fieldStr);
    return ANI_OK;
}

static string GetFileIdFromUri(const string& uri)
{
    auto startIndex = uri.find(PhotoColumn::PHOTO_URI_PREFIX);
    if (startIndex == std::string::npos) {
        return "";
    }
    auto endIndex = uri.find("/", startIndex + PhotoColumn::PHOTO_URI_PREFIX.length());
    if (endIndex == std::string::npos) {
        return uri.substr(startIndex + PhotoColumn::PHOTO_URI_PREFIX.length());
    }
    return uri.substr(startIndex + PhotoColumn::PHOTO_URI_PREFIX.length(),
        endIndex - startIndex - PhotoColumn::PHOTO_URI_PREFIX.length());
}

static ani_status SetSubUris(ani_env *env, const shared_ptr<MessageParcel> parcel, ani_object &result)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    CHECK_COND_RET(parcel != nullptr, ANI_ERROR, "parcel is nullptr");
    uint32_t len = 0;
    if (!parcel->ReadUint32(len)) {
        ANI_ERR_LOG("Failed to read sub uri list length");
        return ANI_INVALID_ARGS;
    }
    if (len > MAX_QUERY_LIMIT) {
        ANI_ERR_LOG("suburi length exceed the limit.");
        return ANI_INVALID_ARGS;
    }

    ani_class cls {};
    static const std::string className = "Lescompat/Array;";
    CHECK_STATUS_RET(env->FindClass(className.c_str(), &cls), "Can't find Lescompat/Array");

    ani_method arrayConstructor {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<ctor>", "I:V", &arrayConstructor),
        "Can't find method <ctor> in Lescompat/Array");

    ani_object subUriArray {};
    CHECK_STATUS_RET(env->Object_New(cls, arrayConstructor, &subUriArray, len), "New subUriArray failed");

    ani_method setMethod {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "$_set", "ILstd/core/Object;:V", &setMethod),
        "Can't find method $_set in Lescompat/Array.");

    vector<std::string> fileIds;
    for (uint32_t i = 0; i < len; i++) {
        string subUri = parcel->ReadString();
        if (subUri.empty()) {
            ANI_ERR_LOG("Failed to read sub uri");
            return ANI_INVALID_ARGS;
        }
        ani_string subUriRet {};
        CHECK_STATUS_RET(MediaLibraryAniUtils::ToAniString(env, subUri, subUriRet), "ToAniString fail");
        CHECK_STATUS_RET(env->Object_CallMethod_Void(subUriArray, setMethod, static_cast<ani_int>(i), subUriRet),
            "Call method $_set failed.");
        string fileId = GetFileIdFromUri(subUri);
        if (fileId == "") {
            ANI_ERR_LOG("Failed to read sub uri fileId");
            continue;
        }
        fileIds.push_back(fileId);
    }
    ani_ref propRef = static_cast<ani_ref>(subUriArray);
    CHECK_STATUS_RET(env->Object_SetPropertyByName_Ref(result, "extraUris", propRef),
        "Set subUri named property error!");
    return ANI_OK;
}

string ChangeListenerAni::GetTrashAlbumUri()
{
    if (!trashAlbumUri_.empty()) {
        return trashAlbumUri_;
    }
    string queryUri = UFM_QUERY_PHOTO_ALBUM;
    Uri uri(queryUri);
    int errCode = 0;
    DataSharePredicates predicates;
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_SUBTYPE, to_string(PhotoAlbumSubType::TRASH));
    vector<string> columns;
    auto resultSet = UserFileClient::Query(uri, predicates, columns, errCode);
    unique_ptr<FetchResult<PhotoAlbum>> albumSet = make_unique<FetchResult<PhotoAlbum>>(move(resultSet));
    if (albumSet == nullptr) {
        return trashAlbumUri_;
    }
    if (albumSet->GetCount() != 1) {
        return trashAlbumUri_;
    }
    unique_ptr<PhotoAlbum> albumAssetPtr = albumSet->GetFirstObject();
    if (albumAssetPtr == nullptr) {
        return trashAlbumUri_;
    }
    return albumSet->GetFirstObject()->GetAlbumUri();
}

static ani_object CreateChangeDataObject(ani_env *env)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
    ani_class changeDataCls {};
    CHECK_COND_RET(env->FindClass(PAH_ANI_CLASS_CHANGE_DATA_HANDLE.c_str(), &changeDataCls),
        nullptr, " Find ChangeData class fail");

    ani_method changeDataCtor {};
    CHECK_COND_RET(env->Class_FindMethod(changeDataCls, "<ctor>", nullptr, &changeDataCtor),
        nullptr, " Find ChangeData ctor fail");

    ani_object changeDataObj {};
    CHECK_COND_RET(env->Object_New(changeDataCls, changeDataCtor, &changeDataObj),
        nullptr, " New ChangeData object fail");
    return changeDataObj;
}

ani_object ChangeListenerAni::SolveOnChange(ani_env *env, UvChangeMsg *msg)
{
    if (env == nullptr || msg->changeInfo_.uris_.empty()) {
        return nullptr;
    }
    ani_object result = CreateChangeDataObject(env);
    CHECK_COND_RET(result != nullptr, nullptr, "result is nullptr");
    SetValueArray(env, "uris", msg->changeInfo_.uris_, result);

    if (msg->changeInfo_.uris_.size() == DEFAULT_ALBUM_COUNT) {
        if (msg->changeInfo_.uris_.front().ToString().compare(GetTrashAlbumUri()) == 0) {
            if (!MediaLibraryAniUtils::IsSystemApp()) {
                return nullptr;
            }
        }
    }
    if (msg->data_ != nullptr && msg->changeInfo_.size_ > 0) {
        if ((int)msg->changeInfo_.changeType_ == ChangeType::INSERT) {
            SetValueInt32(env, "type", (int)NotifyType::NOTIFY_ALBUM_ADD_ASSET, result);
        } else {
            SetValueInt32(env, "type", (int)NotifyType::NOTIFY_ALBUM_REMOVE_ASSET, result);
        }
        shared_ptr<MessageParcel> parcel = make_shared<MessageParcel>();
        if (parcel->ParseFrom(reinterpret_cast<uintptr_t>(msg->data_), msg->changeInfo_.size_)) {
            ani_status status = SetSubUris(env, parcel, result);
            if (status != ANI_OK) {
                ANI_ERR_LOG("Set subArray named property error! field: subUris");
                return nullptr;
            }
        }
    } else {
        SetValueInt32(env, "type", (int)msg->changeInfo_.changeType_, result);
    }
    return result;
}

MediaLibraryAni::MediaLibraryAni() : env_(nullptr)
{}

MediaLibraryAni::~MediaLibraryAni() = default;

ani_status MediaLibraryAni::UserFileMgrInit(ani_env *env)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    static const char *className = UFM_ANI_CLASS_USER_FILE_MANAGER_HANDLE.c_str();
    ani_class cls;
    ani_status status = env->FindClass(className, &cls);
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to find class: %{public}s", className);
        return status;
    }

    std::array methods = {
        ani_native_function {"getPhotoAssetsSync", nullptr, reinterpret_cast<void *>(GetPhotoAssets)},
        ani_native_function {"releaseSync", nullptr, reinterpret_cast<void *>(Release)},
    };

    status = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to bind native methods to: %{public}s", className);
        return status;
    }
    return ANI_OK;
}

ani_status MediaLibraryAni::PhotoAccessHelperInit(ani_env *env)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    static const char *className = PAH_ANI_CLASS_PHOTO_ACCESS_HELPER_HANDLE.c_str();
    ani_class cls;
    ani_status status = env->FindClass(className, &cls);
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to find class: %{public}s", className);
        return status;
    }

    std::array methods = {
        ani_native_function {"getAssetsSync", nullptr, reinterpret_cast<void *>(GetAssetsSync)},
        ani_native_function {"getFileAssetsInfo", nullptr, reinterpret_cast<void *>(GetFileAssetsInfo)},
        ani_native_function {"getAssetsInner", nullptr, reinterpret_cast<void *>(GetAssetsInner)},
        ani_native_function {"getBurstAssetsInner", nullptr, reinterpret_cast<void *>(GetBurstAssets)},
        ani_native_function {"createAssetSystemInner", nullptr, reinterpret_cast<void *>(CreateAssetSystem)},
        ani_native_function {"createAssetComponentInner", nullptr, reinterpret_cast<void *>(CreateAssetComponent)},
        ani_native_function {"registerChange", nullptr, reinterpret_cast<void *>(PhotoAccessHelperOnCallback)},
        ani_native_function {"unRegisterChange", nullptr, reinterpret_cast<void *>(PhotoAccessHelperOffCallback)},
        ani_native_function {"getAlbumsInner", nullptr, reinterpret_cast<void *>(GetPhotoAlbums)},
        ani_native_function {"createAssetsForAppInner", nullptr,
            reinterpret_cast<void *>(PhotoAccessHelperAgentCreateAssets)},
        ani_native_function {"createAssetsForAppWithModeInner", nullptr,
            reinterpret_cast<void *>(PhotoAccessHelperAgentCreateAssetsWithMode)},
        ani_native_function {"releaseInner", nullptr, reinterpret_cast<void *>(Release)},
        ani_native_function {"applyChangesInner", nullptr, reinterpret_cast<void *>(ApplyChanges)},
        ani_native_function {"getIndexConstructProgressInner", nullptr,
            reinterpret_cast<void *>(PhotoAccessGetIndexConstructProgress)},
        ani_native_function {"grantPhotoUriPermissionInner", nullptr,
            reinterpret_cast<void *>(PhotoAccessGrantPhotoUriPermission)},
        ani_native_function {"saveFormInfoInner", nullptr, reinterpret_cast<void *>(PhotoAccessSaveFormInfo)},
        ani_native_function {"stopThumbnailCreationTask", nullptr,
            reinterpret_cast<void *>(PhotoAccessStopCreateThumbnailTask)},
        ani_native_function {"startCreateThumbnailTask", nullptr,
            reinterpret_cast<void *>(PhotoAccessStartCreateThumbnailTask)},
    };

    status = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to bind native methods to: %{public}s", className);
        return status;
    }
    return ANI_OK;
}

static ani_status ParseArgsGetAssets(ani_env *env, ani_object options, unique_ptr<MediaLibraryAsyncContext> &context)
{
    CHECK_COND_RET(context != nullptr, ANI_ERROR, "context is nullptr");
    /* Parse the first argument */
    CHECK_STATUS_RET(MediaLibraryAniUtils::GetFetchOption(env, options, ASSET_FETCH_OPT, context),
        "invalid predicate");
    auto &predicates = context->predicates;
    switch (context->assetType) {
        case TYPE_AUDIO: {
            CHECK_STATUS_RET(MediaLibraryAniUtils::AddDefaultAssetColumns(env, context->fetchColumn,
                AudioColumn::IsAudioColumn, TYPE_AUDIO), "TYPE_AUDIO: add default asset columns failed");
            break;
        }
        case TYPE_PHOTO: {
            CHECK_STATUS_RET(MediaLibraryAniUtils::AddDefaultAssetColumns(env, context->fetchColumn,
                PhotoColumn::IsPhotoColumn, TYPE_PHOTO), "TYPE_PHOTO: add default asset columns failed");
            break;
        }
        default: {
            AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
            return ANI_ERROR;
        }
    }
    predicates.And()->EqualTo(MediaColumn::MEDIA_DATE_TRASHED, to_string(0));
    predicates.And()->EqualTo(MediaColumn::MEDIA_TIME_PENDING, to_string(0));
    if (context->assetType == TYPE_PHOTO) {
        predicates.And()->EqualTo(MediaColumn::MEDIA_HIDDEN, to_string(0));
        predicates.And()->EqualTo(PhotoColumn::PHOTO_IS_TEMP, to_string(false));
        predicates.EqualTo(PhotoColumn::PHOTO_BURST_COVER_LEVEL,
            to_string(static_cast<int32_t>(BurstCoverLevelType::COVER)));
    }

    return ANI_OK;
}

static void GetPhotoAssetsExecute(ani_env *env, unique_ptr<MediaLibraryAsyncContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "context is nullptr");
    MediaLibraryTracer tracer;
    tracer.Start("JSGetAssetsExecute");

    string queryUri;
    switch (context->assetType) {
        case TYPE_AUDIO: {
            queryUri = UFM_QUERY_AUDIO;
            MediaLibraryAniUtils::UriAppendKeyValue(queryUri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
            break;
        }
        case TYPE_PHOTO: {
            queryUri = UFM_QUERY_PHOTO;
            MediaLibraryAniUtils::UriAppendKeyValue(queryUri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
            break;
        }
        default: {
            context->SaveError(-EINVAL);
            return;
        }
    }

    Uri uri(queryUri);
    int errCode = 0;
    shared_ptr<DataShare::DataShareResultSet> resultSet = UserFileClient::Query(uri,
        context->predicates, context->fetchColumn, errCode);
    if (resultSet == nullptr) {
        context->SaveError(errCode);
        return;
    }
    context->fetchFileResult = make_unique<FetchResult<FileAsset>>(move(resultSet));
    context->fetchFileResult->SetResultNapiType(ResultNapiType::TYPE_USERFILE_MGR);
}

static ani_object GetFileAssetsComplete(ani_env *env, unique_ptr<MediaLibraryAsyncContext> &context)
{
    CHECK_COND_RET(context != nullptr, nullptr, "context is nullptr");
    MediaLibraryTracer tracer;
    tracer.Start("GetFileAssetsAsyncCallbackComplete");

    ani_object fetchRes {};
    ani_object errorObj {};
    if (context->error != ERR_DEFAULT) {
        context->HandleError(env, errorObj);
    } else {
        // Create FetchResult object using the contents of resultSet
        if (context->fetchFileResult == nullptr) {
            ANI_ERR_LOG("No fetch file result found!");
            MediaLibraryAniUtils::CreateAniErrorObject(env, errorObj, ERR_INVALID_OUTPUT,
                "Failed to obtain Fetch File Result");
        }
        fetchRes = FetchFileResultAni::CreateFetchFileResult(env, move(context->fetchFileResult));
        if (fetchRes == nullptr) {
            MediaLibraryAniUtils::CreateAniErrorObject(env, errorObj, ERR_INVALID_OUTPUT,
                "Failed to create ani object for Fetch File Result");
        }
    }
    context.reset();
    return fetchRes;
}

ani_object MediaLibraryAni::GetPhotoAssets(ani_env *env, [[maybe_unused]] ani_object object, ani_object options)
{
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    if (asyncContext == nullptr) {
        AniError::ThrowError(env, JS_INNER_FAIL);
        return nullptr;
    }
    asyncContext->assetType = TYPE_PHOTO;
    if (ANI_OK != ParseArgsGetAssets(env, options, asyncContext)) {
        AniError::ThrowError(env, JS_INNER_FAIL);
        return nullptr;
    }
    GetPhotoAssetsExecute(env, asyncContext);
    return GetFileAssetsComplete(env, asyncContext);
}

static ani_status ParseArgsStartCreateThumbnailTask(ani_env *env, ani_object object, ani_object predicate,
    ani_object callback, unique_ptr<MediaLibraryAsyncContext> &context)
{
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return ANI_ERROR;
    }
    CHECK_COND_RET(context != nullptr, ANI_ERROR, "context is nullptr");
    context->objectInfo = MediaLibraryAni::Unwrap(env, object);
    CHECK_COND_RET(context->objectInfo != nullptr, ANI_INVALID_ARGS, "objectInfo is nullptr");
    // get callback function
    if (callback != nullptr) {
        context->callback = callback;
    }
    
    CHECK_STATUS_RET(MediaLibraryAniUtils::ParsePredicates(env, predicate, context, ASSET_FETCH_OPT),
        "invalid predicate");
    return ANI_OK;
}

static void RegisterThumbnailGenerateObserver(ani_env *env,
    std::unique_ptr<MediaLibraryAsyncContext> &asyncContext, int32_t requestId)
{
    std::shared_ptr<ThumbnailBatchGenerateObserver> dataObserver;
    CHECK_NULL_PTR_RETURN_VOID(dataObserver, "dataObserver is nullptr");
    if (thumbnailGenerateObserverMap.Find(requestId, dataObserver)) {
        ANI_INFO_LOG("RequestId: %{public}d exist in observer map, no need to register", requestId);
        return;
    }
    dataObserver = std::make_shared<ThumbnailBatchGenerateObserver>();
    std::string observerUri = PhotoColumn::PHOTO_URI_PREFIX + std::to_string(requestId);
    UserFileClient::RegisterObserverExt(Uri(observerUri), dataObserver, false);
    thumbnailGenerateObserverMap.Insert(requestId, dataObserver);
}

static void UnregisterThumbnailGenerateObserver(int32_t requestId)
{
    std::shared_ptr<ThumbnailBatchGenerateObserver> dataObserver;
    CHECK_NULL_PTR_RETURN_VOID(dataObserver, "dataObserver is nullptr");
    if (!thumbnailGenerateObserverMap.Find(requestId, dataObserver)) {
        ANI_DEBUG_LOG("UnregisterThumbnailGenerateObserver with RequestId: %{public}d not exist in observer map",
            requestId);
        return;
    }

    std::string observerUri = PhotoColumn::PHOTO_URI_PREFIX + std::to_string(requestId);
    UserFileClient::UnregisterObserverExt(Uri(observerUri), dataObserver);
    thumbnailGenerateObserverMap.Erase(requestId);
}

static void DeleteThumbnailHandler(int32_t requestId)
{
    std::shared_ptr<ThumbnailGenerateHandler> dataHandler;
    CHECK_NULL_PTR_RETURN_VOID(dataHandler, "dataHandler is nullptr");
    if (!thumbnailGenerateHandlerMap.Find(requestId, dataHandler)) {
        ANI_DEBUG_LOG("DeleteThumbnailHandler with RequestId: %{public}d not exist in handler map", requestId);
        return;
    }
    thumbnailGenerateHandlerMap.Erase(requestId);
}

static void ReleaseThumbnailTask(int32_t requestId)
{
    UnregisterThumbnailGenerateObserver(requestId);
    DeleteThumbnailHandler(requestId);
}

static void CreateThumbnailHandler(ani_env *env, std::unique_ptr<MediaLibraryAsyncContext> &asyncContext,
    int32_t requestId)
{
    ani_object callback = asyncContext->callback;
    ThreadFunciton threadSafeFunc = MediaLibraryAni::OnThumbnailGenerated;

    std::shared_ptr<ThumbnailGenerateHandler> dataHandler =
        std::make_shared<ThumbnailGenerateHandler>(callback, threadSafeFunc);
    CHECK_NULL_PTR_RETURN_VOID(dataHandler, "dataHandler is nullptr");
    thumbnailGenerateHandlerMap.Insert(requestId, dataHandler);
}

void MediaLibraryAni::OnThumbnailGenerated(ani_env *env, ani_object callback, void *context, void *data)
{
    if (env == nullptr) {
        return;
    }
    std::shared_ptr<ThumbnailGenerateHandler> dataHandler;
    CHECK_NULL_PTR_RETURN_VOID(dataHandler, "dataHandler is nullptr");
    if (!thumbnailGenerateHandlerMap.Find(requestIdCallback_, dataHandler)) {
        return;
    }

    // calling onDataPrepared
    ani_vm *etsVm;
    ani_env *etsEnv;
    [[maybe_unused]] int res = env->GetVM(&etsVm);
    if (res != ANI_OK) {
        return;
    }
    ani_option interopEnabled {"--interop=disable", nullptr};
    ani_options aniArgs {1, &interopEnabled};
    if (ANI_OK != etsVm->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &etsEnv)) {
        return;
    }
    auto fnObject = reinterpret_cast<ani_fn_object>(static_cast<ani_ref>(callback));
    const std::string str = "AsyncWorkName:ThumbSafeThread";
    ani_string arg1 = {};
    if (ANI_OK != etsEnv->String_NewUTF8(str.c_str(), str.size(), &arg1)) {
        return;
    }
    std::vector<ani_ref> args = {reinterpret_cast<ani_ref>(arg1)};

    ani_ref result;
    if (ANI_OK != etsEnv->FunctionalObject_Call(fnObject, args.size(), args.data(), &result)) {
        return;
    }
    if (ANI_OK != etsVm->DetachCurrentThread()) {
        return;
    }
}

static int32_t AssignRequestId()
{
    return ++requestIdCounter_;
}

static int32_t GetRequestId()
{
    return requestIdCounter_;
}

ani_int MediaLibraryAni::PhotoAccessStartCreateThumbnailTask([[maybe_unused]] ani_env *env,
    [[maybe_unused]] ani_object object, ani_object predicate)
{
    ani_object callback = nullptr;
    std::unique_ptr<MediaLibraryAsyncContext> asyncContext = std::make_unique<MediaLibraryAsyncContext>();
    CHECK_COND_RET(asyncContext != nullptr, ANI_INVALID_ARGS, "asyncContext is nullptr");
    CHECK_COND_WITH_RET_MESSAGE(env,
        ParseArgsStartCreateThumbnailTask(env, object, predicate, callback, asyncContext) == ANI_OK,
        ANI_INVALID_ARGS, "ParseArgsStartCreateThumbnailTask error");
    
    ReleaseThumbnailTask(GetRequestId());
    int32_t requestId = AssignRequestId();
    RegisterThumbnailGenerateObserver(env, asyncContext, requestId);
    CreateThumbnailHandler(env, asyncContext, requestId);

    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(THUMBNAIL_BATCH_GENERATE_REQUEST_ID, requestId);
    string updateUri = PAH_START_GENERATE_THUMBNAILS;
    MediaLibraryAniUtils::UriAppendKeyValue(updateUri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri uri(updateUri);
    int changedRows = UserFileClient::Update(uri, asyncContext->predicates, valuesBucket);
    if (changedRows < 0) {
        ReleaseThumbnailTask(requestId);
        asyncContext->SaveError(changedRows);
        ANI_ERR_LOG("Create thumbnail task, update failed, err: %{public}d", changedRows);
        return changedRows;
    }
    return requestId;
}

void ThumbnailBatchGenerateObserver::OnChange(const ChangeInfo &changeInfo)
{
    if (changeInfo.changeType_ != static_cast<int32_t>(NotifyType::NOTIFY_THUMB_ADD)) {
        return;
    }

    for (auto &uri : changeInfo.uris_) {
        string uriString = uri.ToString();
        auto pos = uriString.find_last_of('/');
        if (pos == std::string::npos) {
            continue;
        }

        try {
            requestIdCallback_ = std::stoi(uriString.substr(pos + 1));
        } catch (const std::invalid_argument& e) {
            ANI_ERR_LOG("Invalid argument: %{public}s", e.what());
            continue;
        } catch (const std::out_of_range& e) {
            ANI_ERR_LOG("Out of range: %{public}s", e.what());
            continue;
        }

        std::shared_ptr<ThumbnailGenerateHandler> dataHandler;
        if (!thumbnailGenerateHandlerMap.Find(requestIdCallback_, dataHandler)) {
            continue;
        }
        // napi_call_threadsafe_function
    }
}

static ani_status ParseArgsStopCreateThumbnailTask(ani_env *env, ani_object object,
    unique_ptr<MediaLibraryAsyncContext> &context)
{
    CHECK_COND_RET(context != nullptr, ANI_ERROR, "context is nullptr");
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return ANI_ERROR;
    }

    context->objectInfo = MediaLibraryAni::Unwrap(env, object);
    CHECK_COND_RET(context->objectInfo != nullptr, ANI_INVALID_ARGS, "objectInfo is nullptr");
    return ANI_OK;
}

void MediaLibraryAni::PhotoAccessStopCreateThumbnailTask([[maybe_unused]] ani_env *env,
    [[maybe_unused]] ani_object object, ani_double taskId)
{
    ANI_DEBUG_LOG("PhotoAccessStopCreateThumbnailTask with taskId: %{public}d", static_cast<int32_t>(taskId));
    std::unique_ptr<MediaLibraryAsyncContext> asyncContext = std::make_unique<MediaLibraryAsyncContext>();
    CHECK_NULL_PTR_RETURN_VOID(asyncContext, "asyncContext is nullptr");

    if (ParseArgsStopCreateThumbnailTask(env, object, asyncContext) != ANI_OK) {
        ANI_ERR_LOG("ParseArgsStopCreateThumbnailTask error");
        return;
    }

    int32_t requestId = static_cast<int32_t>(taskId);
    if (requestId <= 0) {
        ANI_ERR_LOG("PhotoAccessStopCreateThumbnailTask with Invalid requestId: %{public}d", requestId);
        return;
    }

    ReleaseThumbnailTask(requestId);

    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(THUMBNAIL_BATCH_GENERATE_REQUEST_ID, requestId);
    string updateUri = PAH_STOP_GENERATE_THUMBNAILS;
    MediaLibraryAniUtils::UriAppendKeyValue(updateUri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri uri(updateUri);
    int changedRows = UserFileClient::Update(uri, asyncContext->predicates, valuesBucket);
    if (changedRows < 0) {
        asyncContext->SaveError(changedRows);
        ANI_ERR_LOG("Stop create thumbnail task, update failed, err: %{public}d", changedRows);
    }
    ANI_DEBUG_LOG("MediaLibraryAni::PhotoAccessStopCreateThumbnailTask Finished");
}

ani_object MediaLibraryAni::GetFileAssetsInfo([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object,
    ani_object options)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
    MediaLibraryTracer tracer;
    tracer.Start("GetFileAssetsInfo");
    ANI_DEBUG_LOG("GetFileAssetsInfo start");

    ani_ref fetchColumns;
    if (ANI_OK != env->Object_GetPropertyByName_Ref(options, "fetchColumns", &fetchColumns)) {
        ANI_ERR_LOG("get fieldname fetchCloumns failed");
        return nullptr;
    }
    std::vector<std::string> fetchColumnsVec;
    if (ANI_OK != MediaLibraryAniUtils::GetStringArray(env, (ani_object)fetchColumns, fetchColumnsVec)) {
        ANI_ERR_LOG("GetStringArray failed");
        return nullptr;
    }

    ani_ref predicates;
    if (ANI_OK != env->Object_GetPropertyByName_Ref(options, "predicates", &predicates)) {
        ANI_ERR_LOG("get fieldname predicates failed");
        return nullptr;
    }
    DataSharePredicates* predicate = MediaLibraryAniUtils::UnwrapPredicate(env, (ani_object)predicates);
    if (predicate == nullptr) {
        ANI_ERR_LOG("UnwrapPredicate failed");
        return nullptr;
    }

    std::vector<std::unique_ptr<FileAsset>> fileAssetArray = MediaAniNativeImpl::GetFileAssetsInfo(fetchColumnsVec,
        predicate);

    ani_object result = nullptr;
    if (ANI_OK != MediaLibraryAniUtils::ToFileAssetInfoAniArray(env, fileAssetArray, result)) {
        ANI_ERR_LOG("MediaLibraryAniUtils::ToFileAssetInfoAniArray failed");
    }

    ANI_DEBUG_LOG("GetFileAssetsInfo end");
    return result;
}

ani_object MediaLibraryAni::GetAssetsSync([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object,
    ani_object options)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
    MediaLibraryTracer tracer;
    tracer.Start("GetAssetsSync");
    ANI_DEBUG_LOG("GetAssetsSync start");

    ani_ref fetchColumns;
    if (ANI_OK != env->Object_GetPropertyByName_Ref(options, "fetchColumns", &fetchColumns)) {
        ANI_ERR_LOG("get fieldname fetchCloumns failed");
        return nullptr;
    }
    std::vector<std::string> fetchColumnsVec;
    if (ANI_OK != MediaLibraryAniUtils::GetStringArray(env, (ani_object)fetchColumns, fetchColumnsVec)) {
        ANI_ERR_LOG("GetStringArray failed");
        return nullptr;
    }

    ani_ref predicates;
    if (ANI_OK != env->Object_GetPropertyByName_Ref(options, "predicates", &predicates)) {
        ANI_ERR_LOG("get fieldname predicates failed");
        return nullptr;
    }
    DataSharePredicates* predicate = MediaLibraryAniUtils::UnwrapPredicate(env, (ani_object)predicates);
    if (predicate == nullptr) {
        ANI_ERR_LOG("UnwrapPredicate failed");
        return nullptr;
    }
    std::vector<std::unique_ptr<FileAsset>> fileAssetArray = MediaAniNativeImpl::GetAssetsSync(fetchColumnsVec,
        predicate);

    ani_object result = nullptr;
    if (ANI_OK != MediaLibraryAniUtils::ToFileAssetAniArray(env, fileAssetArray, result)) {
        ANI_ERR_LOG("MediaLibraryAniUtils::ToFileAssetAniArray failed");
    }

    ANI_DEBUG_LOG("GetAssetsSync end");
    return result;
}

ani_object MediaLibraryAni::GetAssetsInner([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object,
    ani_object options)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
    MediaLibraryTracer tracer;
    tracer.Start("GetAssets");
    ANI_DEBUG_LOG("GetAssetsInner start");

    ani_ref fetchColumns;
    if (ANI_OK != env->Object_GetPropertyByName_Ref(options, "fetchColumns", &fetchColumns)) {
        ANI_ERR_LOG("get fieldname fetchCloumns failed");
        return nullptr;
    }
    std::vector<std::string> fetchColumnsVec;
    if (ANI_OK != MediaLibraryAniUtils::GetStringArray(env, (ani_object)fetchColumns, fetchColumnsVec)) {
        ANI_ERR_LOG("GetStringArray failed");
        return nullptr;
    }

    ani_ref predicates;
    if (ANI_OK != env->Object_GetPropertyByName_Ref(options, "predicates", &predicates)) {
        ANI_ERR_LOG("get fieldname predicates failed");
        return nullptr;
    }
    DataSharePredicates* predicate = MediaLibraryAniUtils::UnwrapPredicate(env, (ani_object)predicates);
    if (predicate == nullptr) {
        ANI_ERR_LOG("UnwrapPredicate failed");
        return nullptr;
    }
    std::unique_ptr<FetchResult<FileAsset>> fileAsset = MediaAniNativeImpl::GetAssets(fetchColumnsVec, predicate);

    ani_object result = nullptr;
    if (ANI_OK != MediaLibraryAniUtils::ToFileAssetAniPtr(env, std::move(fileAsset), result)) {
        ANI_ERR_LOG("MediaLibraryAniUtils::ToFileAssetAniPtr failed");
    }

    ANI_DEBUG_LOG("GetAssetsInner end");
    return result;
}

bool InitUserFileClient(ani_env *env, [[maybe_unused]] ani_object context, bool isAsync = false)
{
    if (!isAsync) {
        std::unique_lock<std::mutex> helperLock(MediaLibraryAni::sUserFileClientMutex_);
        if (!UserFileClient::IsValid()) {
            UserFileClient::Init(env, context);
            if (!UserFileClient::IsValid()) {
                ANI_ERR_LOG("UserFileClient creation failed");
                helperLock.unlock();
                return false;
            }
        }
        helperLock.unlock();
    }
    return true;
}

static int32_t GetUserIdFromContext(unique_ptr<MediaLibraryAsyncContext> &context)
{
    CHECK_COND_RET(context != nullptr, E_FAIL, "context is nullptr");
    CHECK_COND_RET(context->objectInfo != nullptr, E_FAIL, "context->objectInfo is nullptr");
    return context->objectInfo->GetUserId();
}

static int32_t ParseUserIdFormCbInfo(ani_env *env, ani_object userIdObject)
{
    CHECK_COND_RET(env != nullptr, E_FAIL, "env is nullptr");
    ani_boolean isUndefined {};
    env->Reference_IsUndefined(userIdObject, &isUndefined);
    int userId = -1;
    if (isUndefined) {
        ANI_DEBUG_LOG("userIdObject is undefined");
        return userId;
    }
    ani_double result;
    ani_class doubleClass;
    env->FindClass("Lstd/core/Double;", &doubleClass);
    ani_boolean isDouble;
    env->Object_InstanceOf(userIdObject, doubleClass, &isDouble);
    if (!isDouble) {
        ANI_DEBUG_LOG("userIdObject is not a double");
        return userId;
    }
    if (ANI_OK !=env->Object_CallMethodByName_Double(userIdObject, "unboxed", nullptr, &result)) {
        ANI_DEBUG_LOG("userId is undefined");
        return userId;
    }
    userId = static_cast<int>(result);
    return userId;
}

static ani_status CheckWhetherAsync(ani_env *env, ani_object userIdObject, bool &isAsync)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    isAsync = false;
    ani_status status = ANI_OK;
    ani_boolean isUndefined;
    env->Reference_IsUndefined(userIdObject, &isUndefined);
    if (isUndefined) {
        ANI_DEBUG_LOG("CheckWhetherAsync userIdObject is undefined");
        return ANI_OK;
    } else {
        ani_class doubleClass;
        status = env->FindClass("Lstd/core/Double;", &doubleClass);
        ani_boolean isDouble;
        status = env->Object_InstanceOf(userIdObject, doubleClass, &isDouble);
        if (isDouble) {
            return ANI_OK;
        }
        ani_class booleanClass;
        status = env->FindClass("Lstd/core/Boolean;", &booleanClass);
        ani_boolean isBoolean;
        status = env->Object_InstanceOf(userIdObject, booleanClass, &isBoolean);
        if (isBoolean) {
            isAsync = true;
        }
        ani_boolean isAsyncBoolean;
        status = env->Object_CallMethodByName_Boolean(userIdObject, "unboxed", nullptr, &isAsyncBoolean);
        isAsync = static_cast<bool>(isAsyncBoolean);
        return status;
    }
    ANI_ERR_LOG("parameter is invalid");
    return ANI_INVALID_ARGS;
}

ani_object MediaLibraryAni::Constructor(ani_env *env, ani_class clazz, ani_object context, ani_object userIdObject)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
    CHECK_COND_RET(context != nullptr, nullptr, "context is nullptr");
    ani_object result = nullptr;
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAcessHelperAniConstructor");
    int32_t userId = ParseUserIdFormCbInfo(env, userIdObject);
    UserFileClient::SetUserId(userId);
    std::unique_ptr<MediaLibraryAni> nativeHandle = std::make_unique<MediaLibraryAni>();
    if (nativeHandle == nullptr) {
        ANI_ERR_LOG("nativeHandle is nullptr");
        return result;
    }

    nativeHandle->env_ = env;
    nativeHandle->SetUserId(userId);
    // Initialize the ChangeListener object
    if (g_listObj == nullptr) {
        g_listObj = std::make_unique<ChangeListenerAni>(env);
    }

    bool isAsync = false;
    CheckWhetherAsync(env, userIdObject, isAsync);
    if (!InitUserFileClient(env, context, isAsync)) {
        ANI_ERR_LOG("Constructor InitUserFileClient failed");
        return result;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(clazz, "<ctor>", "J:V", &ctor)) {
        ANI_ERR_LOG("Failed to find method: %{public}s", "ctor");
        return result;
    }

    if (ANI_OK !=env->Object_New(clazz, ctor, &result, reinterpret_cast<ani_long>(nativeHandle.release()))) {
        ANI_ERR_LOG("New PhotoAccessHelper Fail");
    }
    return result;
}

ani_object MediaLibraryAni::Constructor(ani_env *env, ani_class clazz, ani_object context)
{
    CHECK_COND_RET(context != nullptr, nullptr, "context is nullptr");
    ani_object result = nullptr;
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAcessHelperAniConstructor");
    std::unique_ptr<MediaLibraryAni> nativeHandle = std::make_unique<MediaLibraryAni>();
    if (nativeHandle == nullptr) {
        ANI_ERR_LOG("nativeHandle is nullptr");
        return result;
    }

    nativeHandle->env_ = env;
    // Initialize the ChangeListener object
    if (g_listObj == nullptr) {
        g_listObj = std::make_unique<ChangeListenerAni>(env);
    }

    bool isAsync = true;
    if (!InitUserFileClient(env, context, isAsync)) {
        ANI_ERR_LOG("Constructor InitUserFileClient failed");
        return result;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(clazz, "<ctor>", "J:V", &ctor)) {
        ANI_ERR_LOG("Failed to find method: %{public}s", "ctor");
        return result;
    }

    if (ANI_OK !=env->Object_New(clazz, ctor, &result, reinterpret_cast<ani_long>(nativeHandle.release()))) {
        ANI_ERR_LOG("New PhotoAccessHelper Fail");
    }
    return result;
}

MediaLibraryAni* MediaLibraryAni::Unwrap(ani_env *env, ani_object object)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
    ani_long photoAccessHelperLong;
    auto status = env->Object_GetFieldByName_Long(object, "nativeHandle", &photoAccessHelperLong);
    if (ANI_OK != status || photoAccessHelperLong == 0) {
        ANI_ERR_LOG("GetAllPhotoAssetHandleObjects nullptr");
        return nullptr;
    }
    return reinterpret_cast<MediaLibraryAni*>(photoAccessHelperLong);
}

ani_object MediaLibraryAni::GetUserFileMgr(ani_env *env, ani_object context)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
    MediaLibraryTracer tracer;
    tracer.Start("getUserFileManager");

    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "Only system apps can get userFileManger instance");
        return nullptr;
    }

    static const char *className = UFM_ANI_CLASS_USER_FILE_MANAGER_HANDLE.c_str();
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        ANI_ERR_LOG("Failed to find class: %{public}s", className);
        return nullptr;
    }

    return Constructor(env, cls, context);
}

ani_object MediaLibraryAni::CreateNewInstance(ani_env *env, ani_class clazz, ani_object context,
    ani_object userIdObject, bool isAsync)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
    constexpr size_t ARG_CONTEXT = 1;
    constexpr size_t ARGS_TWO = 2;
    size_t argc = ARG_CONTEXT;
    ani_boolean isUndefined;
    env->Reference_IsUndefined(userIdObject, &isUndefined);
    if (!isUndefined) {
        argc = ARGS_TWO;
    }
    ani_status status = ANI_OK;
    if (isAsync) {
        argc = ARGS_TWO;
        status = MediaLibraryAniUtils::ToAniBooleanObject(env, true, userIdObject);
        if (status != ANI_OK) {
            ANI_ERR_LOG("ToAniBooleanObject failed");
            return nullptr;
        }
    }
    int32_t userId = -1;
    if (argc > 1 && !isAsync) {
        argc = ARGS_TWO;
        ani_class doubleClass;
        env->FindClass("Lstd/core/Double;", &doubleClass);
        ani_boolean isDouble;
        env->Object_InstanceOf(userIdObject, doubleClass, &isDouble);
        if (isDouble) {
            ani_double result;
            env->Object_CallMethodByName_Double(userIdObject, "unboxed", nullptr, &result);
            userId = static_cast<int>(result);
            if (userId != -1 && !MediaLibraryAniUtils::IsSystemApp()) {
                ANI_ERR_LOG("CreateNewInstance failed, target is not system app");
                return nullptr;
            }
            UserFileClient::SetUserId(userId);
            ANI_INFO_LOG("CreateNewInstance for other user is %{public}d", userId);
        }
    }
    ani_object result = nullptr;
    result = Constructor(env, clazz, context, userIdObject);
    return result;
}

ani_object MediaLibraryAni::GetPhotoAccessHelperInner(ani_env *env, ani_object context, ani_object userId)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
    MediaLibraryTracer tracer;
    tracer.Start("GetPhotoAccessHelper");

    static const char *className = PAH_ANI_CLASS_PHOTO_ACCESS_HELPER_HANDLE.c_str();
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        ANI_ERR_LOG("Failed to find class: %{public}s", className);
        return nullptr;
    }

    return CreateNewInstance(env, cls, context, userId);
}

static bool ParseLocationAlbumTypes(unique_ptr<MediaLibraryAsyncContext> &context, const int32_t albumSubType)
{
    CHECK_COND_RET(context != nullptr, false, "context is nullptr");
    if (albumSubType == PhotoAlbumSubType::GEOGRAPHY_LOCATION) {
        context->isLocationAlbum = PhotoAlbumSubType::GEOGRAPHY_LOCATION;
        context->fetchColumn.insert(context->fetchColumn.end(),
            PhotoAlbumColumns::LOCATION_DEFAULT_FETCH_COLUMNS.begin(),
            PhotoAlbumColumns::LOCATION_DEFAULT_FETCH_COLUMNS.end());
        MediaLibraryAniUtils::GetAllLocationPredicates(context->predicates);
        return false;
    } else if (albumSubType == PhotoAlbumSubType::GEOGRAPHY_CITY) {
        context->fetchColumn = PhotoAlbumColumns::CITY_DEFAULT_FETCH_COLUMNS;
        context->isLocationAlbum = PhotoAlbumSubType::GEOGRAPHY_CITY;
        string onClause = PhotoAlbumColumns::ALBUM_NAME  + " = " + CITY_ID;
        context->predicates.InnerJoin(GEO_DICTIONARY_TABLE)->On({ onClause });
        context->predicates.NotEqualTo(PhotoAlbumColumns::ALBUM_COUNT, to_string(0));
    }
    return true;
}

static ani_status ParseAlbumTypes(ani_env *env, ani_enum_item albumTypeItem, ani_enum_item albumSubtype,
    std::unique_ptr<MediaLibraryAsyncContext>& context)
{
    CHECK_COND_RET(context != nullptr, ANI_ERROR, "context is nullptr");
    /* Parse the first argument to photo album type */
    AlbumType albumType;
    int32_t albumTypeInt;
    CHECK_COND_WITH_RET_MESSAGE(env, MediaLibraryEnumAni::EnumGetValueInt32(env, albumTypeItem,
        albumTypeInt) == ANI_OK, ANI_INVALID_ARGS, "Failed to get albumType");
    albumType = static_cast<AlbumType>(albumTypeInt);
    if (!PhotoAlbum::CheckPhotoAlbumType(static_cast<PhotoAlbumType>(albumTypeInt))) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return ANI_ERROR;
    }
    context->isAnalysisAlbum = (albumTypeInt == PhotoAlbumType::SMART) ? 1 : 0;

    /* Parse the second argument to photo album subType */
    PhotoAlbumSubType photoAlbumSubType;
    int32_t albumSubTypeInt;
    CHECK_COND_WITH_RET_MESSAGE(env, MediaLibraryEnumAni::EnumGetValueInt32(env, albumSubtype,
        albumSubTypeInt) == ANI_OK, ANI_INVALID_ARGS, "Failed to get albumSubtype");
    photoAlbumSubType = static_cast<PhotoAlbumSubType>(albumSubTypeInt);
    if (!PhotoAlbum::CheckPhotoAlbumSubType(static_cast<PhotoAlbumSubType>(albumSubTypeInt))) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return ANI_ERROR;
    }

    if (!ParseLocationAlbumTypes(context, albumSubTypeInt)) {
        return ANI_OK;
    }

    context->predicates.And()->EqualTo(PhotoAlbumColumns::ALBUM_TYPE, to_string(albumTypeInt));
    if (albumSubTypeInt != ANY) {
        context->predicates.And()->EqualTo(PhotoAlbumColumns::ALBUM_SUBTYPE, to_string(albumSubTypeInt));
    }
    if (albumSubTypeInt == PhotoAlbumSubType::SHOOTING_MODE || albumSubTypeInt == PhotoAlbumSubType::GEOGRAPHY_CITY) {
        context->predicates.OrderByDesc(PhotoAlbumColumns::ALBUM_COUNT);
    }
    if (albumSubTypeInt == PhotoAlbumSubType::HIGHLIGHT ||
        albumSubTypeInt == PhotoAlbumSubType::HIGHLIGHT_SUGGESTIONS) {
        context->isHighlightAlbum = albumSubTypeInt;
        vector<string> onClause = {
            ANALYSIS_ALBUM_TABLE + "." + PhotoAlbumColumns::ALBUM_ID + " = " +
            HIGHLIGHT_ALBUM_TABLE + "." + PhotoAlbumColumns::ALBUM_ID,
        };
        if (albumSubTypeInt == PhotoAlbumSubType::HIGHLIGHT_SUGGESTIONS) {
            onClause = {
                ANALYSIS_ALBUM_TABLE + "." + PhotoAlbumColumns::ALBUM_ID + " = " +
                HIGHLIGHT_ALBUM_TABLE + "." + AI_ALBUM_ID,
            };
        }
        context->predicates.InnerJoin(HIGHLIGHT_ALBUM_TABLE)->On(onClause);
        context->predicates.OrderByDesc(MAX_DATE_ADDED + ", " + GENERATE_TIME);
    }
    return ANI_OK;
}

static void RestrictAlbumSubtypeOptions(unique_ptr<MediaLibraryAsyncContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "context is nullptr");
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        context->predicates.And()->In(PhotoAlbumColumns::ALBUM_SUBTYPE, vector<string>({
            to_string(PhotoAlbumSubType::USER_GENERIC),
            to_string(PhotoAlbumSubType::FAVORITE),
            to_string(PhotoAlbumSubType::VIDEO),
            to_string(PhotoAlbumSubType::IMAGE),
        }));
    } else {
        context->predicates.And()->NotEqualTo(PhotoAlbumColumns::ALBUM_SUBTYPE, to_string(PhotoAlbumSubType::HIDDEN));
    }
}

static ani_status AddDefaultPhotoAlbumColumns(ani_env *env, vector<string> &fetchColumn)
{
    auto validFetchColumns = PhotoAlbumColumns::DEFAULT_FETCH_COLUMNS;
    for (const auto &column : fetchColumn) {
        if (PhotoAlbumColumns::IsPhotoAlbumColumn(column)) {
            validFetchColumns.insert(column);
        } else if (column.compare(MEDIA_DATA_DB_URI) == 0) {
            // uri is default property of album
            continue;
        } else {
            ANI_ERR_LOG("unknown columns:%{public}s", column.c_str());
            AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
            return ANI_ERROR;
        }
    }
    fetchColumn.assign(validFetchColumns.begin(), validFetchColumns.end());
    return ANI_OK;
}

static void AddDefaultColumnsForNonAnalysisAlbums(unique_ptr<MediaLibraryAsyncContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "context is nullptr");
    if (!context->isAnalysisAlbum) {
        context->fetchColumn.push_back(PhotoAlbumColumns::ALBUM_IMAGE_COUNT);
        context->fetchColumn.push_back(PhotoAlbumColumns::ALBUM_VIDEO_COUNT);
        context->fetchColumn.push_back(PhotoAlbumColumns::ALBUM_LPATH);
        context->fetchColumn.push_back(PhotoAlbumColumns::ALBUM_DATE_ADDED);
    }
}

static ani_status GetAlbumFetchOption(ani_env *env, unique_ptr<MediaLibraryAsyncContext> &context,
    ani_object fetchOptions)
{
    CHECK_COND_RET(context != nullptr, ANI_ERROR, "context is nullptr");
    CHECK_COND_WITH_RET_MESSAGE(env, MediaLibraryAniUtils::GetFetchOption(env, fetchOptions,
        ALBUM_FETCH_OPT, context) == ANI_OK, ANI_INVALID_ARGS, "GetAlbumFetchOption error");
    if (!context->uri.empty()) {
        if (context->uri.find(PhotoAlbumColumns::ANALYSIS_ALBUM_URI_PREFIX) != std::string::npos) {
            context->isAnalysisAlbum = 1; // 1:is an analysis album
        }
    }
    return ANI_OK;
}

static ani_status ParseArgsGetPhotoAlbum(ani_env *env, ani_enum_item albumTypeItem, ani_enum_item albumSubtypeItem,
    ani_object fetchOptions, std::unique_ptr<MediaLibraryAsyncContext>& context)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    CHECK_COND_RET(context != nullptr, ANI_ERROR, "context is nullptr");
    // Parse fetchOptions if exists.
    ani_boolean isUndefined;
    env->Reference_IsUndefined(fetchOptions, &isUndefined);
    if (!isUndefined) {
        CHECK_COND_WITH_RET_MESSAGE(env, GetAlbumFetchOption(env, context, fetchOptions) == ANI_OK,
            ANI_INVALID_ARGS, "GetAlbumFetchOption error");
    } else {
        ANI_INFO_LOG("fetchOptions is undefined. There is no need to parse fetchOptions.");
    }
    // Parse albumType and albumSubtype
    CHECK_COND_WITH_RET_MESSAGE(env, ParseAlbumTypes(env, albumTypeItem, albumSubtypeItem,
        context) == ANI_OK, ANI_INVALID_ARGS, "ParseAlbumTypes error");
    RestrictAlbumSubtypeOptions(context);
    if (context->isLocationAlbum != PhotoAlbumSubType::GEOGRAPHY_LOCATION &&
        context->isLocationAlbum != PhotoAlbumSubType::GEOGRAPHY_CITY) {
        CHECK_COND_WITH_RET_MESSAGE(env, AddDefaultPhotoAlbumColumns(env, context->fetchColumn) == ANI_OK,
            ANI_INVALID_ARGS, "AddDefaultPhotoAlbumColumns error");
        AddDefaultColumnsForNonAnalysisAlbums(context);
        if (context->isHighlightAlbum) {
            context->fetchColumn.erase(std::remove(context->fetchColumn.begin(), context->fetchColumn.end(),
                PhotoAlbumColumns::ALBUM_ID), context->fetchColumn.end());
            context->fetchColumn.push_back(ANALYSIS_ALBUM_TABLE + "." + PhotoAlbumColumns::ALBUM_ID + " AS " +
            PhotoAlbumColumns::ALBUM_ID);
        }
    }
    return ANI_OK;
}

static void GetPhotoAlbumsExecute(ani_env *env, unique_ptr<MediaLibraryAsyncContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "context is nullptr");
    MediaLibraryTracer tracer;
    tracer.Start("GetPhotoAlbumsExecute");

    string queryUri;
    if (context->hiddenOnly || context->hiddenAlbumFetchMode == ASSETS_MODE) {
        queryUri = (context->resultNapiType == ResultNapiType::TYPE_USERFILE_MGR) ?
            UFM_QUERY_HIDDEN_ALBUM : PAH_QUERY_HIDDEN_ALBUM;
    } else if (context->isAnalysisAlbum) {
        queryUri = context->isLocationAlbum == PhotoAlbumSubType::GEOGRAPHY_LOCATION ?
            PAH_QUERY_GEO_PHOTOS : PAH_QUERY_ANA_PHOTO_ALBUM;
    } else {
        queryUri = (context->resultNapiType == ResultNapiType::TYPE_USERFILE_MGR) ?
            UFM_QUERY_PHOTO_ALBUM : PAH_QUERY_PHOTO_ALBUM;
    }
    Uri uri(queryUri);
    int errCode = 0;
    auto resultSet = UserFileClient::Query(uri, context->predicates, context->fetchColumn, errCode,
        GetUserIdFromContext(context));
    if (resultSet == nullptr) {
        ANI_ERR_LOG("resultSet == nullptr, errCode is %{public}d", errCode);
        if (errCode == E_PERMISSION_DENIED || errCode == -E_CHECK_SYSTEMAPP_FAIL) {
            context->SaveError(errCode);
        } else {
            context->SaveError(E_HAS_DB_ERROR);
        }
        return;
    }

    context->fetchPhotoAlbumResult = make_unique<FetchResult<PhotoAlbum>>(move(resultSet));
    context->fetchPhotoAlbumResult->SetResultNapiType(context->resultNapiType);
    context->fetchPhotoAlbumResult->SetHiddenOnly(context->hiddenOnly);
    context->fetchPhotoAlbumResult->SetLocationOnly(context->isLocationAlbum ==
        PhotoAlbumSubType::GEOGRAPHY_LOCATION);
    context->fetchPhotoAlbumResult->SetUserId(GetUserIdFromContext(context));
}

static ani_object GetPhotoAlbumsComplete(ani_env *env, unique_ptr<MediaLibraryAsyncContext> &context)
{
    CHECK_COND_RET(context != nullptr, nullptr, "context is nullptr");
    MediaLibraryTracer tracer;
    tracer.Start("GetPhotoAlbumsComplete");

    ani_object fetchRes {};
    ani_object errorObj {};
    if (context->error != ERR_DEFAULT  || context->fetchPhotoAlbumResult == nullptr) {
        ANI_ERR_LOG("No fetch file result found!");
        context->HandleError(env, errorObj);
    } else {
        fetchRes = FetchFileResultAni::CreateFetchFileResult(env, move(context->fetchPhotoAlbumResult));
        if (fetchRes == nullptr) {
            MediaLibraryAniUtils::CreateAniErrorObject(env, errorObj, ERR_MEM_ALLOCATION,
                "Failed to create ani object for FetchFileResult");
        }
    }
    tracer.Finish();
    context.reset();
    return fetchRes;
}

ani_object MediaLibraryAni::GetPhotoAlbums(ani_env *env, ani_object object, ani_enum_item albumTypeItem,
    ani_enum_item albumSubtypeItem, ani_object fetchOptions)
{
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    CHECK_COND_RET(asyncContext != nullptr, nullptr, "asyncContext is nullptr");
    asyncContext->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    asyncContext->objectInfo = Unwrap(env, object);
    CHECK_COND_WITH_RET_MESSAGE(env, ParseArgsGetPhotoAlbum(env, albumTypeItem, albumSubtypeItem,
        fetchOptions, asyncContext) == ANI_OK, nullptr, "Failed to parse get albums options");
    GetPhotoAlbumsExecute(env, asyncContext);
    return GetPhotoAlbumsComplete(env, asyncContext);
}

static ani_status ParseArgsGetBurstAssets(ani_env *env, ani_object object, ani_string burstKey,
    ani_object fetchOptions, std::unique_ptr<MediaLibraryAsyncContext>& context)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    context->objectInfo = MediaLibraryAni::Unwrap(env, object);
    /* Parse the first argument */
    std::string burstKeyStr;
    ani_status result = MediaLibraryAniUtils::GetParamStringPathMax(env, burstKey, burstKeyStr);
    if (result != ANI_OK) {
        AniError::ThrowError(env, OHOS_INVALID_PARAM_CODE);
        return result;
    }
    if (burstKeyStr.empty()) {
        ANI_ERR_LOG("The input burstkey cannot be empty");
        return ANI_INVALID_ARGS;
    }

    /* Parse the second argument */
    ani_status resultFetchOption = MediaLibraryAniUtils::GetFetchOption(env, fetchOptions, ASSET_FETCH_OPT, context);
    if (resultFetchOption != ANI_OK) {
        AniError::ThrowError(env, JS_INNER_FAIL);
        return resultFetchOption;
    }

    auto &predicates = context->predicates;
    if (context->assetType != TYPE_PHOTO) {
        return ANI_INVALID_ARGS;
    }

    CHECK_STATUS_RET(MediaLibraryAniUtils::AddDefaultAssetColumns(env, context->fetchColumn,
        PhotoColumn::IsPhotoColumn, TYPE_PHOTO), "AddDefaultAssetColumns failed");

    predicates.And()->EqualTo(PhotoColumn::PHOTO_BURST_KEY, burstKeyStr);
    predicates.And()->EqualTo(MediaColumn::MEDIA_TIME_PENDING, to_string(0));
    predicates.And()->EqualTo(PhotoColumn::PHOTO_IS_TEMP, to_string(0));
    predicates.OrderByAsc(MediaColumn::MEDIA_NAME);
    return ANI_OK;
}

// Easter egg operation: query duplicate assets
static bool EasterEgg(unique_ptr<MediaLibraryAsyncContext> &context)
{
    CHECK_COND_RET(context != nullptr, false, "context is nullptr");
    string queryUri;
    if (context->uri == URI_FIND_ALL_DUPLICATE_ASSETS) {
        queryUri = PAH_FIND_ALL_DUPLICATE_ASSETS;
    } else if (context->uri == URI_FIND_ALL_DUPLICATE_ASSETS_TO_DELETE) {
        queryUri = PAH_FIND_DUPLICATE_ASSETS_TO_DELETE;
    } else {
        return false;
    }
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        ANI_ERR_LOG("Easter egg operation failed, target is not system app");
        return false;
    };
    bool isQueryCount = find(context->fetchColumn.begin(), context->fetchColumn.end(), MEDIA_COLUMN_COUNT)
        != context->fetchColumn.end();
    int64_t startTime = MediaFileUtils::UTCTimeMilliSeconds();
    ANI_INFO_LOG(
        "Easter egg operation start: %{public}s, is query count: %{public}d",
        queryUri == PAH_FIND_ALL_DUPLICATE_ASSETS ?
        "find all duplicate assets" : "find all duplicate assets to delete", isQueryCount);
    int errCode = 0;
    Uri uri(queryUri);
    shared_ptr<DataShare::DataShareResultSet> resultSet = UserFileClient::Query(uri,
        context->predicates, context->fetchColumn, errCode, GetUserIdFromContext(context));
    if (resultSet == nullptr) {
        context->SaveError(errCode);
        ANI_ERR_LOG("Easter egg operation failed, errCode: %{public}d", errCode);
        return true;
    }
    context->fetchFileResult = make_unique<FetchResult<FileAsset>>(move(resultSet));
    context->fetchFileResult->SetResultNapiType(ResultNapiType::TYPE_PHOTOACCESS_HELPER);
    ANI_INFO_LOG(
        "Easter egg operation end: %{public}s, is query count: %{public}d, cost time: %{public}" PRId64 "ms",
        queryUri == PAH_FIND_ALL_DUPLICATE_ASSETS ?
        "find all duplicate assets" : "find all duplicate assets to delete", isQueryCount,
        MediaFileUtils::UTCTimeMilliSeconds() - startTime);
    return true;
}

static void PhotoAccessGetAssetsExecute(ani_env *env, unique_ptr<MediaLibraryAsyncContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "context is nullptr");
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAccessGetAssetsExecute");

    if (EasterEgg(context)) {
        ANI_ERR_LOG("YMINFO MediaLibraryAni::PhotoAccessGetAssetsExecute----------3 return");
        return;
    }
    string queryUri;
    switch (context->assetType) {
        case TYPE_PHOTO: {
            queryUri = PAH_QUERY_PHOTO;
            MediaLibraryAniUtils::UriAppendKeyValue(queryUri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
            break;
        }
        default: {
            context->SaveError(-EINVAL);
            return;
        }
    }

    Uri uri(queryUri);
    int errCode = 0;
    shared_ptr<DataShare::DataShareResultSet> resultSet = UserFileClient::Query(uri,
        context->predicates, context->fetchColumn, errCode, GetUserIdFromContext(context));
    if (resultSet == nullptr && !context->uri.empty() && errCode == E_PERMISSION_DENIED) {
        Uri queryWithUri(context->uri);
        resultSet = UserFileClient::Query(queryWithUri, context->predicates, context->fetchColumn, errCode,
            GetUserIdFromContext(context));
    }
    if (resultSet == nullptr) {
        context->SaveError(errCode);
        return;
    }
    context->fetchFileResult = make_unique<FetchResult<FileAsset>>(move(resultSet));
    context->fetchFileResult->SetResultNapiType(ResultNapiType::TYPE_PHOTOACCESS_HELPER);
    context->fetchFileResult->SetUserId(GetUserIdFromContext(context));
}

ani_object MediaLibraryAni::GetBurstAssets(ani_env *env, ani_object object,
    ani_string burstKey, ani_object fetchOptions)
{
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    CHECK_COND_RET(asyncContext != nullptr, nullptr, "asyncContext is nullptr");
    asyncContext->assetType = TYPE_PHOTO;
    if (ANI_OK != ParseArgsGetBurstAssets(env, object, burstKey, fetchOptions, asyncContext)) {
        AniError::ThrowError(env, JS_INNER_FAIL);
        return nullptr;
    }
    PhotoAccessGetAssetsExecute(env, asyncContext);
    return GetFileAssetsComplete(env, asyncContext);
}

ani_status MediaLibraryAni::Release(ani_env *env, ani_object object)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    auto mediaLibraryAni = Unwrap(env, object);
    if (mediaLibraryAni) {
        delete mediaLibraryAni;
        if (ANI_OK != env->Object_SetFieldByName_Long(object, "nativeHandle", 0)) {
            ANI_WARN_LOG("Set nativeHandle failed");
        }
    }
    return ANI_OK;
}

ani_status MediaLibraryAni::ApplyChanges(ani_env *env, ani_object object, ani_object mediaChangeRequest)
{
    MediaChangeRequestAni* mediaChangeRequestAni = MediaChangeRequestAni::Unwrap(env, mediaChangeRequest);
    if (mediaChangeRequestAni == nullptr) {
        ANI_ERR_LOG("Failed to unwrap MediaChangeRequestAni");
        return ANI_ERROR;
    }
    CHECK_COND_RET(mediaChangeRequestAni != nullptr, ANI_ERROR, "mediaChangeRequestAni is nullptr");
    return mediaChangeRequestAni->ApplyChanges(env);
}

static bool CheckDisplayNameParams(unique_ptr<MediaLibraryAsyncContext> &context)
{
    if (context == nullptr) {
        ANI_ERR_LOG("Async context is null");
        return false;
    }
    if (!context->isCreateByComponent) {
        bool isValid = false;
        string displayName = context->valuesBucket.Get(MEDIA_DATA_DB_NAME, isValid);
        if (!isValid) {
            ANI_ERR_LOG("getting displayName is invalid");
            return false;
        }
        if (displayName.empty()) {
            return false;
        }
    }

    return true;
}

static bool IsDirectory(const string &dirName)
{
    struct stat statInfo {};
    if (stat((ROOT_MEDIA_DIR + dirName).c_str(), &statInfo) == E_SUCCESS) {
        if (statInfo.st_mode & S_IFDIR) {
            return true;
        }
    }

    return false;
}

static string GetFirstDirName(const string &relativePath)
{
    string firstDirName = "";
    if (!relativePath.empty()) {
        string::size_type pos = relativePath.find_first_of('/');
        if (pos == relativePath.length()) {
            return relativePath;
        }
        firstDirName = relativePath.substr(0, pos + 1);
        ANI_DEBUG_LOG("firstDirName substr = %{private}s", firstDirName.c_str());
    }
    return firstDirName;
}

static bool CheckTypeOfType(const string &firstDirName, int32_t fileMediaType)
{
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
    if (!strcmp(firstDirName.c_str(), directoryEnumValues[SECOND_ENUM].c_str())) {
        if (fileMediaType == MEDIA_TYPE_IMAGE || fileMediaType == MEDIA_TYPE_VIDEO) {
            return true;
        } else {
            ANI_INFO_LOG("CheckTypeOfType RETURN FALSE");
            return false;
        }
    }
    if (!strcmp(firstDirName.c_str(), directoryEnumValues[THIRD_ENUM].c_str())) {
        if (fileMediaType == MEDIA_TYPE_AUDIO) {
            return true;
        } else {
            return false;
        }
    }
    return true;
}

static bool CheckRelativePathParams(unique_ptr<MediaLibraryAsyncContext> &context)
{
    if (context == nullptr) {
        ANI_ERR_LOG("Async context is null");
        return false;
    }
    bool isValid = false;
    string relativePath = context->valuesBucket.Get(MEDIA_DATA_DB_RELATIVE_PATH, isValid);
    if (!isValid) {
        ANI_DEBUG_LOG("getting relativePath is invalid");
        return false;
    }
    isValid = false;
    int32_t fileMediaType = context->valuesBucket.Get(MEDIA_DATA_DB_MEDIA_TYPE, isValid);
    if (!isValid) {
        ANI_DEBUG_LOG("getting fileMediaType is invalid");
        return false;
    }
    if (relativePath.empty()) {
        return false;
    }

    if (IsDirectory(relativePath)) {
        return true;
    }

    string firstDirName = GetFirstDirName(relativePath);
    if (!firstDirName.empty() && IsDirectory(firstDirName)) {
        return true;
    }

    if (!firstDirName.empty()) {
        ANI_DEBUG_LOG("firstDirName = %{private}s", firstDirName.c_str());
        for (unsigned int i = 0; i < directoryEnumValues.size(); i++) {
            ANI_DEBUG_LOG("directoryEnumValues%{private}d = %{private}s", i, directoryEnumValues[i].c_str());
            if (!strcmp(firstDirName.c_str(), directoryEnumValues[i].c_str())) {
                return CheckTypeOfType(firstDirName, fileMediaType);
            }
            if (!strcmp(firstDirName.c_str(), DOCS_PATH.c_str())) {
                return true;
            }
        }
        ANI_ERR_LOG("Failed to check relative path, firstDirName = %{private}s", firstDirName.c_str());
    }
    return false;
}

bool GetCreationUri(unique_ptr<MediaLibraryAsyncContext> &context, std::string& outUri)
{
    switch (context->assetType) {
        case TYPE_PHOTO:
            if (context->resultNapiType == ResultNapiType::TYPE_USERFILE_MGR) {
                outUri = (context->isCreateByComponent) ? UFM_CREATE_PHOTO_COMPONENT : UFM_CREATE_PHOTO;
            } else {
                outUri = (context->isCreateByComponent) ? PAH_CREATE_PHOTO_COMPONENT :
                    (context->needSystemApp ? PAH_SYS_CREATE_PHOTO : PAH_CREATE_PHOTO);
            }
            return true;
            
        case TYPE_AUDIO:
            outUri = (context->isCreateByComponent) ? UFM_CREATE_AUDIO_COMPONENT : UFM_CREATE_AUDIO;
            return true;
            
        default:
            ANI_ERR_LOG("Unsupported creation napitype %{public}d",
                static_cast<int32_t>(context->assetType));
            return false;
    }
}

static void GetCreateUri(unique_ptr<MediaLibraryAsyncContext> &context, string &uri)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "context is nullptr");
    if (context->resultNapiType == ResultNapiType::TYPE_USERFILE_MGR ||
        context->resultNapiType == ResultNapiType::TYPE_PHOTOACCESS_HELPER) {
            if (!GetCreationUri(context, uri)) {
                return;
            }
        MediaLibraryAniUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    } else {
#ifdef MEDIALIBRARY_COMPATIBILITY
        bool isValid = false;
        string relativePath = context->valuesBucket.Get(MEDIA_DATA_DB_RELATIVE_PATH, isValid);
        if (MediaFileUtils::StartsWith(relativePath, DOCS_PATH + DOC_DIR_VALUES) ||
            MediaFileUtils::StartsWith(relativePath, DOCS_PATH + DOWNLOAD_DIR_VALUES)) {
            uri = MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_CREATEASSET;
            MediaLibraryAniUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V9));
            return;
        }
        switch (context->assetType) {
            case TYPE_PHOTO:
                uri = MEDIALIBRARY_DATA_URI + "/" + MEDIA_PHOTOOPRN + "/" + MEDIA_FILEOPRN_CREATEASSET;
                break;
            case TYPE_AUDIO:
                uri = MEDIALIBRARY_DATA_URI + "/" + MEDIA_AUDIOOPRN + "/" + MEDIA_FILEOPRN_CREATEASSET;
                break;
            case TYPE_DEFAULT:
                uri = MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_CREATEASSET;
                break;
            default:
                ANI_ERR_LOG("Unsupported creation napi type %{public}d", static_cast<int32_t>(context->assetType));
                return;
        }
        MediaLibraryAniUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V9));
#else
        uri = MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_CREATEASSET;
#endif
    }
}

static void PhotoAccessSetFileAssetByIdV10(int32_t id, const string &networkId, const string &uri,
    unique_ptr<MediaLibraryAsyncContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "context is nullptr");
    bool isValid = false;
    string displayName = context->valuesBucket.Get(MEDIA_DATA_DB_NAME, isValid);
    if (!isValid) {
        ANI_ERR_LOG("getting title is invalid");
        return;
    }
    auto fileAsset = make_unique<FileAsset>();
    CHECK_NULL_PTR_RETURN_VOID(fileAsset, "fileAsset is nullptr");
    fileAsset->SetId(id);
    MediaType mediaType = MediaFileUtils::GetMediaType(displayName);
    fileAsset->SetUri(uri);
    fileAsset->SetMediaType(mediaType);
    fileAsset->SetDisplayName(displayName);
    fileAsset->SetTitle(MediaFileUtils::GetTitleFromDisplayName(displayName));
    fileAsset->SetResultNapiType(ResultNapiType::TYPE_PHOTOACCESS_HELPER);
    fileAsset->SetTimePending(UNCREATE_FILE_TIMEPENDING);
    fileAsset->SetUserId(GetUserIdFromContext(context));
    context->fileAsset = move(fileAsset);
}

#ifndef MEDIALIBRARY_COMPATIBILITY
static void getFileAssetById(int32_t id, const string &networkId, unique_ptr<MediaLibraryAsyncContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    vector<string> columns;
    DataShare::DataSharePredicates predicates;

    predicates.SetWhereClause(MEDIA_DATA_DB_ID + " = ? ");
    predicates.SetWhereArgs({ to_string(id) });

    string queryUri = MEDIALIBRARY_DATA_URI;
    Uri uri(queryUri);
    int errCode = 0;

    auto resultSet = UserFileClient::Query(uri, predicates, columns, errCode, GetUserIdFromContext(context));
    CHECK_NULL_PTR_RETURN_VOID(resultSet, "Failed to get file asset by id, query resultSet is nullptr");

    // Create FetchResult object using the contents of resultSet
    context->fetchFileResult = make_unique<FetchResult<FileAsset>>(move(resultSet));
    CHECK_NULL_PTR_RETURN_VOID(context->fetchFileResult, "Failed to get file asset by id, fetchFileResult is nullptr");
    context->fetchFileResult->SetNetworkId(networkId);
    if (context->resultNapiType == ResultNapiType::TYPE_USERFILE_MGR ||
        context->resultNapiType == ResultNapiType::TYPE_PHOTOACCESS_HELPER) {
        context->fetchFileResult->SetResultNapiType(context->resultNapiType);
    }
    if (context->fetchFileResult->GetCount() < 1) {
        ANI_ERR_LOG("Failed to query file by id: %{public}d, query count is 0", id);
        return;
    }
    unique_ptr<FileAsset> fileAsset = context->fetchFileResult->GetFirstObject();
    CHECK_NULL_PTR_RETURN_VOID(fileAsset, "getFileAssetById: fileAsset is nullptr");
    context->fileAsset = move(fileAsset);
}
#endif

#ifdef MEDIALIBRARY_COMPATIBILITY
static void SetFileAssetByIdV9(int32_t id, const string &networkId, unique_ptr<MediaLibraryAsyncContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    bool isValid = false;
    string displayName = context->valuesBucket.Get(MEDIA_DATA_DB_NAME, isValid);
    if (!isValid) {
        ANI_ERR_LOG("get title is invalid");
        return;
    }
    string relativePath = context->valuesBucket.Get(MEDIA_DATA_DB_RELATIVE_PATH, isValid);
    if (!isValid) {
        ANI_ERR_LOG("get relativePath is invalid");
        return;
    }
    unique_ptr<FileAsset> fileAsset = make_unique<FileAsset>();
    CHECK_NULL_PTR_RETURN_VOID(fileAsset, "fileAsset is nullptr");
    fileAsset->SetId(id);
    MediaType mediaType = MediaFileUtils::GetMediaType(displayName);
    string uri;
    if (MediaFileUtils::StartsWith(relativePath, DOCS_PATH + DOC_DIR_VALUES) ||
        MediaFileUtils::StartsWith(relativePath, DOCS_PATH + DOWNLOAD_DIR_VALUES)) {
        uri = MediaFileUtils::GetVirtualUriFromRealUri(MediaFileUri(MediaType::MEDIA_TYPE_FILE,
            to_string(id), networkId, MEDIA_API_VERSION_V9).ToString());
        relativePath = MediaFileUtils::RemoveDocsFromRelativePath(relativePath);
    } else {
        uri = MediaFileUtils::GetVirtualUriFromRealUri(MediaFileUri(mediaType,
            to_string(id), networkId, MEDIA_API_VERSION_V9).ToString());
    }
    fileAsset->SetUri(uri);
    fileAsset->SetMediaType(mediaType);
    fileAsset->SetDisplayName(displayName);
    fileAsset->SetTitle(MediaFileUtils::GetTitleFromDisplayName(displayName));
    fileAsset->SetResultNapiType(ResultNapiType::TYPE_MEDIALIBRARY);
    fileAsset->SetRelativePath(relativePath);
    context->fileAsset = move(fileAsset);
}
#endif

static bool CheckTitleCompatible(unique_ptr<MediaLibraryAsyncContext> &context)
{
    CHECK_COND_RET(context != nullptr, false, "context is nullptr");
    if (!context->isCreateByComponent) {
        return true;
    }
    bool hasTitleParam = false;
    const string title = context->valuesBucket.Get(MediaColumn::MEDIA_TITLE, hasTitleParam);
    if (!hasTitleParam) {
        return true;
    }
    return MediaFileUtils::CheckTitleCompatible(title) == E_OK;
}

static void PhotoAccessCreateAssetExecute(unique_ptr<MediaLibraryAsyncContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAccessCreateAssetExecute");

    if (context == nullptr) {
        ANI_ERR_LOG("PhotoAccessCreateAssetExecute: context is null");
        return;
    }

    if (!CheckDisplayNameParams(context)) {
        context->error = JS_E_DISPLAYNAME;
        return;
    }

    if (!CheckTitleCompatible(context)) {
        context->error = JS_E_DISPLAYNAME;
        return;
    }
    if ((context->resultNapiType != ResultNapiType::TYPE_PHOTOACCESS_HELPER) && (!CheckRelativePathParams(context))) {
        context->error = JS_E_RELATIVEPATH;
        return;
    }

    string uri;
    GetCreateUri(context, uri);
    Uri createFileUri(uri);
    string outUri;
    int index = UserFileClient::InsertExt(createFileUri, context->valuesBucket, outUri, GetUserIdFromContext(context));
    if (index < 0) {
        context->SaveError(index);
        ANI_ERR_LOG("InsertExt fail, index: %{public}d.", index);
    } else {
        if (context->resultNapiType == ResultNapiType::TYPE_PHOTOACCESS_HELPER) {
            if (context->isCreateByComponent) {
                context->uri = outUri;
            } else {
                PhotoAccessSetFileAssetByIdV10(index, "", outUri, context);
            }
        } else {
#ifdef MEDIALIBRARY_COMPATIBILITY
            SetFileAssetByIdV9(index, "", context);
#else
            getFileAssetById(index, "", context);
#endif
        }
    }
}

static ani_status CheckCreateOption(unique_ptr<MediaLibraryAsyncContext> &asyncContext)
{
    CHECK_COND_RET(asyncContext != nullptr, ANI_ERROR, "asyncContext is nullptr");
    bool isValid = false;
    int32_t subtype = asyncContext->valuesBucket.Get(PhotoColumn::PHOTO_SUBTYPE, isValid);
    string cameraShotKey = asyncContext->valuesBucket.Get(PhotoColumn::CAMERA_SHOT_KEY, isValid);
    if (isValid) {
        if (cameraShotKey.size() < CAMERA_SHOT_KEY_SIZE) {
            ANI_ERR_LOG("cameraShotKey is not null with but is less than CAMERA_SHOT_KEY_SIZE");
            return ANI_INVALID_ARGS;
        }
        if (subtype == static_cast<int32_t>(PhotoSubType::SCREENSHOT)) {
            ANI_ERR_LOG("cameraShotKey is not null with subtype is SCREENSHOT");
            return ANI_INVALID_ARGS;
        } else {
            asyncContext->valuesBucket.Put(PhotoColumn::PHOTO_SUBTYPE, static_cast<int32_t>(PhotoSubType::CAMERA));
        }
    }
    return ANI_OK;
}

static ani_status ParseCreateOptions(std::unique_ptr<MediaLibraryAsyncContext>& context,
    const std::unordered_map<std::string, std::variant<int32_t, bool, std::string>>& optionsMap,
    const std::map<std::string, std::string>& createOptionsMap, bool isCheckCreateOption)
{
    CHECK_COND_RET(context != nullptr, ANI_ERROR, "context is nullptr");
    for (const auto& [key, column] : createOptionsMap) {
        auto iter = optionsMap.find(key);
        if (iter == optionsMap.end()) {
            ANI_WARN_LOG("key %{public}s not found in optionsMap", key.c_str());
            continue;
        }
        auto value = iter->second;
        if (std::holds_alternative<int32_t>(value)) {
            context->valuesBucket.Put(column, std::get<int32_t>(value));
        } else if (std::holds_alternative<bool>(value)) {
            context->valuesBucket.Put(column, std::get<bool>(value));
        } else if (std::holds_alternative<std::string>(value)) {
            context->valuesBucket.Put(column, std::get<std::string>(value));
        } else {
            ANI_ERR_LOG("value type of key: %{public}s not supported", key.c_str());
            continue;
        }
    }
    if (isCheckCreateOption) {
        return CheckCreateOption(context);
    }

    return ANI_OK;
}

static ani_status ParseArgsCreateAssetSystem(ani_env* env, ani_string stringObj, ani_object photoCreateOptions,
    unique_ptr<MediaLibraryAsyncContext> &asyncContext)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    CHECK_COND_RET(asyncContext != nullptr, ANI_ERROR, "asyncContext is nullptr");
    asyncContext->isCreateByComponent = false;
    asyncContext->needSystemApp = true;
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return ANI_ERROR;
    }
    std::string displayNameStr;
    CHECK_COND_WITH_RET_MESSAGE(env,
        MediaLibraryAniUtils::GetParamStringPathMax(env, stringObj, displayNameStr) == ANI_OK, ANI_ERROR,
        "Failed to get displayName");
    MediaType mediaType = MediaFileUtils::GetMediaType(displayNameStr);
    CHECK_COND_WITH_RET_MESSAGE(env, mediaType == MEDIA_TYPE_IMAGE || mediaType == MEDIA_TYPE_VIDEO, ANI_ERROR,
        "Invalid file type");
    asyncContext->valuesBucket.Put(MEDIA_DATA_DB_NAME, displayNameStr);

    ani_boolean isUndefined;
    env->Reference_IsUndefined(photoCreateOptions, &isUndefined);
    if (!isUndefined) {
        auto optionsMap = MediaLibraryAniUtils::GetPhotoCreateOptions(env, photoCreateOptions);
        CHECK_COND_WITH_RET_MESSAGE(env,
            ParseCreateOptions(asyncContext, optionsMap, PHOTO_CREATE_OPTIONS_PARAM, true) == ANI_OK,
            ANI_ERROR, "Parse asset create option failed");
    }
    asyncContext->valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, static_cast<int32_t>(mediaType));
    return ANI_OK;
}

static ani_status ParseArgsCreatePhotoAssetComponent(ani_env* env, ani_enum_item photoTypeAni, ani_string stringObj,
    ani_object createOptions, unique_ptr<MediaLibraryAsyncContext> &asyncContext)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    CHECK_COND_RET(asyncContext != nullptr, ANI_ERROR, "asyncContext is nullptr");
    asyncContext->isCreateByComponent = true;
    // Parse photoType.
    int32_t mediaTypeInt;
    CHECK_COND_WITH_RET_MESSAGE(env, MediaLibraryEnumAni::EnumGetValueInt32(
        env, photoTypeAni, mediaTypeInt) == ANI_OK, ANI_ERROR, "Failed to get photoType");
    MediaType mediaType = static_cast<MediaType>(mediaTypeInt);
    CHECK_COND_WITH_RET_MESSAGE(env, mediaType == MEDIA_TYPE_IMAGE || mediaType == MEDIA_TYPE_VIDEO,
        ANI_ERROR, "Invalid photoType");

    // Parse extension.
    std::string extensionStr;
    CHECK_COND_WITH_RET_MESSAGE(env,
        MediaLibraryAniUtils::GetParamStringPathMax(env, stringObj, extensionStr) == ANI_OK, ANI_ERROR,
        "Failed to get extension");
    CHECK_COND_WITH_RET_MESSAGE(env, mediaType == MediaFileUtils::GetMediaType("." + extensionStr), ANI_ERROR,
        "Failed to check extension");
    asyncContext->valuesBucket.Put(ASSET_EXTENTION, extensionStr);

    // Parse options if exists.
    ani_boolean isUndefined;
    env->Reference_IsUndefined(createOptions, &isUndefined);
    if (!isUndefined) {
        auto optionsMap = MediaLibraryAniUtils::GetCreateOptions(env, createOptions);
        CHECK_COND_WITH_RET_MESSAGE(env,
            ParseCreateOptions(asyncContext, optionsMap, CREATE_OPTIONS_PARAM, false) == ANI_OK,
            ANI_ERROR, "Parse asset create option failed");
    }
    asyncContext->valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, static_cast<int32_t>(mediaType));
    return ANI_OK;
}

static ani_object CreateAsset(ani_env *env, unique_ptr<MediaLibraryAsyncContext> &context, ani_object &error)
{
    CHECK_COND_RET(context != nullptr, nullptr, "context is nullptr");
    ani_object resultObj = {};
    if (context->fileAsset == nullptr) {
        MediaLibraryAniUtils::CreateAniErrorObject(env, error, ERR_INVALID_OUTPUT,
            "Obtain file asset failed");
    } else {
        context->fileAsset->SetUserId(GetUserIdFromContext(context));
        auto asset = FileAssetAni::CreateFileAsset(env, context->fileAsset);
        if (asset == nullptr) {
            ANI_ERR_LOG("Failed to get file asset napi object");
            MediaLibraryAniUtils::CreateAniErrorObject(env, error, JS_INNER_FAIL,
                "System inner fail");
        } else {
            ANI_DEBUG_LOG("CreateAsset jsFileAsset != nullptr");
            FileAssetAniMethod fileAssetAniMethod;
            if (ANI_OK != FileAssetAni::InitFileAssetAniMethod(env, asset->GetFileAssetInstance()->GetResultNapiType(),
                fileAssetAniMethod)) {
                ANI_ERR_LOG("InitFileAssetAniMethod failed");
                return nullptr;
            }
            resultObj = FileAssetAni::Wrap(env, asset, fileAssetAniMethod);
        }
    }
    return resultObj;
}

static ani_object CreateUri(ani_env *env, unique_ptr<MediaLibraryAsyncContext> &context, ani_object &error)
{
    CHECK_COND_RET(context != nullptr, nullptr, "context is nullptr");
    ani_string retUri = {};
    if (context->uri.empty()) {
        MediaLibraryAniUtils::CreateAniErrorObject(env, error, ERR_INVALID_OUTPUT,
            "Obtain file asset uri failed");
    } else {
        auto status = MediaLibraryAniUtils::ToAniString(env, context->uri, retUri);
        if (status != ANI_OK) {
            ANI_ERR_LOG("Failed to get file asset uri ani object");
            MediaLibraryAniUtils::CreateAniErrorObject(env, error, JS_INNER_FAIL,
                "System inner fail");
        }
    }
    return static_cast<ani_object>(retUri);
}

static ani_object CreateUriArray(ani_env *env, unique_ptr<MediaLibraryAsyncContext> &context, ani_object &error)
{
    CHECK_COND_RET(context != nullptr, nullptr, "context is nullptr");
    ani_object retObj = {};
    if (context->uriArray.empty()) {
        MediaLibraryAniUtils::CreateAniErrorObject(env, error, ERR_INVALID_OUTPUT,
            "Obtain file asset uri array failed");
    } else {
        auto status = MediaLibraryAniUtils::ToAniStringArray(env, context->uriArray, retObj);
        if (status != ANI_OK) {
            ANI_ERR_LOG("Failed to get file asset uri array ani object");
            MediaLibraryAniUtils::CreateAniErrorObject(env, error, JS_INNER_FAIL,
                "System inner fail");
        }
    }
    return retObj;
}

static ani_object CreateAssetComplete(ani_env *env, unique_ptr<MediaLibraryAsyncContext> &context)
{
    CHECK_COND_RET(context != nullptr, nullptr, "context is nullptr");
    MediaLibraryTracer tracer;
    tracer.Start("CreateAssetComplete");

    ani_object resultObj = {};
    ani_object error = {};
    if (context->error == ERR_DEFAULT) {
        if (context->isCreateByAgent) {
            resultObj = CreateUriArray(env, context, error);
        } else if (context->isCreateByComponent) {
            resultObj = CreateUri(env, context, error);
        } else {
            resultObj = CreateAsset(env, context, error);
        }
    } else {
        context->HandleError(env, error);
    }

    tracer.Finish();
    context.reset();
    return resultObj;
}

ani_object MediaLibraryAni::CreateAssetSystem([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object,
    ani_string displayName, ani_object options)
{
    MediaLibraryTracer tracer;
    tracer.Start("CreateAssetSystem");
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    CHECK_COND_RET(asyncContext != nullptr, nullptr, "asyncContext is nullptr");
    asyncContext->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    asyncContext->assetType = TYPE_PHOTO;
    asyncContext->objectInfo = Unwrap(env, object);
    CHECK_COND_WITH_RET_MESSAGE(env, ANI_OK == ParseArgsCreateAssetSystem(env, displayName, options, asyncContext),
        nullptr, "Failed to parse args");
    PhotoAccessCreateAssetExecute(asyncContext);
    return CreateAssetComplete(env, asyncContext);
}

ani_object MediaLibraryAni::CreateAssetComponent([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object,
    ani_enum_item photoTypeAni, ani_string extension, ani_object options)
{
    MediaLibraryTracer tracer;
    tracer.Start("CreateAssetComponent");
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    CHECK_COND_RET(asyncContext != nullptr, nullptr, "asyncContext is nullptr");
    asyncContext->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    asyncContext->assetType = TYPE_PHOTO;
    asyncContext->objectInfo = Unwrap(env, object);
    CHECK_COND_WITH_RET_MESSAGE(env,
        ANI_OK == ParseArgsCreatePhotoAssetComponent(env, photoTypeAni, extension, options, asyncContext),
        nullptr, "Failed to parse args");
    PhotoAccessCreateAssetExecute(asyncContext);
    return CreateAssetComplete(env, asyncContext);
}

void MediaLibraryAni::RegisterNotifyChange(ani_env *env, const std::string &uri, bool isDerived, ani_ref ref,
    ChangeListenerAni &listObj)
{
    Uri notifyUri(uri);
    shared_ptr<MediaOnNotifyObserver> observer = make_shared<MediaOnNotifyObserver>(listObj, uri, ref);
    CHECK_NULL_PTR_RETURN_VOID(observer, "observer is nullptr");
    UserFileClient::RegisterObserverExt(notifyUri,
        static_cast<shared_ptr<DataShare::DataShareObserver>>(observer), isDerived);
    lock_guard<mutex> lock(sOnOffMutex_);
    listObj.observers_.push_back(observer);
}

void MediaLibraryAni::UnRegisterNotifyChange(ani_env *env, const std::string &uri, ani_ref ref,
    ChangeListenerAni &listObj)
{
    if (ref != nullptr) {
        CheckRef(env, ref, listObj, true, uri);
        return;
    }
    if (listObj.observers_.size() == 0) {
        return;
    }
    std::vector<std::shared_ptr<MediaOnNotifyObserver>> offObservers;
    {
        lock_guard<mutex> lock(sOnOffMutex_);
        for (auto iter = listObj.observers_.begin(); iter != listObj.observers_.end();) {
            if (uri.compare((*iter)->uri_) == 0) {
                offObservers.push_back(*iter);
                vector<shared_ptr<MediaOnNotifyObserver>>::iterator tmp = iter;
                iter = listObj.observers_.erase(tmp);
            } else {
                iter++;
            }
        }
    }
    for (auto obs: offObservers) {
        UserFileClient::UnregisterObserverExt(Uri(uri), static_cast<shared_ptr<DataShare::DataShareObserver>>(obs));
    }
}

bool MediaLibraryAni::CheckRef(ani_env *env, ani_ref ref, ChangeListenerAni &listObj, bool isOff,
    const std::string &uri)
{
    if (ref == nullptr) {
        ANI_ERR_LOG("offCallback reference is nullptr");
        return false;
    }
    CHECK_COND_RET(env != nullptr, false, "env is nullptr");
    ani_boolean isSame = ANI_FALSE;
    shared_ptr<DataShare::DataShareObserver> obs;
    string obsUri;
    {
        lock_guard<mutex> lock(sOnOffMutex_);
        for (auto it = listObj.observers_.begin(); it < listObj.observers_.end(); it++) {
            ani_ref onCallback = (*it)->ref_;
            if (onCallback == nullptr) {
                ANI_ERR_LOG("onCallback reference is nullptr");
                return false;
            }
            env->Reference_StrictEquals(ref, onCallback, &isSame);
            if (isSame == ANI_TRUE) {
                obsUri = (*it)->uri_;
                if ((isOff) && (uri.compare(obsUri) == 0)) {
                    obs = static_cast<shared_ptr<DataShare::DataShareObserver>>(*it);
                    listObj.observers_.erase(it);
                    break;
                }
                if (uri.compare(obsUri) != 0) {
                    return true;
                }
                return false;
            }
        }
    }
    if (isSame == ANI_TRUE && isOff) {
        if (obs != nullptr) {
            UserFileClient::UnregisterObserverExt(Uri(obsUri), obs);
        }
    }
    return true;
}

void MediaLibraryAni::PhotoAccessHelperOnCallback(ani_env *env, ani_object object, ani_string aniUri,
    ani_boolean forChildUris, ani_fn_object callbackOn)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is nullptr");
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAccessHelperOnCallback");

    MediaLibraryAni *obj = Unwrap(env, object);
    if (obj == nullptr) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return;
    }

    std::string uri;
    if (MediaLibraryAniUtils::GetString(env, aniUri, uri) != ANI_OK) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return;
    }
    bool isDerived = (forChildUris == ANI_TRUE);
    ani_ref cbOnRef {};
    env->GlobalReference_Create(static_cast<ani_ref>(callbackOn), &cbOnRef);
    tracer.Start("RegisterNotifyChange");
    if (CheckRef(env, cbOnRef, *g_listObj, false, uri)) {
        obj->RegisterNotifyChange(env, uri, isDerived, cbOnRef, *g_listObj);
    } else {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        env->GlobalReference_Delete(cbOnRef);
        cbOnRef = nullptr;
        return;
    }
    tracer.Finish();
}

void MediaLibraryAni::PhotoAccessHelperOffCallback(ani_env *env, ani_object object, ani_string aniUri,
    ani_fn_object callbackOff)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is nullptr");
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAccessHelperOffCallback");

    MediaLibraryAni *obj = Unwrap(env, object);
    if (obj == nullptr) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return;
    }

    std::string uri;
    if (MediaLibraryAniUtils::GetString(env, aniUri, uri) != ANI_OK) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return;
    }

    ani_ref cbOffRef = nullptr;
    ani_boolean isUndefined = ANI_TRUE;
    env->Reference_IsUndefined(object, &isUndefined);
    if (isUndefined == ANI_FALSE) {
        env->GlobalReference_Create(static_cast<ani_ref>(callbackOff), &cbOffRef);
    }
    tracer.Start("UnRegisterNotifyChange");
    obj->UnRegisterNotifyChange(env, uri, cbOffRef, *g_listObj);
}

static ani_status CheckFormId(string &formId)
{
    if (formId.empty() || formId.length() > FORMID_MAX_LEN) {
        return ANI_INVALID_ARGS;
    }
    for (uint32_t i = 0; i < formId.length(); i++) {
        if (!isdigit(formId[i])) {
            return ANI_INVALID_ARGS;
        }
    }
    unsigned long long num = stoull(formId);
    if (num > MAX_INT64) {
        return ANI_INVALID_ARGS;
    }
    return ANI_OK;
}

static ani_status ParseArgsSaveFormInfo(ani_env *env, ani_object info, unique_ptr<MediaLibraryAsyncContext> &context)
{
    CHECK_COND_RET(context != nullptr, ANI_ERROR, "context is nullptr");
    const std::string formId = "formId";
    const std::string uri = "uri";
    const std::map<std::string, std::string> saveFormInfoOptionsParam = {
        { formId, FormMap::FORMMAP_FORM_ID },
        { uri, FormMap::FORMMAP_URI }
    };
    for (const auto &iter: saveFormInfoOptionsParam) {
        std::string propertyName = iter.first;
        std::string propertyValue = "";
        CHECK_STATUS_RET(MediaLibraryAniUtils::GetProperty(env, info, propertyName, propertyValue),
            "GetProperty %{public}s fail", propertyName.c_str());
        context->valuesBucket.Put(iter.second, propertyValue);
    }
    bool isValid = false;
    std::string tempFormId = context->valuesBucket.Get(FormMap::FORMMAP_FORM_ID, isValid);
    if (!isValid) {
        return ANI_INVALID_ARGS;
    }
    return CheckFormId(tempFormId);
}

static void SaveFormInfoExec(ani_env *env, unique_ptr<MediaLibraryAsyncContext> &context, ResultNapiType type)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "context is nullptr");
    context->resultNapiType = type;
    string uri = PAH_STORE_FORM_MAP;
    Uri createFormIdUri(uri);
    auto ret = UserFileClient::Insert(createFormIdUri, context->valuesBucket);
    if (ret < 0) {
        if (ret == E_PERMISSION_DENIED) {
            context->error = OHOS_PERMISSION_DENIED_CODE;
        } else if (ret == E_GET_PRAMS_FAIL) {
            context->error = OHOS_INVALID_PARAM_CODE;
        } else {
            context->SaveError(ret);
        }
        ANI_ERR_LOG("store formInfo failed, ret: %{public}d", ret);
    }
}

static void PhotoAccessSaveFormInfoExec(ani_env *env, unique_ptr<MediaLibraryAsyncContext> &context)
{
    SaveFormInfoExec(env, context, ResultNapiType::TYPE_PHOTOACCESS_HELPER);
}

static void PhotoAccessSaveFormInfoComplete(ani_env *env, unique_ptr<MediaLibraryAsyncContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "context is nullptr");
    ani_object errorObj {};
    if (context->error != ERR_DEFAULT) {
        context->HandleError(env, errorObj);
    }
    context.reset();
}

void MediaLibraryAni::PhotoAccessSaveFormInfo(ani_env *env, ani_object object, ani_object info)
{
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAccessSaveFormInfo");

    unique_ptr<MediaLibraryAsyncContext> context = make_unique<MediaLibraryAsyncContext>();
    CHECK_NULL_PTR_RETURN_VOID(context, "context is nullptr");
    context->objectInfo = Unwrap(env, object);
    if (context->objectInfo == nullptr) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return;
    }

    CHECK_IF_EQUAL(ParseArgsSaveFormInfo(env, info, context) == ANI_OK, "ParseArgsSaveFormInfo fail");
    PhotoAccessSaveFormInfoExec(env, context);
    PhotoAccessSaveFormInfoComplete(env, context);
}

static ani_status ParseBundleInfo(ani_env *env, ani_object appInfo, BundleInfo &bundleInfo)
{
    CHECK_STATUS_RET(MediaLibraryAniUtils::GetProperty(env, appInfo, CONFIRM_BOX_BUNDLE_NAME, bundleInfo.bundleName),
        "Failed to get bundleName");
    CHECK_STATUS_RET(MediaLibraryAniUtils::GetProperty(env, appInfo, CONFIRM_BOX_APP_NAME, bundleInfo.packageName),
        "Failed to get appName");
    CHECK_STATUS_RET(MediaLibraryAniUtils::GetProperty(env, appInfo, CONFIRM_BOX_APP_ID, bundleInfo.appId),
        "Failed to get appId");
    CHECK_STATUS_RET(MediaLibraryAniUtils::GetProperty(env, appInfo, TOKEN_ID, bundleInfo.tokenId),
        "Failed to get appId");
    return ANI_OK;
}

static void HandleBundleInfo(OHOS::DataShare::DataShareValuesBucket &valuesBucket, bool isAuthorization,
    const BundleInfo &bundleInfo)
{
    if (isAuthorization) {
        valuesBucket.Put(MEDIA_DATA_DB_OWNER_PACKAGE, bundleInfo.bundleName);
        valuesBucket.Put(MEDIA_DATA_DB_OWNER_APPID, bundleInfo.appId);
        valuesBucket.Put(MEDIA_DATA_DB_PACKAGE_NAME, bundleInfo.packageName);
    }
    if (!bundleInfo.ownerAlbumId.empty()) {
        valuesBucket.Put(PhotoColumn::PHOTO_OWNER_ALBUM_ID, bundleInfo.ownerAlbumId);
        ANI_INFO_LOG("client put ownerAlbumId: %{public}s", bundleInfo.ownerAlbumId.c_str());
    }
}

static ani_status ParseCreateConfig(ani_env *env, ani_object photoCreationConfig, const BundleInfo &bundleInfo,
    unique_ptr<MediaLibraryAsyncContext> &context, bool isAuthorization = true)
{
    OHOS::DataShare::DataShareValuesBucket valuesBucket;
    ani_object photoTypeAni {};
    CHECK_STATUS_RET(MediaLibraryAniUtils::GetProperty(env, photoCreationConfig, PHOTO_TYPE, photoTypeAni),
        "Failed to get %{public}s", PHOTO_TYPE.c_str());
    int32_t photoType = 0;
    CHECK_STATUS_RET(MediaLibraryEnumAni::EnumGetValueInt32(env, static_cast<ani_enum_item>(photoTypeAni), photoType),
        "Failed to call EnumGetValueInt32 for %{public}s", PHOTO_TYPE.c_str());
    valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, photoType);

    ani_object subTypeAni {};
    CHECK_STATUS_RET(MediaLibraryAniUtils::GetProperty(env, photoCreationConfig, PHOTO_SUB_TYPE, subTypeAni),
        "Failed to get %{public}s", PHOTO_SUB_TYPE.c_str());
    if (MediaLibraryAniUtils::IsUndefined(env, subTypeAni) == ANI_FALSE) {
        int32_t subType = 0;
        CHECK_STATUS_RET(MediaLibraryEnumAni::EnumGetValueInt32(env, static_cast<ani_enum_item>(subTypeAni), subType),
            "Failed to call EnumGetValueInt32 for %{public}s", PHOTO_SUB_TYPE.c_str());
        valuesBucket.Put(PhotoColumn::PHOTO_SUBTYPE, photoType);
    }

    ani_object titleAni {};
    CHECK_STATUS_RET(MediaLibraryAniUtils::GetProperty(env, photoCreationConfig, TITLE, titleAni),
        "Failed to get %{public}s", TITLE.c_str());
    if (MediaLibraryAniUtils::IsUndefined(env, titleAni) == ANI_FALSE) {
        std::string title = "";
        CHECK_STATUS_RET(MediaLibraryAniUtils::GetString(env, titleAni, title),
            "Failed to call GetString for %{public}s", TITLE.c_str());
        valuesBucket.Put(MediaColumn::MEDIA_TITLE, title);
    }

    ani_object extensionAni {};
    CHECK_STATUS_RET(MediaLibraryAniUtils::GetProperty(env, photoCreationConfig, EXTENSION, extensionAni),
        "Failed to get %{public}s", EXTENSION.c_str());
    std::string extension = "";
    CHECK_STATUS_RET(MediaLibraryAniUtils::GetString(env, extensionAni, extension),
        "Failed to call GetString for %{public}s", EXTENSION.c_str());
    valuesBucket.Put(ASSET_EXTENTION, extension);

    HandleBundleInfo(valuesBucket, isAuthorization, bundleInfo);
    context->valuesBucketArray.push_back(move(valuesBucket));
    return ANI_OK;
}

static ani_status ParseArgsAgentCreateAssets(ani_env *env, ani_object appInfo, ani_object photoCreationConfigs,
    unique_ptr<MediaLibraryAsyncContext> &context)
{
    context->isCreateByComponent = false;
    context->isCreateByAgent = true;

    /* Parse the arguments */
    BundleInfo bundleInfo;
    CHECK_STATUS_RET(ParseBundleInfo(env, appInfo, bundleInfo), "ParseBundleInfo fail");

    std::vector<ani_object> aniValues;
    CHECK_STATUS_RET(MediaLibraryAniUtils::GetObjectArray(env, photoCreationConfigs, aniValues),
        "GetObjectArray fail");
    if (aniValues.empty()) {
        ANI_INFO_LOG("photoCreationConfigs is empty");
        return ANI_OK;
    }

    for (const auto &aniValue: aniValues) {
        CHECK_STATUS_RET(ParseCreateConfig(env, aniValue, bundleInfo, context), "Parse asset create config failed");
    }
    return ANI_OK;
}

static bool CheckAlbumUri(ani_env *env, OHOS::DataShare::DataShareValuesBucket &valueBucket,
    unique_ptr<MediaLibraryAsyncContext> &context)
{
    bool isValid = false;
    string ownerAlbumId = valueBucket.Get(PhotoColumn::PHOTO_OWNER_ALBUM_ID, isValid);
    if (!isValid || ownerAlbumId.empty()) {
        return false;
    }
    string queryUri = PAH_QUERY_PHOTO_ALBUM;
    Uri uri(queryUri);
    DataSharePredicates predicates;
    vector selectionArgs = {to_string(PhotoAlbumSubType::USER_GENERIC), to_string(PhotoAlbumSubType::SOURCE_GENERIC)};
    predicates.In(PhotoAlbumColumns::ALBUM_SUBTYPE, selectionArgs);
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, ownerAlbumId);
    int errCode = 0;
    vector<string> columns;
    columns.push_back(MEDIA_COLUMN_COUNT_1);
    shared_ptr<DataShareResultSet> resultSet =
        UserFileClient::Query(uri, predicates, columns, errCode, GetUserIdFromContext(context));
    CHECK_COND_RET(resultSet != nullptr, false, "resultSet is nullptr");
    int err = resultSet->GoToFirstRow();
    if (err != NativeRdb::E_OK) {
        ANI_ERR_LOG("Invalid albumuri, Failed GoToFirstRow %{public}d", err);
        resultSet->Close();
        return false;
    }
    int32_t count = 0;
    resultSet->GetInt(0, count);
    if (count == 0) {
        ANI_ERR_LOG("Invalid albumuri!");
        resultSet->Close();
        return false;
    }
    resultSet->Close();
    return true;
}

static void PhotoAccessAgentCreateAssetsExecute(ani_env *env, unique_ptr<MediaLibraryAsyncContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "context is nullptr");
    string uri;
    GetCreateUri(context, uri);
    if (context->isContainsAlbumUri) {
        bool isValid = CheckAlbumUri(env, context->valuesBucketArray[0], context);
        if (!isValid) {
            context->error = JS_ERR_PARAMETER_INVALID;
            return;
        }
    }
    if (context->tokenId != 0) {
        ANI_INFO_LOG("tokenId: %{public}d", context->tokenId);
        MediaLibraryAniUtils::UriAppendKeyValue(uri, TOKEN_ID, to_string(context->tokenId));
    }
    Uri createFileUri(uri);
    for (const auto& valuesBucket : context->valuesBucketArray) {
        bool inValid = false;
        string title = valuesBucket.Get(MediaColumn::MEDIA_TITLE, inValid);
        if (!context->isContainsAlbumUri && !title.empty() && MediaFileUtils::CheckTitleCompatible(title) != E_OK) {
            ANI_ERR_LOG("Title contains invalid characters: %{private}s, skipping", title.c_str());
            context->uriArray.push_back(to_string(E_INVALID_DISPLAY_NAME));
            continue;
        }
        string outUri;
        int index = UserFileClient::InsertExt(createFileUri, valuesBucket, outUri, GetUserIdFromContext(context));
        if (index < 0) {
            if (index == E_PERMISSION_DENIED || index == -E_CHECK_SYSTEMAPP_FAIL) {
                context->SaveError(index);
                ANI_ERR_LOG("PERMISSION_DENIED, index: %{public}d.", index);
                return;
            }
            if (index == E_HAS_DB_ERROR) {
                index = OHOS_INVALID_PARAM_CODE;
            }
            context->uriArray.push_back(to_string(index));
            ANI_ERR_LOG("InsertExt fail, index: %{public}d title: %{public}s.", index, title.c_str());
        } else {
            context->uriArray.push_back(move(outUri));
        }
    }
}

ani_object MediaLibraryAni::PhotoAccessHelperAgentCreateAssets(ani_env *env, ani_object object,
    ani_object appInfo, ani_object photoCreationConfigs)
{
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAccessHelperAgentCreateAssets");

    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return nullptr;
    }

    unique_ptr<MediaLibraryAsyncContext> context = make_unique<MediaLibraryAsyncContext>();
    CHECK_COND_RET(context != nullptr, nullptr, "context is nullptr");
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    context->assetType = TYPE_PHOTO;
    context->needSystemApp = true;
    context->objectInfo = Unwrap(env, object);
    if (context->objectInfo == nullptr) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return nullptr;
    }

    if (ParseArgsAgentCreateAssets(env, appInfo, photoCreationConfigs, context) != ANI_OK) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID, "ParseArgsAgentCreateAssets fail");
        return nullptr;
    }
    PhotoAccessAgentCreateAssetsExecute(env, context);
    return CreateAssetComplete(env, context);
}

static ani_status ParseArgsAgentCreateAssetsWithMode(ani_env *env, ani_object appInfo,
    ani_object photoCreationConfigs, unique_ptr<MediaLibraryAsyncContext> &context)
{
    CHECK_COND_RET(context != nullptr, ANI_ERROR, "context is nullptr");
    context->isCreateByComponent = false;
    context->isCreateByAgent = true;
    context->needSystemApp = true;
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return ANI_ERROR;
    }

    /* Parse the arguments */
    BundleInfo bundleInfo;
    CHECK_STATUS_RET(ParseBundleInfo(env, appInfo, bundleInfo), "ParseBundleInfo fail");

    std::vector<ani_object> aniValues;
    CHECK_STATUS_RET(MediaLibraryAniUtils::GetObjectArray(env, photoCreationConfigs, aniValues),
        "GetObjectArray fail");
    if (aniValues.empty()) {
        ANI_INFO_LOG("photoCreationConfigs is empty");
        return ANI_OK;
    }

    for (const auto &aniValue: aniValues) {
        CHECK_STATUS_RET(ParseCreateConfig(env, aniValue, bundleInfo, context), "Parse asset create config failed");
    }
    return ANI_OK;
}

ani_object MediaLibraryAni::PhotoAccessHelperAgentCreateAssetsWithMode(ani_env *env, ani_object object,
    ani_object appInfo, ani_enum_item authorizationMode, ani_object photoCreationConfigs)
{
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAccessHelperAgentCreateAssetsWithMode");

    int32_t authorizationModeInt = -1;
    CHECK_COND_WITH_MESSAGE(env,
        MediaLibraryEnumAni::EnumGetValueInt32(env, authorizationMode, authorizationModeInt) == ANI_OK,
        "Failed to call EnumGetValueInt32 for authorizationMode");
    CHECK_COND_WITH_MESSAGE(env, authorizationModeInt == SaveType::SHORT_IMAGE_PERM, "authorizationMode is error");

    uint32_t tokenId = 0;
    if (MediaLibraryAniUtils::GetProperty(env, appInfo, TOKEN_ID, tokenId) != ANI_OK) {
        AniError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "Invalid tokenId");
        return nullptr;
    }
    int ret = Security::AccessToken::AccessTokenKit::GrantPermissionForSpecifiedTime(
        tokenId, PERM_SHORT_TERM_WRITE_IMAGEVIDEO, SHORT_TERM_PERMISSION_DURATION_300S);
    if (ret != E_SUCCESS) {
        AniError::ThrowError(env, OHOS_PERMISSION_DENIED_CODE, "This app have no short permission");
        return nullptr;
    }

    unique_ptr<MediaLibraryAsyncContext> context = make_unique<MediaLibraryAsyncContext>();
    CHECK_COND_RET(context != nullptr, nullptr, "context is nullptr");
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    context->assetType = TYPE_PHOTO;
    context->objectInfo = Unwrap(env, object);
    if (context->objectInfo == nullptr) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return nullptr;
    }

    if (ParseArgsAgentCreateAssetsWithMode(env, appInfo, photoCreationConfigs, context) != ANI_OK) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID, "ParseArgsAgentCreateAssetsWithMode fail");
        return nullptr;
    }
    PhotoAccessAgentCreateAssetsExecute(env, context);
    return CreateAssetComplete(env, context);
}

static bool GetProgressStr(const shared_ptr<DataShare::DataShareResultSet> &resultSet, string &progress)
{
    CHECK_COND_RET(resultSet != nullptr, false, "resultSet is nullptr");
    const vector<string> columns = {
        PHOTO_COMPLETE_NUM,
        PHOTO_TOTAL_NUM,
        VIDEO_COMPLETE_NUM,
        VIDEO_TOTAL_NUM
    };
    int32_t index = 0;
    string value = "";
    progress = "{";
    for (const auto &item : columns) {
        if (resultSet->GetColumnIndex(item, index) != DataShare::E_OK) {
            ANI_ERR_LOG("ResultSet GetColumnIndex failed, progressObject=%{public}s", item.c_str());
            return false;
        }
        if (resultSet->GetString(index, value) != DataShare::E_OK) {
            ANI_ERR_LOG("ResultSet GetString failed, progressObject=%{public}s", item.c_str());
            return false;
        }
        progress += "\"" + item + "\":" + value + ",";
    }
    progress = progress.substr(0, progress.length() - 1);
    progress += "}";
    ANI_DEBUG_LOG("GetProgressStr progress=%{public}s", progress.c_str());
    return true;
}

static bool GetProgressFromResultSet(const shared_ptr<DataShare::DataShareResultSet> &resultSet, string &progress)
{
    if (resultSet == nullptr) {
        ANI_ERR_LOG("ResultSet is null");
        return false;
    }
    int32_t count = 0;
    int32_t errCode = resultSet->GetRowCount(count);
    if (errCode != DataShare::E_OK) {
        ANI_ERR_LOG("Can not get row count from resultSet, errCode=%{public}d", errCode);
        return false;
    }
    if (count == 0) {
        ANI_ERR_LOG("Can not find index construction progress");
        return false;
    }
    errCode = resultSet->GoToFirstRow();
    if (errCode != DataShare::E_OK) {
        ANI_ERR_LOG("ResultSet GotoFirstRow failed, errCode=%{public}d", errCode);
        return false;
    }

    return GetProgressStr(resultSet, progress);
}

static void PhotoAccessGetIndexConstructProgressExec(ani_env *env, unique_ptr<MediaLibraryAsyncContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "context is nullptr");
    string queryUri = MEDIALIBRARY_DATA_URI + "/" + SEARCH_INDEX_CONSTRUCTION_STATUS + "/" + OPRN_QUERY;
    MediaLibraryAniUtils::UriAppendKeyValue(queryUri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri uri(queryUri);
    int errCode = 0;
    string indexProgress;
    auto resultSet = UserFileClient::Query(uri, context->predicates, context->fetchColumn, errCode,
        GetUserIdFromContext(context));
    if (!GetProgressFromResultSet(resultSet, indexProgress)) {
        if (errCode == E_PERMISSION_DENIED) {
            context->error = OHOS_PERMISSION_DENIED_CODE;
        } else {
            context->SaveError(E_FAIL);
        }
    } else {
        context->indexProgress = indexProgress;
    }
}

static ani_string GetIndexConstructProgressComplete(ani_env *env, unique_ptr<MediaLibraryAsyncContext> &context)
{
    CHECK_COND_RET(context != nullptr, nullptr, "context is nullptr");
    ani_string indexProgress = {};
    ani_object error = {};
    if (context->error != ERR_DEFAULT) {
        context->HandleError(env, error);
    } else {
        auto status = MediaLibraryAniUtils::ToAniString(env, context->indexProgress, indexProgress);
        if (status != ANI_OK) {
            AniError::ThrowError(env, JS_INNER_FAIL, "Failed to get indexProgress ani string");
        }
    }

    context.reset();
    return indexProgress;
}

ani_string MediaLibraryAni::PhotoAccessGetIndexConstructProgress(ani_env *env, ani_object object)
{
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return nullptr;
    }

    unique_ptr<MediaLibraryAsyncContext> context = make_unique<MediaLibraryAsyncContext>();
    CHECK_COND_RET(context != nullptr, nullptr, "context is nullptr");
    context->objectInfo = Unwrap(env, object);
    if (context->objectInfo == nullptr) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return nullptr;
    }
    PhotoAccessGetIndexConstructProgressExec(env, context);
    return GetIndexConstructProgressComplete(env, context);
}

static ani_status ParsePermissionType(ani_env *env, ani_enum_item permissionTypeAni, int32_t &permissionType)
{
    CHECK_STATUS_RET(MediaLibraryEnumAni::EnumGetValueInt32(env, permissionTypeAni, permissionType),
        "Failed to get permissionType");
    if (AppUriPermissionColumn::PERMISSION_TYPES_PICKER.find((int)permissionType) ==
        AppUriPermissionColumn::PERMISSION_TYPES_PICKER.end()) {
        ANI_ERR_LOG("invalid picker permissionType, permissionType=%{public}d", permissionType);
        return ANI_INVALID_ARGS;
    }
    return ANI_OK;
}

static ani_status ParseHidenSensitiveType(ani_env *env, ani_enum_item hideSensitiveTypeAni, int32_t &hideSensitiveType)
{
    CHECK_STATUS_RET(MediaLibraryEnumAni::EnumGetValueInt32(env, hideSensitiveTypeAni, hideSensitiveType),
        "Failed to get hideSensitiveType");
    if (AppUriSensitiveColumn::SENSITIVE_TYPES_ALL.find((int)hideSensitiveType) ==
        AppUriSensitiveColumn::SENSITIVE_TYPES_ALL.end()) {
        ANI_ERR_LOG("invalid picker hideSensitiveType, hideSensitiveType=%{public}d", hideSensitiveType);
        return ANI_INVALID_ARGS;
    }
    return ANI_OK;
}

static ani_status ParseArgsGrantPhotoUriPermission(ani_env *env, unique_ptr<MediaLibraryAsyncContext> &context,
    ani_object param, ani_enum_item permissionTypeAni, ani_enum_item hideSensitiveTypeAni)
{
    CHECK_COND_RET(context != nullptr, ANI_ERROR, "context is nullptr");
    context->isCreateByComponent = false;
    context->needSystemApp = true;
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return ANI_INVALID_ARGS;
    }

    // parse appid or tokenId
    uint32_t tokenId = 0;
    CHECK_STATUS_RET(MediaLibraryAniUtils::GetProperty(env, param, "tokenId", tokenId), "Failed to parse tokenId");
    context->valuesBucket.Put(AppUriPermissionColumn::TARGET_TOKENID, static_cast<int64_t>(tokenId));
    uint32_t srcTokenId = IPCSkeleton::GetCallingTokenID();
    context->valuesBucket.Put(AppUriSensitiveColumn::SOURCE_TOKENID, static_cast<int64_t>(srcTokenId));

    // parse fileId
    std::string uri = "";
    CHECK_STATUS_RET(MediaLibraryAniUtils::GetProperty(env, param, "uri", uri), "Failed to get uri");
    int32_t fileId = MediaLibraryAniUtils::GetFileIdFromPhotoUri(uri);
    CHECK_COND_RET(fileId >= 0, ANI_INVALID_ARGS, "Invalid fileId: %{public}d", fileId);
    context->valuesBucket.Put(AppUriPermissionColumn::FILE_ID, fileId);

    // parse permissionType
    int32_t permissionType = 0;
    CHECK_STATUS_RET(ParsePermissionType(env, permissionTypeAni, permissionType), "Invalid PermissionType");
    context->valuesBucket.Put(AppUriPermissionColumn::PERMISSION_TYPE, permissionType);

    // parse hideSensitiveType
    int32_t hideSensitiveType = 0;
    CHECK_STATUS_RET(ParseHidenSensitiveType(env, hideSensitiveTypeAni, hideSensitiveType), "Invalid SensitiveType");
    context->valuesBucket.Put(AppUriSensitiveColumn::HIDE_SENSITIVE_TYPE, hideSensitiveType);

    // parsing fileId ensured uri is photo.
    context->valuesBucket.Put(AppUriPermissionColumn::URI_TYPE, AppUriPermissionColumn::URI_PHOTO);
    return ANI_OK;
}

static void PhotoAccessGrantPhotoUriPermissionExecute(ani_env *env, unique_ptr<MediaLibraryAsyncContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "context is nullptr");
    string uri = PAH_CREATE_APP_URI_PERMISSION;
    MediaLibraryAniUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri createUri(uri);
    
    int result = UserFileClient::Insert(createUri, context->valuesBucket);
    if (result < 0) {
        context->SaveError(result);
        ANI_ERR_LOG("Insert fail, result: %{public}d.", result);
    } else {
        context->retVal = result;
    }
}

static ani_double PhotoUriPermissionComplete(ani_env *env, unique_ptr<MediaLibraryAsyncContext> &context)
{
    ani_double result = -1;
    CHECK_COND_RET(context != nullptr, result, "context is nullptr");
    ani_object error = {};
    if (context->error != ERR_DEFAULT) {
        context->HandleError(env, error);
    } else {
        result = static_cast<ani_double>(context->retVal);
    }

    context.reset();
    return result;
}

ani_double MediaLibraryAni::PhotoAccessGrantPhotoUriPermission(ani_env *env, ani_object object, ani_object param,
    ani_enum_item photoPermissionType, ani_enum_item hideSensitiveType)
{
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAccessGrantPhotoUriPermission");

    unique_ptr<MediaLibraryAsyncContext> context = make_unique<MediaLibraryAsyncContext>();
    CHECK_COND_RET(context != nullptr, -1, "context is nullptr");
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    context->assetType = TYPE_PHOTO;
    context->objectInfo = Unwrap(env, object);
    if (context->objectInfo == nullptr) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return -1;
    }
    if (ParseArgsGrantPhotoUriPermission(env, context, param, photoPermissionType, hideSensitiveType) != ANI_OK) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return -1;
    }
    PhotoAccessGrantPhotoUriPermissionExecute(env, context);
    return PhotoUriPermissionComplete(env, context);
}

int32_t MediaLibraryAni::GetUserId()
{
    return userId_;
}
 
void MediaLibraryAni::SetUserId(const int32_t &userId)
{
    userId_ = userId;
}

static void GetMediaAnalysisServiceProgress(nlohmann::json& jsonObj, unordered_map<int, string>& idxToCount,
    vector<string> columns)
{
    Uri uri(URI_TOTAL);
    string clause = VISION_TOTAL_TABLE + "." + MediaColumn::MEDIA_ID + " = " + PhotoColumn::PHOTOS_TABLE+ "." +
        MediaColumn::MEDIA_ID;
    DataShare::DataSharePredicates predicates;
    predicates.InnerJoin(PhotoColumn::PHOTOS_TABLE)->On({ clause });
    predicates.EqualTo(PhotoColumn::PHOTO_HIDDEN_TIME, 0)->And()
        ->EqualTo(MediaColumn::MEDIA_DATE_TRASHED, 0)->And()
        ->EqualTo(MediaColumn::MEDIA_TIME_PENDING, 0);

    int errCode = 0;
    shared_ptr<DataShare::DataShareResultSet> ret = UserFileClient::Query(uri, predicates, columns, errCode);
    CHECK_NULL_PTR_RETURN_VOID(ret, "ret is nullptr");
    if (ret->GoToFirstRow() != NativeRdb::E_OK) {
        ANI_ERR_LOG("GotoFirstRow failed, errCode is %{public}d", errCode);
        ret->Close();
        return;
    }
    for (size_t i = 0; i < columns.size(); ++i) {
        int tmp = -1;
        ret->GetInt(i, tmp);
        jsonObj[idxToCount[i]] = tmp;
    }
    ret->Close();
}

static std::string GetLabelAnalysisProgress()
{
    unordered_map<int, string> idxToCount = {
        {0, "totalCount"}, {1, "finishedCount"}, {2, "LabelCount"}
    };
    vector<string> columns = {
        "COUNT(*) AS totalCount",
        "SUM(CASE WHEN ((aesthetics_score != 0 AND label != 0 AND ocr != 0 AND face != 0 AND face != 1 AND face != 2 "
            "AND saliency != 0 AND segmentation != 0 AND head != 0 AND Photos.media_type = 1) OR "
            "(label != 0 AND face != 0 AND Photos.media_type = 2)) THEN 1 ELSE 0 END) AS finishedCount",
        "SUM(CASE WHEN label != 0 THEN 1 ELSE 0 END) AS LabelCount"
    };
    nlohmann::json jsonObj;
    GetMediaAnalysisServiceProgress(jsonObj, idxToCount, columns);
    ANI_INFO_LOG("Progress json is %{public}s", jsonObj.dump().c_str());
    return jsonObj.dump();
}

static std::string GetTotalCount()
{
    Uri uri(URI_TOTAL);
    string clause = VISION_TOTAL_TABLE + "." + MediaColumn::MEDIA_ID + " = " + PhotoColumn::PHOTOS_TABLE+ "." +
        MediaColumn::MEDIA_ID;
    DataShare::DataSharePredicates predicates;
    predicates.InnerJoin(PhotoColumn::PHOTOS_TABLE)->On({ clause });
    predicates.EqualTo(PhotoColumn::PHOTO_HIDDEN_TIME, 0)->And()
        ->EqualTo(MediaColumn::MEDIA_DATE_TRASHED, 0)->And()
        ->EqualTo(MediaColumn::MEDIA_TIME_PENDING, 0);

    vector<string> column = {
        "SUM(CASE WHEN (media_type = 1 OR (media_type = 2 AND (position = 1 OR position = 3))) THEN 1 ELSE 0 END) AS "
            "totalCount"
    };

    int errCode = 0;
    shared_ptr<DataShare::DataShareResultSet> ret = UserFileClient::Query(uri, predicates, column, errCode);
    CHECK_COND_RET(ret != nullptr, "", "ret is nullptr");
    if (ret->GoToFirstRow() != NativeRdb::E_OK) {
        ret->Close();
        ANI_ERR_LOG("GotoFirstRow failed, errCode is %{public}d", errCode);
        return "";
    }
    int totalCount = 0;
    ret->GetInt(0, totalCount);
    ret->Close();
    return to_string(totalCount);
}

static std::string GetFaceAnalysisProgress()
{
    string curTotalCount = GetTotalCount();

    Uri uri(URI_USER_PHOTOGRAPHY_INFO);
    vector<string> column = {
        HIGHLIGHT_ANALYSIS_PROGRESS
    };
    DataShare::DataSharePredicates predicates;
    int errCode = 0;
    shared_ptr<DataShare::DataShareResultSet> ret = UserFileClient::Query(uri, predicates, column, errCode);
    CHECK_COND_RET(ret != nullptr, "", "ret is nullptr");
    if (ret->GoToNextRow() != NativeRdb::E_OK) {
        ret->Close();
        nlohmann::json jsonObj;
        jsonObj["cvFinishedCount"] = 0;
        jsonObj["geoFinishedCount"] = 0;
        jsonObj["searchFinishedCount"] = 0;
        jsonObj["totalCount"] = curTotalCount;
        string retJson = jsonObj.dump();
        ANI_ERR_LOG("GetFaceAnalysisProgress failed, errCode is %{public}d, json is %{public}s", errCode,
            retJson.c_str());
        return retJson;
    }
    string retJson = MediaLibraryAniUtils::GetStringValueByColumn(ret, HIGHLIGHT_ANALYSIS_PROGRESS);
    if (retJson == "" || !nlohmann::json::accept(retJson)) {
        ret->Close();
        ANI_ERR_LOG("retJson is empty or invalid");
        return "";
    }
    nlohmann::json curJsonObj = nlohmann::json::parse(retJson);
    int preTotalCount = curJsonObj["totalCount"];
    if (to_string(preTotalCount) != curTotalCount) {
        ANI_ERR_LOG("preTotalCount != curTotalCount, curTotalCount is %{public}s, preTotalCount is %{public}d",
            curTotalCount.c_str(), preTotalCount);
        curJsonObj["totalCount"] = curTotalCount;
    }
    retJson = curJsonObj.dump();
    ANI_ERR_LOG("GoToNextRow successfully and json is %{public}s", retJson.c_str());
    ret->Close();
    return retJson;
}

static std::string GetHighlightAnalysisProgress()
{
    unordered_map<int, string> idxToCount = {
        {0, "ClearCount"}, {1, "DeleteCount"}, {2, "NotProduceCount"}, {3, "ProduceCount"}, {4, "PushCount"}
    };
    Uri uri(URI_HIGHLIGHT_ALBUM);
    vector<string> columns = {
        "SUM(CASE WHEN highlight_status = -3 THEN 1 ELSE 0 END) AS ClearCount",
        "SUM(CASE WHEN highlight_status = -2 THEN 1 ELSE 0 END) AS DeleteCount",
        "SUM(CASE WHEN highlight_status = -1 THEN 1 ELSE 0 END) AS NotProduceCount",
        "SUM(CASE WHEN highlight_status > 0 THEN 1 ELSE 0 END) AS ProduceCount",
        "SUM(CASE WHEN highlight_status = 1 THEN 1 ELSE 0 END) AS PushCount",
    };
    DataShare::DataSharePredicates predicates;
    int errCode = 0;
    shared_ptr<DataShare::DataShareResultSet> ret = UserFileClient::Query(uri, predicates, columns, errCode);
    CHECK_COND_RET(ret != nullptr, "", "ret is nullptr");
    if (ret->GoToFirstRow() != NativeRdb::E_OK) {
        ANI_ERR_LOG("GotoFirstRow failed, errCode is %{public}d", errCode);
        ret->Close();
        return "";
    }
    nlohmann::json jsonObj;
    for (size_t i = 0; i < columns.size(); ++i) {
        int tmp = -1;
        ret->GetInt(i, tmp);
        jsonObj[idxToCount[i]] = tmp;
    }
    ret->Close();
    string retStr = jsonObj.dump();
    ANI_ERR_LOG("Progress json is %{public}s", retStr.c_str());
    return retStr;
}

static void GetAnalysisProgressExecute(unique_ptr<MediaLibraryAsyncContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "context is nullptr");
    MediaLibraryTracer tracer;
    tracer.Start("JSGetAnalysisProgressExecute");
    std::vector<std::string> fetchColumn;
    DataShare::DataSharePredicates predicates;
    switch (context->analysisType) {
        case ANALYSIS_LABEL: {
            context->analysisProgress = GetLabelAnalysisProgress();
            break;
        }
        case ANALYSIS_FACE: {
            context->analysisProgress = GetFaceAnalysisProgress();
            break;
        }
        case ANALYSIS_HIGHLIGHT: {
            context->analysisProgress = GetHighlightAnalysisProgress();
            break;
        }
        default:
            break;
    }
}

static ani_string GetDataAnalysisProgressComplete(ani_env *env, unique_ptr<MediaLibraryAsyncContext> &context)
{
    ani_string result = nullptr;
    ani_object error = {};
    CHECK_COND_RET(context != nullptr, result, "Async context is null");
    if (context->error == ERR_DEFAULT) {
        MediaLibraryAniUtils::ToAniString(env, context->analysisProgress, result);
    } else {
        context->HandleError(env, error);
    }
    context.reset();
    return result;
}

ani_string MediaLibraryAni::PhotoAccessHelperGetDataAnalysisProgress(ani_env *env, ani_object object,
    ani_enum_item analysisType)
{
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAccessHelperGetDataAnalysisProgress");
    ani_string result = nullptr;
    unique_ptr<MediaLibraryAsyncContext> context = make_unique<MediaLibraryAsyncContext>();
    CHECK_COND_RET(context != nullptr, result, "asyncContext context is null");
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    context->objectInfo = Unwrap(env, object);
    CHECK_COND_RET(context->objectInfo != nullptr, result, "Failed to get object info");
    MediaLibraryEnumAni::EnumGetValueInt32(env, analysisType, context->analysisType);
    GetAnalysisProgressExecute(context);
    return GetDataAnalysisProgressComplete(env, context);
}
} // namespace Media
} // namespace OHOS
