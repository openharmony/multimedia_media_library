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

#include <string>
#include <array>
#include <mutex>
#include "ani.h"
#include "ani_class_name.h"
#include "medialibrary_ani_log.h"
#include "medialibrary_tracer.h"
#include "userfile_client.h"
#include "vision_column.h"
#include "story_album_column.h"
#include "media_change_request_ani.h"
#include "medialibrary_ani_utils.h"
#include "directory_ex.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_ani_enum_comm.h"
#include "media_file_utils.h"
#include "media_file_uri.h"
#include "media_ani_native_impl.h"
#include "datashare_predicates.h"
#include "userfilemgr_uri.h"
#include "datashare_helper.h"
#include "safe_map.h"
#include "ani_error.h"
#include "album_operation_uri.h"

#define MEDIALIBRARY_COMPATIBILITY

using namespace OHOS::DataShare;

namespace OHOS {
namespace Media {
std::mutex MediaLibraryAni::sUserFileClientMutex_;
thread_local std::unique_ptr<ChangeListenerAni> g_listObj = nullptr;

static SafeMap<int32_t, std::shared_ptr<ThumbnailBatchGenerateObserver>> thumbnailGenerateObserverMap;
static SafeMap<int32_t, std::shared_ptr<ThumbnailGenerateHandler>> thumbnailGenerateHandlerMap;
static std::atomic<int32_t> requestIdCounter_ = 0;
static std::atomic<int32_t> requestIdCallback_ = 0;

const int32_t SECOND_ENUM = 2;
const int32_t THIRD_ENUM = 3;

ani_status MediaLibraryAni::PhotoAccessHelperInit(ani_env *env)
{
    static const char *className = ANI_CLASS_PHOTO_ACCESS_HELPER.c_str();
    ani_class cls;
    ani_status status = env->FindClass(className, &cls);
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to find class: %{public}s", className);
        return status;
    }

    std::array methods = {
        ani_native_function {"getAlbumsInner", nullptr, reinterpret_cast<void *>(GetPhotoAlbums)},
        ani_native_function {"release", nullptr, reinterpret_cast<void *>(Release)},
        ani_native_function {"applyChanges", nullptr, reinterpret_cast<void *>(ApplyChanges)},
        ani_native_function {"createAsset1", nullptr, reinterpret_cast<void *>(createAsset1)},
        ani_native_function {"getAssetsSync", nullptr, reinterpret_cast<void *>(GetAssetsSync)},
        ani_native_function {"getFileAssetsInfo", nullptr, reinterpret_cast<void *>(GetFileAssetsInfo)},
        ani_native_function {"getAssetsInner", nullptr, reinterpret_cast<void *>(GetAssetsInner)},
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

    ANI_INFO_LOG("PhotoAccessHelperInit ok");
    return ANI_OK;
}

static ani_status ParseArgsStartCreateThumbnailTask(ani_env *env, ani_object object, ani_object predicate,
    ani_object callback, unique_ptr<MediaLibraryAsyncContext> &context)
{
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return ANI_ERROR;
    }

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
    thumbnailGenerateHandlerMap.Insert(requestId, dataHandler);
}

void MediaLibraryAni::OnThumbnailGenerated(ani_env *env, ani_object callback, void *context, void *data)
{
    if (env == nullptr) {
        return;
    }
    std::shared_ptr<ThumbnailGenerateHandler> dataHandler;
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
    if (isAsync) {
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

ani_object MediaLibraryAni::Constructor(ani_env *env, ani_object context)
{
    ANI_INFO_LOG("getPhotoAccessHelper start");
    if (context == nullptr) {
        ANI_ERR_LOG("context is nullptr");
        return nullptr;
    }

    ani_object result = nullptr;
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAcessHelperAniConstructor");
    std::unique_ptr<MediaLibraryAni> nativeHandle = std::make_unique<MediaLibraryAni>();

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

    static const char *className = ANI_CLASS_PHOTO_ACCESS_HELPER.c_str();
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        ANI_ERR_LOG("Failed to find class: %{public}s", className);
        return result;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "J:V", &ctor)) {
        ANI_ERR_LOG("Failed to find method: %{public}s", "ctor");
        return result;
    }

    if (ANI_OK !=env->Object_New(cls, ctor, &result, reinterpret_cast<ani_long>(nativeHandle.release()))) {
        ANI_ERR_LOG("New PhotoAccessHelper Fail");
    }
    return result;
}

MediaLibraryAni* MediaLibraryAni::Unwrap(ani_env *env, ani_object object)
{
    ani_long photoAccessHelper;
    if (ANI_OK != env->Object_GetFieldByName_Long(object, "nativePhotoAccessHelper", &photoAccessHelper)) {
        return nullptr;
    }
    return reinterpret_cast<MediaLibraryAni*>(photoAccessHelper);
}

static bool ParseLocationAlbumTypes(unique_ptr<MediaLibraryAsyncContext> &context, const int32_t albumSubType)
{
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
        context->predicates.InnerJoin(HIGHLIGHT_ALBUM_TABLE)->On(onClause);
        context->predicates.OrderByDesc(MAX_DATE_ADDED + ", " + GENERATE_TIME);
    }

    return ANI_OK;
}

static void RestrictAlbumSubtypeOptions(unique_ptr<MediaLibraryAsyncContext> &context)
{
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

static void AddDefaultColumnsForNonAnalysisAlbums(MediaLibraryAsyncContext& context)
{
    if (!context.isAnalysisAlbum) {
        context.fetchColumn.push_back(PhotoAlbumColumns::ALBUM_IMAGE_COUNT);
        context.fetchColumn.push_back(PhotoAlbumColumns::ALBUM_VIDEO_COUNT);
        context.fetchColumn.push_back(PhotoAlbumColumns::ALBUM_LPATH);
    }
}

static ani_status GetAlbumFetchOption(ani_env *env, unique_ptr<MediaLibraryAsyncContext> &context,
    ani_object fetchOptions)
{
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
        AddDefaultColumnsForNonAnalysisAlbums(*context);
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
    auto resultSet = UserFileClient::Query(uri, context->predicates, context->fetchColumn, errCode);
    if (resultSet == nullptr) {
        ANI_ERR_LOG("resultSet == nullptr, errCode is %{public}d", errCode);
        if (errCode == E_PERMISSION_DENIED) {
            context->SaveError(E_PERMISSION_DENIED);
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
}

static ani_object GetPhotoAlbumsComplete(ani_env *env, unique_ptr<MediaLibraryAsyncContext> &context)
{
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
    asyncContext->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    asyncContext->objectInfo = Unwrap(env, object);
    CHECK_COND_WITH_RET_MESSAGE(env, ParseArgsGetPhotoAlbum(env, albumTypeItem, albumSubtypeItem,
        fetchOptions, asyncContext) == ANI_OK, nullptr, "Failed to parse get albums options");
    GetPhotoAlbumsExecute(env, asyncContext);
    return(GetPhotoAlbumsComplete(env, asyncContext));
}

ani_status MediaLibraryAni::Release(ani_env *env, ani_object object)
{
    auto mediaLibraryAni = Unwrap(env, object);
    if (mediaLibraryAni == nullptr) {
        ANI_ERR_LOG("mediaLibraryAni is nullptr");
        return ANI_ERROR;
    }
    delete mediaLibraryAni;
    mediaLibraryAni = nullptr;
    return ANI_OK;
}

ani_status MediaLibraryAni::ApplyChanges(ani_env *env, ani_object object)
{
    auto* mediaChangeRequestAni = MediaChangeRequestAni::Unwrap(env, object);
    if (mediaChangeRequestAni == nullptr) {
        ANI_ERR_LOG("Failed to unwrap MediaChangeRequestAni");
        return ANI_ERROR;
    }
    return mediaChangeRequestAni->ApplyChanges(env, object);
}

static bool CheckDisplayNameParams(MediaLibraryAsyncContext* context)
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

static bool CheckRelativePathParams(MediaLibraryAsyncContext *context)
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

static void GetCreateUri(MediaLibraryAsyncContext *context, string &uri)
{
    if (context->resultNapiType == ResultNapiType::TYPE_USERFILE_MGR ||
        context->resultNapiType == ResultNapiType::TYPE_PHOTOACCESS_HELPER) {
        switch (context->assetType) {
            case TYPE_PHOTO:
                uri = (context->resultNapiType == ResultNapiType::TYPE_USERFILE_MGR) ?
                    ((context->isCreateByComponent) ? UFM_CREATE_PHOTO_COMPONENT : UFM_CREATE_PHOTO) :
                    ((context->isCreateByComponent) ? PAH_CREATE_PHOTO_COMPONENT : PAH_CREATE_PHOTO);
                break;
            case TYPE_AUDIO:
                uri = (context->isCreateByComponent) ? UFM_CREATE_AUDIO_COMPONENT : UFM_CREATE_AUDIO;
                break;
            default:
                ANI_ERR_LOG("Unsupported creation napitype %{public}d", static_cast<int32_t>(context->assetType));
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
                                           MediaLibraryAsyncContext *context)
{
    bool isValid = false;
    string displayName = context->valuesBucket.Get(MEDIA_DATA_DB_NAME, isValid);
    if (!isValid) {
        ANI_ERR_LOG("getting title is invalid");
        return;
    }
    auto fileAsset = make_unique<FileAsset>();
    fileAsset->SetId(id);
    MediaType mediaType = MediaFileUtils::GetMediaType(displayName);
    fileAsset->SetUri(uri);
    fileAsset->SetMediaType(mediaType);
    fileAsset->SetDisplayName(displayName);
    fileAsset->SetTitle(MediaFileUtils::GetTitleFromDisplayName(displayName));
    fileAsset->SetResultNapiType(ResultNapiType::TYPE_PHOTOACCESS_HELPER);
    fileAsset->SetTimePending(UNCREATE_FILE_TIMEPENDING);
    context->fileAsset = move(fileAsset);
}

#ifdef MEDIALIBRARY_COMPATIBILITY
static void SetFileAssetByIdV9(int32_t id, const string &networkId, MediaLibraryAsyncContext *context)
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

static void PhotoAccessCreateAssetExecute(MediaLibraryAsyncContext* context)
{
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
    if ((context->resultNapiType != ResultNapiType::TYPE_PHOTOACCESS_HELPER) && (!CheckRelativePathParams(context))) {
        context->error = JS_E_RELATIVEPATH;
        return;
    }

    string uri;
    GetCreateUri(context, uri);
    Uri createFileUri(uri);
    string outUri;
    int index = UserFileClient::InsertExt(createFileUri, context->valuesBucket, outUri);
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

ani_object MediaLibraryAni::createAsset1([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object thisObject,
    [[maybe_unused]] ani_string stringObj)
{
    MediaLibraryTracer tracer;
    tracer.Start("createAsset1");
    ani_object result_obj = {};
    MediaLibraryAsyncContext *context = nullptr;
    PhotoAccessCreateAssetExecute(context);
    return result_obj;
}
} // namespace Media
} // namespace OHOS
