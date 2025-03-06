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

#include <array>
#include <mutex>
#include "ani.h"
#include "medialibrary_ani_log.h"
#include "medialibrary_tracer.h"
#include "photo_access_helper_ani.h"
#include "userfile_client.h"
#include "vision_column.h"
#include "story_album_column.h"
#include "media_change_request_ani.h"
#include "medialibrary_ani_utils.h"
#include <iostream>
#include <string>
#include "directory_ex.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_ani_enum_comm.h"
#include "media_file_utils.h"
#include "media_file_uri.h"

#define MEDIALIBRARY_COMPATIBILITY

namespace OHOS {
namespace Media {
std::mutex PhotoAccessHelperAni::sUserFileClientMutex_;
thread_local std::unique_ptr<ChangeListenerAni> g_listObj = nullptr;

const int32_t SECOND_ENUM = 2;
const int32_t THIRD_ENUM = 3;

static int mygettid(ani_env *env, ani_object obj)
{
    return gettid();
}

ani_status PhotoAccessHelperAni::PhotoAccessHelperInit(ani_env *env)
{
    DEBUG_LOG_T("PhotoAccessHelperInit begin");
    static const char *className = "Lphoto_access_helper/PhotoAccessHelperHandle;";
    ani_class cls;
    ani_status status = env->FindClass(className, &cls);
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to find class: %{public}s", className);
        env->ThrowError(reinterpret_cast<ani_error>(status));
    }

    std::array methods = {
        ani_native_function {"getAlbums", nullptr, reinterpret_cast<void *>(PhotoAccessHelperAni::GetPhotoAlbums) },
        ani_native_function {"release", ":V", reinterpret_cast<void *>(PhotoAccessHelperAni::Release) },
        ani_native_function {"applyChanges", "Lmedia_library_common/MediaChangeRequest:V",
            reinterpret_cast<void *>(PhotoAccessHelperAni::ApplyChanges) },
        ani_native_function {"createAsset1", nullptr,
            reinterpret_cast<void *>(PhotoAccessHelperAni::createAsset1) },
        ani_native_function {"gettid", ":I", reinterpret_cast<void *>(mygettid)},
    };

    status = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to bind native methods to: %{public}s", className);
        env->ThrowError(reinterpret_cast<ani_error>(status));
    }
    return ANI_OK;
}

bool InitUserFileClient(ani_env *env, [[maybe_unused]] ani_object context, bool isAsync = false)
{
    if (isAsync) {
        std::unique_lock<std::mutex> helperLock(PhotoAccessHelperAni::sUserFileClientMutex_);
        if (!UserFileClient::IsValid()) {
            UserFileClient::Init(env, context);
            if (!UserFileClient::IsValid()) {
                ANI_ERR_LOG("UserFileClient creation failed");
                DEBUG_LOG_T("Constructor UserFileClient creation failed");
                helperLock.unlock();
                return false;
            }
        }
        helperLock.unlock();
    }
    return true;
}

ani_object PhotoAccessHelperAni::Constructor(ani_env *env, [[maybe_unused]] ani_class clazz,
    [[maybe_unused]] ani_object context)
{
    ani_object result = nullptr;
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAcessHelperAniConstructor");
    std::unique_ptr<PhotoAccessHelperAni> nativeHandle = std::make_unique<PhotoAccessHelperAni>();

    nativeHandle->env_ = env;
    // Initialize the ChangeListener object
    if (g_listObj == nullptr) {
        g_listObj = std::make_unique<ChangeListenerAni>(env);
    }

    // Only !Async Need to init UserFileClient and be locked. How to solve Async?
    if (!InitUserFileClient(env, context)) {
        DEBUG_LOG_T("Constructor InitUserFileClient failed");
        return result;
    }

    static const char *className = "Lphoto_access_helper/PhotoAccessHelperHandle;";
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

PhotoAccessHelperAni* PhotoAccessHelperAni::Unwrap(ani_env *env, ani_object object)
{
    ani_long photoAccessHelper;
    if (ANI_OK != env->Object_GetFieldByName_Long(object, "nativePhotoAccessHelper", &photoAccessHelper)) {
        return nullptr;
    }
    return reinterpret_cast<PhotoAccessHelperAni*>(photoAccessHelper);
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

static ani_status ParseAlbumTypes(ani_env *env, ani_int albumTypeIndex, ani_int albumSubtypeIndex,
    std::unique_ptr<MediaLibraryAsyncContext>& context)
{
    /* Parse the first argument to photo album type */
    AlbumType albumType;
    int32_t albumTypeInt;
    CHECK_COND_WITH_RET_MESSAGE(env, MediaLibraryEnumAni::EnumGetValueInt32(env, EnumTypeInt32::AlbumTypeAni,
        albumTypeIndex, albumTypeInt) == ANI_OK, ANI_INVALID_ARGS, "Failed to get albumType");
    albumType = static_cast<AlbumType>(albumTypeInt);
    if (!PhotoAlbum::CheckPhotoAlbumType(static_cast<PhotoAlbumType>(albumTypeInt))) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return ANI_ERROR;
    }
    context->isAnalysisAlbum = (albumTypeInt == PhotoAlbumType::SMART) ? 1 : 0;

    /* Parse the second argument to photo album subType */
    PhotoAlbumSubType photoAlbumSubType;  // 枚举用AlbumSubtype?
    int32_t albumSubTypeInt;
    CHECK_COND_WITH_RET_MESSAGE(env, MediaLibraryEnumAni::EnumGetValueInt32(env, EnumTypeInt32::AlbumSubtypeAni,
        albumSubtypeIndex, albumSubTypeInt) == ANI_OK, ANI_INVALID_ARGS, "Failed to get albumSubtype");
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
        ALBUM_FETCH_OPT, context) != ANI_OK, ANI_INVALID_ARGS, "GetAlbumFetchOption error");
    if (!context->uri.empty()) {
        if (context->uri.find(PhotoAlbumColumns::ANALYSIS_ALBUM_URI_PREFIX) != std::string::npos) {
            context->isAnalysisAlbum = 1; // 1:is an analysis album
        }
    }
    return ANI_OK;
}


static ani_status ParseArgsGetPhotoAlbum(ani_env *env, ani_int albumTypeIndex, ani_int albumSubtypeIndex,
    ani_object fetchOptions, std::unique_ptr<MediaLibraryAsyncContext>& context)
{
    // Parse fetchOptions if exists.
    ani_boolean isUndefined;
    env->Reference_IsUndefined(fetchOptions, &isUndefined);
    if (!isUndefined) {
        CHECK_COND_WITH_RET_MESSAGE(env, GetAlbumFetchOption(env, context, fetchOptions) != ANI_OK,
            ANI_INVALID_ARGS, "GetAlbumFetchOption error");
    } else {
        ANI_INFO_LOG("fetchOptions is undefined. There is no need to parse fetchOptions.");
    }
    // Parse albumType and albumSubtype
    CHECK_COND_WITH_RET_MESSAGE(env, ParseAlbumTypes(env, albumTypeIndex, albumSubtypeIndex,
        context) != ANI_OK, ANI_INVALID_ARGS, "ParseAlbumTypes error");
    RestrictAlbumSubtypeOptions(context);
    if (context->isLocationAlbum != PhotoAlbumSubType::GEOGRAPHY_LOCATION &&
        context->isLocationAlbum != PhotoAlbumSubType::GEOGRAPHY_CITY) {
        CHECK_COND_WITH_RET_MESSAGE(env, AddDefaultPhotoAlbumColumns(env, context->fetchColumn) != ANI_OK,
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

static ani_object GetPhotoAlbumsCompleteCallback(ani_env *env, unique_ptr<MediaLibraryAsyncContext> &context)
{
    MediaLibraryTracer tracer;
    tracer.Start("GetPhotoAlbumsCompleteCallback");

    ani_object fetchRes = FetchFileResultAni::CreateFetchFileResult(env, move(context->fetchPhotoAlbumResult));
    context = nullptr;
    return fetchRes;
}

ani_object PhotoAccessHelperAni::GetPhotoAlbums(ani_env *env, ani_object object, ani_int albumTypeIndex,
    ani_int albumSubtypeIndex, ani_object fetchOptions)
{
    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    asyncContext->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    CHECK_COND_WITH_RET_MESSAGE(env, ParseArgsGetPhotoAlbum(env, albumTypeIndex, albumSubtypeIndex,
        fetchOptions, asyncContext), nullptr, "Failed to parse get albums options");
    GetPhotoAlbumsExecute(env, asyncContext);
    return(GetPhotoAlbumsCompleteCallback(env, asyncContext));
}

ani_status PhotoAccessHelperAni::Release(ani_env *env, ani_object object)
{
    auto photoAccessHelperAni = Unwrap(env, object);
    delete photoAccessHelperAni;
    return ANI_OK;
}

ani_status PhotoAccessHelperAni::ApplyChanges(ani_env *env, ani_object object)
{
    auto mediaChangeRequestAni = MediaChangeRequestAni::Unwrap(env, object);
    return mediaChangeRequestAni->ApplyChanges(env, object);
}

static bool CheckDisplayNameParams(MediaLibraryAsyncContext* context)
{
    if (context == nullptr) {
        DEBUG_LOG_T("Async context is null");
        return false;
    }
    if (!context->isCreateByComponent) {
        bool isValid = false;
        string displayName = context->valuesBucket.Get(MEDIA_DATA_DB_NAME, isValid);
        if (!isValid) {
            DEBUG_LOG_T("getting displayName is invalid");
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
        DEBUG_LOG_T("getting title is invalid");
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
        DEBUG_LOG_T("get title is invalid");
        return;
    }
    string relativePath = context->valuesBucket.Get(MEDIA_DATA_DB_RELATIVE_PATH, isValid);
    if (!isValid) {
        ANI_ERR_LOG("get relativePath is invalid");
        DEBUG_LOG_T("get relativePath is invalid");
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
    DEBUG_LOG_T("PhotoAccessCreateAssetExecute Begin");
    MediaLibraryTracer tracer;
    tracer.Start("JScreateAsset1");

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
        DEBUG_LOG_T("PInsertExt fail, index: %d", index);
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
    DEBUG_LOG_T("PhotoAccessCreateAssetExecute End");
}

ani_object PhotoAccessHelperAni::createAsset1([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object thisObject,
    [[maybe_unused]] ani_string stringObj)
{
    MediaLibraryTracer tracer;
    tracer.Start("createAsset1");
    DEBUG_LOG_T("PhotoAccessHelperAni::createAsset1 Begin in thread");
    ani_object result_obj = {};

    static const char *className = "Lphoto_access_helper/Result;";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        DEBUG_LOG_T("Not found '%s'", className);
        return result_obj;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor)) {
        DEBUG_LOG_T("get ctor Failed '%s'", className);
        return result_obj;
    }

    unique_ptr<MediaLibraryAsyncContext> asyncContext = make_unique<MediaLibraryAsyncContext>();
    asyncContext->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    asyncContext->assetType = TYPE_PHOTO;
    asyncContext->isCreateByComponent = false;
    string displayName;
    MediaLibraryAniUtils::GetString(env, stringObj, displayName);
    DEBUG_LOG_T("PhotoAccessHelperAni::createAsset1 displayName: %s", displayName.c_str());
    MediaType mediaType = MediaFileUtils::GetMediaType(displayName);
    if (!(mediaType == MEDIA_TYPE_IMAGE || mediaType == MEDIA_TYPE_VIDEO)) {
        DEBUG_LOG_T("invalid file type");
    }
    asyncContext->valuesBucket.Put(MEDIA_DATA_DB_NAME, displayName);
    asyncContext->valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, static_cast<int32_t>(mediaType));

    PhotoAccessCreateAssetExecute(asyncContext.get());
    ani_class errCls;
    if (ANI_OK != env->FindClass("Lphoto_access_helper/PhotoAccessHelperError;", &errCls)) {
        DEBUG_LOG_T("Not found Lphoto_access_helper/PhotoAccessHelperError");
        return result_obj;
    }
    ani_method errCtor;
    if (ANI_OK != env->Class_FindMethod(errCls, "<ctor>", nullptr, &errCtor)) {
        DEBUG_LOG_T("get errCtor Failed Lphoto_access_helper/PhotoAccessHelperError");
        return result_obj;
    }
    ani_object errObj;
    std::string name = "no ok";
    ani_string errStr{};
    env->String_NewUTF8(name.c_str(), name.size(), &errStr);

    if (ANI_OK != env->Object_New(errCls, errCtor, &errObj, reinterpret_cast<ani_int>(asyncContext->error), errStr)) {
        DEBUG_LOG_T("Create Object Failed, Lphoto_access_helper/PhotoAccessHelperError");
        return result_obj;
    }
    ani_class photoAssetCls;
    if (ANI_OK != env->FindClass("Lphoto_access_helper/PhotoAsset;", &photoAssetCls)) {
        DEBUG_LOG_T("Not found Lphoto_access_helper/PhotoAsset");
        return result_obj;
    }
    ani_method photoAssetCtor;
    if (ANI_OK != env->Class_FindMethod(photoAssetCls, "<ctor>", nullptr, &photoAssetCtor)) {
        DEBUG_LOG_T("get photoAssetCtor Failed Lphoto_access_helper/PhotoAsset");
        return result_obj;
    }
    ani_object photoAssetObj;
    if (ANI_OK != env->Object_New(photoAssetCls, photoAssetCtor,
        &photoAssetObj, reinterpret_cast<ani_long>(asyncContext->fileAsset.release()))) {
        DEBUG_LOG_T("Create Object Failed, Lphoto_access_helper/PhotoAsset");
        return result_obj;
    }
    if (ANI_OK != env->Object_New(cls, ctor, &result_obj, photoAssetObj, errObj)) {
        DEBUG_LOG_T("Create Object Failed, Lphoto_access_helper/Result");
        return result_obj;
    }
    DEBUG_LOG_T("Create Object Success, Lphoto_access_helper/Result");
    return result_obj;
}
} // namespace Media
} // namespace OHOS
