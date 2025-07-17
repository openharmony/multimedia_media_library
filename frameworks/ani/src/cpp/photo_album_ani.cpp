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

#include "photo_album_ani.h"

#include "ani_class_name.h"
#include "fetch_result_ani.h"
#include "file_asset_ani.h"
#include "media_file_utils.h"
#include "media_library_enum_ani.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_ani_log.h"
#include "medialibrary_ani_utils.h"
#include "medialibrary_tracer.h"
#include "photo_map_column.h"
#include "result_set_utils.h"
#include "userfile_client.h"
#include "album_operation_uri.h"
#include "shooting_mode_column.h"

using namespace std;
using namespace OHOS::DataShare;

namespace OHOS::Media {

struct PhotoAlbumAttributes {
    PhotoAlbumType albumType;
    PhotoAlbumSubType albumSubtype;
    std::string albumName;
    std::string albumUri;
    int32_t count;
    std::string coverUri;
};

thread_local PhotoAlbum *PhotoAlbumAni::pAlbumData_ = nullptr;

PhotoAlbumAni::PhotoAlbumAni() : env_(nullptr) {}

PhotoAlbumAni::~PhotoAlbumAni() = default;

ani_status PhotoAlbumAni::PhotoAccessInit(ani_env *env)
{
    ani_class cls;
    if (ANI_OK != env->FindClass(PAH_ANI_CLASS_PHOTO_ALBUM_HANDLE.c_str(), &cls)) {
        ANI_ERR_LOG("Failed to find class: %{public}s", PAH_ANI_CLASS_PHOTO_ALBUM_HANDLE.c_str());
        return ANI_ERROR;
    }

    std::array methods = {
        ani_native_function {"getAssetsInner", nullptr, reinterpret_cast<void *>(PhotoAccessGetPhotoAssets)},
        ani_native_function {"getAssetsSync", nullptr, reinterpret_cast<void *>(PhotoAccessGetPhotoAssetsSync)},
        ani_native_function {"commitModifyInner", nullptr, reinterpret_cast<void *>(PhotoAccessHelperCommitModify)},
        ani_native_function {"addAssetsInner", nullptr, reinterpret_cast<void *>(PhotoAccessHelperAddAssets)},
        ani_native_function {"removeAssetsInner", nullptr, reinterpret_cast<void *>(PhotoAccessHelperRemoveAssets)},
        ani_native_function {"recoverAssetsInner", nullptr, reinterpret_cast<void *>(PhotoAccessHelperRecoverPhotos)},
        ani_native_function {"deleteAssetsInner", nullptr, reinterpret_cast<void *>(PhotoAccessHelperDeletePhotos)},
        ani_native_function {"setCoverUriInner", nullptr, reinterpret_cast<void *>(PhotoAccessHelperSetCoverUri)},
        ani_native_function {"getFaceIdInner", nullptr, reinterpret_cast<void *>(PhotoAccessHelperGetFaceId)},
        ani_native_function {"getImageCount", nullptr, reinterpret_cast<void *>(GetImageCount)},
        ani_native_function {"getVideoCount", nullptr, reinterpret_cast<void *>(GetVideoCount)},
    };

    if (ANI_OK != env->Class_BindNativeMethods(cls, methods.data(), methods.size())) {
        ANI_ERR_LOG("Failed to bind native methods to: %{public}s", PAH_ANI_CLASS_PHOTO_ALBUM_HANDLE.c_str());
        return ANI_ERROR;
    }

    ANI_INFO_LOG("PhotoAccessInit ok");
    return ANI_OK;
}

ani_object PhotoAlbumAni::CreatePhotoAlbumAni(ani_env *env, std::unique_ptr<PhotoAlbum> &albumData)
{
    if (albumData == nullptr) {
        return nullptr;
    }

    ani_class cls {};
    if (albumData->GetResultNapiType() == ResultNapiType::TYPE_PHOTOACCESS_HELPER) {
        CHECK_COND_RET(MediaLibraryAniUtils::FindClass(env, PAH_ANI_CLASS_PHOTO_ALBUM_HANDLE, &cls) == ANI_OK,
            nullptr, "Can't find class");
    } else {
        CHECK_COND_RET(MediaLibraryAniUtils::FindClass(env, UFM_ANI_CLASS_PHOTO_ALBUM_HANDLE, &cls) == ANI_OK,
            nullptr, "Can't find class");
    }

    pAlbumData_ = albumData.release();
    ani_object result = PhotoAlbumAniConstructor(env, cls);
    pAlbumData_ = nullptr;
    return result;
}

ani_object PhotoAlbumAni::CreatePhotoAlbumAni(ani_env *env, std::shared_ptr<PhotoAlbum> &albumData)
{
    if (albumData == nullptr || albumData->GetResultNapiType() != ResultNapiType::TYPE_PHOTOACCESS_HELPER) {
        ANI_ERR_LOG("Unsupported photo album data");
        return nullptr;
    }

    ani_class cls {};
    CHECK_COND_RET(MediaLibraryAniUtils::FindClass(env, PAH_ANI_CLASS_PHOTO_ALBUM_HANDLE, &cls) == ANI_OK,
        nullptr, "Can't find class");

    ani_object result = PhotoAlbumAniConstructor(env, cls);
    PhotoAlbumAni *photoAlbumAni = PhotoAlbumAni::UnwrapPhotoAlbumObject(env, result);
    CHECK_COND_RET(photoAlbumAni != nullptr, nullptr, "PhotoAlbumAni is nullptr");
    photoAlbumAni->photoAlbumPtr = albumData;
    return result;
}

PhotoAlbumAni* PhotoAlbumAni::UnwrapPhotoAlbumObject(ani_env *env, ani_object object)
{
    ani_long photoAlbum {};
    if (ANI_OK != env->Object_GetFieldByName_Long(object, "nativePhotoAlbum", &photoAlbum)) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return nullptr;
    }
    return reinterpret_cast<PhotoAlbumAni*>(photoAlbum);
}

std::shared_ptr<PhotoAlbum> PhotoAlbumAni::GetPhotoAlbumInstance() const
{
    return photoAlbumPtr;
}

void PhotoAlbumAni::SetPhotoAlbumAniProperties()
{
    photoAlbumPtr = shared_ptr<PhotoAlbum>(pAlbumData_);
}

static ani_status GetPhotoAlbumAttributes(ani_env *env, ani_object object, PhotoAlbumAttributes &attrs)
{
    PhotoAlbumAni *photoAlbumAni = PhotoAlbumAni::UnwrapPhotoAlbumObject(env, object);
    CHECK_COND_RET(photoAlbumAni != nullptr, ANI_ERROR, "PhotoAlbumAni is nullptr");
    auto photoAlbum = photoAlbumAni->GetPhotoAlbumInstance();
    CHECK_COND_RET(photoAlbum != nullptr, ANI_ERROR, "PhotoAlbum is nullptr");

    attrs.albumType = photoAlbum->GetPhotoAlbumType();
    attrs.albumSubtype = photoAlbum->GetPhotoAlbumSubType();
    attrs.albumName = photoAlbum->GetAlbumName();
    attrs.albumUri = photoAlbum->GetAlbumUri();
    attrs.count = photoAlbum->GetCount();
    attrs.coverUri = photoAlbum->GetCoverUri();
    return ANI_OK;
}

static ani_status BindAniAttributes(ani_env *env, ani_class cls, ani_object object)
{
    PhotoAlbumAttributes attrs;
    CHECK_STATUS_RET(GetPhotoAlbumAttributes(env, object, attrs), "GetPhotoAlbumAttributes fail");

    ani_method albumTypeSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>albumType", nullptr, &albumTypeSetter), "No <set>albumType");
    ani_enum_item albumType = 0;
    CHECK_STATUS_RET(MediaLibraryEnumAni::ToAniEnum(env, attrs.albumType, albumType), "Get albumType index fail");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, albumTypeSetter, albumType), "<set>albumType fail");

    ani_method albumSubtypeSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>albumSubtype", nullptr, &albumSubtypeSetter), "No <set>subtype");
    ani_enum_item albumSubtype = 0;
    CHECK_STATUS_RET(MediaLibraryEnumAni::ToAniEnum(env, attrs.albumSubtype, albumSubtype),
        "Get albumSubtype index fail");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, albumSubtypeSetter, albumSubtype), "<set>albumType fail");

    ani_method albumNameSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>albumName", nullptr, &albumNameSetter), "No <set>albumName");
    ani_string albumName {};
    CHECK_STATUS_RET(MediaLibraryAniUtils::ToAniString(env, attrs.albumName, albumName), "ToAniString albumName fail");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, albumNameSetter, albumName), "<set>albumName fail");

    ani_method albumUriSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>albumUri", nullptr, &albumUriSetter), "No <set>albumUri");
    ani_string albumUri {};
    CHECK_STATUS_RET(MediaLibraryAniUtils::ToAniString(env, attrs.albumUri, albumUri), "ToAniString albumUri fail");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, albumUriSetter, albumUri), "<set>albumUri fail");

    ani_method countSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>count", nullptr, &countSetter), "No <set>count");
    ani_double count = static_cast<ani_double>(attrs.count);
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, countSetter, count), "<set>count fail");

    ani_method coverUriSetter {};
    CHECK_STATUS_RET(env->Class_FindMethod(cls, "<set>coverUri", nullptr, &coverUriSetter), "No <set>coverUri");
    ani_string coverUri {};
    CHECK_STATUS_RET(MediaLibraryAniUtils::ToAniString(env, attrs.coverUri, coverUri), "ToAniString coverUri fail");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, coverUriSetter, coverUri), "<set>coverUri fail");
    return ANI_OK;
}

ani_object PhotoAlbumAni::PhotoAlbumAniConstructor(ani_env *env, ani_class clazz)
{
    ani_method ctor {};
    CHECK_COND_RET(env->Class_FindMethod(clazz, "<ctor>", nullptr, &ctor) == ANI_OK, nullptr,
        "Failed to find method: <ctor>");

    unique_ptr<PhotoAlbumAni> obj = make_unique<PhotoAlbumAni>();
    obj->env_ = env;
    if (pAlbumData_ != nullptr) {
        obj->SetPhotoAlbumAniProperties();
    }
    ani_object albumHandle {};
    CHECK_COND_RET(env->Object_New(clazz, ctor, &albumHandle, reinterpret_cast<ani_long>(obj.release())) == ANI_OK,
        nullptr, "New PhotoAlbumHandle Fail");
    CHECK_COND_RET(BindAniAttributes(env, clazz, albumHandle) == ANI_OK, nullptr, "PhotoAlbum BindAniAttributes Fail");
    return albumHandle;
}

void PhotoAlbumAni::PhotoAlbumAniDestructor(ani_env *env, ani_object object)
{
    PhotoAlbumAni *photoAlbum = UnwrapPhotoAlbumObject(env, object);
    if (photoAlbum == nullptr) {
        return;
    }
    photoAlbum->env_ = nullptr;
    delete photoAlbum;
}

static int32_t NapiGetAnalysisAlbumPredicates(const shared_ptr<PhotoAlbum>& photoAlbum,
    DataSharePredicates& predicates)
{
    PhotoAlbumSubType subType = photoAlbum->GetPhotoAlbumSubType();
    if (subType == PhotoAlbumSubType::PORTRAIT) {
        MediaLibraryAniUtils::GetPortraitAlbumPredicates(photoAlbum->GetAlbumId(), predicates);
        return E_SUCCESS;
    }
    if (subType == PhotoAlbumSubType::GEOGRAPHY_LOCATION) {
        return MediaLibraryAniUtils::GetAllLocationPredicates(predicates);
    }
    if (subType == PhotoAlbumSubType::SHOOTING_MODE) {
        ShootingModeAlbumType type {};
        if (!ShootingModeAlbum::AlbumNameToShootingModeAlbumType(photoAlbum->GetAlbumName(), type)) {
            ANI_ERR_LOG("Invalid shooting mode album name: %{public}s", photoAlbum->GetAlbumName().c_str());
            return E_INVALID_ARGUMENTS;
        }
        ShootingModeAlbum::GetShootingModeAlbumPredicates(type, predicates, photoAlbum->GetHiddenOnly());
        return E_SUCCESS;
    }
    string albumName = photoAlbum->GetAlbumName();
    if (MediaLibraryAniUtils::IsFeaturedSinglePortraitAlbum(albumName, predicates)) {
        return MediaLibraryAniUtils::GetFeaturedSinglePortraitAlbumPredicates(
            photoAlbum->GetAlbumId(), predicates);
    }
    MediaLibraryAniUtils::GetAnalysisPhotoMapPredicates(photoAlbum->GetAlbumId(), predicates);
    return E_SUCCESS;
}

static int32_t GetPredicatesByAlbumTypes(const shared_ptr<PhotoAlbum> &photoAlbum,
    DataSharePredicates &predicates, const bool hiddenOnly)
{
    int32_t albumId = photoAlbum->GetAlbumId();
    PhotoAlbumSubType subType = photoAlbum->GetPhotoAlbumSubType();
    bool isLocationAlbum = subType == PhotoAlbumSubType::GEOGRAPHY_LOCATION;
    if (albumId <= 0 && !isLocationAlbum) {
        ANI_ERR_LOG("Invalid album ID");
        return E_INVALID_ARGUMENTS;
    }
    PhotoAlbumType type = photoAlbum->GetPhotoAlbumType();
    if ((!PhotoAlbum::CheckPhotoAlbumType(type)) || (!PhotoAlbum::CheckPhotoAlbumSubType(subType))) {
        ANI_ERR_LOG("Invalid album type or subtype: type=%{public}d, subType=%{public}d", static_cast<int>(type),
            static_cast<int>(subType));
        return E_INVALID_ARGUMENTS;
    }

    if (PhotoAlbum::IsUserPhotoAlbum(type, subType)) {
        return MediaLibraryAniUtils::GetUserAlbumPredicates(photoAlbum->GetAlbumId(), predicates, hiddenOnly);
    }

    if (PhotoAlbum::IsSourceAlbum(type, subType)) {
        return MediaLibraryAniUtils::GetSourceAlbumPredicates(photoAlbum->GetAlbumId(), predicates, hiddenOnly);
    }

    if (type == PhotoAlbumType::SMART) {
        return NapiGetAnalysisAlbumPredicates(photoAlbum, predicates);
    }

    if (type == PhotoAlbumType::SYSTEM) {
        return MediaLibraryAniUtils::GetSystemAlbumPredicates(subType, predicates, hiddenOnly);
    }

    ANI_ERR_LOG("Invalid album type and subtype: type=%{public}d, subType=%{public}d", static_cast<int>(type),
        static_cast<int>(subType));
    return E_INVALID_ARGUMENTS;
}

static ani_status ParseArgsGetPhotoAssets(ani_env *env, ani_object object, ani_object fetchOptions,
    unique_ptr<PhotoAlbumAniContext> &context)
{
    context->objectInfo = PhotoAlbumAni::UnwrapPhotoAlbumObject(env, object);
    if (context->objectInfo == nullptr) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID, __FUNCTION__, __LINE__);
        return ANI_INVALID_ARGS;
    }

    /* Parse the first argument */
    ani_status result = MediaLibraryAniUtils::GetFetchOption(env, fetchOptions, ASSET_FETCH_OPT, context);
    if (result != ANI_OK) {
        AniError::ThrowError(env, JS_INNER_FAIL);
        return result;
    }

    auto photoAlbum = context->objectInfo->GetPhotoAlbumInstance();
    auto ret = GetPredicatesByAlbumTypes(photoAlbum, context->predicates, photoAlbum->GetHiddenOnly());
    if (ret != E_SUCCESS) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return ANI_INVALID_ARGS;
    }
    CHECK_STATUS_RET(MediaLibraryAniUtils::AddDefaultAssetColumns(env, context->fetchColumn,
        PhotoColumn::IsPhotoColumn, AniAssetType::TYPE_PHOTO), "AddDefaultAssetColumns failed");
    if (photoAlbum->GetHiddenOnly() || photoAlbum->GetPhotoAlbumSubType() == PhotoAlbumSubType::HIDDEN) {
        if (!MediaLibraryAniUtils::IsSystemApp()) {
            AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
            return ANI_ERROR;
        }
        // sort by hidden time desc if is hidden asset
        context->predicates.IndexedBy(PhotoColumn::PHOTO_HIDDEN_TIME_INDEX);
    }
    return ANI_OK;
}

static bool IsFeaturedSinglePortraitAlbum(const shared_ptr<PhotoAlbum>& photoAlbum)
{
    constexpr int portraitAlbumId = 0;
    return photoAlbum->GetPhotoAlbumSubType() == PhotoAlbumSubType::CLASSIFY &&
        photoAlbum->GetAlbumName().compare(to_string(portraitAlbumId)) == 0;
}

static void ConvertColumnsForPortrait(unique_ptr<PhotoAlbumAniContext> &context)
{
    if (context == nullptr || context->objectInfo == nullptr) {
        ANI_ERR_LOG("context is null or PhotoAlbumNapi is null");
        return;
    }

    shared_ptr<PhotoAlbum> photoAlbum = context->objectInfo->GetPhotoAlbumInstance();
    if (photoAlbum == nullptr || (photoAlbum->GetPhotoAlbumSubType() != PhotoAlbumSubType::PORTRAIT &&
        !IsFeaturedSinglePortraitAlbum(photoAlbum))) {
        return;
    }

    for (size_t i = 0; i < context->fetchColumn.size(); i++) {
        if (context->fetchColumn[i] != "count(*)") {
            context->fetchColumn[i] = PhotoColumn::PHOTOS_TABLE + "." + context->fetchColumn[i];
        }
    }
}

static void PhotoAccessGetPhotoAssetsExecute(ani_env *env, unique_ptr<PhotoAlbumAniContext> &context)
{
    Uri uri(PAH_QUERY_PHOTO_MAP);
    ConvertColumnsForPortrait(context);
    int32_t errCode = 0;
    auto resultSet = UserFileClient::Query(uri, context->predicates, context->fetchColumn, errCode);
    if (resultSet == nullptr) {
        context->SaveError(E_HAS_DB_ERROR);
        return;
    }
    context->fetchResult = make_unique<FetchResult<FileAsset>>(move(resultSet));
    context->fetchResult->SetResultNapiType(ResultNapiType::TYPE_PHOTOACCESS_HELPER);
}

static ani_object GetPhotoAssetsComplete(ani_env *env, unique_ptr<PhotoAlbumAniContext> &context)
{
    ani_object fetchRes {};
    ani_object errorObj {};
    if (context->fetchResult != nullptr) {
        fetchRes = FetchFileResultAni::CreateFetchFileResult(env, move(context->fetchResult));
        if (fetchRes == nullptr) {
            MediaLibraryAniUtils::CreateAniErrorObject(env, errorObj, ERR_MEM_ALLOCATION,
                "Failed to create ani object for FetchFileResult");
        }
    } else {
        ANI_ERR_LOG("No fetch file result found!");
        context->HandleError(env, errorObj);
    }
    context.reset();
    return fetchRes;
}

ani_object PhotoAlbumAni::PhotoAccessGetPhotoAssets(ani_env *env, ani_object object, ani_object fetchOptions)
{
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAccessGetPhotoAssets");

    unique_ptr<PhotoAlbumAniContext> context = make_unique<PhotoAlbumAniContext>();
    if (ANI_OK != ParseArgsGetPhotoAssets(env, object, fetchOptions, context)) {
        AniError::ThrowError(env, JS_INNER_FAIL);
        return nullptr;
    }
    PhotoAccessGetPhotoAssetsExecute(env, context);
    return GetPhotoAssetsComplete(env, context);
}

static ani_object PhotoAccessGetPhotoAssetsExecuteSync(ani_env *env, unique_ptr<PhotoAlbumAniContext> &context)
{
    Uri uri(PAH_QUERY_PHOTO_MAP);
    ConvertColumnsForPortrait(context);
    int32_t errCode = 0;
    auto resultSet = UserFileClient::Query(uri, context->predicates, context->fetchColumn, errCode);
    CHECK_NULLPTR_RET(resultSet);
    auto fetchResult = make_unique<FetchResult<FileAsset>>(move(resultSet));
    fetchResult->SetResultNapiType(ResultNapiType::TYPE_PHOTOACCESS_HELPER);

    std::vector<std::unique_ptr<FileAsset>> fileAssetArray;
    auto file = fetchResult->GetFirstObject();
    while (file != nullptr) {
        fileAssetArray.push_back(move(file));
        file = fetchResult->GetNextObject();
    }
    ani_object result {};
    CHECK_COND_RET(MediaLibraryAniUtils::ToFileAssetAniArray(env, fileAssetArray, result) == ANI_OK, nullptr,
        "ToFileAssetAniArray fail");
    return result;
}

ani_object PhotoAlbumAni::PhotoAccessGetPhotoAssetsSync(ani_env *env, ani_object object, ani_object fetchOptions)
{
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAccessGetPhotoAssetsSync");

    unique_ptr<PhotoAlbumAniContext> context = make_unique<PhotoAlbumAniContext>();
    if (ANI_OK != ParseArgsGetPhotoAssets(env, object, fetchOptions, context)) {
        AniError::ThrowError(env, JS_INNER_FAIL);
        return nullptr;
    }
    return PhotoAccessGetPhotoAssetsExecuteSync(env, context);
}

void SyncAlbumName(ani_env *env, ani_object object, std::shared_ptr<PhotoAlbum> &photoAlbum)
{
    std::string albumName = "";
    CHECK_IF_EQUAL(MediaLibraryAniUtils::GetProperty(env, object, "albumName", albumName) == ANI_OK,
        "Failed to get albumName");
    CHECK_IF_EQUAL(!albumName.empty(), "Get empty albumName");
    photoAlbum->SetAlbumName(albumName);
}

static ani_status ParseArgsCommitModify(ani_env *env, ani_object object, unique_ptr<PhotoAlbumAniContext> &context)
{
    context->objectInfo = PhotoAlbumAni::UnwrapPhotoAlbumObject(env, object);
    if (context->objectInfo == nullptr) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID, __FUNCTION__, __LINE__);
        return ANI_INVALID_ARGS;
    }

    auto photoAlbum = context->objectInfo->GetPhotoAlbumInstance();
    if (photoAlbum == nullptr) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return ANI_INVALID_ARGS;
    }
    if (!PhotoAlbum::IsUserPhotoAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType())) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return ANI_INVALID_ARGS;
    }

    SyncAlbumName(env, object, photoAlbum);
    if (MediaFileUtils::CheckAlbumName(photoAlbum->GetAlbumName()) < 0) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return ANI_INVALID_ARGS;
    }
    context->predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, to_string(photoAlbum->GetAlbumId()));
    context->valuesBucket.Put(PhotoAlbumColumns::ALBUM_NAME, photoAlbum->GetAlbumName());
    context->valuesBucket.Put(PhotoAlbumColumns::ALBUM_COVER_URI, photoAlbum->GetCoverUri());
    return ANI_OK;
}

static void CommitModifyExecute(ani_env *env, unique_ptr<PhotoAlbumAniContext> &context)
{
    string commitModifyUri = (context->resultNapiType == ResultNapiType::TYPE_USERFILE_MGR) ?
        UFM_UPDATE_PHOTO_ALBUM : PAH_UPDATE_PHOTO_ALBUM;
    Uri uri(commitModifyUri);
    int changedRows = UserFileClient::Update(uri, context->predicates, context->valuesBucket);
    context->SaveError(changedRows);
    context->changedRows = changedRows;
}

static void CommitModifyComplete(ani_env *env, unique_ptr<PhotoAlbumAniContext> &context)
{
    ani_object errorObj {};
    if (context->error != ERR_DEFAULT) {
        context->HandleError(env, errorObj);
    }
    context.reset();
}

void PhotoAlbumAni::PhotoAccessHelperCommitModify(ani_env *env, ani_object object)
{
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAccessHelperCommitModify");

    unique_ptr<PhotoAlbumAniContext> context = make_unique<PhotoAlbumAniContext>();
    CHECK_IF_EQUAL(ParseArgsCommitModify(env, object, context) == ANI_OK, "ParseArgsCommitModify fail");
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    CommitModifyExecute(env, context);
    CommitModifyComplete(env, context);
}

static ani_status GetAssetsIdArray(ani_env *env, ani_object photoAssets, std::vector<string> &assetsArray)
{
    ani_boolean isArray = MediaLibraryAniUtils::isArray(env, photoAssets);
    if (isArray == ANI_FALSE) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID, "Failed to check array type");
        return ANI_INVALID_ARGS;
    }

    ani_double length = 0;
    CHECK_STATUS_RET(env->Object_GetPropertyByName_Double(photoAssets, "length", &length),
        "Call method <get>length failed.");
    if (length <= 0) {
        ANI_ERR_LOG("Failed to check array length: %{public}f", length);
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID, "Failed to check array length");
        return ANI_INVALID_ARGS;
    }

    for (ani_int i = 0; i < static_cast<ani_int>(length); i++) {
        ani_ref asset {};
        CHECK_STATUS_RET(env->Object_CallMethodByName_Ref(photoAssets, "$_get", "I:Lstd/core/Object;", &asset, i),
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
        assetsArray.push_back(obj->GetFileAssetInstance()->GetUri());
    }
    return ANI_OK;
}

static ani_status ParseArgsAddAssets(ani_env *env, ani_object object, ani_object photoAssets,
    unique_ptr<PhotoAlbumAniContext> &context)
{
    context->objectInfo = PhotoAlbumAni::UnwrapPhotoAlbumObject(env, object);
    if (context->objectInfo == nullptr) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID, __FUNCTION__, __LINE__);
        return ANI_INVALID_ARGS;
    }

    auto photoAlbum = context->objectInfo->GetPhotoAlbumInstance();
    if (photoAlbum == nullptr) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return ANI_INVALID_ARGS;
    }
    if (!PhotoAlbum::IsUserPhotoAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType())) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return ANI_INVALID_ARGS;
    }

    std::vector<string> assetsArray;
    CHECK_STATUS_RET(GetAssetsIdArray(env, photoAssets, assetsArray), "Parse photoAssets uri fail");
    if (assetsArray.empty()) {
        AniError::ThrowError(env, JS_INNER_FAIL);
        return ANI_INVALID_ARGS;
    }
    int32_t albumId = photoAlbum->GetAlbumId();
    for (const auto &assetId : assetsArray) {
        DataShareValuesBucket valuesBucket;
        valuesBucket.Put(PhotoColumn::PHOTO_OWNER_ALBUM_ID, albumId);
        valuesBucket.Put(PhotoColumn::MEDIA_ID, assetId);
        context->valuesBuckets.push_back(valuesBucket);
    }
    return ANI_OK;
}

static bool FetchNewCount(unique_ptr<PhotoAlbumAniContext> &context)
{
    auto photoAlbum = context->objectInfo->GetPhotoAlbumInstance();
    if (photoAlbum == nullptr) {
        ANI_ERR_LOG("photoAlbum is nullptr");
        return false;
    }
    string queryUri = (context->resultNapiType == ResultNapiType::TYPE_USERFILE_MGR) ?
        UFM_QUERY_PHOTO_ALBUM : PAH_QUERY_PHOTO_ALBUM;
    Uri qUri(queryUri);
    int errCode = 0;
    DataSharePredicates predicates;
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, photoAlbum->GetAlbumId());
    vector<string> fetchColumn = {
        PhotoAlbumColumns::ALBUM_ID,
        PhotoAlbumColumns::ALBUM_COUNT,
    };
    bool isSmartAlbum = (photoAlbum->GetPhotoAlbumType() == PhotoAlbumType::SMART);
    if (!isSmartAlbum) {
        fetchColumn.push_back(PhotoAlbumColumns::ALBUM_IMAGE_COUNT);
        fetchColumn.push_back(PhotoAlbumColumns::ALBUM_VIDEO_COUNT);
    }
    auto resultSet = UserFileClient::Query(qUri, predicates, fetchColumn, errCode);
    if (resultSet == nullptr) {
        ANI_ERR_LOG("resultSet == nullptr, errCode is %{public}d", errCode);
        return false;
    }
    if (resultSet->GoToFirstRow() != 0) {
        ANI_ERR_LOG("go to first row failed");
        return false;
    }
    bool hiddenOnly = photoAlbum->GetHiddenOnly();
    int imageCount = (hiddenOnly || isSmartAlbum) ? -1 :
            get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_IMAGE_COUNT, resultSet, TYPE_INT32));
    int videoCount = (hiddenOnly || isSmartAlbum) ? -1 :
            get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_VIDEO_COUNT, resultSet, TYPE_INT32));
    context->newCount =
            get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_COUNT, resultSet, TYPE_INT32));
    context->newImageCount = imageCount;
    context->newVideoCount = videoCount;
    return true;
}

static void PhotoAlbumAddAssetsExecute(ani_env *env, unique_ptr<PhotoAlbumAniContext> &context)
{
    if (context->valuesBuckets.empty()) {
        return;
    }
    string addAssetsUri = (context->resultNapiType == ResultNapiType::TYPE_USERFILE_MGR) ?
        UFM_PHOTO_ALBUM_ADD_ASSET : PAH_PHOTO_ALBUM_ADD_ASSET;
    Uri uri(addAssetsUri);
    
    auto changedRows = UserFileClient::BatchInsert(uri, context->valuesBuckets);
    if (changedRows < 0) {
        context->SaveError(changedRows);
        return;
    }
    context->changedRows = changedRows;
    if (!FetchNewCount(context)) {
        ANI_ERR_LOG("Update count failed");
        context->SaveError(E_HAS_DB_ERROR);
    }
}

static void PhotoAlbumAddAssetsComplete(ani_env *env, unique_ptr<PhotoAlbumAniContext> &context)
{
    ani_object errorObj {};
    if (context->error == ERR_DEFAULT) {
        auto photoAlbum = context->objectInfo->GetPhotoAlbumInstance();
        photoAlbum->SetCount(context->newCount);
        photoAlbum->SetImageCount(context->newImageCount);
        photoAlbum->SetVideoCount(context->newVideoCount);
    } else {
        context->HandleError(env, errorObj);
    }
    context.reset();
}

void PhotoAlbumAni::PhotoAccessHelperAddAssets(ani_env *env, ani_object object, ani_object photoAssets)
{
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAccessHelperAddAssets");

    unique_ptr<PhotoAlbumAniContext> context = make_unique<PhotoAlbumAniContext>();
    CHECK_IF_EQUAL(ParseArgsAddAssets(env, object, photoAssets, context) == ANI_OK, "ParseArgsAddAssets fail");
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    PhotoAlbumAddAssetsExecute(env, context);
    PhotoAlbumAddAssetsComplete(env, context);
}

static ani_status ParseArgsRemoveAssets(ani_env *env, ani_object object, ani_object photoAssets,
    unique_ptr<PhotoAlbumAniContext> &context)
{
    context->objectInfo = PhotoAlbumAni::UnwrapPhotoAlbumObject(env, object);
    if (context->objectInfo == nullptr) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID, __FUNCTION__, __LINE__);
        return ANI_INVALID_ARGS;
    }

    auto photoAlbum = context->objectInfo->GetPhotoAlbumInstance();
    if (photoAlbum == nullptr) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return ANI_INVALID_ARGS;
    }
    if (!PhotoAlbum::IsUserPhotoAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType())) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return ANI_INVALID_ARGS;
    }

    std::vector<string> assetsArray;
    CHECK_STATUS_RET(GetAssetsIdArray(env, photoAssets, assetsArray), "Parse photoAssets uri fail");
    if (assetsArray.empty()) {
        AniError::ThrowError(env, JS_INNER_FAIL);
        return ANI_INVALID_ARGS;
    }
    context->predicates.EqualTo(PhotoColumn::PHOTO_OWNER_ALBUM_ID, to_string(photoAlbum->GetAlbumId()));
    context->predicates.And()->In(PhotoColumn::MEDIA_ID, assetsArray);
    return ANI_OK;
}

static void PhotoAlbumRemoveAssetsExecute(ani_env *env, unique_ptr<PhotoAlbumAniContext> &context)
{
    if (context->predicates.GetOperationList().empty()) {
        return;
    }

    string removeAssetsUri = (context->resultNapiType == ResultNapiType::TYPE_USERFILE_MGR) ?
        UFM_PHOTO_ALBUM_REMOVE_ASSET : PAH_PHOTO_ALBUM_REMOVE_ASSET;
    Uri uri(removeAssetsUri);
    auto deletedRows = UserFileClient::Delete(uri, context->predicates);
    if (deletedRows < 0) {
        context->SaveError(deletedRows);
        return;
    }
    context->changedRows = deletedRows;
    if (!FetchNewCount(context)) {
        ANI_ERR_LOG("Update count failed");
        context->SaveError(E_HAS_DB_ERROR);
    }
}

static void PhotoAlbumRemoveAssetsComplete(ani_env *env, unique_ptr<PhotoAlbumAniContext> &context)
{
    ani_object errorObj {};
    if (context->error == ERR_DEFAULT) {
        auto photoAlbum = context->objectInfo->GetPhotoAlbumInstance();
        photoAlbum->SetCount(context->newCount);
        photoAlbum->SetImageCount(context->newImageCount);
        photoAlbum->SetVideoCount(context->newVideoCount);
    } else {
        context->HandleError(env, errorObj);
    }
    context.reset();
}

void PhotoAlbumAni::PhotoAccessHelperRemoveAssets(ani_env *env, ani_object object, ani_object photoAssets)
{
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAccessHelperRemoveAssets");

    unique_ptr<PhotoAlbumAniContext> context = make_unique<PhotoAlbumAniContext>();
    CHECK_IF_EQUAL(ParseArgsRemoveAssets(env, object, photoAssets, context) == ANI_OK, "ParseArgsRemoveAssets fail");
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    PhotoAlbumRemoveAssetsExecute(env, context);
    PhotoAlbumRemoveAssetsComplete(env, context);
}

static ani_status TrashAlbumParseArgs(ani_env *env, ani_object object, ani_object photoAssets,
    unique_ptr<PhotoAlbumAniContext> &context)
{
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return ANI_ERROR;
    }

    context->objectInfo = PhotoAlbumAni::UnwrapPhotoAlbumObject(env, object);
    if (context->objectInfo == nullptr) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID, __FUNCTION__, __LINE__);
        return ANI_INVALID_ARGS;
    }

    auto photoAlbum = context->objectInfo->GetPhotoAlbumInstance();
    if (photoAlbum == nullptr) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return ANI_INVALID_ARGS;
    }
    if (!PhotoAlbum::IsTrashAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType())) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID, "Failed to check trash album type");
        return ANI_INVALID_ARGS;
    }

    std::vector<string> uris;
    CHECK_STATUS_RET(MediaLibraryAniUtils::GetUriArrayFromAssets(env, photoAssets, uris), "Parse uris fail");
    if (uris.empty()) {
        AniError::ThrowError(env, JS_INNER_FAIL);
        return ANI_INVALID_ARGS;
    }
    context->predicates.In(MediaColumn::MEDIA_ID, uris);
    context->valuesBucket.Put(MediaColumn::MEDIA_DATE_TRASHED, 0);
    return ANI_OK;
}

static void TrashAlbumExecute(ani_env *env, unique_ptr<PhotoAlbumAniContext> &context, const std::string &optUri)
{
    if (context->predicates.GetOperationList().empty()) {
        ANI_ERR_LOG("Operation list is empty.");
        return;
    }
    Uri uri(optUri);
    int changedRows = UserFileClient::Update(uri, context->predicates, context->valuesBucket);
    if (changedRows < 0) {
        context->SaveError(changedRows);
        ANI_ERR_LOG("Trash album executed, changeRows: %{public}d.", changedRows);
        return;
    }
    context->changedRows = changedRows;
}

static void TrashAlbumComplete(ani_env *env, unique_ptr<PhotoAlbumAniContext> &context)
{
    ani_object errorObj {};
    if (context->error != ERR_DEFAULT) {
        context->HandleError(env, errorObj);
    }
    context.reset();
}

static void RecoverPhotosExecute(ani_env *env, unique_ptr<PhotoAlbumAniContext> &context)
{
    std::string uri = (context->resultNapiType == ResultNapiType::TYPE_USERFILE_MGR) ?
        UFM_RECOVER_PHOTOS : PAH_RECOVER_PHOTOS;
    TrashAlbumExecute(env, context, uri);
}

static void RecoverPhotosComplete(ani_env *env, unique_ptr<PhotoAlbumAniContext> &context)
{
    TrashAlbumComplete(env, context);
}

void PhotoAlbumAni::PhotoAccessHelperRecoverPhotos(ani_env *env, ani_object object, ani_object photoAssets)
{
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAccessHelperRecoverPhotos");

    unique_ptr<PhotoAlbumAniContext> context = make_unique<PhotoAlbumAniContext>();
    CHECK_IF_EQUAL(TrashAlbumParseArgs(env, object, photoAssets, context) == ANI_OK, "TrashAlbumParseArgs fail");
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    RecoverPhotosExecute(env, context);
    RecoverPhotosComplete(env, context);
}

static void DeletePhotosExecute(ani_env *env, unique_ptr<PhotoAlbumAniContext> &context)
{
    std::string uri = (context->resultNapiType == ResultNapiType::TYPE_USERFILE_MGR) ?
        UFM_DELETE_PHOTOS : PAH_DELETE_PHOTOS;
    TrashAlbumExecute(env, context, uri);
}

static void DeletePhotosComplete(ani_env *env, unique_ptr<PhotoAlbumAniContext> &context)
{
    TrashAlbumComplete(env, context);
}

void PhotoAlbumAni::PhotoAccessHelperDeletePhotos(ani_env *env, ani_object object, ani_object photoAssets)
{
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAccessHelperDeletePhotos");

    unique_ptr<PhotoAlbumAniContext> context = make_unique<PhotoAlbumAniContext>();
    CHECK_IF_EQUAL(TrashAlbumParseArgs(env, object, photoAssets, context) == ANI_OK, "TrashAlbumParseArgs fail");
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    DeletePhotosExecute(env, context);
    DeletePhotosComplete(env, context);
}

static ani_status ParseArgsSetCoverUri(ani_env *env, ani_object object, ani_string uri,
    unique_ptr<PhotoAlbumAniContext> &context)
{
    context->objectInfo = PhotoAlbumAni::UnwrapPhotoAlbumObject(env, object);
    if (context->objectInfo == nullptr) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID, __FUNCTION__, __LINE__);
        return ANI_INVALID_ARGS;
    }

    std::string coverUri;
    CHECK_STATUS_RET(MediaLibraryAniUtils::GetParamStringPathMax(env, uri, coverUri), "Parse coverUri failed.");
    
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "Only system apps can update album cover");
        return ANI_ERROR;
    }

    auto photoAlbum = context->objectInfo->GetPhotoAlbumInstance();
    if (photoAlbum == nullptr) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return ANI_INVALID_ARGS;
    }
    context->predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, to_string(photoAlbum->GetAlbumId()));
    context->valuesBucket.Put(PhotoAlbumColumns::ALBUM_COVER_URI, coverUri);
    return ANI_OK;
}

void PhotoAlbumAni::PhotoAccessHelperSetCoverUri(ani_env *env, ani_object object, ani_string uri)
{
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAccessHelperSetCoverUri");

    unique_ptr<PhotoAlbumAniContext> context = make_unique<PhotoAlbumAniContext>();
    CHECK_IF_EQUAL(ParseArgsSetCoverUri(env, object, uri, context) == ANI_OK, "ParseArgsSetCoverUri fail");
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    CommitModifyExecute(env, context);
    CommitModifyComplete(env, context);
}

static void PhotoAccessHelperGetFaceIdExec(ani_env *env, unique_ptr<PhotoAlbumAniContext> &context)
{
    auto photoAlbum = context->objectInfo->GetPhotoAlbumInstance();
    PhotoAlbumSubType albumSubType = photoAlbum->GetPhotoAlbumSubType();
    if (albumSubType != PhotoAlbumSubType::PORTRAIT && albumSubType != PhotoAlbumSubType::GROUP_PHOTO) {
        ANI_WARN_LOG("albumSubType: %{public}d, not support getFaceId", albumSubType);
        return;
    }

    Uri uri(PAH_QUERY_ANA_PHOTO_ALBUM);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, photoAlbum->GetAlbumId());
    vector<string> fetchColumn = { GROUP_TAG };
    int errCode = 0;

    auto resultSet = UserFileClient::Query(uri, predicates, fetchColumn, errCode);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != 0) {
        if (errCode == E_PERMISSION_DENIED) {
            context->error = OHOS_PERMISSION_DENIED_CODE;
        } else {
            context->SaveError(E_FAIL);
        }
        ANI_ERR_LOG("get face id failed, errCode is %{public}d", errCode);
        return;
    }

    context->faceTag = GetStringVal(GROUP_TAG, resultSet);
}

static ani_string GetFaceIdComplete(ani_env *env, unique_ptr<PhotoAlbumAniContext> &context)
{
    ani_string result {};
    ani_object errorObj {};
    if (context->error != ERR_DEFAULT) {
        context->HandleError(env, errorObj);
    } else {
        CHECK_COND_RET(MediaLibraryAniUtils::ToAniString(env, context->faceTag, result) == ANI_OK, nullptr,
            "ToAniString faceTag fail");
    }
    context.reset();
    return result;
}

ani_string PhotoAlbumAni::PhotoAccessHelperGetFaceId(ani_env *env, ani_object object)
{
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAccessHelperGetFaceId");
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "Only system apps can get the Face ID of the album");
        return nullptr;
    }

    unique_ptr<PhotoAlbumAniContext> context = make_unique<PhotoAlbumAniContext>();
    context->objectInfo = PhotoAlbumAni::UnwrapPhotoAlbumObject(env, object);
    if (context->objectInfo == nullptr) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID, __FUNCTION__, __LINE__);
        return nullptr;
    }
    PhotoAccessHelperGetFaceIdExec(env, context);
    return GetFaceIdComplete(env, context);
}

ani_double PhotoAlbumAni::GetImageCount(ani_env *env, ani_object object)
{
    PhotoAlbumAni *photoAlbumAni = PhotoAlbumAni::UnwrapPhotoAlbumObject(env, object);
    if (photoAlbumAni == nullptr || photoAlbumAni->GetPhotoAlbumInstance() == nullptr) {
        ANI_ERR_LOG("photoAlbumAni or photoAlbum is nullptr");
        return 0;
    }
    int32_t imageCount = photoAlbumAni->GetPhotoAlbumInstance()->GetImageCount();
    return static_cast<ani_double>(imageCount);
}

ani_double PhotoAlbumAni::GetVideoCount(ani_env *env, ani_object object)
{
    PhotoAlbumAni *photoAlbumAni = PhotoAlbumAni::UnwrapPhotoAlbumObject(env, object);
    if (photoAlbumAni == nullptr || photoAlbumAni->GetPhotoAlbumInstance() == nullptr) {
        ANI_ERR_LOG("photoAlbumAni or photoAlbum is nullptr");
        return 0;
    }
    int32_t videoCount = photoAlbumAni->GetPhotoAlbumInstance()->GetVideoCount();
    return static_cast<ani_double>(videoCount);
}
} // namespace OHOS::Media