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
#define MLOG_TAG "PhotoAlbumNapi"

#include "photo_album_napi.h"
#include <nlohmann/json.hpp>

#include "fetch_file_result_napi.h"
#include "file_asset_napi.h"
#include "media_file_utils.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_napi_log.h"
#include "medialibrary_napi_utils_ext.h"
#include "medialibrary_tracer.h"
#include "photo_map_column.h"
#include "result_set_utils.h"
#include "userfile_client.h"

using namespace std;
using namespace OHOS::DataShare;

namespace OHOS::Media {
thread_local PhotoAlbum *PhotoAlbumNapi::pAlbumData_ = nullptr;
thread_local napi_ref PhotoAlbumNapi::constructor_ = nullptr;
thread_local napi_ref PhotoAlbumNapi::photoAccessConstructor_ = nullptr;
static const string PHOTO_ALBUM_CLASS = "UserFileMgrPhotoAlbum";
static const string PHOTOACCESS_PHOTO_ALBUM_CLASS = "PhotoAccessPhotoAlbum";
static const string COUNT_GROUP_BY = "count(*) AS count";

struct TrashAlbumExecuteOpt {
    napi_env env;
    void *data;
    string tracerLabel;
    string uri;
};

using CompleteCallback = napi_async_complete_callback;

PhotoAlbumNapi::PhotoAlbumNapi() : env_(nullptr) {}

PhotoAlbumNapi::~PhotoAlbumNapi() = default;

napi_value PhotoAlbumNapi::Init(napi_env env, napi_value exports)
{
    NapiClassInfo info = {
        .name = PHOTO_ALBUM_CLASS,
        .ref = &constructor_,
        .constructor = PhotoAlbumNapiConstructor,
        .props = {
            DECLARE_NAPI_GETTER_SETTER("albumName", JSGetAlbumName, JSSetAlbumName),
            DECLARE_NAPI_GETTER("albumUri", JSGetAlbumUri),
            DECLARE_NAPI_GETTER("count", JSGetAlbumCount),
            DECLARE_NAPI_GETTER("albumType", JSGetPhotoAlbumType),
            DECLARE_NAPI_GETTER("albumSubType", JSGetPhotoAlbumSubType),
            DECLARE_NAPI_GETTER_SETTER("coverUri", JSGetCoverUri, JSSetCoverUri),
            DECLARE_NAPI_GETTER("dateModified", JSGetDateModified),
            DECLARE_NAPI_FUNCTION("commitModify", JSCommitModify),
            DECLARE_NAPI_FUNCTION("addPhotoAssets", JSPhotoAlbumAddAssets),
            DECLARE_NAPI_FUNCTION("removePhotoAssets", JSPhotoAlbumRemoveAssets),
            DECLARE_NAPI_FUNCTION("getPhotoAssets", JSGetPhotoAssets),
            DECLARE_NAPI_FUNCTION("recoverPhotoAssets", JSRecoverPhotos),
            DECLARE_NAPI_FUNCTION("deletePhotoAssets", JSDeletePhotos),
            // PrivateAlbum.recover
            DECLARE_NAPI_FUNCTION("recover", PrivateAlbumRecoverPhotos),
            // PrivateAlbum.delete
            DECLARE_NAPI_FUNCTION("delete", PrivateAlbumDeletePhotos),
        }
    };

    MediaLibraryNapiUtils::NapiDefineClass(env, exports, info);
    return exports;
}

napi_value PhotoAlbumNapi::PhotoAccessInit(napi_env env, napi_value exports)
{
    NapiClassInfo info = {
        .name = PHOTOACCESS_PHOTO_ALBUM_CLASS,
        .ref = &photoAccessConstructor_,
        .constructor = PhotoAlbumNapiConstructor,
        .props = {
            DECLARE_NAPI_GETTER_SETTER("albumName", JSPhotoAccessGetAlbumName, JSPhotoAccessSetAlbumName),
            DECLARE_NAPI_GETTER("albumUri", JSPhotoAccessGetAlbumUri),
            DECLARE_NAPI_GETTER("count", JSPhotoAccessGetAlbumCount),
            DECLARE_NAPI_GETTER("imageCount", JSPhotoAccessGetAlbumImageCount),
            DECLARE_NAPI_GETTER("videoCount", JSPhotoAccessGetAlbumVideoCount),
            DECLARE_NAPI_GETTER("albumType", JSGetPhotoAlbumType),
            DECLARE_NAPI_GETTER("albumSubtype", JSGetPhotoAlbumSubType),
            DECLARE_NAPI_GETTER("coverUri", JSGetCoverUri),
            DECLARE_NAPI_GETTER("latitude", JSGetLatitude),
            DECLARE_NAPI_GETTER("longitude", JSGetLongitude),
            DECLARE_NAPI_GETTER("lpath", JSGetAlbumLPath),
            DECLARE_NAPI_FUNCTION("commitModify", PhotoAccessHelperCommitModify),
            DECLARE_NAPI_FUNCTION("addAssets", PhotoAccessHelperAddAssets),
            DECLARE_NAPI_FUNCTION("removeAssets", PhotoAccessHelperRemoveAssets),
            DECLARE_NAPI_FUNCTION("getAssets", JSPhotoAccessGetPhotoAssets),
            DECLARE_NAPI_FUNCTION("recoverAssets", PhotoAccessHelperRecoverPhotos),
            DECLARE_NAPI_FUNCTION("deleteAssets", PhotoAccessHelperDeletePhotos),
            DECLARE_NAPI_FUNCTION("setCoverUri", PhotoAccessHelperSetCoverUri),
            DECLARE_NAPI_FUNCTION("getAssetsSync", JSPhotoAccessGetPhotoAssetsSync),
            DECLARE_NAPI_FUNCTION("getSharedPhotoAssets", JSPhotoAccessGetSharedPhotoAssets),
            DECLARE_NAPI_FUNCTION("getFaceId", PhotoAccessHelperGetFaceId),
        }
    };

    MediaLibraryNapiUtils::NapiDefineClass(env, exports, info);
    return exports;
}

napi_value PhotoAlbumNapi::CreatePhotoAlbumNapi(napi_env env, unique_ptr<PhotoAlbum> &albumData)
{
    if (albumData == nullptr) {
        return nullptr;
    }

    napi_value constructor;
    napi_ref constructorRef;
    if (albumData->GetResultNapiType() == ResultNapiType::TYPE_PHOTOACCESS_HELPER) {
        constructorRef = photoAccessConstructor_;
    } else {
        constructorRef = constructor_;
    }
    CHECK_ARGS(env, napi_get_reference_value(env, constructorRef, &constructor), JS_INNER_FAIL);

    napi_value result = nullptr;
    pAlbumData_ = albumData.release();
    CHECK_ARGS(env, napi_new_instance(env, constructor, 0, nullptr, &result), JS_INNER_FAIL);
    pAlbumData_ = nullptr;
    return result;
}

napi_value PhotoAlbumNapi::CreatePhotoAlbumNapi(napi_env env, shared_ptr<PhotoAlbum>& albumData)
{
    if (albumData == nullptr || albumData->GetResultNapiType() != ResultNapiType::TYPE_PHOTOACCESS_HELPER) {
        NAPI_ERR_LOG("Unsupported photo album data");
        return nullptr;
    }

    napi_value constructor = nullptr;
    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_reference_value(env, photoAccessConstructor_, &constructor), JS_INNER_FAIL);
    CHECK_ARGS(env, napi_new_instance(env, constructor, 0, nullptr, &result), JS_INNER_FAIL);
    CHECK_COND(env, result != nullptr, JS_INNER_FAIL);

    PhotoAlbumNapi* photoAlbumNapi = nullptr;
    CHECK_ARGS(env, napi_unwrap(env, result, reinterpret_cast<void**>(&photoAlbumNapi)), JS_INNER_FAIL);
    CHECK_COND(env, photoAlbumNapi != nullptr, JS_INNER_FAIL);
    photoAlbumNapi->photoAlbumPtr = albumData;
    return result;
}

int32_t PhotoAlbumNapi::GetAlbumId() const
{
    return photoAlbumPtr->GetAlbumId();
}

int32_t PhotoAlbumNapi::GetCount() const
{
    return photoAlbumPtr->GetCount();
}

void PhotoAlbumNapi::SetCount(int32_t count)
{
    return photoAlbumPtr->SetCount(count);
}

int32_t PhotoAlbumNapi::GetImageCount() const
{
    return photoAlbumPtr->GetImageCount();
}

void PhotoAlbumNapi::SetImageCount(int32_t count)
{
    return photoAlbumPtr->SetImageCount(count);
}

int32_t PhotoAlbumNapi::GetVideoCount() const
{
    return photoAlbumPtr->GetVideoCount();
}

void PhotoAlbumNapi::SetVideoCount(int32_t count)
{
    return photoAlbumPtr->SetVideoCount(count);
}

const string& PhotoAlbumNapi::GetAlbumUri() const
{
    return photoAlbumPtr->GetAlbumUri();
}

const string& PhotoAlbumNapi::GetCoverUri() const
{
    return photoAlbumPtr->GetCoverUri();
}

int64_t PhotoAlbumNapi::GetDateModified() const
{
    return photoAlbumPtr->GetDateModified();
}

const string& PhotoAlbumNapi::GetAlbumName() const
{
    return photoAlbumPtr->GetAlbumName();
}

PhotoAlbumType PhotoAlbumNapi::GetPhotoAlbumType() const
{
    return photoAlbumPtr->GetPhotoAlbumType();
}

PhotoAlbumSubType PhotoAlbumNapi::GetPhotoAlbumSubType() const
{
    return photoAlbumPtr->GetPhotoAlbumSubType();
}

double PhotoAlbumNapi::GetLatitude() const
{
    return photoAlbumPtr->GetLatitude();
}

double PhotoAlbumNapi::GetLongitude() const
{
    return photoAlbumPtr->GetLongitude();
}

const string& PhotoAlbumNapi::GetLPath() const
{
    return photoAlbumPtr->GetLPath();
}

shared_ptr<PhotoAlbum> PhotoAlbumNapi::GetPhotoAlbumInstance() const
{
    return photoAlbumPtr;
}

bool PhotoAlbumNapi::GetHiddenOnly() const
{
    return photoAlbumPtr->GetHiddenOnly();
}

void PhotoAlbumNapi::SetHiddenOnly(const bool hiddenOnly_)
{
    return photoAlbumPtr->SetHiddenOnly(hiddenOnly_);
}

void PhotoAlbumNapi::SetPhotoAlbumNapiProperties()
{
    photoAlbumPtr = shared_ptr<PhotoAlbum>(pAlbumData_);
}

// Constructor callback
napi_value PhotoAlbumNapi::PhotoAlbumNapiConstructor(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_undefined(env, &result), JS_INNER_FAIL);

    napi_value thisVar = nullptr;
    CHECK_ARGS(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr), JS_INNER_FAIL);
    if (thisVar == nullptr) {
        NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return result;
    }

    unique_ptr<PhotoAlbumNapi> obj = make_unique<PhotoAlbumNapi>();
    obj->env_ = env;
    if (pAlbumData_ != nullptr) {
        obj->SetPhotoAlbumNapiProperties();
    }
    CHECK_ARGS(env, napi_wrap(env, thisVar, reinterpret_cast<void *>(obj.get()),
        PhotoAlbumNapi::PhotoAlbumNapiDestructor, nullptr, nullptr), JS_INNER_FAIL);
    obj.release();
    return thisVar;
}

void PhotoAlbumNapi::PhotoAlbumNapiDestructor(napi_env env, void *nativeObject, void *finalizeHint)
{
    auto *album = reinterpret_cast<PhotoAlbumNapi*>(nativeObject);
    if (album != nullptr) {
        delete album;
        album = nullptr;
    }
}

napi_value UnwrapPhotoAlbumObject(napi_env env, napi_callback_info info, PhotoAlbumNapi** obj)
{
    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_undefined(env, &result), JS_INNER_FAIL);

    napi_value thisVar = nullptr;
    CHECK_ARGS(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr), JS_INNER_FAIL);
    if (thisVar == nullptr) {
        NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return result;
    }

    CHECK_ARGS(env, napi_unwrap(env, thisVar, reinterpret_cast<void **>(obj)), JS_INNER_FAIL);
    if (obj == nullptr) {
        NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return result;
    }

    CHECK_ARGS(env, napi_get_boolean(env, true, &result), JS_INNER_FAIL);
    return result;
}

napi_value PhotoAlbumNapi::JSGetAlbumName(napi_env env, napi_callback_info info)
{
    PhotoAlbumNapi *obj = nullptr;
    CHECK_NULLPTR_RET(UnwrapPhotoAlbumObject(env, info, &obj));

    napi_value jsResult = nullptr;
    CHECK_ARGS(env, napi_create_string_utf8(env, obj->GetAlbumName().c_str(), NAPI_AUTO_LENGTH, &jsResult),
        JS_INNER_FAIL);
    return jsResult;
}

napi_value PhotoAlbumNapi::JSPhotoAccessGetAlbumName(napi_env env, napi_callback_info info)
{
    PhotoAlbumNapi *obj = nullptr;
    CHECK_NULLPTR_RET(UnwrapPhotoAlbumObject(env, info, &obj));

    napi_value jsResult = nullptr;
    CHECK_ARGS(env, napi_create_string_utf8(env, obj->GetAlbumName().c_str(), NAPI_AUTO_LENGTH, &jsResult),
        JS_INNER_FAIL);
    return jsResult;
}

napi_value PhotoAlbumNapi::JSGetAlbumUri(napi_env env, napi_callback_info info)
{
    PhotoAlbumNapi *obj = nullptr;
    CHECK_NULLPTR_RET(UnwrapPhotoAlbumObject(env, info, &obj));

    napi_value jsResult = nullptr;
    CHECK_ARGS(env, napi_create_string_utf8(env, obj->GetAlbumUri().c_str(), NAPI_AUTO_LENGTH, &jsResult),
        JS_INNER_FAIL);
    return jsResult;
}

napi_value PhotoAlbumNapi::JSPhotoAccessGetAlbumUri(napi_env env, napi_callback_info info)
{
    PhotoAlbumNapi *obj = nullptr;
    CHECK_NULLPTR_RET(UnwrapPhotoAlbumObject(env, info, &obj));

    napi_value jsResult = nullptr;
    CHECK_ARGS(env, napi_create_string_utf8(env, obj->GetAlbumUri().c_str(), NAPI_AUTO_LENGTH, &jsResult),
        JS_INNER_FAIL);
    return jsResult;
}

napi_value PhotoAlbumNapi::JSGetAlbumCount(napi_env env, napi_callback_info info)
{
    PhotoAlbumNapi *obj = nullptr;
    CHECK_NULLPTR_RET(UnwrapPhotoAlbumObject(env, info, &obj));

    napi_value jsResult = nullptr;
    CHECK_ARGS(env, napi_create_int32(env, obj->GetCount(), &jsResult), JS_INNER_FAIL);
    return jsResult;
}

napi_value PhotoAlbumNapi::JSPhotoAccessGetAlbumCount(napi_env env, napi_callback_info info)
{
    PhotoAlbumNapi *obj = nullptr;
    CHECK_NULLPTR_RET(UnwrapPhotoAlbumObject(env, info, &obj));

    napi_value jsResult = nullptr;
    CHECK_ARGS(env, napi_create_int32(env, obj->GetCount(), &jsResult), JS_INNER_FAIL);
    return jsResult;
}

napi_value PhotoAlbumNapi::JSPhotoAccessGetAlbumImageCount(napi_env env, napi_callback_info info)
{
    PhotoAlbumNapi *obj = nullptr;
    CHECK_NULLPTR_RET(UnwrapPhotoAlbumObject(env, info, &obj));

    napi_value jsResult = nullptr;
    CHECK_ARGS(env, napi_create_int32(env, obj->GetImageCount(), &jsResult), JS_INNER_FAIL);
    return jsResult;
}

napi_value PhotoAlbumNapi::JSPhotoAccessGetAlbumVideoCount(napi_env env, napi_callback_info info)
{
    PhotoAlbumNapi *obj = nullptr;
    CHECK_NULLPTR_RET(UnwrapPhotoAlbumObject(env, info, &obj));

    napi_value jsResult = nullptr;
    CHECK_ARGS(env, napi_create_int32(env, obj->GetVideoCount(), &jsResult), JS_INNER_FAIL);
    return jsResult;
}

napi_value PhotoAlbumNapi::JSGetPhotoAlbumType(napi_env env, napi_callback_info info)
{
    PhotoAlbumNapi *obj = nullptr;
    CHECK_NULLPTR_RET(UnwrapPhotoAlbumObject(env, info, &obj));

    napi_value jsResult = nullptr;
    CHECK_ARGS(env, napi_create_int32(env, obj->GetPhotoAlbumType(), &jsResult), JS_INNER_FAIL);
    return jsResult;
}

napi_value PhotoAlbumNapi::JSGetPhotoAlbumSubType(napi_env env, napi_callback_info info)
{
    PhotoAlbumNapi *obj = nullptr;
    CHECK_NULLPTR_RET(UnwrapPhotoAlbumObject(env, info, &obj));

    napi_value jsResult = nullptr;
    CHECK_ARGS(env, napi_create_int32(env, obj->GetPhotoAlbumSubType(), &jsResult), JS_INNER_FAIL);
    return jsResult;
}

napi_value PhotoAlbumNapi::JSGetCoverUri(napi_env env, napi_callback_info info)
{
    PhotoAlbumNapi *obj = nullptr;
    CHECK_NULLPTR_RET(UnwrapPhotoAlbumObject(env, info, &obj));

    napi_value jsResult = nullptr;
    CHECK_ARGS(env, napi_create_string_utf8(env, obj->GetCoverUri().c_str(), NAPI_AUTO_LENGTH, &jsResult),
        JS_INNER_FAIL);
    return jsResult;
}

napi_value PhotoAlbumNapi::JSGetLatitude(napi_env env, napi_callback_info info)
{
    PhotoAlbumNapi *obj = nullptr;
    CHECK_NULLPTR_RET(UnwrapPhotoAlbumObject(env, info, &obj));

    napi_value jsResult = nullptr;
    CHECK_ARGS(env, napi_create_double(env, obj->GetLatitude(), &jsResult), JS_INNER_FAIL);
    return jsResult;
}

napi_value PhotoAlbumNapi::JSGetLongitude(napi_env env, napi_callback_info info)
{
    PhotoAlbumNapi *obj = nullptr;
    CHECK_NULLPTR_RET(UnwrapPhotoAlbumObject(env, info, &obj));

    napi_value jsResult = nullptr;
    CHECK_ARGS(env, napi_create_double(env, obj->GetLongitude(), &jsResult), JS_INNER_FAIL);
    return jsResult;
}

napi_value PhotoAlbumNapi::JSGetAlbumLPath(napi_env env, napi_callback_info info)
{
    CHECK_COND_LOG_THROW_RETURN_RET(env, MediaLibraryNapiUtils::IsSystemApp(), JS_ERR_PERMISSION_DENIED,
        "Get lpath permission denied: not a system app", nullptr, "Get album lpath failed: not a system app");
    CHECK_COND(env, MediaLibraryNapiUtils::IsSystemApp(), JS_ERR_PERMISSION_DENIED);
    PhotoAlbumNapi *obj = nullptr;
    CHECK_NULLPTR_RET(UnwrapPhotoAlbumObject(env, info, &obj));

    napi_value jsResult = nullptr;
    CHECK_ARGS(env, napi_create_string_utf8(env, obj->GetLPath().c_str(), NAPI_AUTO_LENGTH, &jsResult), JS_INNER_FAIL);
    return jsResult;
}

napi_value GetStringArg(napi_env env, napi_callback_info info, PhotoAlbumNapi **obj, string &output)
{
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE];
    napi_value thisVar = nullptr;
    CHECK_ARGS(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr), JS_INNER_FAIL);
    CHECK_COND(env, argc == ARGS_ONE, JS_ERR_PARAMETER_INVALID);

    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_undefined(env, &result), JS_INNER_FAIL);
    napi_valuetype valueType = napi_undefined;
    if ((thisVar == nullptr) || (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok) || (valueType != napi_string)) {
        NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return result;
    }

    size_t res = 0;
    char buffer[FILENAME_MAX];
    CHECK_ARGS(env, napi_get_value_string_utf8(env, argv[PARAM0], buffer, FILENAME_MAX, &res), JS_INNER_FAIL);
    output = string(buffer);

    CHECK_ARGS(env, napi_unwrap(env, thisVar, reinterpret_cast<void **>(obj)), JS_INNER_FAIL);
    if (obj == nullptr) {
        NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return result;
    }

    CHECK_ARGS(env, napi_get_boolean(env, true, &result), JS_INNER_FAIL);
    return result;
}

napi_value PhotoAlbumNapi::JSSetAlbumName(napi_env env, napi_callback_info info)
{
    PhotoAlbumNapi *obj = nullptr;
    string albumName;
    CHECK_NULLPTR_RET(GetStringArg(env, info, &obj, albumName));
    obj->photoAlbumPtr->SetAlbumName(albumName);

    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_undefined(env, &result), JS_INNER_FAIL);
    return result;
}

napi_value PhotoAlbumNapi::JSPhotoAccessSetAlbumName(napi_env env, napi_callback_info info)
{
    PhotoAlbumNapi *obj = nullptr;
    string albumName;
    CHECK_NULLPTR_RET(GetStringArg(env, info, &obj, albumName));
    obj->photoAlbumPtr->SetAlbumName(albumName);

    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_undefined(env, &result), JS_INNER_FAIL);
    return result;
}

napi_value PhotoAlbumNapi::JSSetCoverUri(napi_env env, napi_callback_info info)
{
    PhotoAlbumNapi *obj = nullptr;
    string coverUri;
    CHECK_NULLPTR_RET(GetStringArg(env, info, &obj, coverUri));
    obj->photoAlbumPtr->SetCoverUri(coverUri);

    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_undefined(env, &result), JS_INNER_FAIL);
    return result;
}

napi_value PhotoAlbumNapi::JSGetDateModified(napi_env env, napi_callback_info info)
{
    PhotoAlbumNapi *obj = nullptr;
    CHECK_NULLPTR_RET(UnwrapPhotoAlbumObject(env, info, &obj));

    napi_value jsResult = nullptr;
    CHECK_ARGS(env, napi_create_int64(env, obj->GetDateModified(), &jsResult),
        JS_INNER_FAIL);
    return jsResult;
}

static napi_value ParseArgsCommitModify(napi_env env, napi_callback_info info,
    unique_ptr<PhotoAlbumNapiAsyncContext> &context)
{
    constexpr size_t minArgs = ARGS_ZERO;
    constexpr size_t maxArgs = ARGS_ONE;
    CHECK_ARGS(env, MediaLibraryNapiUtils::AsyncContextSetObjectInfo(env, info, context, minArgs, maxArgs),
        JS_ERR_PARAMETER_INVALID);

    auto photoAlbum = context->objectInfo->GetPhotoAlbumInstance();
    if (photoAlbum == nullptr) {
        NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return nullptr;
    }
    if (!PhotoAlbum::IsUserPhotoAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType())) {
        NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return nullptr;
    }

    if (MediaFileUtils::CheckAlbumName(photoAlbum->GetAlbumName()) < 0) {
        NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return nullptr;
    }
    context->predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, to_string(photoAlbum->GetAlbumId()));
    context->valuesBucket.Put(PhotoAlbumColumns::ALBUM_NAME, photoAlbum->GetAlbumName());
    context->valuesBucket.Put(PhotoAlbumColumns::ALBUM_COVER_URI, photoAlbum->GetCoverUri());

    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_boolean(env, true, &result), JS_INNER_FAIL);
    return result;
}

static void JSCommitModifyExecute(napi_env env, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSCommitModifyExecute");

    auto *context = static_cast<PhotoAlbumNapiAsyncContext*>(data);
    string commitModifyUri = (context->resultNapiType == ResultNapiType::TYPE_USERFILE_MGR) ?
        UFM_UPDATE_PHOTO_ALBUM : PAH_UPDATE_PHOTO_ALBUM;
    Uri uri(commitModifyUri);
    int changedRows = UserFileClient::Update(uri, context->predicates, context->valuesBucket);
    context->SaveError(changedRows);
    context->changedRows = changedRows;
}

static void JSCommitModifyCompleteCallback(napi_env env, napi_status status, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSCommitModifyCompleteCallback");

    auto *context = static_cast<PhotoAlbumNapiAsyncContext*>(data);
    auto jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    CHECK_ARGS_RET_VOID(env, napi_get_undefined(env, &jsContext->data), JS_INNER_FAIL);
    if (context->error == ERR_DEFAULT) {
        CHECK_ARGS_RET_VOID(env, napi_get_undefined(env, &jsContext->error), JS_INNER_FAIL);
        jsContext->status = true;
    } else {
        context->HandleError(env, jsContext->error);
    }

    tracer.Finish();
    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value PhotoAlbumNapi::JSCommitModify(napi_env env, napi_callback_info info)
{
    auto asyncContext = make_unique<PhotoAlbumNapiAsyncContext>();
    CHECK_NULLPTR_RET(ParseArgsCommitModify(env, info, asyncContext));
    asyncContext->resultNapiType = ResultNapiType::TYPE_USERFILE_MGR;

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSCommitModify", JSCommitModifyExecute,
        JSCommitModifyCompleteCallback);
}

napi_value PhotoAlbumNapi::PhotoAccessHelperCommitModify(napi_env env, napi_callback_info info)
{
    auto asyncContext = make_unique<PhotoAlbumNapiAsyncContext>();
    CHECK_NULLPTR_RET(ParseArgsCommitModify(env, info, asyncContext));
    asyncContext->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSCommitModify", JSCommitModifyExecute,
        JSCommitModifyCompleteCallback);
}

static napi_value GetAssetsIdArray(napi_env env, napi_value arg, vector<string> &assetsArray)
{
    bool isArray = false;
    CHECK_ARGS(env, napi_is_array(env, arg, &isArray), JS_INNER_FAIL);
    if (!isArray) {
        NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID, "Failed to check array type");
        return nullptr;
    }

    uint32_t len = 0;
    CHECK_ARGS(env, napi_get_array_length(env, arg, &len), JS_INNER_FAIL);
    if (len < 0) {
        NAPI_ERR_LOG("Failed to check array length: %{public}u", len);
        NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID, "Failed to check array length");
        return nullptr;
    }
    if (len == 0) {
        napi_value result = nullptr;
        CHECK_ARGS(env, napi_get_boolean(env, true, &result), JS_INNER_FAIL);
        return result;
    }

    for (uint32_t i = 0; i < len; i++) {
        napi_value asset = nullptr;
        CHECK_ARGS(env, napi_get_element(env, arg, i, &asset), JS_INNER_FAIL);
        if (asset == nullptr) {
            NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID, "Failed to get asset element");
            return nullptr;
        }

        FileAssetNapi *obj = nullptr;
        CHECK_ARGS(env, napi_unwrap(env, asset, reinterpret_cast<void **>(&obj)), JS_INNER_FAIL);
        if (obj == nullptr) {
            NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID, "Failed to get asset napi object");
            return nullptr;
        }
        if ((obj->GetMediaType() != MEDIA_TYPE_IMAGE && obj->GetMediaType() != MEDIA_TYPE_VIDEO)) {
            NAPI_INFO_LOG("Skip invalid asset, mediaType: %{public}d", obj->GetMediaType());
            continue;
        }
        assetsArray.push_back(obj->GetFileUri());
    }

    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_boolean(env, true, &result), JS_INNER_FAIL);
    return result;
}

static napi_value ParseArgsAddAssets(napi_env env, napi_callback_info info,
    unique_ptr<PhotoAlbumNapiAsyncContext> &context)
{
    constexpr size_t minArgs = ARGS_ONE;
    constexpr size_t maxArgs = ARGS_TWO;
    CHECK_ARGS(env, MediaLibraryNapiUtils::AsyncContextSetObjectInfo(env, info, context, minArgs, maxArgs),
        JS_ERR_PARAMETER_INVALID);

    auto photoAlbum = context->objectInfo->GetPhotoAlbumInstance();
    if (!PhotoAlbum::IsUserPhotoAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType())) {
        NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return nullptr;
    }

    /* Parse the first argument */
    vector<string> assetsArray;
    CHECK_NULLPTR_RET(GetAssetsIdArray(env, context->argv[PARAM0], assetsArray));
    if (assetsArray.empty()) {
        napi_value result = nullptr;
        CHECK_ARGS(env, napi_get_boolean(env, true, &result), JS_INNER_FAIL);
        return result;
    }
    int32_t albumId = photoAlbum->GetAlbumId();
    for (const auto &assetId : assetsArray) {
        DataShareValuesBucket valuesBucket;
        valuesBucket.Put(PhotoColumn::PHOTO_OWNER_ALBUM_ID, albumId);
        valuesBucket.Put(PhotoColumn::MEDIA_ID, assetId);
        context->valuesBuckets.push_back(valuesBucket);
    }

    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_boolean(env, true, &result), JS_INNER_FAIL);
    return result;
}

static int32_t FetchNewCount(PhotoAlbumNapiAsyncContext *context)
{
    string queryUri = (context->resultNapiType == ResultNapiType::TYPE_USERFILE_MGR) ?
        UFM_QUERY_PHOTO_ALBUM : PAH_QUERY_PHOTO_ALBUM;
    Uri qUri(queryUri);
    int errCode = 0;
    DataSharePredicates predicates;
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, context->objectInfo->GetAlbumId());
    vector<string> fetchColumn = {
        PhotoAlbumColumns::ALBUM_ID,
        PhotoAlbumColumns::ALBUM_COUNT,
    };
    bool isSmartAlbum = (context->objectInfo->GetPhotoAlbumType() == PhotoAlbumType::SMART);
    if (!isSmartAlbum) {
        fetchColumn.push_back(PhotoAlbumColumns::ALBUM_IMAGE_COUNT);
        fetchColumn.push_back(PhotoAlbumColumns::ALBUM_VIDEO_COUNT);
    }
    auto resultSet = UserFileClient::Query(qUri, predicates, fetchColumn, errCode);
    if (resultSet == nullptr) {
        NAPI_ERR_LOG("resultSet == nullptr, errCode is %{public}d", errCode);
        return -1;
    }
    if (resultSet->GoToFirstRow() != 0) {
        NAPI_ERR_LOG("go to first row failed");
        return -1;
    }
    bool hiddenOnly = context->objectInfo->GetHiddenOnly();
    int imageCount = (hiddenOnly || isSmartAlbum) ? -1 :
            get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_IMAGE_COUNT, resultSet, TYPE_INT32));
    int videoCount = (hiddenOnly || isSmartAlbum) ? -1 :
            get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_VIDEO_COUNT, resultSet, TYPE_INT32));
    context->newCount =
            get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_COUNT, resultSet, TYPE_INT32));
    context->newImageCount = imageCount;
    context->newVideoCount = videoCount;
    return 0;
}

static void JSPhotoAlbumAddAssetsExecute(napi_env env, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSPhotoAlbumAddAssetsExecute");
    auto *context = static_cast<PhotoAlbumNapiAsyncContext*>(data);
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
    int32_t ret = FetchNewCount(context);
    if (ret < 0) {
        NAPI_ERR_LOG("Update count failed");
        context->SaveError(E_HAS_DB_ERROR);
    }
}

static void JSPhotoAlbumAddAssetsCompleteCallback(napi_env env, napi_status status, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSPhotoAlbumAddAssetsCompleteCallback");

    auto *context = static_cast<PhotoAlbumNapiAsyncContext*>(data);
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    CHECK_ARGS_RET_VOID(env, napi_get_undefined(env, &jsContext->data), JS_INNER_FAIL);
    if (context->error == ERR_DEFAULT) {
        CHECK_ARGS_RET_VOID(env, napi_get_undefined(env, &jsContext->error), JS_INNER_FAIL);
        jsContext->status = true;
        context->objectInfo->SetCount(context->newCount);
        context->objectInfo->SetImageCount(context->newImageCount);
        context->objectInfo->SetVideoCount(context->newVideoCount);
    } else {
        context->HandleError(env, jsContext->error);
    }

    tracer.Finish();
    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value PhotoAlbumNapi::JSPhotoAlbumAddAssets(napi_env env, napi_callback_info info)
{
    unique_ptr<PhotoAlbumNapiAsyncContext> asyncContext = make_unique<PhotoAlbumNapiAsyncContext>();
    CHECK_NULLPTR_RET(ParseArgsAddAssets(env, info, asyncContext));
    asyncContext->resultNapiType = ResultNapiType::TYPE_USERFILE_MGR;

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSPhotoAlbumAddAssets",
        JSPhotoAlbumAddAssetsExecute, JSPhotoAlbumAddAssetsCompleteCallback);
}

napi_value PhotoAlbumNapi::PhotoAccessHelperAddAssets(napi_env env, napi_callback_info info)
{
    unique_ptr<PhotoAlbumNapiAsyncContext> asyncContext = make_unique<PhotoAlbumNapiAsyncContext>();
    CHECK_NULLPTR_RET(ParseArgsAddAssets(env, info, asyncContext));
    asyncContext->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSPhotoAlbumAddAssets",
        JSPhotoAlbumAddAssetsExecute, JSPhotoAlbumAddAssetsCompleteCallback);
}

static napi_value ParseArgsRemoveAssets(napi_env env, napi_callback_info info,
    unique_ptr<PhotoAlbumNapiAsyncContext> &context)
{
    constexpr size_t minArgs = ARGS_ONE;
    constexpr size_t maxArgs = ARGS_TWO;
    CHECK_ARGS(env, MediaLibraryNapiUtils::AsyncContextSetObjectInfo(env, info, context, minArgs, maxArgs),
        JS_ERR_PARAMETER_INVALID);

    auto photoAlbum = context->objectInfo->GetPhotoAlbumInstance();
    if (!PhotoAlbum::IsUserPhotoAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType())) {
        NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return nullptr;
    }

    /* Parse the first argument */
    vector<string> assetsArray;
    CHECK_NULLPTR_RET(GetAssetsIdArray(env, context->argv[PARAM0], assetsArray));
    if (assetsArray.empty()) {
        napi_value result = nullptr;
        CHECK_ARGS(env, napi_get_boolean(env, true, &result), JS_INNER_FAIL);
        return result;
    }
    context->predicates.EqualTo(PhotoColumn::PHOTO_OWNER_ALBUM_ID, to_string(photoAlbum->GetAlbumId()));
    context->predicates.And()->In(PhotoColumn::MEDIA_ID, assetsArray);

    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_boolean(env, true, &result), JS_INNER_FAIL);
    return result;
}

static void JSPhotoAlbumRemoveAssetsExecute(napi_env env, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSPhotoAlbumRemoveAssetsExecute");

    auto *context = static_cast<PhotoAlbumNapiAsyncContext*>(data);
    if (context->predicates.GetOperationList().empty()) {
        NAPI_ERR_LOG("Invalid input: operation list is empty");
        return;
    }

    string removeAssetsUri = (context->resultNapiType == ResultNapiType::TYPE_USERFILE_MGR) ?
        UFM_PHOTO_ALBUM_REMOVE_ASSET : PAH_PHOTO_ALBUM_REMOVE_ASSET;
    Uri uri(removeAssetsUri);
    auto deletedRows = UserFileClient::Delete(uri, context->predicates);
    if (deletedRows < 0) {
        NAPI_ERR_LOG("Remove assets failed: %{public}d", deletedRows);
        context->SaveError(deletedRows);
        return;
    }
    context->changedRows = deletedRows;
    int32_t ret = FetchNewCount(context);
    if (ret < 0) {
        NAPI_ERR_LOG("Update count failed");
        context->SaveError(E_HAS_DB_ERROR);
    }
}

static void JSPhotoAlbumRemoveAssetsCompleteCallback(napi_env env, napi_status status, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSPhotoAlbumRemoveAssetsCompleteCallback");

    auto *context = static_cast<PhotoAlbumNapiAsyncContext*>(data);
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    CHECK_ARGS_RET_VOID(env, napi_get_undefined(env, &jsContext->data), JS_INNER_FAIL);
    if (context->error == ERR_DEFAULT) {
        CHECK_ARGS_RET_VOID(env, napi_get_undefined(env, &jsContext->error), JS_INNER_FAIL);
        jsContext->status = true;
        context->objectInfo->SetCount(context->newCount);
        context->objectInfo->SetImageCount(context->newImageCount);
        context->objectInfo->SetVideoCount(context->newVideoCount);
    } else {
        context->HandleError(env, jsContext->error);
    }

    tracer.Finish();
    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value PhotoAlbumNapi::JSPhotoAlbumRemoveAssets(napi_env env, napi_callback_info info)
{
    auto asyncContext = make_unique<PhotoAlbumNapiAsyncContext>();
    CHECK_NULLPTR_RET(ParseArgsRemoveAssets(env, info, asyncContext));
    asyncContext->resultNapiType = ResultNapiType::TYPE_USERFILE_MGR;

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSPhotoAlbumRemoveAssets",
        JSPhotoAlbumRemoveAssetsExecute, JSPhotoAlbumRemoveAssetsCompleteCallback);
}

napi_value PhotoAlbumNapi::PhotoAccessHelperRemoveAssets(napi_env env, napi_callback_info info)
{
    auto asyncContext = make_unique<PhotoAlbumNapiAsyncContext>();
    CHECK_NULLPTR_RET(ParseArgsRemoveAssets(env, info, asyncContext));
    asyncContext->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSPhotoAlbumRemoveAssets",
        JSPhotoAlbumRemoveAssetsExecute, JSPhotoAlbumRemoveAssetsCompleteCallback);
}

static int32_t GetPredicatesByAlbumTypes(const shared_ptr<PhotoAlbum> &photoAlbum,
    DataSharePredicates &predicates, const bool hiddenOnly)
{
    auto albumId = photoAlbum->GetAlbumId();
    auto subType = photoAlbum->GetPhotoAlbumSubType();
    bool isLocationAlbum = subType == PhotoAlbumSubType::GEOGRAPHY_LOCATION;
    if (albumId <= 0 && !isLocationAlbum) {
        return E_INVALID_ARGUMENTS;
    }
    auto type = photoAlbum->GetPhotoAlbumType();
    if ((!PhotoAlbum::CheckPhotoAlbumType(type)) || (!PhotoAlbum::CheckPhotoAlbumSubType(subType))) {
        return E_INVALID_ARGUMENTS;
    }

    if (type == PhotoAlbumType::SMART && subType == PhotoAlbumSubType::PORTRAIT) {
        return MediaLibraryNapiUtils::GetPortraitAlbumPredicates(photoAlbum->GetAlbumId(), predicates);
    }

    if (PhotoAlbum::IsUserPhotoAlbum(type, subType)) {
        return MediaLibraryNapiUtils::GetUserAlbumPredicates(photoAlbum->GetAlbumId(), predicates, hiddenOnly);
    }

    if (PhotoAlbum::IsSourceAlbum(type, subType)) {
        return MediaLibraryNapiUtils::GetSourceAlbumPredicates(photoAlbum->GetAlbumId(), predicates, hiddenOnly);
    }

    if (type == PhotoAlbumType::SMART) {
        if (isLocationAlbum) {
            return MediaLibraryNapiUtils::GetAllLocationPredicates(predicates);
        }
        auto albumName = photoAlbum->GetAlbumName();
        if (MediaLibraryNapiUtils::IsFeaturedSinglePortraitAlbum(albumName, predicates)) {
            return MediaLibraryNapiUtils::GetFeaturedSinglePortraitAlbumPredicates(
                photoAlbum->GetAlbumId(), predicates);
        }
        return MediaLibraryNapiUtils::GetAnalysisAlbumPredicates(photoAlbum->GetAlbumId(), predicates);
    }
    
    if ((type != PhotoAlbumType::SYSTEM) || (subType == PhotoAlbumSubType::USER_GENERIC) ||
        (subType == PhotoAlbumSubType::ANY)) {
        return E_INVALID_ARGUMENTS;
    }
    return MediaLibraryNapiUtils::GetSystemAlbumPredicates(subType, predicates, hiddenOnly);
}

static napi_value ParseArgsGetPhotoAssets(napi_env env, napi_callback_info info,
    unique_ptr<PhotoAlbumNapiAsyncContext> &context)
{
    constexpr size_t minArgs = ARGS_ONE;
    constexpr size_t maxArgs = ARGS_TWO;
    CHECK_ARGS(env, MediaLibraryNapiUtils::AsyncContextSetObjectInfo(env, info, context, minArgs, maxArgs),
        JS_ERR_PARAMETER_INVALID);

    /* Parse the first argument */
    CHECK_ARGS(env, MediaLibraryNapiUtils::GetFetchOption(env, context->argv[PARAM0], ASSET_FETCH_OPT, context),
        JS_INNER_FAIL);

    auto photoAlbum = context->objectInfo->GetPhotoAlbumInstance();
    auto ret = GetPredicatesByAlbumTypes(photoAlbum, context->predicates, photoAlbum->GetHiddenOnly());
    if (ret != E_SUCCESS) {
        NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return nullptr;
    }
    CHECK_NULLPTR_RET(MediaLibraryNapiUtils::AddDefaultAssetColumns(env, context->fetchColumn,
        PhotoColumn::IsPhotoColumn, NapiAssetType::TYPE_PHOTO));
    if (photoAlbum->GetHiddenOnly() || photoAlbum->GetPhotoAlbumSubType() == PhotoAlbumSubType::HIDDEN) {
        if (!MediaLibraryNapiUtils::IsSystemApp()) {
            NapiError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
            return nullptr;
        }
        // sort by hidden time desc if is hidden asset
        context->predicates.IndexedBy(PhotoColumn::PHOTO_HIDDEN_TIME_INDEX);
    }

    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_boolean(env, true, &result), JS_INNER_FAIL);
    return result;
}

static void JSGetPhotoAssetsExecute(napi_env env, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSGetPhotoAssetsExecute");

    auto *context = static_cast<PhotoAlbumNapiAsyncContext *>(data);
    string queryUri = UFM_QUERY_PHOTO_MAP;
    Uri uri(queryUri);
    int32_t errCode = 0;
    std::vector<DataShare::OperationItem> operationItems = context->predicates.GetOperationList();
    for (DataShare::OperationItem item : operationItems) {
        if (item.operation == DataShare::OperationType::GROUP_BY) {
            context->fetchColumn.insert(context->fetchColumn.begin(), COUNT_GROUP_BY);
        }
    }
    auto resultSet = UserFileClient::Query(uri, context->predicates, context->fetchColumn, errCode);
    if (resultSet == nullptr) {
        context->SaveError(E_HAS_DB_ERROR);
        return;
    }
    context->fetchResult = make_unique<FetchResult<FileAsset>>(move(resultSet));
    context->fetchResult->SetResultNapiType(ResultNapiType::TYPE_USERFILE_MGR);
}

static bool IsFeaturedSinglePortraitAlbum(const shared_ptr<PhotoAlbum>& photoAlbum)
{
    constexpr int portraitAlbumId = 0;
    return photoAlbum->GetPhotoAlbumSubType() == PhotoAlbumSubType::CLASSIFY &&
        photoAlbum->GetAlbumName().compare(to_string(portraitAlbumId)) == 0;
}

static void ConvertColumnsForPortrait(PhotoAlbumNapiAsyncContext *context)
{
    if (context == nullptr || context->objectInfo == nullptr) {
        NAPI_ERR_LOG("context is null or PhotoAlbumNapi is null");
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

static void JSPhotoAccessGetPhotoAssetsExecute(napi_env env, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSPhotoAccessGetPhotoAssetsExecute");

    auto *context = static_cast<PhotoAlbumNapiAsyncContext *>(data);
    Uri uri(PAH_QUERY_PHOTO_MAP);
    ConvertColumnsForPortrait(context);
    int32_t errCode = 0;
    int32_t userId = -1;
    if (context->objectInfo != nullptr) {
        shared_ptr<PhotoAlbum> photoAlbum =  context->objectInfo->GetPhotoAlbumInstance();
        if (photoAlbum != nullptr) {
            userId = photoAlbum->GetUserId();
        }
    }
    auto resultSet = UserFileClient::Query(uri, context->predicates, context->fetchColumn, errCode, userId);
    if (resultSet == nullptr) {
        context->SaveError(E_HAS_DB_ERROR);
        return;
    }
    context->fetchResult = make_unique<FetchResult<FileAsset>>(move(resultSet));
    context->fetchResult->SetResultNapiType(ResultNapiType::TYPE_PHOTOACCESS_HELPER);
    context->fetchResult->SetUserId(userId);
}

static napi_value JSPhotoAccessGetPhotoAssetsExecuteSync(napi_env env, PhotoAlbumNapiAsyncContext& asyncContext)
{
    auto context = &asyncContext;
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
    napi_value jsFileArray = nullptr;
    size_t len = fileAssetArray.size();
    napi_create_array_with_length(env, len, &jsFileArray);
    size_t i = 0;
    int32_t userId = -1;
    if (context->objectInfo != nullptr) {
        shared_ptr<PhotoAlbum> photoAlbum =  context->objectInfo->GetPhotoAlbumInstance();
        if (photoAlbum != nullptr) {
            userId = photoAlbum->GetUserId();
        }
    }
    for (i = 0; i < len; i++) {
        fileAssetArray[i]->SetUserId(userId);
        napi_value jsFileAsset = FileAssetNapi::CreateFileAsset(env, fileAssetArray[i]);
        if ((jsFileAsset == nullptr) || (napi_set_element(env, jsFileArray, i, jsFileAsset) != napi_ok)) {
            NAPI_ERR_LOG("Failed to get file asset napi object");
            break;
        }
    }
    return (i == len) ? jsFileArray : nullptr;
}

static void GetPhotoMapQueryResult(napi_env env, PhotoAlbumNapiAsyncContext *context,
    unique_ptr<JSAsyncContextOutput> &jsContext)
{
    napi_value fetchRes = FetchFileResultNapi::CreateFetchFileResult(env, move(context->fetchResult));
    if (fetchRes == nullptr) {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_MEM_ALLOCATION,
            "Failed to create js object for FetchFileResult");
        return;
    }
    jsContext->data = fetchRes;
    jsContext->status = true;
}

static void JSGetPhotoAssetsCallbackComplete(napi_env env, napi_status status, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSGetPhotoAssetsCallbackComplete");

    auto *context = static_cast<PhotoAlbumNapiAsyncContext *>(data);

    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    CHECK_ARGS_RET_VOID(env, napi_get_undefined(env, &jsContext->data), JS_INNER_FAIL);
    CHECK_ARGS_RET_VOID(env, napi_get_undefined(env, &jsContext->error), JS_INNER_FAIL);
    if (context->fetchResult != nullptr) {
        GetPhotoMapQueryResult(env, context, jsContext);
    } else {
        NAPI_ERR_LOG("No fetch file result found!");
        context->HandleError(env, jsContext->error);
    }

    tracer.Finish();
    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value PhotoAlbumNapi::JSGetPhotoAssets(napi_env env, napi_callback_info info)
{
    unique_ptr<PhotoAlbumNapiAsyncContext> asyncContext = make_unique<PhotoAlbumNapiAsyncContext>();
    CHECK_NULLPTR_RET(ParseArgsGetPhotoAssets(env, info, asyncContext));

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSGetPhotoAssets", JSGetPhotoAssetsExecute,
        JSGetPhotoAssetsCallbackComplete);
}

napi_value PhotoAlbumNapi::JSPhotoAccessGetPhotoAssets(napi_env env, napi_callback_info info)
{
    unique_ptr<PhotoAlbumNapiAsyncContext> asyncContext = make_unique<PhotoAlbumNapiAsyncContext>();
    CHECK_NULLPTR_RET(ParseArgsGetPhotoAssets(env, info, asyncContext));

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSGetPhotoAssets",
        JSPhotoAccessGetPhotoAssetsExecute, JSGetPhotoAssetsCallbackComplete);
}

napi_value PhotoAlbumNapi::JSPhotoAccessGetPhotoAssetsSync(napi_env env, napi_callback_info info)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSPhotoAccessGetPhotoAssetsSync");

    unique_ptr<PhotoAlbumNapiAsyncContext> asyncContext = make_unique<PhotoAlbumNapiAsyncContext>();
    CHECK_NULLPTR_RET(ParseArgsGetPhotoAssets(env, info, asyncContext));
    return JSPhotoAccessGetPhotoAssetsExecuteSync(env, *asyncContext);
}

static napi_value TrashAlbumParseArgs(napi_env env, napi_callback_info info,
    unique_ptr<PhotoAlbumNapiAsyncContext> &context)
{
    if (!MediaLibraryNapiUtils::IsSystemApp()) {
        NapiError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return nullptr;
    }

    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_boolean(env, true, &result), JS_INNER_FAIL);
    constexpr size_t minArgs = ARGS_ONE;
    constexpr size_t maxArgs = ARGS_TWO;
    CHECK_ARGS(env, MediaLibraryNapiUtils::AsyncContextSetObjectInfo(env, info, context, minArgs, maxArgs),
        JS_ERR_PARAMETER_INVALID);
    auto photoAlbum = context->objectInfo->GetPhotoAlbumInstance();
    if (!PhotoAlbum::IsTrashAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType())) {
        NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID, "Failed to check trash album type");
        return nullptr;
    }

    /* Parse the first argument */
    vector<napi_value> napiValues;
    CHECK_NULLPTR_RET(MediaLibraryNapiUtils::GetNapiValueArray(env, context->argv[PARAM0], napiValues));
    if (napiValues.empty()) {
        return result;
    }
    napi_valuetype valueType = napi_undefined;
    vector<string> uris;
    CHECK_ARGS(env, napi_typeof(env, napiValues.front(), &valueType), JS_ERR_PARAMETER_INVALID);
    if (valueType == napi_string) {
        // The input should be an array of asset uri.
        CHECK_NULLPTR_RET(MediaLibraryNapiUtils::GetStringArray(env, napiValues, uris));
    } else if (valueType == napi_object) {
        // The input should be an array of asset object.
        CHECK_NULLPTR_RET(MediaLibraryNapiUtils::GetUriArrayFromAssets(env, napiValues, uris));
    }
    if (uris.empty()) {
        return result;
    }

    context->predicates.In(MediaColumn::MEDIA_ID, uris);
    context->valuesBucket.Put(MediaColumn::MEDIA_DATE_TRASHED, 0);

    CHECK_ARGS(env, napi_get_boolean(env, true, &result), JS_INNER_FAIL);
    return result;
}

static void TrashAlbumExecute(const TrashAlbumExecuteOpt &opt)
{
    MediaLibraryTracer tracer;
    tracer.Start(opt.tracerLabel);

    auto *context = static_cast<PhotoAlbumNapiAsyncContext*>(opt.data);
    if (context->predicates.GetOperationList().empty()) {
        NAPI_ERR_LOG("Operation list is empty.");
        return;
    }
    Uri uri(opt.uri);
    int changedRows = UserFileClient::Update(uri, context->predicates, context->valuesBucket);
    if (changedRows < 0) {
        context->SaveError(changedRows);
        NAPI_ERR_LOG("Trash album executed, changeRows: %{public}d.", changedRows);
        return;
    }
    context->changedRows = changedRows;
}

static void TrashAlbumComplete(napi_env env, napi_status status, void *data)
{
    auto *context = static_cast<PhotoAlbumNapiAsyncContext*>(data);
    auto jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    CHECK_ARGS_RET_VOID(env, napi_get_undefined(env, &jsContext->data), JS_INNER_FAIL);
    if (context->error == ERR_DEFAULT) {
        CHECK_ARGS_RET_VOID(env, napi_get_undefined(env, &jsContext->error), JS_INNER_FAIL);
        jsContext->status = true;
    } else {
        context->HandleError(env, jsContext->error);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

static void RecoverPhotosExecute(napi_env env, void *data)
{
    TrashAlbumExecuteOpt opt = {
        .env = env,
        .data = data,
        .tracerLabel = "RecoverPhotosExecute",
        .uri = (static_cast<PhotoAlbumNapiAsyncContext *>(data)->resultNapiType == ResultNapiType::TYPE_USERFILE_MGR) ?
            UFM_RECOVER_PHOTOS : PAH_RECOVER_PHOTOS,
    };
    TrashAlbumExecute(opt);
}

static void RecoverPhotosComplete(napi_env env, napi_status status, void *data)
{
    TrashAlbumComplete(env, status, data);
}

napi_value PhotoAlbumNapi::JSRecoverPhotos(napi_env env, napi_callback_info info)
{
    auto asyncContext = make_unique<PhotoAlbumNapiAsyncContext>();
    CHECK_NULLPTR_RET(TrashAlbumParseArgs(env, info, asyncContext));
    asyncContext->resultNapiType = ResultNapiType::TYPE_USERFILE_MGR;

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSRecoverPhotos", RecoverPhotosExecute,
        RecoverPhotosComplete);
}

static napi_value PrivateAlbumParseArgs(napi_env env, napi_callback_info info,
    unique_ptr<PhotoAlbumNapiAsyncContext> &context)
{
    string uri;
    CHECK_ARGS(env, MediaLibraryNapiUtils::ParseArgsStringCallback(env, info, context, uri),
        JS_ERR_PARAMETER_INVALID);
    auto photoAlbum = context->objectInfo->GetPhotoAlbumInstance();
    if (photoAlbum == nullptr) {
        NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID, "Failed to get photo album instance");
        return nullptr;
    }
    if (!PhotoAlbum::IsTrashAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType())) {
        NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID, "Failed to check trash album type");
        return nullptr;
    }

    context->predicates.EqualTo(MediaColumn::MEDIA_ID, MediaFileUtils::GetIdFromUri(uri));
    context->valuesBucket.Put(MediaColumn::MEDIA_DATE_TRASHED, 0);

    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_boolean(env, true, &result), JS_INNER_FAIL);
    return result;
}

napi_value PhotoAlbumNapi::PrivateAlbumRecoverPhotos(napi_env env, napi_callback_info info)
{
    auto asyncContext = make_unique<PhotoAlbumNapiAsyncContext>();
    asyncContext->resultNapiType = ResultNapiType::TYPE_USERFILE_MGR;
    CHECK_NULLPTR_RET(PrivateAlbumParseArgs(env, info, asyncContext));

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "PrivateAlbumRecoverPhotos",
        RecoverPhotosExecute, RecoverPhotosComplete);
}

napi_value PhotoAlbumNapi::PhotoAccessHelperRecoverPhotos(napi_env env, napi_callback_info info)
{
    auto asyncContext = make_unique<PhotoAlbumNapiAsyncContext>();
    CHECK_NULLPTR_RET(TrashAlbumParseArgs(env, info, asyncContext));
    asyncContext->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSRecoverPhotos", RecoverPhotosExecute,
        RecoverPhotosComplete);
}

static void DeletePhotosExecute(napi_env env, void *data)
{
    TrashAlbumExecuteOpt opt = {
        .env = env,
        .data = data,
        .tracerLabel = "DeletePhotosExecute",
        .uri = (static_cast<PhotoAlbumNapiAsyncContext *>(data)->resultNapiType == ResultNapiType::TYPE_USERFILE_MGR) ?
            UFM_DELETE_PHOTOS : PAH_DELETE_PHOTOS,
    };
    TrashAlbumExecute(opt);
}

static void DeletePhotosComplete(napi_env env, napi_status status, void *data)
{
    TrashAlbumComplete(env, status, data);
}

napi_value PhotoAlbumNapi::JSDeletePhotos(napi_env env, napi_callback_info info)
{
    auto asyncContext = make_unique<PhotoAlbumNapiAsyncContext>();
    CHECK_NULLPTR_RET(TrashAlbumParseArgs(env, info, asyncContext));
    asyncContext->resultNapiType = ResultNapiType::TYPE_USERFILE_MGR;

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSDeletePhotos", DeletePhotosExecute,
        DeletePhotosComplete);
}

napi_value PhotoAlbumNapi::PrivateAlbumDeletePhotos(napi_env env, napi_callback_info info)
{
    auto asyncContext = make_unique<PhotoAlbumNapiAsyncContext>();
    asyncContext->resultNapiType = ResultNapiType::TYPE_USERFILE_MGR;
    CHECK_NULLPTR_RET(PrivateAlbumParseArgs(env, info, asyncContext));

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "PrivateAlbumDeletePhotos",
        DeletePhotosExecute, DeletePhotosComplete);
}

napi_value PhotoAlbumNapi::PhotoAccessHelperDeletePhotos(napi_env env, napi_callback_info info)
{
    NAPI_INFO_LOG("enter");
    auto asyncContext = make_unique<PhotoAlbumNapiAsyncContext>();
    CHECK_NULLPTR_RET(TrashAlbumParseArgs(env, info, asyncContext));
    asyncContext->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSDeletePhotos", DeletePhotosExecute,
        DeletePhotosComplete);
}

static napi_value ParseArgsSetCoverUri(napi_env env, napi_callback_info info,
    unique_ptr<PhotoAlbumNapiAsyncContext> &context)
{
    string coverUri;
    CHECK_ARGS(env, MediaLibraryNapiUtils::ParseArgsStringCallback(env, info, context, coverUri),
        JS_ERR_PARAMETER_INVALID);
    auto photoAlbum = context->objectInfo->GetPhotoAlbumInstance();
    if (!MediaLibraryNapiUtils::IsSystemApp()) {
        NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID, "Only system apps can update album cover");
        return nullptr;
    }

    context->predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, to_string(photoAlbum->GetAlbumId()));
    context->valuesBucket.Put(PhotoAlbumColumns::ALBUM_COVER_URI, coverUri);

    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_boolean(env, true, &result), JS_INNER_FAIL);
    return result;
}

napi_value PhotoAlbumNapi::PhotoAccessHelperSetCoverUri(napi_env env, napi_callback_info info)
{
    auto asyncContext = make_unique<PhotoAlbumNapiAsyncContext>();
    asyncContext->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    CHECK_NULLPTR_RET(ParseArgsSetCoverUri(env, info, asyncContext));

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSCommitModify", JSCommitModifyExecute,
        JSCommitModifyCompleteCallback);
}

static void PhotoAccessHelperGetFaceIdExec(napi_env env, void *data)
{
    auto *context = static_cast<PhotoAlbumNapiAsyncContext *>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    auto *objectInfo = context->objectInfo;
    CHECK_NULL_PTR_RETURN_VOID(objectInfo, "objectInfo is null");

    auto photoAlbumInstance = objectInfo->GetPhotoAlbumInstance();
    CHECK_NULL_PTR_RETURN_VOID(photoAlbumInstance, "photoAlbumInstance is null");

    PhotoAlbumSubType albumSubType = photoAlbumInstance->GetPhotoAlbumSubType();
    if (albumSubType != PhotoAlbumSubType::PORTRAIT && albumSubType != PhotoAlbumSubType::GROUP_PHOTO) {
        NAPI_WARN_LOG("albumSubType: %{public}d, not support getFaceId", albumSubType);
        return;
    }

    Uri uri(PAH_QUERY_ANA_PHOTO_ALBUM);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, objectInfo->GetAlbumId());
    vector<string> fetchColumn = { GROUP_TAG };
    int errCode = 0;

    auto resultSet = UserFileClient::Query(uri, predicates, fetchColumn, errCode);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != 0) {
        if (errCode == E_PERMISSION_DENIED) {
            context->error = OHOS_PERMISSION_DENIED_CODE;
        } else {
            context->SaveError(E_FAIL);
        }
        NAPI_ERR_LOG("get face id failed, errCode is %{public}d", errCode);
        return;
    }

    context->faceTag = GetStringVal(GROUP_TAG, resultSet);
}

static void GetFaceIdCompleteCallback(napi_env env, napi_status status, void *data)
{
    auto *context = static_cast<PhotoAlbumNapiAsyncContext *>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    auto jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    CHECK_ARGS_RET_VOID(env, napi_get_undefined(env, &jsContext->data), JS_INNER_FAIL);
    if (context->error != ERR_DEFAULT) {
        context->HandleError(env, jsContext->error);
    } else {
        CHECK_ARGS_RET_VOID(env,
            napi_create_string_utf8(env, context->faceTag.c_str(), NAPI_AUTO_LENGTH, &jsContext->data), JS_INNER_FAIL);
        jsContext->status = true;
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef, context->work,
            *jsContext);
    }
    delete context;
}

napi_value PhotoAlbumNapi::PhotoAccessHelperGetFaceId(napi_env env, napi_callback_info info)
{
    if (!MediaLibraryNapiUtils::IsSystemApp()) {
        NapiError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "Only system apps can get the Face ID of the album");
        return nullptr;
    }

    auto asyncContext = make_unique<PhotoAlbumNapiAsyncContext>();

    CHECK_ARGS(env, MediaLibraryNapiUtils::AsyncContextSetObjectInfo(env, info, asyncContext, 0, 0),
        JS_ERR_PARAMETER_INVALID);

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSAnalysisAlbumGetFaceId",
        PhotoAccessHelperGetFaceIdExec, GetFaceIdCompleteCallback);
}

napi_value PhotoAlbumNapi::JSPhotoAccessGetSharedPhotoAssets(napi_env env, napi_callback_info info)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSPhotoAccessGetSharedPhotoAssets");
    unique_ptr<PhotoAlbumNapiAsyncContext> asyncContext =
        make_unique<PhotoAlbumNapiAsyncContext>();
    CHECK_NULLPTR_RET(ParseArgsGetPhotoAssets(env, info, asyncContext));

    PhotoAlbumNapiAsyncContext* context =
        static_cast<PhotoAlbumNapiAsyncContext*>((asyncContext.get()));

    Uri uri(PAH_QUERY_PHOTO_MAP);
    ConvertColumnsForPortrait(context);
    shared_ptr<NativeRdb::ResultSet> resultSet = UserFileClient::QueryRdb(uri,
        context->predicates, context->fetchColumn);
    CHECK_NULLPTR_RET(resultSet);

    napi_value jsFileArray = 0;
    napi_create_array(env, &jsFileArray);

    int count = 0;
    int err = resultSet->GoToFirstRow();
    if (err != napi_ok) {
        NAPI_ERR_LOG("Failed GoToFirstRow %{public}d", err);
        return jsFileArray;
    }
    do {
        napi_value item = MediaLibraryNapiUtils::GetNextRowObject(env, resultSet, true);
        napi_set_element(env, jsFileArray, count++, item);
    } while (!resultSet->GoToNextRow());
    resultSet->Close();
    return jsFileArray;
}
} // namespace OHOS::Media
