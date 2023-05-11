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

#include "fetch_file_result_napi.h"
#include "file_asset_napi.h"
#include "media_file_utils.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_napi_log.h"
#include "medialibrary_tracer.h"
#include "photo_map_column.h"
#include "userfile_client.h"

using namespace std;
using namespace OHOS::DataShare;

namespace OHOS::Media {
thread_local PhotoAlbum *PhotoAlbumNapi::pAlbumData_ = nullptr;
thread_local napi_ref PhotoAlbumNapi::constructor_ = nullptr;
static const string PHOTO_ALBUM_CLASS = "UserFileMgrPhotoAlbum";

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
            DECLARE_NAPI_FUNCTION("commitModify", JSCommitModify),
            DECLARE_NAPI_FUNCTION("addPhotoAssets", JSPhotoAlbumAddAssets),
            DECLARE_NAPI_FUNCTION("removePhotoAssets", JSPhotoAlbumRemoveAssets),
            DECLARE_NAPI_FUNCTION("getPhotoAssets", JSGetPhotoAssets),
            DECLARE_NAPI_FUNCTION("recoverPhotoAssets", JSRecoverPhotos),
            DECLARE_NAPI_FUNCTION("deletePhotoAssets", JSDeletePhotos),
        }
    };

    MediaLibraryNapiUtils::NapiDefineClass(env, exports, info);
    return exports;
}

napi_value PhotoAlbumNapi::CreatePhotoAlbumNapi(napi_env env, unique_ptr<PhotoAlbum> &albumData)
{
    if (albumData == nullptr) {
        NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return nullptr;
    }

    napi_value constructor;
    napi_ref constructorRef = constructor_;
    CHECK_ARGS(env, napi_get_reference_value(env, constructorRef, &constructor), JS_INNER_FAIL);

    napi_value result = nullptr;
    pAlbumData_ = albumData.release();
    CHECK_ARGS(env, napi_new_instance(env, constructor, 0, nullptr, &result), JS_INNER_FAIL);
    pAlbumData_ = nullptr;
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

const string& PhotoAlbumNapi::GetAlbumUri() const
{
    return photoAlbumPtr->GetAlbumUri();
}

const string& PhotoAlbumNapi::GetCoverUri() const
{
    return photoAlbumPtr->GetCoverUri();
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

shared_ptr<PhotoAlbum> PhotoAlbumNapi::GetPhotoAlbumInstance() const
{
    return photoAlbumPtr;
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
    if (pAlbumData_ == nullptr) {
        NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return result;
    }
    obj->SetPhotoAlbumNapiProperties();
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

napi_value PhotoAlbumNapi::JSGetAlbumUri(napi_env env, napi_callback_info info)
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

    if (MediaFileUtils::CheckTitle(photoAlbum->GetAlbumName()) < 0) {
        NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return nullptr;
    }
    context->predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, to_string(photoAlbum->GetAlbumId()));
    context->valuesBucket.Put(PhotoAlbumColumns::ALBUM_NAME, photoAlbum->GetAlbumName());
    context->valuesBucket.Put(PhotoAlbumColumns::ALBUM_COVER_URI, photoAlbum->GetCoverUri());

    CHECK_ARGS(env, MediaLibraryNapiUtils::GetParamCallback(env, context), JS_ERR_PARAMETER_INVALID);

    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_boolean(env, true, &result), JS_INNER_FAIL);
    return result;
}

static void JSCommitModifyExecute(napi_env env, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSCommitModifyExecute");

    auto *context = static_cast<PhotoAlbumNapiAsyncContext*>(data);

    string updateUri = URI_UPDATE_PHOTO_ALBUM;
    MediaLibraryNapiUtils::UriAddFragmentTypeMask(updateUri, PHOTO_TYPE_MASK);
    Uri uri(updateUri);
    int changedRows = UserFileClient::Update(uri, context->predicates, context->valuesBucket);
    context->SaveError(changedRows);
    context->changedRows = changedRows;
}

static void JSCommitModifyCompleteCallback(napi_env env, napi_status status, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSCommitModifyCompleteCallback");

    PhotoAlbumNapiAsyncContext *context = static_cast<PhotoAlbumNapiAsyncContext*>(data);
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
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
    unique_ptr<PhotoAlbumNapiAsyncContext> asyncContext = make_unique<PhotoAlbumNapiAsyncContext>();
    CHECK_NULLPTR_RET(ParseArgsCommitModify(env, info, asyncContext));

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
        assetsArray.push_back(to_string(obj->GetFileId()));
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
        valuesBucket.Put(PhotoMap::ALBUM_ID, albumId);
        valuesBucket.Put(PhotoMap::ASSET_ID, assetId);
        context->valuesBuckets.push_back(valuesBucket);
    }

    CHECK_ARGS(env, MediaLibraryNapiUtils::GetParamCallback(env, context), JS_ERR_PARAMETER_INVALID);

    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_boolean(env, true, &result), JS_INNER_FAIL);
    return result;
}

static void JSPhotoAlbumAddAssetsExecute(napi_env env, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSPhotoAlbumAddAssetsExecute");

    auto *context = static_cast<PhotoAlbumNapiAsyncContext*>(data);
    if (context->valuesBuckets.empty()) {
        return;
    }

    string addAssetUri = URI_PHOTO_ALBUM_ADD_ASSET;
    MediaLibraryNapiUtils::UriAddFragmentTypeMask(addAssetUri, PHOTO_TYPE_MASK);
    Uri uri(addAssetUri);
    auto changedRows = UserFileClient::BatchInsert(uri, context->valuesBuckets);
    context->SaveError(changedRows);
}

static void JSPhotoAlbumAddAssetsCompleteCallback(napi_env env, napi_status status, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSPhotoAlbumAddAssetsCompleteCallback");

    PhotoAlbumNapiAsyncContext *context = static_cast<PhotoAlbumNapiAsyncContext*>(data);
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
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

napi_value PhotoAlbumNapi::JSPhotoAlbumAddAssets(napi_env env, napi_callback_info info)
{
    unique_ptr<PhotoAlbumNapiAsyncContext> asyncContext = make_unique<PhotoAlbumNapiAsyncContext>();
    CHECK_NULLPTR_RET(ParseArgsAddAssets(env, info, asyncContext));

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
    context->predicates.EqualTo(PhotoMap::ALBUM_ID, to_string(photoAlbum->GetAlbumId()));
    context->predicates.And()->In(PhotoMap::ASSET_ID, assetsArray);

    CHECK_ARGS(env, MediaLibraryNapiUtils::GetParamCallback(env, context), JS_ERR_PARAMETER_INVALID);

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
        return;
    }

    string removeAssetUri = URI_PHOTO_ALBUM_REMOVE_ASSET;
    MediaLibraryNapiUtils::UriAddFragmentTypeMask(removeAssetUri, PHOTO_TYPE_MASK);
    Uri uri(removeAssetUri);
    auto deletedRows = UserFileClient::Delete(uri, context->predicates);
    if (deletedRows < 0) {
        context->SaveError(deletedRows);
    }
}

static void JSPhotoAlbumRemoveAssetsCompleteCallback(napi_env env, napi_status status, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSPhotoAlbumRemoveAssetsCompleteCallback");

    PhotoAlbumNapiAsyncContext *context = static_cast<PhotoAlbumNapiAsyncContext*>(data);
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
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

napi_value PhotoAlbumNapi::JSPhotoAlbumRemoveAssets(napi_env env, napi_callback_info info)
{
    unique_ptr<PhotoAlbumNapiAsyncContext> asyncContext = make_unique<PhotoAlbumNapiAsyncContext>();
    CHECK_NULLPTR_RET(ParseArgsRemoveAssets(env, info, asyncContext));

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSPhotoAlbumRemoveAssets",
        JSPhotoAlbumRemoveAssetsExecute, JSPhotoAlbumRemoveAssetsCompleteCallback);
}

static int32_t GetUserAlbumPredicates(const int32_t albumId, DataSharePredicates &predicates)
{
    string onClause = MediaColumn::MEDIA_ID + " = " + PhotoMap::ASSET_ID;
    predicates.InnerJoin(PhotoMap::TABLE)->On({ onClause });
    predicates.EqualTo(PhotoMap::ALBUM_ID, to_string(albumId));
    predicates.EqualTo(MediaColumn::MEDIA_DATE_TRASHED, to_string(0));
    predicates.EqualTo(MediaColumn::MEDIA_HIDDEN, to_string(0));
    return E_SUCCESS;
}

static int32_t GetFavoritePredicates(DataSharePredicates &predicates)
{
    predicates.BeginWrap();
    constexpr int32_t IS_FAVORITE = 1;
    predicates.EqualTo(MediaColumn::MEDIA_IS_FAV, to_string(IS_FAVORITE));
    predicates.And()->EqualTo(MediaColumn::MEDIA_DATE_TRASHED, to_string(0));
    predicates.And()->EqualTo(MediaColumn::MEDIA_HIDDEN, to_string(0));
    predicates.EndWrap();
    return E_SUCCESS;
}

static int32_t GetVideoPredicates(DataSharePredicates &predicates)
{
    predicates.BeginWrap();
    predicates.EqualTo(MediaColumn::MEDIA_TYPE, to_string(MEDIA_TYPE_VIDEO));
    predicates.And()->EqualTo(MediaColumn::MEDIA_DATE_TRASHED, to_string(0));
    predicates.And()->EqualTo(MediaColumn::MEDIA_HIDDEN, to_string(0));
    predicates.EndWrap();
    return E_SUCCESS;
}

static int32_t GetHiddenPredicates(DataSharePredicates &predicates)
{
    predicates.BeginWrap();
    constexpr int32_t IS_HIDDEN = 1;
    predicates.EqualTo(MediaColumn::MEDIA_HIDDEN, to_string(IS_HIDDEN));
    predicates.And()->EqualTo(MediaColumn::MEDIA_DATE_TRASHED, to_string(0));
    predicates.EndWrap();
    return E_SUCCESS;
}

static int32_t GetTrashPredicates(DataSharePredicates &predicates)
{
    predicates.BeginWrap();
    predicates.GreaterThan(MediaColumn::MEDIA_DATE_TRASHED, to_string(0));
    predicates.EndWrap();
    return E_SUCCESS;
}

static int32_t GetScreenshotPredicates(DataSharePredicates &predicates)
{
    predicates.BeginWrap();
    predicates.EqualTo(PhotoColumn::PHOTO_SUBTYPE, to_string(static_cast<int32_t>(PhotoSubType::SCREENSHOT)));
    predicates.And()->EqualTo(MediaColumn::MEDIA_DATE_TRASHED, to_string(0));
    predicates.And()->EqualTo(MediaColumn::MEDIA_HIDDEN, to_string(0));
    predicates.EndWrap();
    return E_SUCCESS;
}

static int32_t GetCameraPredicates(DataSharePredicates &predicates)
{
    predicates.BeginWrap();
    predicates.EqualTo(PhotoColumn::PHOTO_SUBTYPE, to_string(static_cast<int32_t>(PhotoSubType::CAMERA)));
    predicates.And()->EqualTo(MediaColumn::MEDIA_DATE_TRASHED, to_string(0));
    predicates.And()->EqualTo(MediaColumn::MEDIA_HIDDEN, to_string(0));
    predicates.EndWrap();
    return E_SUCCESS;
}

static int32_t GetSystemAlbumPredicates(const PhotoAlbumSubType subType, DataSharePredicates &predicates)
{
    switch (subType) {
        case PhotoAlbumSubType::FAVORITE: {
            return GetFavoritePredicates(predicates);
        }
        case PhotoAlbumSubType::VIDEO: {
            return GetVideoPredicates(predicates);
        }
        case PhotoAlbumSubType::HIDDEN: {
            return GetHiddenPredicates(predicates);
        }
        case PhotoAlbumSubType::TRASH: {
            return GetTrashPredicates(predicates);
        }
        case PhotoAlbumSubType::SCREENSHOT: {
            return GetScreenshotPredicates(predicates);
        }
        case PhotoAlbumSubType::CAMERA: {
            return GetCameraPredicates(predicates);
        }
        default: {
            NAPI_ERR_LOG("Unsupported photo album subtype: %{public}d", subType);
            return E_INVALID_ARGUMENTS;
        }
    }
}

static int32_t GetPredicatesByAlbumTypes(const shared_ptr<PhotoAlbum> &photoAlbum,
    DataSharePredicates &predicates)
{
    auto albumId = photoAlbum->GetAlbumId();
    if (albumId <= 0) {
        return E_INVALID_ARGUMENTS;
    }
    auto type = photoAlbum->GetPhotoAlbumType();
    auto subType = photoAlbum->GetPhotoAlbumSubType();
    if ((!PhotoAlbum::CheckPhotoAlbumType(type)) || (!PhotoAlbum::CheckPhotoAlbumSubType(subType))) {
        return E_INVALID_ARGUMENTS;
    }

    if (PhotoAlbum::IsUserPhotoAlbum(type, subType)) {
        return GetUserAlbumPredicates(photoAlbum->GetAlbumId(), predicates);
    }

    if ((type != PhotoAlbumType::SYSTEM) || (subType == PhotoAlbumSubType::USER_GENERIC) ||
        (subType == PhotoAlbumSubType::ANY)) {
        return E_INVALID_ARGUMENTS;
    }
    return GetSystemAlbumPredicates(subType, predicates);
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
    auto ret = GetPredicatesByAlbumTypes(photoAlbum, context->predicates);
    if (ret != E_SUCCESS) {
        NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return nullptr;
    }
    CHECK_NULLPTR_RET(MediaLibraryNapiUtils::AddDefaultAssetColumns(env, context->fetchColumn,
        PhotoColumn::IsPhotoColumn));

    CHECK_ARGS(env, MediaLibraryNapiUtils::GetParamCallback(env, context), JS_ERR_PARAMETER_INVALID);

    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_boolean(env, true, &result), JS_INNER_FAIL);
    return result;
}

static void JSGetPhotoAssetsExecute(napi_env env, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSGetPhotoAssetsExecute");

    auto context = static_cast<PhotoAlbumNapiAsyncContext *>(data);

    string queryUri = URI_QUERY_PHOTO_MAP;
    MediaLibraryNapiUtils::UriAddFragmentTypeMask(queryUri, PHOTO_TYPE_MASK);
    Uri uri(queryUri);
    int32_t errCode = 0;
    auto resultSet = UserFileClient::Query(uri, context->predicates, context->fetchColumn, errCode);
    if (resultSet == nullptr) {
        context->SaveError(E_HAS_DB_ERROR);
        return;
    }
    context->fetchResult = make_unique<FetchResult<FileAsset>>(move(resultSet));
    context->fetchResult->SetResultNapiType(ResultNapiType::TYPE_USERFILE_MGR);
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

    auto context = static_cast<PhotoAlbumNapiAsyncContext *>(data);

    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    CHECK_ARGS_RET_VOID(env, napi_get_undefined(env, &jsContext->data), JS_INNER_FAIL);
    CHECK_ARGS_RET_VOID(env, napi_get_undefined(env, &jsContext->error), JS_INNER_FAIL);
    if (context->fetchResult != nullptr) {
        GetPhotoMapQueryResult(env, context, jsContext);
    } else {
        NAPI_ERR_LOG("No fetch file result found!");
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
            "Failed to get fetchFileResult from DB");
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

static napi_value TrashAlbumParseArgs(napi_env env, napi_callback_info info,
    unique_ptr<PhotoAlbumNapiAsyncContext> &context)
{
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
    vector<string> assetsArray;
    CHECK_NULLPTR_RET(GetAssetsIdArray(env, context->argv[PARAM0], assetsArray));
    if (assetsArray.empty()) {
        napi_value result = nullptr;
        CHECK_ARGS(env, napi_get_boolean(env, true, &result), JS_INNER_FAIL);
        return result;
    }
    context->predicates.In(MediaColumn::MEDIA_ID, assetsArray);
    context->predicates.GreaterThan(MediaColumn::MEDIA_DATE_TRASHED, to_string(0));
    context->valuesBucket.Put(MediaColumn::MEDIA_DATE_TRASHED, 0);

    CHECK_ARGS(env, MediaLibraryNapiUtils::GetParamCallback(env, context), JS_ERR_PARAMETER_INVALID);

    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_boolean(env, true, &result), JS_INNER_FAIL);
    return result;
}

static void TrashAlbumExecute(const TrashAlbumExecuteOpt &opt)
{
    MediaLibraryTracer tracer;
    tracer.Start(opt.tracerLabel);

    auto *context = static_cast<PhotoAlbumNapiAsyncContext*>(opt.data);
    if (context->predicates.GetOperationList().empty()) {
        return;
    }
    string uriStr = opt.uri;
    MediaLibraryNapiUtils::UriAddFragmentTypeMask(uriStr, PHOTO_TYPE_MASK);
    Uri uri(uriStr);
    int changedRows = UserFileClient::Update(uri, context->predicates, context->valuesBucket);
    if (changedRows < 0) {
        context->SaveError(changedRows);
        return;
    }
    context->changedRows = changedRows;
}

static void TrashAlbumComplete(napi_env env, napi_status status, void *data)
{
    PhotoAlbumNapiAsyncContext *context = static_cast<PhotoAlbumNapiAsyncContext*>(data);
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
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
        .uri = URI_RECOVER_PHOTOS,
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

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSRecoverPhotos", RecoverPhotosExecute,
        RecoverPhotosComplete);
}

static void DeletePhotosExecute(napi_env env, void *data)
{
    TrashAlbumExecuteOpt opt = {
        .env = env,
        .data = data,
        .tracerLabel = "DeletePhotosExecute",
        .uri = URI_DELETE_PHOTOS,
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

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSDeletePhotos", DeletePhotosExecute,
        DeletePhotosComplete);
}
} // namespace OHOS::Media
