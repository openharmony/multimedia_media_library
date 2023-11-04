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

#define MLOG_TAG "MediaAlbumChangeRequestNapi"

#include "media_album_change_request_napi.h"

#include <unordered_set>

#include "file_asset_napi.h"
#include "media_file_utils.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_napi_log.h"
#include "medialibrary_tracer.h"
#include "photo_album_napi.h"
#include "userfile_client.h"

using namespace std;

namespace OHOS::Media {
static const string MEDIA_ALBUM_CHANGE_REQUEST_CLASS = "MediaAlbumChangeRequest";
thread_local napi_ref MediaAlbumChangeRequestNapi::constructor_ = nullptr;

napi_value MediaAlbumChangeRequestNapi::Init(napi_env env, napi_value exports)
{
    NapiClassInfo info = { .name = MEDIA_ALBUM_CHANGE_REQUEST_CLASS,
        .ref = &constructor_,
        .constructor = Constructor,
        .props = {
            DECLARE_NAPI_FUNCTION("setAlbumName", JSSetAlbumName),
            DECLARE_NAPI_FUNCTION("setCoverUri", JSSetCoverUri),
            DECLARE_NAPI_FUNCTION("placeToFrontOf", JSPlaceToFrontOf)
        } };
    MediaLibraryNapiUtils::NapiDefineClass(env, exports, info);
    return exports;
}

napi_value MediaAlbumChangeRequestNapi::Constructor(napi_env env, napi_callback_info info)
{
    napi_value newTarget = nullptr;
    CHECK_ARGS(env, napi_get_new_target(env, info, &newTarget), JS_INNER_FAIL);
    bool isConstructor = newTarget != nullptr;

    if (isConstructor) {
        size_t argc = ARGS_ONE;
        napi_value argv[ARGS_ONE] = { 0 };
        napi_value thisVar = nullptr;
        napi_valuetype valueType;
        PhotoAlbumNapi* photoAlbumNapi;
        CHECK_ARGS(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr), JS_INNER_FAIL);
        CHECK_COND_WITH_MESSAGE(env, argc == ARGS_ONE, "Number of args is invalid");
        CHECK_ARGS(env, napi_typeof(env, argv[PARAM0], &valueType), JS_INNER_FAIL);
        CHECK_COND_WITH_MESSAGE(env, valueType == napi_object, "Invalid argument type");
        CHECK_ARGS(env, napi_unwrap(env, argv[PARAM0], reinterpret_cast<void**>(&photoAlbumNapi)), JS_INNER_FAIL);
        CHECK_COND_WITH_MESSAGE(env, photoAlbumNapi != nullptr, "Failed to get PhotoAlbumNapi object");

        unique_ptr<MediaAlbumChangeRequestNapi> obj = make_unique<MediaAlbumChangeRequestNapi>();
        CHECK_COND_WITH_MESSAGE(env, obj != nullptr, "Create MediaAlbumChangeRequestNapi failed");
        obj->photoAlbum_ = photoAlbumNapi->GetPhotoAlbumInstance();
        CHECK_ARGS(env,
            napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()), MediaAlbumChangeRequestNapi::Destructor,
                nullptr, nullptr),
            JS_INNER_FAIL);
        obj.release();
        return thisVar;
    }

    napi_value constructor = nullptr;
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_reference_value(env, constructor_, &constructor));
    NAPI_CALL(env, napi_new_instance(env, constructor, 0, nullptr, &result));
    return result;
}

void MediaAlbumChangeRequestNapi::Destructor(napi_env env, void* nativeObject, void* finalizeHint)
{
    auto* albumChangeRequest = reinterpret_cast<MediaAlbumChangeRequestNapi*>(nativeObject);
    if (albumChangeRequest != nullptr) {
        delete albumChangeRequest;
        albumChangeRequest = nullptr;
    }
}

shared_ptr<PhotoAlbum> MediaAlbumChangeRequestNapi::GetPhotoAlbumInstance() const
{
    return photoAlbum_;
}

shared_ptr<PhotoAlbum> MediaAlbumChangeRequestNapi::GetReferencePhotoAlbumInstance() const
{
    return referencePhotoAlbum_;
}

napi_value MediaAlbumChangeRequestNapi::JSSetAlbumName(napi_env env, napi_callback_info info)
{
    auto asyncContext = make_unique<MediaAlbumChangeRequestAsyncContext>();
    string albumName;
    CHECK_COND_WITH_MESSAGE(env,
        MediaLibraryNapiUtils::ParseArgsStringCallback(env, info, asyncContext, albumName) == napi_ok,
        "Failed to parse args");
    CHECK_COND_WITH_MESSAGE(env, asyncContext->argc == ARGS_ONE, "Number of args is invalid");
    CHECK_COND_WITH_MESSAGE(env, MediaFileUtils::CheckAlbumName(albumName) == E_OK, "Invalid album name");

    auto photoAlbum = asyncContext->objectInfo->photoAlbum_;
    CHECK_COND_WITH_MESSAGE(env, photoAlbum != nullptr, "PhotoAlbum is nullptr");
    CHECK_COND_WITH_MESSAGE(env,
        PhotoAlbum::IsUserPhotoAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType()),
        "Only user album can set album name");
    photoAlbum->SetAlbumName(albumName);
    asyncContext->objectInfo->albumChangeOperations_.push_back(AlbumChangeOperation::SET_ALBUM_NAME);

    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_undefined(env, &result), JS_INNER_FAIL);
    return result;
}

napi_value MediaAlbumChangeRequestNapi::JSSetCoverUri(napi_env env, napi_callback_info info)
{
    if (!MediaLibraryNapiUtils::IsSystemApp()) {
        NapiError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return nullptr;
    }

    auto asyncContext = make_unique<MediaAlbumChangeRequestAsyncContext>();
    string coverUri;
    CHECK_COND_WITH_MESSAGE(env,
        MediaLibraryNapiUtils::ParseArgsStringCallback(env, info, asyncContext, coverUri) == napi_ok,
        "Failed to parse args");
    CHECK_COND_WITH_MESSAGE(env, asyncContext->argc == ARGS_ONE, "Number of args is invalid");

    auto photoAlbum = asyncContext->objectInfo->photoAlbum_;
    CHECK_COND_WITH_MESSAGE(env, photoAlbum != nullptr, "PhotoAlbum is nullptr");
    CHECK_COND_WITH_MESSAGE(env,
        PhotoAlbum::IsUserPhotoAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType()),
        "Only user album can set cover uri");
    photoAlbum->SetCoverUri(coverUri);
    asyncContext->objectInfo->albumChangeOperations_.push_back(AlbumChangeOperation::SET_COVER_URI);

    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_undefined(env, &result), JS_INNER_FAIL);
    return result;
}

napi_value MediaAlbumChangeRequestNapi::JSPlaceToFrontOf(napi_env env, napi_callback_info info)
{
    if (!MediaLibraryNapiUtils::IsSystemApp()) {
        NapiError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return nullptr;
    }
    napi_valuetype valueType;
    auto asyncContext = make_unique<MediaAlbumChangeRequestAsyncContext>();

    CHECK_COND_WITH_MESSAGE(env, MediaLibraryNapiUtils::AsyncContextSetObjectInfo(
        env, info, asyncContext, ARGS_ONE, ARGS_ONE) == napi_ok, "Failed to get object info");
    CHECK_ARGS(env, napi_typeof(env, asyncContext->argv[PARAM0], &valueType), JS_INNER_FAIL);
    CHECK_COND_WITH_MESSAGE(env, valueType == napi_object || valueType == napi_null, "Invalid argument type");
    if (valueType == napi_object) {
        PhotoAlbumNapi* photoAlbumNapi;
        CHECK_ARGS(env, napi_unwrap(env, asyncContext->argv[PARAM0],
            reinterpret_cast<void**>(&photoAlbumNapi)), JS_INNER_FAIL);
        CHECK_COND_WITH_MESSAGE(env, photoAlbumNapi != nullptr, "Failed to get PhotoAlbumNapi object");
        asyncContext->objectInfo->referencePhotoAlbum_ = photoAlbumNapi->GetPhotoAlbumInstance();
    }
    asyncContext->objectInfo->albumChangeOperations_.push_back(AlbumChangeOperation::ORDER_ALBUM);
    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_undefined(env, &result), JS_INNER_FAIL);
    return result;
}

static bool OrderAlbumExecute(MediaAlbumChangeRequestAsyncContext& context)
{
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    auto photoAlbum = context.objectInfo->GetPhotoAlbumInstance();
    auto referenceAlum = context.objectInfo->GetReferencePhotoAlbumInstance();
    Uri updateAlbumUri(URI_COMPAT_ORDER_ALBUM);
    valuesBucket.Put(PhotoAlbumColumns::ALBUM_ID, photoAlbum->GetAlbumId());
    int32_t referenceAlbumId = -1;
    if (referenceAlum != nullptr) {
        referenceAlbumId = referenceAlum->GetAlbumId();
    }
    valuesBucket.Put(PhotoAlbumColumns::REFERENCE_ALBUM_ID, referenceAlbumId);
    int32_t result = UserFileClient::Update(updateAlbumUri, predicates, valuesBucket);
    if (result < 0) {
        context.SaveError(result);
        NAPI_ERR_LOG("Failed to order albums err: %{public}d", result);
        return false;
    }
    return true;
}

static bool SetAlbumPropertyExecute(
    MediaAlbumChangeRequestAsyncContext& context, const AlbumChangeOperation& changeOperation)
{
    string property;
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    auto photoAlbum = context.objectInfo->GetPhotoAlbumInstance();
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, to_string(photoAlbum->GetAlbumId()));
    switch (changeOperation) {
        case AlbumChangeOperation::SET_ALBUM_NAME:
            property = PhotoAlbumColumns::ALBUM_NAME;
            valuesBucket.Put(property, photoAlbum->GetAlbumName());
            break;
        case AlbumChangeOperation::SET_COVER_URI:
            property = PhotoAlbumColumns::ALBUM_COVER_URI;
            valuesBucket.Put(property, photoAlbum->GetCoverUri());
            break;
        default:
            context.SaveError(E_FAIL);
            NAPI_ERR_LOG("Unsupported album change operation: %{public}d", changeOperation);
            return false;
    }

    string uri = PAH_UPDATE_PHOTO_ALBUM;
    MediaLibraryNapiUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri updateAlbumUri(uri);
    int32_t changedRows = UserFileClient::Update(updateAlbumUri, predicates, valuesBucket);
    if (changedRows < 0) {
        context.SaveError(changedRows);
        NAPI_ERR_LOG("Failed to set %{public}s, err: %{public}d", property.c_str(), changedRows);
        return false;
    }
    return true;
}

static void ApplyAlbumChangeRequestExecute(napi_env env, void* data)
{
    auto* context = static_cast<MediaAlbumChangeRequestAsyncContext*>(data);
    unordered_set<AlbumChangeOperation> appliedOperations;
    for (auto& changeOperation : context->albumChangeOperations) {
        // Keep the final result(s) of each operation, and commit only once.
        if (appliedOperations.find(changeOperation) != appliedOperations.end()) {
            continue;
        }

        bool valid = true;
        switch (changeOperation) {
            case AlbumChangeOperation::SET_ALBUM_NAME:
            case AlbumChangeOperation::SET_COVER_URI:
                valid = SetAlbumPropertyExecute(*context, changeOperation);
                break;
            case AlbumChangeOperation::ORDER_ALBUM:
                valid = OrderAlbumExecute(*context);
                break;
            default:
                NAPI_ERR_LOG("Invalid album change operation: %{public}d", changeOperation);
                context->error = JS_ERR_PARAMETER_INVALID;
                return;
        }

        if (!valid) {
            NAPI_ERR_LOG("Failed to apply album change request, operation: %{public}d", changeOperation);
            return;
        }
        appliedOperations.insert(changeOperation);
    }
}

static void ApplyAlbumChangeRequestCompleteCallback(napi_env env, napi_status status, void* data)
{
    auto* context = static_cast<MediaAlbumChangeRequestAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    auto jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    napi_get_undefined(env, &jsContext->data);
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

napi_value MediaAlbumChangeRequestNapi::ApplyChanges(napi_env env, napi_callback_info info)
{
    constexpr size_t minArgs = ARGS_ONE;
    constexpr size_t maxArgs = ARGS_TWO;
    auto asyncContext = make_unique<MediaAlbumChangeRequestAsyncContext>();
    CHECK_COND_WITH_MESSAGE(env,
        MediaLibraryNapiUtils::AsyncContextGetArgs(env, info, asyncContext, minArgs, maxArgs) == napi_ok,
        "Failed to get args");
    asyncContext->objectInfo = this;
    CHECK_COND_WITH_MESSAGE(env, !albumChangeOperations_.empty(), "None request to apply");
    asyncContext->albumChangeOperations = albumChangeOperations_;
    albumChangeOperations_.clear();
    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "ApplyMediaAlbumChangeRequest",
        ApplyAlbumChangeRequestExecute, ApplyAlbumChangeRequestCompleteCallback);
}
} // namespace OHOS::Media