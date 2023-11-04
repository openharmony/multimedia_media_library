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
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <unordered_set>

#include "directory_ex.h"
#include "file_asset_napi.h"
#include "file_uri.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_errno.h"
#include "medialibrary_napi_log.h"
#include "medialibrary_tracer.h"
#include "userfile_client.h"
#include "userfile_manager_types.h"

using namespace std;

namespace OHOS::Media {
static const string MEDIA_ASSET_CHANGE_REQUEST_CLASS = "MediaAssetChangeRequest";
thread_local napi_ref MediaAssetChangeRequestNapi::constructor_ = nullptr;

constexpr int32_t YES = 1;
constexpr int32_t NO = 0;

constexpr int32_t USER_COMMENT_MAX_LEN = 140;

napi_value MediaAssetChangeRequestNapi::Init(napi_env env, napi_value exports)
{
    NAPI_DEBUG_LOG("MediaAssetChangeRequestNapi::Init");
    NapiClassInfo info = { .name = MEDIA_ASSET_CHANGE_REQUEST_CLASS,
        .ref = &constructor_,
        .constructor = Constructor,
        .props = {
            DECLARE_NAPI_STATIC_FUNCTION("deleteAssets", JSDeleteAssets),
            DECLARE_NAPI_FUNCTION("setFavorite", JSSetFavorite),
            DECLARE_NAPI_FUNCTION("setUserComment", JSSetUserComment),
        } };
    MediaLibraryNapiUtils::NapiDefineClass(env, exports, info);
    return exports;
}

napi_value MediaAssetChangeRequestNapi::Constructor(napi_env env, napi_callback_info info)
{
    NAPI_DEBUG_LOG("enter MediaAssetChangeRequestNapi::Constructor");
    napi_value newTarget = nullptr;
    CHECK_ARGS(env, napi_get_new_target(env, info, &newTarget), JS_INNER_FAIL);
    bool isConstructor = newTarget != nullptr;

    if (isConstructor) {
        size_t argc = ARGS_ONE;
        napi_value argv[ARGS_ONE] = { 0 };
        napi_value thisVar = nullptr;
        napi_valuetype valueType;
        FileAssetNapi* fileAssetNapi;
        CHECK_ARGS(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr), JS_INNER_FAIL);
        CHECK_ARGS_WITH_MESSAGE(env, argc == ARGS_ONE, "Number of args is invalid");
        CHECK_ARGS(env, napi_typeof(env, argv[PARAM0], &valueType), JS_INNER_FAIL);
        CHECK_ARGS_WITH_MESSAGE(env, valueType == napi_object, "Invalid argument type");
        CHECK_ARGS(env, napi_unwrap(env, argv[PARAM0], reinterpret_cast<void**>(&fileAssetNapi)), JS_INNER_FAIL);
        CHECK_ARGS_WITH_MESSAGE(env, fileAssetNapi != nullptr, "Failed to get FileAssetNapi object");

        unique_ptr<MediaAssetChangeRequestNapi> obj = make_unique<MediaAssetChangeRequestNapi>();
        CHECK_ARGS_WITH_MESSAGE(env, obj != nullptr, "Create MediaAssetChangeRequestNapi failed");
        obj->fileAsset_ = fileAssetNapi->GetFileAssetInstance();
        CHECK_ARGS(env,
            napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()), MediaAssetChangeRequestNapi::Destructor,
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

void MediaAssetChangeRequestNapi::Destructor(napi_env env, void* nativeObject, void* finalizeHint)
{
    auto* assetChangeRequest = reinterpret_cast<MediaAssetChangeRequestNapi*>(nativeObject);
    if (assetChangeRequest != nullptr) {
        delete assetChangeRequest;
        assetChangeRequest = nullptr;
    }
}

shared_ptr<FileAsset> MediaAssetChangeRequestNapi::GetFileAssetInstance() const
{
    return fileAsset_;
}

static napi_value ParseArgsDeleteAssets(
    napi_env env, napi_callback_info info, unique_ptr<MediaAssetChangeRequestAsyncContext>& context)
{
    if (!MediaLibraryNapiUtils::IsSystemApp()) {
        NapiError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return nullptr;
    }

    constexpr size_t minArgs = ARGS_TWO;
    constexpr size_t maxArgs = ARGS_THREE;
    CHECK_ARGS_WITH_MESSAGE(env,
        MediaLibraryNapiUtils::AsyncContextGetArgs(env, info, context, minArgs, maxArgs) == napi_ok,
        "Failed to get args");
    CHECK_COND(env, MediaAssetChangeRequestNapi::InitUserFileClient(env, info), JS_INNER_FAIL);

    vector<string> uris;
    vector<napi_value> napiValues;
    napi_valuetype valueType = napi_undefined;
    CHECK_NULLPTR_RET(MediaLibraryNapiUtils::GetNapiValueArray(env, context->argv[PARAM1], napiValues));
    CHECK_ARGS_WITH_MESSAGE(env, !napiValues.empty(), "array is empty");
    CHECK_ARGS(env, napi_typeof(env, napiValues.front(), &valueType), JS_ERR_PARAMETER_INVALID);
    if (valueType == napi_string) { // array of asset uri
        CHECK_NULLPTR_RET(MediaLibraryNapiUtils::GetStringArray(env, napiValues, uris));
    } else if (valueType == napi_object) { // array of asset object
        CHECK_NULLPTR_RET(MediaLibraryNapiUtils::GetUriArrayFromAssets(env, napiValues, uris));
    } else {
        NapiError::ThrowError(env, JS_ERR_PARAMETER_INVALID, "Invalid type");
        return nullptr;
    }

    CHECK_ARGS_WITH_MESSAGE(env, !uris.empty(), "Failed to check empty uri");
    for (const auto& uri : uris) {
        CHECK_ARGS_WITH_MESSAGE(env, uri.find(PhotoColumn::PHOTO_URI_PREFIX) != string::npos,
            "Failed to check uri format, not a photo uri");
    }

    context->predicates.In(PhotoColumn::MEDIA_ID, uris);
    context->valuesBucket.Put(PhotoColumn::MEDIA_DATE_TRASHED, MediaFileUtils::UTCTimeSeconds());

    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, true, &result));
    return result;
}

static void DeleteAssetsExecute(napi_env env, void* data)
{
    NAPI_DEBUG_LOG("enter DeleteAssetsExecute");
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
    NAPI_DEBUG_LOG("enter DeleteAssetsCompleteCallback");
    auto* context = static_cast<MediaAssetChangeRequestAsyncContext*>(data);
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

napi_value MediaAssetChangeRequestNapi::JSDeleteAssets(napi_env env, napi_callback_info info)
{
    NAPI_DEBUG_LOG("enter MediaAssetChangeRequestNapi::JSDeleteAssets");
    auto asyncContext = make_unique<MediaAssetChangeRequestAsyncContext>();
    CHECK_ARGS_WITH_MESSAGE(env, ParseArgsDeleteAssets(env, info, asyncContext), "Failed to parse args");
    return MediaLibraryNapiUtils::NapiCreateAsyncWork(
        env, asyncContext, "ChangeRequestDeleteAssets", DeleteAssetsExecute, DeleteAssetsCompleteCallback);
}

napi_value MediaAssetChangeRequestNapi::JSSetFavorite(napi_env env, napi_callback_info info)
{
    NAPI_DEBUG_LOG("enter MediaAssetChangeRequestNapi::JSSetFavorite");
    if (!MediaLibraryNapiUtils::IsSystemApp()) {
        NapiError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return nullptr;
    }

    auto asyncContext = make_unique<MediaAssetChangeRequestAsyncContext>();
    bool isFavorite;
    CHECK_ARGS_WITH_MESSAGE(env,
        MediaLibraryNapiUtils::ParseArgsBoolCallBack(env, info, asyncContext, isFavorite) == napi_ok,
        "Failed to parse args");
    CHECK_ARGS_WITH_MESSAGE(env, asyncContext->argc == ARGS_ONE, "Number of args is invalid");
    CHECK_ARGS_WITH_MESSAGE(env, asyncContext->objectInfo->fileAsset_ != nullptr, "FileAsset is nullptr");
    asyncContext->objectInfo->fileAsset_->SetFavorite(isFavorite);
    asyncContext->objectInfo->assetChangeOperations_.push_back(AssetChangeOperation::SET_FAVORITE);

    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_undefined(env, &result), JS_INNER_FAIL);
    return result;
}

napi_value MediaAssetChangeRequestNapi::JSSetUserComment(napi_env env, napi_callback_info info)
{
    NAPI_DEBUG_LOG("enter MediaAssetChangeRequestNapi::JSSetUserComment");
    if (!MediaLibraryNapiUtils::IsSystemApp()) {
        NapiError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return nullptr;
    }

    auto asyncContext = make_unique<MediaAssetChangeRequestAsyncContext>();
    string userComment;
    CHECK_ARGS_WITH_MESSAGE(env,
        MediaLibraryNapiUtils::ParseArgsStringCallback(env, info, asyncContext, userComment) == napi_ok,
        "Failed to parse args");
    CHECK_ARGS_WITH_MESSAGE(env, asyncContext->argc == ARGS_ONE, "Number of args is invalid");
    CHECK_ARGS_WITH_MESSAGE(env, userComment.length() <= USER_COMMENT_MAX_LEN, "user comment too long");
    CHECK_ARGS_WITH_MESSAGE(env, asyncContext->objectInfo->fileAsset_ != nullptr, "FileAsset is nullptr");
    asyncContext->objectInfo->fileAsset_->SetUserComment(userComment);
    asyncContext->objectInfo->assetChangeOperations_.push_back(AssetChangeOperation::SET_USER_COMMENT);

    napi_value result = nullptr;
    CHECK_ARGS(env, napi_get_undefined(env, &result), JS_INNER_FAIL);
    return result;
}

static bool SetAssetPropertyExecute(
    MediaAssetChangeRequestAsyncContext& context, const AssetChangeOperation& changeOperation)
{
    NAPI_DEBUG_LOG("enter SetAssetPropertyExecute");
    string uri;
    string property;
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    auto fileAsset = context.objectInfo->GetFileAssetInstance();
    predicates.SetWhereClause(PhotoColumn::MEDIA_ID + " = ? ");
    predicates.SetWhereArgs({ to_string(fileAsset->GetId()) });
    switch (changeOperation) {
        case AssetChangeOperation::SET_FAVORITE:
            uri = PAH_UPDATE_PHOTO;
            property = PhotoColumn::MEDIA_IS_FAV;
            valuesBucket.Put(property, fileAsset->IsFavorite() ? YES : NO);
            break;
        case AssetChangeOperation::SET_USER_COMMENT:
            uri = PAH_EDIT_USER_COMMENT_PHOTO;
            property = PhotoColumn::PHOTO_USER_COMMENT;
            valuesBucket.Put(property, fileAsset->GetUserComment());
            break;
        default:
            context.SaveError(E_FAIL);
            NAPI_ERR_LOG("Unsupported asset change operation: %{public}d", changeOperation);
            return false;
    }

    MediaLibraryNapiUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri updateAssetUri(uri);
    int32_t changedRows = UserFileClient::Update(updateAssetUri, predicates, valuesBucket);
    if (changedRows < 0) {
        context.SaveError(changedRows);
        NAPI_ERR_LOG("Failed to set %{public}s, err: %{public}d", property.c_str(), changedRows);
        return false;
    }
    return true;
}

static void ApplyAssetChangeRequestExecute(napi_env env, void* data)
{
    NAPI_DEBUG_LOG("enter ApplyAssetChangeRequestExecute");
    auto* context = static_cast<MediaAssetChangeRequestAsyncContext*>(data);
    unordered_set<AssetChangeOperation> appliedOperations;
    for (auto& changeOperation : context->assetChangeOperations) {
        // Keep the final result of each operation, and commit it only once.
        if (appliedOperations.find(changeOperation) != appliedOperations.end()) {
            continue;
        }

        bool valid = true;
        switch (changeOperation) {
            case AssetChangeOperation::SET_FAVORITE:
            case AssetChangeOperation::SET_USER_COMMENT:
                valid = SetAssetPropertyExecute(*context, changeOperation);
                break;
            default:
                NAPI_ERR_LOG("Invalid asset change operation: %{public}d", changeOperation);
                context->error = JS_ERR_PARAMETER_INVALID;
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
    NAPI_DEBUG_LOG("enter ApplyAssetChangeRequestCompleteCallback");
    auto* context = static_cast<MediaAssetChangeRequestAsyncContext*>(data);
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

napi_value MediaAssetChangeRequestNapi::ApplyChanges(napi_env env, napi_callback_info info)
{
    NAPI_DEBUG_LOG("enter MediaAssetChangeRequestNapi::ApplyChanges");
    constexpr size_t minArgs = ARGS_ONE;
    constexpr size_t maxArgs = ARGS_TWO;
    auto asyncContext = make_unique<MediaAssetChangeRequestAsyncContext>();
    CHECK_ARGS_WITH_MESSAGE(env,
        MediaLibraryNapiUtils::AsyncContextGetArgs(env, info, asyncContext, minArgs, maxArgs) == napi_ok,
        "Failed to get args");
    asyncContext->objectInfo = this;
    CHECK_ARGS_WITH_MESSAGE(env, !assetChangeOperations_.empty(), "None request to apply");
    asyncContext->assetChangeOperations = assetChangeOperations_;
    assetChangeOperations_.clear();
    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "ApplyMediaAssetChangeRequest",
        ApplyAssetChangeRequestExecute, ApplyAssetChangeRequestCompleteCallback);
}
} // namespace OHOS::Media