/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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

#define MLOG_TAG "HighlightAlbumNapi"

#include <unordered_map>
#include <unordered_set>

#include "highlight_album_napi.h"
#include "file_asset_napi.h"
#include "media_file_utils.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_napi_log.h"
#include "medialibrary_tracer.h"
#include "photo_album.h"
#include "photo_album_napi.h"
#include "photo_map_column.h"
#include "result_set_utils.h"
#include "userfile_client.h"
#include "vision_column.h"
#include "story_album_column.h"
#include "story_cover_info_column.h"
#include "story_play_info_column.h"
#include "user_photography_info_column.h"

using namespace std;

namespace OHOS::Media {
static const string HIGHLIGHT_ALBUM_CLASS = "HighlightAlbum";
thread_local napi_ref HighlightAlbumNapi::constructor_ = nullptr;

using CompleteCallback = napi_async_complete_callback;

HighlightAlbumNapi::HighlightAlbumNapi() : highlightmEnv_(nullptr) {}

HighlightAlbumNapi::~HighlightAlbumNapi() = default;

napi_value HighlightAlbumNapi::Init(napi_env env, napi_value exports)
{
    NapiClassInfo info = {
        .name = HIGHLIGHT_ALBUM_CLASS,
        .ref = &constructor_,
        .constructor = Constructor,
        .props = {
            DECLARE_NAPI_FUNCTION("getHighlightAlbumInfo", JSGetHighlightAlbumInfo),
            DECLARE_NAPI_FUNCTION("setHighlightUserActionData", JSSetHighlightUserActionData),
            DECLARE_NAPI_FUNCTION("getHighlightResource", JSGetHighlightResource),
        } };
    MediaLibraryNapiUtils::NapiDefineClass(env, exports, info);
    return exports;
}

static napi_value ParseHighlightAlbum(napi_env env, napi_value arg, shared_ptr<PhotoAlbum>& photoAlbum)
{
    napi_valuetype valueType;
    PhotoAlbumNapi* photoAlbumNapi;
    CHECK_ARGS(env, napi_typeof(env, arg, &valueType), JS_INNER_FAIL);
    CHECK_COND_WITH_MESSAGE(env, valueType == napi_object, "Invalid argument type");
    CHECK_ARGS(env, napi_unwrap(env, arg, reinterpret_cast<void**>(&photoAlbumNapi)), JS_INNER_FAIL);
    CHECK_COND_WITH_MESSAGE(env, photoAlbumNapi != nullptr, "Failed to get PhotoAlbumNapi object");

    auto photoAlbumPtr = photoAlbumNapi->GetPhotoAlbumInstance();
    CHECK_COND_WITH_MESSAGE(env, photoAlbumPtr != nullptr, "photoAlbum is null");
    CHECK_COND_WITH_MESSAGE(env,
        photoAlbumPtr->GetResultNapiType() == ResultNapiType::TYPE_PHOTOACCESS_HELPER &&
            PhotoAlbum::CheckPhotoAlbumType(photoAlbumPtr->GetPhotoAlbumType()) &&
            PhotoAlbum::CheckPhotoAlbumSubType(photoAlbumPtr->GetPhotoAlbumSubType()),
        "Unsupported type of photoAlbum");
    photoAlbum = photoAlbumPtr;
    RETURN_NAPI_TRUE(env);
}

napi_value HighlightAlbumNapi::Constructor(napi_env env, napi_callback_info info)
{
    napi_value newTarget = nullptr;
    CHECK_ARGS(env, napi_get_new_target(env, info, &newTarget), JS_INNER_FAIL);
    CHECK_COND_RET(newTarget != nullptr, nullptr, "Failed to check new.target");

    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = { 0 };
    napi_value thisVar = nullptr;
    shared_ptr<PhotoAlbum> photoAlbum = nullptr;
    CHECK_ARGS(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr), JS_INNER_FAIL);
    CHECK_COND_WITH_MESSAGE(env, argc == ARGS_ONE, "Number of args is invalid");
    CHECK_COND_WITH_MESSAGE(env, ParseHighlightAlbum(env, argv[PARAM0], photoAlbum), "Failed to parse album");

    unique_ptr<HighlightAlbumNapi> obj = make_unique<HighlightAlbumNapi>();
    CHECK_COND(env, obj != nullptr, JS_INNER_FAIL);
    obj->highlightAlbumPtr = photoAlbum;
    obj->highlightmEnv_ = env;
    CHECK_ARGS(env,
        napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()), HighlightAlbumNapi::Destructor, nullptr,
            nullptr),
        JS_INNER_FAIL);
    obj.release();
    return thisVar;
}

void HighlightAlbumNapi::Destructor(napi_env env, void* nativeObject, void* finalizeHint)
{
    auto* hightlihgtAlbum = reinterpret_cast<HighlightAlbumNapi*>(nativeObject);
    if (hightlihgtAlbum != nullptr) {
        delete hightlihgtAlbum;
        hightlihgtAlbum = nullptr;
    }
}

static const map<int32_t, struct HighlightAlbumInfo> HIGHLIGHT_ALBUM_INFO_MAP = {
    { COVER_INFO, { PAH_QUERY_HIGHLIGHT_COVER, { SUB_TITLE, CLUSTER_TYPE, CLUSTER_SUB_TYPE,
        CLUSTER_CONDITION, MIN_DATE_ADDED, MAX_DATE_ADDED, GENERATE_TIME, HIGHLIGHT_VERSION,
        REMARKS, HIGHLIGHT_STATUS, RATIO, BACKGROUND, FOREGROUND, WORDART, IS_COVERED, COLOR,
        RADIUS, SATURATION, BRIGHTNESS, TITLE_SCALE_X, TITLE_SCALE_Y, TITLE_RECT_WIDTH,
        TITLE_RECT_HEIGHT, BACKGROUND_SCALE_X, BACKGROUND_SCALE_Y, BACKGROUND_RECT_WIDTH,
        BACKGROUND_RECT_HEIGHT, COVER_ALGO_VERSION, COVER_KEY } } },
    { PLAY_INFO, { PAH_QUERY_HIGHLIGHT_PLAY, { MUSIC, FILTER, HIGHLIGHT_PLAY_INFO,
        IS_CHOSEN, PLAY_INFO_VERSION, PLAY_INFO_ID } } },
};

static const map<int32_t, std::string> HIGHLIGHT_USER_ACTION_MAP = {
    { INSERTED_PIC_COUNT, HIGHLIGHT_INSERT_PIC_COUNT },
    { REMOVED_PIC_COUNT, HIGHLIGHT_REMOVE_PIC_COUNT },
    { SHARED_SCREENSHOT_COUNT, HIGHLIGHT_SHARE_SCREENSHOT_COUNT },
    { SHARED_COVER_COUNT, HIGHLIGHT_SHARE_COVER_COUNT },
    { RENAMED_COUNT, HIGHLIGHT_RENAME_COUNT },
    { CHANGED_COVER_COUNT, HIGHLIGHT_CHANGE_COVER_COUNT },
    { RENDER_VIEWED_TIMES, HIGHLIGHT_RENDER_VIEWED_TIMES },
    { RENDER_VIEWED_DURATION, HIGHLIGHT_RENDER_VIEWED_DURATION },
    { ART_LAYOUT_VIEWED_TIMES, HIGHLIGHT_ART_LAYOUT_VIEWED_TIMES },
    { ART_LAYOUT_VIEWED_DURATION, HIGHLIGHT_ART_LAYOUT_VIEWED_DURATION },
};

static void JSGetHighlightAlbumInfoExecute(napi_env env, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSGetHighlightAlbumInfoExecute");

    auto *context = static_cast<HighlightAlbumNapiAsyncContext*>(data);
    string uriStr;
    std::vector<std::string> fetchColumn;
    string tabStr;
    DataShare::DataSharePredicates predicates;
    if (HIGHLIGHT_ALBUM_INFO_MAP.find(context->highlightAlbumInfoType) != HIGHLIGHT_ALBUM_INFO_MAP.end()) {
        uriStr = HIGHLIGHT_ALBUM_INFO_MAP.at(context->highlightAlbumInfoType).uriStr;
        fetchColumn = HIGHLIGHT_ALBUM_INFO_MAP.at(context->highlightAlbumInfoType).fetchColumn;
        if (context->highlightAlbumInfoType == COVER_INFO) {
            tabStr = HIGHLIGHT_COVER_INFO_TABLE;
            vector<string> onClause = {
                HIGHLIGHT_COVER_INFO_TABLE + "." + PhotoAlbumColumns::ALBUM_ID + " = " +
                HIGHLIGHT_ALBUM_TABLE + "." + PhotoAlbumColumns::ALBUM_ID
            };
            predicates.InnerJoin(HIGHLIGHT_ALBUM_TABLE)->On(onClause);
        } else {
            tabStr = HIGHLIGHT_PLAY_INFO_TABLE;
        }
    } else {
        NAPI_ERR_LOG("Invalid highlightAlbumInfoType");
        return;
    }
    int albumId = context->objectInfo->GetPhotoAlbumInstance()->GetAlbumId();
    Uri uri (uriStr);
    predicates.EqualTo(tabStr + "." + PhotoAlbumColumns::ALBUM_ID, to_string(albumId));
    int errCode = 0;
    auto resultSet = UserFileClient::Query(uri, predicates, fetchColumn, errCode);
    if (resultSet != nullptr) {
        context->highlightAlbumInfo = MediaLibraryNapiUtils::ParseResultSet2JsonStr(resultSet, fetchColumn);
    }
}

static void JSGetHighlightAlbumInfoCompleteCallback(napi_env env, napi_status status, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSGetHighlightAlbumInfoCompleteCallback");

    auto *context = static_cast<HighlightAlbumNapiAsyncContext *>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    CHECK_ARGS_RET_VOID(env, napi_get_undefined(env, &jsContext->data), JS_INNER_FAIL);
    CHECK_ARGS_RET_VOID(env, napi_get_undefined(env, &jsContext->error), JS_INNER_FAIL);
    if (context->error == ERR_DEFAULT) {
        CHECK_ARGS_RET_VOID(env, napi_create_string_utf8(env, context->highlightAlbumInfo.c_str(),
            NAPI_AUTO_LENGTH, &jsContext->data), JS_INNER_FAIL);
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

static void JSSetHighlightUserActionDataExecute(napi_env env, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSSetHighlightUserActionDataExecute");

    auto *context = static_cast<HighlightAlbumNapiAsyncContext*>(data);
    string userActionType;
    if (HIGHLIGHT_USER_ACTION_MAP.find(context->highlightUserActionType) != HIGHLIGHT_USER_ACTION_MAP.end()) {
        userActionType = HIGHLIGHT_USER_ACTION_MAP.at(context->highlightUserActionType);
        context->fetchColumn.push_back(userActionType);
    } else {
        NAPI_ERR_LOG("Invalid highlightUserActionType");
        return;
    }
    int albumId = context->objectInfo->GetPhotoAlbumInstance()->GetAlbumId();
    Uri uri(URI_HIGHLIGHT_ALBUM);
    context->predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, to_string(albumId));
    int errCode = 0;
    auto resultSet = UserFileClient::Query(uri, context->predicates, context->fetchColumn, errCode);
    if (resultSet != nullptr) {
        auto count = 0;
        auto ret = resultSet->GetRowCount(count);
        if (ret != NativeRdb::E_OK || count == 0 || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
            NAPI_ERR_LOG("highlight user action data get rdbstore failed");
            context->error = JS_INNER_FAIL;
            return;
        }
        int64_t userActionDataCount = get<int64_t>(ResultSetUtils::GetValFromColumn(userActionType,
            resultSet, TYPE_INT64));
        context->valuesBucket.Put(userActionType, to_string(userActionDataCount + context->actionData));
        int changedRows = UserFileClient::Update(uri, context->predicates, context->valuesBucket);
        context->SaveError(changedRows);
        context->changedRows = changedRows;
    } else {
        NAPI_ERR_LOG("highlight user action data resultSet is null");
        context->error = JS_INNER_FAIL;
        return;
    }
}

static void JSSetHighlightUserActionDataCompleteCallback(napi_env env, napi_status status, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSSetHighlightUserActionDataCompleteCallback");

    auto *context = static_cast<HighlightAlbumNapiAsyncContext*>(data);
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

static int32_t GetFdForArrayBuffer(std::string uriStr)
{
    int32_t fd = 0;
    Uri uri(uriStr);
    fd = UserFileClient::OpenFile(uri, MEDIA_FILEMODE_READONLY);
    if (fd == E_ERR) {
        NAPI_ERR_LOG("Open highlight cover file failed, error: %{public}d", errno);
        return E_HAS_FS_ERROR;
    } else if (fd < 0) {
        NAPI_ERR_LOG("Open highlight cover file failed due to OpenFile failure");
        return fd;
    }
    return fd;
}

static void JSGetHighlightResourceExecute(napi_env env, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSGetHighlightResourceExecute");

    auto *context = static_cast<HighlightAlbumNapiAsyncContext*>(data);
    if (context->resourceUri.find(MEDIA_DATA_DB_HIGHLIGHT) == string::npos) {
        NAPI_ERR_LOG("Invalid highlight resource uri");
        return;
    }
    
    int32_t fd = GetFdForArrayBuffer(context->resourceUri);
    if (fd < 0) {
        return;
    }
    UniqueFd uniqueFd(fd);
    size_t fileLen = static_cast<size_t>(lseek(uniqueFd.Get(), 0, SEEK_END));
    if (fileLen < 0) {
        NAPI_ERR_LOG("Failed to get highlight cover file length, error: %{public}d", errno);
        return;
    }
    int32_t ret = lseek(uniqueFd.Get(), 0, SEEK_SET);
    if (ret < 0) {
        NAPI_ERR_LOG("Failed to reset highlight cover file offset, error: %{public}d", errno);
        return;
    }
    void* arrayBufferData = nullptr;
    napi_value arrayBuffer;
    if (napi_create_arraybuffer(env, fileLen, &arrayBufferData, &arrayBuffer) != napi_ok) {
        NAPI_ERR_LOG("failed to create napi arraybuffer");
        return;
    }

    size_t readBytes = read(uniqueFd.Get(), arrayBufferData, fileLen);
    if (readBytes != fileLen) {
        NAPI_ERR_LOG("read file failed, read bytes is %{public}zu, actual length is %{public}zu, "
            "error: %{public}d", readBytes, fileLen, errno);
        return;
    }
    context->napiArrayBuffer = arrayBuffer;
}

static void JSGetHighlightResourceCompleteCallback(napi_env env, napi_status status, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSGetHighlightResourceCompleteCallback");

    auto *context = static_cast<HighlightAlbumNapiAsyncContext *>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    CHECK_ARGS_RET_VOID(env, napi_get_undefined(env, &jsContext->data), JS_INNER_FAIL);
    CHECK_ARGS_RET_VOID(env, napi_get_undefined(env, &jsContext->error), JS_INNER_FAIL);
    if (context->error == ERR_DEFAULT) {
        jsContext->data = context->napiArrayBuffer;
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

napi_value HighlightAlbumNapi::JSGetHighlightAlbumInfo(napi_env env, napi_callback_info info)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSGetHighlightAlbumInfo");

    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_undefined(env, &result));
    unique_ptr<HighlightAlbumNapiAsyncContext> asyncContext = make_unique<HighlightAlbumNapiAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, result, "asyncContext context is null");
    CHECK_ARGS(env, MediaLibraryNapiUtils::ParseArgsNumberCallback(env, info, asyncContext,
        asyncContext->highlightAlbumInfoType), JS_ERR_PARAMETER_INVALID);

    auto photoAlbum = asyncContext->objectInfo->GetPhotoAlbumInstance();
    CHECK_COND_WITH_MESSAGE(env, photoAlbum != nullptr, "photoAlbum is null");
    CHECK_COND_WITH_MESSAGE(env,
        PhotoAlbum::IsHighlightAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType()),
        "Only and smart highlight album can get highlight album info");

    asyncContext->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSGetHighlightAlbumInfo",
        JSGetHighlightAlbumInfoExecute, JSGetHighlightAlbumInfoCompleteCallback);
}

napi_value HighlightAlbumNapi::JSSetHighlightUserActionData(napi_env env, napi_callback_info info)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSSetHighlightUserActionData");

    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_undefined(env, &result));
    unique_ptr<HighlightAlbumNapiAsyncContext> asyncContext = make_unique<HighlightAlbumNapiAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, result, "asyncContext context is null");

    CHECK_ARGS(env, MediaLibraryNapiUtils::ParseArgsNumberCallback(env, info, asyncContext,
        asyncContext->highlightUserActionType), JS_ERR_PARAMETER_INVALID);
    CHECK_NULLPTR_RET(MediaLibraryNapiUtils::GetInt32Arg(env, asyncContext->argv[1], asyncContext->actionData));

    auto photoAlbum = asyncContext->objectInfo->GetPhotoAlbumInstance();
    CHECK_COND_WITH_MESSAGE(env, photoAlbum != nullptr, "photoAlbum is null");
    CHECK_COND_WITH_MESSAGE(env,
        PhotoAlbum::IsHighlightAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType()),
        "Only and smart highlight album can set user action info");

    asyncContext->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSSetHighlightUserActionData",
        JSSetHighlightUserActionDataExecute, JSSetHighlightUserActionDataCompleteCallback);
}

napi_value HighlightAlbumNapi::JSGetHighlightResource(napi_env env, napi_callback_info info)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSGetHighlightResource");

    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_undefined(env, &result));
    unique_ptr<HighlightAlbumNapiAsyncContext> asyncContext = make_unique<HighlightAlbumNapiAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, result, "asyncContext context is null");

    CHECK_ARGS(env, MediaLibraryNapiUtils::ParseArgsStringCallback(env, info, asyncContext, asyncContext->resourceUri),
        JS_ERR_PARAMETER_INVALID);

    auto photoAlbum = asyncContext->objectInfo->GetPhotoAlbumInstance();
    CHECK_COND_WITH_MESSAGE(env, photoAlbum != nullptr, "photoAlbum is null");
    CHECK_COND_WITH_MESSAGE(env,
        PhotoAlbum::IsHighlightAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType()),
        "Only and smart highlight album can set user action info");

    asyncContext->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSGetHighlightResource",
        JSGetHighlightResourceExecute, JSGetHighlightResourceCompleteCallback);
}

shared_ptr<PhotoAlbum> HighlightAlbumNapi::GetPhotoAlbumInstance() const
{
    return highlightAlbumPtr;
}
} // namespace OHOS::Media