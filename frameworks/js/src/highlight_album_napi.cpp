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
#include "media_album_change_request_napi.h"
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
#include "vision_photo_map_column.h"
#include "highlight_column.h"
#include "album_operation_uri.h"

using namespace std;

namespace OHOS::Media {
static const string HIGHLIGHT_ALBUM_CLASS = "HighlightAlbum";
static const string ANALYSIS_ALBUM_CLASS = "AnalysisAlbum";
thread_local napi_ref HighlightAlbumNapi::constructor_ = nullptr;
thread_local napi_ref HighlightAlbumNapi::analysisAlbumConstructor_ = nullptr;

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
            DECLARE_NAPI_FUNCTION("getOrderPosition", JSGetOrderPosition),
            DECLARE_NAPI_FUNCTION("setSubTitle", JSSetHighlightSubtitle),
            DECLARE_NAPI_STATIC_FUNCTION("deleteHighlightAlbums", JSDeleteHighlightAlbums),
        } };
    MediaLibraryNapiUtils::NapiDefineClass(env, exports, info);
    return exports;
}

napi_value HighlightAlbumNapi::AnalysisAlbumInit(napi_env env, napi_value exports)
{
    NapiClassInfo info = {
        .name = ANALYSIS_ALBUM_CLASS,
        .ref = &analysisAlbumConstructor_,
        .constructor = Constructor,
        .props = {
            DECLARE_NAPI_FUNCTION("getOrderPosition", JSGetOrderPosition),
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
    { COVER_INFO, { PAH_QUERY_HIGHLIGHT_COVER, { ID, HIGHLIGHT_ALBUM_TABLE + "." + PhotoAlbumColumns::ALBUM_ID,
        AI_ALBUM_ID, SUB_TITLE, CLUSTER_TYPE, CLUSTER_SUB_TYPE,
        CLUSTER_CONDITION, MIN_DATE_ADDED, MAX_DATE_ADDED, GENERATE_TIME, HIGHLIGHT_VERSION,
        REMARKS, HIGHLIGHT_STATUS, RATIO, BACKGROUND, FOREGROUND, WORDART, IS_COVERED, COLOR,
        RADIUS, SATURATION, BRIGHTNESS, BACKGROUND_COLOR_TYPE, SHADOW_LEVEL, TITLE_SCALE_X,
        TITLE_SCALE_Y, TITLE_RECT_WIDTH, TITLE_RECT_HEIGHT, BACKGROUND_SCALE_X, BACKGROUND_SCALE_Y,
        BACKGROUND_RECT_WIDTH, BACKGROUND_RECT_HEIGHT, LAYOUT_INDEX, COVER_ALGO_VERSION, COVER_KEY, COVER_STATUS,
        HIGHLIGHT_IS_MUTED, HIGHLIGHT_IS_FAVORITE, HIGHLIGHT_THEME, HIGHLIGHT_PIN_TIME, HIGHLIGHT_USE_SUBTITLE } } },
    { PLAY_INFO, { PAH_QUERY_HIGHLIGHT_PLAY, { ID, HIGHLIGHT_ALBUM_TABLE + "." + PhotoAlbumColumns::ALBUM_ID,
        MUSIC, FILTER, HIGHLIGHT_PLAY_INFO, IS_CHOSEN, PLAY_INFO_VERSION, PLAY_INFO_ID } } },
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
    DataShare::DataSharePredicates predicates;
    if (HIGHLIGHT_ALBUM_INFO_MAP.find(context->highlightAlbumInfoType) != HIGHLIGHT_ALBUM_INFO_MAP.end()) {
        uriStr = HIGHLIGHT_ALBUM_INFO_MAP.at(context->highlightAlbumInfoType).uriStr;
        fetchColumn = HIGHLIGHT_ALBUM_INFO_MAP.at(context->highlightAlbumInfoType).fetchColumn;
        string tabStr;
        if (context->highlightAlbumInfoType == COVER_INFO) {
            tabStr = HIGHLIGHT_COVER_INFO_TABLE;
        } else {
            tabStr = HIGHLIGHT_PLAY_INFO_TABLE;
        }
        vector<string> onClause = {
            tabStr + "." + PhotoAlbumColumns::ALBUM_ID + " = " +
            HIGHLIGHT_ALBUM_TABLE + "." + ID
        };
        predicates.InnerJoin(HIGHLIGHT_ALBUM_TABLE)->On(onClause);
    } else {
        NAPI_ERR_LOG("Invalid highlightAlbumInfoType");
        return;
    }
    int32_t albumId = context->albumId;
    PhotoAlbumSubType subType = context->subType;
    Uri uri (uriStr);
    if (subType == PhotoAlbumSubType::HIGHLIGHT) {
        predicates.EqualTo(HIGHLIGHT_ALBUM_TABLE + "." + PhotoAlbumColumns::ALBUM_ID, to_string(albumId));
    } else if (subType == PhotoAlbumSubType::HIGHLIGHT_SUGGESTIONS) {
        predicates.EqualTo(HIGHLIGHT_ALBUM_TABLE + "." + AI_ALBUM_ID, to_string(albumId));
    } else {
        NAPI_ERR_LOG("Invalid highlight album subType");
        return;
    }
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

static void JSSetHighlightSubtitleExecute(napi_env env, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSSetHighlightSubtitleExecute");

    auto *context = static_cast<HighlightAlbumNapiAsyncContext*>(data);
    int albumId = context->objectInfo->GetPhotoAlbumInstance()->GetAlbumId();
    Uri uri(PAH_HIGHLIGHT_SUBTITLE);
    context->predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, to_string(albumId));
    context->valuesBucket.Put(SUB_TITLE, context->subtitle);
    int changedRows = UserFileClient::Update(uri, context->predicates, context->valuesBucket);
    if (changedRows < 0) {
        context->SaveError(changedRows);
        NAPI_ERR_LOG("Failed to set highlight subtitle, err: %{public}d", changedRows);
        return;
    }
}

static void JSSetHighlightSubtitleCompleteCallback(napi_env env, napi_status status, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSSetHighlightSubtitleCompleteCallback");

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
    off_t fileLen = lseek(uniqueFd.Get(), 0, SEEK_END);
    if (fileLen < 0) {
        NAPI_ERR_LOG("Failed to get highlight cover file length, error: %{public}d", errno);
        return;
    }
    off_t ret = lseek(uniqueFd.Get(), 0, SEEK_SET);
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

    ssize_t readBytes = read(uniqueFd.Get(), arrayBufferData, fileLen);
    if (readBytes != fileLen) {
        NAPI_ERR_LOG("read file failed, read bytes is %{public}zu,""actual length is %{public}" PRId64
            ",error: %{public}d", readBytes, fileLen, errno);
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

static void JSGetOrderPositionExecute(napi_env env, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSGetOrderPositionExecute");

    auto *context = static_cast<HighlightAlbumNapiAsyncContext *>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    // make fetch column
    std::vector<std::string> fetchColumn{MAP_ASSET, ORDER_POSITION};

    // make where predicates
    DataShare::DataSharePredicates predicates;
    const std::vector<std::string> &assetIdArray = context->assetIdArray;
    CHECK_NULL_PTR_RETURN_VOID(context->objectInfo, "objectInfo is null");
    auto photoAlbum = context->objectInfo->GetPhotoAlbumInstance();
    CHECK_NULL_PTR_RETURN_VOID(photoAlbum, "photoAlbum is null");
    int albumId = photoAlbum->GetAlbumId();
    const string mapTable = ANALYSIS_PHOTO_MAP_TABLE;
    predicates.EqualTo(mapTable + "." + MAP_ALBUM, albumId)->And()->In(mapTable + "." + MAP_ASSET, assetIdArray);

    // start query, deal with result
    Uri uri(PAH_QUERY_ORDER_ANA_ALBUM);
    int errCode = 0;
    auto resultSet = UserFileClient::Query(uri, predicates, fetchColumn, errCode);
    if (resultSet == nullptr) {
        NAPI_ERR_LOG("Query failed, error code: %{public}d", errCode);
        context->error = JS_INNER_FAIL;
        return;
    }
    int count = 0;
    int ret = resultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK || count <= 0) {
        NAPI_ERR_LOG("GetRowCount failed, error code: %{public}d, count: %{public}d", ret, count);
        context->error = JS_INNER_FAIL;
        return;
    }
    unordered_map<std::string, int32_t> idOrderMap;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t mapAsset = get<int32_t>(ResultSetUtils::GetValFromColumn(MAP_ASSET, resultSet, TYPE_INT32));
        int32_t orderPosition = get<int32_t>(ResultSetUtils::GetValFromColumn(ORDER_POSITION, resultSet, TYPE_INT32));
        idOrderMap[std::to_string(mapAsset)] = orderPosition;
    }
    context->orderPositionArray.clear();
    for (string& assetId : context->assetIdArray) {
        context->orderPositionArray.push_back(idOrderMap[assetId]);
    }
    NAPI_INFO_LOG("GetOrderPosition: result size: %{public}d, orderPositionArray size: %{public}d",
                  count,
                  static_cast<int>(context->orderPositionArray.size())
                  );
}

static void JSGetOrderPositionCompleteCallback(napi_env env, napi_status status, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSGetOrderPositionCompleteCallback");

    auto *context = static_cast<HighlightAlbumNapiAsyncContext *>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    CHECK_ARGS_RET_VOID(env, napi_get_undefined(env, &jsContext->data), JS_INNER_FAIL);
    CHECK_ARGS_RET_VOID(env, napi_get_undefined(env, &jsContext->error), JS_INNER_FAIL);

    size_t positionSize = context->orderPositionArray.size();
    size_t assetSize = context->assetIdArray.size();
    if (positionSize != assetSize) {
        NAPI_ERR_LOG("GetOrderPosition failed, position size: %{public}d, asset size: %{public}d",
                     static_cast<int>(positionSize), static_cast<int>(assetSize));
        context->HandleError(env, jsContext->error);
        napi_get_undefined(env, &jsContext->data);
    } else {
        napi_value jsArray = nullptr;
        napi_create_array_with_length(env, positionSize, &jsArray);
        for (size_t i = 0; i < positionSize; i++) {
            napi_value element;
            napi_create_int32(env, context->orderPositionArray[i], &element);
            napi_set_element(env, jsArray, i, element);
        }
        jsContext->data = jsArray;
        napi_get_undefined(env, &jsContext->error);
        jsContext->status = true;
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred,
                                                   context->callbackRef, context->work, *jsContext);
    }
    delete context;
}

napi_value HighlightAlbumNapi::JSGetOrderPosition(napi_env env, napi_callback_info info)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSGetOrderPosition");

    // make undefined
    napi_value undefinedObject = nullptr;
    NAPI_CALL(env, napi_get_undefined(env, &undefinedObject));

    // make async context, if error then return undefined
    unique_ptr<HighlightAlbumNapiAsyncContext> asyncContext = make_unique<HighlightAlbumNapiAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, undefinedObject, "asyncContext context is null");
    CHECK_COND_WITH_MESSAGE(env,
        MediaLibraryNapiUtils::AsyncContextSetObjectInfo(env, info, asyncContext, ARGS_ONE, ARGS_ONE) == napi_ok,
        "Failed to get object info");

    // get this album, check it is an analysis album
    auto photoAlbum = asyncContext->objectInfo->GetPhotoAlbumInstance();
    CHECK_COND_WITH_MESSAGE(env, photoAlbum != nullptr, "Failed to get photo album instance");
    CHECK_COND_WITH_MESSAGE(env,
        PhotoAlbum::IsAnalysisAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType()),
        "Only analysis album can get asset order positions");

    // get assets, check duplicated
    vector<string> assetIdArray;
    CHECK_COND_WITH_MESSAGE(env,
        MediaLibraryNapiUtils::ParseAssetIdArray(env, asyncContext->argv[PARAM0], assetIdArray),
        "Failed to parse assets");
    NAPI_INFO_LOG("GetOrderPosition: get assets id size: %{public}d", static_cast<int>(assetIdArray.size()));
    CHECK_COND_WITH_MESSAGE(
        env, assetIdArray.size() > 0, "The getOrderPosition operation needs at least one asset id");
    std::set<std::string> idSet(assetIdArray.begin(), assetIdArray.end());
    CHECK_COND_WITH_MESSAGE(
        env, assetIdArray.size() == idSet.size(), "The getOrderPosition operation has same assets");
    asyncContext->assetIdArray = std::move(assetIdArray);

    // make async task
    asyncContext->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    return MediaLibraryNapiUtils::NapiCreateAsyncWork(
        env, asyncContext, "JSGetOrderPosition", JSGetOrderPositionExecute, JSGetOrderPositionCompleteCallback);
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

    asyncContext->albumId = photoAlbum->GetAlbumId();
    asyncContext->subType = photoAlbum->GetPhotoAlbumSubType();
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

napi_value HighlightAlbumNapi::JSSetHighlightSubtitle(napi_env env, napi_callback_info info)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSSetHighlightSubtitle");

    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_undefined(env, &result));
    unique_ptr<HighlightAlbumNapiAsyncContext> asyncContext = make_unique<HighlightAlbumNapiAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, result, "asyncContext context is null");
    CHECK_ARGS(env, MediaLibraryNapiUtils::ParseArgsStringCallback(env, info, asyncContext, asyncContext->subtitle),
        OHOS_INVALID_PARAM_CODE);

    CHECK_COND_WITH_MESSAGE(env, MediaFileUtils::CheckHighlightSubtitle(asyncContext->subtitle) == E_OK,
        "Invalid highlight subtitle");
    auto photoAlbum = asyncContext->objectInfo->GetPhotoAlbumInstance();
    CHECK_COND_WITH_MESSAGE(env, photoAlbum != nullptr, "photoAlbum is null");
    CHECK_COND_WITH_MESSAGE(env,
        PhotoAlbum::IsHighlightAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType()),
        "Only highlight album can set highlight sub title");
    
    asyncContext->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSSetHighlightSubtitle",
        JSSetHighlightSubtitleExecute, JSSetHighlightSubtitleCompleteCallback);
}

static void DeleteHighlightAlbumsCompleteCallback(napi_env env, napi_status status, void* data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSDeleteHighlightAlbumsCompleteCallback");
    int32_t deleteAlbumFailed = 1;
    auto* context = static_cast<MediaAlbumChangeRequestAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    auto jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    napi_get_undefined(env, &jsContext->data);
    napi_get_undefined(env, &jsContext->error);
    if (context->error == ERR_DEFAULT) {
        napi_create_int32(env, E_SUCCESS, &jsContext->data);
        jsContext->status = true;
    } else {
        napi_create_int32(env, deleteAlbumFailed, &jsContext->data);
        context->HandleError(env, jsContext->error);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(
            env, context->deferred, context->callbackRef, context->work, *jsContext);
    }
    delete context;
}

static void DeleteHighlightAlbumsExecute(napi_env env, void* data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSDeleteHighlightAlbumsExecute");
    NAPI_INFO_LOG("Start delete highlight album(s)");

    auto* context = static_cast<MediaAlbumChangeRequestAsyncContext*>(data);
    Uri deleteAlbumUri(PAH_DELETE_HIGHLIGHT_ALBUM);
    int ret = UserFileClient::Delete(deleteAlbumUri, context->predicates);
    if (ret < 0) {
        context->SaveError(ret);
        NAPI_ERR_LOG("Failed to delete highlight albums, err: %{public}d", ret);
        return;
    }
    NAPI_INFO_LOG("Delete highlight album(s): %{public}d", ret);
}

static napi_value ParseArgsDeleteHighlightAlbums(
    napi_env env, napi_callback_info info, unique_ptr<MediaAlbumChangeRequestAsyncContext>& context)
{
    if (!MediaLibraryNapiUtils::IsSystemApp()) {
        NapiError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return nullptr;
    }
 
    constexpr size_t minArgs = ARGS_TWO;
    constexpr size_t maxArgs = ARGS_THREE;
    CHECK_COND_WITH_MESSAGE(env,
        MediaLibraryNapiUtils::AsyncContextGetArgs(env, info, context, minArgs, maxArgs) == napi_ok,
        "Failed to get args");
    CHECK_COND(env, MediaAlbumChangeRequestNapi::InitUserFileClient(env, info), JS_INNER_FAIL);
 
    vector<napi_value> napiValues;
    napi_valuetype valueType = napi_undefined;
    CHECK_NULLPTR_RET(MediaLibraryNapiUtils::GetNapiValueArray(env, context->argv[PARAM1], napiValues));
    CHECK_COND_WITH_MESSAGE(env, !napiValues.empty(), "array is empty");
    CHECK_ARGS(env, napi_typeof(env, napiValues.front(), &valueType), JS_INNER_FAIL);
    CHECK_COND_WITH_MESSAGE(env, valueType == napi_object, "Invalid argument type");
 
    vector<string> deleteIds;
    for (const auto& napiValue : napiValues) {
        PhotoAlbumNapi* obj = nullptr;
        CHECK_ARGS(env, napi_unwrap(env, napiValue, reinterpret_cast<void**>(&obj)), JS_INNER_FAIL);
        CHECK_COND_WITH_MESSAGE(env, obj != nullptr, "Failed to get album napi object");
        CHECK_COND_WITH_MESSAGE(env,
            PhotoAlbum::IsHighlightAlbum(obj->GetPhotoAlbumType(), obj->GetPhotoAlbumSubType()),
            "Only highlight album can be deleted");
        deleteIds.push_back(to_string(obj->GetAlbumId()));
    }
    context->predicates.In(PhotoAlbumColumns::ALBUM_ID, deleteIds);
    RETURN_NAPI_TRUE(env);
}

napi_value HighlightAlbumNapi::JSDeleteHighlightAlbums(napi_env env, napi_callback_info info)
{
    auto asyncContext = make_unique<MediaAlbumChangeRequestAsyncContext>();
    CHECK_COND_WITH_MESSAGE(env, ParseArgsDeleteHighlightAlbums(env, info, asyncContext),
        "Failed to parse highlight args");
    return MediaLibraryNapiUtils::NapiCreateAsyncWork(
        env, asyncContext, "ChangeRequestDeleteHighlightAlbums",
        DeleteHighlightAlbumsExecute, DeleteHighlightAlbumsCompleteCallback);
}

shared_ptr<PhotoAlbum> HighlightAlbumNapi::GetPhotoAlbumInstance() const
{
    return highlightAlbumPtr;
}
} // namespace OHOS::Media