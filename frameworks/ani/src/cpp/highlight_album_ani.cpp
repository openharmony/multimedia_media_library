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

#include "highlight_album_ani.h"
#include <unordered_map>
#include <unordered_set>

#include "ani_class_name.h"
#include "file_asset_ani.h"
#include "media_album_change_request_ani.h"
#include "media_file_utils.h"
#include "media_library_enum_ani.h"
#include "medialibrary_ani_utils.h"
#include "medialibrary_tracer.h"
#include "photo_album_ani.h"
#include "photo_map_column.h"
#include "result_set_utils.h"
#include "story_album_column.h"
#include "story_cover_info_column.h"
#include "story_play_info_column.h"
#include "user_photography_info_column.h"
#include "userfile_client.h"
#include "vision_column.h"
#include "album_operation_uri.h"
#include "highlight_column.h"

namespace OHOS::Media {
namespace {
static const std::string MAP_ALBUM = "map_album";
static const std::string MAP_ASSET = "map_asset";
static const std::string ORDER_POSITION = "order_position";
}
static const map<int32_t, struct HighlightAlbumInfo> HIGHLIGHT_ALBUM_INFO_MAP = {
    { COVER_INFO, { PAH_QUERY_HIGHLIGHT_COVER, { ID, HIGHLIGHT_ALBUM_TABLE + "." + PhotoAlbumColumns::ALBUM_ID,
        AI_ALBUM_ID, SUB_TITLE, CLUSTER_TYPE, CLUSTER_SUB_TYPE,
        CLUSTER_CONDITION, MIN_DATE_ADDED, MAX_DATE_ADDED, GENERATE_TIME, HIGHLIGHT_VERSION,
        REMARKS, HIGHLIGHT_STATUS, RATIO, BACKGROUND, FOREGROUND, WORDART, IS_COVERED, COLOR,
        RADIUS, SATURATION, BRIGHTNESS, BACKGROUND_COLOR_TYPE, SHADOW_LEVEL, TITLE_SCALE_X,
        TITLE_SCALE_Y, TITLE_RECT_WIDTH, TITLE_RECT_HEIGHT, BACKGROUND_SCALE_X, BACKGROUND_SCALE_Y,
        BACKGROUND_RECT_WIDTH, BACKGROUND_RECT_HEIGHT, LAYOUT_INDEX, COVER_ALGO_VERSION, COVER_KEY,
        HIGHLIGHT_IS_MUTED, HIGHLIGHT_IS_FAVORITE, HIGHLIGHT_THEME } } },
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

HighlightAlbumAni::HighlightAlbumAni() : highlightEnv_(nullptr) {}

HighlightAlbumAni::~HighlightAlbumAni() = default;

ani_status HighlightAlbumAni::Init(ani_env *env)
{
    CHECK_COND_RET(env != nullptr, ANI_INVALID_ARGS, "env is null");
    ani_class cls;
    if (ANI_OK != env->FindClass(PAH_ANI_CLASS_HIGHLIGHT_ALBUM.c_str(), &cls)) {
        ANI_ERR_LOG("Failed to find class: %{public}s", PAH_ANI_CLASS_HIGHLIGHT_ALBUM.c_str());
        return ANI_ERROR;
    }

    std::array methods = {
        ani_native_function {"nativeConstructor", nullptr, reinterpret_cast<void *>(Constructor)},
        ani_native_function {"getHighlightAlbumInfoInner", nullptr, reinterpret_cast<void *>(GetHighlightAlbumInfo)},
        ani_native_function {"getHighlightResourceInner", nullptr, reinterpret_cast<void *>(GetHighlightResource)},
        ani_native_function {"setHighlightUserActionDataInner", nullptr,
            reinterpret_cast<void *>(SetHighlightUserActionData)},
        ani_native_function {"setSubTitleInner", nullptr, reinterpret_cast<void *>(SetSubTitle)},
        ani_native_function {"deleteHighlightAlbumsInner", nullptr, reinterpret_cast<void *>(DeleteHighlightAlbums)},
    };

    if (ANI_OK != env->Class_BindNativeMethods(cls, methods.data(), methods.size())) {
        ANI_ERR_LOG("Failed to bind native methods to: %{public}s", PAH_ANI_CLASS_HIGHLIGHT_ALBUM.c_str());
        return ANI_ERROR;
    }
    return ANI_OK;
}

ani_status HighlightAlbumAni::AnalysisAlbumInit(ani_env *env)
{
    CHECK_COND_RET(env != nullptr, ANI_INVALID_ARGS, "env is null");
    static const char *className = PAH_ANI_CLASS_ANALYSIS_ALBUM.c_str();
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        ANI_ERR_LOG("Failed to find class: %{public}s", className);
        return ANI_ERROR;
    }

    std::array methods = {
        ani_native_function {"nativeConstructor", nullptr, reinterpret_cast<void *>(Constructor)},
        ani_native_function {"getOrderPositionInner", nullptr, reinterpret_cast<void *>(GetOrderPosition)}
    };

    if (ANI_OK != env->Class_BindNativeMethods(cls, methods.data(), methods.size())) {
        ANI_ERR_LOG("Failed to bind native methods to: %{public}s", PAH_ANI_CLASS_HIGHLIGHT_ALBUM.c_str());
        return ANI_ERROR;
    }
    return ANI_OK;
}

HighlightAlbumAni* HighlightAlbumAni::Unwrap(ani_env *env, ani_object object)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is null");
    ani_long photoAlbum {};
    if (ANI_OK != env->Object_GetFieldByName_Long(object, "nativePhotoAlbum", &photoAlbum)) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return nullptr;
    }
    return reinterpret_cast<HighlightAlbumAni*>(photoAlbum);
}

std::shared_ptr<PhotoAlbum> HighlightAlbumAni::GetPhotoAlbumInstance() const
{
    return highlightAlbumPtr;
}

ani_long HighlightAlbumAni::Constructor(ani_env *env, [[maybe_unused]] ani_object object, ani_object aniAlbum)
{
    CHECK_COND_RET(env != nullptr, ANI_INVALID_ARGS, "env is null");
    PhotoAlbumAni* photoAlbumAni = PhotoAlbumAni::UnwrapPhotoAlbumObject(env, aniAlbum);
    CHECK_COND_RET(photoAlbumAni != nullptr, 0, "Failed to get PhotoAlbumAni object");

    auto photoAlbumPtr = photoAlbumAni->GetPhotoAlbumInstance();
    CHECK_COND_RET(photoAlbumPtr != nullptr, 0, "photoAlbum is null");
    bool isSupportType = photoAlbumPtr->GetResultNapiType() == ResultNapiType::TYPE_PHOTOACCESS_HELPER &&
        PhotoAlbum::CheckPhotoAlbumType(photoAlbumPtr->GetPhotoAlbumType()) &&
        PhotoAlbum::CheckPhotoAlbumSubType(photoAlbumPtr->GetPhotoAlbumSubType());
    CHECK_COND_RET(isSupportType, 0, "Unsupported type of photoAlbum");

    unique_ptr<HighlightAlbumAni> highlightAlbum = make_unique<HighlightAlbumAni>();
    CHECK_COND_RET(highlightAlbum != nullptr, 0, "Failed to new HighlightAlbumAni");
    highlightAlbum->highlightAlbumPtr = photoAlbumPtr;
    highlightAlbum->highlightEnv_ = env;
    return reinterpret_cast<ani_long>(highlightAlbum.release());
}

void HighlightAlbumAni::Destructor(ani_env *env, ani_object object)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is nullptr");
    HighlightAlbumAni *highlightAlbum = Unwrap(env, object);
    if (highlightAlbum == nullptr) {
        return;
    }
    highlightAlbum->highlightEnv_ = nullptr;
    delete highlightAlbum;
}

static void GetHighlightAlbumInfoExecute(ani_env *env, unique_ptr<HighlightAlbumAniContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is nullptr");
    CHECK_NULL_PTR_RETURN_VOID(context, "context is nullptr");
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
        ANI_ERR_LOG("Invalid highlightAlbumInfoType");
        return;
    }
    int32_t albumId = context->albumId;
    PhotoAlbumSubType subType = context->subType;
    Uri uri(uriStr);
    if (subType == PhotoAlbumSubType::HIGHLIGHT) {
        predicates.EqualTo(HIGHLIGHT_ALBUM_TABLE + "." + PhotoAlbumColumns::ALBUM_ID, to_string(albumId));
    } else if (subType == PhotoAlbumSubType::HIGHLIGHT_SUGGESTIONS) {
        predicates.EqualTo(HIGHLIGHT_ALBUM_TABLE + "." + AI_ALBUM_ID, to_string(albumId));
    } else {
        ANI_ERR_LOG("Invalid highlight album subType");
        context->error = JS_ERR_PARAMETER_INVALID;
        return;
    }
    int errCode = 0;
    auto resultSet = UserFileClient::Query(uri, predicates, fetchColumn, errCode);
    if (resultSet != nullptr) {
        context->highlightAlbumInfo = MediaLibraryAniUtils::ParseResultSet2JsonStr(resultSet, fetchColumn);
    }
}

static ani_string GetHighlightAlbumInfoComplete(ani_env *env, unique_ptr<HighlightAlbumAniContext> &context)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is null");
    CHECK_COND_RET(context != nullptr, nullptr, "context is null");
    ani_string result {};
    ani_object errorObj {};
    if (context->error != ERR_DEFAULT) {
        context->HandleError(env, errorObj);
    } else {
        CHECK_COND_RET(MediaLibraryAniUtils::ToAniString(env, context->highlightAlbumInfo, result) == ANI_OK,
            nullptr, "ToAniString highlightAlbumInfo fail");
    }
    context.reset();
    return result;
}

ani_string HighlightAlbumAni::GetHighlightAlbumInfo(ani_env *env, ani_object object, ani_enum_item type)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is null");
    MediaLibraryTracer tracer;
    tracer.Start("GetHighlightAlbumInfo");

    unique_ptr<HighlightAlbumAniContext> context = make_unique<HighlightAlbumAniContext>();
    CHECK_COND_RET(context != nullptr, nullptr, "context is null");
    context->objectInfo = Unwrap(env, object);
    if (context->objectInfo == nullptr) {
        ANI_ERR_LOG("Unwrap HighlightAlbumAni fail");
        return nullptr;
    }

    if (MediaLibraryEnumAni::EnumGetValueInt32(env, type, context->highlightAlbumInfoType) != ANI_OK) {
        ANI_ERR_LOG("Parse highlightAlbumInfoType fail");
        return nullptr;
    }

    auto photoAlbum = context->objectInfo->GetPhotoAlbumInstance();
    CHECK_COND_RET(photoAlbum != nullptr, nullptr, "photoAlbum is null");
    if (!PhotoAlbum::IsHighlightAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType())) {
        ANI_ERR_LOG("Only and smart highlight album can get highlight album info");
        return nullptr;
    }

    context->albumId = photoAlbum->GetAlbumId();
    context->subType = photoAlbum->GetPhotoAlbumSubType();
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    GetHighlightAlbumInfoExecute(env, context);
    return GetHighlightAlbumInfoComplete(env, context);
}

static int32_t GetFdForArrayBuffer(std::string uriStr)
{
    int32_t fd = 0;
    Uri uri(uriStr);
    fd = UserFileClient::OpenFile(uri, MEDIA_FILEMODE_READONLY);
    if (fd == E_ERR) {
        ANI_ERR_LOG("Open highlight cover file failed, error: %{public}d", errno);
        return E_HAS_FS_ERROR;
    } else if (fd < 0) {
        ANI_ERR_LOG("Open highlight cover file failed due to OpenFile failure");
        return fd;
    }
    return fd;
}

static void GetHighlightResourceExecute(ani_env *env, unique_ptr<HighlightAlbumAniContext> &context)
{
    MediaLibraryTracer tracer;
    tracer.Start("GetHighlightResourceExecute");
    CHECK_NULL_PTR_RETURN_VOID(context, "context is nullptr");
    if (context->resourceUri.find(MEDIA_DATA_DB_HIGHLIGHT) == string::npos) {
        ANI_ERR_LOG("Invalid highlight resource uri");
        return;
    }
    int32_t fd = GetFdForArrayBuffer(context->resourceUri);
    if (fd < 0) {
        return;
    }
    UniqueFd uniqueFd(fd);
    off_t fileLen = lseek(uniqueFd.Get(), 0, SEEK_END);
    if (fileLen < 0) {
        ANI_ERR_LOG("Failed to get highlight cover file length, error: %{public}d", errno);
        return;
    }
    off_t ret = lseek(uniqueFd.Get(), 0, SEEK_SET);
    if (ret < 0) {
        ANI_ERR_LOG("Failed to reset highlight cover file offset, error: %{public}d", errno);
        return;
    }
    void* arrayBufferData = nullptr;
    ani_arraybuffer arrayBuffer = {};

    if (env->CreateArrayBuffer(fileLen, &arrayBufferData, &arrayBuffer) != ANI_OK) {
        ANI_ERR_LOG("Create array buffer fail");
        return;
    }
    ssize_t readBytes = read(uniqueFd.Get(), arrayBufferData, fileLen);
    if (readBytes != fileLen) {
        ANI_ERR_LOG("read file failed, read bytes is %{public}zu,""actual length is %{public}" PRId64
            ",error: %{public}d", readBytes, fileLen, errno);
        return;
    }
    context->aniArrayBuffer = arrayBuffer;
}

static ani_arraybuffer GetHighlightResourceCompleteCallback(ani_env *env,
    unique_ptr<HighlightAlbumAniContext> &context)
{
    ani_arraybuffer result {};
    ani_object errorObj {};
    CHECK_COND_RET(context != nullptr, result, "context is null");
    if (context->error != ERR_DEFAULT) {
        context->HandleError(env, errorObj);
    } else {
        result = context->aniArrayBuffer;
    }
    context.reset();
    return result;
}

ani_object HighlightAlbumAni::GetHighlightResource(ani_env *env, ani_object object, ani_string resourceUri)
{
    MediaLibraryTracer tracer;
    tracer.Start("GetHighlightResource");

    unique_ptr<HighlightAlbumAniContext> context = make_unique<HighlightAlbumAniContext>();
    CHECK_COND_RET(context != nullptr, nullptr, "context is null");
    context->objectInfo = Unwrap(env, object);
    if (context->objectInfo == nullptr) {
        ANI_ERR_LOG("Unwrap HighlightAlbumAni fail");
        return nullptr;
    }
    std::string resourceUriStr("");
    auto ret = MediaLibraryAniUtils::GetString(env, resourceUri, resourceUriStr);
    CHECK_COND_WITH_RET_MESSAGE(env, ret == ANI_OK, nullptr, "get resourceUriStr failed");
    context->resourceUri = resourceUriStr;

    auto photoAlbum = context->objectInfo->GetPhotoAlbumInstance();
    CHECK_COND_RET(photoAlbum != nullptr, nullptr, "photoAlbum is null");
    if (!PhotoAlbum::IsHighlightAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType())) {
        ANI_ERR_LOG("Only and smart highlight album can get highlight resource");
        return nullptr;
    }
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    GetHighlightResourceExecute(env, context);
    return GetHighlightResourceCompleteCallback(env, context);
}

static void SetHighlightUserActionDataExecute(ani_env *env, unique_ptr<HighlightAlbumAniContext> &context)
{
    MediaLibraryTracer tracer;
    tracer.Start("SetHighlightUserActionDataExecute");
    CHECK_NULL_PTR_RETURN_VOID(context, "context is nullptr");
    string userActionType("");
    if (HIGHLIGHT_USER_ACTION_MAP.find(context->highlightUserActionType) != HIGHLIGHT_USER_ACTION_MAP.end()) {
        userActionType = HIGHLIGHT_USER_ACTION_MAP.at(context->highlightUserActionType);
        context->fetchColumn.push_back(userActionType);
    } else {
        ANI_ERR_LOG("Invalid highlightUserActionType");
        return;
    }
    CHECK_NULL_PTR_RETURN_VOID(context->objectInfo, "context->objectInfo is nullptr");
    CHECK_NULL_PTR_RETURN_VOID(context->objectInfo->GetPhotoAlbumInstance(), "GetPhotoAlbumInstance is nullptr");
    int albumId = context->objectInfo->GetPhotoAlbumInstance()->GetAlbumId();
    Uri uri(URI_HIGHLIGHT_ALBUM);
    context->predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, to_string(albumId));
    int errCode = 0;
    auto resultSet = UserFileClient::Query(uri, context->predicates, context->fetchColumn, errCode);
    if (resultSet != nullptr) {
        auto count = 0;
        auto ret = resultSet->GetRowCount(count);
        if (ret != NativeRdb::E_OK || count == 0 || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
            ANI_ERR_LOG("highlight user action data get rdbstore failed");
            context->error = JS_INNER_FAIL;
            return;
        }
        int64_t userActionDataCount = get<int64_t>(ResultSetUtils::GetValFromColumn(userActionType,
            resultSet, TYPE_INT64));
        context->valuesBucket.Put(userActionType, to_string(userActionDataCount + context->actionData));
        int changedRows = UserFileClient::Update(uri, context->predicates, context->valuesBucket);
        if (changedRows < 0) {
            context->SaveError(changedRows);
        }
        context->changedRows = changedRows;
    } else {
        ANI_ERR_LOG("highlight user action data get rdbstore failed");
        context->error = JS_INNER_FAIL;
        return;
    }
}

static ani_status SetHighlightUserActionDataCompleteCallback(ani_env *env,
    unique_ptr<HighlightAlbumAniContext> &context)
{
    CHECK_COND_RET(env != nullptr, ANI_INVALID_ARGS, "env is null");
    CHECK_COND_WITH_RET_MESSAGE(env, context != nullptr, ANI_INVALID_ARGS, "context is nullptr");
    ani_status result {};
    ani_object errorObj {};
    if (context->error != ERR_DEFAULT) {
        context->HandleError(env, errorObj);
        result = ANI_ERROR;
    }
    context.reset();
    return result;
}

ani_status HighlightAlbumAni::SetHighlightUserActionData(ani_env *env, ani_object object,
    ani_enum_item type, ani_int actionDataAni)
{
    MediaLibraryTracer tracer;
    tracer.Start("SetHighlightUserActionData");
    unique_ptr<HighlightAlbumAniContext> context = make_unique<HighlightAlbumAniContext>();
    CHECK_COND_RET(context != nullptr, ANI_ERROR, "context is null");
    context->objectInfo = Unwrap(env, object);
    if (context->objectInfo == nullptr) {
        ANI_ERR_LOG("Unwrap HighlightAlbumAni fail");
        return ANI_ERROR;
    }
    int32_t actionData = 0;
    auto ret = MediaLibraryAniUtils::GetInt32(env, actionDataAni, actionData);
    CHECK_COND_WITH_RET_MESSAGE(env, ret == ANI_OK, ANI_ERROR, "get actionData failed");
    context->actionData = actionData;
    int32_t typeInt = 0;
    CHECK_COND_WITH_RET_MESSAGE(env, MediaLibraryEnumAni::EnumGetValueInt32(env, type, typeInt)== ANI_OK,
        ANI_ERROR, "Failed to get photoType");
    context->highlightUserActionType = typeInt;
    auto photoAlbum = context->objectInfo->GetPhotoAlbumInstance();
    CHECK_COND_RET(photoAlbum != nullptr, ANI_ERROR, "photoAlbum is null");
    if (!PhotoAlbum::IsHighlightAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType())) {
        ANI_ERR_LOG("Only and smart highlight album can set highlight user action data");
        return ANI_ERROR;
    }
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;

    SetHighlightUserActionDataExecute(env, context);
    return SetHighlightUserActionDataCompleteCallback(env, context);
}

static ani_object GetOrderPositionComplete(ani_env *env, std::unique_ptr<HighlightAlbumAniContext> &context)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is null");
    CHECK_COND_RET(context != nullptr, nullptr, "objectInfo is null");
    ani_object result {};
    ani_object errorObj {};
    auto cond = context->orderPositionArray.size() == context->assetIdArray.size();
    if (context->error != ERR_DEFAULT || !cond) {
        ANI_ERR_LOG("GetOrderPosition failed, error code: %{public}d, orderPositionArray size: %{public}zu",
            context->error, context->orderPositionArray.size());
        context->HandleError(env, errorObj);
    } else {
        if (MediaLibraryAniUtils::ToAniNumberArray(env, context->orderPositionArray, result) != ANI_OK) {
            ANI_ERR_LOG("ToAniInt32Array orderPositionArray fail");
        }
    }
    context.reset();
    return result;
}

static void GetOrderPositionExecute(std::unique_ptr<HighlightAlbumAniContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    CHECK_NULL_PTR_RETURN_VOID(context->objectInfo, "objectInfo is null");
    // make fetch column
    std::vector<std::string> fetchColumn{MAP_ASSET, ORDER_POSITION};
    // make where predicates
    DataShare::DataSharePredicates predicates;
    const std::vector<std::string> &assetIdArray = context->assetIdArray;
    auto photoAlbum = context->objectInfo->GetPhotoAlbumInstance();
    CHECK_NULL_PTR_RETURN_VOID(photoAlbum, "photoAlbum is null");

    auto albumId = photoAlbum->GetAlbumId();
    const std::string mapTable = ANALYSIS_PHOTO_MAP_TABLE;
    predicates.EqualTo(mapTable + "." + MAP_ALBUM, albumId)->And()->In(mapTable + "." + MAP_ASSET, assetIdArray);

    // start query, deal with result
    Uri uri(PAH_QUERY_ORDER_ANA_ALBUM);
    int errCode = 0;
    auto resultSet = UserFileClient::Query(uri, predicates, fetchColumn, errCode);
    if (resultSet == nullptr) {
        ANI_ERR_LOG("Query failed, error code: %{public}d", errCode);
        context->error = JS_INNER_FAIL;
        return;
    }
    int count = 0;
    int ret = resultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK || count <= 0) {
        ANI_ERR_LOG("GetRowCount failed, error code: %{public}d, count: %{public}d", ret, count);
        context->error = JS_INNER_FAIL;
        return;
    }

    std::unordered_map<std::string, int32_t> idOrderMap;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t mapAsset = get<int32_t>(ResultSetUtils::GetValFromColumn(MAP_ASSET, resultSet, TYPE_INT32));
        int32_t orderPosition = get<int32_t>(ResultSetUtils::GetValFromColumn(ORDER_POSITION, resultSet, TYPE_INT32));
        idOrderMap[std::to_string(mapAsset)] = orderPosition;
    }
    context->orderPositionArray.clear();
    for (std::string& assetId : context->assetIdArray) {
        context->orderPositionArray.emplace_back(idOrderMap[assetId]);
    }
    ANI_INFO_LOG("GetOrderPosition: result size: %{public}d, orderPositionArray size: %{public}d", count,
        static_cast<int>(context->orderPositionArray.size()));
}

ani_object HighlightAlbumAni::GetOrderPosition(ani_env *env, ani_object object, ani_object photoAssets)
{
    MediaLibraryTracer tracer;
    tracer.Start("GetOrderPosition");

    ANI_DEBUG_LOG("%{public}s is called", __func__);
    CHECK_COND_RET(env != nullptr, nullptr, "env is null");
    std::unique_ptr<HighlightAlbumAniContext> context = std::make_unique<HighlightAlbumAniContext>();
    CHECK_COND_WITH_MESSAGE(env, context != nullptr, "context is null");
    context->objectInfo = Unwrap(env, object);
    CHECK_COND_WITH_MESSAGE(env, context->objectInfo != nullptr, "objectInfo is null");

    auto photoAlbum = context->objectInfo->GetPhotoAlbumInstance();
    CHECK_COND_WITH_MESSAGE(env, photoAlbum != nullptr, "photoAlbum is null");
    auto cond = PhotoAlbum::IsHighlightAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType());
    CHECK_COND_WITH_MESSAGE(env, cond, "Only analysis album can get asset order positions");

    // get assets, check duplicated
    std::vector<std::string> assetIdArray;
    auto ret = MediaLibraryAniUtils::ParseAssetIdArray(env, photoAssets, assetIdArray);
    CHECK_COND_WITH_MESSAGE(env, ret == ANI_OK, "Failed to parse assets");
    ANI_INFO_LOG("GetOrderPosition assetIdArray size: %{public}zu", assetIdArray.size());
    CHECK_COND_WITH_MESSAGE(env, !assetIdArray.empty(), "assetIdArray is empty");

    std::set<std::string> idSet(assetIdArray.begin(), assetIdArray.end());
    CHECK_COND_WITH_MESSAGE(env, idSet.size() == assetIdArray.size(), "assetIdArray has duplicated elements");
    context->assetIdArray = std::move(assetIdArray);
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;

    GetOrderPositionExecute(context);
    return GetOrderPositionComplete(env, context);
}

static ani_status SetHighlightSubtitleComplete(ani_env *env, std::unique_ptr<HighlightAlbumAniContext> &context)
{
    CHECK_COND_RET(context != nullptr, ANI_INVALID_ARGS, "context is null");
    MediaLibraryTracer tracer;
    tracer.Start("JSSetHighlightSubtitleCompleteCallback");

    CHECK_COND_RET(env != nullptr, ANI_INVALID_ARGS, "env is null");
    CHECK_COND_WITH_RET_MESSAGE(env, context != nullptr, ANI_INVALID_ARGS, "context is nullptr");
    ani_status result {};
    ani_object errorObj {};
    if (context->error != ERR_DEFAULT) {
        ANI_ERR_LOG("GetOrderPosition failed, error code: %{public}d", context->error);
        context->HandleError(env, errorObj);
        result = ANI_ERROR;
    }
    context.reset();
    return result;
}

static void SetHighlightSubtitleExecute(std::unique_ptr<HighlightAlbumAniContext> &context)
{
    MediaLibraryTracer tracer;
    tracer.Start("SetHighlightSubtitleExecute");

    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    if (context->objectInfo == nullptr || context->objectInfo->GetPhotoAlbumInstance() == nullptr) {
        ANI_ERR_LOG("objectInfo is null");
        context->SaveError(ANI_INVALID_ARGS);
        return;
    }

    auto albumId = context->objectInfo->GetPhotoAlbumInstance()->GetAlbumId();
    Uri uri(PAH_HIGHLIGHT_SUBTITLE);
    context->predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, to_string(albumId));
    context->valuesBucket.Put(SUB_TITLE, context->subtitle);
    int changedRows = UserFileClient::Update(uri, context->predicates, context->valuesBucket);
    if (changedRows < 0) {
        context->SaveError(changedRows);
        ANI_ERR_LOG("Failed to set highlight subtitle, err: %{public}d", changedRows);
        return;
    }
}

ani_status HighlightAlbumAni::SetSubTitle(ani_env *env, ani_object object, ani_object subTitle)
{
    MediaLibraryTracer tracer;
    tracer.Start("SetSubTitle");

    ANI_DEBUG_LOG("%{public}s is called", __func__);
    CHECK_COND_RET(env != nullptr, ANI_INVALID_ARGS, "env is null");
    auto context = std::make_unique<HighlightAlbumAniContext>();
    CHECK_COND_WITH_RET_MESSAGE(env, context != nullptr, ANI_INVALID_ARGS, "context is nullptr");
    context->objectInfo = Unwrap(env, object);
    CHECK_COND_WITH_RET_MESSAGE(env, context->objectInfo != nullptr, ANI_INVALID_ARGS, "objectInfo is null");

    auto ret = MediaLibraryAniUtils::GetString(env, subTitle, context->subtitle);
    CHECK_COND_WITH_RET_MESSAGE(env, ret == ANI_OK, ANI_INVALID_ARGS, "parse param subtile failed");

    CHECK_COND_WITH_RET_MESSAGE(env, MediaFileUtils::CheckHighlightSubtitle(context->subtitle) == E_OK,
        ANI_INVALID_ARGS, "Invalid highlight subtitle");

    auto photoAlbum = context->objectInfo->GetPhotoAlbumInstance();
    CHECK_COND_WITH_RET_MESSAGE(env, photoAlbum != nullptr, ANI_INVALID_ARGS, "photoAlbum is nullptr");
    CHECK_COND_WITH_RET_MESSAGE(env,
        PhotoAlbum::IsHighlightAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType()),
        ANI_INVALID_ARGS, "Only highlight album can set highlight sub title");
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;

    SetHighlightSubtitleExecute(context);
    return SetHighlightSubtitleComplete(env, context);
}

ani_double HighlightAlbumAni::DeleteHighlightAlbums(ani_env *env, ani_object object, ani_object context,
    ani_object albums)
{
    ANI_DEBUG_LOG("%{public}s is called", __func__);
    ani_double returnObj {};
    CHECK_COND_RET(env != nullptr, returnObj, "env is null");
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "DeleteHighlightAlbums can be called only by system apps");
        return returnObj;
    }

    auto aniContext = std::make_unique<HighlightAlbumAniContext>();
    CHECK_COND_WITH_RET_MESSAGE(env, aniContext != nullptr, returnObj, "aniContext is nullptr");
    CHECK_COND_WITH_RET_MESSAGE(env, MediaAlbumChangeRequestAni::InitUserFileClient(env, context), returnObj,
        "DeleteAlbums InitUserFileClient failed");

    std::vector<PhotoAlbumAni*> array;
    CHECK_COND_WITH_RET_MESSAGE(env, MediaLibraryAniUtils::GetPhotoAlbumAniArray(env, albums, array) == ANI_OK,
        returnObj, "Failed to get arrayAlbum");

    std::vector<std::string> deleteIds;
    for (const auto& obj : array) {
        CHECK_COND_WITH_RET_MESSAGE(env, obj != nullptr, returnObj, "obj is null");
        auto photoAlbum = obj->GetPhotoAlbumInstance();
        CHECK_COND_WITH_RET_MESSAGE(env, photoAlbum != nullptr, returnObj, "photoAlbum is null");
        CHECK_COND_WITH_RET_MESSAGE(env,
            PhotoAlbum::IsUserPhotoAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType()) ||
            PhotoAlbum::IsHighlightAlbum(photoAlbum->GetPhotoAlbumType(), photoAlbum->GetPhotoAlbumSubType()),
            returnObj, "Only user or highlight album can be deleted");
        deleteIds.push_back(std::to_string(photoAlbum->GetAlbumId()));
    }
    aniContext->predicates.In(PhotoAlbumColumns::ALBUM_ID, deleteIds);
    Uri deleteAlbumUri(PAH_DELETE_PHOTO_ALBUM);
    int ret = UserFileClient::Delete(deleteAlbumUri, aniContext->predicates);
    if (ret < 0) {
        ANI_ERR_LOG("Failed to delete albums, err: %{public}d", ret);
        aniContext->ThrowError(env, ret, "Failed to delete albums");
        return returnObj;
    }
    ANI_INFO_LOG("Delete %{public}d album(s)", ret);
    CHECK_COND_WITH_RET_MESSAGE(env,
        MediaLibraryAniUtils::ToAniDouble(env, static_cast<double>(ret), returnObj) == ANI_OK,
        returnObj, "ToAniDouble failed");
    return returnObj;
}
} // namespace OHOS::Media