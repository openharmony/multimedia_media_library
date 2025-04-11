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

#include <unordered_map>
#include <unordered_set>

#include "highlight_album_ani.h"
#include "ani_class_name.h"
#include "file_asset_ani.h"
#include "media_file_utils.h"
#include "media_library_enum_ani.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_ani_log.h"
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

using namespace std;

namespace OHOS::Media {

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

HighlightAlbumAni::HighlightAlbumAni() : highlightmEnv_(nullptr) {}

HighlightAlbumAni::~HighlightAlbumAni() = default;

ani_status HighlightAlbumAni::Init(ani_env *env)
{
    ani_class cls;
    if (ANI_OK != env->FindClass(PAH_ANI_CLASS_HIGHLIGHT_ALBUM.c_str(), &cls)) {
        ANI_ERR_LOG("Failed to find class: %{public}s", PAH_ANI_CLASS_HIGHLIGHT_ALBUM.c_str());
        return ANI_ERROR;
    }

    std::array methods = {
        ani_native_function {"nativeConstructor", nullptr, reinterpret_cast<void *>(Constructor)},
        ani_native_function {"getHighlightAlbumInfoInner", nullptr, reinterpret_cast<void *>(GetHighlightAlbumInfo)},
    };

    if (ANI_OK != env->Class_BindNativeMethods(cls, methods.data(), methods.size())) {
        ANI_ERR_LOG("Failed to bind native methods to: %{public}s", PAH_ANI_CLASS_HIGHLIGHT_ALBUM.c_str());
        return ANI_ERROR;
    }

    return ANI_OK;
}

HighlightAlbumAni* HighlightAlbumAni::Unwrap(ani_env *env, ani_object object)
{
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
    highlightAlbum->highlightmEnv_ = env;
    return reinterpret_cast<ani_long>(highlightAlbum.release());
}

void HighlightAlbumAni::Destructor(ani_env *env, ani_object object)
{
    HighlightAlbumAni *highlightAlbum = Unwrap(env, object);
    if (highlightAlbum == nullptr) {
        return;
    }
    highlightAlbum->highlightmEnv_ = nullptr;
    delete highlightAlbum;
}

static void GetHighlightAlbumInfoExecute(ani_env *env, unique_ptr<HighlightAlbumAniContext> &context)
{
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
    auto photoAlbum = context->objectInfo->GetPhotoAlbumInstance();
    CHECK_NULL_PTR_RETURN_VOID(photoAlbum, "photoAlbum is null");
    int albumId = photoAlbum->GetAlbumId();
    int subType = photoAlbum->GetPhotoAlbumSubType();
    Uri uri (uriStr);
    if (subType == PhotoAlbumSubType::HIGHLIGHT) {
        predicates.EqualTo(HIGHLIGHT_ALBUM_TABLE + "." + PhotoAlbumColumns::ALBUM_ID, to_string(albumId));
    } else if (subType == PhotoAlbumSubType::HIGHLIGHT_SUGGESTIONS) {
        predicates.EqualTo(HIGHLIGHT_ALBUM_TABLE + "." + AI_ALBUM_ID, to_string(albumId));
    } else {
        ANI_ERR_LOG("Invalid highlight album subType");
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
    MediaLibraryTracer tracer;
    tracer.Start("GetHighlightAlbumInfo");

    unique_ptr<HighlightAlbumAniContext> context = make_unique<HighlightAlbumAniContext>();
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

    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    GetHighlightAlbumInfoExecute(env, context);
    return GetHighlightAlbumInfoComplete(env, context);
}
} // namespace OHOS::Media