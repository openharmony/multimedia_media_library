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
#define MLOG_TAG "FileAssetAni"

#include "file_asset_ani.h"
#include <fcntl.h>
#include <sys/stat.h>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "ani_class_name.h"
#include "datashare_values_bucket.h"
#include "ipc_skeleton.h"
#include "medialibrary_ani_utils.h"
#include "media_column.h"
#include "media_exif.h"
#include "media_file_utils.h"
#include "pixel_map_ani.h"
#include "sandbox_helper.h"
#include "thumbnail_const.h"
#include "thumbnail_manager_ani.h"
#include "userfile_manager_types.h"
#include "userfile_client.h"
#include "userfilemgr_uri.h"
#include "datashare_predicates.h"
#include "vision_total_column.h"
#include "vision_aesthetics_score_column.h"
#include "vision_composition_column.h"
#include "vision_head_column.h"
#include "vision_image_face_column.h"
#include "vision_object_column.h"
#include "vision_ocr_column.h"
#include "vision_pose_column.h"
#include "vision_recommendation_column.h"
#include "vision_saliency_detect_column.h"
#include "vision_segmentation_column.h"
#include "vision_video_label_column.h"
#include "vision_multi_crop_column.h"
#include "locale_config.h"
#include "medialibrary_tracer.h"
#include "nlohmann/json.hpp"
#include "media_asset_edit_data_ani.h"
#include "file_uri.h"
#include "album_operation_uri.h"
#include "pixel_map_taihe_ani.h"

namespace OHOS::Media {
namespace {
using DataSharePredicates = OHOS::DataShare::DataSharePredicates;
using DataShareValuesBucket = OHOS::DataShare::DataShareValuesBucket;
using DataShareResultSet = OHOS::DataShare::DataShareResultSet;

const std::array fileAssetAniMethods = {
    ani_native_function {"set", nullptr, reinterpret_cast<void *>(FileAssetAni::Set)},
    ani_native_function {"get", nullptr, reinterpret_cast<void *>(FileAssetAni::Get)},
    ani_native_function {"commitModifySync", nullptr,
        reinterpret_cast<void *>(FileAssetAni::PhotoAccessHelperCommitModify)},
    ani_native_function {"setUserCommentSync", nullptr,
        reinterpret_cast<void *>(FileAssetAni::PhotoAccessHelperSetUserComment)},
    ani_native_function {"openSync", nullptr, reinterpret_cast<void *>(FileAssetAni::PhotoAccessHelperOpen)},
    ani_native_function {"closeSync", nullptr, reinterpret_cast<void *>(FileAssetAni::PhotoAccessHelperClose)},
    ani_native_function {"getAnalysisDataSync", nullptr,
        reinterpret_cast<void *>(FileAssetAni::PhotoAccessHelperGetAnalysisData)},
    ani_native_function {"requestEditDataSync", nullptr,
        reinterpret_cast<void *>(FileAssetAni::PhotoAccessHelperRequestEditData)},
    ani_native_function {"getEditDataSync", nullptr,
        reinterpret_cast<void *>(FileAssetAni::PhotoAccessHelperGetEditData)},
    ani_native_function {"cloneSync", nullptr,
        reinterpret_cast<void *>(FileAssetAni::PhotoAccessHelperCloneAsset)},
    ani_native_function {"requestSourceSync", nullptr,
        reinterpret_cast<void *>(FileAssetAni::PhotoAccessHelperRequestSource)},
    ani_native_function {"commitEditedAssetSync", nullptr,
        reinterpret_cast<void *>(FileAssetAni::PhotoAccessHelperCommitEditedAsset)},
    ani_native_function {"revertToOriginalSync", nullptr,
        reinterpret_cast<void *>(FileAssetAni::PhotoAccessHelperRevertToOriginal)},
    ani_native_function {"requestPhotoSync", nullptr,
        reinterpret_cast<void *>(FileAssetAni::PhotoAccessHelperRequestPhoto)},
    ani_native_function {"cancelPhotoRequest", nullptr,
        reinterpret_cast<void *>(FileAssetAni::PhotoAccessHelperCancelPhotoRequest)},
    ani_native_function {"getKeyFrameThumbnailSync", nullptr,
        reinterpret_cast<void *>(FileAssetAni::PhotoAccessHelperGetKeyFrameThumbnail)},
    ani_native_function {"isEditedSync", nullptr,
        reinterpret_cast<void *>(FileAssetAni::PhotoAccessHelperIsEdited)},
    ani_native_function {"setHiddenSync", nullptr,
        reinterpret_cast<void *>(FileAssetAni::PhotoAccessHelperSetHidden)},
    ani_native_function {"setFavoriteSync", nullptr,
        reinterpret_cast<void *>(FileAssetAni::PhotoAccessHelperSetFavorite)},
    ani_native_function {"getThumbnailSync", nullptr,
        reinterpret_cast<void *>(FileAssetAni::PhotoAccessHelperGetThumbnail)},
    ani_native_function {"getThumbnailDataSync", nullptr,
        reinterpret_cast<void *>(FileAssetAni::PhotoAccessHelperGetThumbnailData)},
    ani_native_function {"getExifSync", nullptr,
        reinterpret_cast<void *>(FileAssetAni::GetExif)},
    ani_native_function {"setPendingSync", nullptr,
        reinterpret_cast<void *>(FileAssetAni::PhotoAccessHelperSetPending)},
};
} // namespace
struct FileAssetAttributes {
    std::string uri;
    MediaType photoType;
    std::string displayName;
};
static const std::string ANALYSIS_NO_RESULTS = "[]";
static const std::string ANALYSIS_INIT_VALUE = "0";
static const std::string ANALYSIS_STATUS_ANALYZED = "Analyzed, no results";

const std::string LANGUAGE_ZH = "zh-Hans";
const std::string LANGUAGE_EN = "en-Latn-US";
const std::string LANGUAGE_ZH_TR = "zh-Hant";

constexpr int32_t IS_HIDDEN = 1;
constexpr int32_t NOT_HIDDEN = 0;

constexpr int32_t IS_FAV = 1;
constexpr int32_t NOT_FAV = 0;

constexpr int32_t USER_COMMENT_MAX_LEN = 420;

thread_local std::shared_ptr<FileAsset> FileAssetAni::sFileAsset_ = nullptr;
shared_ptr<ThumbnailManagerAni> FileAssetAni::thumbnailManager_ = nullptr;

struct AnalysisSourceInfo {
    std::string fieldStr;
    std::string uriStr;
    std::vector<std::string> fetchColumn;
};

static const map<int32_t, struct AnalysisSourceInfo> ANALYSIS_SOURCE_INFO_MAP = {
    { ANALYSIS_AESTHETICS_SCORE, { AESTHETICS_SCORE, PAH_QUERY_ANA_ATTS, { AESTHETICS_SCORE, PROB } } },
    { ANALYSIS_LABEL, { LABEL, PAH_QUERY_ANA_LABEL, { CATEGORY_ID, SUB_LABEL, PROB, FEATURE, SIM_RESULT,
        SALIENCY_SUB_PROB } } },
    { ANALYSIS_VIDEO_LABEL, { VIDEO_LABEL, PAH_QUERY_ANA_VIDEO_LABEL, { CATEGORY_ID, CONFIDENCE_PROBABILITY,
        SUB_CATEGORY, SUB_CONFIDENCE_PROB, SUB_LABEL, SUB_LABEL_PROB, SUB_LABEL_TYPE, TRACKS, VIDEO_PART_FEATURE,
        FILTER_TAG} } },
    { ANALYSIS_OCR, { OCR, PAH_QUERY_ANA_OCR, { OCR_TEXT, OCR_TEXT_MSG, OCR_WIDTH, OCR_HEIGHT } } },
    { ANALYSIS_FACE, { FACE, PAH_QUERY_ANA_FACE, { FACE_ID, TAG_ID, SCALE_X, SCALE_Y, SCALE_WIDTH, SCALE_HEIGHT,
        LANDMARKS, PITCH, YAW, ROLL, PROB, TOTAL_FACES, FEATURES, FACE_OCCLUSION, BEAUTY_BOUNDER_X, BEAUTY_BOUNDER_Y,
        BEAUTY_BOUNDER_WIDTH, BEAUTY_BOUNDER_HEIGHT, FACE_AESTHETICS_SCORE} } },
    { ANALYSIS_OBJECT, { OBJECT, PAH_QUERY_ANA_OBJECT, { OBJECT_ID, OBJECT_LABEL, OBJECT_SCALE_X, OBJECT_SCALE_Y,
        OBJECT_SCALE_WIDTH, OBJECT_SCALE_HEIGHT, PROB, SCALE_X, SCALE_Y, SCALE_WIDTH, SCALE_HEIGHT } } },
    { ANALYSIS_RECOMMENDATION, { RECOMMENDATION, PAH_QUERY_ANA_RECOMMENDATION, { RECOMMENDATION_ID,
        RECOMMENDATION_RESOLUTION, RECOMMENDATION_SCALE_X, RECOMMENDATION_SCALE_Y, RECOMMENDATION_SCALE_WIDTH,
        RECOMMENDATION_SCALE_HEIGHT, SCALE_X, SCALE_Y, SCALE_WIDTH, SCALE_HEIGHT } } },
    { ANALYSIS_SEGMENTATION, { SEGMENTATION, PAH_QUERY_ANA_SEGMENTATION, { SEGMENTATION_AREA, SEGMENTATION_NAME,
        PROB } } },
    { ANALYSIS_COMPOSITION, { COMPOSITION, PAH_QUERY_ANA_COMPOSITION, { COMPOSITION_ID, COMPOSITION_RESOLUTION,
        CLOCK_STYLE, CLOCK_LOCATION_X, CLOCK_LOCATION_Y, CLOCK_COLOUR, COMPOSITION_SCALE_X, COMPOSITION_SCALE_Y,
        COMPOSITION_SCALE_WIDTH, COMPOSITION_SCALE_HEIGHT, SCALE_X, SCALE_Y, SCALE_WIDTH, SCALE_HEIGHT } } },
    { ANALYSIS_SALIENCY, { SALIENCY, PAH_QUERY_ANA_SAL, { SALIENCY_X, SALIENCY_Y } } },
    { ANALYSIS_DETAIL_ADDRESS, { DETAIL_ADDRESS, PAH_QUERY_ANA_ADDRESS, { PhotoColumn::PHOTOS_TABLE + "." + LATITUDE,
        PhotoColumn::PHOTOS_TABLE + "." + LONGITUDE, LANGUAGE, COUNTRY, ADMIN_AREA, SUB_ADMIN_AREA, LOCALITY,
        SUB_LOCALITY, THOROUGHFARE, SUB_THOROUGHFARE, FEATURE_NAME, CITY_NAME, ADDRESS_DESCRIPTION, LOCATION_TYPE,
        AOI, POI, FIRST_AOI, FIRST_POI, LOCATION_VERSION, FIRST_AOI_CATEGORY, FIRST_POI_CATEGORY, FILE_ID} } },
    { ANALYSIS_HUMAN_FACE_TAG, { FACE_TAG, PAH_QUERY_ANA_FACE_TAG, { VISION_FACE_TAG_TABLE + "." + TAG_ID, TAG_NAME,
        USER_OPERATION, GROUP_TAG, RENAME_OPERATION, CENTER_FEATURES, USER_DISPLAY_LEVEL, TAG_ORDER, IS_ME, COVER_URI,
        COUNT, PORTRAIT_DATE_MODIFY, ALBUM_TYPE, IS_REMOVED } } },
    { ANALYSIS_HEAD_POSITION, { HEAD, PAH_QUERY_ANA_HEAD, { HEAD_ID, HEAD_LABEL, HEAD_SCALE_X, HEAD_SCALE_Y,
        HEAD_SCALE_WIDTH, HEAD_SCALE_HEIGHT, PROB, SCALE_X, SCALE_Y, SCALE_WIDTH, SCALE_HEIGHT } } },
    { ANALYSIS_BONE_POSE, { POSE, PAH_QUERY_ANA_POSE, { POSE_ID, POSE_LANDMARKS, POSE_SCALE_X, POSE_SCALE_Y,
        POSE_SCALE_WIDTH, POSE_SCALE_HEIGHT, PROB, POSE_TYPE, SCALE_X, SCALE_Y, SCALE_WIDTH, SCALE_HEIGHT } } },
    { ANALYSIS_MULTI_CROP, { RECOMMENDATION, PAH_QUERY_ANA_RECOMMENDATION, { MOVEMENT_CROP, MOVEMENT_VERSION } } },
};

FileAssetAni::FileAssetAni(std::shared_ptr<FileAsset> fileAsset)
{
    fileAssetPtr = fileAsset;
}

FileAssetAni::FileAssetAni() {}

FileAssetAni::~FileAssetAni() = default;

void FileAssetAni::Destructor(ani_env env, void *nativeObject, void *finalize_hint)
{
    FileAssetAni *fileAssetObj = reinterpret_cast<FileAssetAni*>(nativeObject);
    if (fileAssetObj != nullptr) {
        delete fileAssetObj;
        fileAssetObj = nullptr;
    }
}

ani_status FileAssetAni::UserFileMgrInit(ani_env *env)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    static const char *className = UFM_ANI_CLASS_FILE_ASSET_HANDLE.c_str();
    ani_class cls;
    ani_status status = env->FindClass(className, &cls);
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to find class: %{public}s", className);
        return status;
    }
    return ANI_OK;
}

ani_status FileAssetAni::PhotoAccessHelperInit(ani_env *env)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    static const char *className = PAH_ANI_CLASS_PHOTO_ASSET_HANDLE.c_str();
    ani_class cls;
    ani_status status = env->FindClass(className, &cls);
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to find class: %{public}s", className);
        return status;
    }

    status = env->Class_BindNativeMethods(cls, fileAssetAniMethods.data(), fileAssetAniMethods.size());
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to bind native methods to: %{public}s", className);
        return status;
    }
    return ANI_OK;
}

static ani_status BindAniAttributes(ani_env *env, ani_object object,
    const FileAssetAniMethod &fileAssetAniMethod, const FileAssetAttributes &attrs)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    ani_enum_item photoType = 0;
    CHECK_STATUS_RET(MediaLibraryEnumAni::ToAniEnum(env, attrs.photoType, photoType), "Get photoType index fail");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, fileAssetAniMethod.setPhotoType, photoType),
        "<set>photoType fail");

    ani_string uri {};
    CHECK_STATUS_RET(MediaLibraryAniUtils::ToAniString(env, attrs.uri, uri), "ToAniString uri fail");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, fileAssetAniMethod.setUri, uri), "<set>uri fail");

    ani_string displayName {};
    CHECK_STATUS_RET(MediaLibraryAniUtils::ToAniString(env, attrs.displayName, displayName),
        "ToAniString displayName fail");
    CHECK_STATUS_RET(env->Object_CallMethod_Void(object, fileAssetAniMethod.setDisplayName, displayName),
        "<set>displayName fail");
    return ANI_OK;
}

shared_ptr<FileAsset> FileAssetAni::GetFileAssetInstance() const
{
    return fileAssetPtr;
}

FileAssetAni* FileAssetAni::CreatePhotoAsset(ani_env *env, std::shared_ptr<FileAsset> &fileAsset)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
    if (fileAsset == nullptr || fileAsset->GetResultNapiType() != ResultNapiType::TYPE_PHOTOACCESS_HELPER) {
        ANI_ERR_LOG("Unsupported fileAsset");
        return nullptr;
    }

    std::unique_ptr<FileAssetAni> fileAssetAni = std::make_unique<FileAssetAni>(fileAsset);
    return fileAssetAni.release();
}

FileAssetAni* FileAssetAni::CreateFileAsset(ani_env *env, std::unique_ptr<FileAsset> &fileAsset)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
    if (fileAsset == nullptr || fileAsset->GetResultNapiType() != ResultNapiType::TYPE_PHOTOACCESS_HELPER) {
        ANI_ERR_LOG("Unsupported fileAsset");
        return nullptr;
    }
    sFileAsset_ = std::move(fileAsset);
    std::unique_ptr<FileAssetAni> fileAssetAni = std::make_unique<FileAssetAni>(sFileAsset_);
    sFileAsset_ = nullptr;
    return fileAssetAni.release();
}

ani_status FileAssetAni::InitFileAssetAniMethod(ani_env *env, ResultNapiType classType,
    FileAssetAniMethod &fileAssetAniMethod)
{
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");
    std::string className;
    if (classType == ResultNapiType::TYPE_PHOTOACCESS_HELPER) {
        className = PAH_ANI_CLASS_PHOTO_ASSET_HANDLE;
    } else if (classType == ResultNapiType::TYPE_USERFILE_MGR) {
        className = UFM_ANI_CLASS_FILE_ASSET_HANDLE;
    } else {
        ANI_ERR_LOG("type not support");
        return ANI_ERROR;
    }

    CHECK_STATUS_RET(env->FindClass(className.c_str(), &fileAssetAniMethod.cls),
        "No className: %{public}s", className.c_str());
    CHECK_STATUS_RET(env->Class_FindMethod(fileAssetAniMethod.cls, "<ctor>", "l:", &fileAssetAniMethod.ctor),
        "No <ctor>");
    CHECK_STATUS_RET(env->Class_FindMethod(fileAssetAniMethod.cls, "<set>uri", nullptr, &fileAssetAniMethod.setUri),
        "No <set>uri");
    CHECK_STATUS_RET(env->Class_FindMethod(fileAssetAniMethod.cls, "<set>photoType", nullptr,
        &fileAssetAniMethod.setPhotoType), "No <set>photoType");
    CHECK_STATUS_RET(env->Class_FindMethod(fileAssetAniMethod.cls, "<set>displayName", nullptr,
        &fileAssetAniMethod.setDisplayName), "No <set>displayName");
    return ANI_OK;
}

ani_object FileAssetAni::Wrap(ani_env *env, FileAssetAni *fileAssetAni, const FileAssetAniMethod &fileAssetAniMethod)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
    if (fileAssetAni == nullptr || fileAssetAni->GetFileAssetInstance() == nullptr) {
        ANI_ERR_LOG("fileAssetAni is nullptr");
        return nullptr;
    }

    std::shared_ptr<FileAsset> fileAsset = fileAssetAni->GetFileAssetInstance();
    CHECK_COND_RET(fileAsset != nullptr, nullptr, "fileAsset is nullptr");
    FileAssetAttributes attrs;
    attrs.uri = fileAsset->GetUri();
    attrs.photoType = fileAsset->GetMediaType();
    attrs.displayName = fileAsset->GetDisplayName();

    ani_object fileAsset_object = nullptr;
    if (ANI_OK != env->Object_New(fileAssetAniMethod.cls, fileAssetAniMethod.ctor, &fileAsset_object,
        reinterpret_cast<ani_long>(fileAssetAni))) {
        ANI_ERR_LOG("New FileAsset Fail");
        return nullptr;
    }

    if (ANI_OK != BindAniAttributes(env, fileAsset_object, fileAssetAniMethod, attrs)) {
        ANI_ERR_LOG("fileAsset BindAniAttributes Fail");
        return nullptr;
    }
    return fileAsset_object;
}

FileAssetAni* FileAssetAni::Unwrap(ani_env *env, ani_object object)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
    ani_long fileAsset;
    if (ANI_OK != env->Object_GetFieldByName_Long(object, "nativePhotoAsset", &fileAsset)) {
        ANI_ERR_LOG("get FileAssetAni nativePhotoAsset failed");
        return nullptr;
    }
    return reinterpret_cast<FileAssetAni*>(fileAsset);
}

void FileAssetAni::Set(ani_env *env, ani_object object, ani_string member, ani_string value)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    auto fileAssetAni = Unwrap(env, object);
    if (fileAssetAni == nullptr || fileAssetAni->fileAssetPtr == nullptr) {
        ANI_ERR_LOG("fileAssetAni is nullptr");
        return;
    }

    std::string memberStr;
    MediaLibraryAniUtils::GetString(env, member, memberStr);
    std::string valueStr;
    MediaLibraryAniUtils::GetString(env, value, valueStr);

    std::shared_ptr<FileAsset> fileAssetPtr = fileAssetAni->fileAssetPtr;
    CHECK_NULL_PTR_RETURN_VOID(fileAssetPtr, "fileAssetPtr is null");
    ResultNapiType resultNapiType = fileAssetPtr->GetResultNapiType();
    ANI_INFO_LOG("fileAsset set key: %{public}s, value: %{public}s, type: %{public}d",
        memberStr.c_str(), valueStr.c_str(), resultNapiType);
    if (resultNapiType == ResultNapiType::TYPE_PHOTOACCESS_HELPER) {
        if (memberStr == MediaColumn::MEDIA_TITLE) {
            fileAssetPtr->SetTitle(valueStr);
        } else {
            ANI_ERR_LOG("invalid key %{private}s, no support key", memberStr.c_str());
            AniError::ThrowError(env, JS_E_FILE_KEY);
        }
    } else if (resultNapiType == ResultNapiType::TYPE_USERFILE_MGR) {
        if (memberStr == MediaColumn::MEDIA_NAME) {
            fileAssetPtr->SetDisplayName(valueStr);
            fileAssetPtr->SetTitle(MediaFileUtils::GetTitleFromDisplayName(valueStr));
        } else if (memberStr == MediaColumn::MEDIA_TITLE) {
            fileAssetPtr->SetTitle(valueStr);
            string displayName = fileAssetPtr->GetDisplayName();
            if (!displayName.empty()) {
                string extention = MediaFileUtils::SplitByChar(displayName, '.');
                fileAssetPtr->SetDisplayName(valueStr + "." + extention);
            }
        } else {
            ANI_ERR_LOG("invalid key %{private}s, no support key", memberStr.c_str());
            AniError::ThrowError(env, JS_E_FILE_KEY);
        }
    } else {
        ANI_ERR_LOG("invalid resultNapiType");
        AniError::ThrowError(env, JS_E_FILE_KEY);
    }
}

static int32_t CheckSystemApiKeys(ani_env *env, const string &key)
{
    static const set<string> SYSTEM_API_KEYS = {
        MediaColumn::MEDIA_DATE_TRASHED,
        MediaColumn::MEDIA_HIDDEN,
        PhotoColumn::PHOTO_USER_COMMENT,
        PhotoColumn::CAMERA_SHOT_KEY,
        PhotoColumn::MOVING_PHOTO_EFFECT_MODE,
        PhotoColumn::SUPPORTED_WATERMARK_TYPE,
        PhotoColumn::PHOTO_IS_AUTO,
        PhotoColumn::PHOTO_IS_RECENT_SHOW,
        PENDING_STATUS,
        MEDIA_DATA_DB_DATE_TRASHED_MS,
    };

    if (SYSTEM_API_KEYS.find(key) != SYSTEM_API_KEYS.end() && !MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This key can only be used by system apps");
        return E_CHECK_SYSTEMAPP_FAIL;
    }
    return E_SUCCESS;
}

static ani_object HandleDateTransitionKey(ani_env *env, const string &key, const shared_ptr<FileAsset> &fileAssetPtr)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
    CHECK_COND_RET(fileAssetPtr != nullptr, nullptr, "fileAssetPtr is nullptr");
    ani_object aniResult = nullptr;
    if (fileAssetPtr->GetMemberMap().count(key) == 0) {
        AniError::ThrowError(env, JS_E_FILE_KEY);
        return aniResult;
    }

    auto m = fileAssetPtr->GetMemberMap().at(key);
    if (m.index() == MEMBER_TYPE_INT64) {
        double val = static_cast<double>(get<int64_t>(m));
        MediaLibraryAniUtils::ToAniDoubleObject(env, val, aniResult);
    } else {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return aniResult;
    }
    return aniResult;
}

static bool IsSpecialKey(const string &key)
{
    static const set<string> SPECIAL_KEY = {
        PENDING_STATUS
    };

    if (SPECIAL_KEY.find(key) != SPECIAL_KEY.end()) {
        return true;
    }
    return false;
}

static ani_object HandleGettingSpecialKey(ani_env *env, const string &key, const shared_ptr<FileAsset> &fileAssetPtr)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
    CHECK_COND_RET(fileAssetPtr != nullptr, nullptr, "fileAssetPtr is nullptr");
    if (key == PENDING_STATUS) {
        bool isTimePending = (fileAssetPtr->GetTimePending() != 0);
        ani_object aniResult = nullptr;
        MediaLibraryAniUtils::ToAniBooleanObject(env, isTimePending, aniResult);
        return aniResult;
    }
    return nullptr;
}

static void UpdateDetailTimeByDateTaken(ani_env *env, const shared_ptr<FileAsset> &fileAssetPtr,
    const string &detailTime, int64_t &dateTaken)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    CHECK_NULL_PTR_RETURN_VOID(fileAssetPtr, "fileAssetPtr is null");
    string uri = PAH_UPDATE_PHOTO;
    MediaLibraryAniUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri updateAssetUri(uri);
    DataSharePredicates predicates;
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(PhotoColumn::PHOTO_DETAIL_TIME, detailTime);
    predicates.SetWhereClause(MediaColumn::MEDIA_ID + " = ? ");
    predicates.SetWhereArgs({ MediaFileUtils::GetIdFromUri(fileAssetPtr->GetUri()) });
    int32_t changedRows = UserFileClient::Update(updateAssetUri, predicates, valuesBucket);
    if (changedRows <= 0) {
        ANI_ERR_LOG("Failed to modify detail time, err: %{public}d", changedRows);
        AniError::ThrowError(env, JS_INNER_FAIL);
    } else {
        ANI_INFO_LOG("success to modify detial time, detailTime: %{public}s, dateTaken: %{public}" PRId64,
            detailTime.c_str(), dateTaken);
    }
}

static bool GetDateTakenFromResultSet(const shared_ptr<DataShareResultSet> &resultSet, int64_t &dateTaken)
{
    if (resultSet == nullptr) {
        ANI_ERR_LOG("ResultSet is null");
        return false;
    }
    int32_t count = 0;
    int32_t errCode = resultSet->GetRowCount(count);
    if (errCode != OHOS::DataShare::E_OK) {
        ANI_ERR_LOG("Can not get row count from resultSet, errCode=%{public}d", errCode);
        return false;
    }
    if (count == 0) {
        ANI_ERR_LOG("Can not find photo edit time from database");
        return false;
    }
    errCode = resultSet->GoToFirstRow();
    if (errCode != OHOS::DataShare::E_OK) {
        ANI_ERR_LOG("ResultSet GotoFirstRow failed, errCode=%{public}d", errCode);
        return false;
    }
    int32_t index = 0;
    errCode = resultSet->GetColumnIndex(PhotoColumn::MEDIA_DATE_TAKEN, index);
    if (errCode != OHOS::DataShare::E_OK) {
        ANI_ERR_LOG("ResultSet GetColumnIndex failed, errCode=%{public}d", errCode);
        return false;
    }
    errCode = resultSet->GetLong(index, dateTaken);
    if (errCode != OHOS::DataShare::E_OK) {
        ANI_ERR_LOG("ResultSet GetLong failed, errCode=%{public}d", errCode);
        return false;
    }
    return true;
}

static ani_object HandleGettingDetailTimeKey(ani_env *env, const shared_ptr<FileAsset> &fileAssetPtr)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
    CHECK_COND_RET(fileAssetPtr != nullptr, nullptr, "enfileAssetPtrv is nullptr");
    ani_object aniResult = nullptr;
    CHECK_COND_RET(fileAssetPtr->GetMemberMap().count(PhotoColumn::PHOTO_DETAIL_TIME) > 0, nullptr,
        "MemberMap is not have PHOTO_DETAIL_TIME");
    auto detailTimeValue = fileAssetPtr->GetMemberMap().at(PhotoColumn::PHOTO_DETAIL_TIME);
    if (detailTimeValue.index() == MEMBER_TYPE_STRING && !get<string>(detailTimeValue).empty()) {
        ani_string aniDetailTime {};
        MediaLibraryAniUtils::ToAniString(env, get<string>(detailTimeValue), aniDetailTime);
        return reinterpret_cast<ani_object>(aniDetailTime);
    } else {
        string fileId = MediaFileUtils::GetIdFromUri(fileAssetPtr->GetUri());
        string queryUriStr = PAH_QUERY_PHOTO;
        MediaLibraryAniUtils::UriAppendKeyValue(queryUriStr, API_VERSION, to_string(MEDIA_API_VERSION_V10));
        Uri uri(queryUriStr);
        DataSharePredicates predicates;
        predicates.EqualTo(MediaColumn::MEDIA_ID, fileId);
        DataShareValuesBucket values;
        vector<string> columns = { MediaColumn::MEDIA_DATE_TAKEN };
        int32_t errCode = 0;
        int64_t dateTaken = 0;
        shared_ptr<DataShareResultSet> resultSet = UserFileClient::Query(uri, predicates, columns, errCode);
        if (GetDateTakenFromResultSet(resultSet, dateTaken)) {
            if (dateTaken > SECONDS_LEVEL_LIMIT) {
                dateTaken = dateTaken / MSEC_TO_SEC;
            }
            string detailTime = MediaFileUtils::StrCreateTimeSafely(PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
            ani_string aniDetailTime {};
            MediaLibraryAniUtils::ToAniString(env, detailTime, aniDetailTime);
            UpdateDetailTimeByDateTaken(env, fileAssetPtr, detailTime, dateTaken);
            return reinterpret_cast<ani_object>(aniDetailTime);
        } else {
            AniError::ThrowError(env, JS_INNER_FAIL);
        }
    }
    return aniResult;
}

static inline int64_t GetCompatDate(const string inputKey, const int64_t date)
{
    if (inputKey == MEDIA_DATA_DB_DATE_ADDED || inputKey == MEDIA_DATA_DB_DATE_MODIFIED ||
        inputKey == MEDIA_DATA_DB_DATE_TRASHED || inputKey == MEDIA_DATA_DB_DATE_TAKEN) {
        return date / MSEC_TO_SEC;
    }
    return date;
}

ani_object FileAssetAni::Get(ani_env *env, ani_object object, ani_string member)
{
    auto fileAssetAni = Unwrap(env, object);
    if (fileAssetAni == nullptr || fileAssetAni->GetFileAssetInstance() == nullptr) {
        ANI_ERR_LOG("fileAssetAni is nullptr");
        return nullptr;
    }
    auto fileAssetPtr = fileAssetAni->fileAssetPtr;
    CHECK_COND_RET(fileAssetPtr != nullptr, nullptr, "fileAssetPtr is nullptr");
    std::string inputKey;
    MediaLibraryAniUtils::GetString(env, member, inputKey);

    if (CheckSystemApiKeys(env, inputKey) < 0) {
        return nullptr;
    }

    ani_object aniResult = nullptr;
    if (DATE_TRANSITION_MAP.count(inputKey) != 0) {
        return HandleDateTransitionKey(env, DATE_TRANSITION_MAP.at(inputKey), fileAssetPtr);
    }

    if (fileAssetPtr->GetMemberMap().count(inputKey) == 0) {
        AniError::ThrowError(env, JS_E_FILE_KEY);
        return aniResult;
    }

    if (IsSpecialKey(inputKey)) {
        return HandleGettingSpecialKey(env, inputKey, fileAssetPtr);
    }
    if (inputKey == PhotoColumn::PHOTO_DETAIL_TIME) {
        return HandleGettingDetailTimeKey(env, fileAssetPtr);
    }
    auto m = fileAssetPtr->GetMemberMap().at(inputKey);
    if (m.index() == MEMBER_TYPE_STRING) {
        ani_string aniString {};
        MediaLibraryAniUtils::ToAniString(env, std::get<std::string>(m), aniString);
        return reinterpret_cast<ani_object>(aniString);
    } else if (m.index() == MEMBER_TYPE_INT32) {
        double val = static_cast<double>(std::get<int32_t>(m));
        MediaLibraryAniUtils::ToAniDoubleObject(env, val, aniResult);
    } else if (m.index() == MEMBER_TYPE_INT64) {
        double val = static_cast<double>(GetCompatDate(inputKey, get<int64_t>(m)));
        MediaLibraryAniUtils::ToAniDoubleObject(env, val, aniResult);
    } else {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return aniResult;
    }
    return aniResult;
}

static void BuildCommitModifyUriApi10(FileAssetContext *context, string &uri)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    CHECK_NULL_PTR_RETURN_VOID(context->objectPtr, "objectPtr is null");
    if (context->objectPtr->GetMediaType() == MEDIA_TYPE_IMAGE ||
        context->objectPtr->GetMediaType() == MEDIA_TYPE_VIDEO) {
        uri = (context->resultNapiType == ResultNapiType::TYPE_USERFILE_MGR) ? UFM_UPDATE_PHOTO : PAH_UPDATE_PHOTO;
    } else if (context->objectPtr->GetMediaType() == MEDIA_TYPE_AUDIO) {
        uri = UFM_UPDATE_AUDIO;
    }
}

#ifdef MEDIALIBRARY_COMPATIBILITY
static void BuildCommitModifyUriApi9(FileAssetContext *context, string &uri)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    CHECK_NULL_PTR_RETURN_VOID(context->objectPtr, "objectPtr is null");
    if (context->objectPtr->GetMediaType() == MEDIA_TYPE_IMAGE ||
        context->objectPtr->GetMediaType() == MEDIA_TYPE_VIDEO) {
        uri = URI_UPDATE_PHOTO;
    } else if (context->objectPtr->GetMediaType() == MEDIA_TYPE_AUDIO) {
        uri = URI_UPDATE_AUDIO;
    } else if (context->objectPtr->GetMediaType() == MEDIA_TYPE_FILE) {
        uri = URI_UPDATE_FILE;
    }
}
#endif

std::string FileAssetAni::GetFileDisplayName() const
{
    return fileAssetPtr->GetDisplayName();
}

std::string FileAssetAni::GetFileUri() const
{
    return fileAssetPtr->GetUri();
}

int32_t FileAssetAni::GetFileId() const
{
    return fileAssetPtr->GetId();
}

static void BuildCommitModifyValuesBucket(FileAssetContext* context,
    OHOS::DataShare::DataShareValuesBucket &valuesBucket)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    const auto fileAsset = context->objectPtr;
    CHECK_NULL_PTR_RETURN_VOID(fileAsset, "fileAsset is null");
    if (context->resultNapiType == ResultNapiType::TYPE_PHOTOACCESS_HELPER) {
        valuesBucket.Put(MediaColumn::MEDIA_TITLE, fileAsset->GetTitle());
    } else if (context->resultNapiType == ResultNapiType::TYPE_USERFILE_MGR) {
        valuesBucket.Put(MediaColumn::MEDIA_NAME, fileAsset->GetDisplayName());
    } else {
#ifdef MEDIALIBRARY_COMPATIBILITY
        valuesBucket.Put(MEDIA_DATA_DB_TITLE, fileAsset->GetTitle());
        valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH,
            MediaFileUtils::AddDocsToRelativePath(fileAsset->GetRelativePath()));
        if (fileAsset->GetMediaType() != MediaType::MEDIA_TYPE_AUDIO) {
            // IMAGE, VIDEO AND FILES
            if (fileAsset->GetOrientation() >= 0) {
                valuesBucket.Put(MEDIA_DATA_DB_ORIENTATION, fileAsset->GetOrientation());
            }
            if ((fileAsset->GetMediaType() != MediaType::MEDIA_TYPE_IMAGE) &&
                (fileAsset->GetMediaType() != MediaType::MEDIA_TYPE_VIDEO)) {
                // ONLY FILES
                valuesBucket.Put(MEDIA_DATA_DB_URI, fileAsset->GetUri());
                valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, fileAsset->GetMediaType());
            }
        }
#else
        valuesBucket.Put(MEDIA_DATA_DB_URI, fileAsset->GetUri());
        valuesBucket.Put(MEDIA_DATA_DB_TITLE, fileAsset->GetTitle());

        if (fileAsset->GetOrientation() >= 0) {
            valuesBucket.Put(MEDIA_DATA_DB_ORIENTATION, fileAsset->GetOrientation());
        }
        valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, fileAsset->GetRelativePath());
        valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, fileAsset->GetMediaType());
#endif
        valuesBucket.Put(MEDIA_DATA_DB_NAME, fileAsset->GetDisplayName());
    }
}

static bool CheckDisplayNameInCommitModify(unique_ptr<FileAssetContext> &context)
{
    CHECK_COND_RET(context != nullptr, false, "context is nullptr");
    CHECK_COND_RET(context->objectPtr != nullptr, false, "objectPtr is nullptr");
    if (context->resultNapiType != ResultNapiType::TYPE_PHOTOACCESS_HELPER) {
        if (context->objectPtr->GetPhotoSubType() == static_cast<int32_t>(PhotoSubType::BURST)) {
            context->error = JS_E_DISPLAYNAME;
            return false;
        }
        if (context->objectPtr->GetMediaType() != MediaType::MEDIA_TYPE_FILE) {
            if (MediaFileUtils::CheckDisplayName(context->objectPtr->GetDisplayName(), true) != E_OK) {
                context->error = JS_E_DISPLAYNAME;
                return false;
            }
        } else {
            if (MediaFileUtils::CheckFileDisplayName(context->objectPtr->GetDisplayName()) != E_OK) {
                context->error = JS_E_DISPLAYNAME;
                return false;
            }
        }
    } else {
        if (MediaFileUtils::CheckTitleCompatible(context->objectPtr->GetTitle()) != E_OK) {
            context->error = JS_E_DISPLAYNAME;
            return false;
        }
    }
    return true;
}

static void CommitModifyExecute(ani_env *env, unique_ptr<FileAssetContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    if (!CheckDisplayNameInCommitModify(context)) {
        return;
    }
    string uri;
    if (context->resultNapiType == ResultNapiType::TYPE_USERFILE_MGR ||
        context->resultNapiType == ResultNapiType::TYPE_PHOTOACCESS_HELPER) {
        BuildCommitModifyUriApi10(context.get(), uri);
        MediaLibraryAniUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    } else {
#ifdef MEDIALIBRARY_COMPATIBILITY
        BuildCommitModifyUriApi9(context.get(), uri);
#else
        uri = URI_UPDATE_FILE;
#endif
    }
    CHECK_NULL_PTR_RETURN_VOID(context->objectPtr, "objectPtr is null");
    OHOS::Uri updateAssetUri(uri);
    MediaType mediaType = context->objectPtr->GetMediaType();
    string notifyUri = MediaFileUtils::GetMediaTypeUri(mediaType);
    DataSharePredicates predicates;
    DataShareValuesBucket valuesBucket;
    BuildCommitModifyValuesBucket(context.get(), valuesBucket);
    predicates.SetWhereClause(MEDIA_DATA_DB_ID + " = ? ");
    predicates.SetWhereArgs({std::to_string(context->objectPtr->GetId())});

    int32_t changedRows = UserFileClient::Update(updateAssetUri, predicates, valuesBucket);
    if (changedRows < 0) {
        context->SaveError(changedRows);
        ANI_ERR_LOG("File asset modification failed, err: %{public}d", changedRows);
    } else {
        context->changedRows = changedRows;
        Uri modifyNotify(notifyUri);
        UserFileClient::NotifyChange(modifyNotify);
    }
}

static void CommitModifyCompleteCallback(ani_env *env, unique_ptr<FileAssetContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    ani_object errorObj {};
    if (context->error == ERR_DEFAULT) {
        if (context->changedRows < 0) {
            MediaLibraryAniUtils::CreateAniErrorObject(env, errorObj, context->changedRows,
                "File asset modification failed");
            env->ThrowError(static_cast<ani_error>(errorObj));
        }
    } else {
        context->HandleError(env, errorObj);
        env->ThrowError(static_cast<ani_error>(errorObj));
    }
    context.reset();
}

void FileAssetAni::PhotoAccessHelperCommitModify(ani_env *env, ani_object object)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    auto fileAssetAni = Unwrap(env, object);
    CHECK_NULL_PTR_RETURN_VOID(fileAssetAni, "fileAssetAni is null");
    if (fileAssetAni == nullptr || fileAssetAni->GetFileAssetInstance() == nullptr) {
        ANI_ERR_LOG("fileAssetAni is nullptr");
        return;
    }
    auto fileAssetPtr = fileAssetAni->GetFileAssetInstance();
    unique_ptr<FileAssetContext> context = make_unique<FileAssetContext>();
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    context->objectPtr = fileAssetPtr;
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;

    CommitModifyExecute(env, context);
    CommitModifyCompleteCallback(env, context);
}

static void PhotoAccessHelperOpenExecute(ani_env *env, unique_ptr<FileAssetContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    bool isValid = false;
    string mode = context->valuesBucket.Get(MEDIA_FILEMODE, isValid);
    if (!isValid) {
        context->SaveError(-EINVAL);
        return;
    }
    string fileUri = context->valuesBucket.Get(MEDIA_DATA_DB_URI, isValid);
    if (!isValid) {
        context->SaveError(-EINVAL);
        return;
    }

    CHECK_NULL_PTR_RETURN_VOID(context->objectPtr, "context->objectPtr is null");
    if (context->objectPtr->GetTimePending() == UNCREATE_FILE_TIMEPENDING) {
        MediaFileUtils::UriAppendKeyValue(fileUri, MediaColumn::MEDIA_TIME_PENDING,
            to_string(context->objectPtr->GetTimePending()));
    }
    Uri openFileUri(fileUri);
    int32_t retVal = UserFileClient::OpenFile(openFileUri, mode, context->objectPtr->GetUserId());
    if (retVal <= 0) {
        context->SaveError(retVal);
        ANI_ERR_LOG("File open asset failed, ret: %{public}d", retVal);
    } else {
        context->fd = retVal;
        if (mode.find('w') != string::npos) {
            context->objectPtr->SetOpenStatus(retVal, OPEN_TYPE_WRITE);
        } else {
            context->objectPtr->SetOpenStatus(retVal, OPEN_TYPE_READONLY);
        }
        if (context->objectPtr->GetTimePending() == UNCREATE_FILE_TIMEPENDING) {
            context->objectPtr->SetTimePending(UNCLOSE_FILE_TIMEPENDING);
        }
    }
}

static void PhotoAccessHelperOpenCallbackComplete(ani_env *env, unique_ptr<FileAssetContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    ani_object errorObj {};
    if (context->error != ERR_DEFAULT) {
        context->HandleError(env, errorObj);
    }
    context.reset();
}

ani_double FileAssetAni::PhotoAccessHelperOpen(ani_env *env, ani_object object, ani_string mode)
{
    ani_double aniDouble {};
    CHECK_COND_RET(env != nullptr, aniDouble, "env is nullptr");
    auto fileAssetAni = Unwrap(env, object);
    if (fileAssetAni == nullptr || fileAssetAni->GetFileAssetInstance() == nullptr) {
        ANI_ERR_LOG("fileAssetAni is nullptr");
        return aniDouble;
    }

    auto fileAssetPtr = fileAssetAni->GetFileAssetInstance();
    unique_ptr<FileAssetContext> context = make_unique<FileAssetContext>();
    CHECK_COND_RET(context != nullptr, aniDouble, "context is nullptr");
    context->objectPtr = fileAssetPtr;

    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return aniDouble;
    }
    CHECK_COND_RET(context->objectPtr != nullptr, aniDouble, "context->objectPtr is nullptr");
    auto fileUri = context->objectPtr->GetUri();
    MediaLibraryAniUtils::UriAppendKeyValue(fileUri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    context->valuesBucket.Put(MEDIA_DATA_DB_URI, fileUri);

    std::string modeStr;
    MediaLibraryAniUtils::GetString(env, mode, modeStr);
    transform(modeStr.begin(), modeStr.end(), modeStr.begin(), ::tolower);
    if (!MediaFileUtils::CheckMode(modeStr)) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return aniDouble;
    }
    context->valuesBucket.Put(MEDIA_FILEMODE, modeStr);

    PhotoAccessHelperOpenExecute(env, context);
    MediaLibraryAniUtils::ToAniDouble(env, context->fd, aniDouble);
    PhotoAccessHelperOpenCallbackComplete(env, context);
    return aniDouble;
}

static bool CheckFileOpenStatus(FileAssetContext *context, int fd)
{
    CHECK_COND_RET(context != nullptr, false, "context is nullptr");
    auto fileAssetPtr = context->objectPtr;
    CHECK_COND_RET(fileAssetPtr != nullptr, false, "fileAssetPtr is nullptr");
    int ret = fileAssetPtr->GetOpenStatus(fd);
    if (ret < 0) {
        return false;
    } else {
        fileAssetPtr->RemoveOpenStatus(fd);
        if (ret == OPEN_TYPE_READONLY) {
            return false;
        } else {
            return true;
        }
    }
}

static void PhotoAccessHelperCloseExecute(ani_env *env, unique_ptr<FileAssetContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    CHECK_NULL_PTR_RETURN_VOID(context->objectPtr, "context->objectPtr is null");
    int32_t mediaFd = context->fd;
    if (!CheckFileOpenStatus(context.get(), mediaFd)) {
        ANI_ERR_LOG("CheckFileOpenStatus failed");
        return;
    }
    string closeUri;
    if (context->objectPtr->GetMediaType() == MEDIA_TYPE_IMAGE ||
        context->objectPtr->GetMediaType() == MEDIA_TYPE_VIDEO) {
        closeUri = PAH_CLOSE_PHOTO;
    } else {
        ANI_ERR_LOG("fileAsset close failed");
        context->SaveError(-EINVAL);
        return;
    }
    MediaLibraryAniUtils::UriAppendKeyValue(closeUri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    MediaLibraryAniUtils::UriAppendKeyValue(closeUri, MediaColumn::MEDIA_TIME_PENDING,
        to_string(context->objectPtr->GetTimePending()));
    Uri closeAssetUri(closeUri);
    int32_t ret = UserFileClient::Insert(closeAssetUri, context->valuesBucket);
    if (ret != E_SUCCESS) {
        ANI_ERR_LOG("fileAsset close failed, ret: %{public}d", ret);
        context->SaveError(ret);
        return;
    } else {
        if (context->objectPtr->GetTimePending() == UNCLOSE_FILE_TIMEPENDING) {
            context->objectPtr->SetTimePending(0);
        }
    }
}

static void PhotoAccessHelperCloseCallbackComplete(ani_env *env, unique_ptr<FileAssetContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    ani_object errorObj {};
    if (context->error != ERR_DEFAULT) {
        context->HandleError(env, errorObj);
    }
    context.reset();
}

void FileAssetAni::PhotoAccessHelperClose(ani_env *env, ani_object object, ani_double fd)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    auto fileAssetAni = Unwrap(env, object);
    if (fileAssetAni == nullptr || fileAssetAni->GetFileAssetInstance() == nullptr) {
        ANI_ERR_LOG("fileAssetAni is nullptr");
        return;
    }

    auto fileAssetPtr = fileAssetAni->GetFileAssetInstance();
    CHECK_NULL_PTR_RETURN_VOID(fileAssetPtr, "env is null");
    unique_ptr<FileAssetContext> context = make_unique<FileAssetContext>();
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    context->objectPtr = fileAssetPtr;
    CHECK_NULL_PTR_RETURN_VOID(context->objectPtr, "context->objectPtr is null");
    context->valuesBucket.Put(MEDIA_DATA_DB_URI, context->objectPtr->GetUri());

    double fdValue;
    MediaLibraryAniUtils::GetDouble(env, fd, fdValue);
    if (fdValue <= 0) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return;
    }
    context->fd = static_cast<int32_t>(fdValue);

    PhotoAccessHelperCloseExecute(env, context);
    PhotoAccessHelperCloseCallbackComplete(env, context);
}

static void GetThumbnailExecute(ani_env *env, unique_ptr<FileAssetContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    CHECK_NULL_PTR_RETURN_VOID(context->objectPtr, "context->objectPtr is null");
    std::string path = context->objectPtr->GetPath();
#ifndef MEDIALIBRARY_COMPATIBILITY
    if (path.empty() && !context->objectPtr->GetRelativePath().empty() &&
        !context->objectPtr->GetDisplayName().empty()) {
        path = ROOT_MEDIA_DIR + context->objectPtr->GetRelativePath() + context->objectPtr->GetDisplayName();
    }
#endif
    context->pixelmap = ThumbnailManagerAni::QueryThumbnail(context->objectPtr->GetUri(), context->size, path);
}

static void GetThumbnailCompleteCallback(ani_env *env, unique_ptr<FileAssetContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    ani_object errorObj {};
    if (context->error != ERR_DEFAULT) {
        MediaLibraryAniUtils::CreateAniErrorObject(env, errorObj, ERR_INVALID_OUTPUT,
            "Ability helper or thumbnail helper is null");
    }
    context.reset();
}

ani_object FileAssetAni::PhotoAccessHelperGetThumbnail(ani_env *env, ani_object object, ani_object size)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
    ani_object pixelMapAni {};
    auto fileAssetAni = Unwrap(env, object);
    if (fileAssetAni == nullptr || fileAssetAni->GetFileAssetInstance() == nullptr) {
        ANI_ERR_LOG("fileAssetAni is nullptr");
        return pixelMapAni;
    }

    unique_ptr<FileAssetContext> context = make_unique<FileAssetContext>();
    CHECK_COND_RET(context != nullptr, nullptr, "context is nullptr");
    context->objectPtr = fileAssetAni->GetFileAssetInstance();
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    context->size.width = DEFAULT_THUMB_SIZE;
    context->size.height = DEFAULT_THUMB_SIZE;
    if (MediaLibraryAniUtils::IsUndefined(env, size) == ANI_FALSE) {
        ani_int heightValue = DEFAULT_THUMB_SIZE;
        ani_int widthValue = DEFAULT_THUMB_SIZE;
        ani_object errorObj {};
        if (ANI_OK != env->Object_GetPropertyByName_Int(size, "height", &heightValue)) {
            ANI_ERR_LOG("Class_FindMethod Fail %{public}s", PAH_ANI_CLASS_SIZE.c_str());
            MediaLibraryAniUtils::CreateAniErrorObject(env, errorObj, ERR_INVALID_OUTPUT, "Get size height failed");
        }
        if (ANI_OK != env->Object_GetPropertyByName_Int(size, "width", &widthValue)) {
            ANI_ERR_LOG("Class_FindMethod Fail %{public}s", PAH_ANI_CLASS_SIZE.c_str());
            MediaLibraryAniUtils::CreateAniErrorObject(env, errorObj, ERR_INVALID_OUTPUT, "Get size width failed");
        }
        context->size.width = static_cast<int32_t>(widthValue);
        context->size.height = static_cast<int32_t>(heightValue);
        if (heightValue == 0 && widthValue == 0) {
            AniError::ThrowError(env, ERR_INVALID_OUTPUT, __FUNCTION__, __LINE__);
            return pixelMapAni;
        }
        if (heightValue == 0) {
            context->size.height = DEFAULT_THUMB_SIZE;
        }
        if (widthValue == 0) {
            context->size.width = DEFAULT_THUMB_SIZE;
        }
    }

    GetThumbnailExecute(env, context);
    if (context->pixelmap != nullptr) {
        pixelMapAni = OHOS::Media::PixelMapTaiheAni::CreateEtsPixelMap(env, context->pixelmap);
        CHECK_COND_RET(pixelMapAni != nullptr, nullptr, "pixelMapAni is nullptr");
    } else {
        ani_object errorObj {};
        MediaLibraryAniUtils::CreateAniErrorObject(env, errorObj, ERR_INVALID_OUTPUT, "Get thumbnail failed");
    }
    GetThumbnailCompleteCallback(env, context);
    return pixelMapAni;
}

static void PhotoAccessHelperSetUserCommentExecute(ani_env *env, unique_ptr<FileAssetContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    CHECK_NULL_PTR_RETURN_VOID(context->objectPtr, "context->objectPtr is null");
    string uri = PAH_EDIT_USER_COMMENT_PHOTO;
    MediaLibraryAniUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri editUserCommentUri(uri);
    DataSharePredicates predicates;
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(PhotoColumn::PHOTO_USER_COMMENT, context->userComment);
    predicates.SetWhereClause(MediaColumn::MEDIA_ID + " = ? ");
    predicates.SetWhereArgs({to_string(context->objectPtr->GetId())});
    int32_t changedRows = UserFileClient::Update(editUserCommentUri, predicates, valuesBucket);
    if (changedRows < 0) {
        context->SaveError(changedRows);
        ANI_ERR_LOG("Failed to modify user comment, err: %{public}d", changedRows);
    } else {
        context->objectPtr->SetUserComment(context->userComment);
        context->changedRows = changedRows;
    }
}

static void PhotoAccessHelperSetUserCommentComplete(ani_env *env, unique_ptr<FileAssetContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    ani_object errorObj {};
    if (context->error != ERR_DEFAULT) {
        context->HandleError(env, errorObj);
    }
    context.reset();
}

void FileAssetAni::PhotoAccessHelperSetUserComment(ani_env *env, ani_object object, ani_string userComment)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    auto fileAssetAni = Unwrap(env, object);
    if (fileAssetAni == nullptr || fileAssetAni->fileAssetPtr == nullptr) {
        ANI_ERR_LOG("fileAssetAni is nullptr");
        return;
    }

    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return;
    }

    string userCommentStr;
    MediaLibraryAniUtils::GetString(env, userComment, userCommentStr);

    auto fileAssetPtr = fileAssetAni->GetFileAssetInstance();
    unique_ptr<FileAssetContext> context = make_unique<FileAssetContext>();
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    context->objectPtr = fileAssetPtr;
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    context->userComment = userCommentStr;

    if (context->userComment.length() > USER_COMMENT_MAX_LEN) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID, "user comment too long");
        return;
    }

    PhotoAccessHelperSetUserCommentExecute(env, context);
    PhotoAccessHelperSetUserCommentComplete(env, context);
}

static void GetAnalysisDataExecute(ani_env *env, unique_ptr<FileAssetContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    if (ANALYSIS_SOURCE_INFO_MAP.find(context->analysisType) == ANALYSIS_SOURCE_INFO_MAP.end()) {
        ANI_ERR_LOG("Invalid analysisType");
        return;
    }
    auto &analysisInfo = ANALYSIS_SOURCE_INFO_MAP.at(context->analysisType);
    DataSharePredicates predicates;
    if (context->analysisType == ANALYSIS_HUMAN_FACE_TAG) {
        string onClause = VISION_IMAGE_FACE_TABLE + "." + TAG_ID + " = " + VISION_FACE_TAG_TABLE + "." + TAG_ID;
        predicates.InnerJoin(VISION_IMAGE_FACE_TABLE)->On({ onClause });
    }
    CHECK_NULL_PTR_RETURN_VOID(context->objectPtr, "context->objectPtr is null");
    string fileId = to_string(context->objectPtr->GetId());
    if (context->analysisType == ANALYSIS_DETAIL_ADDRESS) {
        string language = Global::I18n::LocaleConfig::GetSystemLanguage();
        // Chinese and English supported. Other languages English default.
        if (language == LANGUAGE_ZH || language == LANGUAGE_ZH_TR) {
            language = LANGUAGE_ZH;
        } else {
            language = LANGUAGE_EN;
        }
        vector<string> onClause = { PhotoColumn::PHOTOS_TABLE + "." + PhotoColumn::MEDIA_ID + " = " +
            GEO_KNOWLEDGE_TABLE + "." + FILE_ID + " AND " +
            GEO_KNOWLEDGE_TABLE + "." + LANGUAGE + " = \'" + language + "\'" };
        predicates.EqualTo(PhotoColumn::PHOTOS_TABLE + "." + MediaColumn::MEDIA_ID, fileId);
    } else {
        predicates.EqualTo(MediaColumn::MEDIA_ID, fileId);
    }
    Uri uri(analysisInfo.uriStr);
    std::vector<std::string> fetchColumn = analysisInfo.fetchColumn;
    int errCode = 0;
    int userId = context->objectPtr != nullptr ? context->objectPtr->GetUserId() : DEFAULT_USER_ID;
    auto resultSet = UserFileClient::Query(uri, predicates, fetchColumn, errCode, userId);
    context->analysisData = context->analysisType == ANALYSIS_FACE ?
        MediaLibraryAniUtils::ParseAnalysisFace2JsonStr(resultSet, fetchColumn) :
        MediaLibraryAniUtils::ParseResultSet2JsonStr(resultSet, fetchColumn);
    if (context->analysisData == ANALYSIS_NO_RESULTS) {
        Uri uri(PAH_QUERY_ANA_TOTAL);
        DataSharePredicates predicates;
        std::vector<std::string> fetchColumn = { analysisInfo.fieldStr };
        predicates.EqualTo(MediaColumn::MEDIA_ID, fileId);
        auto fieldValue = UserFileClient::Query(uri, predicates, fetchColumn, errCode, userId);
        string value = MediaLibraryAniUtils::ParseResultSet2JsonStr(fieldValue, fetchColumn);
        if (strstr(value.c_str(), ANALYSIS_INIT_VALUE.c_str()) == NULL) {
            context->analysisData = ANALYSIS_STATUS_ANALYZED;
        }
    }
}

static void GetAnalysisDataCompleteCallback(ani_env *env, unique_ptr<FileAssetContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    ani_object errorObj {};
    if (context->error != ERR_DEFAULT) {
        context->HandleError(env, errorObj);
    }
    context.reset();
}

ani_string FileAssetAni::PhotoAccessHelperGetAnalysisData(ani_env *env, ani_object object, ani_enum_item analysisType)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
    ani_string aniString {};
    auto fileAssetAni = Unwrap(env, object);
    if (fileAssetAni == nullptr || fileAssetAni->fileAssetPtr == nullptr) {
        ANI_ERR_LOG("fileAssetAni is nullptr");
        return aniString;
    }

    int32_t value;
    MediaLibraryEnumAni::EnumGetValueInt32(env, analysisType, value);

    auto fileAssetPtr = fileAssetAni->GetFileAssetInstance();
    unique_ptr<FileAssetContext> context = make_unique<FileAssetContext>();
    CHECK_COND_RET(context != nullptr, nullptr, "context is nullptr");
    context->objectPtr = fileAssetPtr;
    context->analysisType = value;
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;

    GetAnalysisDataExecute(env, context);
    MediaLibraryAniUtils::ToAniString(env, context->analysisData, aniString);
    GetAnalysisDataCompleteCallback(env, context);
    return aniString;
}

static void QueryPhotoEditDataExists(int32_t fileId, int32_t &hasEditData)
{
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(MediaColumn::MEDIA_ID, to_string(fileId));
    vector<string> columns;
    Uri uri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_QUERYOPRN_QUERYEDITDATA + "/" + MEDIA_QUERYOPRN_QUERYEDITDATA);
    int errCode = 0;
    shared_ptr<DataShare::DataShareResultSet> resultSet = UserFileClient::Query(uri, predicates, columns, errCode);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        ANI_ERR_LOG("Query failed");
        return;
    }
    if (resultSet->GetInt(0, hasEditData) != NativeRdb::E_OK) {
        ANI_ERR_LOG("Can not get hasEditData");
        return;
    }
}

static void ProcessEditData(unique_ptr<FileAssetContext> &context, const UniqueFd &uniqueFd)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    struct stat fileInfo;
    if (fstat(uniqueFd.Get(), &fileInfo) == 0) {
        off_t fileSize = fileInfo.st_size;
        if (fileSize < 0 || fileSize + 1 < 0) {
            ANI_ERR_LOG("fileBuffer error : %{public}" PRId64, fileSize);
            context->SaveError(E_FAIL);
            return;
        }
        context->editDataBuffer = static_cast<char *>(malloc(fileSize + 1));
        if (!context->editDataBuffer) {
            ANI_ERR_LOG("Photo request edit data failed, fd: %{public}d", uniqueFd.Get());
            context->SaveError(E_FAIL);
            return;
        }
        ssize_t bytes = read(uniqueFd.Get(), context->editDataBuffer, fileSize);
        if (bytes < 0) {
            ANI_ERR_LOG("Read edit data failed, errno: %{public}d", errno);
            free(context->editDataBuffer);
            context->editDataBuffer = nullptr;
            context->SaveError(E_FAIL);
            return;
        }
        context->editDataBuffer[bytes] = '\0';
    } else {
        ANI_ERR_LOG("can not get stat errno:%{public}d", errno);
        context->SaveError(E_FAIL);
    }
}

static void PhotoAccessHelperRequestEditDataExecute(ani_env *env, unique_ptr<FileAssetContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    CHECK_NULL_PTR_RETURN_VOID(context->objectPtr, "context->objectPtr is null");
    int32_t hasEditData = 0;
    QueryPhotoEditDataExists(context->objectPtr->GetId(), hasEditData);
    if (hasEditData == 0) {
        context->editDataBuffer = static_cast<char*>(malloc(1));
        if (context->editDataBuffer == nullptr) {
            ANI_ERR_LOG("malloc edit data buffer failed");
            context->SaveError(E_FAIL);
            return;
        }
        context->editDataBuffer[0] = '\0';
        return;
    }
    bool isValid = false;
    string fileUri = context->valuesBucket.Get(MEDIA_DATA_DB_URI, isValid);
    if (!isValid) {
        context->error = OHOS_INVALID_PARAM_CODE;
        return;
    }
    MediaFileUtils::UriAppendKeyValue(fileUri, MEDIA_OPERN_KEYWORD, EDIT_DATA_REQUEST);
    Uri uri(fileUri);
    UniqueFd uniqueFd(UserFileClient::OpenFile(uri, "r"));
    if (uniqueFd.Get() <= 0) {
        if (uniqueFd.Get() == E_PERMISSION_DENIED) {
            context->error = OHOS_PERMISSION_DENIED_CODE;
        } else {
            context->SaveError(uniqueFd.Get());
        }
        ANI_ERR_LOG("Photo request edit data failed, ret: %{public}d", uniqueFd.Get());
    } else {
        ProcessEditData(context, uniqueFd);
    }
}

static void GetEditDataString(const char* editDataBuffer, string& result)
{
    if (editDataBuffer == nullptr) {
        result = "";
        ANI_WARN_LOG("editDataBuffer is nullptr");
        return;
    }
    string editDataStr(editDataBuffer);
    if (!nlohmann::json::accept(editDataStr)) {
        result = editDataStr;
        return;
    }
    nlohmann::json editDataJson = nlohmann::json::parse(editDataStr);
    if (editDataJson.contains(COMPATIBLE_FORMAT) && editDataJson.contains(FORMAT_VERSION) &&
        editDataJson.contains(EDIT_DATA) && editDataJson.contains(APP_ID)) {
        // edit data saved by media change request
        result = editDataJson.at(EDIT_DATA);
    } else {
        // edit data saved by commitEditedAsset
        result = editDataStr;
    }
}

static void PhotoAccessHelperRequestEditDataComplete(ani_env *env, unique_ptr<FileAssetContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    ani_object errorObj{};
    if (context->error != ERR_DEFAULT) {
        context->HandleError(env, errorObj);
    }
    if (context->editDataBuffer != nullptr) {
        free(context->editDataBuffer);
        context->editDataBuffer = nullptr;
    }
    context.reset();
}

ani_string FileAssetAni::PhotoAccessHelperRequestEditData(ani_env *env, ani_object object)
{
    ani_string aniString {};
    CHECK_COND_RET(env != nullptr, aniString, "env is nullptr");
    auto fileAssetAni = Unwrap(env, object);
    if (fileAssetAni == nullptr || fileAssetAni->fileAssetPtr == nullptr) {
        ANI_ERR_LOG("fileAssetAni is nullptr");
        return aniString;
    }
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return aniString;
    }
    auto fileAssetPtr = fileAssetAni->GetFileAssetInstance();
    auto context = make_unique<FileAssetContext>();
    CHECK_COND_RET(context != nullptr, aniString, "context is nullptr");
    context->objectPtr = fileAssetPtr;
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    if (context->objectPtr == nullptr) {
        ANI_ERR_LOG("PhotoAsset is nullptr");
        return aniString;
    }
    auto fileUri = context->objectPtr->GetUri();
    MediaLibraryAniUtils::UriAppendKeyValue(fileUri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    context->valuesBucket.Put(MEDIA_DATA_DB_URI, fileUri);
    PhotoAccessHelperRequestEditDataExecute(env, context);
    if (context->editDataBuffer != nullptr) {
        string editDataStr;
        GetEditDataString(context->editDataBuffer, editDataStr);
        MediaLibraryAniUtils::ToAniString(env, editDataStr, aniString);
    }
    PhotoAccessHelperRequestEditDataComplete(env, context);
    return aniString;
}

static ani_object GetEditDataObject(ani_env *env, char* editDataBuffer)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
    if (editDataBuffer == nullptr) {
        ANI_WARN_LOG("editDataBuffer is nullptr");
        return MediaAssetEditDataAni::CreateMediaAssetEditData(env, "", "", "");
    }
    string editDataStr(editDataBuffer);
    if (!nlohmann::json::accept(editDataStr)) {
        return MediaAssetEditDataAni::CreateMediaAssetEditData(env, "", "", editDataStr);
    }
    nlohmann::json editDataJson = nlohmann::json::parse(editDataStr);
    if (editDataJson.contains(COMPATIBLE_FORMAT) && editDataJson.contains(FORMAT_VERSION) &&
        editDataJson.contains(EDIT_DATA) && editDataJson.contains(APP_ID)) {
        return MediaAssetEditDataAni::CreateMediaAssetEditData(env, editDataJson.at(COMPATIBLE_FORMAT),
            editDataJson.at(FORMAT_VERSION), editDataJson.at(EDIT_DATA));
    }
    return MediaAssetEditDataAni::CreateMediaAssetEditData(env, "", "", editDataStr);
}

static void PhotoAccessHelperGetEditDataComplete(ani_env *env, unique_ptr<FileAssetContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    ani_object errorObj{};
    if (context->error != ERR_DEFAULT) {
        context->HandleError(env, errorObj);
    }
    if (context->editDataBuffer != nullptr) {
        free(context->editDataBuffer);
        context->editDataBuffer = nullptr;
    }
    context.reset();
}

ani_object FileAssetAni::PhotoAccessHelperGetEditData(ani_env *env, ani_object object)
{
    ani_object editDataObject{};
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
    auto fileAssetAni = Unwrap(env, object);
    if (fileAssetAni == nullptr || fileAssetAni->fileAssetPtr == nullptr) {
        ANI_ERR_LOG("fileAssetAni is nullptr");
        return nullptr;
    }
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return nullptr;
    }
    auto fileAssetPtr = fileAssetAni->GetFileAssetInstance();
    auto context = make_unique<FileAssetContext>();
    CHECK_COND_RET(context != nullptr, nullptr, "context is nullptr");
    context->objectPtr = fileAssetPtr;
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    if (context->objectPtr == nullptr) {
        ANI_ERR_LOG("PhotoAsset is nullptr");
        return nullptr;
    }
    auto fileUri = context->objectPtr->GetUri();
    MediaLibraryAniUtils::UriAppendKeyValue(fileUri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    context->valuesBucket.Put(MEDIA_DATA_DB_URI, fileUri);

    PhotoAccessHelperRequestEditDataExecute(env, context);
    if (context->editDataBuffer != nullptr) {
        editDataObject = GetEditDataObject(env, context->editDataBuffer);
    }
    PhotoAccessHelperGetEditDataComplete(env, context);
    return editDataObject;
}

static void CloneAssetHandlerExecute(ani_env *env, unique_ptr<FileAssetContext> &context)
{
    MediaLibraryTracer tracer;
    tracer.Start("CloneAssetHandlerExecute");
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    auto fileAsset = context->objectPtr;
    if (fileAsset == nullptr) {
        context->SaveError(E_FAIL);
        ANI_ERR_LOG("fileAsset is null");
        return;
    }
    DataShare::DataShareValuesBucket valuesBucket;
    string uri = PAH_CLONE_ASSET;
    MediaFileUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    valuesBucket.Put(MediaColumn::MEDIA_ID, fileAsset->GetId());
    valuesBucket.Put(MediaColumn::MEDIA_TITLE, context->title);
    Uri cloneAssetUri(uri);
    int32_t newAssetId = UserFileClient::Insert(cloneAssetUri, valuesBucket);
    if (newAssetId < 0) {
        context->SaveError(newAssetId);
        ANI_ERR_LOG("Failed to clone asset, ret: %{public}d", newAssetId);
        return;
    }
    context->assetId = newAssetId;
}

static ani_object CreateClonePhotoAsset(ani_env *env, unique_ptr<FileAssetContext> &context)
{
    CHECK_COND_RET(env, nullptr, "env is null");
    CHECK_COND_RET(context, nullptr, "context is null");
    ani_object resultObj{};
    auto asset = FileAssetAni::CreatePhotoAsset(env, context->objectPtr);
    if (asset == nullptr) {
        ANI_ERR_LOG("Failed to clone file asset ani object");
        ani_object errorObj{};
        MediaLibraryAniUtils::CreateAniErrorObject(env, errorObj, JS_INNER_FAIL, "System inner fail");
        return nullptr;
    } else {
        ANI_INFO_LOG("CreatePhotoAsset cloneAssetObj != nullptr");
        FileAssetAniMethod fileAssetAniMethod;
        if (ANI_OK != FileAssetAni::InitFileAssetAniMethod(env, asset->GetFileAssetInstance()->GetResultNapiType(),
            fileAssetAniMethod)) {
            ANI_ERR_LOG("InitFileAssetAniMethod failed");
            return nullptr;
        }
        resultObj = FileAssetAni::Wrap(env, asset, fileAssetAniMethod);
    }
    return resultObj;
}

static void CloneAssetHandlerCompleteCallback(ani_env *env, unique_ptr<FileAssetContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    ani_object errorObj {};
    if (context->error != ERR_DEFAULT) {
        context->HandleError(env, errorObj);
    }
    context.reset();
}

ani_object FileAssetAni::PhotoAccessHelperCloneAsset(ani_env * env, ani_object object, ani_string title)
{
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
    ani_object cloneAssetObj{};
    ANI_INFO_LOG("PhotoAccessHelperCloneAsset in");
    auto fileAssetAni = Unwrap(env, object);
    if (fileAssetAni == nullptr || fileAssetAni->fileAssetPtr == nullptr) {
        ANI_ERR_LOG("fileAssetAni is nullptr");
        return nullptr;
    }
    auto context = make_unique<FileAssetContext>();
    CHECK_COND_RET(context != nullptr, nullptr, "context is nullptr");
    context->objectPtr = fileAssetAni->fileAssetPtr;
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;

    if (context->objectPtr == nullptr) {
        ANI_ERR_LOG("PhotoAsset is nullptr");
        return nullptr;
    }
    string str_title;
    MediaLibraryAniUtils::GetString(env, title, str_title);
    string extension = MediaFileUtils::SplitByChar(context->objectPtr->GetDisplayName(), '.');
    string displayName = str_title + "." + extension;
    CHECK_COND_WITH_MESSAGE(env, MediaFileUtils::CheckDisplayName(displayName, true) == E_OK,
                            "Input title is invalid");

    context->title = str_title;
    CloneAssetHandlerExecute(env, context);
    if (context->assetId == 0) {
        ANI_ERR_LOG("Clone file asset failed");
        return nullptr;
    } else {
        cloneAssetObj = CreateClonePhotoAsset(env, context);
    }

    CloneAssetHandlerCompleteCallback(env, context);
    return cloneAssetObj;
}

static void PhotoAccessHelperRequestSourceExecute(ani_env *env, unique_ptr<FileAssetContext> &context)
{
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAccessHelperRequestSourceExecute");
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    bool isValid = false;
    string fileUri = context->valuesBucket.Get(MEDIA_DATA_DB_URI, isValid);
    if (!isValid) {
        context->error = OHOS_INVALID_PARAM_CODE;
        return;
    }
    MediaFileUtils::UriAppendKeyValue(fileUri, MEDIA_OPERN_KEYWORD, SOURCE_REQUEST);
    Uri uri(fileUri);
    CHECK_NULL_PTR_RETURN_VOID(context->objectPtr, "objectPtr is null");
    int32_t retVal = UserFileClient::OpenFile(uri, "r", context->objectPtr->GetUserId());
    if (retVal <= 0) {
        if (retVal == E_PERMISSION_DENIED) {
            context->error = OHOS_PERMISSION_DENIED_CODE;
        } else {
            context->SaveError(retVal);
        }
        ANI_ERR_LOG("Photo request edit data failed, ret: %{public}d", retVal);
    } else {
        context->fd = retVal;
        context->objectPtr->SetOpenStatus(retVal, OPEN_TYPE_READONLY);
    }
}

static void PhotoAccessHelperRequestSourceComplete(ani_env *env, unique_ptr<FileAssetContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    ani_object errorObj {};
    if (context->error != ERR_DEFAULT) {
        context->HandleError(env, errorObj);
    }
    context.reset();
}

ani_double FileAssetAni::PhotoAccessHelperRequestSource(ani_env *env, ani_object object)
{
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAccessHelperRequestSource");
    CHECK_COND_RET(env != nullptr, ANI_ERROR, "env is nullptr");

    ani_double aniDouble{};
    auto fileAssetAni = Unwrap(env, object);
    if (fileAssetAni == nullptr || fileAssetAni->fileAssetPtr == nullptr) {
        ANI_ERR_LOG("fileAssetAni is nullptr");
        return ANI_ERROR;
    }
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL,
            "This interface can be called only by system apps");
        return ANI_ERROR;
    }

    auto context = make_unique<FileAssetContext>();
    CHECK_COND_RET(context != nullptr, ANI_ERROR, "context is nullptr");
    context->objectPtr = fileAssetAni->fileAssetPtr;
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;

    if (context->objectPtr == nullptr) {
        ANI_ERR_LOG("PhotoAsset is nullptr");
        return ANI_ERROR;
    }
    auto fileUri = fileAssetAni->GetFileUri();
    MediaLibraryAniUtils::UriAppendKeyValue(fileUri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    context->valuesBucket.Put(MEDIA_DATA_DB_URI, fileUri);
    PhotoAccessHelperRequestSourceExecute(env, context);
    MediaLibraryAniUtils::ToAniDouble(env, context->fd, aniDouble);
    PhotoAccessHelperRequestSourceComplete(env, context);
    return aniDouble;
}

static int32_t GetFileUriFd(unique_ptr<FileAssetContext> &context)
{
    CHECK_COND_RET(context, E_FAIL, "context is null");
    AppFileService::ModuleFileUri::FileUri fileUri(context->uri);
    string uriRealPath = fileUri.GetRealPath();
    if (uriRealPath.empty()) {
        ANI_ERR_LOG("Can not get file in path by uri %{private}s", context->uri.c_str());
        context->SaveError(E_FAIL);
        return E_FAIL;
    }
    int32_t fd = open(uriRealPath.c_str(), O_RDONLY);
    if (fd < 0) {
        ANI_ERR_LOG("Can not open fileUri, ret: %{public}d, errno:%{public}d", fd, errno);
        context->SaveError(E_FAIL);
        return E_FAIL;
    }
    return fd;
}

static void PhotoAccessHelperCommitEditExecute(ani_env *env, unique_ptr<FileAssetContext> &context)
{
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAccessHelperCommitEditExecute");
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    UniqueFd uriFd(GetFileUriFd(context));
    CHECK_IF_EQUAL(uriFd.Get() > 0, "Can not open fileUri");

    bool isValid = false;
    string fileUri = context->valuesBucket.Get(MEDIA_DATA_DB_URI, isValid);
    if (!isValid) {
        context->error = OHOS_INVALID_PARAM_CODE;
        return;
    }
    MediaFileUtils::UriAppendKeyValue(fileUri, MEDIA_OPERN_KEYWORD, COMMIT_REQUEST);
    Uri uri(fileUri);
    UniqueFd fd(UserFileClient::OpenFile(uri, "rw"));
    if (fd.Get() <= 0) {
        if (fd.Get() == E_PERMISSION_DENIED) {
            context->error = OHOS_PERMISSION_DENIED_CODE;
        } else {
            context->SaveError(fd.Get());
        }
        ANI_ERR_LOG("File request edit data failed, ret: %{public}d", fd.Get());
    } else {
        if (ftruncate(fd.Get(), 0) == -1) {
            ANI_ERR_LOG("Can not erase content from old file, errno:%{public}d", errno);
            context->SaveError(E_FAIL);
            return;
        }
        if (!MediaFileUtils::CopyFile(uriFd.Get(), fd.Get())) {
            ANI_ERR_LOG("Failed to copy file: rfd:%{public}d, wfd:%{public}d, errno:%{public}d",
                uriFd.Get(), fd.Get(), errno);
            context->SaveError(E_FAIL);
            return;
        }
        ANI_INFO_LOG("commit edit asset copy file finished, fileUri:%{public}s", fileUri.c_str());
        string insertUriStr = PAH_COMMIT_EDIT_PHOTOS;
        MediaLibraryAniUtils::UriAppendKeyValue(insertUriStr, API_VERSION, to_string(MEDIA_API_VERSION_V10));
        Uri insertUri(insertUriStr);
        int32_t ret = UserFileClient::Insert(insertUri, context->valuesBucket);
        if (ret != E_SUCCESS) {
            if (ret == E_PERMISSION_DENIED) {
                context->error = OHOS_PERMISSION_DENIED_CODE;
            } else {
                context->SaveError(ret);
            }
            ANI_ERR_LOG("File commit edit execute failed");
        }
    }
}

static void PhotoAccessHelperCommitEditComplete(ani_env *env, unique_ptr<FileAssetContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    ani_object errorObj {};
    if (context->error != ERR_DEFAULT) {
        context->HandleError(env, errorObj);
    }
    context.reset();
}

void FileAssetAni::PhotoAccessHelperCommitEditedAsset(ani_env *env, ani_object object,
                                                      ani_string editData, ani_string uri)
{
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAccessHelperCommitEditedAsset");
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");

    auto fileAssetAni = Unwrap(env, object);
    if (fileAssetAni == nullptr || fileAssetAni->fileAssetPtr == nullptr) {
        ANI_ERR_LOG("fileAssetAni is nullptr");
        return;
    }
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return;
    }

    auto context = make_unique<FileAssetContext>();
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    context->objectPtr = fileAssetAni->fileAssetPtr;
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;

    string editDatastr;
    MediaLibraryAniUtils::GetString(env, editData, editDatastr);

    string uristr;
    MediaLibraryAniUtils::GetString(env, uri, uristr);
    context->uri = uristr;
    if (context->objectPtr == nullptr) {
        ANI_ERR_LOG("PhotoAsset is nullptr");
        return;
    }
    auto fileUri = fileAssetAni->GetFileUri();
    MediaLibraryAniUtils::UriAppendKeyValue(fileUri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    context->valuesBucket.Put(MEDIA_DATA_DB_URI, fileUri);
    context->valuesBucket.Put(EDIT_DATA, editData);
    context->valuesBucket.Put(MediaColumn::MEDIA_ID, context->objectPtr->GetId());

    PhotoAccessHelperCommitEditExecute(env, context);
    PhotoAccessHelperCommitEditComplete(env, context);
    return;
}

static void PhotoAccessHelperRevertToOriginalExecute(ani_env *env, unique_ptr<FileAssetContext> &context)
{
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAccessHelperRevertToOriginalExecute");
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    string uriString = PAH_REVERT_EDIT_PHOTOS;
    MediaFileUtils::UriAppendKeyValue(uriString, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri uri(uriString);
    int32_t ret = UserFileClient::Insert(uri, context->valuesBucket);
    if (ret < 0) {
        if (ret == E_PERMISSION_DENIED) {
            context->error = OHOS_PERMISSION_DENIED_CODE;
        } else {
            context->SaveError(ret);
        }
        ANI_ERR_LOG("Photo revert edit data failed, ret: %{public}d", ret);
    }
}

static void PhotoAccessHelperRevertToOriginalComplete(ani_env *env, unique_ptr<FileAssetContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    ani_object errorObj {};
    if (context->error != ERR_DEFAULT) {
        context->HandleError(env, errorObj);
    }
    context.reset();
}

void FileAssetAni::PhotoAccessHelperRevertToOriginal(ani_env *env, ani_object object)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return;
    }
    auto fileAssetAni = Unwrap(env, object);
    if (fileAssetAni == nullptr || fileAssetAni->fileAssetPtr == nullptr) {
        ANI_ERR_LOG("fileAssetAni is nullptr");
        return;
    }
    auto context = make_unique<FileAssetContext>();
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    context->objectPtr = fileAssetAni->fileAssetPtr;
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    if (context->objectPtr == nullptr) {
        ANI_ERR_LOG("PhotoAsset is nullptr");
        return;
    }
    context->valuesBucket.Put(MediaColumn::MEDIA_ID, context->objectPtr->GetId());
    PhotoAccessHelperRevertToOriginalExecute(env, context);
    PhotoAccessHelperRevertToOriginalComplete(env, context);
}


static ani_status GetPhotoRequestOption(ani_env *env, ani_object object,
    unique_ptr<FileAssetContext> &context, RequestPhotoType &type)
{
    CHECK_COND_WITH_RET_MESSAGE(env, context != nullptr, ANI_INVALID_ARGS, "context is null");
    const std::string size = "size";
    ani_object sizeObj;
    CHECK_STATUS_RET(MediaLibraryAniUtils::GetProperty(env, object, size, sizeObj), "Failed to check empty size!");
    ANI_INFO_LOG("sizeObj: %{public}p", sizeObj);
    if (MediaLibraryAniUtils::IsUndefined(env, sizeObj) == ANI_FALSE) {
        ani_int heightValue = 0;
        ani_int widthValue = 0;
        if (ANI_OK != env->Object_GetPropertyByName_Int(sizeObj, "height", &heightValue)) {
            AniError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "Invalid parameter height");
            return ANI_ERROR;
        }
        if (ANI_OK != env->Object_GetPropertyByName_Int(sizeObj, "width", &widthValue)) {
            AniError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "Invalid parameter width");
            return ANI_ERROR;
        }
        context->size.width = static_cast<int32_t>(widthValue);
        context->size.height = static_cast<int32_t>(heightValue);
    }

    ani_int requestType = 0;
    if (ANI_OK != env->Object_GetPropertyByName_Int(object, REQUEST_PHOTO_TYPE.c_str(), &requestType)) {
        if (requestType >= static_cast<int>(RequestPhotoType::REQUEST_TYPE_END)) {
            AniError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "Invalid parameter type");
            return ANI_ERROR;
        }
        type = static_cast<RequestPhotoType>(requestType);
    } else {
        type = RequestPhotoType::REQUEST_ALL_THUMBNAILS;
    }
    return ANI_OK;
}

ani_string FileAssetAni::PhotoAccessHelperRequestPhoto(ani_env *env, ani_object object, ani_fn_object callbackOn,
    ani_object option)
{
    ani_string result {};
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAccessHelperRequestPhoto");
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return result;
    }
    auto fileAssetAni = Unwrap(env, object);
    if (fileAssetAni == nullptr || fileAssetAni->fileAssetPtr == nullptr) {
        ANI_ERR_LOG("fileAssetAni is nullptr");
        return result;
    }
    auto context = make_unique<FileAssetContext>();
    CHECK_COND_RET(context != nullptr, nullptr, "context is nullptr");
    context->size.width = DEFAULT_THUMB_SIZE;
    context->size.height = DEFAULT_THUMB_SIZE;
    ani_ref cbOnRef {};
    CHECK_COND_RET(env != nullptr, nullptr, "env is nullptr");
    env->GlobalReference_Create(static_cast<ani_ref>(callbackOn), &cbOnRef);
    context->callbackRef = cbOnRef;
    RequestPhotoType type = RequestPhotoType::REQUEST_ALL_THUMBNAILS;
    if (MediaLibraryAniUtils::IsUndefined(env, option) == ANI_FALSE) {
        if (GetPhotoRequestOption(env, option, context, type) != ANI_OK) {
            AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
            return result;
        }
    }
    RequestPhotoParams params = {
        .uri = fileAssetAni->fileAssetPtr->GetUri(),
        .path = fileAssetAni->fileAssetPtr->GetFilePath(),
        .size = context->size,
        .type = type
    };
    static std::once_flag onceFlag;
    std::call_once(onceFlag, []() mutable {
        thumbnailManager_ = ThumbnailManagerAni::GetInstance();
        if (thumbnailManager_ != nullptr) {
            thumbnailManager_->Init();
        }
    });
    string requestId {};
    if (thumbnailManager_ != nullptr) {
        requestId = thumbnailManager_->AddPhotoRequest(params, env, context->callbackRef);
    }
    MediaLibraryAniUtils::ToAniString(env, requestId, result);
    return result;
}

void FileAssetAni::PhotoAccessHelperCancelPhotoRequest(ani_env *env, ani_object object, ani_string requestId)
{
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAccessHelperCancelPhotoRequest");
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return;
    }
    auto fileAssetAni = Unwrap(env, object);
    if (fileAssetAni == nullptr || fileAssetAni->fileAssetPtr == nullptr) {
        ANI_ERR_LOG("fileAssetAni is nullptr");
        return;
    }

    string requestKey;
    if (MediaLibraryAniUtils::GetString(env, requestId, requestKey) != ANI_OK) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return;
    }

    if (thumbnailManager_ != nullptr) {
        thumbnailManager_->RemovePhotoRequest(requestKey);
    }
}

static void GetKeyFrameThumbnailExecute(ani_env *env, unique_ptr<FileAssetContext> &context)
{
    MediaLibraryTracer tracer;
    tracer.Start("GetKeyFrameThumbnailExecute");

    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    CHECK_NULL_PTR_RETURN_VOID(context->objectPtr, "context->objectPtr is null");
    string path = context->objectPtr->GetPath();
#ifndef MEDIALIBRARY_COMPATIBILITY
    if (path.empty() && !context->objectPtr->GetRelativePath().empty() &&
        !context->objectPtr->GetDisplayName().empty()) {
        path = ROOT_MEDIA_DIR + context->objectPtr->GetRelativePath() + context->objectPtr->GetDisplayName();
    }
#endif
    context->pixelmap = ThumbnailManagerAni::QueryKeyFrameThumbnail(context->objectPtr->GetUri(), context->beginStamp,
        context->type, path);
}

ani_object FileAssetAni::PhotoAccessHelperGetKeyFrameThumbnail(ani_env *env, ani_object object,
    ani_double beginFrameTimeMs, ani_enum_item type)
{
    ani_object pixelMapAni {};
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAccessHelperGetKeyFrameThumbnail");
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return pixelMapAni;
    }
    auto fileAssetAni = Unwrap(env, object);
    if (fileAssetAni == nullptr || fileAssetAni->fileAssetPtr == nullptr) {
        ANI_ERR_LOG("fileAssetAni is nullptr");
        return pixelMapAni;
    }
    auto context = make_unique<FileAssetContext>();
    CHECK_COND_RET(context != nullptr, nullptr, "context is nullptr");
    context->objectPtr = fileAssetAni->fileAssetPtr;
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    if (context->objectPtr == nullptr) {
        ANI_ERR_LOG("PhotoAsset is nullptr");
        return pixelMapAni;
    }
    double beginFrameTimeMsValue = 0;
    if (MediaLibraryAniUtils::GetDouble(env, beginFrameTimeMs, beginFrameTimeMsValue) != ANI_OK) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return pixelMapAni;
    }
    context->beginStamp = static_cast<int32_t>(beginFrameTimeMsValue);
    int32_t typeValue = 0;
    if (MediaLibraryEnumAni::EnumGetValueInt32(env, type, typeValue) != ANI_OK) {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return pixelMapAni;
    }
    context->type = static_cast<int32_t>(typeValue);

    GetKeyFrameThumbnailExecute(env, context);
    if (context->pixelmap != nullptr) {
        pixelMapAni = OHOS::Media::PixelMapTaiheAni::CreateEtsPixelMap(env, context->pixelmap);
    } else {
        ani_object errorObj {};
        MediaLibraryAniUtils::CreateAniErrorObject(env, errorObj, ERR_INVALID_OUTPUT, "Get thumbnail failed");
    }
    GetThumbnailCompleteCallback(env, context);
    return pixelMapAni;
}

static void PhotoAccessHelperSetHiddenExecute(ani_env *env, unique_ptr<FileAssetContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    CHECK_NULL_PTR_RETURN_VOID(context->objectPtr, "context->objectPtr is null");
    if (context->objectPtr->GetMediaType() != MEDIA_TYPE_IMAGE &&
        context->objectPtr->GetMediaType() != MEDIA_TYPE_VIDEO) {
        context->SaveError(-EINVAL);
        return;
    }

    string uri = PAH_HIDE_PHOTOS;
    MediaLibraryAniUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri updateAssetUri(uri);
    DataSharePredicates predicates;
    predicates.In(MediaColumn::MEDIA_ID, vector<string>({ context->objectPtr->GetUri() }));
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MediaColumn::MEDIA_HIDDEN, context->isHidden ? IS_HIDDEN : NOT_HIDDEN);

    int32_t changedRows = UserFileClient::Update(updateAssetUri, predicates, valuesBucket);
    if (changedRows < 0) {
        context->SaveError(changedRows);
        ANI_ERR_LOG("Failed to modify hidden state, err: %{public}d", changedRows);
    } else {
        context->objectPtr->SetHidden(context->isHidden);
        context->changedRows = changedRows;
    }
}

static void PhotoAccessHelperSetHiddenComplete(ani_env *env, unique_ptr<FileAssetContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    ani_object errorObj {};
    if (context->error != ERR_DEFAULT) {
        context->HandleError(env, errorObj);
    }
    context.reset();
}


void FileAssetAni::PhotoAccessHelperSetHidden(ani_env *env, ani_object object, ani_boolean hiddenState)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    auto fileAssetAni = Unwrap(env, object);
    if (fileAssetAni == nullptr || fileAssetAni->fileAssetPtr == nullptr) {
        ANI_ERR_LOG("fileAssetAni is nullptr");
        return;
    }

    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return;
    }

    bool isHidden;
    MediaLibraryAniUtils::GetBool(env, hiddenState, isHidden);

    auto fileAssetPtr = fileAssetAni->GetFileAssetInstance();
    unique_ptr<FileAssetContext> context = make_unique<FileAssetContext>();
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    context->objectPtr = fileAssetPtr;
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    context->isHidden = isHidden;

    PhotoAccessHelperSetHiddenExecute(env, context);
    PhotoAccessHelperSetHiddenComplete(env, context);
}

static void PhotoAccessHelperFavoriteExecute(ani_env *env, unique_ptr<FileAssetContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    CHECK_NULL_PTR_RETURN_VOID(context->objectPtr, "context->objectPtr is null");
    string uri;
    if (context->objectPtr->GetMediaType() == MEDIA_TYPE_IMAGE ||
        context->objectPtr->GetMediaType() == MEDIA_TYPE_VIDEO) {
        uri = PAH_UPDATE_PHOTO;
    } else {
        context->SaveError(-EINVAL);
        return;
    }

    MediaLibraryAniUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri updateAssetUri(uri);
    DataSharePredicates predicates;
    DataShareValuesBucket valuesBucket;
    int32_t changedRows = 0;
    valuesBucket.Put(MediaColumn::MEDIA_IS_FAV, context->isFavorite ? IS_FAV : NOT_FAV);
    ANI_INFO_LOG("update asset %{public}d favorite to %{public}d", context->objectPtr->GetId(),
        context->isFavorite ? IS_FAV : NOT_FAV);
    predicates.SetWhereClause(MediaColumn::MEDIA_ID + " = ? ");
    predicates.SetWhereArgs({ std::to_string(context->objectPtr->GetId()) });

    changedRows = UserFileClient::Update(updateAssetUri, predicates, valuesBucket);
    if (changedRows < 0) {
        context->SaveError(changedRows);
        ANI_ERR_LOG("Failed to modify favorite state, err: %{public}d", changedRows);
    } else {
        context->objectPtr->SetFavorite(context->isFavorite);
        context->changedRows = changedRows;
    }
}

static void PhotoAccessHelperFavoriteComplete(ani_env *env, unique_ptr<FileAssetContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    ani_object errorObj {};
    if (context->error != ERR_DEFAULT) {
        context->HandleError(env, errorObj);
    }
}

void FileAssetAni::PhotoAccessHelperSetFavorite(ani_env *env, ani_object object, ani_boolean favoriteState)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    auto fileAssetAni = Unwrap(env, object);
    if (fileAssetAni == nullptr || fileAssetAni->fileAssetPtr == nullptr) {
        ANI_ERR_LOG("fileAssetAni is nullptr");
        return;
    }

    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return;
    }

    bool isFavorite;
    MediaLibraryAniUtils::GetBool(env, favoriteState, isFavorite);

    auto fileAssetPtr = fileAssetAni->GetFileAssetInstance();
    unique_ptr<FileAssetContext> context = make_unique<FileAssetContext>();
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    context->objectPtr = fileAssetPtr;
    context->isFavorite = isFavorite;
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;

    PhotoAccessHelperFavoriteExecute(env, context);
    PhotoAccessHelperFavoriteComplete(env, context);
}

static bool GetEditTimeFromResultSet(const shared_ptr<DataShare::DataShareResultSet> &resultSet,
    int64_t &editTime)
{
    if (resultSet == nullptr) {
        ANI_ERR_LOG("ResultSet is null");
        return false;
    }
    int32_t count = 0;
    int32_t errCode = resultSet->GetRowCount(count);
    if (errCode != DataShare::E_OK) {
        ANI_ERR_LOG("Can not get row count from resultSet, errCode=%{public}d", errCode);
        return false;
    }
    if (count == 0) {
        ANI_ERR_LOG("Can not find photo edit time from database");
        return false;
    }
    errCode = resultSet->GoToFirstRow();
    if (errCode != DataShare::E_OK) {
        ANI_ERR_LOG("ResultSet GotoFirstRow failed, errCode=%{public}d", errCode);
        return false;
    }
    int32_t index = 0;
    errCode = resultSet->GetColumnIndex(PhotoColumn::PHOTO_EDIT_TIME, index);
    if (errCode != DataShare::E_OK) {
        ANI_ERR_LOG("ResultSet GetColumnIndex failed, errCode=%{public}d", errCode);
        return false;
    }
    errCode = resultSet->GetLong(index, editTime);
    if (errCode != DataShare::E_OK) {
        ANI_ERR_LOG("ResultSet GetLong failed, errCode=%{public}d", errCode);
        return false;
    }
    return true;
}

static void PhotoAccessHelperIsEditedExecute(ani_env *env, unique_ptr<FileAssetContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAccessHelperIsEditedExecute");
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    CHECK_NULL_PTR_RETURN_VOID(context->objectPtr, "FileAsset is null");
    int32_t fileId = context->objectPtr->GetId();
    string queryUriStr = PAH_QUERY_PHOTO;
    MediaLibraryAniUtils::UriAppendKeyValue(queryUriStr, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri uri(queryUriStr);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(MediaColumn::MEDIA_ID, to_string(fileId));
    DataShare::DataShareValuesBucket values;
    vector<string> columns = { PhotoColumn::PHOTO_EDIT_TIME };
    int32_t errCode = 0;
    int64_t editTime = 0;
    shared_ptr<DataShare::DataShareResultSet> resultSet = UserFileClient::Query(uri, predicates, columns, errCode);
    if (!GetEditTimeFromResultSet(resultSet, editTime)) {
        if (errCode == E_PERMISSION_DENIED) {
            context->error = OHOS_PERMISSION_DENIED_CODE;
        } else {
            context->SaveError(E_FAIL);
        }
    } else {
        if (editTime == 0) {
            context->hasEdit = false;
        } else {
            context->hasEdit = true;
        }
    }
}

static void PhotoAccessHelperIsEditedComplete(ani_env *env, unique_ptr<FileAssetContext> &context)
{
    CHECK_NULL_PTR_RETURN_VOID(env, "env is nullptr");
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    ani_object errorObj {};
    if (context->error != ERR_DEFAULT) {
        context->HandleError(env, errorObj);
    }
    context.reset();
}

ani_boolean FileAssetAni::PhotoAccessHelperIsEdited(ani_env *env, ani_object object)
{
    CHECK_COND_RET(env != nullptr, false, "env is nullptr");
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAccessHelperIsEdited");

    // edit function in API11 is system api, maybe public soon
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return false;
    }

    auto context = make_unique<FileAssetContext>();
    CHECK_COND_RET(context != nullptr, false, "context is nullptr");
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    auto fileAssetAni = Unwrap(env, object);
    if (fileAssetAni == nullptr) {
        AniError::ThrowError(env, OHOS_INVALID_PARAM_CODE, "fileAssetAni is nullptr");
        return false;
    }
    context->objectPtr = fileAssetAni->fileAssetPtr;
    PhotoAccessHelperIsEditedExecute(env, context);
    ani_boolean isEdited = context->hasEdit;
    PhotoAccessHelperIsEditedComplete(env, context);
    return isEdited;
}

static ani_status CheckType(int32_t type)
{
    const int lcdType = 1;
    const int thmType = 2;

    if (type == lcdType || type == thmType) {
        return ANI_OK;
    }
    return ANI_INVALID_ARGS;
}

static void JSGetThumbnailDataExecute(ani_env *env, std::unique_ptr<FileAssetContext> &context)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSGetThumbnailDataExecute");

    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    CHECK_NULL_PTR_RETURN_VOID(context, "context is null");
    CHECK_NULL_PTR_RETURN_VOID(context->objectPtr, "context->objectPtr is null");
    string path = context->objectPtr->GetPath();
#ifndef MEDIALIBRARY_COMPATIBILITY
    if (path.empty()
            && !context->objectPtr->GetRelativePath().empty() && !context->objectPtr->GetDisplayName().empty()) {
        path = ROOT_MEDIA_DIR + context->objectPtr->GetRelativePath() + context->objectPtr->GetDisplayName();
    }
#endif
    context->path = path;
}

ani_object FileAssetAni::PhotoAccessHelperGetThumbnailData(ani_env *env, ani_object object, ani_enum_item type)
{
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAccessHelperGetThumbnailData");

    ani_object retObject {};
    auto context = std::make_unique<FileAssetContext>();
    CHECK_COND_WITH_RET_MESSAGE(env, context != nullptr, retObject, "context is null");
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    auto fileAssetAni = Unwrap(env, object);
    CHECK_COND_WITH_RET_MESSAGE(env, fileAssetAni != nullptr, retObject, "fileAssetAni is nullptr");
    context->objectPtr = fileAssetAni->fileAssetPtr;
    CHECK_COND_WITH_RET_MESSAGE(env, context->objectPtr != nullptr, retObject, "context->objectPtr is nullptr");

    JSGetThumbnailDataExecute(env, context);
    int32_t value;
    CHECK_COND_WITH_RET_MESSAGE(env, MediaLibraryEnumAni::EnumGetValueInt32(env, type, value) == ANI_OK,
        retObject, "EnumGetValueInt32 failed");
    CHECK_COND_WITH_RET_MESSAGE(env, CheckType(value) == ANI_OK, retObject, "CheckType failed");
    context->type = value;
    return ThumbnailManagerAni::QueryThumbnailData(env, context->objectPtr->GetUri(), context->type, context->path);
}

static void UserFileMgrGetExifExecute(ani_env *env, std::unique_ptr<FileAssetContext> &context) {}

static bool CheckAniCallerPermission(const std::string &permission)
{
    MediaLibraryTracer tracer;
    tracer.Start("CheckAniCallerPermission");

    OHOS::Security::AccessToken::AccessTokenID tokenCaller = IPCSkeleton::GetSelfTokenID();
    int res = Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenCaller, permission);
    if (res != Security::AccessToken::PermissionState::PERMISSION_GRANTED) {
        ANI_ERR_LOG("Have no media permission: %{public}s", permission.c_str());
        return false;
    }
    return true;
}

static ani_string UserFileMgrGetExifComplete(ani_env *env, std::unique_ptr<FileAssetContext> &context)
{
    ani_string result {};
    CHECK_COND_RET(env != nullptr, result, "env is null");
    CHECK_COND_WITH_RET_MESSAGE(env, context != nullptr, result, "context is null");

    auto obj = context->objectPtr;
    CHECK_COND_WITH_RET_MESSAGE(env, obj != nullptr, result, "obj is null");
    nlohmann::json allExifJson;
    if (!obj->GetAllExif().empty() && nlohmann::json::accept(obj->GetAllExif())) {
        allExifJson = nlohmann::json::parse(obj->GetAllExif());
    }

    std::string allExif = obj->GetAllExif();
    std::string userComment = obj->GetUserComment();
    context.reset();
    if (allExifJson.is_discarded() || allExif.empty()) {
        ANI_ERR_LOG("parse json failed");
    } else {
        const std::string PERMISSION_NAME_MEDIA_LOCATION = "ohos.permission.MEDIA_LOCATION";
        auto err = CheckAniCallerPermission(PERMISSION_NAME_MEDIA_LOCATION);
        if (err == false) {
            allExifJson.erase(PHOTO_DATA_IMAGE_GPS_LATITUDE);
            allExifJson.erase(PHOTO_DATA_IMAGE_GPS_LONGITUDE);
            allExifJson.erase(PHOTO_DATA_IMAGE_GPS_LATITUDE_REF);
            allExifJson.erase(PHOTO_DATA_IMAGE_GPS_LONGITUDE_REF);
        }
        allExifJson[PHOTO_DATA_IMAGE_USER_COMMENT] = std::move(userComment);
        allExifJson[PHOTO_DATA_IMAGE_IMAGE_DESCRIPTION] =
            AppFileService::SandboxHelper::Decode(allExifJson[PHOTO_DATA_IMAGE_IMAGE_DESCRIPTION]);
        std::string allExifJsonStr = allExifJson.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
        CHECK_COND_WITH_MESSAGE(env, MediaLibraryAniUtils::ToAniString(env, allExifJsonStr, result) == ANI_OK,
            "ToAniString failed");
    }
    return result;
}

ani_string FileAssetAni::GetExif(ani_env *env, ani_object object)
{
    MediaLibraryTracer tracer;
    tracer.Start("GetExif");

    ani_string result {};
    auto context = std::make_unique<FileAssetContext>();
    CHECK_COND_WITH_RET_MESSAGE(env, context != nullptr, result, "context is null");
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    auto fileAssetAni = Unwrap(env, object);
    CHECK_COND_WITH_RET_MESSAGE(env, fileAssetAni != nullptr, result, "fileAssetAni is nullptr");
    context->objectPtr = fileAssetAni->fileAssetPtr;
    CHECK_COND_WITH_RET_MESSAGE(env, context->objectPtr != nullptr, result, "context->objectPtr is nullptr");

    UserFileMgrGetExifExecute(env, context);
    return UserFileMgrGetExifComplete(env, context);
}

static void PhotoAccessHelperSetPendingExecute(ani_env *env, std::unique_ptr<FileAssetContext> &context)
{
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAccessHelperSetPendingExecute");

    constexpr int64_t TIME_PENDING_ZERO = 0;
    constexpr int64_t TIME_PENDING_ONE = 1;
    CHECK_NULL_PTR_RETURN_VOID(env, "env is null");
    CHECK_NULL_PTR_RETURN_VOID(context, "context is nullptr");
    auto fileAsset = context->objectPtr;
    CHECK_NULL_PTR_RETURN_VOID(fileAsset, "fileAsset is nullptr");
    string uri = MEDIALIBRARY_DATA_URI + "/";
    if (fileAsset->GetMediaType() == MEDIA_TYPE_IMAGE || fileAsset->GetMediaType() == MEDIA_TYPE_VIDEO) {
        uri += PAH_PHOTO + "/" + OPRN_PENDING;
    } else {
        context->SaveError(-EINVAL);
        return;
    }

    MediaLibraryAniUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri updateAssetUri(uri);
    DataSharePredicates predicates;
    DataShareValuesBucket valuesBucket;
    int32_t changedRows = 0;
    valuesBucket.Put(MediaColumn::MEDIA_TIME_PENDING, context->isPending ? 1 : 0);
    predicates.SetWhereClause(MediaColumn::MEDIA_ID + " = ? ");
    predicates.SetWhereArgs({ std::to_string(fileAsset->GetId()) });

    changedRows = UserFileClient::Update(updateAssetUri, predicates, valuesBucket);
    if (changedRows < 0) {
        if (changedRows == E_PERMISSION_DENIED) {
            context->error = OHOS_PERMISSION_DENIED_CODE;
        } else {
            context->SaveError(changedRows);
        }
        ANI_ERR_LOG("Failed to modify pending state, err: %{public}d", changedRows);
    } else {
        context->changedRows = changedRows;
        fileAsset->SetTimePending(context->isPending ? TIME_PENDING_ONE : TIME_PENDING_ZERO);
    }
}

static ani_status PhotoAccessHelperSetPendingComplete(ani_env *env, std::unique_ptr<FileAssetContext> &context)
{
    CHECK_COND_RET(env != nullptr, ANI_INVALID_ARGS, "env is null");
    CHECK_COND_WITH_RET_MESSAGE(env, context != nullptr, ANI_INVALID_ARGS, "context is null");

    ani_status retStatus = ANI_OK;
    ani_object errorObj {};
    if (context->error != ERR_DEFAULT) {
        ANI_ERR_LOG("SetPending failed, error code: %{public}d", context->error);
        context->HandleError(env, errorObj);
        retStatus = ANI_ERROR;
    }
    context.reset();
    return retStatus;
}

ani_status FileAssetAni::PhotoAccessHelperSetPending(ani_env *env, ani_object object, ani_boolean pendingState)
{
    MediaLibraryTracer tracer;
    tracer.Start("PhotoAccessHelperSetPending");

    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return ANI_ERROR;
    }

    CHECK_COND_RET(env != nullptr, ANI_INVALID_ARGS, "env is null");
    auto context = std::make_unique<FileAssetContext>();
    CHECK_COND_WITH_RET_MESSAGE(env, context != nullptr, ANI_INVALID_ARGS, "context is null");
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    auto fileAssetAni = Unwrap(env, object);
    CHECK_COND_WITH_RET_MESSAGE(env, fileAssetAni != nullptr, ANI_INVALID_ARGS, "fileAssetAni is nullptr");
    MediaLibraryAniUtils::GetBool(env, pendingState, context->isPending);
    context->objectPtr = fileAssetAni->fileAssetPtr;
    CHECK_COND_WITH_RET_MESSAGE(env, context->objectPtr != nullptr, ANI_INVALID_ARGS, "context->objectPtr is nullptr");

    PhotoAccessHelperSetPendingExecute(env, context);
    return PhotoAccessHelperSetPendingComplete(env, context);
}
} // namespace OHOS::Media
