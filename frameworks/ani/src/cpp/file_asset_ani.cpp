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

#include "ani_class_name.h"
#include "datashare_values_bucket.h"
#include "file_asset_ani.h"
#include "medialibrary_ani_log.h"
#include "medialibrary_ani_utils.h"
#include "medialibrary_db_const.h"
#include "media_log.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "thumbnail_const.h"
#include "thumbnail_manager_ani.h"
#include "userfile_manager_types.h"
#include "medialibrary_ani_utils.h"
#include "userfile_client.h"
#include "userfilemgr_uri.h"
#include "datashare_predicates.h"
#include "values_bucket.h"
#include "vision_column.h"
#include "vision_total_column.h"
#include "vision_aesthetics_score_column.h"
#include "vision_album_column.h"
#include "vision_column_comm.h"
#include "vision_column.h"
#include "vision_composition_column.h"
#include "vision_face_tag_column.h"
#include "vision_head_column.h"
#include "vision_image_face_column.h"
#include "vision_label_column.h"
#include "vision_object_column.h"
#include "vision_ocr_column.h"
#include "vision_photo_map_column.h"
#include "vision_pose_column.h"
#include "vision_recommendation_column.h"
#include "vision_saliency_detect_column.h"
#include "vision_segmentation_column.h"
#include "vision_total_column.h"
#include "vision_video_label_column.h"
#include "vision_multi_crop_column.h"
#include "location_column.h"
#include "locale_config.h"
#include "userfile_manager_types.h"
#include "medialibrary_ani_log.h"

using namespace OHOS::Media;
using namespace std;
using namespace OHOS::DataShare;

static const std::string ANALYSIS_NO_RESULTS = "[]";
static const std::string ANALYSIS_INIT_VALUE = "0";
static const std::string ANALYSIS_STATUS_ANALYZED = "Analyzed, no results";

constexpr int32_t IS_HIDDEN = 1;
constexpr int32_t NOT_HIDDEN = 0;

constexpr int32_t IS_FAV = 1;
constexpr int32_t NOT_FAV = 0;

thread_local std::shared_ptr<FileAsset> FileAssetAni::sFileAsset_ = nullptr;

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

ani_status FileAssetAni::FileAssetAniInit(ani_env *env)
{
    static const char *className = ANI_CLASS_PHOTO_ASSET.c_str();
    ani_class cls;
    ani_status status = env->FindClass(className, &cls);
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to find class: %{public}s", className);
        return status;
    }

    std::array methods = {
        ani_native_function {"create", nullptr, reinterpret_cast<void *>(FileAssetAni::Constructor)},
        ani_native_function {"set", nullptr, reinterpret_cast<void *>(FileAssetAni::Set)},
        ani_native_function {"get", nullptr, reinterpret_cast<void *>(FileAssetAni::Get)},
        ani_native_function {"commitModifySync", nullptr, reinterpret_cast<void *>(FileAssetAni::CommitModify)},
        ani_native_function {"setUserCommentSync", nullptr, reinterpret_cast<void *>(FileAssetAni::SetUserComment)},
        ani_native_function {"openSync", nullptr, reinterpret_cast<void *>(FileAssetAni::Open)},
        ani_native_function {"closeSync", nullptr, reinterpret_cast<void *>(FileAssetAni::Close)},
        ani_native_function {"getAnalysisDataSync", nullptr, reinterpret_cast<void *>(FileAssetAni::GetAnalysisData)},
        ani_native_function {"setHiddenSync", nullptr, reinterpret_cast<void *>(FileAssetAni::SetHidden)},
        ani_native_function {"setFavoriteSync", nullptr, reinterpret_cast<void *>(FileAssetAni::SetFavorite)},
        ani_native_function {"getThumbnailSync", nullptr, reinterpret_cast<void *>(FileAssetAni::GetThumbnail)},
    };

    status = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to bind native methods to: %{public}s", className);
        return status;
    }
    return ANI_OK;
}

ani_object FileAssetAni::Constructor([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_class clazz)
{
    std::shared_ptr<FileAsset> fileAssetPtr = std::make_shared<FileAsset>();
    std::unique_ptr<FileAssetAni> nativeFileAssetAni = std::make_unique<FileAssetAni>(fileAssetPtr);

    static const char *className = ANI_CLASS_PHOTO_ASSET.c_str();
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        ANI_ERR_LOG("Failed to find class: %{public}s", className);
        ani_object nullobj = nullptr;
        return nullobj;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "J:V", &ctor)) {
        ANI_ERR_LOG("Failed to find method: %{public}s", "ctor");
        ani_object nullobj = nullptr;
        return nullobj;
    }

    ani_object fileAsset_object;
    if (ANI_OK != env->Object_New(cls, ctor, &fileAsset_object,
        reinterpret_cast<ani_long>(nativeFileAssetAni.release()))) {
        ANI_ERR_LOG("New FileAsset Fail");
    }
    return fileAsset_object;
}

shared_ptr<FileAsset> FileAssetAni::GetFileAssetInstance() const
{
    return fileAssetPtr;
}

FileAssetAni* FileAssetAni::CreatePhotoAsset(ani_env *env, std::shared_ptr<FileAsset> &fileAsset)
{
    if (fileAsset == nullptr || fileAsset->GetResultNapiType() != ResultNapiType::TYPE_PHOTOACCESS_HELPER) {
        ANI_ERR_LOG("Unsupported fileAsset");
        return nullptr;
    }

    std::unique_ptr<FileAssetAni> fileAssetAni = std::make_unique<FileAssetAni>(fileAsset);
    return fileAssetAni.release();
}

FileAssetAni* FileAssetAni::CreateFileAsset(ani_env *env, std::unique_ptr<FileAsset> &fileAsset)
{
    if (fileAsset == nullptr || fileAsset->GetResultNapiType() != ResultNapiType::TYPE_PHOTOACCESS_HELPER) {
        ANI_ERR_LOG("Unsupported fileAsset");
        return nullptr;
    }
    sFileAsset_ = std::move(fileAsset);
    std::unique_ptr<FileAssetAni> fileAssetAni = std::make_unique<FileAssetAni>(sFileAsset_);
    sFileAsset_ = nullptr;
    return fileAssetAni.release();
}

ani_object FileAssetAni::Wrap(ani_env *env, FileAssetAni* fileAssetAni)
{
    static const char *className = ANI_CLASS_PHOTO_ASSET.c_str();
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        ANI_ERR_LOG("Failed to find class: %{public}s", className);
        ani_object nullobj = nullptr;
        return nullobj;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "J:V", &ctor)) {
        ANI_ERR_LOG("Failed to find method: %{public}s", "ctor");
        ani_object nullobj = nullptr;
        return nullobj;
    }

    ani_object fileAsset_object;
    if (ANI_OK != env->Object_New(cls, ctor, &fileAsset_object, reinterpret_cast<ani_long>(fileAssetAni))) {
        ANI_ERR_LOG("New FileAsset Fail");
    }
    return fileAsset_object;
}

FileAssetAni* FileAssetAni::Unwrap(ani_env *env, ani_object object)
{
    ani_long fileAsset;
    if (ANI_OK != env->Object_GetFieldByName_Long(object, "nativePhotoAsset", &fileAsset)) {
        return nullptr;
    }
    return reinterpret_cast<FileAssetAni*>(fileAsset);
}

void FileAssetAni::Set(ani_env *env, ani_object object, ani_string member, ani_string value)
{
    auto fileAssetAni = Unwrap(env, object);
    if (fileAssetAni == nullptr || fileAssetAni->fileAssetPtr == nullptr) {
        ANI_ERR_LOG("fileAssetAni is nullptr");
        return;
    }

    std::string memberStr;
    MediaLibraryAniUtils::GetString(env, member, memberStr);
    std::string valueStr;
    MediaLibraryAniUtils::GetString(env, value, valueStr);

    auto fileAssetPtr = fileAssetAni->fileAssetPtr;
    auto resultNapiType = fileAssetPtr->GetResultNapiType();
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
        PhotoColumn::PHOTO_POSITION,
        MediaColumn::MEDIA_DATE_TRASHED,
        MediaColumn::MEDIA_HIDDEN,
        PhotoColumn::PHOTO_USER_COMMENT,
        PhotoColumn::CAMERA_SHOT_KEY,
        PhotoColumn::MOVING_PHOTO_EFFECT_MODE,
        PhotoColumn::SUPPORTED_WATERMARK_TYPE,
        PENDING_STATUS,
        MEDIA_DATA_DB_DATE_TRASHED_MS,
    };

    if (SYSTEM_API_KEYS.find(key) != SYSTEM_API_KEYS.end() && !MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This key can only be used by system apps");
        return E_CHECK_SYSTEMAPP_FAIL;
    }
    return E_SUCCESS;
}

static ani_ref HandleDateTransitionKey(ani_env *env, const string &key, const shared_ptr<FileAsset> &fileAssetPtr)
{
    ani_ref aniResult = nullptr;
    if (fileAssetPtr->GetMemberMap().count(key) == 0) {
        AniError::ThrowError(env, JS_E_FILE_KEY);
        return aniResult;
    }

    auto m = fileAssetPtr->GetMemberMap().at(key);
    if (m.index() == MEMBER_TYPE_INT64) {
        ani_long aniLong;
        MediaLibraryAniUtils::ToAniLong(env, get<int64_t>(m), aniLong);
        return reinterpret_cast<ani_ref>(aniLong);
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

static ani_ref HandleGettingSpecialKey(ani_env *env, const string &key, const shared_ptr<FileAsset> &fileAssetPtr)
{
    if (key == PENDING_STATUS) {
        if (fileAssetPtr->GetTimePending() == 0) {
            return reinterpret_cast<ani_ref>(false);
        } else {
            return reinterpret_cast<ani_ref>(true);
        }
    }

    return nullptr;
}

static void UpdateDetailTimeByDateTaken(ani_env *env, const shared_ptr<FileAsset> &fileAssetPtr,
    const string &detailTime)
{
    string uri = PAH_UPDATE_PHOTO;
    MediaLibraryAniUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri updateAssetUri(uri);
    DataSharePredicates predicates;
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(PhotoColumn::PHOTO_DETAIL_TIME, detailTime);
    predicates.SetWhereClause(MediaColumn::MEDIA_ID + " = ? ");
    predicates.SetWhereArgs({ MediaFileUtils::GetIdFromUri(fileAssetPtr->GetUri()) });
    int32_t changedRows = UserFileClient::Update(updateAssetUri, predicates, valuesBucket);
    if (changedRows < 0) {
        ANI_ERR_LOG("Failed to modify detail time, err: %{public}d", changedRows);
        AniError::ThrowError(env, JS_INNER_FAIL);
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

static ani_ref HandleGettingDetailTimeKey(ani_env *env, const shared_ptr<FileAsset> &fileAssetPtr)
{
    ani_ref aniResult = nullptr;
    auto detailTimeValue = fileAssetPtr->GetMemberMap().at(PhotoColumn::PHOTO_DETAIL_TIME);
    if (detailTimeValue.index() == MEMBER_TYPE_STRING && !get<string>(detailTimeValue).empty()) {
        ani_string aniDetailTime {};
        env->String_NewUTF8(get<string>(detailTimeValue).c_str(), ANI_AUTO_LENGTH, &aniDetailTime);
        return reinterpret_cast<ani_ref>(aniDetailTime);
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
            string detailTime = MediaFileUtils::StrCreateTime(PhotoColumn::PHOTO_DETAIL_TIME_FORMAT, dateTaken);
            ani_string aniDetailTime {};
            MediaLibraryAniUtils::ToAniString(env, detailTime, aniDetailTime);
            UpdateDetailTimeByDateTaken(env, fileAssetPtr, detailTime);
            return reinterpret_cast<ani_ref>(aniDetailTime);
        } else {
            AniError::ThrowError(env, JS_INNER_FAIL);
        }
    }
    return aniResult;
}

ani_ref FileAssetAni::Get(ani_env *env, ani_object object, ani_string member)
{
    auto fileAssetAni = Unwrap(env, object);
    if (fileAssetAni == nullptr || fileAssetAni->GetFileAssetInstance() == nullptr) {
        ANI_ERR_LOG("fileAssetAni is nullptr");
        return nullptr;
    }
    auto fileAssetPtr = fileAssetAni->fileAssetPtr;

    std::string inputKey;
    MediaLibraryAniUtils::GetString(env, member, inputKey);

    if (CheckSystemApiKeys(env, inputKey) < 0) {
        return nullptr;
    }

    ani_ref aniResult = nullptr;
    env->GetUndefined(&aniResult);

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
        return reinterpret_cast<ani_ref>(aniString);
    } else if (m.index() == MEMBER_TYPE_INT32) {
        ani_int aniInt {};
        MediaLibraryAniUtils::ToAniInt(env, std::get<int32_t>(m), aniInt);
        return reinterpret_cast<ani_ref>(aniInt);
    } else if (m.index() == MEMBER_TYPE_INT64) {
        ani_long aniLong {};
        MediaLibraryAniUtils::ToAniLong(env, std::get<int64_t>(m), aniLong);
        return reinterpret_cast<ani_ref>(aniLong);
    } else {
        AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID);
        return aniResult;
    }
    return aniResult;
}

static void BuildCommitModifyUriApi10(FileAssetContext *context, string &uri)
{
    if (context->objectPtr->GetMediaType() == MEDIA_TYPE_IMAGE ||
        context->objectPtr->GetMediaType() == MEDIA_TYPE_VIDEO) {
        uri = (context->resultNapiType == ResultNapiType::TYPE_USERFILE_MGR) ? UFM_UPDATE_PHOTO : PAH_UPDATE_PHOTO;
    } else if (context->objectPtr->GetMediaType() == MEDIA_TYPE_AUDIO) {
        uri = UFM_UPDATE_AUDIO;
    }
}

static void BuildCommitModifyValuesBucket(FileAssetContext* context,
    OHOS::DataShare::DataShareValuesBucket &valuesBucket)
{
    const auto fileAsset = context->objectPtr;
    valuesBucket.Put(MediaColumn::MEDIA_TITLE, fileAsset->GetTitle());
}

void FileAssetAni::CommitModify(ani_env *env, ani_object object)
{
    auto fileAssetAni = Unwrap(env, object);
    if (fileAssetAni == nullptr || fileAssetAni->GetFileAssetInstance() == nullptr) {
        ANI_ERR_LOG("fileAssetAni is nullptr");
        return;
    }

    auto fileAssetPtr = fileAssetAni->GetFileAssetInstance();
    unique_ptr<FileAssetContext> context = make_unique<FileAssetContext>();
    context->objectPtr = fileAssetPtr;
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;

    string uri;
    BuildCommitModifyUriApi10(context.get(), uri);
    MediaLibraryAniUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));

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

ani_double FileAssetAni::Open(ani_env *env, ani_object object, ani_string mode)
{
    ani_double aniDouble {};
    auto fileAssetAni = Unwrap(env, object);
    if (fileAssetAni == nullptr || fileAssetAni->GetFileAssetInstance() == nullptr) {
        ANI_ERR_LOG("fileAssetAni is nullptr");
        return ANI_ERROR;
    }

    auto fileAssetPtr = fileAssetAni->GetFileAssetInstance();
    unique_ptr<FileAssetContext> context = make_unique<FileAssetContext>();
    context->objectPtr = fileAssetPtr;

    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return aniDouble;
    }
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

    if (context->objectPtr->GetTimePending() == UNCREATE_FILE_TIMEPENDING) {
        MediaFileUtils::UriAppendKeyValue(fileUri, MediaColumn::MEDIA_TIME_PENDING,
            to_string(context->objectPtr->GetTimePending()));
    }
    Uri openFileUri(fileUri);
    int32_t retVal = UserFileClient::OpenFile(openFileUri, modeStr);
    if (retVal <= 0) {
        context->SaveError(retVal);
        ANI_ERR_LOG("File open asset failed, ret: %{public}d", retVal);
    } else {
        context->fd = retVal;
        if (modeStr.find('w') != string::npos) {
            context->objectPtr->SetOpenStatus(retVal, OPEN_TYPE_WRITE);
        } else {
            context->objectPtr->SetOpenStatus(retVal, OPEN_TYPE_READONLY);
        }
        if (context->objectPtr->GetTimePending() == UNCREATE_FILE_TIMEPENDING) {
            context->objectPtr->SetTimePending(UNCLOSE_FILE_TIMEPENDING);
        }
    }
    MediaLibraryAniUtils::ToAniDouble(env, context->fd, aniDouble);
    return aniDouble;
}

static bool CheckFileOpenStatus(FileAssetContext *context, int fd)
{
    auto fileAssetPtr = context->objectPtr;
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

void FileAssetAni::Close(ani_env *env, ani_object object, ani_double fd)
{
    auto fileAssetAni = Unwrap(env, object);
    if (fileAssetAni == nullptr || fileAssetAni->GetFileAssetInstance() == nullptr) {
        ANI_ERR_LOG("fileAssetAni is nullptr");
        return;
    }

    auto fileAssetPtr = fileAssetAni->GetFileAssetInstance();
    unique_ptr<FileAssetContext> context = make_unique<FileAssetContext>();
    context->objectPtr = fileAssetPtr;
    UniqueFd unifd(context->fd);
    if (!CheckFileOpenStatus(context.get(), unifd.Get())) {
        return;
    }
    string closeUri;
    if (context->objectPtr->GetMediaType() == MEDIA_TYPE_IMAGE ||
        context->objectPtr->GetMediaType() == MEDIA_TYPE_VIDEO) {
        closeUri = PAH_CLOSE_PHOTO;
    } else {
        context->SaveError(-EINVAL);
        return;
    }
    MediaLibraryAniUtils::UriAppendKeyValue(closeUri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    MediaLibraryAniUtils::UriAppendKeyValue(closeUri, MediaColumn::MEDIA_TIME_PENDING,
        to_string(context->objectPtr->GetTimePending()));
    Uri closeAssetUri(closeUri);
    int32_t ret = UserFileClient::Insert(closeAssetUri, context->valuesBucket);
    if (ret != E_SUCCESS) {
        context->SaveError(ret);
        return;
    } else {
        if (context->objectPtr->GetTimePending() == UNCLOSE_FILE_TIMEPENDING) {
            context->objectPtr->SetTimePending(0);
        }
    }
}

ani_object FileAssetAni::GetThumbnail(ani_env *env, ani_object object, ani_object size)
{
    auto fileAssetAni = Unwrap(env, object);
    if (fileAssetAni == nullptr || fileAssetAni->GetFileAssetInstance() == nullptr) {
        ANI_ERR_LOG("fileAssetAni is nullptr");
        return nullptr;
    }

    auto fileAssetPtr = fileAssetAni->GetFileAssetInstance();
    unique_ptr<FileAssetContext> context = make_unique<FileAssetContext>();
    context->objectPtr = fileAssetPtr;
    
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    context->size.width = DEFAULT_THUMB_SIZE;
    context->size.height = DEFAULT_THUMB_SIZE;

    if (MediaLibraryAniUtils::isUndefined(env, size) == ANI_FALSE) {
        ani_class cls;
        if (ANI_OK != env->FindClass(ANI_CLASS_SIZE.c_str(), &cls)) {
            return nullptr;
        }
        ani_method heightGetter;
        ani_method widthGetter;
        if (ANI_OK != env->Class_FindMethod(cls, "<get>height", nullptr, &heightGetter)) {
            ANI_ERR_LOG("Class_FindMethod Fail %{public}s", ANI_CLASS_SIZE.c_str());
        }
        if (ANI_OK != env->Class_FindMethod(cls, "<get>width", nullptr, &widthGetter)) {
            ANI_ERR_LOG("Class_FindMethod Fail %{public}s", ANI_CLASS_SIZE.c_str());
        }

        ani_double heightValue;
        ani_double widthValue;
        if (ANI_OK != env->Object_CallMethod_Double(size, heightGetter, &heightValue)) {
            return nullptr;
        }
        if (ANI_OK != env->Object_CallMethod_Double(size, widthGetter, &widthValue)) {
            return nullptr;
        }
        double height;
        double width;
        MediaLibraryAniUtils::GetDouble(env, heightValue, height);
        MediaLibraryAniUtils::GetDouble(env, widthValue, width);

        context->size.width = width;
        context->size.height = height;
    }
    std::string path = fileAssetPtr->GetPath();
#ifndef MEDIALIBRARY_COMPATIBILITY
    if (path.empty() && !fileAssetPtr->GetRelativePath().empty() && !fileAssetPtr->GetDisplayName().empty()) {
        path = ROOT_MEDIA_DIR + fileAssetPtr->GetRelativePath() + fileAssetPtr->GetDisplayName();
    }
#endif
    context->pixelmap = ThumbnailManagerAni::QueryThumbnail(fileAssetPtr->GetUri(), context->size, path);

    return nullptr;
}

void FileAssetAni::SetUserComment([[maybe_unused]] ani_env *env, ani_object object, ani_string userComment)
{
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
    cout << "userCommentStr is " << userCommentStr << endl;

    auto fileAssetPtr = fileAssetAni->GetFileAssetInstance();
    unique_ptr<FileAssetContext> context = make_unique<FileAssetContext>();
    context->objectPtr = fileAssetPtr;
    context->resultNapiType = ResultNapiType::TYPE_PHOTOACCESS_HELPER;
    
    string uri = UFM_SET_USER_COMMENT;
    MediaLibraryAniUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri editUserCommentUri(uri);
    DataSharePredicates predicates;
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(PhotoColumn::PHOTO_USER_COMMENT, userCommentStr);
    predicates.SetWhereClause(MediaColumn::MEDIA_ID + " = ? ");
    predicates.SetWhereArgs({to_string(fileAssetPtr->GetId())});
    int32_t changedRows = UserFileClient::Update(editUserCommentUri, predicates, valuesBucket);
    if (changedRows < 0) {
        context->SaveError(changedRows);
        ANI_ERR_LOG("Failed to modify user comment, err: %{public}d", changedRows);
    } else {
        fileAssetPtr->SetUserComment(userCommentStr);
        context->changedRows = changedRows;
    }
}

ani_string FileAssetAni::GetAnalysisData([[maybe_unused]] ani_env *env, ani_object object, ani_enum_item analysisType)
{
    ani_string aniString {};
    auto fileAssetAni = Unwrap(env, object);
    if (fileAssetAni == nullptr || fileAssetAni->fileAssetPtr == nullptr) {
        ANI_ERR_LOG("fileAssetAni is nullptr");
        return aniString;
    }

    int32_t value;
    MediaLibraryEnumAni::EnumGetValueInt32(env, EnumTypeInt32::AnalysisTypeAni, analysisType, value);

    auto fileAssetPtr = fileAssetAni->GetFileAssetInstance();
    unique_ptr<FileAssetContext> context = make_unique<FileAssetContext>();
    context->objectPtr = fileAssetPtr;
    context->analysisType = value;
    if (ANALYSIS_SOURCE_INFO_MAP.find(context->analysisType) == ANALYSIS_SOURCE_INFO_MAP.end()) {
        ANI_ERR_LOG("Invalid analysisType");
        return aniString;
    }
    auto &analysisInfo = ANALYSIS_SOURCE_INFO_MAP.at(context->analysisType);
    DataSharePredicates predicates;
    if (context->analysisType == ANALYSIS_HUMAN_FACE_TAG) {
        string onClause = VISION_IMAGE_FACE_TABLE + "." + TAG_ID + " = " + VISION_FACE_TAG_TABLE + "." + TAG_ID;
        predicates.InnerJoin(VISION_IMAGE_FACE_TABLE)->On({ onClause });
    }
    string fileId = to_string(fileAssetPtr->GetId());
    if (context->analysisType == ANALYSIS_DETAIL_ADDRESS) {
        string language = Global::I18n::LocaleConfig::GetSystemLanguage();
        vector<string> onClause = { PhotoColumn::PHOTOS_TABLE + "." + PhotoColumn::PHOTO_LATITUDE + " = " +
            GEO_KNOWLEDGE_TABLE + "." + LATITUDE + " AND " + PhotoColumn::PHOTOS_TABLE + "." +
            PhotoColumn::PHOTO_LONGITUDE + " = " + GEO_KNOWLEDGE_TABLE + "." + LONGITUDE + " AND " +
            GEO_KNOWLEDGE_TABLE + "." + LANGUAGE + " = \'" + language + "\'" };
        predicates.LeftOuterJoin(GEO_KNOWLEDGE_TABLE)->On(onClause);
        predicates.EqualTo(PhotoColumn::PHOTOS_TABLE + "." + MediaColumn::MEDIA_ID, fileId);
    } else {
        predicates.EqualTo(MediaColumn::MEDIA_ID, fileId);
    }
    Uri uri(analysisInfo.uriStr);
    std::vector<std::string> fetchColumn = analysisInfo.fetchColumn;
    int errCode = 0;
    auto resultSet = UserFileClient::Query(uri, predicates, fetchColumn, errCode);
    context->analysisData = context->analysisType == ANALYSIS_FACE ?
        MediaLibraryAniUtils::ParseAnalysisFace2JsonStr(resultSet, fetchColumn) :
        MediaLibraryAniUtils::ParseResultSet2JsonStr(resultSet, fetchColumn);
    if (context->analysisData == ANALYSIS_NO_RESULTS) {
        Uri uri(PAH_QUERY_ANA_TOTAL);
        DataSharePredicates predicates;
        std::vector<std::string> fetchColumn = { analysisInfo.fieldStr };
        predicates.EqualTo(MediaColumn::MEDIA_ID, fileId);
        auto fieldValue = UserFileClient::Query(uri, predicates, fetchColumn, errCode);
        string value = MediaLibraryAniUtils::ParseResultSet2JsonStr(fieldValue, fetchColumn);
        if (strstr(value.c_str(), ANALYSIS_INIT_VALUE.c_str()) == NULL) {
            context->analysisData = ANALYSIS_STATUS_ANALYZED;
        }
        MediaLibraryAniUtils::ToAniString(env, value, aniString);
        return aniString;
    }
    return aniString;
}

void FileAssetAni::SetHidden([[maybe_unused]] ani_env *env, ani_object object, ani_boolean hiddenState)
{
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
    context->objectPtr = fileAssetPtr;
    if (context->objectPtr->GetMediaType() != MEDIA_TYPE_IMAGE &&
        context->objectPtr->GetMediaType() != MEDIA_TYPE_VIDEO) {
        context->SaveError(-EINVAL);
        return;
    }

    string uri = UFM_HIDE_PHOTO;
    MediaLibraryAniUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri updateAssetUri(uri);
    DataSharePredicates predicates;
    predicates.In(MediaColumn::MEDIA_ID, vector<string>({ context->objectPtr->GetUri() }));
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MediaColumn::MEDIA_HIDDEN, context->isHidden ? IS_HIDDEN : NOT_HIDDEN);

    int32_t changedRows = UserFileClient::Update(updateAssetUri, predicates, valuesBucket);
    if (changedRows < 0) {
        ANI_ERR_LOG("Failed to modify hidden state, err: %{public}d", changedRows);
    } else {
        context->SaveError(changedRows);
        context->objectPtr->SetHidden(context->isHidden);
        context->changedRows = changedRows;
    }
}

void FileAssetAni::SetFavorite([[maybe_unused]] ani_env *env, ani_object object, ani_boolean favoriteState)
{
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
    context->objectPtr = fileAssetPtr;
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