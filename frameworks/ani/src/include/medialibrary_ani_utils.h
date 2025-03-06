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

#ifndef FRAMEWORKS_ANI_SRC_INCLUDE_MEDIALIBRARY_ANI_UTILS_H
#define FRAMEWORKS_ANI_SRC_INCLUDE_MEDIALIBRARY_ANI_UTILS_H

#include <memory>
#include <set>
#include <vector>

#include "ani.h"
#include "ani_error.h"
#include "datashare_predicates.h"
#include "datashare_result_set.h"
#include "file_asset.h"
#include "file_asset_ani.h"
#include "location_column.h"
#include "media_column.h"
#include "media_library_enum_ani.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_db_const.h"
#include "medialibrary_ani_log.h"
#include "photo_album_ani.h"
#include "photo_album_column.h"
#include "rdb_store.h"

#ifdef ANI_ASSERT
#undef ANI_ASSERT
#endif

// Temporary debugging
#define DEBUG_LOG_T(fmt, ...) \
    do {                                  \
        printf("\033[1;31mTEMPORARY\033[0m [%s:%d] %s" fmt "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__);  \
    } while (0)
// Temporary debugging end

#define CHECK_ARGS_WITH_MESSAGE(env, cond, msg)                                                 \
    do {                                                                                        \
        if (!(cond)) {                                                                          \
            AniError::ThrowError(env, JS_ERR_PARAMETER_INVALID, __FUNCTION__, __LINE__, msg);   \
            return nullptr;                                                                     \
        }                                                                                       \
    } while (0)

#define CHECK_COND_WITH_MESSAGE(env, cond, msg)                                                 \
    do {                                                                                        \
        if (!(cond)) {                                                                          \
            AniError::ThrowError(env, OHOS_INVALID_PARAM_CODE, __FUNCTION__, __LINE__, msg);    \
            return nullptr;                                                                     \
        }                                                                                       \
    } while (0)

#define CHECK_COND_WITH_RET_MESSAGE(env, cond, ret, msg)                                        \
    do {                                                                                        \
        if (!(cond)) {                                                                          \
            AniError::ThrowError(env, OHOS_INVALID_PARAM_CODE, __FUNCTION__, __LINE__, msg);    \
            return ret;                                                                         \
        }                                                                                       \
    } while (0)

#define ANI_ASSERT(env, cond, msg) CHECK_ARGS_WITH_MESSAGE(env, cond, msg)

#define ASSERT_NULLPTR_CHECK(env, result)       \
    do {                                        \
        if ((result) == nullptr) {              \
            GetUndefiend(env, &(result));       \
            return result;                      \
        }                                       \
    } while (0)

#define CHECK_NULL_PTR_RETURN_UNDEFINED(env, ptr, ret, message)     \
    do {                                                            \
        if ((ptr) == nullptr) {                                     \
            ANI_ERR_LOG(message);                                   \
            GetUndefiend(env, &(ret));                              \
            return ret;                                             \
        }                                                           \
    } while (0)

#define CHECK_NULL_PTR_RETURN_VOID(ptr, message)    \
    do {                                            \
        if ((ptr) == nullptr) {                     \
            ANI_ERR_LOG(message);                   \
            return;                                 \
        }                                           \
    } while (0)
#define CHECK_IF_EQUAL(condition, errMsg, ...)      \
    do {                                            \
        if (!(condition)) {                         \
            ANI_ERR_LOG(errMsg, ##__VA_ARGS__);     \
            return;                                 \
        }                                           \
    } while (0)

#define CHECK_COND_RET(cond, ret, message, ...)                     \
    do {                                                            \
        if (!(cond)) {                                              \
            ANI_ERR_LOG(message, ##__VA_ARGS__);                    \
            return ret;                                             \
        }                                                           \
    } while (0)

#define CHECK_STATUS_RET(cond, message)                             \
    do {                                                            \
        ani_status __ret = (cond);                                  \
        if (__ret != ANI_OK) {                                      \
            ANI_ERR_LOG(message);                                   \
            DEBUG_LOG_T("Ani Status [%d], %s", __ret, message);     \
            return __ret;                                           \
        }                                                           \
    } while (0)

#define CHECK_NULLPTR_RET(ret)                                      \
    do {                                                            \
        if ((ret) == nullptr) {                                     \
            return nullptr;                                         \
        }                                                           \
    } while (0)

#define CHECK_ARGS_BASE(env, cond, err, retVal)                     \
    do {                                                            \
        if ((cond) != ANI_OK) {                                    \
            AniError::ThrowError(env, err, __FUNCTION__, __LINE__); \
            return retVal;                                          \
        }                                                           \
    } while (0)

#define CHECK_ARGS(env, cond, err) CHECK_ARGS_BASE(env, cond, err, nullptr)

#define CHECK_ARGS_THROW_INVALID_PARAM(env, cond) CHECK_ARGS(env, cond, OHOS_INVALID_PARAM_CODE)

#define CHECK_ARGS_RET_VOID(env, cond, err)                         \
    do {                                                            \
        if ((cond) != ANI_OK) {                                     \
            AniError::ThrowError(env, err, __FUNCTION__, __LINE__); \
            return;                                                 \
        }                                                           \
    } while (0)

#define CHECK_COND(env, cond, err)                                  \
    do {                                                            \
        if (!(cond)) {                                              \
            AniError::ThrowError(env, err, __FUNCTION__, __LINE__); \
            return nullptr;                                         \
        }                                                           \
    } while (0)

#define RETURN_ANI_UNDEFINED(env)                                         \
    do {                                                                  \
        ani_ref result = nullptr;                                         \
        CHECK_ARGS(env, GetUndefiend(env, &result), JS_INNER_FAIL);       \
        return result;                                                    \
    } while (0)

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))

// Error codes
const int32_t ERR_DEFAULT = 0;
const int32_t ERR_MEM_ALLOCATION = 2;
const int32_t ERR_INVALID_OUTPUT = 3;

const int32_t TRASH_SMART_ALBUM_ID = 1;
const std::string TRASH_SMART_ALBUM_NAME = "TrashAlbum";
const int32_t FAVORIT_SMART_ALBUM_ID = 2;
const std::string FAVORIT_SMART_ALBUM_NAME = "FavoritAlbum";

const std::string API_VERSION = "api_version";

const std::string PENDING_STATUS = "pending";

enum NapiAssetType {
    TYPE_DEFAULT = 0,
    TYPE_AUDIO = 1,
    TYPE_PHOTO = 2,
    TYPE_ALBUM = 3,
};

enum AlbumType {
    TYPE_VIDEO_ALBUM = 0,
    TYPE_IMAGE_ALBUM = 1,
    TYPE_NONE = 2,
};

enum FetchOptionType {
    ASSET_FETCH_OPT = 0,
    ALBUM_FETCH_OPT = 1
};

enum HiddenPhotosDisplayMode {
    ASSETS_MODE = 0,
    ALBUMS_MODE = 1
};

/* Util class used by ani methods for making call to js callback function */
class MediaLibraryAniUtils {
public:
    static const std::unordered_map<std::string, std::pair<ResultSetDataType, std::string>> &GetTypeMap()
    {
        static const std::unordered_map<std::string, std::pair<ResultSetDataType, std::string>> TYPE_MAP = {
            {MEDIA_DATA_DB_ID, {TYPE_INT32, "fileId"}},
            {MEDIA_DATA_DB_FILE_PATH, {TYPE_STRING, "data"}},
            {MEDIA_DATA_DB_MEDIA_TYPE, {TYPE_INT32, "mediaType"}},
            {MEDIA_DATA_DB_NAME, {TYPE_STRING, "displayName"}},
            {MEDIA_DATA_DB_SIZE, {TYPE_INT64, "size"}},
            {MEDIA_DATA_DB_DATE_ADDED, {TYPE_INT64, "dateAddedMs"}},
            {MEDIA_DATA_DB_DATE_MODIFIED, {TYPE_INT64, "dateModifiedMs"}},
            {MEDIA_DATA_DB_DURATION, {TYPE_INT64, "duration"}},
            {MEDIA_DATA_DB_WIDTH, {TYPE_INT32, "width"}},
            {MEDIA_DATA_DB_HEIGHT, {TYPE_INT32, "height"}},
            {MEDIA_DATA_DB_DATE_TAKEN, {TYPE_INT64, "dateTaken"}},
            {MEDIA_DATA_DB_ORIENTATION, {TYPE_INT32, "orientation"}},
            {MEDIA_DATA_DB_IS_FAV, {TYPE_INT32, "isFavorite"}},
            {MEDIA_DATA_DB_TITLE, {TYPE_STRING, "title"}},
            {MEDIA_DATA_DB_POSITION, {TYPE_INT32, "position"}},
            {MEDIA_DATA_DB_DATE_TRASHED, {TYPE_INT64, "dateTrashedMs"}},
            {MediaColumn::MEDIA_HIDDEN, {TYPE_INT32, "hidden"}},
            {PhotoColumn::PHOTO_USER_COMMENT, {TYPE_STRING, "userComment"}},
            {PhotoColumn::CAMERA_SHOT_KEY, {TYPE_STRING, "cameraShotKey"}},
            {PhotoColumn::PHOTO_DATE_YEAR, {TYPE_STRING, "dateYear"}},
            {PhotoColumn::PHOTO_DATE_MONTH, {TYPE_STRING, "dateMonth"}},
            {PhotoColumn::PHOTO_DATE_DAY, {TYPE_STRING, "dateDay"}},
            {MEDIA_DATA_DB_TIME_PENDING, {TYPE_INT64, "pending"}},
            {PhotoColumn::PHOTO_SUBTYPE, {TYPE_INT32, "subtype"}},
            {PhotoColumn::MOVING_PHOTO_EFFECT_MODE, {TYPE_INT32, "movingPhotoEffectMode"}},
            {PhotoColumn::PHOTO_DYNAMIC_RANGE_TYPE, {TYPE_INT32, "dynamicRangeType"}},
            {PhotoColumn::PHOTO_THUMBNAIL_READY, {TYPE_INT64, "thumbnailModifiedMs"}},
            {PhotoColumn::PHOTO_LCD_SIZE, {TYPE_STRING, "lcdSize"}},
            {PhotoColumn::PHOTO_THUMB_SIZE, {TYPE_STRING, "thmSize"}},
            {PhotoColumn::PHOTO_OWNER_ALBUM_ID, {TYPE_INT32, "ownerAlbumId"}},
            {MEDIA_DATA_DB_COUNT, {TYPE_INT32, "count"}},
            {PhotoAlbumColumns::ALBUM_ID, {TYPE_INT32, "albumId"}},
            {PhotoAlbumColumns::ALBUM_TYPE, {TYPE_INT32, "albumType"}},
            {PhotoAlbumColumns::ALBUM_SUBTYPE, {TYPE_INT32, "albumSubType"}},
            {PhotoAlbumColumns::ALBUM_NAME, {TYPE_STRING, "albumName"}},
            {PhotoAlbumColumns::ALBUM_COVER_URI, {TYPE_STRING, "coverUri"}},
            {PhotoAlbumColumns::ALBUM_COUNT, {TYPE_INT32, "count"}},
            {PhotoAlbumColumns::ALBUM_IMAGE_COUNT, {TYPE_INT32, "imageCount"}},
            {PhotoAlbumColumns::ALBUM_VIDEO_COUNT, {TYPE_INT32, "videoCount"}},
        };
        return TYPE_MAP;
    }

    static const std::unordered_map<std::string, std::pair<ResultSetDataType, std::string>>& GetTimeTypeMap()
    {
        static const std::unordered_map<std::string, std::pair<ResultSetDataType, std::string>> TIME_TYPE_MAP = {
            {MEDIA_DATA_DB_DATE_ADDED, {TYPE_INT64, "dateAdded"}},
            {MEDIA_DATA_DB_DATE_MODIFIED, {TYPE_INT64, "dateModified"}},
            {MEDIA_DATA_DB_DATE_TRASHED, {TYPE_INT64, "dateTrashed"}},
        };
        return TIME_TYPE_MAP;
    }

    static ani_boolean isArray(ani_env *env, ani_object object);
    static ani_boolean isUndefined(ani_env *env, ani_object object);

    static ani_status GetBool(ani_env *env, ani_boolean arg, bool &value);
    static ani_status GetBool(ani_env *env, ani_object arg, bool &value);

    static ani_status GetByte(ani_env *env, ani_byte arg, uint8_t &value);
    static ani_status GetByte(ani_env *env, ani_object arg, uint8_t &value);

    static ani_status GetShort(ani_env *env, ani_short arg, int16_t &value);
    static ani_status GetShort(ani_env *env, ani_object arg, int16_t &value);

    static ani_status GetInt32(ani_env *env, ani_int arg, int32_t &value);
    static ani_status GetInt32(ani_env *env, ani_object arg, int32_t &value);

    static ani_status GetUint32(ani_env *env, ani_int arg, uint32_t &value);
    static ani_status GetUint32(ani_env *env, ani_object arg, uint32_t &value);

    static ani_status GetInt64(ani_env *env, ani_long arg, int64_t &value);
    static ani_status GetInt64(ani_env *env, ani_object arg, int64_t &value);

    static ani_status GetFloat(ani_env *env, ani_float arg, float &value);
    static ani_status GetFloat(ani_env *env, ani_object arg, float &value);

    static ani_status GetDouble(ani_env *env, ani_double arg, double &value);
    static ani_status GetDouble(ani_env *env, ani_object arg, double &value);

    static ani_status GetString(ani_env *env, ani_string arg, std::string &str);
    static ani_status GetString(ani_env *env, ani_object arg, std::string &str);
    static ani_status ToAniString(ani_env *env, const std::string &str, ani_string &aniStr);
    static ani_status ToAniInt(ani_env *env, const std::int32_t &int32, ani_int &aniInt);
    static ani_status ToAniLong(ani_env *env, const std::int64_t &int64, ani_long &aniLong);
    static ani_status ToAniDouble(ani_env *env, const double &arg, ani_double &aniDouble);
    static ani_status GetParamStringWithLength(ani_env *env, ani_string arg, int32_t maxLen, std::string &str);
    static ani_status GetParamStringPathMax(ani_env *env, ani_string arg, std::string &str);
    static ani_status GetParamStringPathMax(ani_env *env, ani_object arg, std::string &str);

    static ani_status GetUint32Array(ani_env *env, ani_object arg, std::vector<uint32_t> &array);
    static ani_status ToAniInt32Array(ani_env *env, const std::vector<uint32_t> &array, ani_object &aniArray);
    static ani_status GetStringArray(ani_env *env, ani_object arg, std::vector<std::string> &array);
    static ani_status ToAniStringArray(ani_env *env, const std::vector<std::string> &array, ani_object &aniArray);

    static ani_status GetProperty(ani_env *env, ani_object arg, const std::string &propName, std::string &propValue);
    static ani_status GetProperty(ani_env *env, ani_object arg, const std::string &propName, ani_object &propObj);
    static ani_status GetArrayProperty(ani_env *env, ani_object arg, const std::string &propName,
        std::vector<std::string> &array);

    static ani_status GetUriArrayFromAssets(ani_env *env, ani_object arg, std::vector<std::string> &array);
    static ani_status ToFileAssetAniArray(ani_env *env,
        std::vector<std::unique_ptr<FileAsset>> &array, ani_object &aniArray);

    static ani_status GetPhotoAlbumAniArray(ani_env *env, ani_object arg, std::vector<PhotoAlbumAni*> &array);
    static ani_status ToPhotoAlbumAniArray(ani_env *env, std::vector<unique_ptr<PhotoAlbum>> &array,
        ani_object &aniArray);

    static ani_status GetArrayBuffer(ani_env *env, ani_object arg, std::unique_ptr<uint8_t[]> &buffer, size_t &size);

    static ani_status GetOptionalStringPathMaxField(ani_env *env, ani_object src,
        const std::string &fieldName, std::string &value);
    static ani_status GetOptionalEnumInt32Field(ani_env *env, ani_object src, const std::string &fieldName,
        EnumTypeInt32 enumType, int32_t &value);
    static ani_status GetOptionalEnumStringField(ani_env *env, ani_object src, const std::string &fieldName,
        EnumTypeString enumType, std::string &value);
    static std::unordered_map<std::string, std::variant<int32_t, bool, std::string>> GetCreateOptions(
        ani_env *env, ani_object src);
    static std::unordered_map<std::string, std::variant<int32_t, bool, std::string>> GetPhotoCreateOptions(
        ani_env *env, ani_object src);

    template <class AniContext>
    static ani_status GetPredicate(ani_env *env, const ani_object fetchOptions, const std::string &propName,
        AniContext &context, FetchOptionType fetchOptType);
    template <class AniContext>
    static bool HandleSpecialPredicate(AniContext &context,
        std::shared_ptr<DataShare::DataShareAbsPredicates> &predicate, FetchOptionType fetchOptType);

    template <class AniContext>
    static ani_status GetFetchOption(ani_env *env, ani_object fetchOptions, FetchOptionType fetchOptType,
        AniContext &context);

    template <class AniContext>
    static bool GetLocationPredicate(AniContext &context,
        std::shared_ptr<DataShare::DataShareAbsPredicates> &predicate);

    static int TransErrorCode(const std::string &Name, std::shared_ptr<DataShare::DataShareResultSet> resultSet);

    static int TransErrorCode(const std::string &Name, int error);

    static void HandleError(ani_env *env, int error, ani_error &errorObj, const std::string &Name);

    static void CreateAniErrorObject(ani_env *env, ani_error &errorObj, const int32_t errCode,
        const std::string &errMsg);

    static void UriAppendKeyValue(std::string &uri, const std::string &key, const std::string &value);

    static ani_status AddDefaultAssetColumns(ani_env *env, std::vector<std::string> &fetchColumn,
        std::function<bool(const std::string &columnName)> isValidColumn, NapiAssetType assetType,
        const PhotoAlbumSubType subType = PhotoAlbumSubType::USER_GENERIC);

    static int32_t GetSystemAlbumPredicates(const PhotoAlbumSubType subType,
        DataShare::DataSharePredicates &predicates, const bool hiddenOnly);
    static int32_t GetUserAlbumPredicates(const int32_t albumId,
        DataShare::DataSharePredicates &predicates, const bool hiddenOnly);
    static int32_t GetAnalysisAlbumPredicates(const int32_t albumId, DataShare::DataSharePredicates &predicates);
    static int32_t GetFeaturedSinglePortraitAlbumPredicates(
        const int32_t albumId, DataShare::DataSharePredicates &predicates);
    static int32_t GetPortraitAlbumPredicates(const int32_t albumId, DataShare::DataSharePredicates &predicates);
    static int32_t GetAllLocationPredicates(DataShare::DataSharePredicates &predicates);
    static int32_t GetSourceAlbumPredicates(const int32_t albumId, DataShare::DataSharePredicates &predicates,
        const bool hiddenOnly);
    static bool IsFeaturedSinglePortraitAlbum(std::string albumName, DataShare::DataSharePredicates &predicates);
    static bool IsSystemApp();

    EXPORT static std::string ParseResultSet2JsonStr(std::shared_ptr<DataShare::DataShareResultSet> resultSet,
        const std::vector<std::string> &cloumns);

    static std::string ParseAnalysisFace2JsonStr(std::shared_ptr<DataShare::DataShareResultSet> resultSet,
        const std::vector<std::string> &cloumns);

    static std::string GetStringValueByColumn(std::shared_ptr<DataShare::DataShareResultSet> resultSet,
        const std::string columnName);
};

} // namespace Media
} // namespace OHOS

#endif  // FRAMEWORKS_ANI_SRC_INCLUDE_MEDIALIBRARY_ANI_UTILS_H