/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "file_asset_napi.h"

#include <cstring>

#include "abs_shared_result_set.h"
#include "hitrace_meter.h"
#include "data_ability_predicates.h"
#include "fetch_result.h"
#include "hilog/log.h"
#include "media_file_utils.h"
#include "medialibrary_napi_log.h"
#include "medialibrary_napi_utils.h"
#include "rdb_errno.h"
#include "string_ex.h"

using OHOS::HiviewDFX::HiLog;
using OHOS::HiviewDFX::HiLogLabel;
using namespace std;
using namespace OHOS::AppExecFwk;
using namespace OHOS::NativeRdb;
using std::string;

namespace OHOS {
namespace Media {
thread_local napi_ref FileAssetNapi::sConstructor_ = nullptr;
thread_local FileAsset *FileAssetNapi::sFileAsset_ = nullptr;
std::shared_ptr<DataShare::DataShareHelper> FileAssetNapi::sDataShareHelper_ = nullptr;
std::shared_ptr<MediaThumbnailHelper> FileAssetNapi::sThumbnailHelper_ = nullptr;
using CompleteCallback = napi_async_complete_callback;

FileAssetNapi::FileAssetNapi()
    : env_(nullptr), wrapper_(nullptr)
{
    fileId_ = DEFAULT_MEDIA_ID;
    fileUri_ = DEFAULT_MEDIA_URI;
    mimeType_ = DEFAULT_MEDIA_MIMETYPE;
    mediaType_ = DEFAULT_MEDIA_TYPE;
    title_ = DEFAULT_MEDIA_TITLE;
    size_ = DEFAULT_MEDIA_SIZE;
    albumId_ = DEFAULT_ALBUM_ID;
    albumName_ = DEFAULT_ALBUM_NAME;
    dateAdded_ = DEFAULT_MEDIA_DATE_ADDED;
    dateModified_ = DEFAULT_MEDIA_DATE_MODIFIED;
    orientation_ = DEFAULT_MEDIA_ORIENTATION;
    width_ = DEFAULT_MEDIA_WIDTH;
    height_ = DEFAULT_MEDIA_HEIGHT;
    relativePath_ = DEFAULT_MEDIA_RELATIVE_PATH;
    album_ = DEFAULT_MEDIA_ALBUM;
    artist_ = DEFAULT_MEDIA_TITLE;
    filePath_ = DEFAULT_MEDIA_PATH;
    displayName_ = DEFAULT_MEDIA_NAME;
    duration_ = DEFAULT_MEDIA_DURATION;
    parent_ = DEFAULT_PARENT_ID;
    dateTaken_ = DEFAULT_MEDIA_DATE_TAKEN;
}

FileAssetNapi::~FileAssetNapi()
{
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
        wrapper_ = nullptr;
    }
    NAPI_DEBUG_LOG("FileAssetNapi destructor exit");
}

void FileAssetNapi::FileAssetNapiDestructor(napi_env env, void *nativeObject, void *finalize_hint)
{
    FileAssetNapi *fileAssetObj = reinterpret_cast<FileAssetNapi*>(nativeObject);
    if (fileAssetObj != nullptr) {
        delete fileAssetObj;
        fileAssetObj = nullptr;
    }
    NAPI_DEBUG_LOG("FileAssetNapiDestructor exit");
}

napi_value FileAssetNapi::Init(napi_env env, napi_value exports)
{
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;
    napi_property_descriptor file_asset_props[] = {
        DECLARE_NAPI_GETTER("id", JSGetFileId),
        DECLARE_NAPI_GETTER("uri", JSGetFileUri),
        DECLARE_NAPI_GETTER("mediaType", JSGetMediaType),
        DECLARE_NAPI_GETTER_SETTER("displayName", JSGetFileDisplayName, JSSetFileDisplayName),
        DECLARE_NAPI_GETTER_SETTER("relativePath", JSGetRelativePath, JSSetRelativePath),
        DECLARE_NAPI_GETTER("parent", JSParent),
        DECLARE_NAPI_GETTER("size", JSGetSize),
        DECLARE_NAPI_GETTER("dateAdded", JSGetDateAdded),
        DECLARE_NAPI_GETTER("dateTrashed", JSGetDateTrashed),
        DECLARE_NAPI_GETTER("dateModified", JSGetDateModified),
        DECLARE_NAPI_GETTER("dateTaken", JSGetDateTaken),
        DECLARE_NAPI_GETTER("mimeType", JSGetMimeType),
        DECLARE_NAPI_GETTER_SETTER("title", JSGetTitle, JSSetTitle),
        DECLARE_NAPI_GETTER("artist", JSGetArtist),
        DECLARE_NAPI_GETTER("audioAlbum", JSGetAlbum),
        DECLARE_NAPI_GETTER("width", JSGetWidth),
        DECLARE_NAPI_GETTER("height", JSGetHeight),
        DECLARE_NAPI_GETTER_SETTER("orientation", JSGetOrientation, JSSetOrientation),
        DECLARE_NAPI_GETTER("duration", JSGetDuration),
        DECLARE_NAPI_GETTER("albumId", JSGetAlbumId),
        DECLARE_NAPI_GETTER("albumUri", JSGetAlbumUri),
        DECLARE_NAPI_GETTER("albumName", JSGetAlbumName),
        DECLARE_NAPI_FUNCTION("isDirectory", JSIsDirectory),
        DECLARE_NAPI_FUNCTION("commitModify", JSCommitModify),
        DECLARE_NAPI_FUNCTION("open", JSOpen),
        DECLARE_NAPI_FUNCTION("close", JSClose),
        DECLARE_NAPI_FUNCTION("getThumbnail", JSGetThumbnail),
        DECLARE_NAPI_FUNCTION("favorite", JSFavorite),
        DECLARE_NAPI_FUNCTION("isFavorite", JSIsFavorite),
        DECLARE_NAPI_FUNCTION("trash", JSTrash),
        DECLARE_NAPI_FUNCTION("isTrash", JSIsTrash),
    };

    status = napi_define_class(env, FILE_ASSET_NAPI_CLASS_NAME.c_str(), NAPI_AUTO_LENGTH,
                               FileAssetNapiConstructor, nullptr,
                               sizeof(file_asset_props) / sizeof(file_asset_props[PARAM0]),
                               file_asset_props, &ctorObj);
    if (status == napi_ok) {
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            status = napi_set_named_property(env, exports, FILE_ASSET_NAPI_CLASS_NAME.c_str(), ctorObj);
            if (status == napi_ok) {
                return exports;
            }
        }
    }
    return nullptr;
}

// Constructor callback
napi_value FileAssetNapi::FileAssetNapiConstructor(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<FileAssetNapi> obj = std::make_unique<FileAssetNapi>();
        if (obj != nullptr) {
            obj->env_ = env;
            if (sFileAsset_ != nullptr) {
                obj->UpdateFileAssetInfo();
            }

            if (obj->sDataShareHelper_ == nullptr) {
                obj->sDataShareHelper_ = sDataShareHelper_;
                CHECK_NULL_PTR_RETURN_UNDEFINED(env, obj->sDataShareHelper_, result, "Helper creation failed");
            }

            if (obj->sThumbnailHelper_ == nullptr) {
                obj->sThumbnailHelper_ = std::make_shared<MediaThumbnailHelper>();
            }
            status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                               FileAssetNapi::FileAssetNapiDestructor, nullptr, &(obj->wrapper_));
            if (status == napi_ok) {
                obj.release();
                return thisVar;
            } else {
                NAPI_ERR_LOG("Failure wrapping js to native napi, status: %{public}d", status);
            }
        }
    }

    return result;
}

napi_value FileAssetNapi::CreateFileAsset(napi_env env, FileAsset &iAsset,
    std::shared_ptr<DataShare::DataShareHelper> abilityHelper)
{
    StartTrace(HITRACE_TAG_OHOS, "CreateFileAsset");

    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;

    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sDataShareHelper_ = abilityHelper;
        sFileAsset_ = &iAsset;
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sFileAsset_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            return result;
        } else {
            NAPI_ERR_LOG("Failed to create file asset instance, status: %{public}d", status);
        }
    }

    napi_get_undefined(env, &result);
    FinishTrace(HITRACE_TAG_OHOS);

    return result;
}

std::string FileAssetNapi::GetFileDisplayName() const
{
    return displayName_;
}

std::string FileAssetNapi::GetRelativePath() const
{
    return relativePath_;
}

std::string FileAssetNapi::GetTitle() const
{
    return title_;
}

std::string FileAssetNapi::GetFileUri() const
{
    return fileUri_;
}

int32_t FileAssetNapi::GetFileId() const
{
    return fileId_;
}

Media::MediaType FileAssetNapi::GetMediaType() const
{
    return mediaType_;
}

int32_t FileAssetNapi::GetOrientation() const
{
    return orientation_;
}

std::string FileAssetNapi::GetNetworkId() const
{
    return MediaFileUtils::GetNetworkIdFromUri(fileUri_);
}

bool FileAssetNapi::IsFavorite() const
{
    return isFavorite_;
}

void FileAssetNapi::SetFavorite(bool isFavorite)
{
    isFavorite_ = isFavorite;
}

bool FileAssetNapi::IsTrash() const
{
    return isTrash_;
}

void FileAssetNapi::SetTrash(bool isTrash)
{
    isTrash_ = isTrash;
}

napi_value FileAssetNapi::JSGetFileId(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    FileAssetNapi* obj = nullptr;
    int32_t id;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &jsResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return jsResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        id = obj->fileId_;
        napi_create_int32(env, id, &jsResult);
    }

    return jsResult;
}

napi_value FileAssetNapi::JSGetFileUri(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    FileAssetNapi* obj = nullptr;
    string uri = "";
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &jsResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return jsResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        uri = obj->fileUri_;
        napi_create_string_utf8(env, uri.c_str(), NAPI_AUTO_LENGTH, &jsResult);
    }

    return jsResult;
}

napi_value FileAssetNapi::JSGetFilePath(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    FileAssetNapi* obj = nullptr;
    string path = "";
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &jsResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return jsResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        path = obj->filePath_;
        napi_create_string_utf8(env, path.c_str(), NAPI_AUTO_LENGTH, &jsResult);
    }

    return jsResult;
}

napi_value FileAssetNapi::JSGetFileDisplayName(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    FileAssetNapi* obj = nullptr;
    string displayName = "";
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &jsResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return jsResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        displayName = obj->displayName_;
        napi_create_string_utf8(env, displayName.c_str(), NAPI_AUTO_LENGTH, &jsResult);
    }

    return jsResult;
}

napi_value FileAssetNapi::JSSetFileDisplayName(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value undefinedResult = nullptr;
    FileAssetNapi* obj = nullptr;
    napi_valuetype valueType = napi_undefined;
    size_t res = 0;
    char buffer[FILENAME_MAX];
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_ONE, "requires 1 parameter");

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        if (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_string) {
            NAPI_ERR_LOG("Invalid arguments type! valueType: %{public}d", valueType);
            return undefinedResult;
        }
        status = napi_get_value_string_utf8(env, argv[PARAM0], buffer, FILENAME_MAX, &res);
        if (status == napi_ok) {
            obj->displayName_ = string(buffer);
        }
    }

    return undefinedResult;
}

napi_value FileAssetNapi::JSGetMimeType(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    FileAssetNapi* obj = nullptr;
    string mimeType = "";
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &jsResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return jsResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        mimeType = obj->mimeType_;
        napi_create_string_utf8(env, mimeType.c_str(), NAPI_AUTO_LENGTH, &jsResult);
    }

    return jsResult;
}

napi_value FileAssetNapi::JSGetMediaType(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    FileAssetNapi* obj = nullptr;
    int32_t mediaType;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &jsResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return jsResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        mediaType = static_cast<int32_t>(obj->mediaType_);
        napi_create_int32(env, mediaType, &jsResult);
    }

    return jsResult;
}

napi_value FileAssetNapi::JSGetTitle(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    FileAssetNapi* obj = nullptr;
    string title = "";
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &jsResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return jsResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        title = obj->title_;
        napi_create_string_utf8(env, title.c_str(), NAPI_AUTO_LENGTH, &jsResult);
    }

    return jsResult;
}
napi_value FileAssetNapi::JSSetTitle(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value undefinedResult = nullptr;
    FileAssetNapi* obj = nullptr;
    napi_valuetype valueType = napi_undefined;
    size_t res = 0;
    char buffer[SIZE];
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    napi_get_undefined(env, &undefinedResult);
    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_ONE, "requires 1 parameter");
    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        if (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_string) {
            NAPI_ERR_LOG("Invalid arguments type! valueType: %{public}d", valueType);
            return undefinedResult;
        }
        status = napi_get_value_string_utf8(env, argv[PARAM0], buffer, SIZE, &res);
        if (status == napi_ok) {
            obj->title_ = string(buffer);
        }
    }
    return undefinedResult;
}

napi_value FileAssetNapi::JSGetSize(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    FileAssetNapi* obj = nullptr;
    int64_t size;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &jsResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return jsResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        size = obj->size_;
        napi_create_int64(env, size, &jsResult);
    }

    return jsResult;
}

napi_value FileAssetNapi::JSGetAlbumId(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    FileAssetNapi* obj = nullptr;
    int32_t albumId;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &jsResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return jsResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        albumId = obj->albumId_;
        napi_create_int32(env, albumId, &jsResult);
    }

    return jsResult;
}

napi_value FileAssetNapi::JSGetAlbumName(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    FileAssetNapi* obj = nullptr;
    string albumName = "";
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &jsResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return jsResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        albumName = obj->albumName_;
        napi_create_string_utf8(env, albumName.c_str(), NAPI_AUTO_LENGTH, &jsResult);
    }

    return jsResult;
}

napi_value FileAssetNapi::JSGetDateAdded(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    FileAssetNapi* obj = nullptr;
    int64_t dateAdded;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &jsResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return jsResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        dateAdded = obj->dateAdded_;
        napi_create_int64(env, dateAdded, &jsResult);
    }

    return jsResult;
}

napi_value FileAssetNapi::JSGetDateTrashed(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    FileAssetNapi* obj = nullptr;
    int64_t dateTrashed;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &jsResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{private}d", status);
        return jsResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        dateTrashed = obj->dateTrashed_;
        napi_create_int64(env, dateTrashed, &jsResult);
    }

    return jsResult;
}

napi_value FileAssetNapi::JSGetDateModified(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    FileAssetNapi* obj = nullptr;
    int64_t dateModified;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &jsResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return jsResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        dateModified = obj->dateModified_;
        napi_create_int64(env, dateModified, &jsResult);
    }

    return jsResult;
}

napi_value FileAssetNapi::JSGetOrientation(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    FileAssetNapi* obj = nullptr;
    int32_t orientation;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &jsResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return jsResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        orientation = obj->orientation_;
        napi_create_int32(env, orientation, &jsResult);
    }

    return jsResult;
}
napi_value FileAssetNapi::JSSetOrientation(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value undefinedResult = nullptr;
    FileAssetNapi* obj = nullptr;
    napi_valuetype valueType = napi_undefined;
    int32_t orientation;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    napi_get_undefined(env, &undefinedResult);

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_ONE, "requires 1 parameter");

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        if (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_number) {
            NAPI_ERR_LOG("Invalid arguments type! valueType: %{public}d", valueType);
            return undefinedResult;
        }

        status = napi_get_value_int32(env, argv[PARAM0], &orientation);
        if (status == napi_ok) {
            obj->orientation_ = orientation;
        }
    }

    return undefinedResult;
}

napi_value FileAssetNapi::JSGetWidth(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    FileAssetNapi* obj = nullptr;
    int32_t width;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &jsResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return jsResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        width = obj->width_;
        napi_create_int32(env, width, &jsResult);
    }

    return jsResult;
}

napi_value FileAssetNapi::JSGetHeight(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    FileAssetNapi* obj = nullptr;
    int32_t height;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &jsResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return jsResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        height = obj->height_;
        napi_create_int32(env, height, &jsResult);
    }

    return jsResult;
}

napi_value FileAssetNapi::JSGetRelativePath(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    FileAssetNapi* obj = nullptr;
    string relativePath = "";
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &jsResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return jsResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        relativePath = obj->relativePath_;
        napi_create_string_utf8(env, relativePath.c_str(), NAPI_AUTO_LENGTH, &jsResult);
    }

    return jsResult;
}

napi_value FileAssetNapi::JSSetRelativePath(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value undefinedResult = nullptr;
    FileAssetNapi* obj = nullptr;
    napi_valuetype valueType = napi_undefined;
    size_t res = 0;
    char buffer[SIZE];
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    napi_get_undefined(env, &undefinedResult);
    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_ONE, "requires 1 parameter");
    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        if (napi_typeof(env, argv[PARAM0], &valueType) != napi_ok || valueType != napi_string) {
            NAPI_ERR_LOG("Invalid arguments type! valueType: %{public}d", valueType);
            return undefinedResult;
        }
        status = napi_get_value_string_utf8(env, argv[PARAM0], buffer, SIZE, &res);
        if (status == napi_ok) {
            obj->relativePath_ = string(buffer);
        }
    }
    return undefinedResult;
}
napi_value FileAssetNapi::JSGetAlbum(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    FileAssetNapi* obj = nullptr;
    string album = "";
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &jsResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return jsResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        album = obj->album_;
        napi_create_string_utf8(env, album.c_str(), NAPI_AUTO_LENGTH, &jsResult);
    }

    return jsResult;
}

napi_value FileAssetNapi::JSGetArtist(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    FileAssetNapi* obj = nullptr;
    string artist = "";
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &jsResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return jsResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        artist = obj->artist_;
        napi_create_string_utf8(env, artist.c_str(), NAPI_AUTO_LENGTH, &jsResult);
    }

    return jsResult;
}

napi_value FileAssetNapi::JSGetDuration(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    FileAssetNapi* obj = nullptr;
    int32_t duration;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &jsResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return jsResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        duration = obj->duration_;
        napi_create_int32(env, duration, &jsResult);
    }

    return jsResult;
}

napi_value FileAssetNapi::JSParent(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    FileAssetNapi* obj = nullptr;
    int32_t parent;
    napi_value thisVar = nullptr;
    napi_get_undefined(env, &jsResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return jsResult;
    }
    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        parent = obj->parent_;
        napi_create_int32(env, parent, &jsResult);
    }
    return jsResult;
}
napi_value FileAssetNapi::JSGetAlbumUri(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    FileAssetNapi* obj = nullptr;
    string albumUri = "";
    napi_value thisVar = nullptr;
    napi_get_undefined(env, &jsResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return jsResult;
    }
    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        albumUri = obj->albumUri_;
        napi_create_string_utf8(env, albumUri.c_str(), NAPI_AUTO_LENGTH, &jsResult);
    }
    return jsResult;
}
napi_value FileAssetNapi::JSGetDateTaken(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    FileAssetNapi* obj = nullptr;
    int64_t dateTaken;
    napi_value thisVar = nullptr;
    napi_get_undefined(env, &jsResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return jsResult;
    }
    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        dateTaken = obj->dateTaken_;
        napi_create_int64(env, dateTaken, &jsResult);
    }
    return jsResult;
}

static void JSCommitModifyExecute(FileAssetAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri updateAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_MODIFYASSET);
    Media::MediaType mediaType = context->objectInfo->GetMediaType();
    string notifyUri = MediaLibraryNapiUtils::GetMediaTypeUri(mediaType);
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    int32_t changedRows;
    valuesBucket.PutString(MEDIA_DATA_DB_URI, context->objectInfo->GetFileUri());

    if (MediaFileUtils::CheckTitle(context->objectInfo->GetTitle()) &&
        MediaFileUtils::CheckDisplayName(context->objectInfo->GetFileDisplayName())) {
        valuesBucket.PutString(MEDIA_DATA_DB_TITLE, context->objectInfo->GetTitle());
        valuesBucket.PutString(MEDIA_DATA_DB_NAME, context->objectInfo->GetFileDisplayName());
        if (context->objectInfo->GetOrientation() >= 0) {
            valuesBucket.PutInt(MEDIA_DATA_DB_ORIENTATION, context->objectInfo->GetOrientation());
        }
        valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, context->objectInfo->GetRelativePath());
        valuesBucket.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, context->objectInfo->GetMediaType());
        valuesBucket.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, MediaFileUtils::UTCTimeSeconds());
        predicates.SetWhereClause(MEDIA_DATA_DB_ID + " = " + std::to_string(context->objectInfo->GetFileId()));
        changedRows = context->objectInfo->sDataShareHelper_->Update(updateAssetUri, predicates, valuesBucket);
        if (changedRows < 0) {
            context->error = changedRows;
            NAPI_ERR_LOG("File asset modification failed, err: %{public}d", changedRows);
        } else {
            context->changedRows = changedRows;
            Uri modifyNotify(notifyUri);
            context->objectInfo->sDataShareHelper_->NotifyChange(modifyNotify);
        }
    } else {
        NAPI_ERR_LOG("JSCommitModify CheckDisplayName fail");
        context->error = DATA_ABILITY_VIOLATION_PARAMETERS;
    }
}

static void JSCommitModifyCompleteCallback(napi_env env, napi_status status,
                                           FileAssetAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    if (context->error == ERR_DEFAULT) {
        if (context->changedRows < 0) {
            MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, context->changedRows,
                                                         "File asset modification failed");
            napi_get_undefined(env, &jsContext->data);
        } else {
            napi_create_int32(env, context->changedRows, &jsContext->data);
            jsContext->status = true;
            napi_get_undefined(env, &jsContext->error);
        }
    } else {
        NAPI_ERR_LOG("JSCommitModify fail %{public}d", context->error);
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, context->error, "CheckDisplayName fail");
        napi_get_undefined(env, &jsContext->data);
    }
    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}
napi_value GetJSArgsForCommitModify(napi_env env, size_t argc, const napi_value argv[],
                                    FileAssetAsyncContext &asyncContext)
{
    const int32_t refCount = 1;
    napi_value result = nullptr;
    auto context = &asyncContext;
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, context, result, "Async context is null");
    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");
    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == PARAM0 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }
    napi_get_boolean(env, true, &result);
    return result;
}

napi_value FileAssetNapi::JSCommitModify(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;
    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ZERO || argc == ARGS_ONE), "requires 1 parameters maximum");
    napi_get_undefined(env, &result);
    unique_ptr<FileAssetAsyncContext> asyncContext = make_unique<FileAssetAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForCommitModify(env, argc, argv, *asyncContext);
        ASSERT_NULLPTR_CHECK(env, result);
        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSCommitModify");
        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<FileAssetAsyncContext*>(data);
                JSCommitModifyExecute(context);
            },
            reinterpret_cast<CompleteCallback>(JSCommitModifyCompleteCallback),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }
    return result;
}

static void JSOpenExecute(FileAssetAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    if (context->objectInfo->sDataShareHelper_ != nullptr) {
        DataShare::DataShareValueObject valueObject;
        string fileUri = context->objectInfo->GetFileUri();
        string mode = MEDIA_FILEMODE_READONLY;

        if (context->valuesBucket.GetObject(MEDIA_FILEMODE, valueObject)) {
            valueObject.GetString(mode);
        }

        Uri openFileUri(fileUri);
        int32_t retVal = context->objectInfo->sDataShareHelper_->OpenFile(openFileUri, mode);
        if (retVal <= 0) {
            context->error = retVal;
            NAPI_ERR_LOG("File open asset failed, ret: %{public}d", retVal);
        } else {
            context->fd = retVal;
        }
    } else {
        context->error = ERR_INVALID_OUTPUT;
        NAPI_ERR_LOG("Ability helper is null");
    }
}

static void JSOpenCompleteCallback(napi_env env, napi_status status,
                                   FileAssetAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    if (context->error == ERR_DEFAULT) {
        NAPI_DEBUG_LOG("return fd = %{public}d", context->fd);
        napi_create_int32(env, context->fd, &jsContext->data);
        napi_get_undefined(env, &jsContext->error);
        jsContext->status = true;
    } else {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, context->error, "File open asset failed");
        napi_get_undefined(env, &jsContext->data);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value GetJSArgsForOpen(napi_env env, size_t argc, const napi_value argv[],
                            FileAssetAsyncContext &asyncContext)
{
    NAPI_DEBUG_LOG("GetJSArgsForOpen IN");
    const int32_t refCount = 1;
    napi_value result = nullptr;
    auto context = &asyncContext;
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, context, result, "Async context is null");
    size_t res = 0;
    char buffer[SIZE];

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (i == PARAM0 && valueType == napi_string) {
            napi_get_value_string_utf8(env, argv[i], buffer, SIZE, &res);
        } else if (i == PARAM1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }
    context->valuesBucket.PutString(MEDIA_FILEMODE, string(buffer));
    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    NAPI_DEBUG_LOG("GetJSArgsForOpen OUT");
    return result;
}

napi_value FileAssetNapi::JSOpen(napi_env env, napi_callback_info info)
{
    NAPI_DEBUG_LOG("JSOpen IN");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;
    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");
    napi_get_undefined(env, &result);
    unique_ptr<FileAssetAsyncContext> asyncContext = make_unique<FileAssetAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForOpen(env, argc, argv, *asyncContext);
        ASSERT_NULLPTR_CHECK(env, result);
        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSOpen");
        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<FileAssetAsyncContext*>(data);
                JSOpenExecute(context);
            },
            reinterpret_cast<CompleteCallback>(JSOpenCompleteCallback),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }
    NAPI_DEBUG_LOG("JSOpen OUT");
    return result;
}

static void JSCloseExecute(FileAssetAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    if (context->objectInfo->sDataShareHelper_ != nullptr) {
        string abilityUri = MEDIALIBRARY_DATA_URI;
        Uri closeAssetUri(abilityUri + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_CLOSEASSET);
        DataShare::DataShareValueObject valueObject;
        int fd = 0;

        if (context->valuesBucket.GetObject(MEDIA_FILEDESCRIPTOR, valueObject)) {
            valueObject.GetInt(fd);
        }

        int32_t retVal = close(fd);
        if (retVal == DATA_ABILITY_SUCCESS) {
            retVal = context->objectInfo->sDataShareHelper_->Insert(closeAssetUri, context->valuesBucket);
            if (retVal == DATA_ABILITY_SUCCESS) {
                return;
            }
        }
        context->error = retVal;
        NAPI_ERR_LOG("File close asset failed %{public}d", retVal);
    } else {
        context->error = ERR_INVALID_OUTPUT;
        NAPI_ERR_LOG("Ability helper is null");
    }
}

static void JSCloseCompleteCallback(napi_env env, napi_status status,
                                    FileAssetAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    if (context->error == ERR_DEFAULT) {
        napi_create_int32(env, DATA_ABILITY_SUCCESS, &jsContext->data);
        napi_get_undefined(env, &jsContext->error);
        jsContext->status = true;
    } else {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, context->error,
            "File close asset failed");
        napi_get_undefined(env, &jsContext->data);
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value GetJSArgsForClose(napi_env env, size_t argc, const napi_value argv[],
                             FileAssetAsyncContext &asyncContext)
{
    const int32_t refCount = 1;
    napi_value result = nullptr;
    auto context = &asyncContext;
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, context, result, "Async context is null");
    int32_t fd = 0;

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (i == PARAM0 && valueType == napi_number) {
            napi_get_value_int32(env, argv[i], &fd);
            if (fd <= 0) {
                NAPI_ASSERT(env, false, "fd <= 0");
            }
        } else if (i == PARAM1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }
    context->valuesBucket.PutInt(MEDIA_FILEDESCRIPTOR, fd);
    context->valuesBucket.PutString(MEDIA_DATA_DB_URI, context->objectInfo->GetFileUri());
    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}

napi_value FileAssetNapi::JSClose(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;
    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");
    napi_get_undefined(env, &result);
    unique_ptr<FileAssetAsyncContext> asyncContext = make_unique<FileAssetAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForClose(env, argc, argv, *asyncContext);
        ASSERT_NULLPTR_CHECK(env, result);
        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSClose");
        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<FileAssetAsyncContext*>(data);
                JSCloseExecute(context);
            },
            reinterpret_cast<CompleteCallback>(JSCloseCompleteCallback),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }
    return result;
}
static string GetStringInfo(shared_ptr<DataShare::DataShareResultSet> resultSet, int pos)
{
    string res;
    int errorCode = resultSet->GetString(pos, res);
    if (errorCode != 0) {
        NAPI_ERR_LOG("Failed to get string column %{public}d %{public}d", pos, errorCode);
    }
    return res;
}

static unique_ptr<PixelMap> QueryThumbnail(shared_ptr<DataShare::DataShareHelper> &abilityHelper,
    shared_ptr<MediaThumbnailHelper> &thumbnailHelper, int32_t &fileId,
    std::string &uri, int32_t &width, int32_t &height)
{
    StartTrace(HITRACE_TAG_OHOS, "QueryThumbnail");
    if ((abilityHelper == nullptr) ||(thumbnailHelper == nullptr)) {
        return nullptr;
    }

    Uri queryUri1(uri + "?" + MEDIA_OPERN_KEYWORD + "=" + MEDIA_DATA_DB_THUMBNAIL + "&" + MEDIA_DATA_DB_WIDTH + "=" +
        to_string(width) + "&" + MEDIA_DATA_DB_HEIGHT + "=" + to_string(height));

    vector<string> columns;
    Size size = { .width = width, .height = height };
    columns.push_back(MEDIA_DATA_DB_ID);
    if (thumbnailHelper->isThumbnailFromLcd(size)) {
        columns.push_back(MEDIA_DATA_DB_LCD);
    } else {
        columns.push_back(MEDIA_DATA_DB_THUMBNAIL);
    }

    StartTrace(HITRACE_TAG_OHOS, "abilityHelper->Query");
    DataShare::DataSharePredicates predicates;
    shared_ptr<DataShare::DataShareResultSet> resultSet = abilityHelper->Query(queryUri1, predicates, columns);
    if (resultSet == nullptr) {
        NAPI_ERR_LOG("Query thumbnail error");
        return nullptr;
    }
    FinishTrace(HITRACE_TAG_OHOS);

    resultSet->GoToFirstRow();
    string id = GetStringInfo(resultSet, PARAM0);
    string thumbnailKey;
    if (!thumbnailHelper->isThumbnailFromLcd(size)) {
        thumbnailKey = GetStringInfo(resultSet, PARAM2);
    } else {
        thumbnailKey = GetStringInfo(resultSet, PARAM3);
    }

    if (to_string(fileId) != id) {
        NAPI_ERR_LOG("Query thumbnail id error as %{public}s", id.c_str());
        return nullptr;
    }

    if (thumbnailKey.empty()) {
        NAPI_ERR_LOG("thumbnailKey is empty");
        return nullptr;
    }

    NAPI_DEBUG_LOG("Query thumbnail id %{public}s with key %{public}s", id.c_str(), thumbnailKey.c_str());
    StartTrace(HITRACE_TAG_OHOS, "thumbnailHelper->GetThumbnail");
    auto ret = thumbnailHelper->GetThumbnail(thumbnailKey, size, uri);
    FinishTrace(HITRACE_TAG_OHOS);

    FinishTrace(HITRACE_TAG_OHOS);
    return ret;
}

static void JSGetThumbnailExecute(FileAssetAsyncContext* context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    if (context->objectInfo->sDataShareHelper_ != nullptr &&
        context->objectInfo->sThumbnailHelper_ != nullptr) {
        int32_t fileId = context->objectInfo->GetFileId();
        std::string uri = context->objectInfo->GetFileUri();
        context->pixelmap = QueryThumbnail(context->objectInfo->sDataShareHelper_,
            context->objectInfo->sThumbnailHelper_, fileId, uri,
            context->thumbWidth, context->thumbHeight);
    } else {
        context->error = ERR_INVALID_OUTPUT;
        NAPI_INFO_LOG("Ability helper is null");
    }
}

static void JSGetThumbnailCompleteCallback(napi_env env, napi_status status,
                                           FileAssetAsyncContext* context)
{
    StartTrace(HITRACE_TAG_OHOS, "JSGetThumbnailCompleteCallback");
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    if (context->error == ERR_DEFAULT) {
        if (context->pixelmap != nullptr) {
            jsContext->data = Media::PixelMapNapi::CreatePixelMap(env, context->pixelmap);
            napi_get_undefined(env, &jsContext->error);
            jsContext->status = true;
        } else {
            NAPI_ERR_LOG("negative ret");
            MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
                "Get thumbnail failed");
            napi_get_undefined(env, &jsContext->data);
        }
    } else {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
            "Ability helper or thumbnail helper is null");
        napi_get_undefined(env, &jsContext->data);
    }

    if (context->work != nullptr) {
        StartTrace(HITRACE_TAG_OHOS, "InvokeJSAsyncMethod");
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
        FinishTrace(HITRACE_TAG_OHOS);
    }
    delete context;

    FinishTrace(HITRACE_TAG_OHOS);
}

static void GetSizeInfo(napi_env env, napi_value configObj, std::string type, int32_t &result)
{
    napi_value item = nullptr;
    bool exist = false;
    napi_status status = napi_has_named_property(env, configObj, type.c_str(), &exist);
    if (status != napi_ok || !exist) {
        NAPI_ERR_LOG("can not find named property, status: %{public}d", status);
        return;
    }

    if (napi_get_named_property(env, configObj, type.c_str(), &item) != napi_ok) {
        NAPI_ERR_LOG("get named property fail");
        return;
    }

    if (napi_get_value_int32(env, item, &result) != napi_ok) {
        NAPI_ERR_LOG("get property value fail");
    }
}

napi_value GetJSArgsForGetThumbnail(napi_env env, size_t argc, const napi_value argv[],
                                    FileAssetAsyncContext &asyncContext)
{
    const int32_t refCount = 1;
    napi_value result = nullptr;
    auto context = &asyncContext;
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, context, result, "Async context is null");
    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    context->thumbWidth = Media::DEFAULT_THUMBNAIL_SIZE.width;
    context->thumbHeight = Media::DEFAULT_THUMBNAIL_SIZE.height;

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (i == PARAM0 && valueType == napi_object) {
            GetSizeInfo(env, argv[PARAM0], "width", context->thumbWidth);
            GetSizeInfo(env, argv[PARAM0], "height", context->thumbHeight);
        } else if (i == PARAM0 && valueType == napi_string) {
            size_t res = 0;
            char buffer[PATH_MAX];
            napi_status status = napi_get_value_string_utf8(env, argv[PARAM0], buffer, FILENAME_MAX, &res);
            if (status == napi_ok) {
                context->networkId = string(buffer);
            }
        } else if (i == PARAM0 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else if (i == PARAM1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }

    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}

napi_value FileAssetNapi::JSGetThumbnail(napi_env env, napi_callback_info info)
{
    StartTrace(HITRACE_TAG_OHOS, "JSGetThumbnail");

    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;
    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ZERO || argc == ARGS_ONE || argc == ARGS_TWO),
        "requires 2 parameters maximum");
    napi_get_undefined(env, &result);
    unique_ptr<FileAssetAsyncContext> asyncContext = make_unique<FileAssetAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForGetThumbnail(env, argc, argv, *asyncContext);
        ASSERT_NULLPTR_CHECK(env, result);
        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSGetThumbnail");
        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<FileAssetAsyncContext*>(data);
                JSGetThumbnailExecute(context);
            },
            reinterpret_cast<CompleteCallback>(JSGetThumbnailCompleteCallback),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    FinishTrace(HITRACE_TAG_OHOS);

    return result;
}

extern "C" __attribute__((visibility("default"))) void* OHOS_MEDIA_NativeGetThumbnail(const char* uri, void* context)
{
    if (uri == nullptr || context == nullptr) {
        NAPI_INFO_LOG("uri or context is null while trying call NativeGetThumbnail");
        return nullptr;
    }
    std::string uriStr(uri);
    auto runtimeContext = *reinterpret_cast<std::shared_ptr<OHOS::AbilityRuntime::Context>*>(context);
    auto ret = FileAssetNapi::NativeGetThumbnail(uriStr, runtimeContext);
    if (ret == nullptr) {
        NAPI_INFO_LOG("return value from NativeGetThumbnail is nullptr, uri: %{public}s", uri);
        return nullptr;
    }
    return ret.release();
}

std::unique_ptr<PixelMap> FileAssetNapi::NativeGetThumbnail(const string &uri,
    const std::shared_ptr<AbilityRuntime::Context> &context)
{
    // uri is dataability:///media/image/<id>/thumbnail/<width>/<height>
    auto index = uri.find("//");
    if (index == string::npos) {
        return nullptr;
    }
    auto tmpIdx = index + 2; // "//" len
    if (uri.substr(0, tmpIdx) != MEDIALIBRARY_DATA_ABILITY_PREFIX) {
        return nullptr;
    }
    index = uri.find("thumbnail");
    if (index == string::npos) {
        return nullptr;
    }
    auto fileUri = uri.substr(0, index - 1);
    tmpIdx = fileUri.rfind("/");
    int32_t fileId = 0;
    StrToInt(fileUri.substr(tmpIdx + 1), fileId);
    index += strlen("thumbnail");
    index = uri.find("/", index);
    if (index == string::npos) {
        return nullptr;
    }
    index += 1;
    tmpIdx = uri.find("/", index);
    if (index == string::npos) {
        return nullptr;
    }
    int32_t width = 0;
    StrToInt(uri.substr(index, tmpIdx - index), width);
    int32_t height = 0;
    StrToInt(uri.substr(tmpIdx + 1), height);

    auto dataAbilityHelper = DataShare::DataShareHelper::Creator(context, MEDIALIBRARY_DATA_URI);
    if (dataAbilityHelper == nullptr) {
        return nullptr;
    }
    if (sThumbnailHelper_ == nullptr) {
        sThumbnailHelper_ = std::make_shared<MediaThumbnailHelper>();
    }
    return QueryThumbnail(dataAbilityHelper, sThumbnailHelper_, fileId, fileUri, width, height);
}

static void JSFavoriteCallbackComplete(napi_env env, napi_status status,
                                       FileAssetAsyncContext* context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    CHECK_NULL_PTR_RETURN_VOID(jsContext, "jsContext context is null");
    jsContext->status = false;
    napi_get_undefined(env, &jsContext->data);
    if (context->error == ERR_DEFAULT) {
        jsContext->status = true;
        Media::MediaType mediaType = context->objectInfo->GetMediaType();
        string notifyUri = MediaLibraryNapiUtils::GetMediaTypeUri(mediaType);
        Uri modifyNotify(notifyUri);
        context->objectInfo->sDataShareHelper_->NotifyChange(modifyNotify);
    } else {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
            "Ability helper is null");
        napi_get_undefined(env, &jsContext->data);
    }
    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

static bool GetIsDirectoryiteNative(napi_env env, const FileAssetAsyncContext &fileContext)
{
    FileAssetAsyncContext *context = const_cast<FileAssetAsyncContext *>(&fileContext);
    if (context == nullptr) {
        NAPI_ERR_LOG("Async context is null");
        return false;
    }
    bool IsDirectory = false;
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri isDirectoryAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_ISDIRECTORY);
    context->valuesBucket.PutInt(Media::MEDIA_DATA_DB_ID, context->objectInfo->GetFileId());
    int retVal = context->objectInfo->sDataShareHelper_->Insert(isDirectoryAssetUri, context->valuesBucket);
    NAPI_DEBUG_LOG("GetIsDirectoryiteNative retVal = %{public}d", retVal);
    if (retVal == SUCCESS) {
        IsDirectory = true;
    }
    return IsDirectory;
}
static void JSIsDirectoryCallbackComplete(napi_env env, napi_status status,
                                          FileAssetAsyncContext* context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    CHECK_NULL_PTR_RETURN_VOID(jsContext, "jsContext context is null");
    jsContext->status = false;

    if (context->status) {
        napi_get_boolean(env, context->isDirectory, &jsContext->data);
        napi_get_undefined(env, &jsContext->error);
        jsContext->status = true;
    } else {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
                                                     "Ability helper is null");
        napi_get_undefined(env, &jsContext->data);
    }
    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

static napi_value GetJSArgsForIsDirectory(napi_env env, size_t argc, const napi_value argv[],
                                          FileAssetAsyncContext &asyncContext)
{
    string str = "";
    vector<string> strArr;
    string order = "";
    const int32_t refCount = 1;
    napi_value result;
    auto context = &asyncContext;
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, context, result, "Async context is null");
    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");
    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == PARAM0 && valueType == napi_object) {
        } else if (i == PARAM0 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else if (i == PARAM1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }
    napi_get_boolean(env, true, &result);
    return result;
}

napi_value FileAssetNapi::JSIsDirectory(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;
    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ZERO || argc == ARGS_ONE), "requires 2 parameters maximum");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    unique_ptr<FileAssetAsyncContext> asyncContext = make_unique<FileAssetAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, result, "asyncContext context is null");
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForIsDirectory(env, argc, argv, *asyncContext);
        ASSERT_NULLPTR_CHECK(env, result);
        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSClose");
        status = napi_create_async_work(env, nullptr, resource, [](napi_env env, void* data) {
                FileAssetAsyncContext* context = static_cast<FileAssetAsyncContext*>(data);
                if (context->objectInfo->sDataShareHelper_ != nullptr) {
                    context->isDirectory = GetIsDirectoryiteNative(env, *context);
                    context->status = true;
                } else {
                    context->status = false;
                }
            },
            reinterpret_cast<CompleteCallback>(JSIsDirectoryCallbackComplete),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }
    return result;
}

static void MakeIsFavorite(shared_ptr<DataShare::DataShareResultSet> resultSet, FileAssetAsyncContext* context)
{
    if (resultSet != nullptr) {
        // Create FetchResult object using the contents of resultSet
        unique_ptr<FetchResult> fetchFileResult = make_unique<FetchResult>(move(resultSet));
        if (fetchFileResult->GetCount() != 0) {
            unique_ptr<FileAsset> fileAsset = fetchFileResult->GetFirstObject();
            if (fileAsset == nullptr) {
                context->error = ERR_INVALID_OUTPUT;
                NAPI_ERR_LOG("MakeIsFavorite fileAsset is nullptr");
                return;
            }
            context->isFavorite = fileAsset->IsFavorite();
        } else {
            NAPI_ERR_LOG("have no fileAssets");
            context->error = ERR_INVALID_OUTPUT;
        }
    } else {
        NAPI_ERR_LOG("helper == nullptr");
        context->error = ERR_INVALID_OUTPUT;
    }
}

static void JSIsFavoriteExecute(FileAssetAsyncContext* context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    vector<string> columns, selectionArgs;
    string trashPrefix = MEDIA_DATA_DB_ID + " = ?";
    selectionArgs.insert(selectionArgs.begin(), to_string(context->objectInfo->GetFileId()));
    DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause(trashPrefix);
    predicates.SetWhereArgs(selectionArgs);
    string queryUri = MEDIALIBRARY_DATA_URI;
    Uri uri(queryUri);
    shared_ptr<DataShare::DataShareResultSet> resultSet;
    if (context->objectInfo->sDataShareHelper_ != nullptr) {
        resultSet = context->objectInfo->sDataShareHelper_->Query(uri, predicates, columns);
        MakeIsFavorite(resultSet, context);
    }
    return;
}

static void JSIsFavoriteCallbackComplete(napi_env env, napi_status status,
                                         FileAssetAsyncContext* context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    CHECK_NULL_PTR_RETURN_VOID(jsContext, "jsContext context is null");
    jsContext->status = false;
    if (context->error == ERR_DEFAULT) {
        napi_get_boolean(env, context->isFavorite, &jsContext->data);
        napi_get_undefined(env, &jsContext->error);
        jsContext->status = true;
    } else {
        NAPI_ERR_LOG("Get IsFavorite failed, ret: %{public}d", context->error);
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, context->error,
            "Ability helper is null");
        napi_get_undefined(env, &jsContext->data);
    }
    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value GetJSArgsForFavorite(napi_env env, size_t argc, const napi_value argv[],
                                FileAssetAsyncContext &asyncContext)
{
    const int32_t refCount = 1;
    napi_value result = nullptr;
    auto context = &asyncContext;
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, context, result, "Async context is null");
    bool isFavorite = false;
    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");
    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == PARAM0 && valueType == napi_boolean) {
            napi_get_value_bool(env, argv[i], &isFavorite);
        } else if (i == PARAM1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }
    context->isFavorite = isFavorite;
    napi_get_boolean(env, true, &result);
    return result;
}

static void JSFavouriteExecute(FileAssetAsyncContext* context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    if (context->objectInfo->sDataShareHelper_ != nullptr) {
        int32_t changedRows;
        DataShare::DataShareValuesBucket valuesBucket;
        valuesBucket.PutInt(SMARTALBUMMAP_DB_ALBUM_ID, FAVOURITE_ALBUM_ID_VALUES);
        valuesBucket.PutInt(SMARTALBUMMAP_DB_CHILD_ASSET_ID, context->objectInfo->GetFileId());
        if (context->isFavorite) {
            Uri AddAsseturi(MEDIALIBRARY_DATA_URI + "/"
                + MEDIA_SMARTALBUMMAPOPRN + "/" + MEDIA_SMARTALBUMMAPOPRN_ADDSMARTALBUM);
            changedRows =
                context->objectInfo->sDataShareHelper_->Insert(AddAsseturi, valuesBucket);
            context->changedRows = changedRows;
        } else {
            Uri RemoveAsseturi(MEDIALIBRARY_DATA_URI + "/"
                + MEDIA_SMARTALBUMMAPOPRN + "/" + MEDIA_SMARTALBUMMAPOPRN_REMOVESMARTALBUM);
            changedRows =
                context->objectInfo->sDataShareHelper_->Insert(RemoveAsseturi, valuesBucket);
            context->changedRows = changedRows;
        }
    } else {
        context->error = ERR_INVALID_OUTPUT;
        NAPI_ERR_LOG("Ability helper is null");
    }
}

napi_value FileAssetNapi::JSFavorite(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;
    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    unique_ptr<FileAssetAsyncContext> asyncContext = make_unique<FileAssetAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, result, "asyncContext context is null");
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForFavorite(env, argc, argv, *asyncContext);
        ASSERT_NULLPTR_CHECK(env, result);
        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSClose");
        status = napi_create_async_work(env, nullptr, resource, [](napi_env env, void* data) {
                FileAssetAsyncContext* context = static_cast<FileAssetAsyncContext*>(data);
                JSFavouriteExecute(context);
            },
            reinterpret_cast<CompleteCallback>(JSFavoriteCallbackComplete),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }
    return result;
}

static napi_value GetJSArgsForIsFavorite(napi_env env, size_t argc, const napi_value argv[],
                                         FileAssetAsyncContext &asyncContext)
{
    string str = "";
    vector<string> strArr;
    string order = "";
    const int32_t refCount = 1;
    napi_value result;
    auto context = &asyncContext;
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, context, result, "Async context is null");
    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");
    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == PARAM0 && valueType == napi_object) {
        } else if (i == PARAM0 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else if (i == PARAM1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }
    napi_get_boolean(env, true, &result);
    return result;
}

napi_value FileAssetNapi::JSIsFavorite(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;
    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ZERO || argc == ARGS_ONE), "requires 1 parameters maximum");
    napi_get_undefined(env, &result);
    unique_ptr<FileAssetAsyncContext> asyncContext = make_unique<FileAssetAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, result, "asyncContext context is null");
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForIsFavorite(env, argc, argv, *asyncContext);
        ASSERT_NULLPTR_CHECK(env, result);
        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSIsFavorite");
        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<FileAssetAsyncContext*>(data);
                JSIsFavoriteExecute(context);
            },
            reinterpret_cast<CompleteCallback>(JSIsFavoriteCallbackComplete),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }
    return result;
}

static void JSTrashExecute(FileAssetAsyncContext* context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    if (context->objectInfo->sDataShareHelper_ != nullptr) {
        DataShare::DataShareValuesBucket valuesBucket;
        valuesBucket.PutInt(SMARTALBUMMAP_DB_ALBUM_ID, TRASH_ALBUM_ID_VALUES);
        valuesBucket.PutInt(SMARTALBUMMAP_DB_CHILD_ASSET_ID, context->objectInfo->GetFileId());
        int32_t changedRows;
        if (context->isTrash) {
            Uri AddAsseturi(MEDIALIBRARY_DATA_URI + "/"
                + MEDIA_SMARTALBUMMAPOPRN + "/" + MEDIA_SMARTALBUMMAPOPRN_ADDSMARTALBUM);
            changedRows =
                context->objectInfo->sDataShareHelper_->Insert(AddAsseturi, valuesBucket);
            context->changedRows = changedRows;
        } else {
            Uri RemoveAsseturi(MEDIALIBRARY_DATA_URI + "/"
                + MEDIA_SMARTALBUMMAPOPRN + "/" + MEDIA_SMARTALBUMMAPOPRN_REMOVESMARTALBUM);
            changedRows =
                context->objectInfo->sDataShareHelper_->Insert(RemoveAsseturi, valuesBucket);
            context->changedRows = changedRows;
        }
    } else {
        context->error = ERR_INVALID_OUTPUT;
        NAPI_ERR_LOG("Ability helper is null");
    }
}

static void JSTrashCallbackComplete(napi_env env, napi_status status,
                                    FileAssetAsyncContext* context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    CHECK_NULL_PTR_RETURN_VOID(jsContext, "jsContext context is null");
    jsContext->status = false;
    napi_get_undefined(env, &jsContext->data);
    if (context->error == ERR_DEFAULT) {
        jsContext->status = true;
        Media::MediaType mediaType = context->objectInfo->GetMediaType();
        string notifyUri = MediaLibraryNapiUtils::GetMediaTypeUri(mediaType);
        Uri modifyNotify(notifyUri);
        context->objectInfo->sDataShareHelper_->NotifyChange(modifyNotify);
        NAPI_DEBUG_LOG("JSTrashCallbackComplete success");
    } else {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, context->error,
            "Ability helper is null");
    }
    if (context->work != nullptr) {
        NAPI_ERR_LOG("JSTrashCallbackComplete context->work != nullptr");
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value GetJSArgsForTrash(napi_env env, size_t argc, const napi_value argv[],
                             FileAssetAsyncContext &asyncContext)
{
    const int32_t refCount = 1;
    napi_value result = nullptr;
    auto context = &asyncContext;
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, context, result, "Async context is null");
    bool isTrash = false;
    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");
    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == PARAM0 && valueType == napi_boolean) {
            napi_get_value_bool(env, argv[i], &isTrash);
        } else if (i == PARAM1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }
    context->isTrash = isTrash;
    napi_get_boolean(env, true, &result);
    return result;
}

napi_value FileAssetNapi::JSTrash(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;
    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");

    napi_get_undefined(env, &result);
    unique_ptr<FileAssetAsyncContext> asyncContext = make_unique<FileAssetAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, result, "asyncContext context is null");
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForTrash(env, argc, argv, *asyncContext);
        ASSERT_NULLPTR_CHECK(env, result);
        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSTrash");
        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<FileAssetAsyncContext*>(data);
                JSTrashExecute(context);
            },
            reinterpret_cast<CompleteCallback>(JSTrashCallbackComplete),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }
    return result;
}

static void MakeIsTrash(shared_ptr<DataShare::DataShareResultSet> resultSet, FileAssetAsyncContext* context)
{
    if (resultSet != nullptr) {
        // Create FetchResult object using the contents of resultSet
        unique_ptr<FetchResult> fetchFileResult = make_unique<FetchResult>(move(resultSet));
        if (fetchFileResult == nullptr) {
            context->error = ERR_INVALID_OUTPUT;
            NAPI_ERR_LOG("fetchFileResult == nullptr");
        }
        if (fetchFileResult->GetCount() != 0) {
            unique_ptr<FileAsset> fileAsset = fetchFileResult->GetFirstObject();
            if (fileAsset == nullptr) {
                context->error = ERR_INVALID_OUTPUT;
                NAPI_ERR_LOG("fileAsset == nullptr");
                return;
            }
            if (fileAsset->GetIsTrash() == 0) {
                context->isTrash = false;
            } else {
                context->isTrash = true;
            }
        } else {
            NAPI_ERR_LOG("have no fileAssets");
            context->error = ERR_INVALID_OUTPUT;
        }
    } else {
        NAPI_ERR_LOG("helper == nullptr");
        context->error = ERR_INVALID_OUTPUT;
    }
}

static void JSIsTrashExecute(FileAssetAsyncContext* context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    vector<string> columns, selectionArgs;
    string trashPrefix = MEDIA_DATA_DB_ID + " = ?";
    selectionArgs.insert(selectionArgs.begin(), to_string(context->objectInfo->GetFileId()));
    DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause(trashPrefix);
    predicates.SetWhereArgs(selectionArgs);
    string queryUri = MEDIALIBRARY_DATA_URI;
    Uri uri(queryUri);
    shared_ptr<DataShare::DataShareResultSet> resultSet;
    if (context->objectInfo->sDataShareHelper_ != nullptr) {
        resultSet = context->objectInfo->sDataShareHelper_->Query(uri, predicates, columns);
        MakeIsTrash(resultSet, context);
    }
    return;
}

static void JSIsTrashCallbackComplete(napi_env env, napi_status status,
                                      FileAssetAsyncContext* context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    CHECK_NULL_PTR_RETURN_VOID(jsContext, "jsContext context is null");
    jsContext->status = false;
    if (context->error == ERR_DEFAULT) {
        napi_get_boolean(env, context->isTrash, &jsContext->data);
        napi_get_undefined(env, &jsContext->error);
        jsContext->status = true;
    } else {
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, context->error,
            "Ability helper is null");
        napi_get_undefined(env, &jsContext->data);
    }
    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

static napi_value GetJSArgsForIsTrash(napi_env env, size_t argc, const napi_value argv[],
                                      FileAssetAsyncContext &asyncContext)
{
    string str = "";
    vector<string> strArr;
    string order = "";
    const int32_t refCount = 1;
    napi_value result;
    auto context = &asyncContext;
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, context, result, "Async context is null");
    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");
    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == PARAM0 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }
    napi_get_boolean(env, true, &result);
    return result;
}

napi_value FileAssetNapi::JSIsTrash(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;
    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ZERO || argc == ARGS_ONE), "requires 1 parameters maximum");
    napi_get_undefined(env, &result);
    unique_ptr<FileAssetAsyncContext> asyncContext = make_unique<FileAssetAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, result, "asyncContext context is null");
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForIsTrash(env, argc, argv, *asyncContext);
        ASSERT_NULLPTR_CHECK(env, result);
        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSIsTrash");
        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<FileAssetAsyncContext*>(data);
                JSIsTrashExecute(context);
            },
            reinterpret_cast<CompleteCallback>(JSIsTrashCallbackComplete),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }
    return result;
}

void FileAssetNapi::UpdateFileAssetInfo()
{
    fileId_ = sFileAsset_->GetId();
    fileUri_ = sFileAsset_->GetUri();
    filePath_ = sFileAsset_->GetPath();
    displayName_ = sFileAsset_->GetDisplayName();
    mimeType_ = sFileAsset_->GetMimeType();
    mediaType_ = static_cast<MediaType>(sFileAsset_->GetMediaType());
    title_ = sFileAsset_->GetTitle();
    size_ = sFileAsset_->GetSize();
    albumId_ = sFileAsset_->GetAlbumId();
    albumName_ = sFileAsset_->GetAlbumName();
    dateAdded_ = sFileAsset_->GetDateAdded();
    dateModified_ = sFileAsset_->GetDateModified();
    orientation_ = sFileAsset_->GetOrientation();
    width_ = sFileAsset_->GetWidth();
    height_ = sFileAsset_->GetHeight();
    relativePath_ = sFileAsset_->GetRelativePath();
    album_ = sFileAsset_->GetAlbum();
    artist_ = sFileAsset_->GetArtist();
    duration_ = sFileAsset_->GetDuration();

    dateTrashed_ = sFileAsset_->GetDateTrashed();
    parent_ = sFileAsset_->GetParent();
    albumUri_ = sFileAsset_->GetAlbumUri();
    dateTaken_ = sFileAsset_->GetDateTaken();
    isFavorite_ = sFileAsset_->IsFavorite();
    isTrash_ = sFileAsset_->GetDateTrashed() != 0;
}
} // namespace Media
} // namespace OHOS
