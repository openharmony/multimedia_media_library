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
#define MLOG_TAG "FileAssetNapi"

#include "file_asset_napi.h"

#include <cstring>

#include "abs_shared_result_set.h"
#include "hitrace_meter.h"
#include "fetch_result.h"
#include "hilog/log.h"
#include "media_file_utils.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_errno.h"
#include "medialibrary_napi_log.h"
#include "medialibrary_napi_utils.h"
#include "medialibrary_tracer.h"
#include "rdb_errno.h"
#include "string_ex.h"
#include "thumbnail_const.h"
#include "userfile_client.h"

using OHOS::HiviewDFX::HiLog;
using OHOS::HiviewDFX::HiLogLabel;
using namespace std;
using namespace OHOS::AppExecFwk;
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;
using std::string;

namespace OHOS {
namespace Media {
static const std::string MEDIA_FILEDESCRIPTOR = "fd";

thread_local napi_ref FileAssetNapi::sConstructor_ = nullptr;
thread_local FileAsset *FileAssetNapi::sFileAsset_ = nullptr;

constexpr int64_t IS_TRASH = 1;
constexpr int64_t NOT_TRASH = 0;

using CompleteCallback = napi_async_complete_callback;

thread_local napi_ref FileAssetNapi::userFileMgrConstructor_ = nullptr;

FileAssetNapi::FileAssetNapi()
    : env_(nullptr) {}

FileAssetNapi::~FileAssetNapi() = default;

void FileAssetNapi::FileAssetNapiDestructor(napi_env env, void *nativeObject, void *finalize_hint)
{
    FileAssetNapi *fileAssetObj = reinterpret_cast<FileAssetNapi*>(nativeObject);
    if (fileAssetObj != nullptr) {
        delete fileAssetObj;
        fileAssetObj = nullptr;
    }
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
        DECLARE_NAPI_GETTER("count", JSGetCount),
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

napi_value FileAssetNapi::UserFileMgrInit(napi_env env, napi_value exports)
{
    NapiClassInfo info = {
        .name = USERFILEMGR_FILEASSET_NAPI_CLASS_NAME,
        .ref = &userFileMgrConstructor_,
        .constructor = FileAssetNapiConstructor,
        .props = {
            DECLARE_NAPI_FUNCTION("get", UserFileMgrGet),
            DECLARE_NAPI_FUNCTION("set", UserFileMgrSet),
            DECLARE_NAPI_FUNCTION("open", UserFileMgrOpen),
            DECLARE_NAPI_FUNCTION("close", UserFileMgrClose),
            DECLARE_NAPI_FUNCTION("commitModify", UserFileMgrCommitModify),
            DECLARE_NAPI_FUNCTION("favorite", UserFileMgrFavorite),
            DECLARE_NAPI_FUNCTION("trash", UserFileMgrTrash),
            DECLARE_NAPI_GETTER("uri", JSGetFileUri),
            DECLARE_NAPI_GETTER("fileType", JSGetMediaType),
            DECLARE_NAPI_GETTER_SETTER("displayName", JSGetFileDisplayName, JSSetFileDisplayName),
            DECLARE_NAPI_FUNCTION("isFavorite", JSIsFavorite),
            DECLARE_NAPI_FUNCTION("isTrash", JSIsTrash),
            DECLARE_NAPI_FUNCTION("isDirectory", UserFileMgrIsDirectory),
            DECLARE_NAPI_FUNCTION("getThumbnail", UserFileMgrGetThumbnail),
        }
    };
    MediaLibraryNapiUtils::NapiDefineClass(env, exports, info);

    return exports;
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

            status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                               FileAssetNapi::FileAssetNapiDestructor, nullptr, nullptr);
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

napi_value FileAssetNapi::CreateFileAsset(napi_env env, unique_ptr<FileAsset> &iAsset)
{
    MediaLibraryTracer tracer;
    tracer.Start("CreateFileAsset");

    if (iAsset == nullptr) {
        return nullptr;
    }

    napi_value constructor = nullptr;
    napi_ref constructorRef = (iAsset->GetResultNapiType() == ResultNapiType::TYPE_USERFILE_MGR) ?
        (userFileMgrConstructor_) : (sConstructor_);
    NAPI_CALL(env, napi_get_reference_value(env, constructorRef, &constructor));

    sFileAsset_ = iAsset.release();

    napi_value result = nullptr;
    NAPI_CALL(env, napi_new_instance(env, constructor, 0, nullptr, &result));

    sFileAsset_ = nullptr;
    return result;
}

std::string FileAssetNapi::GetFileDisplayName() const
{
    return fileAssetPtr->GetDisplayName();
}

std::string FileAssetNapi::GetRelativePath() const
{
    return fileAssetPtr->GetRelativePath();
}

std::string FileAssetNapi::GetFilePath() const
{
    return fileAssetPtr->GetPath();
}

std::string FileAssetNapi::GetTitle() const
{
    return fileAssetPtr->GetTitle();
}

std::string FileAssetNapi::GetFileUri() const
{
    return fileAssetPtr->GetUri();
}

int32_t FileAssetNapi::GetFileId() const
{
    return fileAssetPtr->GetId();
}

Media::MediaType FileAssetNapi::GetMediaType() const
{
    return fileAssetPtr->GetMediaType();
}

int32_t FileAssetNapi::GetOrientation() const
{
    return fileAssetPtr->GetOrientation();
}

std::string FileAssetNapi::GetNetworkId() const
{
    return MediaFileUtils::GetNetworkIdFromUri(GetFileUri());
}

std::string FileAssetNapi::GetTypeMask() const
{
    return fileAssetPtr->GetTypeMask();
}

void FileAssetNapi::SetTypeMask(const std::string &typeMask)
{
    fileAssetPtr->SetTypeMask(typeMask);
}

bool FileAssetNapi::IsFavorite() const
{
    return fileAssetPtr->IsFavorite();
}

void FileAssetNapi::SetFavorite(bool isFavorite)
{
    fileAssetPtr->SetFavorite(isFavorite);
}

bool FileAssetNapi::IsTrash() const
{
    return (fileAssetPtr->GetIsTrash() != NOT_TRASH);
}

void FileAssetNapi::SetTrash(bool isTrash)
{
    int32_t trashFlag = (isTrash ? IS_TRASH : NOT_TRASH);
    fileAssetPtr->SetIsTrash(trashFlag);
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
        id = obj->GetFileId();
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
        uri = obj->GetFileUri();
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
        path = obj->GetFilePath();
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
        displayName = obj->GetFileDisplayName();
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
            obj->fileAssetPtr->SetDisplayName(string(buffer));
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
        mimeType = obj->fileAssetPtr->GetMimeType();
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
        mediaType = static_cast<int32_t>(obj->GetMediaType());
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
        title = obj->GetTitle();
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
            obj->fileAssetPtr->SetTitle(string(buffer));
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
        size = obj->fileAssetPtr->GetSize();
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
        albumId = obj->fileAssetPtr->GetAlbumId();
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
        albumName = obj->fileAssetPtr->GetAlbumName();
        napi_create_string_utf8(env, albumName.c_str(), NAPI_AUTO_LENGTH, &jsResult);
    }

    return jsResult;
}

napi_value FileAssetNapi::JSGetCount(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &jsResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if ((status != napi_ok) || (thisVar == nullptr)) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return jsResult;
    }

    FileAssetNapi* obj = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if ((status == napi_ok) && (obj != nullptr)) {
        napi_create_int32(env, obj->fileAssetPtr->GetCount(), &jsResult);
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
        dateAdded = obj->fileAssetPtr->GetDateAdded();
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
        dateTrashed = obj->fileAssetPtr->GetDateTrashed();
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
        dateModified = obj->fileAssetPtr->GetDateModified();
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
        orientation = obj->GetOrientation();
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
            obj->fileAssetPtr->SetOrientation(orientation);
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
        width = obj->fileAssetPtr->GetWidth();
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
        height = obj->fileAssetPtr->GetHeight();
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
        relativePath = obj->GetRelativePath();
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
    char buffer[ARG_BUF_SIZE];
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
        status = napi_get_value_string_utf8(env, argv[PARAM0], buffer, ARG_BUF_SIZE, &res);
        if (status == napi_ok) {
            obj->fileAssetPtr->SetRelativePath(string(buffer));
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
        album = obj->fileAssetPtr->GetAlbum();
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
        artist = obj->fileAssetPtr->GetArtist();
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
        duration = obj->fileAssetPtr->GetDuration();
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
        parent = obj->fileAssetPtr->GetParent();
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
        albumUri = obj->fileAssetPtr->GetAlbumUri();
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
        dateTaken = obj->fileAssetPtr->GetDateTaken();
        napi_create_int64(env, dateTaken, &jsResult);
    }
    return jsResult;
}

static void JSCommitModifyExecute(napi_env env, void *data)
{
    FileAssetAsyncContext *context = static_cast<FileAssetAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    MediaLibraryTracer tracer;
    tracer.Start("JSCommitModifyExecute");

    if (!MediaFileUtils::CheckTitle(context->objectPtr->GetTitle()) ||
        !MediaFileUtils::CheckDisplayName(context->objectPtr->GetDisplayName())) {
        NAPI_ERR_LOG("JSCommitModify CheckDisplayName fail");
        context->error = JS_E_DISPLAYNAME;
        return;
    }

    string uri = MEDIALIBRARY_DATA_URI + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_MODIFYASSET;
    MediaLibraryNapiUtils::UriAddFragmentTypeMask(uri, context->typeMask);
    Uri updateAssetUri(uri);
    MediaType mediaType = context->objectPtr->GetMediaType();
    string notifyUri = MediaLibraryNapiUtils::GetMediaTypeUri(mediaType);
    DataSharePredicates predicates;
    DataShareValuesBucket valuesBucket;
    int32_t changedRows;
    valuesBucket.Put(MEDIA_DATA_DB_URI, context->objectPtr->GetUri());
    valuesBucket.Put(MEDIA_DATA_DB_TITLE, context->objectPtr->GetTitle());
    valuesBucket.Put(MEDIA_DATA_DB_NAME, context->objectPtr->GetDisplayName());
    if (context->objectPtr->GetOrientation() >= 0) {
        valuesBucket.Put(MEDIA_DATA_DB_ORIENTATION, context->objectPtr->GetOrientation());
    }
    valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, context->objectPtr->GetRelativePath());
    valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, context->objectPtr->GetMediaType());
    predicates.SetWhereClause(MEDIA_DATA_DB_ID + " = ? ");
    predicates.SetWhereArgs({std::to_string(context->objectPtr->GetId())});

    changedRows = UserFileClient::Update(updateAssetUri, predicates, valuesBucket);
    if (changedRows < 0) {
        context->SaveError(changedRows);
        NAPI_ERR_LOG("File asset modification failed, err: %{public}d", changedRows);
    } else {
        context->changedRows = changedRows;
        Uri modifyNotify(notifyUri);
        UserFileClient::NotifyChange(modifyNotify);
    }
}

static void JSCommitModifyCompleteCallback(napi_env env, napi_status status, void *data)
{
    FileAssetAsyncContext *context = static_cast<FileAssetAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    MediaLibraryTracer tracer;
    tracer.Start("JSCommitModifyCompleteCallback");

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
        context->HandleError(env, jsContext->error);
        napi_get_undefined(env, &jsContext->data);
    }
    tracer.Finish();
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
    MediaLibraryTracer tracer;
    tracer.Start("JSCommitModify");

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ZERO || argc == ARGS_ONE), "requires 1 parameters maximum");
    napi_get_undefined(env, &result);

    unique_ptr<FileAssetAsyncContext> asyncContext = make_unique<FileAssetAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    asyncContext->resultNapiType = ResultNapiType::TYPE_MEDIALIBRARY;
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForCommitModify(env, argc, argv, *asyncContext);
        ASSERT_NULLPTR_CHECK(env, result);
        asyncContext->objectPtr = asyncContext->objectInfo->fileAssetPtr;
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext->objectPtr, result, "FileAsset is nullptr");

        result = MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSCommitModify", JSCommitModifyExecute,
            JSCommitModifyCompleteCallback);
    }

    return result;
}

static void JSOpenExecute(napi_env env, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSOpenExecute");

    FileAssetAsyncContext *context = static_cast<FileAssetAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    string fileUri = context->objectPtr->GetUri();

    bool isValid = false;
    string mode = context->valuesBucket.Get(MEDIA_FILEMODE, isValid);
    if (!isValid) {
        context->error = ERR_INVALID_OUTPUT;
        NAPI_ERR_LOG("getting mode invalid");
        return;
    }

    Uri openFileUri(fileUri);
    int32_t retVal = UserFileClient::OpenFile(openFileUri, mode);
    if (retVal <= 0) {
        context->SaveError(retVal);
        NAPI_ERR_LOG("File open asset failed, ret: %{public}d", retVal);
    } else {
        context->fd = retVal;
    }
}

static void JSOpenCompleteCallback(napi_env env, napi_status status, void *data)
{
    FileAssetAsyncContext *context = static_cast<FileAssetAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    MediaLibraryTracer tracer;
    tracer.Start("JSOpenCompleteCallback");

    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    if (context->error == ERR_DEFAULT) {
        NAPI_DEBUG_LOG("return fd = %{public}d", context->fd);
        napi_create_int32(env, context->fd, &jsContext->data);
        napi_get_undefined(env, &jsContext->error);
        jsContext->status = true;
    } else {
        context->HandleError(env, jsContext->error);
        napi_get_undefined(env, &jsContext->data);
    }

    tracer.Finish();
    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }

    delete context;
}

napi_value GetJSArgsForOpen(napi_env env, size_t argc, const napi_value argv[],
                            FileAssetAsyncContext &asyncContext)
{
    const int32_t refCount = 1;
    napi_value result = nullptr;
    auto context = &asyncContext;
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, context, result, "Async context is null");
    size_t res = 0;
    char buffer[ARG_BUF_SIZE];

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (i == PARAM0 && valueType == napi_string) {
            napi_get_value_string_utf8(env, argv[i], buffer, ARG_BUF_SIZE, &res);
        } else if (i == PARAM1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }
    context->valuesBucket.Put(MEDIA_FILEMODE, string(buffer));
    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}

napi_value FileAssetNapi::JSOpen(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;

    MediaLibraryTracer tracer;
    tracer.Start("JSOpen");

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");
    napi_get_undefined(env, &result);

    unique_ptr<FileAssetAsyncContext> asyncContext = make_unique<FileAssetAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    asyncContext->objectPtr = asyncContext->objectInfo->fileAssetPtr;
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext->objectPtr, result, "FileAsset is nullptr");

    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForOpen(env, argc, argv, *asyncContext);
        ASSERT_NULLPTR_CHECK(env, result);
        result = MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSOpen", JSOpenExecute,
            JSOpenCompleteCallback);
    }

    return result;
}

static void JSCloseExecute(FileAssetAsyncContext *context)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSCloseExecute");

    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    string closeUri = MEDIALIBRARY_DATA_URI + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_CLOSEASSET;
    MediaLibraryNapiUtils::UriAddFragmentTypeMask(closeUri, context->typeMask);
    Uri closeAssetUri(closeUri);

    bool isValid = false;
    int fd = context->valuesBucket.Get(MEDIA_FILEDESCRIPTOR, isValid);
    if (!isValid) {
        context->error = ERR_INVALID_OUTPUT;
        NAPI_ERR_LOG("getting fd is invalid");
        return;
    }

    int32_t retVal = close(fd);
    if (retVal != E_SUCCESS)  {
        context->SaveError(retVal);
        NAPI_ERR_LOG("call close failed %{public}d", retVal);
        return;
    }

    string fileUri = context->valuesBucket.Get(MEDIA_DATA_DB_URI, isValid);
    if (!isValid) {
        context->error = ERR_INVALID_OUTPUT;
        NAPI_ERR_LOG("getting file uri is invalid");
        return;
    }
    if (!MediaFileUtils::GetNetworkIdFromUri(fileUri).empty()) {
        return;
    }

    retVal = UserFileClient::Insert(closeAssetUri, context->valuesBucket);
    if (retVal != E_SUCCESS) {
        context->SaveError(retVal);
        NAPI_ERR_LOG("File close asset failed %{public}d", retVal);
    }
}

static void JSCloseCompleteCallback(napi_env env, napi_status status,
                                    FileAssetAsyncContext *context)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSCloseCompleteCallback");

    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    if (context->error == ERR_DEFAULT) {
        napi_create_int32(env, E_SUCCESS, &jsContext->data);
        napi_get_undefined(env, &jsContext->error);
        jsContext->status = true;
    } else {
        context->HandleError(env, jsContext->error);
        napi_get_undefined(env, &jsContext->data);
    }

    tracer.Finish();
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
    context->valuesBucket.Put(MEDIA_FILEDESCRIPTOR, fd);
    context->valuesBucket.Put(MEDIA_DATA_DB_URI, context->objectInfo->GetFileUri());
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

    MediaLibraryTracer tracer;
    tracer.Start("JSClose");

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");
    napi_get_undefined(env, &result);
    unique_ptr<FileAssetAsyncContext> asyncContext = make_unique<FileAssetAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForClose(env, argc, argv, *asyncContext);
        ASSERT_NULLPTR_CHECK(env, result);
        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSClose", asyncContext);
        JSCloseExecute(asyncContext.get());
        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {},
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

static int GetImageFromResult(const shared_ptr<DataShare::DataShareResultSet> &resultSet, Size &size,
    unique_ptr<PixelMap> &outPixelMap)
{
    MediaLibraryTracer tracer;
    tracer.Start("MediaThumbnailHelper::GetKv");
    int ret = resultSet->GoToFirstRow();
    if (ret != DataShare::E_OK) {
        NAPI_ERR_LOG("GoToFirstRow error %{public}d", ret);
        return ret;
    }

    vector<uint8_t> key;
    ret = resultSet->GetBlob(PARAM0, key);
    if (ret != DataShare::E_OK) {
        NAPI_ERR_LOG("GetBlob key error %{public}d", ret);
        return ret;
    }
    vector<uint8_t> image;
    ret = resultSet->GetBlob(PARAM1, image);
    if (ret != DataShare::E_OK) {
        NAPI_ERR_LOG("GetBlob image error %{public}d", ret);
        return ret;
    }
    resultSet->Close();
    tracer.Finish();

    NAPI_DEBUG_LOG("key %{public}s key len %{public}d len %{public}d", string(key.begin(),
        key.end()).c_str(), static_cast<int>(key.size()), static_cast<int>(image.size()));

    tracer.Start("MediaThumbnailHelper::ResizeImage");
    if (!MediaThumbnailHelper::ResizeImage(image, size, outPixelMap)) {
        NAPI_ERR_LOG("ResizeImage error");
        return E_FAIL;
    }
    return ret;
}

static unique_ptr<PixelMap> QueryThumbnail(std::string &uri, Size &size, const std::string &typeMask)
{
    MediaLibraryTracer tracer;
    tracer.Start("QueryThumbnail");

    string queryUriStr = uri + "?" + MEDIA_OPERN_KEYWORD + "=" + MEDIA_DATA_DB_THUMBNAIL + "&" + MEDIA_DATA_DB_WIDTH + "=" +
        to_string(size.width) + "&" + MEDIA_DATA_DB_HEIGHT + "=" + to_string(size.height);
    MediaLibraryNapiUtils::UriAddFragmentTypeMask(queryUriStr, typeMask);
    Uri queryUri(queryUriStr);
    tracer.Start("DataShare::Query");
    DataShare::DataSharePredicates predicates;
    vector<string> columns;
    auto resultSet = UserFileClient::Query(queryUri, predicates, columns);
    if (resultSet == nullptr) {
        NAPI_ERR_LOG("Query thumbnail error");
        return nullptr;
    }
    int rowCount = 0;
    int err = resultSet->GetRowCount(rowCount);
    if ((err != DataShare::E_OK) || (rowCount <= 0)) {
        NAPI_ERR_LOG("GetRowCount err %{public}d", err);
        return nullptr;
    }
    tracer.Finish();

    unique_ptr<PixelMap> pixelMap;
    auto ret = GetImageFromResult(resultSet, size, pixelMap);
    if (ret != DataShare::E_OK) {
        NAPI_ERR_LOG("getImageFromResult error %{public}d", ret);
    }

    return pixelMap;
}

static void JSGetThumbnailExecute(FileAssetAsyncContext* context)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSGetThumbnailExecute");

    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    std::string uri = context->objectPtr->GetUri();
    MediaLibraryNapiUtils::UriRemoveAllFragment(uri);
    Size size = { .width = context->thumbWidth, .height = context->thumbHeight };
    context->pixelmap = QueryThumbnail(uri, size, context->typeMask);
}

static void JSGetThumbnailCompleteCallback(napi_env env, napi_status status,
                                           FileAssetAsyncContext* context)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSGetThumbnailCompleteCallback");

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

    tracer.Finish();
    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }

    delete context;
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

    context->thumbWidth = DEFAULT_THUMBNAIL_SIZE;
    context->thumbHeight = DEFAULT_THUMBNAIL_SIZE;

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (i == PARAM0 && valueType == napi_object) {
            GetSizeInfo(env, argv[PARAM0], "width", context->thumbWidth);
            GetSizeInfo(env, argv[PARAM0], "height", context->thumbHeight);
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
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;

    MediaLibraryTracer tracer;
    tracer.Start("JSGetThumbnail");

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
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSGetThumbnail", asyncContext);
        asyncContext->objectPtr = asyncContext->objectInfo->fileAssetPtr;
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext->objectPtr, result, "FileAsset is nullptr");

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

    Size size = { .width = width, .height = height };
    return QueryThumbnail(fileUri, size, "");
}

static void JSFavoriteCallbackComplete(napi_env env, napi_status status, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSFavoriteCallbackComplete");

    FileAssetAsyncContext *context = static_cast<FileAssetAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    CHECK_NULL_PTR_RETURN_VOID(jsContext, "jsContext context is null");
    jsContext->status = false;
    napi_get_undefined(env, &jsContext->data);
    if (context->error == ERR_DEFAULT) {
        jsContext->status = true;
        Media::MediaType mediaType = context->objectPtr->GetMediaType();
        string notifyUri = MediaLibraryNapiUtils::GetMediaTypeUri(mediaType);
        Uri modifyNotify(notifyUri);
        UserFileClient::NotifyChange(modifyNotify);
    } else {
        context->HandleError(env, jsContext->error);
        napi_get_undefined(env, &jsContext->data);
    }

    tracer.Finish();
    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }

    delete context;
}

static bool GetIsDirectoryiteNative(napi_env env, const FileAssetAsyncContext &fileContext)
{
    MediaLibraryTracer tracer;
    tracer.Start("GetIsDirectoryiteNative");

    FileAssetAsyncContext *context = const_cast<FileAssetAsyncContext *>(&fileContext);
    if (context == nullptr) {
        NAPI_ERR_LOG("Async context is null");
        return false;
    }

    bool IsDirectory = false;
    string abilityUri = Media::MEDIALIBRARY_DATA_URI;
    Uri isDirectoryAssetUri(abilityUri + "/" + Media::MEDIA_FILEOPRN + "/" + Media::MEDIA_FILEOPRN_ISDIRECTORY);
    context->valuesBucket.Put(Media::MEDIA_DATA_DB_ID, context->objectPtr->GetId());
    int retVal = UserFileClient::Insert(isDirectoryAssetUri, context->valuesBucket);
    NAPI_DEBUG_LOG("GetIsDirectoryiteNative retVal = %{public}d", retVal);
    if (retVal == SUCCESS) {
        IsDirectory = true;
    }

    return IsDirectory;
}
static void JSIsDirectoryCallbackComplete(napi_env env, napi_status status,
                                          FileAssetAsyncContext* context)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSIsDirectoryCallbackComplete");

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
                                                     "UserFileClient is invalid");
        napi_get_undefined(env, &jsContext->data);
    }

    tracer.Finish();
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

    MediaLibraryTracer tracer;
    tracer.Start("JSisDirectory");

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
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSIsDirectory", asyncContext);
        asyncContext->objectPtr = asyncContext->objectInfo->fileAssetPtr;
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext->objectPtr, result, "FileAsset is nullptr");
        status = napi_create_async_work(env, nullptr, resource, [](napi_env env, void* data) {
                FileAssetAsyncContext* context = static_cast<FileAssetAsyncContext*>(data);
                context->isDirectory = GetIsDirectoryiteNative(env, *context);
                context->status = true;
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

static void JSIsFavoriteExecute(FileAssetAsyncContext* context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    context->isFavorite = context->objectPtr->IsFavorite();
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
            "UserFileClient is invalid");
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

static void JSFavouriteExecute(napi_env env, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSFavouriteExecute");

    FileAssetAsyncContext *context = static_cast<FileAssetAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(SMARTALBUMMAP_DB_ALBUM_ID, FAVOURITE_ALBUM_ID_VALUES);
    valuesBucket.Put(SMARTALBUMMAP_DB_CHILD_ASSET_ID, context->objectPtr->GetId());
    string uriString = MEDIALIBRARY_DATA_URI + "/" + MEDIA_SMARTALBUMMAPOPRN + "/";
    uriString += context->isFavorite ? MEDIA_SMARTALBUMMAPOPRN_ADDSMARTALBUM : MEDIA_SMARTALBUMMAPOPRN_REMOVESMARTALBUM;
    MediaLibraryNapiUtils::UriAddFragmentTypeMask(uriString, context->typeMask);
    Uri uri(uriString);
    context->changedRows = UserFileClient::Insert(uri, valuesBucket);
    if (context->changedRows >= 0) {
        context->objectPtr->SetFavorite(context->isFavorite);
    }
    context->SaveError(context->changedRows);
}

napi_value FileAssetNapi::JSFavorite(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;

    MediaLibraryTracer tracer;
    tracer.Start("JSFavorite");

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    unique_ptr<FileAssetAsyncContext> asyncContext = make_unique<FileAssetAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, result, "asyncContext context is null");
    asyncContext->resultNapiType = ResultNapiType::TYPE_MEDIALIBRARY;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo == nullptr) {
        NAPI_DEBUG_LOG("get this Var fail");
        return result;
    }

    result = GetJSArgsForFavorite(env, argc, argv, *asyncContext);
    if (asyncContext->isFavorite == asyncContext->objectInfo->IsFavorite()) {
        NAPI_DEBUG_LOG("favorite state is the same");
        return result;
    }
    ASSERT_NULLPTR_CHECK(env, result);
    asyncContext->objectPtr = asyncContext->objectInfo->fileAssetPtr;
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext->objectPtr, result, "FileAsset is nullptr");

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSFavorite", JSFavouriteExecute,
        JSFavoriteCallbackComplete);
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
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSIsFavorite", asyncContext);
        asyncContext->objectPtr = asyncContext->objectInfo->fileAssetPtr;
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext->objectPtr, result, "FileAsset is nullptr");

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

static void JSTrashExecute(napi_env env, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSTrashExecute");

    FileAssetAsyncContext *context = static_cast<FileAssetAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(SMARTALBUMMAP_DB_ALBUM_ID, TRASH_ALBUM_ID_VALUES);
    valuesBucket.Put(SMARTALBUMMAP_DB_CHILD_ASSET_ID, context->objectPtr->GetId());
    string uriString = MEDIALIBRARY_DATA_URI + "/" + MEDIA_SMARTALBUMMAPOPRN + "/";
    uriString += context->isTrash ? MEDIA_SMARTALBUMMAPOPRN_ADDSMARTALBUM : MEDIA_SMARTALBUMMAPOPRN_REMOVESMARTALBUM;
    MediaLibraryNapiUtils::UriAddFragmentTypeMask(uriString, context->typeMask);
    Uri uri(uriString);
    context->changedRows = UserFileClient::Insert(uri, valuesBucket);
    if (context->changedRows >= 0) {
        int32_t trashFlag = (context->isTrash ? IS_TRASH : NOT_TRASH);
        context->objectPtr->SetIsTrash(trashFlag);
    }
    context->SaveError(context->changedRows);
}

static void JSTrashCallbackComplete(napi_env env, napi_status status, void *data)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSGetThumbnail");

    FileAssetAsyncContext *context = static_cast<FileAssetAsyncContext*>(data);
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    unique_ptr<JSAsyncContextOutput> jsContext = make_unique<JSAsyncContextOutput>();
    CHECK_NULL_PTR_RETURN_VOID(jsContext, "jsContext context is null");
    jsContext->status = false;
    napi_get_undefined(env, &jsContext->data);
    if (context->error == ERR_DEFAULT) {
        jsContext->status = true;
        Media::MediaType mediaType = context->objectPtr->GetMediaType();
        string notifyUri = MediaLibraryNapiUtils::GetMediaTypeUri(mediaType);
        Uri modifyNotify(notifyUri);
        UserFileClient::NotifyChange(modifyNotify);
        NAPI_DEBUG_LOG("JSTrashCallbackComplete success");
    } else {
        context->HandleError(env, jsContext->error);
    }

    tracer.Finish();
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

    MediaLibraryTracer tracer;
    tracer.Start("JSTrash");

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameters maximum");

    napi_get_undefined(env, &result);
    unique_ptr<FileAssetAsyncContext> asyncContext = make_unique<FileAssetAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, result, "asyncContext context is null");
    asyncContext->resultNapiType = ResultNapiType::TYPE_MEDIALIBRARY;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForTrash(env, argc, argv, *asyncContext);
        ASSERT_NULLPTR_CHECK(env, result);
        asyncContext->objectPtr = asyncContext->objectInfo->fileAssetPtr;
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext->objectPtr, result, "FileAsset is nullptr");
        result = MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "JSTrash", JSTrashExecute,
            JSTrashCallbackComplete);
    }
    return result;
}

static void JSIsTrashExecute(FileAssetAsyncContext* context)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSIsTrashExecute");

    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    context->isTrash = (context->objectPtr->GetIsTrash() != NOT_TRASH);
    return;
}

static void JSIsTrashCallbackComplete(napi_env env, napi_status status,
                                      FileAssetAsyncContext* context)
{
    MediaLibraryTracer tracer;
    tracer.Start("JSIsTrashCallbackComplete");

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
            "UserFileClient is invalid");
        napi_get_undefined(env, &jsContext->data);
    }

    tracer.Finish();
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

    MediaLibraryTracer tracer;
    tracer.Start("JSIsTrash");

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
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSIsTrash", asyncContext);
        asyncContext->objectPtr = asyncContext->objectInfo->fileAssetPtr;
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext->objectPtr, result, "FileAsset is nullptr");

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
    fileAssetPtr = std::shared_ptr<FileAsset>(sFileAsset_);
}

napi_value FileAssetNapi::UserFileMgrGet(napi_env env, napi_callback_info info)
{
    MediaLibraryTracer tracer;
    tracer.Start("UserFileMgrGet");

    napi_value ret = nullptr;
    unique_ptr<FileAssetAsyncContext> asyncContext = make_unique<FileAssetAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, ret, "asyncContext context is null");

    string inputKey;
    CHECK_ARGS(env, MediaLibraryNapiUtils::ParseArgsStringCallback(env, info, asyncContext, inputKey), asyncContext,
        JS_ERR_PARAMETER_INVALID);
    napi_status status;
    napi_value thisVar = nullptr;
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    napi_value jsResult = nullptr;
    if ((status != napi_ok) || (thisVar == nullptr)) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return jsResult;
    }
    FileAssetNapi *obj = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    napi_get_undefined(env, &jsResult);
    if ((status != napi_ok) || (obj == nullptr)) {
        NAPI_THROW(env, asyncContext, JS_E_FILE_KEY);
        return jsResult;
    }
    if (obj->fileAssetPtr->GetMemberMap().count(inputKey) == 0) {
        // no exist throw error
        NAPI_THROW(env, asyncContext, JS_E_FILE_KEY);
        return jsResult;
    }
    auto m = obj->fileAssetPtr->GetMemberMap().at(inputKey);
    if (m.index() == MEMBER_TYPE_STRING) {
        napi_create_string_utf8(env, get<string>(m).c_str(), NAPI_AUTO_LENGTH, &jsResult);
    } else if (m.index() == MEMBER_TYPE_INT32) {
        napi_create_int32(env, get<int32_t>(m), &jsResult);
    } else if (m.index() == MEMBER_TYPE_INT64) {
        napi_create_int64(env, get<int64_t>(m), &jsResult);
    } else {
        NAPI_THROW(env, asyncContext, JS_ERR_PARAMETER_INVALID);
        return jsResult;
    }
    return jsResult;
}

bool FileAssetNapi::HandleParamSet(const string &inputKey, const string &value)
{
    if ((inputKey == MEDIA_DATA_DB_NAME) && (fileAssetPtr->GetMemberMap().count(MEDIA_DATA_DB_NAME))) {
        fileAssetPtr->SetDisplayName(value);
        fileAssetPtr->GetMemberMap()[MEDIA_DATA_DB_NAME] = value;
    } else if ((inputKey == MEDIA_DATA_DB_RELATIVE_PATH) &&
        (fileAssetPtr->GetMemberMap().count(MEDIA_DATA_DB_RELATIVE_PATH))) {
        fileAssetPtr->SetRelativePath(value);
        fileAssetPtr->GetMemberMap()[MEDIA_DATA_DB_RELATIVE_PATH] = value;
    } else if ((inputKey == MEDIA_DATA_DB_TITLE) && (fileAssetPtr->GetMemberMap().count(MEDIA_DATA_DB_TITLE))) {
        fileAssetPtr->SetTitle(value);
        fileAssetPtr->GetMemberMap()[MEDIA_DATA_DB_TITLE] = value;
    } else {
        NAPI_ERR_LOG("invalid key %{public}s, no support key", inputKey.c_str());
        return false;
    }
    return true;
}

napi_value FileAssetNapi::UserFileMgrSet(napi_env env, napi_callback_info info)
{
    MediaLibraryTracer tracer;
    tracer.Start("UserFileMgrGet");

    napi_value ret = nullptr;
    unique_ptr<FileAssetAsyncContext> asyncContext = make_unique<FileAssetAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, ret, "asyncContext context is null");
    string inputKey;
    CHECK_ARGS(env, MediaLibraryNapiUtils::ParseArgsStringCallback(env, info, asyncContext, inputKey), asyncContext,
        JS_ERR_PARAMETER_INVALID);
    string value;
    CHECK_ARGS(env, MediaLibraryNapiUtils::GetParamStringPathMax(env, asyncContext->argv[ARGS_ONE], value),
        asyncContext, JS_ERR_PARAMETER_INVALID);
    napi_status status;
    napi_value thisVar = nullptr;
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    napi_value jsResult = nullptr;
    napi_get_undefined(env, &jsResult);
    if ((status != napi_ok) || (thisVar == nullptr)) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return jsResult;
    }
    FileAssetNapi *obj = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status != napi_ok || obj == nullptr) {
        NAPI_THROW(env, asyncContext, JS_E_FILE_KEY);
        return jsResult;
    }
    if (!obj->HandleParamSet(inputKey, value)) {
        NAPI_THROW(env, asyncContext, JS_E_FILE_KEY);
        return jsResult;
    }
    return jsResult;
}

napi_value FileAssetNapi::UserFileMgrOpen(napi_env env, napi_callback_info info)
{
    MediaLibraryTracer tracer;
    tracer.Start("UserFileMgrOpen");

    napi_value ret = nullptr;
    unique_ptr<FileAssetAsyncContext> asyncContext = make_unique<FileAssetAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, ret, "asyncContext context is null");

    string mode;
    NAPI_ASSERT(env, MediaLibraryNapiUtils::ParseArgsStringCallback(env, info, asyncContext, mode) == napi_ok,
        "Failed to parse js args");
    asyncContext->valuesBucket.Put(MEDIA_FILEMODE, mode);
    MediaLibraryNapiUtils::GenTypeMaskFromArray({ asyncContext->objectInfo->GetMediaType() }, asyncContext->typeMask);
    asyncContext->objectPtr = asyncContext->objectInfo->fileAssetPtr;
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext->objectPtr, ret, "FileAsset is nullptr");

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "UserFileMgrOpen",
        JSOpenExecute, JSOpenCompleteCallback);
}

napi_value FileAssetNapi::UserFileMgrClose(napi_env env, napi_callback_info info)
{
    MediaLibraryTracer tracer;
    tracer.Start("UserFileMgrClose");

    napi_value ret = nullptr;
    unique_ptr<FileAssetAsyncContext> asyncContext = make_unique<FileAssetAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, ret, "asyncContext context is null");

    NAPI_ASSERT(env, MediaLibraryNapiUtils::ParseArgsNumberCallback(env, info, asyncContext, asyncContext->fd) ==
        napi_ok, "Failed to parse js args");

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "UserFileMgrClose",
        [](napi_env env, void* data) {
            FileAssetAsyncContext *context = static_cast<FileAssetAsyncContext*>(data);
            if (close(context->fd) < 0) {
               NAPI_ERR_LOG("Failed to close, errno: %{public}d", errno);
               context->error = errno;
            }
        }, reinterpret_cast<CompleteCallback>(JSCloseCompleteCallback));
}

napi_value FileAssetNapi::UserFileMgrCommitModify(napi_env env, napi_callback_info info)
{
    MediaLibraryTracer tracer;
    tracer.Start("UserFileMgrCommitModify");

    napi_value ret = nullptr;
    unique_ptr<FileAssetAsyncContext> asyncContext = make_unique<FileAssetAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, ret, "asyncContext context is null");
    asyncContext->resultNapiType = ResultNapiType::TYPE_USERFILE_MGR;
    NAPI_ASSERT(env, MediaLibraryNapiUtils::ParseArgsOnlyCallBack(env, info, asyncContext) == napi_ok,
        "Failed to parse js args");
    MediaLibraryNapiUtils::GenTypeMaskFromArray({ asyncContext->objectInfo->GetMediaType() }, asyncContext->typeMask);
    asyncContext->objectPtr = asyncContext->objectInfo->fileAssetPtr;
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext->objectPtr, ret, "FileAsset is nullptr");

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "UserFileMgrCommitModify",
        JSCommitModifyExecute, JSCommitModifyCompleteCallback);
}

napi_value FileAssetNapi::UserFileMgrFavorite(napi_env env, napi_callback_info info)
{
    MediaLibraryTracer tracer;
    tracer.Start("UserFileMgrFavorite");

    napi_value ret = nullptr;
    unique_ptr<FileAssetAsyncContext> asyncContext = make_unique<FileAssetAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, ret, "asyncContext context is null");
    asyncContext->resultNapiType = ResultNapiType::TYPE_USERFILE_MGR;
    NAPI_ASSERT(env,  MediaLibraryNapiUtils::ParseArgsBoolCallBack(env, info, asyncContext, asyncContext->isFavorite) ==
        napi_ok, "Failed to parse js args");
    MediaLibraryNapiUtils::GenTypeMaskFromArray({ asyncContext->objectInfo->GetMediaType() }, asyncContext->typeMask);
    asyncContext->objectPtr = asyncContext->objectInfo->fileAssetPtr;
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext->objectPtr, ret, "FileAsset is nullptr");

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "UserFileMgrFavorite", JSFavouriteExecute,
        JSFavoriteCallbackComplete);
}

napi_value FileAssetNapi::UserFileMgrTrash(napi_env env, napi_callback_info info)
{
    MediaLibraryTracer tracer;
    tracer.Start("UserFileMgrTrash");

    napi_value ret = nullptr;
    unique_ptr<FileAssetAsyncContext> asyncContext = make_unique<FileAssetAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, ret, "asyncContext context is null");
    asyncContext->resultNapiType = ResultNapiType::TYPE_USERFILE_MGR;
    NAPI_ASSERT(env,  MediaLibraryNapiUtils::ParseArgsBoolCallBack(env, info, asyncContext, asyncContext->isTrash) ==
        napi_ok, "Failed to parse js args");
    MediaLibraryNapiUtils::GenTypeMaskFromArray({ asyncContext->objectInfo->GetMediaType() }, asyncContext->typeMask);
    asyncContext->objectPtr = asyncContext->objectInfo->fileAssetPtr;
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext->objectPtr, ret, "FileAsset is nullptr");

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "UserFileMgrTrash", JSTrashExecute,
        JSTrashCallbackComplete);
}

napi_value FileAssetNapi::UserFileMgrIsDirectory(napi_env env, napi_callback_info info)
{
    MediaLibraryTracer tracer;
    tracer.Start("UserFileMgrIsDirectory");

    napi_value ret = nullptr;
    unique_ptr<FileAssetAsyncContext> asyncContext = make_unique<FileAssetAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, ret, "asyncContext context is null");
    NAPI_ASSERT(env,  MediaLibraryNapiUtils::ParseArgsOnlyCallBack(env, info, asyncContext) == napi_ok,
        "Failed to parse js args");
    asyncContext->objectPtr = asyncContext->objectInfo->fileAssetPtr;
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext->objectPtr, ret, "FileAsset is nullptr");

    return MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "UserFileMgrIsDirectory",
        [](napi_env env, void* data) {
            FileAssetAsyncContext *context = static_cast<FileAssetAsyncContext*>(data);
            context->isDirectory = MediaFileUtils::IsDirectory(context->objectPtr->GetPath());
            context->status = true;
        },
        reinterpret_cast<CompleteCallback>(JSIsDirectoryCallbackComplete));
}

napi_value FileAssetNapi::UserFileMgrGetThumbnail(napi_env env, napi_callback_info info)
{
    MediaLibraryTracer tracer;
    tracer.Start("UserFileMgrGetThumbnail");

    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_undefined(env, &result));
    unique_ptr<FileAssetAsyncContext> asyncContext = make_unique<FileAssetAsyncContext>();
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext, result, "asyncContext context is null");

    CHECK_COND_RET(MediaLibraryNapiUtils::AsyncContextSetObjectInfo(env, info, asyncContext, ARGS_ZERO, ARGS_TWO) ==
        napi_ok, result, "Failed to get object info");
    result = GetJSArgsForGetThumbnail(env, asyncContext->argc, asyncContext->argv, *asyncContext);
    ASSERT_NULLPTR_CHECK(env, result);
    const std::vector<uint32_t> types = { asyncContext->objectInfo->GetMediaType() };
    MediaLibraryNapiUtils::GenTypeMaskFromArray(types, asyncContext->typeMask);
    asyncContext->objectPtr = asyncContext->objectInfo->fileAssetPtr;
    CHECK_NULL_PTR_RETURN_UNDEFINED(env, asyncContext->objectPtr, result, "FileAsset is nullptr");

    result = MediaLibraryNapiUtils::NapiCreateAsyncWork(env, asyncContext, "UserFileMgrGetThumbnail",
        [](napi_env env, void* data) {
            auto context = static_cast<FileAssetAsyncContext*>(data);
            JSGetThumbnailExecute(context);
        },
        reinterpret_cast<CompleteCallback>(JSGetThumbnailCompleteCallback));

    return result;
}
} // namespace Media
} // namespace OHOS
