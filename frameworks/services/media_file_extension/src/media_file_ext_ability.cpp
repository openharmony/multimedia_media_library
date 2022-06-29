/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "media_file_ext_ability.h"

#include "ability_info.h"
#include "extension_context.h"
#include "file_access_ext_stub_impl.h"
#include "js_runtime_utils.h"
#include "js_runtime.h"
#include "media_asset.h"
#include "media_file_extention_utils.h"
#include "media_file_utils.h"
#include "media_lib_service_const.h"
#include "media_log.h"
#include "medialibrary_data_manager.h"
#include "result_set_utils.h"

namespace OHOS {
namespace Media {
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime;
using namespace OHOS::FileAccessFwk;

MediaFileExtAbility::MediaFileExtAbility(JsRuntime& jsRuntime) : jsRuntime_(jsRuntime) {}

MediaFileExtAbility::~MediaFileExtAbility() {}

MediaFileExtAbility* MediaFileExtAbility::Create(const std::unique_ptr<Runtime>& runtime)
{
    MEDIA_INFO_LOG("create MediaFileExtAbility");
    return new MediaFileExtAbility(static_cast<JsRuntime&>(*runtime));
}

static MediaFileExtAbility* MediaFileExtCreator(const std::unique_ptr<Runtime>& runtime)
{
    MEDIA_INFO_LOG("MediaFileExtCreator::%s", __func__);
    return  MediaFileExtAbility::Create(runtime);
}

__attribute__((constructor)) void RegisterFileExtCreator()
{
    MEDIA_INFO_LOG("MediaFileExtCreator::%s", __func__);
    FileAccessExtAbility::SetCreator(MediaFileExtCreator);
}

void MediaFileExtAbility::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application, std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    MEDIA_INFO_LOG("Init MediaFileExtAbility");
    FileAccessExtAbility::Init(record, application, handler, token);
    auto context = GetContext();
    if (context == nullptr) {
        MEDIA_ERR_LOG("Failed to get context");
        return;
    }
    MEDIA_INFO_LOG("%{public}s runtime language  %{public}d", __func__, jsRuntime_.GetLanguage());
    MediaLibraryDataManager::GetInstance()->InitMediaLibraryMgr(context);
}

void MediaFileExtAbility::OnStart(const AAFwk::Want &want)
{
    MEDIA_INFO_LOG("Onstart MediaFileExtAbility");
    Extension::OnStart(want);
}

void MediaFileExtAbility::OnStop()
{
    MEDIA_INFO_LOG("%{public}s begin.", __func__);
    MediaLibraryDataManager::GetInstance()->ClearMediaLibraryMgr();
}

sptr<IRemoteObject> MediaFileExtAbility::OnConnect(const AAFwk::Want &want)
{
    MEDIA_DEBUG_LOG("OnConnect MediaFileExtAbility");
    Extension::OnConnect(want);
    sptr<FileAccessExtStubImpl> remoteObject = new (std::nothrow) FileAccessExtStubImpl(
        std::static_pointer_cast<MediaFileExtAbility>(shared_from_this()),
        reinterpret_cast<napi_env>(&jsRuntime_.GetNativeEngine()));
    if (remoteObject == nullptr) {
        MEDIA_ERR_LOG("OnConnect MediaFileExtAbility get obj fail");
        return nullptr;
    }

    return remoteObject->AsObject();
}

int MediaFileExtAbility::OpenFile(const Uri &uri, int flags)
{
    if (!MediaFileExtentionUtils::CheckUriValid(uri.ToString())) {
        return ERROR_URI_INVALID;
    }
    string mode;
    if (flags == O_RDONLY) {
        mode = MEDIA_FILEMODE_READONLY;
    } else if (flags == O_WRONLY) {
        mode = MEDIA_FILEMODE_WRITEONLY;
    } else if (flags == O_RDWR) {
        mode = MEDIA_FILEMODE_READWRITE;
    } else {
        MEDIA_ERR_LOG("invalid OpenFile flags %{private}d", flags);
        return ERROR_OPENFILE_INVALID_FLAG;
    }
    return MediaLibraryDataManager::GetInstance()->OpenFile(uri, mode);
}

int MediaFileExtAbility::CreateFile(const Uri &parentUri, const std::string &displayName,  Uri &newFileUri)
{
    if (!MediaFileUtils::CheckDisplayName(displayName)) {
        MEDIA_ERR_LOG("invalid file displayName %{private}s", displayName.c_str());
        return ERROR_INVAVLID_DISPLAY_NAME;
    }
    string parentUriStr = parentUri.ToString();
    if (!MediaFileExtentionUtils::CheckUriValid(parentUriStr)) {
        return ERROR_URI_INVALID;
    }
    if (!MediaFileExtentionUtils::CheckDistributedUri(parentUriStr)) {
        MEDIA_ERR_LOG("CreateFile not support distributed operation");
        return ERROR_DISTIBUTED_URI_NO_SUPPORT;
    }
    Uri createFileUri(MEDIALIBRARY_DATA_URI + SLASH_CHAR + MEDIA_FILEOPRN + SLASH_CHAR + MEDIA_FILEOPRN_CREATEASSET);
    DataShareValuesBucket valuesBucket;
    valuesBucket.PutString(MEDIA_DATA_DB_NAME, displayName);
    string albumId = MediaLibraryDataManagerUtils::GetIdFromUri(parentUriStr);
    string albumPath = MediaLibraryDataManagerUtils::GetPathFromDb(albumId,
        MediaLibraryDataManager::GetInstance()->rdbStore_);
    string relativePath = albumPath.substr(ROOT_MEDIA_DIR.size()) + SLASH_CHAR;
    string destPath = albumPath + SLASH_CHAR + displayName;
    if (MediaLibraryDataManagerUtils::isFileExistInDb(destPath, MediaLibraryDataManager::GetInstance()->rdbStore_)) {
        MEDIA_ERR_LOG("Create file is existed %{private}s", destPath.c_str());
        return ERROR_TARGET_FILE_EXIST;
    }
    valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    valuesBucket.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, MediaAsset::GetMediaType(displayName));
    auto ret = MediaLibraryDataManager::GetInstance()->Insert(createFileUri, valuesBucket);
    if (ret > 0) {
        MediaType mediaType = MediaAsset::GetMediaType(displayName);
        string newUri = MediaFileUtils::GetFileMediaTypeUri(mediaType, "") + SLASH_CHAR + to_string(ret);
        newFileUri = Uri(newUri);
    }
    return ret;
}

int MediaFileExtAbility::Mkdir(const Uri &parentUri, const std::string &displayName, Uri &newFileUri)
{
    string parentUriStr = parentUri.ToString();
    MediaFileUriType uriType = MediaFileExtentionUtils::ResolveUri(parentUriStr);
    string relativePath;
    if (uriType != MediaFileUriType::URI_ROOT) {
        CHECK_AND_RETURN_RET_LOG(MediaFileExtentionUtils::CheckUriValid(parentUriStr),
            ERROR_URI_INVALID, "Mkdir invalid uri");
        CHECK_AND_RETURN_RET_LOG(MediaFileExtentionUtils::CheckDistributedUri(parentUriStr),
            ERROR_DISTIBUTED_URI_NO_SUPPORT, "Mkdir not support distributed operation");
        CHECK_AND_RETURN_RET_LOG(MediaFileUtils::CheckDisplayName(displayName),
            ERROR_INVAVLID_DISPLAY_NAME, "invalid directory displayName %{private}s", displayName.c_str());
        CHECK_AND_RETURN_RET_LOG(MediaFileExtentionUtils::GetAlbumRelativePathFromDB(parentUriStr, "", relativePath),
            ERROR_URI_IS_NOT_ALBUM, "selectUri is not valid album uri %{private}s", parentUriStr.c_str());
    } else {
        CHECK_AND_RETURN_RET_LOG(MediaFileExtentionUtils::CheckDistributedUri(parentUriStr),
            ERROR_DISTIBUTED_URI_NO_SUPPORT, "Mkdir not support distributed operation");
        CHECK_AND_RETURN_RET_LOG(MediaFileExtentionUtils::CheckValidDirName(displayName + SLASH_CHAR),
            ERROR_INVAVLID_DISPLAY_NAME, "invalid directory displayName %{private}s", displayName.c_str());
    }
    Uri mkdirUri(MEDIALIBRARY_DATA_URI + SLASH_CHAR + MEDIA_DIROPRN + SLASH_CHAR + MEDIA_DIROPRN_FMS_CREATEDIR);
    DataShareValuesBucket valuesBucket;
    string dirPath = ROOT_MEDIA_DIR + relativePath + displayName;
    if (MediaLibraryDataManagerUtils::isFileExistInDb(dirPath, MediaLibraryDataManager::GetInstance()->rdbStore_)) {
        MEDIA_ERR_LOG("Create dir is existed %{private}s", dirPath.c_str());
        return ERROR_TARGET_FILE_EXIST;
    }
    relativePath = relativePath + displayName + SLASH_CHAR;
    valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    if (MediaLibraryDataManager::GetInstance()->Insert(mkdirUri, valuesBucket) > 0) {
        MediaType mediaType = MediaAsset::GetMediaType(displayName);
        int32_t dirId = MediaLibraryDataManagerUtils::GetParentIdFromDb(dirPath,
            MediaLibraryDataManager::GetInstance()->rdbStore_);
        string newUri = MediaFileUtils::GetFileMediaTypeUri(mediaType, "") + SLASH_CHAR + to_string(dirId);
        newFileUri = Uri(newUri);
        return DATA_ABILITY_SUCCESS;
    }
    return DATA_ABILITY_FAIL;
}

int MediaFileExtAbility::Delete(const Uri &sourceFileUri)
{
    string sourceUri = sourceFileUri.ToString();
    if (!MediaFileExtentionUtils::CheckUriValid(sourceUri)) {
        return ERROR_URI_INVALID;
    }
    if (!MediaFileExtentionUtils::CheckDistributedUri(sourceUri)) {
        MEDIA_ERR_LOG("Delete not support distributed operation");
        return ERROR_DISTIBUTED_URI_NO_SUPPORT;
    }
    auto result = MediaFileExtentionUtils::GetFileFromDB(sourceUri, "");
    int count = 0;
    result->GetRowCount(count);
    CHECK_AND_RETURN_RET_LOG(count > 0, false, "AbsSharedResultSet empty");
    result->GoToFirstRow();
    int mediaType = get<int32_t>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_MEDIA_TYPE, result, TYPE_INT32));
    int errCode = 0;
    string id = MediaLibraryDataManagerUtils::GetIdFromUri(sourceUri);
    int fileId = stoi(id);
    if (mediaType == MEDIA_TYPE_ALBUM) {
        DataShareValuesBucket valuesBucket;
        valuesBucket.PutInt(MEDIA_DATA_DB_ID, fileId);
        Uri deleteAlbumUri(MEDIALIBRARY_DATA_URI + SLASH_CHAR + MEDIA_DIROPRN + SLASH_CHAR +
            MEDIA_DIROPRN_FMS_TRASHDIR);
        errCode = MediaLibraryDataManager::GetInstance()->Insert(deleteAlbumUri, valuesBucket);
    } else {
        DataShareValuesBucket valuesBucket;
        valuesBucket.PutInt(SMARTALBUMMAP_DB_ALBUM_ID, TRASH_ALBUM_ID_VALUES);
        valuesBucket.PutInt(SMARTALBUMMAP_DB_CHILD_ASSET_ID, fileId);
        Uri trashAssetUri(MEDIALIBRARY_DATA_URI + SLASH_CHAR
                + MEDIA_SMARTALBUMMAPOPRN + SLASH_CHAR + MEDIA_SMARTALBUMMAPOPRN_ADDSMARTALBUM);
        errCode = MediaLibraryDataManager::GetInstance()->Insert(trashAssetUri, valuesBucket);
    }
    return errCode;
}

std::vector<FileAccessFwk::FileInfo> MediaFileExtAbility::ListFile(const Uri &selectUri)
{
    vector<FileAccessFwk::FileInfo> fileList;
    MediaFileExtentionUtils::ListFile(selectUri.ToString(), fileList);
    return fileList;
}

std::vector<DeviceInfo> MediaFileExtAbility::GetRoots()
{
    vector<FileAccessFwk::DeviceInfo> deviceList;
    MediaFileExtentionUtils::GetRoots(deviceList);
    return deviceList;
}

int MediaFileExtAbility::Move(const Uri &sourceFileUri, const Uri &targetParentUri, Uri &newFileUri)
{
    return MediaFileExtentionUtils::Move(sourceFileUri, targetParentUri, newFileUri);
}

int MediaFileExtAbility::Rename(const Uri &sourceFileUri, const std::string &displayName, Uri &newFileUri)
{
    return MediaFileExtentionUtils::Rename(sourceFileUri, displayName, newFileUri);
}
} // Media
} // OHOS
