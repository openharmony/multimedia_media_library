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

#include "media_lib_service_const.h"
#include "extension_context.h"
#include "file_ext_stub_impl.h"
#include "ability_info.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "media_log.h"
#include "medialibrary_data_manager.h"
#include "media_file_extention_utils.h"
#include "media_asset.h"
#include "media_file_extention_utils.h"
#include "medialibrary_object_utils.h"

namespace OHOS {
namespace Media {
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime;
using namespace OHOS::FileAccessFwk;

MediaFileExtAbility::MediaFileExtAbility(JsRuntime& jsRuntime) : jsRuntime_(jsRuntime) {}

MediaFileExtAbility::~MediaFileExtAbility()
{
}

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
    FileExtAbility::SetCreator(MediaFileExtCreator);
}

void MediaFileExtAbility::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application, std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    MEDIA_INFO_LOG("Init MediaFileExtAbility");
    FileExtAbility::Init(record, application, handler, token);
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

sptr<IRemoteObject> MediaFileExtAbility::OnConnect(const AAFwk::Want &want)
{
    MEDIA_DEBUG_LOG("OnConnect MediaFileExtAbility");
    Extension::OnConnect(want);
    sptr<FileExtStubImpl> remoteObject = new (std::nothrow) FileExtStubImpl(
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
    MEDIA_DEBUG_LOG("%{public}s begin.", __func__);
    string mode = MEDIA_FILEMODE_READONLY;
    if (flags == 1) {
        mode = MEDIA_FILEMODE_WRITEONLY;
    } else if (flags > 1) {
        mode = MEDIA_FILEMODE_READWRITE;
    }
    return MediaLibraryDataManager::GetInstance()->OpenFile(uri, mode);
}

int MediaFileExtAbility::CreateFile(const Uri &parentUri, const std::string &displayName,  Uri &newFileUri)
{
    Uri createFileUri(MEDIALIBRARY_DATA_URI + SLASH_CHAR + MEDIA_FILEOPRN + SLASH_CHAR + MEDIA_FILEOPRN_CREATEASSET);
    DataShareValuesBucket valuesBucket;
    valuesBucket.PutString(MEDIA_DATA_DB_NAME, displayName);
    string albumId = MediaLibraryDataManagerUtils::GetIdFromUri(parentUri.ToString());
    MediaLibraryObjectUtils objectUtils;
    string albumPath = objectUtils.GetPathByIdFromDb(albumId);
    string relativePath = albumPath.substr(ROOT_MEDIA_DIR.size()) + '/';
    valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    valuesBucket.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, MediaAsset::GetMediaType(displayName));
    auto ret = MediaLibraryDataManager::GetInstance()->Insert(createFileUri, valuesBucket);
    if (ret > 0) {
        MediaType mediaType = MediaAsset::GetMediaType(displayName);
        string networkId = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(parentUri.ToString());
        string newUri = MediaFileExtentionUtils::GetFileMediaTypeUri(mediaType, networkId) +
            SLASH_CHAR + to_string(ret);
        newFileUri = Uri(newUri);
    }
    return ret;
}

int MediaFileExtAbility::Mkdir(const Uri &parentUri, const std::string &displayName, Uri &newFileUri)
{
    string parentUriStr = parentUri.ToString();
    if (!MediaFileExtentionUtils::CheckSupport(parentUriStr)) {
        MEDIA_ERR_LOG("Mkdir not support distributed operation");
        return DATA_ABILITY_FAIL;
    }
    Uri mkdirUri(MEDIALIBRARY_DATA_URI + SLASH_CHAR + MEDIA_DIROPRN + SLASH_CHAR + MEDIA_DIROPRN_FMS_CREATEDIR);
    DataShareValuesBucket valuesBucket;
    string relativePath;
    if (!MediaFileExtentionUtils::GetAlbumRelativePath(parentUriStr, "", relativePath)) {
        MEDIA_ERR_LOG("selectUri is not valid album uri");
        return DATA_ABILITY_FAIL;
    }
    relativePath = relativePath + displayName + SLASH_CHAR;
    valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    auto ret = MediaLibraryDataManager::GetInstance()->Insert(mkdirUri, valuesBucket);
    if (ret > 0) {
        MediaType mediaType = MediaAsset::GetMediaType(displayName);
        string networkId = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(parentUri.ToString());
        string newUri = MediaFileExtentionUtils::GetFileMediaTypeUri(mediaType, networkId) +
            SLASH_CHAR + to_string(ret);
        newFileUri = Uri(newUri);
    }
    return ret;
}

int MediaFileExtAbility::Delete(const Uri &sourceFileUri)
{
    string sourceUri = sourceFileUri.ToString();
    if (!MediaFileExtentionUtils::CheckSupport(sourceUri)) {
        MEDIA_ERR_LOG("Delete not support distributed operation");
        return DATA_ABILITY_FAIL;
    }
    auto result = MediaFileExtentionUtils::GetFileFromRdb(sourceUri, "");
    int count = 0;
    result->GetRowCount(count);
    CHECK_AND_RETURN_RET_LOG(count != 0, false, "AbsSharedResultSet null");
    result->GoToFirstRow();
    int columnIndex = 0, mediaType = MEDIA_TYPE_FILE;
    result->GetColumnIndex(MEDIA_DATA_DB_MEDIA_TYPE, columnIndex);
    result->GetInt(columnIndex, mediaType);
    int errCode = 0;
    string id = MediaLibraryDataManagerUtils::GetIdFromUri(sourceUri);
    int fileId = stoi(id);
    if (mediaType == MEDIA_TYPE_ALBUM) {
        DataShareValuesBucket valuesBucket;
        valuesBucket.PutInt(MEDIA_DATA_DB_ID, fileId);
        Uri deleteAlbumUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_DIROPRN + "/" + MEDIA_DIROPRN_FMS_TRASHDIR);
        errCode = MediaLibraryDataManager::GetInstance()->Insert(deleteAlbumUri, valuesBucket);
    } else {
        DataShareValuesBucket valuesBucket;
        valuesBucket.PutInt(SMARTALBUMMAP_DB_ALBUM_ID, TRASH_ALBUM_ID_VALUES);
        valuesBucket.PutInt(SMARTALBUMMAP_DB_CHILD_ASSET_ID, fileId);
        Uri trashAssetUri(MEDIALIBRARY_DATA_URI + "/"
                + MEDIA_SMARTALBUMMAPOPRN + "/" + MEDIA_SMARTALBUMMAPOPRN_ADDSMARTALBUM);
        errCode = MediaLibraryDataManager::GetInstance()->Insert(trashAssetUri, valuesBucket);
    }
    return errCode;
}

std::vector<FileAccessFwk::FileInfo> MediaFileExtAbility::ListFile(const Uri &selectUri)
{
    MEDIA_DEBUG_LOG("%{public}s begin.", __func__);
    std::vector<string> typeArray;
    auto ret = MediaFileExtentionUtils::ListFile(selectUri.ToString());
    MEDIA_DEBUG_LOG("%{public}s end.", __func__);
    return ret;
}

std::vector<DeviceInfo> MediaFileExtAbility::GetRoots()
{
    MEDIA_DEBUG_LOG("%{public}s begin.", __func__);
    return MediaFileExtentionUtils::GetRoots();
}

int MediaFileExtAbility::Rename(const Uri &sourceFileUri, const std::string &displayName, Uri &newFileUri)
{
    MEDIA_DEBUG_LOG("%{public}s begin.", __func__);
    auto ret = MediaFileExtentionUtils::Rename(sourceFileUri, displayName, newFileUri);
    return ret;
}
} // Media
} // OHOS
