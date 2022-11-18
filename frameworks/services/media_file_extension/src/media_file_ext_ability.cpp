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
#define MLOG_TAG "FileExtension"

#include "media_file_ext_ability.h"

#include <fcntl.h>

#include "datashare_abs_result_set.h"
#include "extension_context.h"
#include "file_access_ext_stub_impl.h"
#include "js_runtime_utils.h"
#include "js_runtime.h"
#include "media_asset.h"
#include "media_file_extention_utils.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_errno.h"
#include "medialibrary_type_const.h"

namespace OHOS {
namespace Media {
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime;
using namespace OHOS::FileAccessFwk;
using namespace OHOS::DataShare;

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
    auto context = AbilityRuntime::Context::GetApplicationContext();
    if (context == nullptr) {
        MEDIA_ERR_LOG("Failed to get context");
        return;
    }
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

int MediaFileExtAbility::OpenFile(const Uri &uri, const int flags, int &fd)
{
    fd = -1;
    if (!MediaFileExtentionUtils::CheckUriValid(uri.ToString())) {
        return E_URI_INVALID;
    }
    string networkId = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(uri.ToString());
    if (!networkId.empty() && flags != O_RDONLY) {
        return E_OPENFILE_INVALID_FLAG;
    }
    string mode;
    if (flags == O_RDONLY) {
        mode = MEDIA_FILEMODE_READONLY;
    } else if (flags == O_WRONLY) {
        mode = MEDIA_FILEMODE_WRITEONLY;
    } else if (flags == O_RDWR) {
        mode = MEDIA_FILEMODE_READWRITE;
    } else {
        MEDIA_ERR_LOG("invalid OpenFile flags %{public}d", flags);
        return E_OPENFILE_INVALID_FLAG;
    }
    auto ret = MediaLibraryDataManager::GetInstance()->OpenFile(uri, mode);
    if (ret < 0) {
        return ret;
    } else {
        fd = ret;
        return E_SUCCESS;
    }
}

int MediaFileExtAbility::CreateFile(const Uri &parentUri, const string &displayName,  Uri &newFileUri)
{
    if (!MediaFileUtils::CheckDisplayName(displayName)) {
        MEDIA_ERR_LOG("invalid file displayName %{public}s", displayName.c_str());
        return E_INVAVLID_DISPLAY_NAME;
    }
    string parentUriStr = parentUri.ToString();
    auto ret = MediaFileExtentionUtils::CheckUriSupport(parentUriStr);
    CHECK_AND_RETURN_RET_LOG(ret == E_SUCCESS, ret, "invalid uri");
    Uri createFileUri(MEDIALIBRARY_DATA_URI + SLASH_CHAR + MEDIA_FILEOPRN + SLASH_CHAR + MEDIA_FILEOPRN_CREATEASSET);
    auto result = MediaFileExtentionUtils::GetResultSetFromDb(MEDIA_DATA_DB_URI, parentUriStr);
    if (result == nullptr) {
        MEDIA_ERR_LOG("CreateFile parent uri is not correct: %{public}s", parentUriStr.c_str());
        return E_URI_INVALID;
    }
    string albumPath = GetStringVal(MEDIA_DATA_DB_FILE_PATH, result);
    string relativePath = albumPath.substr(ROOT_MEDIA_DIR.size()) + SLASH_CHAR;
    string destPath = albumPath + SLASH_CHAR + displayName;
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_NAME, displayName);
    valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, MediaAsset::GetMediaType(displayName));
    ret = MediaLibraryDataManager::GetInstance()->Insert(createFileUri, valuesBucket);
    if (ret > 0) {
        newFileUri = Uri(MediaFileUtils::GetUriByNameAndId(displayName, "", ret));
        return E_SUCCESS;
    } else {
        MEDIA_ERR_LOG("CreateFile insert fail, %{public}d", ret);
        return ret;
    }
}

int MediaFileExtAbility::Mkdir(const Uri &parentUri, const string &displayName, Uri &newFileUri)
{
    string parentUriStr = parentUri.ToString();
    MediaFileUriType uriType;
    FileAccessFwk::FileInfo parentInfo;
    parentInfo.uri = parentUriStr;
    auto ret = MediaFileExtentionUtils::ResolveUri(parentInfo, uriType);
    if (ret != E_SUCCESS) {
        MEDIA_ERR_LOG("Mkdir::invalid input fileInfo");
        return ret;
    }
    string relativePath;
    ret = MediaFileExtentionUtils::CheckMkdirValid(uriType, parentUriStr, displayName);
    CHECK_AND_RETURN_RET_LOG(ret == E_SUCCESS, ret, "invalid uri");
    if (uriType != MediaFileUriType::URI_FILE_ROOT) {
        CHECK_AND_RETURN_RET_LOG(MediaFileExtentionUtils::GetAlbumRelativePathFromDB(parentUriStr, relativePath),
            E_URI_IS_NOT_ALBUM, "selectUri is not valid album uri %{public}s", parentUriStr.c_str());
    }
    Uri mkdirUri(MEDIALIBRARY_DATA_URI + SLASH_CHAR + MEDIA_DIROPRN + SLASH_CHAR + MEDIA_DIROPRN_FMS_CREATEDIR);
    string dirPath = ROOT_MEDIA_DIR + relativePath + displayName;
    if (MediaFileExtentionUtils::IsFileExistInDb(dirPath)) {
        MEDIA_ERR_LOG("Create dir is existed %{private}s", dirPath.c_str());
        return E_FILE_EXIST;
    }
    relativePath = relativePath + displayName + SLASH_CHAR;
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    ret = MediaLibraryDataManager::GetInstance()->Insert(mkdirUri, valuesBucket);
    if (ret > 0) {
        auto result = MediaFileExtentionUtils::GetResultSetFromDb(MEDIA_DATA_DB_ID, to_string(ret));
        if (result == nullptr) {
            MEDIA_ERR_LOG("The ret value is invalid: %{public}d", ret);
            return E_URI_INVALID;
        }
        int32_t dirId = GetInt32Val(MEDIA_DATA_DB_PARENT_ID, result);
        newFileUri = Uri(MediaFileUtils::GetUriByNameAndId(displayName, "", dirId));
        return E_SUCCESS;
    } else {
        MEDIA_ERR_LOG("mkdir insert fail, %{public}d", ret);
        return ret;
    }
}

int MediaFileExtAbility::Delete(const Uri &sourceFileUri)
{
    string sourceUri = sourceFileUri.ToString();
    auto ret = MediaFileExtentionUtils::CheckUriSupport(sourceUri);
    CHECK_AND_RETURN_RET_LOG(ret == E_SUCCESS, ret, "invalid uri");
    auto result = MediaFileExtentionUtils::GetResultSetFromDb(MEDIA_DATA_DB_URI, sourceUri);
    CHECK_AND_RETURN_RET_LOG(result != nullptr, E_URI_INVALID,
        "GetResultSetFromDb failed, uri: %{public}s", sourceUri.c_str());
    int mediaType = GetInt32Val(MEDIA_DATA_DB_MEDIA_TYPE, result);
    string id = MediaLibraryDataManagerUtils::GetIdFromUri(sourceUri);
    int fileId = stoi(id);
    int errCode = 0;
    DataShareValuesBucket valuesBucket;
    if (mediaType == MEDIA_TYPE_ALBUM) {
        valuesBucket.Put(MEDIA_DATA_DB_ID, fileId);
        Uri trashAlbumUri(MEDIALIBRARY_DATA_URI + SLASH_CHAR + MEDIA_DIROPRN + SLASH_CHAR +
            MEDIA_DIROPRN_FMS_TRASHDIR);
        errCode = MediaLibraryDataManager::GetInstance()->Insert(trashAlbumUri, valuesBucket);
    } else {
        valuesBucket.Put(SMARTALBUMMAP_DB_ALBUM_ID, TRASH_ALBUM_ID_VALUES);
        valuesBucket.Put(SMARTALBUMMAP_DB_CHILD_ASSET_ID, fileId);
        Uri trashAssetUri(MEDIALIBRARY_DATA_URI + SLASH_CHAR + MEDIA_SMARTALBUMMAPOPRN + SLASH_CHAR +
            MEDIA_SMARTALBUMMAPOPRN_ADDSMARTALBUM);
        errCode = MediaLibraryDataManager::GetInstance()->Insert(trashAssetUri, valuesBucket);
    }
    return errCode;
}

int MediaFileExtAbility::ListFile(const FileInfo &parentInfo, const int64_t offset, const int64_t maxCount,
    const DistributedFS::FileFilter &filter, std::vector<FileInfo> &fileList)
{
    return MediaFileExtentionUtils::ListFile(parentInfo, offset, maxCount, filter, fileList);
}

int MediaFileExtAbility::ScanFile(const FileInfo &parentInfo, const int64_t offset, const int64_t maxCount,
    const DistributedFS::FileFilter &filter, std::vector<FileInfo> &fileList)
{
    return MediaFileExtentionUtils::ScanFile(parentInfo, offset, maxCount, filter, fileList);
}

int MediaFileExtAbility::GetRoots(std::vector<FileAccessFwk::RootInfo> &rootList)
{
    return MediaFileExtentionUtils::GetRoots(rootList);
}

int MediaFileExtAbility::Move(const Uri &sourceFileUri, const Uri &targetParentUri, Uri &newFileUri)
{
    return MediaFileExtentionUtils::Move(sourceFileUri, targetParentUri, newFileUri);
}

int MediaFileExtAbility::Rename(const Uri &sourceFileUri, const string &displayName, Uri &newFileUri)
{
    return MediaFileExtentionUtils::Rename(sourceFileUri, displayName, newFileUri);
}

int MediaFileExtAbility::Access(const Uri &uri, bool &isExist)
{
    return MediaFileExtentionUtils::Access(uri, isExist);
}

int MediaFileExtAbility::UriToFileInfo(const Uri &selectFile, FileInfo &fileInfo)
{
    return MediaFileExtentionUtils::UriToFileInfo(selectFile, fileInfo);
}
} // Media
} // OHOS
