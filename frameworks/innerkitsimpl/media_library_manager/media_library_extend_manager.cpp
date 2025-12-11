/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#define MLOG_TAG "MediaLibraryExtendManager"

#include "media_library_extend_manager.h"

#include "accesstoken_kit.h"
#include "datashare_abs_result_set.h"
#include "datashare_predicates.h"
#include "file_uri.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "media_file_uri.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_tracer.h"
#include "medialibrary_type_const.h"
#include "media_app_uri_permission_column.h"
#include "media_app_uri_sensitive_column.h"
#include "moving_photo_file_utils.h"
#include "os_account_manager.h"
#include "permission_utils.h"
#include "result_set_utils.h"
#include "string_ex.h"
#include "system_ability_definition.h"
#include "unique_fd.h"
#include "userfilemgr_uri.h"
#include "data_secondary_directory_uri.h"
#include "user_inner_ipc_client.h"
#include "medialibrary_business_code.h"
#include "get_result_set_from_db_vo.h"
#include "get_result_set_from_photos_extend_vo.h"
#include "cancel_photo_uri_permission_inner_vo.h"
#include "grant_photo_uri_permission_inner_vo.h"
#include "check_photo_uri_permission_inner_vo.h"
#include "start_asset_change_scan_vo.h"
#include "get_asset_compress_version_vo.h"
#include "get_compress_asset_size_vo.h"
#include "notify_asset_sended_vo.h"
#include "open_asset_compress_vo.h"
#include "open_asset_compress_dto.h"

using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::Security::AccessToken;
namespace OHOS {
namespace Media {
constexpr int32_t URI_MAX_SIZE = 1000;
constexpr uint32_t URI_PERMISSION_FLAG_READ = 1;
constexpr uint32_t URI_PERMISSION_FLAG_WRITE = 2;
constexpr uint32_t URI_PERMISSION_FLAG_READWRITE = 3;
constexpr int32_t DEFUALT_USER_ID = 100;
constexpr int32_t DATASHARE_ERR = -1;
constexpr int64_t SHARE_UID = 5520;
constexpr int32_t COMPRESS_URI_MAX_SIZE = 500;
constexpr uint64_t BYTES_PER_KIB = 1024;
constexpr uint64_t KIB_ROUND_UP_MASK = BYTES_PER_KIB - 1;

static map<string, TableType> tableMap = {
    { MEDIALIBRARY_TYPE_IMAGE_URI, TableType::TYPE_PHOTOS },
    { MEDIALIBRARY_TYPE_VIDEO_URI, TableType::TYPE_PHOTOS },
    { MEDIALIBRARY_TYPE_AUDIO_URI, TableType::TYPE_AUDIOS },
    { PhotoColumn::PHOTO_TYPE_URI, TableType::TYPE_PHOTOS },
    { AudioColumn::AUDIO_TYPE_URI, TableType::TYPE_AUDIOS }
};

MediaLibraryExtendManager *MediaLibraryExtendManager::GetMediaLibraryExtendManager()
{
    static MediaLibraryExtendManager mediaLibMgr;
    return &mediaLibMgr;
}

static sptr<IRemoteObject> InitToken()
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_AND_RETURN_RET_LOG(saManager != nullptr, nullptr, "get system ability mgr failed.");

    auto remoteObj = saManager->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(remoteObj != nullptr, nullptr, "GetSystemAbility Service failed.");
    return remoteObj;
}

static int32_t GetCurrentAccountId()
{
    int32_t activeUserId = DEFUALT_USER_ID;
    ErrCode ret = OHOS::AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(activeUserId);
    if (ret != ERR_OK) {
        MEDIA_ERR_LOG("fail to get activeUser:%{public}d", ret);
    }
    return activeUserId;
}

void MediaLibraryExtendManager::InitMediaLibraryExtendManager()
{
    int32_t activeUser =  GetCurrentAccountId();
    if (dataShareHelper_ == nullptr || activeUser != userId_) {
        auto token = InitToken();
        if (token == nullptr) {
            MEDIA_ERR_LOG("fail to get token.");
            return;
        }
        dataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
        userId_ = activeUser;
    }
}

bool MediaLibraryExtendManager::ForceReconnect()
{
    dataShareHelper_ = nullptr;
    InitMediaLibraryExtendManager();
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr, false, "init manager fail");
    return true;
}

static int32_t CheckInputParameters(const vector<string> &urisSource, vector<uint32_t> flags)
{
    CHECK_AND_RETURN_RET_LOG(!urisSource.empty(), E_ERR, "Media Uri list is empty");
    CHECK_AND_RETURN_RET_LOG(urisSource.size() <= URI_MAX_SIZE, E_ERR,
        "Uri list is exceed one Thousand, current list size: %{public}d", (int)urisSource.size());
    CHECK_AND_RETURN_RET_LOG(flags.size() == urisSource.size(), E_ERR,
        "uri size not equal flag size: %{public}d", (int)flags.size());
    for (uint32_t flag : flags) {
        bool cond = (flag == 0 || flag > URI_PERMISSION_FLAG_READWRITE);
        CHECK_AND_RETURN_RET_LOG(!cond, E_ERR, "Flag is invalid, current flag is: %{public}d", flag);
    }
    return E_SUCCESS;
}

static void SaveCheckPermission(const string &fileId, map<std::string, pair<bool, bool>> &permissionMap,
    PhotoPermissionType currentType)
{
    switch (currentType) {
        case PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO:
            permissionMap[fileId].first = true;
            break;
        case PhotoPermissionType::PERSIST_READ_IMAGEVIDEO:
            permissionMap[fileId].first = true;
            break;
        case PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO:
            permissionMap[fileId].first = true;
            permissionMap[fileId].second = true;
            break;
        case PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO:
            permissionMap[fileId].second = true;
            break;
        case PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO:
            permissionMap[fileId].first = true;
            permissionMap[fileId].second = true;
            break;
        case PhotoPermissionType::PERSIST_READWRITE_IMAGEVIDEO:
            permissionMap[fileId].first = true;
            permissionMap[fileId].second = true;
            break;
        default:
            MEDIA_WARN_LOG("invalid permission, break");
    }
}

int32_t MediaLibraryExtendManager::QueryGrantedIndex(uint32_t targetTokenId,
    const std::string &uriType, const std::vector<string> &fileIds,
    std::map<string, pair<bool, bool>> &permissionMap, uint32_t businessCode)
{
    CheckUriPermissionInnerReqBody reqBody;
    reqBody.targetTokenId = static_cast<int64_t>(targetTokenId);
    reqBody.uriType = uriType;
    reqBody.fileIds = fileIds;
    reqBody.columns.emplace_back(AppUriPermissionColumn::FILE_ID);
    reqBody.columns.emplace_back(AppUriPermissionColumn::PERMISSION_TYPE);
    CheckUriPermissionInnerRespBody respBody;
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr, E_ERR,
        "Failed to checkPhotoUriPermission, datashareHelper is nullptr");
    MEDIA_INFO_LOG("before IPC::UserDefineIPCClient().Call, INNER_CHECK_URI_PERMISSION");
    int32_t result = IPC::UserInnerIPCClient().SetDataShareHelper(dataShareHelper_).Call(businessCode,
        reqBody, respBody);
    if (result != E_SUCCESS && ForceReconnect()) {
        MEDIA_WARN_LOG("QueryGrantedIndex Failed, reconnect and retry");
        result = IPC::UserInnerIPCClient().SetDataShareHelper(dataShareHelper_).Call(businessCode, reqBody, respBody);
    }
    CHECK_AND_RETURN_RET_LOG(result == E_SUCCESS, E_ERR, "QueryGrantedIndex Failed");
    auto fileIds_size = respBody.fileIds.size();
    auto permissionTypes_size = respBody.permissionTypes.size();
    bool isValid = (fileIds_size == permissionTypes_size);
    CHECK_AND_RETURN_RET_LOG(isValid, E_ERR, "Failed cause fileIds_size:%{public}zu"
        " not same to permissionTypes_size:%{public}zu", fileIds_size, permissionTypes_size);
    for (size_t i = 0; i < respBody.fileIds.size(); i++) {
        string fileId = respBody.fileIds[i];
        int32_t permissionType = respBody.permissionTypes[i];
        SaveCheckPermission(fileId, permissionMap, static_cast<PhotoPermissionType>(permissionType));
    }
    return E_SUCCESS;
}

static int32_t ClassifyUri(const vector<string> &urisSource, vector<string> &photoIds, vector<string> &audioIds)
{
    for (string uri : urisSource) {
        int32_t tableType = -1;
        for (const auto &iter : tableMap) {
            if (uri.find(iter.first) != string::npos) {
                tableType = static_cast<int32_t>(iter.second);
            }
        }

        CHECK_AND_RETURN_RET_LOG(tableType != -1, E_ERR, "Uri invalid error, uri:%{private}s", uri.c_str());
        string fileId = MediaFileUtils::GetIdFromUri(uri);
        if (tableType == static_cast<int32_t>(TableType::TYPE_PHOTOS)) {
            photoIds.push_back(fileId);
        } else if (tableType == static_cast<int32_t>(TableType::TYPE_AUDIOS)) {
            audioIds.push_back(fileId);
        } else {
            MEDIA_ERR_LOG("Uri invalid error, uri:%{private}s", uri.c_str());
            return E_ERR;
        }
    }
    return E_SUCCESS;
}

static void CheckPhotoAccessTokenPermission(uint32_t tokenId, const vector<string> &photoIds,
    map<string, pair<bool, bool>> &photoPermissionMap, bool readWriteIsolation)
{
    if (photoIds.size() > 0) {
        bool haveReadPermission = AccessTokenKit::VerifyAccessToken(tokenId, PERM_READ_IMAGEVIDEO) == 0;
        bool haveWritePermission = AccessTokenKit::VerifyAccessToken(tokenId, PERM_WRITE_IMAGEVIDEO) == 0;
        for (string fileId : photoIds) {
            if (haveReadPermission) {
                photoPermissionMap[fileId].first = true;
            }
            if (haveWritePermission && !readWriteIsolation) {
                photoPermissionMap[fileId].first = true;
                photoPermissionMap[fileId].second = true;
            }
            if (haveWritePermission && readWriteIsolation) {
                photoPermissionMap[fileId].second = true;
            }
        }
    }
}

static void CheckAudioAccessTokenPermission(uint32_t tokenId, const vector<string> &audioIds,
    map<string, pair<bool, bool>> &audioPermissionMap, bool readWriteIsolation)
{
    if (audioIds.size() > 0) {
        bool haveReadPermission = AccessTokenKit::VerifyAccessToken(tokenId, PERM_READ_AUDIO) == 0;
        bool haveWritePermission = AccessTokenKit::VerifyAccessToken(tokenId, PERM_WRITE_AUDIO) == 0;
        for (string fileId : audioIds) {
            if (haveReadPermission) {
                audioPermissionMap[fileId].first = true;
            }
            if (haveWritePermission && !readWriteIsolation) {
                audioPermissionMap[fileId].first = true;
                audioPermissionMap[fileId].second = true;
            }
            if (haveWritePermission && readWriteIsolation) {
                audioPermissionMap[fileId].second = true;
            }
        }
    }
}

static bool CheckPermissionByMap(const string &fileId, uint32_t flag,
    const map<string, pair<bool, bool>> &permissionMap)
{
    auto it = permissionMap.find(fileId);
    if (it == permissionMap.end()) {
        return false;
    }
    switch (flag) {
        case URI_PERMISSION_FLAG_READ:
            return it->second.first;
        case URI_PERMISSION_FLAG_WRITE:
            return it->second.second;
        case URI_PERMISSION_FLAG_READWRITE:
            return it->second.first && it->second.second;
        default:
            MEDIA_WARN_LOG("invalid check flag!");
            return false;
    }
}

int32_t MediaLibraryExtendManager::CheckPhotoUriPermission(uint32_t tokenId,
    const vector<string> &urisSource, vector<bool> &results, const vector<uint32_t> &flags,
    bool readWriteIsolation)
{
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryExtendManager::CheckPhotoUriPermission");
    auto ret = CheckInputParameters(urisSource, flags);
    CHECK_AND_RETURN_RET(ret == E_SUCCESS, E_ERR);
    map<string, pair<bool, bool>> photoPermissionMap;
    map<string, pair<bool, bool>> audioPermissionMap;
    vector<string> photoIds;
    vector<string> audioIds;
    ret = ClassifyUri(urisSource, photoIds, audioIds);
    CHECK_AND_RETURN_RET_LOG(ret == E_SUCCESS, E_ERR, "invalid uri");
    if (photoIds.size() > 0) {
        CheckPhotoAccessTokenPermission(tokenId, photoIds, photoPermissionMap, readWriteIsolation);
        uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::INNER_CHECK_PHOTO_URI_PERMISSION);
        ret = QueryGrantedIndex(tokenId, to_string(static_cast<int32_t>(TableType::TYPE_PHOTOS)),
            photoIds, photoPermissionMap, businessCode);
    }
    if (audioIds.size() > 0) {
        CheckAudioAccessTokenPermission(tokenId, audioIds, audioPermissionMap, readWriteIsolation);
        uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::INNER_CHECK_AUDIO_URI_PERMISSION);
        ret = QueryGrantedIndex(tokenId, to_string(static_cast<int32_t>(TableType::TYPE_AUDIOS)),
            audioIds, audioPermissionMap, businessCode);
    }
    CHECK_AND_RETURN_RET_LOG(ret == E_SUCCESS, E_ERR, "query db fail!");

    results.resize(urisSource.size(), false);
    for (size_t i = 0; i < urisSource.size(); i++) {
        string uri = urisSource.at(i);
        int32_t tableType = -1;
        for (const auto &iter : tableMap) {
            if (uri.find(iter.first) != string::npos) {
                tableType = static_cast<int32_t>(iter.second);
            }
        }
        string fileId = MediaFileUtils::GetIdFromUri(uri);
        if (tableType == static_cast<int32_t>(TableType::TYPE_AUDIOS)) {
            results[i] = CheckPermissionByMap(fileId, flags.at(i), audioPermissionMap);
        } else {
            results[i] = CheckPermissionByMap(fileId, flags.at(i), photoPermissionMap);
        }
    }
    return E_SUCCESS;
}

static int32_t CheckGrantPermission(const vector<string> &urisSource, vector<PhotoPermissionType> photoPermissionTypes,
    HideSensitiveType hideSensitiveTpye)
{
    bool cond = ((urisSource.empty()) || (urisSource.size() > URI_MAX_SIZE));
    CHECK_AND_RETURN_RET_LOG(!cond, E_ERR, "Media Uri list error, please check!");
    CHECK_AND_RETURN_RET_LOG(urisSource.size() == photoPermissionTypes.size(), E_ERR,
        "uris size not equal PermissionTypes size!");
    for (PhotoPermissionType photoPermissionType : photoPermissionTypes) {
        cond = (photoPermissionType < PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO ||
            photoPermissionType > PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO ||
            photoPermissionType == PhotoPermissionType::PERSIST_READWRITE_IMAGEVIDEO);
        CHECK_AND_RETURN_RET_LOG(!cond, E_ERR, "photoPermissionType error, please check param!");
    }

    cond = (hideSensitiveTpye < HideSensitiveType::ALL_DESENSITIZE ||
        hideSensitiveTpye > HideSensitiveType::DEFAULT);
    CHECK_AND_RETURN_RET_LOG(!cond, E_ERR, "HideSensitiveType error, please check param!");
    return E_SUCCESS;
}

int32_t MediaLibraryExtendManager::GrantPhotoUriPermission(uint32_t srcTokenId, uint32_t targetTokenId,
    const std::vector<string> &uris, const vector<PhotoPermissionType> &photoPermissionTypes,
    HideSensitiveType hideSensitiveTpye)
{
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryExtendManager::GrantPhotoUriPermission");
    auto ret = CheckGrantPermission(uris, photoPermissionTypes, hideSensitiveTpye);
    CHECK_AND_RETURN_RET(ret == E_SUCCESS, E_ERR);
    MEDIA_INFO_LOG("MediaLibraryExtendManager::GrantPhotoUriPermission Start");
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr, E_ERR, "dataShareHelper is nullptr");
    GrantUrisPermissionInnerReqBody reqBody;
    reqBody.tokenId = (int64_t)targetTokenId;
    reqBody.srcTokenId = (int64_t)srcTokenId;
    reqBody.hideSensitiveType = static_cast<int32_t>(hideSensitiveTpye);
    for (size_t i = 0; i < uris.size(); i++) {
        auto uri = uris.at(i);
        auto photoPermissionType = photoPermissionTypes.at(i);
        int32_t tableType = -1;
        for (const auto &iter : tableMap) {
            if (uri.find(iter.first) != string::npos) {
                tableType = static_cast<int32_t>(iter.second);
            }
        }
        CHECK_AND_RETURN_RET_LOG(tableType != -1, E_ERR, "Uri invalid error, uri:%{private}s", uri.c_str());
        string fileId = MediaFileUtils::GetIdFromUri(uri);
        reqBody.fileIds.emplace_back(fileId);
        reqBody.uriTypes.emplace_back(tableType);
        if (photoPermissionType == PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO) {
            reqBody.permissionTypes.emplace_back(static_cast<int32_t>(PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO));
            reqBody.fileIds.emplace_back(fileId);
            reqBody.uriTypes.emplace_back(tableType);
            reqBody.permissionTypes.emplace_back(static_cast<int32_t>(PhotoPermissionType::PERSIST_READ_IMAGEVIDEO));
            continue;
        }
        reqBody.permissionTypes.emplace_back(static_cast<int32_t>(photoPermissionType));
    }
    uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::INNER_GRANT_PHOTO_URI_PERMISSION);
    MEDIA_INFO_LOG("before IPC::UserDefineIPCClient().Call, INNER_GRANT_PHOTO_URI_PERMISSION");
    int32_t result = IPC::UserInnerIPCClient().SetDataShareHelper(dataShareHelper_).Call(businessCode, reqBody);
    if (result == E_ERR && ForceReconnect()) {
        MEDIA_WARN_LOG("Failed to Call INNER_GRANT_PHOTO_URI_PERMISSION and retry");
        result = IPC::UserInnerIPCClient().SetDataShareHelper(dataShareHelper_).Call(businessCode, reqBody);
    }
    return result;
}

static vector<string> BuildPermissionType(const bool persistFlag, const OperationMode mode)
{
    vector<string> permissionTypes;
    if (persistFlag) {
        if (static_cast<uint32_t>(mode) & static_cast<uint32_t>(OperationMode::READ_MODE)) {
            permissionTypes.push_back(
                to_string(static_cast<uint32_t>(PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO)));
            permissionTypes.push_back(
                to_string(static_cast<uint32_t>(PhotoPermissionType::PERSIST_READ_IMAGEVIDEO)));
        }
        if (static_cast<uint32_t>(mode) & static_cast<uint32_t>(OperationMode::WRITE_MODE)) {
            permissionTypes.push_back(
                to_string(static_cast<uint32_t>(PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO)));
            permissionTypes.push_back(
                to_string(static_cast<uint32_t>(PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO)));
        }
        if (static_cast<uint32_t>(mode) & static_cast<uint32_t>(OperationMode::READ_MODE) &&
            static_cast<uint32_t>(mode) & static_cast<uint32_t>(OperationMode::WRITE_MODE)) {
            permissionTypes.push_back(to_string(
                static_cast<uint32_t>(PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO)));
            permissionTypes.push_back(
                to_string(static_cast<uint32_t>(PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO)));
        }
    } else {
        permissionTypes.push_back(
            to_string(static_cast<uint32_t>(PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO)));
        permissionTypes.push_back(
            to_string(static_cast<uint32_t>(PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO)));
        permissionTypes.push_back(
            to_string(static_cast<uint32_t>(PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO)));
    }
    return permissionTypes;
}

int32_t MediaLibraryExtendManager::CancelPhotoUriPermission(uint32_t srcTokenId, uint32_t targetTokenId,
    const std::vector<string> &uris, const bool persistFlag, const vector<OperationMode> &operationModes)
{
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryExtendManager::CancelPhotoUriPermission");
    MEDIA_DEBUG_LOG("CancelPermission begin, srcToken:%{private}d, targetToken:%{private}d", srcTokenId, targetTokenId);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr, E_ERR, "dataShareHelper is nullptr");
    vector<OperationMode> operModesCopy;
    if (persistFlag) {
        operModesCopy.insert(operModesCopy.end(), operationModes.begin(), operationModes.end());
    } else {
        operModesCopy.resize(uris.size(), OperationMode::READ_WRITE_MODE);
    }
    vector<DataShareValuesBucket> valueSet;
    bool cond = ((uris.empty()) || (uris.size() > URI_MAX_SIZE) || (uris.size() != operModesCopy.size()));
    CHECK_AND_RETURN_RET_LOG(!cond, E_ERR, "Media Uri list error, please check!");
    CancelUriPermissionInnerReqBody reqBody;
    reqBody.targetTokenId = (int64_t)targetTokenId;
    reqBody.srcTokenId = (int64_t)srcTokenId;
    for (size_t i = 0; i < uris.size(); i++) {
        string uri = uris[i];
        int32_t tableType = -1;
        for (const auto &iter : tableMap) {
            if (uri.find(iter.first) != string::npos) {
                tableType = static_cast<int32_t>(iter.second);
            }
        }
        CHECK_AND_RETURN_RET_LOG(tableType != -1, E_ERR, "Uri invalid error, uri:%{private}s", uri.c_str());
        string fileId = MediaFileUtils::GetIdFromUri(uri);
        MEDIA_DEBUG_LOG("CancelPermission fileId:%{private}s, tableType:%{private}d", fileId.c_str(), tableType);
        reqBody.fileIds.emplace_back(fileId);
        reqBody.uriTypes.emplace_back(tableType);
        vector<string> permissionTypes = BuildPermissionType(persistFlag, operModesCopy[i]);
        reqBody.permissionTypes.emplace_back(permissionTypes);
    }
    uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::INNER_CANCEL_PHOTO_URI_PERMISSION);
    MEDIA_INFO_LOG("before IPC::UserDefineIPCClient().Call, INNER_CANCEL_PHOTO_URI_PERMISSION");
    int32_t result = IPC::UserInnerIPCClient().SetDataShareHelper(dataShareHelper_).Call(businessCode, reqBody);
    return result;
}

static bool CheckUri(string &uri)
{
    if (uri.find("../") != string::npos) {
        return false;
    }
    string uriprex = "file://media";
    return uri.substr(0, uriprex.size()) == uriprex;
}

int32_t MediaLibraryExtendManager::OpenAsset(string &uri, const string openMode, HideSensitiveType type)
{
    CHECK_AND_RETURN_RET(!openMode.empty(), E_ERR);
    CHECK_AND_RETURN_RET_LOG(CheckUri(uri), E_ERR, "invalid uri");

    string originOpenMode = openMode;
    std::transform(originOpenMode.begin(), originOpenMode.end(),
        originOpenMode.begin(), [](unsigned char c) {return std::tolower(c);});
    CHECK_AND_RETURN_RET(MEDIA_OPEN_MODES.count(originOpenMode), E_ERR);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr, E_ERR, "Failed to open Asset, datashareHelper is nullptr");

    string assetUri = uri;
    MediaFileUtils::UriAppendKeyValue(assetUri, "type", to_string(static_cast<int32_t>(type)));
    MEDIA_DEBUG_LOG("merged uri = %{public}s", assetUri.c_str());
    Uri openUri(assetUri);
    int ret = dataShareHelper_->OpenFile(openUri, openMode);
    if (ret == DATASHARE_ERR && ForceReconnect()) {
        MEDIA_WARN_LOG("Failed to OpenFile and retry");
        ret = dataShareHelper_->OpenFile(openUri, openMode);
    }
    return ret;
}

int32_t MediaLibraryExtendManager::ReadPrivateMovingPhoto(string &uri, const HideSensitiveType type)
{
    CHECK_AND_RETURN_RET_LOG(CheckUri(uri), E_ERR, "invalid uri: %{public}s", uri.c_str());
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr, E_ERR,
        "Failed to read video of moving photo, datashareHelper is nullptr");

    string movingPhotoUri = uri;
    MediaFileUtils::UriAppendKeyValue(movingPhotoUri, "type", to_string(static_cast<int32_t>(type)));
    MediaFileUtils::UriAppendKeyValue(movingPhotoUri, MEDIA_MOVING_PHOTO_OPRN_KEYWORD, OPEN_PRIVATE_LIVE_PHOTO);
    Uri openMovingPhotoUri(movingPhotoUri);
    int ret = dataShareHelper_->OpenFile(openMovingPhotoUri, MEDIA_FILEMODE_READONLY);
    if (ret == DATASHARE_ERR && ForceReconnect()) {
        MEDIA_WARN_LOG("Failed to OpenFile and retry");
        ret = dataShareHelper_->OpenFile(openMovingPhotoUri, MEDIA_FILEMODE_READONLY);
    }
    return ret;
}

static bool CheckPhotoUri(const string &uri)
{
    if (uri.find("../") != string::npos) {
        return false;
    }
    string photoUriPrefix = "file://media/Photo/";
    return MediaFileUtils::StartsWith(uri, photoUriPrefix);
}

std::shared_ptr<DataShareResultSet> MediaLibraryExtendManager::GetResultSetFromPhotos(const string &value,
    vector<string> &columns)
{
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr, nullptr, "datashareHelper is nullptr");
    if (!CheckPhotoUri(value)) {
        MEDIA_ERR_LOG("Failed to check invalid uri: %{public}s", value.c_str());
        return nullptr;
    }

    GetResultSetFromPhotosExtendReqBody reqBody;
    reqBody.value = value;
    reqBody.columns = columns;
    uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::INNER_GET_RESULT_SET_FROM_PHOTOS_EXTEND);
    GetResultSetFromDbRespBody respBody;
    int32_t errCode =
        IPC::UserInnerIPCClient().SetDataShareHelper(dataShareHelper_).Call(businessCode, reqBody, respBody);
    if (errCode != E_OK) {
        MEDIA_WARN_LOG("errCode: %{public}d, reconnect and retry", errCode);
        if (ForceReconnect()) {
            errCode =
                IPC::UserInnerIPCClient().SetDataShareHelper(dataShareHelper_).Call(businessCode, reqBody, respBody);
        }
        if (errCode != E_OK) {
            MEDIA_ERR_LOG("errCode: %{public}d", errCode);
            return nullptr;
        }
    }
    return respBody.resultSet;
}
                                   
int32_t MediaLibraryExtendManager::SendBrokerChangeOperation(string operation)
{
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr, E_ERR, "datashareHelper is nullptr");
    StartAssetChangeScanReqBody reqBody;
    reqBody.operation = operation;

    uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::INNER_CHANGE_SCAN_ASSET);
    MEDIA_INFO_LOG("before IPC::UserDefineIPCClient().Call, INNER_CHANGE_SCAN_ASSET");
    int32_t errCode =
        IPC::UserInnerIPCClient().SetDataShareHelper(dataShareHelper_).Call(businessCode, reqBody);
    return errCode;
}

std::shared_ptr<DataShareResultSet> MediaLibraryExtendManager::GetResultSetFromDb(string columnName,
    const string &value, vector<string> &columns)
{
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr, nullptr, "dataShareHelper is null");
    if (columnName == MEDIA_DATA_DB_URI) {
        return GetResultSetFromPhotos(value, columns);
    }

    GetResultSetFromDbReqBody reqBody;
    reqBody.columnName = columnName;
    reqBody.value = value;
    reqBody.columns = columns;
    uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::INNER_GET_RESULT_SET_FROM_DB_EXTEND);
    GetResultSetFromDbRespBody respBody;
    int32_t errCode =
        IPC::UserInnerIPCClient().SetDataShareHelper(dataShareHelper_).Call(businessCode, reqBody, respBody);
    if (errCode != E_OK) {
        MEDIA_WARN_LOG("errCode: %{public}d, reconnect and retry", errCode);
        if (ForceReconnect()) {
            errCode =
                IPC::UserInnerIPCClient().SetDataShareHelper(dataShareHelper_).Call(businessCode, reqBody, respBody);
        }
        if (errCode != E_OK) {
            MEDIA_ERR_LOG("errCode: %{public}d", errCode);
            return nullptr;
        }
    }
    return respBody.resultSet;
}

static bool CheckPermissionType(const string &fileId, map<string, pair<bool, bool>> &permissionMap,
    PhotoPermissionType checkType)
{
    auto it = permissionMap.find(fileId);
    if (it == permissionMap.end()) {
        return false;
    }
    switch (checkType) {
        case PhotoPermissionType::PERSIST_READ_IMAGEVIDEO:
            return it->second.first;
        case PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO:
            return it->second.second;
        case PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO:
            return it->second.first && it->second.second;
        default:
            MEDIA_WARN_LOG("invalid permissiontype");
            return false;
    }
}

static void SavePermission(const string &fileId, map<string, pair<bool, bool>> &permissionMap,
    PhotoPermissionType currentType)
{
    switch (currentType) {
        case PhotoPermissionType::PERSIST_READ_IMAGEVIDEO:
            permissionMap[fileId].first = true;
            break;
        case PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO:
            permissionMap[fileId].second = true;
            break;
        default:
            MEDIA_WARN_LOG("invalid permission, break");
            return;
    }
}

int32_t MediaLibraryExtendManager::GetPhotoUrisPermission(uint32_t targetTokenId, const std::vector<string> &uris,
    PhotoPermissionType photoPermissionType, std::vector<bool> &result)
{
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr, E_ERR, "dataShareHelper is nullptr");
    MEDIA_DEBUG_LOG("GetPhotoUrisPermission begin, targetTokenId:%{private}d", targetTokenId);

    vector<string> columns = {
        AppUriPermissionColumn::FILE_ID,
        AppUriPermissionColumn::PERMISSION_TYPE,
        AppUriPermissionColumn::TARGET_TOKENID
    };

    DataSharePredicates predicates;
    predicates.EqualTo(AppUriPermissionColumn::TARGET_TOKENID, static_cast<int64_t>(targetTokenId));

    result.resize(uris.size(), false);

    std::vector<std::string> fileIds;
    for (const auto &uri : uris) {
        fileIds.push_back(MediaFileUtils::GetIdFromUri(uri));
    }
    predicates.In(AppUriPermissionColumn::FILE_ID, fileIds);

    Uri queryUri(MEDIALIBRARY_CHECK_URIPERM_URI);
    auto queryResultSet = dataShareHelper_->Query(queryUri, predicates, columns);
    if (queryResultSet == nullptr) {
        MEDIA_ERR_LOG("Failed to query Uris");
        return E_ERR;
    }

    map<string, pair<bool, bool>> permissionMap;
    while (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
        string fileId = GetStringVal(AppUriPermissionColumn::FILE_ID, queryResultSet);
        int32_t permissionType = GetInt32Val(AppUriPermissionColumn::PERMISSION_TYPE, queryResultSet);
        SavePermission(fileId, permissionMap, static_cast<PhotoPermissionType>(permissionType));
    }

    for (size_t i = 0; i < uris.size(); ++i) {
        string fileId = MediaFileUtils::GetIdFromUri(uris[i]);
        result[i] = CheckPermissionType(fileId, permissionMap, photoPermissionType); 
    }
    return E_SUCCESS;
}

int32_t MediaLibraryExtendManager::GetPhotoUrisPermission(uint32_t targetTokenId, const std::vector<string> &uris,
    const vector<PhotoPermissionType> &photoPermissionTypes, std::vector<bool> &result)
{
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryExtendManager::GetPhotoUrisPermission");
    CHECK_AND_RETURN_RET_LOG(!uris.empty() && uris.size() <= URI_MAX_SIZE && uris.size() == photoPermissionTypes.size(),
        E_ERR, "Uri or photoPermissionType list error, please check!");

    std::set<PhotoPermissionType> queryTypes;
    for (auto &photoPermissionType : photoPermissionTypes) {
        if (photoPermissionType != PhotoPermissionType::PERSIST_READ_IMAGEVIDEO &&
            photoPermissionType != PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO &&
            photoPermissionType != PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO) {
            MEDIA_ERR_LOG("photoPermissionType error, please check param!");
            return E_ERR;
        }
        queryTypes.insert(photoPermissionType);
    }

    std::vector<bool> persistReadResult(uris.size(), false);
    std::vector<bool> persistReadWriteResult(uris.size(), false);
    std::vector<bool> persistWriteResult(uris.size(), false);
    map<PhotoPermissionType, std::vector<bool>> typeMap = {
        { PhotoPermissionType::PERSIST_READ_IMAGEVIDEO, persistReadResult },
        { PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO, persistWriteResult },
        { PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO, persistReadWriteResult },
    };
    for (auto& type : queryTypes) {
        int32_t ret = GetPhotoUrisPermission(targetTokenId, uris, type, typeMap[type]);
        if (ret != E_SUCCESS) {
            MEDIA_ERR_LOG("Failed to get permission: %d", type);
            return E_ERR;
        }
    }

    result.resize(uris.size(), false);
    for (size_t i = 0; i < uris.size(); ++i) {
        result[i] = typeMap[photoPermissionTypes[i]][i];
    }
    return E_SUCCESS;
}

int32_t MediaLibraryExtendManager::GetUrisFromFusePaths(const std::vector<std::string> paths,
    std::vector<std::string> &uris)
{
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryExtendManager::GetUrisFromFusePaths");

    if ((paths.empty()) || (paths.size() > URI_MAX_SIZE)) {
        MEDIA_ERR_LOG("Path list error, please check!");
        return E_ERR;
    }
    const std::string FUSE_PATH_PREFIX_1 = "/data/storage/el2/media/";
    const std::string FUSE_PATH_PREFIX_2 = "/mnt/data/100/media_fuse/";
    const std::string URI_PREFIX = "file://media/";

    for (const auto &path : paths) {
        if (path.compare(0, FUSE_PATH_PREFIX_1.length(), FUSE_PATH_PREFIX_1) == 0) {
            std::string uri = URI_PREFIX + path.substr(FUSE_PATH_PREFIX_1.length());
            uris.push_back(uri);
        } else if (path.compare(0, FUSE_PATH_PREFIX_2.length(), FUSE_PATH_PREFIX_2) == 0) {
            std::string uri = URI_PREFIX + path.substr(FUSE_PATH_PREFIX_2.length());
            uris.push_back(uri);
        } else {
            MEDIA_ERR_LOG("Invalid path: %{private}s", path.c_str());
            return E_ERR;
        }
    }
    return E_SUCCESS;
}

int32_t MediaLibraryExtendManager::CheckCloudDownloadPermission(uint32_t tokenId,
    const std::vector<std::string> &uris, std::vector<bool> &result, const std::vector<uint32_t> &flags)
{
    uint64_t tokenIdEx = IPCSkeleton::GetCallingFullTokenID();
    CHECK_AND_RETURN_RET_LOG(TokenIdKit::IsSystemAppByFullTokenID(tokenIdEx),
        E_ERR, "only invoke by systemapp");
    return CheckPhotoUriPermission(tokenId, uris, result, flags, true);
}

int32_t MediaLibraryExtendManager::OpenAssetCompress(const string &uri, HideSensitiveType type, int32_t version)
{
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryExtendManager::OpenAssetCompress");
    MEDIA_INFO_LOG("OpenAssetCompress begin");

    CHECK_AND_RETURN_RET_LOG(IPCSkeleton::GetCallingUid() == SHARE_UID, E_ERR, "only support share");
    CHECK_AND_RETURN_RET_LOG(CheckPhotoUri(uri), E_ERR, "Invalid uri");
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr, E_ERR, "Failed to open Asset, datashareHelper is nullptr");

    OpenAssetCompressReqBody reqBody;
    reqBody.uri = uri;
    reqBody.version = version;
    reqBody.type = static_cast<int32_t>(type);
    uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::INNER_OPEN_ASSET_COMPRESS);
    OpenAssetCompressRespBody respBody;
    int32_t errCode =
        IPC::UserInnerIPCClient().SetDataShareHelper(dataShareHelper_).Call(businessCode, reqBody, respBody);
    if (errCode != E_SUCCESS) {
        MEDIA_WARN_LOG("errCode: %{public}d, reconnect and retry", errCode);
        if (ForceReconnect()) {
            errCode =
                IPC::UserInnerIPCClient().SetDataShareHelper(dataShareHelper_).Call(businessCode, reqBody, respBody);
        }
        CHECK_AND_RETURN_RET_LOG(errCode == E_SUCCESS, E_ERR, "OpenAssetCompress failed, errCode: %{public}d", errCode);
    }
    return respBody.fileDescriptor;
}

int32_t MediaLibraryExtendManager::GetAssetCompressVersion()
{
    MEDIA_INFO_LOG("GetAssetCompressVersion begin");
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr, E_ERR, "dataShareHelper is null");

    GetAssetCompressVersionRespBody respBody;
    uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::INNER_GET_ASSET_COMPRESS_VERSION);
    int32_t errCode =
        IPC::UserInnerIPCClient().SetDataShareHelper(dataShareHelper_).Get(businessCode, respBody);
    if (errCode != E_SUCCESS) {
        MEDIA_WARN_LOG("errCode: %{public}d, reconnect and retry", errCode);
        if (ForceReconnect()) {
            errCode =
                IPC::UserInnerIPCClient().SetDataShareHelper(dataShareHelper_).Get(businessCode, respBody);
        }
        CHECK_AND_RETURN_RET_LOG(errCode == E_SUCCESS, E_ERR,
            "GetAssetCompressVersion failed, errCode: %{public}d", errCode);
    }
    MEDIA_INFO_LOG("GetAssetCompressVersion end, version=%{public}d", respBody.version);
    return respBody.version;
}

int32_t MediaLibraryExtendManager::NotifyAssetSended(const string &uri)
{
    MEDIA_INFO_LOG("NotifyAssetSended begin, uri:%{private}s", uri.c_str());
    CHECK_AND_RETURN_RET_LOG(CheckPhotoUri(uri), E_ERR, "invalid uri");
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr, E_ERR, "dataShareHelper is null");

    NotifyAssetSendedReqBody reqBody;
    reqBody.uri = uri;
    uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::INNER_NOTIFY_ASSET_SENDED);
    int32_t errCode =
        IPC::UserInnerIPCClient().SetDataShareHelper(dataShareHelper_).Call(businessCode, reqBody);
    if (errCode != E_SUCCESS) {
        MEDIA_WARN_LOG("errCode: %{public}d, reconnect and retry", errCode);
        if (ForceReconnect()) {
            errCode =
                IPC::UserInnerIPCClient().SetDataShareHelper(dataShareHelper_).Call(businessCode, reqBody);
        }
        CHECK_AND_RETURN_RET_LOG(errCode == E_SUCCESS, E_ERR, "NotifyAssetSended failed, errCode: %{public}d", errCode);
    }
    return E_SUCCESS;
}

int32_t MediaLibraryExtendManager::GetCompressAssetSize(const std::vector<std::string> &uris)
{
    MEDIA_INFO_LOG("GetCompressAssetSize begin, count: %{public}zu", uris.size());
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr, E_ERR, "dataShareHelper is null");
    CHECK_AND_RETURN_RET_LOG(uris.size() > 0 && uris.size() <= COMPRESS_URI_MAX_SIZE, E_ERR, "invalid uris size");
    GetCompressAssetSizeReqBody reqBody;
    reqBody.uris = uris;
    GetCompressAssetSizeRespBody respBody;
    uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::INNER_GET_COMPRESS_ASSET_SIZE);
    int32_t errCode =
        IPC::UserInnerIPCClient().SetDataShareHelper(dataShareHelper_).Call(businessCode, reqBody, respBody);
    if (errCode != E_SUCCESS) {
        MEDIA_WARN_LOG("errCode: %{public}d, reconnect and retry", errCode);
        if (ForceReconnect()) {
            errCode =
                IPC::UserInnerIPCClient().SetDataShareHelper(dataShareHelper_).Call(businessCode, reqBody, respBody);
        }
    }
    CHECK_AND_RETURN_RET_LOG(errCode == E_SUCCESS, E_ERR, "GetCompressAssetSize failed, errCode: %{public}d", errCode);

    uint64_t totalBytes = respBody.totalSize;
    uint64_t totalKiB = (totalBytes + KIB_ROUND_UP_MASK) / BYTES_PER_KIB;
    CHECK_AND_RETURN_RET_LOG(totalKiB <= static_cast<uint64_t>(INT32_MAX), E_ERR,
        "Total size in KiB overflow: %{public}" PRIu64 " KiB", totalKiB);
    int32_t resultKiB = static_cast<int32_t>(totalKiB);
    MEDIA_INFO_LOG("GetCompressAssetSize success, total bytes: %{public}" PRIu64 ", estimated KiB: %{public}d",
        totalBytes, resultKiB);
    return resultKiB;
}
} // namespace Media
} // namespace OHOS