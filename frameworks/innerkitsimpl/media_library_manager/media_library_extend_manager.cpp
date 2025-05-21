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

static vector<string> READPERMISSIONS_STR = {
    to_string(static_cast<int32_t>(PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO)),
    to_string(static_cast<int32_t>(PhotoPermissionType::PERSIST_READ_IMAGEVIDEO)),
    to_string(static_cast<int32_t>(PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO)),
    to_string(static_cast<int32_t>(PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO)),
    to_string(static_cast<int32_t>(PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO)),
    to_string(static_cast<int32_t>(PhotoPermissionType::PERSIST_READWRITE_IMAGEVIDEO)),
    to_string(static_cast<int32_t>(PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO)),
};

static vector<string> WRITEPERMISSIONS_STR = {
    to_string(static_cast<int32_t>(PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO)),
    to_string(static_cast<int32_t>(PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO)),
    to_string(static_cast<int32_t>(PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO)),
    to_string(static_cast<int32_t>(PhotoPermissionType::PERSIST_READWRITE_IMAGEVIDEO)),
    to_string(static_cast<int32_t>(PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO)),
};

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

static int32_t UrisSourceMediaTypeClassify(const vector<string> &urisSource, const vector<uint32_t> flags,
    map<uint32_t, vector<int32_t>> &photoFileIds, map<uint32_t, vector<int32_t>> &audioFileIds)
{
    for (size_t i = 0; i < urisSource.size(); i++) {
        string uri = urisSource.at(i);
        uint32_t flag = flags.at(i);
        int32_t tableType = -1;
        for (const auto &iter : tableMap) {
            if (uri.find(iter.first) != string::npos) {
                tableType = static_cast<int32_t>(iter.second);
            }
        }

        CHECK_AND_RETURN_RET_LOG(tableType != -1, E_ERR, "Uri invalid error, uri:%{private}s", uri.c_str());
        if (tableType == static_cast<int32_t>(TableType::TYPE_PHOTOS)) {
            auto it = photoFileIds.find(flag);
            if (it != photoFileIds.end()) {
                it->second.push_back(i);
            } else {
                photoFileIds[flag] = {i};
            }
        } else if (tableType == static_cast<int32_t>(TableType::TYPE_AUDIOS)) {
            auto it = audioFileIds.find(flag);
            if (it != audioFileIds.end()) {
                it->second.push_back(i);
            } else {
                audioFileIds[flag] = {i};
            }
        } else {
            MEDIA_ERR_LOG("Uri invalid error, uri:%{private}s", uri.c_str());
            return E_ERR;
        }
    }
    return E_SUCCESS;
}

static void CheckAccessTokenPermission(uint32_t tokenId, map<uint32_t, vector<int32_t>> checkFlags,
    TableType mediaType, map<int32_t, vector<int32_t>> &queryFlags, vector<int32_t> &hasPermissionIndex)
{
    static map<TableType, string> readPermmisionMap = {
        { TableType::TYPE_PHOTOS, PERM_READ_IMAGEVIDEO },
        { TableType::TYPE_AUDIOS, PERM_READ_AUDIO }
    };
    static map<TableType, string> writePermmisionMap = {
        { TableType::TYPE_PHOTOS, PERM_WRITE_IMAGEVIDEO },
        { TableType::TYPE_AUDIOS, PERM_WRITE_AUDIO }
    };
    bool haveReadPermission = AccessTokenKit::VerifyAccessToken(tokenId, readPermmisionMap[mediaType]) == 0;
    bool haveWritePermission = AccessTokenKit::VerifyAccessToken(tokenId, writePermmisionMap[mediaType]) == 0;
    for (auto it = checkFlags.begin(); it != checkFlags.end(); it++) {
        auto checkFlag = it->first;
        int32_t permissionFlag = -1;
        if (checkFlag == URI_PERMISSION_FLAG_READ) {
            permissionFlag = haveReadPermission ? -1 : URI_PERMISSION_FLAG_READ;
        } else if (checkFlag == URI_PERMISSION_FLAG_WRITE) {
            permissionFlag = haveWritePermission ? -1 : URI_PERMISSION_FLAG_WRITE;
        } else if (checkFlag == URI_PERMISSION_FLAG_READWRITE) {
            if (haveWritePermission) {
                permissionFlag = -1;
            } else if (haveReadPermission) {
                permissionFlag = URI_PERMISSION_FLAG_WRITE;
            } else {
                permissionFlag = URI_PERMISSION_FLAG_READWRITE;
            }
        }
        if (permissionFlag == -1) { // have permission index
            hasPermissionIndex.insert(hasPermissionIndex.end(), it->second.begin(), it->second.end());
        } else { // need check further
            auto queryIt = queryFlags.find(permissionFlag);
            if (queryIt != queryFlags.end()) {
                queryIt->second.insert(queryIt->second.end(), it->second.begin(), it->second.end());
            } else {
                queryFlags[permissionFlag] = it->second;
            }
        }
    }
}

static void MakePredicatesForCheckPhotoUriPermission(const int32_t &checkFlag, DataSharePredicates &predicates,
    uint32_t targetTokenId, TableType mediaType, vector<string> &fileIds)
{
    predicates.EqualTo(AppUriPermissionColumn::TARGET_TOKENID, (int64_t)targetTokenId);
    predicates.And()->EqualTo(AppUriPermissionColumn::URI_TYPE, to_string(static_cast<int32_t>(mediaType)));
    predicates.And()->In(AppUriPermissionColumn::FILE_ID, fileIds);
    vector<string> permissionTypes;
    switch (checkFlag) {
        case URI_PERMISSION_FLAG_READ:
            permissionTypes.insert(permissionTypes.end(), READPERMISSIONS_STR.begin(), READPERMISSIONS_STR.end());
            break;
        case URI_PERMISSION_FLAG_WRITE:
            permissionTypes.insert(permissionTypes.end(), WRITEPERMISSIONS_STR.begin(), WRITEPERMISSIONS_STR.end());
            break;
        case URI_PERMISSION_FLAG_READWRITE:
            permissionTypes.insert(permissionTypes.end(), WRITEPERMISSIONS_STR.begin(), WRITEPERMISSIONS_STR.end());
            break;
        default:
            MEDIA_ERR_LOG("error flag object: %{public}d", checkFlag);
            return;
    }
    predicates.And()->In(AppUriPermissionColumn::PERMISSION_TYPE, permissionTypes);
    predicates.OrderByDesc(AppUriPermissionColumn::PERMISSION_TYPE);
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

static vector<string> TransformIndexToId(const vector<string> &urisSource, const vector<int32_t> &indexs)
{
    vector<string> fileIds;
    for (int32_t index : indexs) {
        string uri = urisSource.at(index);
        fileIds.push_back(MediaFileUtils::GetIdFromUri(uri));
    }
    return fileIds;
}

int32_t MediaLibraryExtendManager::QueryGrantedIndex(const DataSharePredicates &predicates,
    const vector<string> &urisSource, const vector<int32_t> &indexVec, vector<int32_t> &grantedIndex)
{
    vector<string> columns = {
        AppUriPermissionColumn::FILE_ID
    };
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr, E_ERR,
        "Failed to checkPhotoUriPermission, datashareHelper is nullptr");

    Uri uri(MEDIALIBRARY_CHECK_URIPERM_URI);
    auto queryResultSet = dataShareHelper_->Query(uri, predicates, columns);
    if (queryResultSet == nullptr && ForceReconnect()) {
        MEDIA_WARN_LOG("resultset is null, reconnect and retry");
        queryResultSet = dataShareHelper_->Query(uri, predicates, columns);
    }
    CHECK_AND_RETURN_RET_LOG(queryResultSet != nullptr, E_ERR, "queryResultSet is null!");

    vector<string> fileIds;
    while (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
        string fileId = GetStringVal(AppUriPermissionColumn::FILE_ID, queryResultSet);
        fileIds.push_back(fileId);
    }

    for (size_t i = 0; i < indexVec.size(); i++) {
        int32_t indexValue = indexVec.at(i);
        string indexFileId = MediaFileUtils::GetIdFromUri(urisSource.at(indexValue));
        for (string fileId : fileIds) {
            if (indexFileId.compare(fileId) == 0) {
                grantedIndex.push_back(indexValue);
                break;
            }
        }
    }

    return E_SUCCESS;
}

int32_t MediaLibraryExtendManager::CheckPhotoUriPermission(uint32_t tokenId,
    const vector<string> &urisSource, vector<bool> &results, const vector<uint32_t> &flags)
{
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryExtendManager::CheckPhotoUriPermission");
    auto ret = CheckInputParameters(urisSource, flags);
    CHECK_AND_RETURN_RET(ret == E_SUCCESS, E_ERR);
    map<uint32_t, vector<int32_t>> photoFileIds;
    map<uint32_t, vector<int32_t>> audioFileIds;
    // group uri by flags
    ret = UrisSourceMediaTypeClassify(urisSource, flags, photoFileIds, audioFileIds);
    CHECK_AND_RETURN_RET(ret == E_SUCCESS, E_ERR);
    vector<int32_t> hasPermissionIndex;
    map<int32_t, vector<int32_t>> queryPhotoFlag;
    map<int32_t, vector<int32_t>> queryAudioFlag;
    // check system permission
    if (!photoFileIds.empty()) {
        CheckAccessTokenPermission(tokenId, photoFileIds, TableType::TYPE_PHOTOS,
            queryPhotoFlag, hasPermissionIndex);
    }
    if (!audioFileIds.empty()) {
        CheckAccessTokenPermission(tokenId, photoFileIds, TableType::TYPE_PHOTOS,
            queryPhotoFlag, hasPermissionIndex);
    }
    // check db permission
    for (auto it = queryPhotoFlag.begin(); it != queryPhotoFlag.end(); it++) {
        DataSharePredicates predicates;
        vector<string> fileIds = TransformIndexToId(urisSource, it->second);
        MakePredicatesForCheckPhotoUriPermission(it->first, predicates,
            tokenId, TableType::TYPE_PHOTOS, fileIds);
        vector<int32_t> grantedIndex;
        ret = QueryGrantedIndex(predicates, urisSource, it->second, grantedIndex);
        CHECK_AND_RETURN_RET(ret == E_SUCCESS, E_ERR);
        hasPermissionIndex.insert(hasPermissionIndex.end(), grantedIndex.begin(), grantedIndex.end());
    }
    for (auto it = queryAudioFlag.begin(); it != queryAudioFlag.end(); it++) {
        DataSharePredicates predicates;
        vector<string> fileIds = TransformIndexToId(urisSource, it->second);
        MakePredicatesForCheckPhotoUriPermission(it->first, predicates,
            tokenId, TableType::TYPE_AUDIOS, fileIds);
        vector<int32_t> grantedIndex;
        ret = QueryGrantedIndex(predicates, urisSource, it->second, grantedIndex);
        CHECK_AND_RETURN_RET(ret == E_SUCCESS, E_ERR);
        hasPermissionIndex.insert(hasPermissionIndex.end(), grantedIndex.begin(), grantedIndex.end());
    }
    for (size_t i = 0; i < urisSource.size(); i++) {
        if (std::find(hasPermissionIndex.begin(), hasPermissionIndex.end(),
            static_cast<int32_t>(i)) != hasPermissionIndex.end()) {
            results.push_back(true);
        } else {
            results.push_back(false);
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
        hideSensitiveTpye > HideSensitiveType::NO_DESENSITIZE);
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
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr, E_ERR, "dataShareHelper is nullptr");
    vector<DataShareValuesBucket> valueSet;

    for (int i = 0; i < uris.size(); i++) {
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
        
        DataShareValuesBucket valuesBucket;
        valuesBucket.Put(AppUriPermissionColumn::SOURCE_TOKENID, (int64_t)srcTokenId);
        valuesBucket.Put(AppUriPermissionColumn::TARGET_TOKENID, (int64_t)targetTokenId);
        valuesBucket.Put(AppUriPermissionColumn::FILE_ID, fileId);
        valuesBucket.Put(AppUriPermissionColumn::URI_TYPE, tableType);
        valuesBucket.Put(AppUriSensitiveColumn::HIDE_SENSITIVE_TYPE, static_cast<int32_t>(hideSensitiveTpye));
        if (photoPermissionType == PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO) {
            DataShareValuesBucket valuesBucketCopy(valuesBucket);
            valuesBucket.Put(AppUriPermissionColumn::PERMISSION_TYPE,
                static_cast<int32_t>(PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO));
            valueSet.push_back(valuesBucket);
            valuesBucketCopy.Put(AppUriPermissionColumn::PERMISSION_TYPE,
                static_cast<int32_t>(PhotoPermissionType::PERSIST_READ_IMAGEVIDEO));
            valueSet.push_back(valuesBucketCopy);
            continue;
        }
        valuesBucket.Put(AppUriPermissionColumn::PERMISSION_TYPE, static_cast<int32_t>(photoPermissionType));
        valueSet.push_back(valuesBucket);
    }
    Uri insertUri(MEDIALIBRARY_GRANT_URIPERM_URI);
    ret = dataShareHelper_->BatchInsert(insertUri, valueSet);
    if (ret == DATASHARE_ERR && ForceReconnect()) {
        MEDIA_WARN_LOG("Failed to BatchInsert and retry");
        ret = dataShareHelper_->BatchInsert(insertUri, valueSet);
    }
    return ret;
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
    vector<DataShareValuesBucket> valueSet;
    bool cond = ((uris.empty()) || (uris.size() > URI_MAX_SIZE) || (uris.size() != operationModes.size()));
    CHECK_AND_RETURN_RET_LOG(!cond, E_ERR, "Media Uri list error, please check!");
    for (auto &mode : operationModes) {
        if (mode != OperationMode::READ_MODE && mode != OperationMode::WRITE_MODE &&
                mode != OperationMode::READ_WRITE_MODE) {
            MEDIA_ERR_LOG("operation mode error, please check param!");
            return E_ERR;
        }
    }
    DataSharePredicates predicates;
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
        if (i > 0) {
            predicates.Or();
        }
        MEDIA_DEBUG_LOG("CancelPermission fileId:%{private}s, tableType:%{private}d", fileId.c_str(), tableType);
        predicates.BeginWrap();
        predicates.BeginWrap();
        predicates.EqualTo(AppUriPermissionColumn::SOURCE_TOKENID, (int64_t)srcTokenId);
        predicates.Or();
        predicates.EqualTo(AppUriPermissionColumn::TARGET_TOKENID, (int64_t)srcTokenId);
        predicates.EndWrap();
        predicates.EqualTo(AppUriPermissionColumn::FILE_ID, fileId);
        predicates.EqualTo(AppUriPermissionColumn::TARGET_TOKENID, (int64_t)targetTokenId);
        predicates.EqualTo(AppUriPermissionColumn::URI_TYPE, tableType);
        vector<string> permissionTypes = BuildPermissionType(persistFlag, operationModes[i]);
        predicates.In(AppUriPermissionColumn::PERMISSION_TYPE, permissionTypes);
        predicates.EndWrap();
    }
    Uri deleteUri(MEDIALIBRARY_GRANT_URIPERM_URI);
    return dataShareHelper_->Delete(deleteUri, predicates);
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
    Uri queryUri(PAH_QUERY_PHOTO);
    DataSharePredicates predicates;
    string fileId = MediaFileUtils::GetIdFromUri(value);
    predicates.EqualTo(MediaColumn::MEDIA_ID, fileId);
    DatashareBusinessError businessError;
    auto resultSet = dataShareHelper_->Query(queryUri, predicates, columns, &businessError);
    if (resultSet == nullptr && ForceReconnect()) {
        MEDIA_WARN_LOG("resultset is null, reconnect and retry");
        return dataShareHelper_->Query(queryUri, predicates, columns, &businessError);
    } else {
        return resultSet;
    }
}

std::shared_ptr<DataShareResultSet> MediaLibraryExtendManager::GetResultSetFromDb(string columnName,
    const string &value, vector<string> &columns)
{
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr, nullptr, "dataShareHelper is null");
    if (columnName == MEDIA_DATA_DB_URI) {
        return GetResultSetFromPhotos(value, columns);
    }
    Uri uri(MEDIALIBRARY_MEDIA_PREFIX);
    DataSharePredicates predicates;
    predicates.EqualTo(columnName, value);
    predicates.And()->EqualTo(MEDIA_DATA_DB_IS_TRASH, to_string(NOT_TRASHED));
    DatashareBusinessError businessError;
    auto resultSet = dataShareHelper_->Query(uri, predicates, columns, &businessError);
    if (resultSet == nullptr && ForceReconnect()) {
        MEDIA_WARN_LOG("resultset is null, reconnect and retry");
        return dataShareHelper_->Query(uri, predicates, columns, &businessError);
    } else {
        return resultSet;
    }
}

static bool HasPermission(int32_t permissionType, PhotoPermissionType photoPermissionType)
{
    switch (photoPermissionType) {
        case PhotoPermissionType::PERSIST_READ_IMAGEVIDEO:
            return permissionType == static_cast<int32_t>(PhotoPermissionType::PERSIST_READ_IMAGEVIDEO) ||
                   permissionType == static_cast<int32_t>(PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO);
        case PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO:
            return permissionType == static_cast<int32_t>(PhotoPermissionType::PERSIST_WRITE_IMAGEVIDEO) ||
                   permissionType == static_cast<int32_t>(PhotoPermissionType::GRANT_PERSIST_READWRITE_IMAGEVIDEO);
        case PhotoPermissionType::PERSIST_READWRITE_IMAGEVIDEO:
            return permissionType == static_cast<int32_t>(PhotoPermissionType::PERSIST_READWRITE_IMAGEVIDEO);
        default:
            return false;
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

    std::unordered_map<std::string, int32_t> permissionMap;
    while (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
        string fileId = GetStringVal(AppUriPermissionColumn::FILE_ID, queryResultSet);
        int32_t permissionType = GetInt32Val(AppUriPermissionColumn::PERMISSION_TYPE, queryResultSet);
        if (HasPermission(permissionType, photoPermissionType)) {
            permissionMap[fileId] = true;
        }
    }

    for (size_t i = 0; i < uris.size(); ++i) {
        string fileId = MediaFileUtils::GetIdFromUri(uris[i]);
        result[i] = permissionMap.find(fileId) != permissionMap.end() ? permissionMap[fileId] : false;
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

    std::vector<bool> temporaryReadResult(uris.size(), false);
    std::vector<bool> persistReadResult(uris.size(), false);
    std::vector<bool> temporaryWriteResult(uris.size(), false);
    std::vector<bool> temporaryReadWriteResult(uris.size(), false);
    std::vector<bool> persistReadWriteResult(uris.size(), false);
    std::vector<bool> persistWriteResult(uris.size(), false);
    map<PhotoPermissionType, std::vector<bool>> typeMap = {
        { PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO, temporaryReadResult },
        { PhotoPermissionType::PERSIST_READ_IMAGEVIDEO, persistReadResult },
        { PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO, temporaryWriteResult },
        { PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO, temporaryReadWriteResult },
        { PhotoPermissionType::PERSIST_READWRITE_IMAGEVIDEO, persistReadWriteResult },
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
} // namespace Media
} // namespace OHOS