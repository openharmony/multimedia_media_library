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

static int32_t UrisSourceMediaTypeClassify(const vector<string> &urisSource,
    vector<string> &photoFileIds, vector<string> &audioFileIds)
{
    for (const auto &uri : urisSource) {
        int32_t tableType = -1;
        for (const auto &iter : tableMap) {
            if (uri.find(iter.first) != string::npos) {
                tableType = static_cast<int32_t>(iter.second);
            }
        }

        CHECK_AND_RETURN_RET_LOG(tableType != -1, E_ERR, "Uri invalid error, uri:%{private}s", uri.c_str());
        string fileId = MediaFileUtils::GetIdFromUri(uri);
        if (tableType == static_cast<int32_t>(TableType::TYPE_PHOTOS)) {
            photoFileIds.emplace_back(fileId);
        } else if (tableType == static_cast<int32_t>(TableType::TYPE_AUDIOS)) {
            audioFileIds.emplace_back(fileId);
        } else {
            MEDIA_ERR_LOG("Uri invalid error, uri:%{private}s", uri.c_str());
            return E_ERR;
        }
    }
    return E_SUCCESS;
}

static void CheckAccessTokenPermissionExecute(uint32_t tokenId, uint32_t checkFlag, TableType mediaType,
    bool &isReadable, bool &isWritable)
{
    static map<TableType, string> readPermmisionMap = {
        { TableType::TYPE_PHOTOS, PERM_READ_IMAGEVIDEO },
        { TableType::TYPE_AUDIOS, PERM_READ_AUDIO }
    };
    static map<TableType, string> writePermmisionMap = {
        { TableType::TYPE_PHOTOS, PERM_WRITE_IMAGEVIDEO },
        { TableType::TYPE_AUDIOS, PERM_WRITE_AUDIO }
    };
    int checkReadResult = -1;
    int checkWriteResult = -1;
    if (checkFlag == URI_PERMISSION_FLAG_READ) {
        checkReadResult = AccessTokenKit::VerifyAccessToken(tokenId, readPermmisionMap[mediaType]);
        if (checkReadResult != PermissionState::PERMISSION_GRANTED) {
            checkReadResult = AccessTokenKit::VerifyAccessToken(tokenId, writePermmisionMap[mediaType]);
        }
    } else if (checkFlag == URI_PERMISSION_FLAG_WRITE) {
        checkWriteResult = AccessTokenKit::VerifyAccessToken(tokenId, writePermmisionMap[mediaType]);
    } else if (checkFlag == URI_PERMISSION_FLAG_READWRITE) {
        checkReadResult = AccessTokenKit::VerifyAccessToken(tokenId, readPermmisionMap[mediaType]);
        if (checkReadResult != PermissionState::PERMISSION_GRANTED) {
            checkReadResult = AccessTokenKit::VerifyAccessToken(tokenId, writePermmisionMap[mediaType]);
        }
        checkWriteResult = AccessTokenKit::VerifyAccessToken(tokenId, writePermmisionMap[mediaType]);
    }
    isReadable = checkReadResult == PermissionState::PERMISSION_GRANTED;
    isWritable = checkWriteResult == PermissionState::PERMISSION_GRANTED;
}
static void CheckAccessTokenPermission(uint32_t tokenId, uint32_t checkFlag,
    TableType mediaType, int64_t &queryFlag)
{
    bool isReadable = false;
    bool isWritable = false;
    CheckAccessTokenPermissionExecute(tokenId, checkFlag, mediaType, isReadable, isWritable);

    if (checkFlag == URI_PERMISSION_FLAG_READ) {
        queryFlag = isReadable ? -1 : URI_PERMISSION_FLAG_READ;
    } else if (checkFlag == URI_PERMISSION_FLAG_WRITE) {
        queryFlag = isWritable ? -1 : URI_PERMISSION_FLAG_WRITE;
    } else if (checkFlag == URI_PERMISSION_FLAG_READWRITE) {
        if (isReadable && isWritable) {
            queryFlag = -1;
        } else if (isReadable) {
            queryFlag = URI_PERMISSION_FLAG_WRITE;
        } else if (isWritable) {
            queryFlag = URI_PERMISSION_FLAG_READ;
        } else {
            queryFlag = URI_PERMISSION_FLAG_READWRITE;
        }
    }
}

static void MakePredicatesForCheckPhotoUriPermission(int64_t &checkFlag, DataSharePredicates &predicates,
    uint32_t targetTokenId, TableType mediaType, vector<string> &fileIds)
{
    predicates.EqualTo(AppUriPermissionColumn::TARGET_TOKENID, (int64_t)targetTokenId);
    predicates.And()->EqualTo(AppUriPermissionColumn::URI_TYPE, to_string(static_cast<int32_t>(mediaType)));
    predicates.And()->In(AppUriPermissionColumn::FILE_ID, fileIds);
    vector<string> permissionTypes;
    switch (checkFlag) {
        case URI_PERMISSION_FLAG_READ:
            permissionTypes.emplace_back(
                to_string(static_cast<int32_t>(PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO)));
            permissionTypes.emplace_back(
                to_string(static_cast<int32_t>(PhotoPermissionType::PERSIST_READ_IMAGEVIDEO)));
            permissionTypes.emplace_back(
                to_string(static_cast<int32_t>(PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO)));
            permissionTypes.emplace_back(
                to_string(static_cast<int32_t>(PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO)));
            permissionTypes.emplace_back(
                to_string(static_cast<int32_t>(AppUriPermissionColumn::PERMISSION_PERSIST_READ_WRITE)));
            break;
        case URI_PERMISSION_FLAG_WRITE:
            permissionTypes.emplace_back(
                to_string(static_cast<int32_t>(PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO)));
            permissionTypes.emplace_back(
                to_string(static_cast<int32_t>(PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO)));
            permissionTypes.emplace_back(
                to_string(static_cast<int32_t>(AppUriPermissionColumn::PERMISSION_PERSIST_READ_WRITE)));
            break;
        case URI_PERMISSION_FLAG_READWRITE:
            permissionTypes.emplace_back(
                to_string(static_cast<int32_t>(PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO)));
            permissionTypes.emplace_back(
                to_string(static_cast<int32_t>(PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO)));
            permissionTypes.emplace_back(
                to_string(static_cast<int32_t>(AppUriPermissionColumn::PERMISSION_PERSIST_READ_WRITE)));
            break;
        default:
            MEDIA_ERR_LOG("error flag object: %{public}ld", (long)checkFlag);
            return;
    }
    predicates.And()->In(AppUriPermissionColumn::PERMISSION_TYPE, permissionTypes);
    predicates.OrderByDesc(AppUriPermissionColumn::PERMISSION_TYPE);
}

int32_t MediaLibraryExtendManager::CheckPhotoUriPermissionQueryOperation(const DataSharePredicates &predicates,
    map<string, int32_t> &resultMap)
{
    vector<string> columns = {
        AppUriPermissionColumn::FILE_ID,
        AppUriPermissionColumn::PERMISSION_TYPE
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

    while (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
        string fileId = GetStringVal(AppUriPermissionColumn::FILE_ID, queryResultSet);
        int32_t permissionType = GetInt32Val(AppUriPermissionColumn::PERMISSION_TYPE, queryResultSet);
        resultMap[fileId] = permissionType;
    }
    return E_SUCCESS;
}

static vector<bool> SetCheckPhotoUriPermissionResult(const vector<string> &urisSource,
    const map<string, int32_t> &photoResultMap, const map<string, int32_t> &audioResultMap,
    int32_t queryPhotoFlag, int32_t queryAudioFlag)
{
    vector<bool> results;
    for (const auto &uri : urisSource) {
        int32_t tableType = -1;
        for (const auto &iter : tableMap) {
            if (uri.find(iter.first) != string::npos) {
                tableType = static_cast<int32_t>(iter.second);
            }
        }
        string fileId = MediaFileUtils::GetIdFromUri(uri);
        if (tableType == static_cast<int32_t>(TableType::TYPE_PHOTOS)) {
            if (queryPhotoFlag == -1 || photoResultMap.find(fileId) != photoResultMap.end()) {
                results.emplace_back(true);
            } else {
                results.emplace_back(false);
            }
        } else if (tableType == static_cast<int32_t>(TableType::TYPE_AUDIOS)) {
            if (queryAudioFlag == -1 || audioResultMap.find(fileId) != audioResultMap.end()) {
                results.emplace_back(true);
            } else {
                results.emplace_back(false);
            }
        }
    }
    return results;
}

static int32_t CheckInputParameters(const vector<string> &urisSource, uint32_t flag)
{
    CHECK_AND_RETURN_RET_LOG(!urisSource.empty(), E_ERR, "Media Uri list is empty");
    CHECK_AND_RETURN_RET_LOG(urisSource.size() <= URI_MAX_SIZE, E_ERR,
        "Uri list is exceed one Thousand, current list size: %{public}d", (int)urisSource.size());
    bool cond = (flag == 0 || flag > URI_PERMISSION_FLAG_READWRITE);
    CHECK_AND_RETURN_RET_LOG(!cond, E_ERR, "Flag is invalid, current flag is: %{public}d", flag);
    return E_SUCCESS;
}

int32_t MediaLibraryExtendManager::CheckPhotoUriPermission(uint32_t tokenId,
    const vector<string> &urisSource, vector<bool> &results, uint32_t flag)
{
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryExtendManager::CheckPhotoUriPermission");
    auto ret = CheckInputParameters(urisSource, flag);
    CHECK_AND_RETURN_RET(ret == E_SUCCESS, E_ERR);
    vector<string> photoFileIds;
    vector<string> audioFileIds;
    ret = UrisSourceMediaTypeClassify(urisSource, photoFileIds, audioFileIds);
    CHECK_AND_RETURN_RET(ret == E_SUCCESS, E_ERR);

    int64_t queryPhotoFlag = URI_PERMISSION_FLAG_READWRITE;
    int64_t queryAudioFlag = URI_PERMISSION_FLAG_READWRITE;
    if (photoFileIds.empty()) {
        queryPhotoFlag = -1;
    } else {
        CheckAccessTokenPermission(tokenId, flag, TableType::TYPE_PHOTOS, queryPhotoFlag);
    }
    if (audioFileIds.empty()) {
        queryAudioFlag = -1;
    } else {
        CheckAccessTokenPermission(tokenId, flag, TableType::TYPE_AUDIOS, queryAudioFlag);
    }
    map<string, int32_t> photoResultMap;
    map<string, int32_t> audioResultMap;
    if (queryPhotoFlag != -1) {
        DataSharePredicates predicates;
        MakePredicatesForCheckPhotoUriPermission(queryPhotoFlag, predicates,
            tokenId, TableType::TYPE_PHOTOS, photoFileIds);
        auto ret = CheckPhotoUriPermissionQueryOperation(predicates, photoResultMap);
        CHECK_AND_RETURN_RET(ret == E_SUCCESS, E_ERR);
    }
    if (queryAudioFlag != -1) {
        DataSharePredicates predicates;
        MakePredicatesForCheckPhotoUriPermission(queryAudioFlag, predicates,
            tokenId, TableType::TYPE_AUDIOS, audioFileIds);
        auto ret = CheckPhotoUriPermissionQueryOperation(predicates, audioResultMap);
        CHECK_AND_RETURN_RET(ret == E_SUCCESS, E_ERR);
    }
    results = SetCheckPhotoUriPermissionResult(urisSource, photoResultMap, audioResultMap,
        queryPhotoFlag, queryAudioFlag);
    return E_SUCCESS;
}

int32_t MediaLibraryExtendManager::GrantPhotoUriPermission(uint32_t srcTokenId, uint32_t targetTokenId,
    const std::vector<string> &uris, PhotoPermissionType photoPermissionType, HideSensitiveType hideSensitiveTpye)
{
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryExtendManager::GrantPhotoUriPermission");
    vector<DataShareValuesBucket> valueSet;
    bool cond = ((uris.empty()) || (uris.size() > URI_MAX_SIZE));
    CHECK_AND_RETURN_RET_LOG(!cond, E_ERR, "Media Uri list error, please check!");
    cond = (photoPermissionType != PhotoPermissionType::TEMPORARY_READ_IMAGEVIDEO &&
        photoPermissionType != PhotoPermissionType::TEMPORARY_WRITE_IMAGEVIDEO &&
        photoPermissionType != PhotoPermissionType::TEMPORARY_READWRITE_IMAGEVIDEO);
    CHECK_AND_RETURN_RET_LOG(!cond, E_ERR, "photoPermissionType error, please check param!");

    cond = (hideSensitiveTpye < HideSensitiveType::ALL_DESENSITIZE ||
        hideSensitiveTpye > HideSensitiveType::NO_DESENSITIZE);
    CHECK_AND_RETURN_RET_LOG(!cond, E_ERR, "HideSensitiveType error, please check param!");
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr, E_ERR, "dataShareHelper is nullptr");

    for (const auto &uri : uris) {
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
        valuesBucket.Put(AppUriPermissionColumn::PERMISSION_TYPE, static_cast<int32_t>(photoPermissionType));
        valuesBucket.Put(AppUriSensitiveColumn::HIDE_SENSITIVE_TYPE, static_cast<int32_t>(hideSensitiveTpye));
        valueSet.push_back(valuesBucket);
    }
    Uri insertUri(MEDIALIBRARY_GRANT_URIPERM_URI);
    auto ret = dataShareHelper_->BatchInsert(insertUri, valueSet);
    if (ret == DATASHARE_ERR && ForceReconnect()) {
        MEDIA_WARN_LOG("Failed to BatchInsert and retry");
        ret = dataShareHelper_->BatchInsert(insertUri, valueSet);
    }
    return ret;
}

int32_t MediaLibraryExtendManager::CancelPhotoUriPermission(uint32_t srcTokenId, uint32_t targetTokenId,
    const std::vector<string> &uris)
{
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryExtendManager::CancelPhotoUriPermission");
    MEDIA_DEBUG_LOG("CancelPermission begin, srcToken:%{private}d, targetToken:%{private}d", srcTokenId, targetTokenId);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper_ != nullptr, E_ERR, "dataShareHelper is nullptr");
    vector<DataShareValuesBucket> valueSet;
    bool cond = ((uris.empty()) || (uris.size() > URI_MAX_SIZE));
    CHECK_AND_RETURN_RET_LOG(!cond, E_ERR, "Media Uri list error, please check!");

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
        predicates.NotEqualTo(AppUriPermissionColumn::PERMISSION_TYPE,
            static_cast<int>(PhotoPermissionType::PERSIST_READ_IMAGEVIDEO));
        predicates.NotEqualTo(AppUriPermissionColumn::PERMISSION_TYPE,
            static_cast<int>(PhotoPermissionType::PERSIST_READWRITE_IMAGEVIDEO));
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
} // namespace Media
} // namespace OHOS