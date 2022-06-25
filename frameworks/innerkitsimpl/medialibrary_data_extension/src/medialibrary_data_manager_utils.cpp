/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "medialibrary_data_manager_utils.h"

#include <regex>

#include "media_log.h"
#include "media_file_utils.h"
#include "medialibrary_common_utils.h"

using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::RdbDataShareAdapter;

namespace OHOS {
namespace Media {
string MediaLibraryDataManagerUtils::GetFileName(const string &path)
{
    string name;
    size_t slashIndex = path.rfind("/");
    if (slashIndex != string::npos) {
        name = path.substr(slashIndex + 1);
    }
    return name;
}

string MediaLibraryDataManagerUtils::GetParentPath(const string &path)
{
    string name;
    size_t slashIndex = path.rfind("/");
    if (slashIndex != string::npos) {
        name = path.substr(0, slashIndex);
    }

    return name;
}

int32_t MediaLibraryDataManagerUtils::GetParentIdFromDb(const string &path, const shared_ptr<RdbStore> &rdbStore)
{
    int32_t parentId = 0;
    int32_t columnIndex(0);

    if (rdbStore != nullptr && !path.empty()) {
        AbsRdbPredicates absPredicates(MEDIALIBRARY_TABLE);
        absPredicates.EqualTo(MEDIA_DATA_DB_FILE_PATH, path);

        vector<string> columns;
        columns.push_back(MEDIA_DATA_DB_ID);

        unique_ptr<NativeRdb::ResultSet> queryResultSet = rdbStore->Query(absPredicates, columns);
        CHECK_AND_RETURN_RET_LOG(queryResultSet != nullptr, parentId, "Failed to obtain parentId from database");

        auto ret = queryResultSet->GoToFirstRow();
        CHECK_AND_RETURN_RET_LOG(ret == 0, parentId, "Failed to shift at first row");

        ret = queryResultSet->GetColumnIndex(MEDIA_DATA_DB_ID, columnIndex);
        CHECK_AND_RETURN_RET_LOG(ret == 0, parentId, "Failed to obtain column index");

        ret = queryResultSet->GetInt(columnIndex, parentId);
        CHECK_AND_RETURN_RET_LOG(ret == 0, parentId, "Failed to obtain parent id");
    }

    return parentId;
}

string MediaLibraryDataManagerUtils::GetParentDisplayNameFromDb(const int &id, const shared_ptr<RdbStore> &rdbStore)
{
    string parentName;
    int32_t columnIndex(0);
    if (rdbStore != nullptr) {
        AbsRdbPredicates absPredicates(MEDIALIBRARY_TABLE);
        absPredicates.EqualTo(MEDIA_DATA_DB_ID, std::to_string(id));
        vector<string> columns;
        columns.push_back(MEDIA_DATA_DB_NAME);
        unique_ptr<NativeRdb::ResultSet> queryResultSet = rdbStore->Query(absPredicates, columns);
        auto ret = queryResultSet->GoToFirstRow();
        ret = queryResultSet->GetColumnIndex(MEDIA_DATA_DB_NAME, columnIndex);
        ret = queryResultSet->GetString(columnIndex, parentName);
    }
    return parentName;
}

bool MediaLibraryDataManagerUtils::IsNumber(const string &str)
{
    if (str.empty()) {
        MEDIA_ERR_LOG("IsNumber input is empty ");
        return false;
    }

    for (char const &c : str) {
        if (isdigit(c) == 0) {
            MEDIA_ERR_LOG("Index is not a number");
            return false;
        }
    }

    return true;
}

NativeAlbumAsset MediaLibraryDataManagerUtils::CreateDirectorys(const string relativePath,
                                                                const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
                                                                vector<int32_t> &outIds)
{
    NativeAlbumAsset albumAsset;
    if (!relativePath.empty()) {
        string path = relativePath;
        ValuesBucket values;
        values.PutString(MEDIA_DATA_DB_FILE_PATH, ROOT_MEDIA_DIR + path);
        MediaLibraryAlbumOperations albumOprn;
        int32_t errorcode = albumOprn.HandleAlbumOperations(MEDIA_ALBUMOPRN_CREATEALBUM, values, rdbStore, outIds);
        albumAsset.SetAlbumId(errorcode);
    }
    return albumAsset;
}

int32_t MediaLibraryDataManagerUtils::DeleteDirectorys(vector<int32_t> &outIds,
                                                       const std::shared_ptr<NativeRdb::RdbStore> &rdbStore)
{
    int32_t errorCode = -1;
    if (!outIds.empty()) {
        MediaLibraryAlbumOperations albumOprn;
        for (vector<int32_t>::reverse_iterator it = outIds.rbegin(); it != outIds.rend(); ++it) {
            ValuesBucket values;
            int32_t id = *it;
            values.PutInt(MEDIA_DATA_DB_ID, id);
            errorCode = albumOprn.HandleAlbumOperations(MEDIA_ALBUMOPRN_DELETEALBUM, values, rdbStore, outIds);
        }
    }
    return errorCode;
}

NativeAlbumAsset MediaLibraryDataManagerUtils::GetAlbumAsset(const std::string &id,
                                                             const std::shared_ptr<NativeRdb::RdbStore> &rdbStore)
{
    NativeAlbumAsset albumAsset;
    vector<string> columns;
    AbsRdbPredicates absPredicates(MEDIALIBRARY_TABLE);
    absPredicates.EqualTo(MEDIA_DATA_DB_ID, id);
    unique_ptr<NativeRdb::ResultSet> queryResultSet = rdbStore->Query(absPredicates, columns);
    if (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t columnIndexId;
        int32_t idVal;
        int32_t columnIndexName;
        string nameVal;
        queryResultSet->GetColumnIndex(MEDIA_DATA_DB_ID, columnIndexId);
        queryResultSet->GetInt(columnIndexId, idVal);
        queryResultSet->GetColumnIndex(MEDIA_DATA_DB_TITLE, columnIndexName);
        queryResultSet->GetString(columnIndexName, nameVal);
        albumAsset.SetAlbumId(idVal);
        albumAsset.SetAlbumName(nameVal);
        MEDIA_DEBUG_LOG("idVal = %{private}d", idVal);
        MEDIA_DEBUG_LOG("nameVal = %{private}s", nameVal.c_str());
    }
    return albumAsset;
}

std::string MediaLibraryDataManagerUtils::GetFileTitle(const std::string& displayName)
{
    std::string title = "";
    if (!displayName.empty()) {
        std::string::size_type pos = displayName.find_first_of('.');
        if (pos == displayName.length()) {
            return displayName;
        }
        title = displayName.substr(0, pos);
        MEDIA_DEBUG_LOG("title substr = %{private}s", title.c_str());
    }
    return title;
}

NativeAlbumAsset MediaLibraryDataManagerUtils::GetLastAlbumExistInDb(const std::string &path,
    const std::shared_ptr<NativeRdb::RdbStore> &rdbStore)
{
    NativeAlbumAsset nativeAlbumAsset;
    int32_t albumId;
    string lastPath = path;
    if (lastPath.substr(lastPath.length() - 1) == "/") {
        lastPath = lastPath.substr(0, lastPath.length() - 1);
    }
    do {
        size_t slashIndex = lastPath.rfind(SLASH_CHAR);
        if (slashIndex != string::npos && lastPath.length() > ROOT_MEDIA_DIR.length()) {
            lastPath = lastPath.substr(0, slashIndex);
            MEDIA_INFO_LOG("GetLastAlbumExistInDb lastPath = %{private}s", lastPath.c_str());
        } else {
            break;
        }
    } while (!isAlbumExistInDb(lastPath, rdbStore, albumId));
    nativeAlbumAsset.SetAlbumId(albumId);
    nativeAlbumAsset.SetAlbumPath(lastPath);
    return nativeAlbumAsset;
}

bool MediaLibraryDataManagerUtils::isAlbumExistInDb(const std::string &path,
    const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
    int32_t &outRow)
{
    vector<string> columns;
    string realPath = path;
    if (realPath.substr(realPath.length() - 1) == "/") {
        realPath = realPath.substr(0, realPath.length() - 1);
    }
    outRow = 0;
    MEDIA_INFO_LOG("isAlbumExistInDb path = %{private}s", realPath.c_str());
    AbsRdbPredicates absPredicates(MEDIALIBRARY_TABLE);
    string strQueryCondition = MEDIA_DATA_DB_FILE_PATH + " = '" + realPath + "' AND "
        + MEDIA_DATA_DB_IS_TRASH + " = 0";
    absPredicates.SetWhereClause(strQueryCondition);
    unique_ptr<NativeRdb::ResultSet> queryResultSet = rdbStore->Query(absPredicates, columns);
    if (queryResultSet != nullptr) {
        if (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
            int32_t columnIndexId;
            int32_t idVal;
            queryResultSet->GetColumnIndex(MEDIA_DATA_DB_ID, columnIndexId);
            queryResultSet->GetInt(columnIndexId, idVal);
            MEDIA_INFO_LOG("id = %{private}d", idVal);
            outRow = idVal;
            return true;
        }
}
    return false;
}

int64_t MediaLibraryDataManagerUtils::GetAlbumDateModified(const string &albumPath)
{
    struct stat statInfo {};
    if (!albumPath.empty() && stat(albumPath.c_str(), &statInfo) == 0) {
        return (statInfo.st_mtime);
    }

    return 0;
}

string MediaLibraryDataManagerUtils::GetOperationType(const string &uri)
{
    string oprn("");
    size_t found = uri.rfind('/');
    if (found != string::npos) {
        oprn = uri.substr(found + 1);
    }

    return oprn;
}

bool MediaLibraryDataManagerUtils::isFileExistInDb(const string &path, const shared_ptr<RdbStore> &rdbStore)
{
    int32_t count = 0;
    vector<string> selectionArgs = {};
    if ((path.empty()) || (rdbStore == nullptr)) {
        MEDIA_ERR_LOG("path is incorrect or rdbStore is null");
        return false;
    }
        string strQueryCondition = MEDIA_DATA_DB_FILE_PATH +
        " = '" + path + "' AND " + MEDIA_DATA_DB_IS_TRASH + " = 0";
    AbsRdbPredicates absPredicates(MEDIALIBRARY_TABLE);
    absPredicates.SetWhereClause(strQueryCondition);
    absPredicates.SetWhereArgs(selectionArgs);
    vector<string> columns;
    columns.push_back(MEDIA_DATA_DB_FILE_PATH);
    unique_ptr<NativeRdb::ResultSet> queryResultSet = rdbStore->Query(absPredicates, columns);
    if (queryResultSet != nullptr) {
        queryResultSet->GetRowCount(count);
        MEDIA_INFO_LOG("count is %{private}d", count);
        if (count > 0) {
            return true;
        }
    }

    return false;
}

string MediaLibraryDataManagerUtils::GetPathFromDb(const string &id, const shared_ptr<RdbStore> &rdbStore)
{
    string filePath("");
    vector<string> selectionArgs = {};
    int32_t columnIndex(0);

    if ((id.empty()) || (!IsNumber(id)) || (stoi(id) == -1) || (rdbStore == nullptr)) {
        MEDIA_ERR_LOG("Id for the path is incorrect or rdbStore is null");
        return filePath;
    }

    string strQueryCondition = MEDIA_DATA_DB_ID + " = " + id;

    AbsRdbPredicates absPredicates(MEDIALIBRARY_TABLE);
    absPredicates.SetWhereClause(strQueryCondition);
    absPredicates.SetWhereArgs(selectionArgs);

    vector<string> columns;
    columns.push_back(MEDIA_DATA_DB_FILE_PATH);

    unique_ptr<NativeRdb::ResultSet> queryResultSet = rdbStore->Query(absPredicates, columns);
    CHECK_AND_RETURN_RET_LOG(queryResultSet != nullptr, filePath, "Failed to obtain path from database");

    auto ret = queryResultSet->GoToFirstRow();
    CHECK_AND_RETURN_RET_LOG(ret == 0, filePath, "Failed to shift at first row");

    ret = queryResultSet->GetColumnIndex(MEDIA_DATA_DB_FILE_PATH, columnIndex);
    CHECK_AND_RETURN_RET_LOG(ret == 0, filePath, "Failed to obtain column index");

    ret = queryResultSet->GetString(columnIndex, filePath);
    CHECK_AND_RETURN_RET_LOG(ret == 0, filePath, "Failed to obtain file path");

    return filePath;
}

string MediaLibraryDataManagerUtils::GetRecyclePathFromDb(const string &id, const shared_ptr<RdbStore> &rdbStore)
{
    string filePath("");
    vector<string> selectionArgs = {};
    int32_t columnIndex(0);

    if ((id.empty()) || (!IsNumber(id)) || (stoi(id) == -1) || (rdbStore == nullptr)) {
        MEDIA_ERR_LOG("Id for the path is incorrect or rdbStore is null");
        return filePath;
    }

    AbsRdbPredicates absPredicates(MEDIALIBRARY_TABLE);
    absPredicates.EqualTo(MEDIA_DATA_DB_ID, id);

    vector<string> columns;
    columns.push_back(MEDIA_DATA_DB_RECYCLE_PATH);

    unique_ptr<NativeRdb::ResultSet> queryResultSet = rdbStore->Query(absPredicates, columns);
    CHECK_AND_RETURN_RET_LOG(queryResultSet != nullptr, filePath, "Failed to obtain path from database");

    auto ret = queryResultSet->GoToFirstRow();
    CHECK_AND_RETURN_RET_LOG(ret == 0, filePath, "Failed to shift at first row");

    ret = queryResultSet->GetColumnIndex(MEDIA_DATA_DB_RECYCLE_PATH, columnIndex);
    CHECK_AND_RETURN_RET_LOG(ret == 0, filePath, "Failed to obtain column index");

    ret = queryResultSet->GetString(columnIndex, filePath);
    CHECK_AND_RETURN_RET_LOG(ret == 0, filePath, "Failed to obtain recycle path");

    return filePath;
}

shared_ptr<FileAsset> MediaLibraryDataManagerUtils::GetFileAssetFromDb(const string &uriStr,
    const shared_ptr<RdbStore> &rdbStore)
{
    string id = MediaLibraryDataManagerUtils::GetIdFromUri(uriStr);
    string networkId = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(uriStr);
    vector<string> selectionArgs = {};

    if ((id.empty()) || (!IsNumber(id)) || (stoi(id) == -1) || (rdbStore == nullptr)) {
        MEDIA_ERR_LOG("Id for the path is incorrect or rdbStore is null");
        return nullptr;
    }

    string strQueryCondition = MEDIA_DATA_DB_ID + " = " + id;
    string tableName = MEDIALIBRARY_TABLE;
    if (!networkId.empty()) {
        tableName = rdbStore->ObtainDistributedTableName(networkId, MEDIALIBRARY_TABLE);
        MEDIA_INFO_LOG("tableName is %{private}s", tableName.c_str());
    }

    if (tableName.empty()) {
        MEDIA_ERR_LOG("Get tableName fail, networkId is %{private}s", networkId.c_str());
        return nullptr;
    }
    AbsRdbPredicates absPredicates(tableName);
    absPredicates.SetWhereClause(strQueryCondition);
    absPredicates.SetWhereArgs(selectionArgs);

    vector<string> columns;

    shared_ptr<AbsSharedResultSet> resultSet = rdbStore->Query(absPredicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, nullptr, "Failed to obtain path from database");

    shared_ptr<FetchResult> fetchFileResult = make_shared<FetchResult>();
    if (fetchFileResult == nullptr) {
        MEDIA_ERR_LOG("Failed to obtain fetch file result");
        return nullptr;
    }
    fetchFileResult->networkId_ = networkId;
    return fetchFileResult->GetObjectFromRdb(resultSet, 0);
}

bool MediaLibraryDataManagerUtils::checkFilePending(const shared_ptr<FileAsset> fileAsset)
{
    MEDIA_INFO_LOG("checkFilePending in");
    if (fileAsset->IsPending()) {
        MEDIA_INFO_LOG("checkFilePending IsPending true");
        return true;
    } else if (fileAsset->GetTimePending() > 0 &&
        (UTCTimeSeconds() - fileAsset->GetTimePending()) > TIMEPENDING_MIN) {
        return true;
    }
    MEDIA_INFO_LOG("checkFilePending IsPending false");
    return false;
}

bool MediaLibraryDataManagerUtils::checkOpenMode(const string &mode)
{
    MEDIA_INFO_LOG("checkOpenMode in mode %{private}s", mode.c_str());

    std::string lowModeStr = mode;
    std::transform(lowModeStr.begin(), lowModeStr.end(), lowModeStr.begin(), [](unsigned char c) {
        return std::tolower(c);
    });

    size_t wIndex = lowModeStr.rfind('w');
    if (wIndex != string::npos) {
        return true;
    }
    return false;
}

int32_t MediaLibraryDataManagerUtils::setFilePending(string &uriStr,
    bool isPending, const shared_ptr<RdbStore> &rdbStore)
{
    string id = MediaLibraryDataManagerUtils::GetIdFromUri(uriStr);
    string networkId = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(uriStr);
    MEDIA_INFO_LOG("setFilePending id = %{private}s, networkId = %{private}s, isPending = %{private}d",
        id.c_str(), networkId.c_str(), isPending);
    vector<string> selectionArgs = {};
    string strUpdateCondition = MEDIA_DATA_DB_ID + " = " + id;

    ValuesBucket values;
    values.PutBool(MEDIA_DATA_DB_IS_PENDING, isPending);
    int64_t timeNow = UTCTimeSeconds();
    if (isPending) {
        values.PutLong(MEDIA_DATA_DB_TIME_PENDING, timeNow);
    } else {
        values.PutLong(MEDIA_DATA_DB_TIME_PENDING, 0);
    }

    values.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, timeNow);

    int32_t changedRows = DATA_ABILITY_FAIL;
    string tableName = MEDIALIBRARY_TABLE;
    if (!networkId.empty()) {
        tableName = rdbStore->ObtainDistributedTableName(networkId, MEDIALIBRARY_TABLE);
        MEDIA_INFO_LOG("tableName is %{private}s", tableName.c_str());
    }

    if (tableName.empty()) {
        MEDIA_ERR_LOG("Get tableName fail, networkId is %{private}s", networkId.c_str());
        return DATA_ABILITY_FAIL;
    }
    (void)rdbStore->Update(changedRows, tableName, values, strUpdateCondition, selectionArgs);
    MEDIA_INFO_LOG("setFilePending out");
    return changedRows;
}

string MediaLibraryDataManagerUtils::GetIdFromUri(const string &uri)
{
    string rowNum = "-1";

    size_t pos = uri.rfind('/');
    if (pos != std::string::npos) {
        rowNum = uri.substr(pos + 1);
    }

    return rowNum;
}

string MediaLibraryDataManagerUtils::GetMediaTypeUri(MediaType mediaType)
{
    switch (mediaType) {
        case MEDIA_TYPE_AUDIO:
            return MEDIALIBRARY_AUDIO_URI;
        case MEDIA_TYPE_VIDEO:
            return MEDIALIBRARY_VIDEO_URI;
        case MEDIA_TYPE_IMAGE:
            return MEDIALIBRARY_IMAGE_URI;
        case MEDIA_TYPE_SMARTALBUM:
            return MEDIALIBRARY_SMARTALBUM_CHANGE_URI;
        case MEDIA_TYPE_DEVICE:
            return MEDIALIBRARY_DEVICE_URI;
        case MEDIA_TYPE_FILE:
        default:
            return MEDIALIBRARY_FILE_URI;
    }
}

int64_t MediaLibraryDataManagerUtils::UTCTimeSeconds()
{
    struct timespec t;
    t.tv_sec = 0;
    t.tv_nsec = 0;
    clock_gettime(CLOCK_REALTIME, &t);
    return (int64_t)(t.tv_sec);
}

bool MediaLibraryDataManagerUtils::CheckDisplayName(std::string displayName)
{
    auto size = displayName.length();
    if (size <= 0 || size > DISPLAYNAME_MAX) {
        return false;
    }
    std::regex express("[\\.\\\\/:*?\"<>|{}\\[\\]]");
    bool bValid = std::regex_search(displayName, express);
    if (bValid) {
        MEDIA_ERR_LOG("CheckDisplayName fail %{private}s", displayName.c_str());
    }
    return !bValid;
}

shared_ptr<AbsSharedResultSet> MediaLibraryDataManagerUtils::QueryFiles(const string &strQueryCondition,
    const shared_ptr<RdbStore> &rdbStore)
{
    vector<string> selectionArgs = {};

    if ((strQueryCondition.empty()) || (rdbStore == nullptr)) {
        MEDIA_ERR_LOG("QueryFiles params is incorrect or rdbStore is null");
        return nullptr;
    }

    AbsRdbPredicates absPredicates(MEDIALIBRARY_TABLE);
    absPredicates.SetWhereClause(strQueryCondition);
    absPredicates.SetWhereArgs(selectionArgs);

    vector<string> columns;

    shared_ptr<AbsSharedResultSet> resultSet = rdbStore->Query(absPredicates, columns);

    return resultSet;
}

shared_ptr<AbsSharedResultSet> MediaLibraryDataManagerUtils::QueryFavFiles(const shared_ptr<RdbStore> &rdbStore)
{
    string strQueryCondition = MEDIA_DATA_DB_IS_FAV + " = 1 AND " + MEDIA_DATA_DB_MEDIA_TYPE + " <> " +
        to_string(MEDIA_TYPE_ALBUM);
    return QueryFiles(strQueryCondition, rdbStore);
}

shared_ptr<AbsSharedResultSet> MediaLibraryDataManagerUtils::QueryTrashFiles(const shared_ptr<RdbStore> &rdbStore)
{
    string strQueryCondition = MEDIA_DATA_DB_DATE_TRASHED + " > 0 AND " + MEDIA_DATA_DB_MEDIA_TYPE + " <> " +
        to_string(MEDIA_TYPE_ALBUM);
    return QueryFiles(strQueryCondition, rdbStore);
}

string MediaLibraryDataManagerUtils::GetNetworkIdFromUri(const string &uri)
{
    string deviceId;
    if (uri.empty()) {
        return deviceId;
    }
    size_t pos = uri.find(MEDIALIBRARY_DATA_ABILITY_PREFIX);
    if (pos == string::npos) {
        return deviceId;
    }

    string tempUri = uri.substr(MEDIALIBRARY_DATA_ABILITY_PREFIX.length());
    if (tempUri.empty()) {
        return deviceId;
    }
    MEDIA_INFO_LOG("MediaLibraryDataManagerUtils::GetNetworkIdFromUri tempUri = %{private}s", tempUri.c_str());
    pos = tempUri.find_first_of('/');
    if (pos == 0 || pos == string::npos) {
        return deviceId;
    }
    deviceId = tempUri.substr(0, pos);

    return deviceId;
}
string MediaLibraryDataManagerUtils::GetDistributedAlbumSql(const string &strQueryCondition, const string &tableName)
{
    string distributedAlbumSql;
    if (!strQueryCondition.empty()) {
        distributedAlbumSql = "SELECT * FROM ( " + DISTRIBUTED_ABLUM_COLUMNS + " FROM " +
        tableName + " " + FILE_TABLE + ", " + tableName + " " + ABLUM_TABLE +
        DISTRIBUTED_ABLUM_WHERE_AND_GROUPBY + " )" +
        " WHERE " + strQueryCondition;
    } else {
        distributedAlbumSql = "SELECT * FROM ( " + DISTRIBUTED_ABLUM_COLUMNS + " FROM " +
        tableName + " " + FILE_TABLE + ", " + tableName + " " + ABLUM_TABLE +
        DISTRIBUTED_ABLUM_WHERE_AND_GROUPBY + " )";
    }
    MEDIA_INFO_LOG("GetDistributedAlbumSql distributedAlbumSql = %{private}s", distributedAlbumSql.c_str());
    return distributedAlbumSql;
}

bool MediaLibraryDataManagerUtils::IsColumnValueExist(const string &value,
    const string &column, const shared_ptr<RdbStore> &rdbStore)
{
    int32_t count = 0;
    vector<string> selectionArgs = {};
    if ((value.empty()) || (rdbStore == nullptr)) {
        MEDIA_ERR_LOG("path is incorrect or rdbStore is null");
        return false;
    }
    AbsRdbPredicates absPredicates(MEDIALIBRARY_TABLE);
    absPredicates.EqualTo(column, value);
    vector<string> columns;
    columns.push_back(column);
    unique_ptr<NativeRdb::ResultSet> queryResultSet = rdbStore->Query(absPredicates, columns);
    if (queryResultSet != nullptr) {
        queryResultSet->GetRowCount(count);
        MEDIA_DEBUG_LOG("count is %{private}d", count);
        if (count > 0) {
            return true;
        }
    }
    return false;
}

int32_t MediaLibraryDataManagerUtils::MakeRecycleDisplayName(const int32_t &assetId,
                                                             string &outRecyclePath,
                                                             const string &trashDirPath,
                                                             const shared_ptr<RdbStore> &rdbStore)
{
    string uri = MEDIALIBRARY_DATA_ABILITY_PREFIX +
        MEDIALIBRARY_DATA_URI_IDENTIFIER + MEDIALIBRARY_TYPE_FILE_URI + "/" + to_string(assetId);
    shared_ptr<FileAsset> fileAsset = GetFileAssetFromDb(uri, rdbStore);
    if (fileAsset == nullptr) {
        return -1;
    }
    string extension = "";
    string hashDisplayName = "";
    string name = to_string(fileAsset->GetId()) +
        fileAsset->GetRelativePath() + fileAsset->GetDisplayName();
    int32_t errorCode = MediaLibraryCommonUtils::GenKeySHA256(name, hashDisplayName);
    if (errorCode < 0) {
        MEDIA_ERR_LOG("Failed to make hash display name, err: %{public}d", errorCode);
        return errorCode;
    }
    MEDIA_DEBUG_LOG("hashDisplayName = %{public}s", hashDisplayName.c_str());
    outRecyclePath = trashDirPath + hashDisplayName;
    if (fileAsset->GetMediaType() != MEDIA_TYPE_ALBUM) {
        size_t displayNameIndex = fileAsset->GetDisplayName().find(".");
        if (displayNameIndex != string::npos) {
            extension = fileAsset->GetDisplayName().substr(displayNameIndex);
        }
        outRecyclePath = outRecyclePath + extension;
        MEDIA_INFO_LOG("asset outRecyclePath = %{public}s", outRecyclePath.c_str());
    }
    while (IsColumnValueExist(outRecyclePath, MEDIA_DATA_DB_RECYCLE_PATH, rdbStore)) {
        name = name + HASH_COLLISION_SUFFIX;
        MEDIA_INFO_LOG("name = %{public}s", name.c_str());
        errorCode = MediaLibraryCommonUtils::GenKeySHA256(name, hashDisplayName);
        if (errorCode < 0) {
            MEDIA_ERR_LOG("Failed to make hash display name, err: %{public}d", errorCode);
            return false;
        }
        if (!extension.empty()) {
            outRecyclePath = trashDirPath + hashDisplayName + extension;
        }
        outRecyclePath =  trashDirPath + hashDisplayName;
        MEDIA_INFO_LOG("outRecyclePath = %{public}s", outRecyclePath.c_str());
    }
    return errorCode;
}

int32_t MediaLibraryDataManagerUtils::GetAssetRecycle(const int32_t &assetId,
                                                      string &outOldPath,
                                                      string &outTrashDirPath,
                                                      const shared_ptr<RdbStore> &rdbStore,
                                                      const unordered_map<string, DirAsset> &dirQuerySetMap)
{
    string path = GetPathFromDb(to_string(assetId), rdbStore);
    outOldPath = path;
    int32_t errorCode = DATA_ABILITY_FAIL;
    string rootPath;
    for (pair<string, DirAsset> dirPair : dirQuerySetMap) {
        DirAsset dirAsset = dirPair.second;
        rootPath = ROOT_MEDIA_DIR + dirAsset.GetDirectory();
        MEDIA_INFO_LOG("GetAssetRecycle = %{public}s", rootPath.c_str());
        if (path.find(rootPath) != string::npos) {
            errorCode = DATA_ABILITY_SUCCESS;
            break;
        }
    }
    outTrashDirPath = rootPath + RECYCLE_DIR;
    return errorCode;
}

bool MediaLibraryDataManagerUtils::isRecycleAssetExist(const int32_t &assetId,
    string &outRecyclePath,
    const shared_ptr<RdbStore> &rdbStore)
{
    string uri = MEDIALIBRARY_DATA_ABILITY_PREFIX +
        MEDIALIBRARY_DATA_URI_IDENTIFIER + MEDIALIBRARY_TYPE_FILE_URI + "/" + to_string(assetId);
    shared_ptr<FileAsset> fileAsset = GetFileAssetFromDb(uri, rdbStore);
    outRecyclePath = fileAsset->GetPath();
    if (fileAsset->GetMediaType() == MEDIA_TYPE_ALBUM) {
        MEDIA_INFO_LOG("assetRescyclePath = %{public}s", outRecyclePath.c_str());
        return MediaFileUtils::IsDirectory(outRecyclePath);
    } else {
        MEDIA_INFO_LOG("assetRescyclePath = %{public}s", outRecyclePath.c_str());
        return MediaFileUtils::IsFileExists(outRecyclePath);
    }
}

shared_ptr<AbsSharedResultSet> MediaLibraryDataManagerUtils::QueryAgeingTrashFiles(
    const shared_ptr<RdbStore> &rdbStore)
{
    vector<string> selectionArgs = {SMARTALBUM_DB_EXPIRED_TIME};
    string strQueryCondition = SMARTALBUM_DB_ID + " = " + to_string(TRASH_ALBUM_ID_VALUES);
    AbsRdbPredicates absPredicates(SMARTALBUM_TABLE);
    absPredicates.SetWhereClause(strQueryCondition);
    absPredicates.SetWhereArgs(selectionArgs);
    vector<string> columns;
    int32_t columnIndex, recycleDays = 30;
    shared_ptr<AbsSharedResultSet> resultSet = rdbStore->Query(absPredicates, columns);
    if (resultSet->GoToFirstRow() == NativeRdb::E_OK) {
        resultSet->GetColumnIndex(SMARTALBUM_DB_EXPIRED_TIME, columnIndex);
        resultSet->GetInt(columnIndex, recycleDays);
    }
    int64_t dateAgeing = MediaFileUtils::UTCTimeSeconds();
    string strAgeingQueryCondition = to_string(dateAgeing) + " - " +
        MEDIA_DATA_DB_DATE_TRASHED + " > " + to_string(recycleDays * ONEDAY_TO_MS);

    return QueryFiles(strAgeingQueryCondition, rdbStore);
}

string MediaLibraryDataManagerUtils::GetDisPlayNameFromPath(std::string &path)
{
    string displayName;
    size_t lastSlashPosition = path.rfind("/");
    if (lastSlashPosition != string::npos) {
        displayName = path.substr(lastSlashPosition + 1);
    }
    return displayName;
}

bool MediaLibraryDataManagerUtils::IsAssetExistInDb(const int &id,
    const shared_ptr<NativeRdb::RdbStore> &rdbStore)
{
    vector<string> columns;
    AbsRdbPredicates absPredicates(MEDIALIBRARY_TABLE);
    absPredicates.EqualTo(MEDIA_DATA_DB_ID, std::to_string(id));
    unique_ptr<NativeRdb::ResultSet> queryResultSet = rdbStore->Query(absPredicates, columns);
    if (queryResultSet != nullptr) {
        if (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
            return true;
        }
    }
    return false;
}
} // namespace Media
} // namespace OHOS
