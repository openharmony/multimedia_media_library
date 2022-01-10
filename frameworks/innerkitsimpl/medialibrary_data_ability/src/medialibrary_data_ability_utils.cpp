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

#include "medialibrary_data_ability_utils.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN, "MediaLibraryDataAbilityUtils"};
string MediaLibraryDataAbilityUtils::GetFileName(const string &path)
{
    string name;
    size_t slashIndex = path.rfind("/");
    if (slashIndex != string::npos) {
        name = path.substr(slashIndex + 1);
    }
    return name;
}

string MediaLibraryDataAbilityUtils::GetParentPath(const string &path)
{
    string name;
    size_t slashIndex = path.rfind("/");
    if (slashIndex != string::npos) {
        name = path.substr(0, slashIndex);
    }

    return name;
}

int32_t MediaLibraryDataAbilityUtils::GetParentIdFromDb(const string &path, const shared_ptr<RdbStore> &rdbStore)
{
    int32_t parentId = 0;
    int32_t columnIndex(0);

    if (rdbStore != nullptr && !path.empty()) {
        AbsRdbPredicates absPredicates(MEDIALIBRARY_TABLE);
        absPredicates.EqualTo(MEDIA_DATA_DB_FILE_PATH, path);

        vector<string> columns;
        columns.push_back(MEDIA_DATA_DB_ID);

        unique_ptr<ResultSet> queryResultSet = rdbStore->Query(absPredicates, columns);
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

bool MediaLibraryDataAbilityUtils::IsNumber(const string &str)
{
    if (str.length() == 0) {
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
NativeAlbumAsset MediaLibraryDataAbilityUtils::CreateDirectorys(const string relativePath,
                                                                const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
                                                                vector<int32_t> &outIds)
{
    NativeAlbumAsset albumAsset;
    if (!relativePath.empty()) {
        string path = relativePath;
        vector<string> columns;
        AbsRdbPredicates absPredicates(MEDIALIBRARY_TABLE);
        absPredicates.EqualTo(MEDIA_DATA_DB_FILE_PATH, MEDIA_DATA_DB_Path + relativePath);
        unique_ptr<ResultSet> queryResultSet = rdbStore->Query(absPredicates, columns);
        OHOS::HiviewDFX::HiLog::Error(LABEL, "no");
        ValuesBucket values;
        values.PutString(MEDIA_DATA_DB_FILE_PATH, MEDIA_DATA_DB_Path + path);
        MediaLibraryAlbumOperations albumOprn;
        int32_t errorcode = albumOprn.HandleAlbumOperations(MEDIA_ALBUMOPRN_CREATEALBUM, values, rdbStore, outIds);
        albumAsset.SetAlbumId(errorcode);
        albumAsset.SetAlbumName(albumOprn.GetNativeAlbumAsset()->GetAlbumName());
    }
    return albumAsset;
}
int32_t MediaLibraryDataAbilityUtils::DeleteDirectorys(vector<int32_t> &outIds,
                                                       const std::shared_ptr<NativeRdb::RdbStore> &rdbStore)
{
    int32_t errorCode = -1;
    if (!outIds.empty()) {
        MediaLibraryAlbumOperations albumOprn;
        for (vector<int32_t>::reverse_iterator it = outIds.rbegin(); it != outIds.rend(); it++) {
            ValuesBucket values;
            int32_t id = *it;
            values.PutInt(MEDIA_DATA_DB_ID, id);
            errorCode = albumOprn.HandleAlbumOperations(MEDIA_ALBUMOPRN_DELETEALBUM, values, rdbStore, outIds);
        }
    }
    return errorCode;
}
NativeAlbumAsset MediaLibraryDataAbilityUtils::GetAlbumAsset(const std::string &id,
                                                             const std::shared_ptr<NativeRdb::RdbStore> &rdbStore)
{
    NativeAlbumAsset albumAsset;
    vector<string> columns;
    AbsRdbPredicates absPredicates(MEDIALIBRARY_TABLE);
    absPredicates.EqualTo(MEDIA_DATA_DB_ID, id);
    unique_ptr<ResultSet> queryResultSet = rdbStore->Query(absPredicates, columns);
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
    }
    return albumAsset;
}
std::string MediaLibraryDataAbilityUtils::GetFileTitle(const std::string& displayName)
{
    std::string title = "";
    if (!displayName.empty()) {
        std::string::size_type pos = displayName.find_first_of('.');
        HiviewDFX::HiLog::Debug(LABEL, "title pos = %{public}d", pos);
        if (pos == displayName.length()) {
            return displayName;
        }
        title = displayName.substr(0, pos);
        HiviewDFX::HiLog::Debug(LABEL, "title substr = %{public}s", title.c_str());
    }
    HiviewDFX::HiLog::Debug(LABEL, "title = %{public}s", title.c_str());
    return title;
}
NativeAlbumAsset MediaLibraryDataAbilityUtils::GetLastAlbumExistInDb(const std::string &relativePath,
    const std::shared_ptr<NativeRdb::RdbStore> &rdbStore)
{
    NativeAlbumAsset nativeAlbumAsset;
    int32_t idVal = 0;
    int32_t columnIndexId;
    int32_t maxColumnIndexPath;
    string maxVal = MEDIA_DATA_DB_Path;
    string::size_type max = maxVal.length();
    string maxPath = MEDIA_DATA_DB_Path;
    int32_t maxId = 0;
    string::size_type idx;
    string sql = "SELECT " + MEDIA_DATA_DB_RELATIVE_PATH + ","
    + MEDIA_DATA_DB_FILE_PATH + "," + MEDIA_DATA_DB_ID + " FROM " + MEDIALIBRARY_TABLE;
    unique_ptr<ResultSet> queryResultSet = rdbStore->QuerySql(sql);
    while (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
        queryResultSet->GetColumnIndex(MEDIA_DATA_DB_FILE_PATH, maxColumnIndexPath);
        queryResultSet->GetString(maxColumnIndexPath, maxPath);
        queryResultSet->GetColumnIndex(MEDIA_DATA_DB_ID, columnIndexId);
        queryResultSet->GetInt(columnIndexId, idVal);
        idx = relativePath.find(maxPath);
        if (idx != string::npos && max < maxPath.length()) {
            max = maxPath.length();
            maxVal = maxPath;
            maxId = idVal;
        }
    }
    nativeAlbumAsset.SetAlbumId(maxId);
    nativeAlbumAsset.SetAlbumPath(maxVal);
    return nativeAlbumAsset;
}
bool MediaLibraryDataAbilityUtils::isAlbumExistInDb(const std::string &relativePath,
    const std::shared_ptr<NativeRdb::RdbStore> &rdbStore,
    int32_t &outRow)
{
    vector<string> columns;
    AbsRdbPredicates absPredicates(MEDIALIBRARY_TABLE);
    absPredicates.EqualTo(MEDIA_DATA_DB_FILE_PATH, relativePath);
    unique_ptr<ResultSet> queryResultSet = rdbStore->Query(absPredicates, columns);
    if (queryResultSet != nullptr) {
        if (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
            int32_t columnIndexId;
            int32_t idVal;
            queryResultSet->GetColumnIndex(MEDIA_DATA_DB_ID, columnIndexId);
            queryResultSet->GetInt(columnIndexId, idVal);
            OHOS::HiviewDFX::HiLog::Error(LABEL, "id = %{public}d", idVal);
            outRow = idVal;
            return true;
        }
}
    return false;
}
int64_t MediaLibraryDataAbilityUtils::GetAlbumDateModified(const string &albumPath)
{
    struct stat statInfo {};
    if (!albumPath.empty() && stat(albumPath.c_str(), &statInfo) == 0) {
        return (statInfo.st_mtime);
    }

    return 0;
}

string MediaLibraryDataAbilityUtils::GetOperationType(const string &uri)
{
    string oprn("");
    size_t found = uri.rfind('/');
    if (found != string::npos) {
        oprn = uri.substr(found + 1);
    }

    return oprn;
}

bool MediaLibraryDataAbilityUtils::isFileExistInDb(const string &path, const shared_ptr<RdbStore> &rdbStore)
{
    int32_t count = 0;
    vector<string> selectionArgs = {};
    if ((path.empty()) || (rdbStore == nullptr)) {
        MEDIA_ERR_LOG("path is incorrect or rdbStore is null");
        return false;
    }
    string strQueryCondition = MEDIA_DATA_DB_FILE_PATH + " = '" + path + "'";
    AbsRdbPredicates absPredicates(MEDIALIBRARY_TABLE);
    absPredicates.SetWhereClause(strQueryCondition);
    absPredicates.SetWhereArgs(selectionArgs);
    vector<string> columns;
    columns.push_back(MEDIA_DATA_DB_FILE_PATH);
    unique_ptr<ResultSet> queryResultSet = rdbStore->Query(absPredicates, columns);
    if (queryResultSet != nullptr) {
        queryResultSet->GetRowCount(count);
        MEDIA_ERR_LOG("count is %{public}d", count);
        if (count > 0) {
            return true;
        }
    }

    return false;
}

string MediaLibraryDataAbilityUtils::GetPathFromDb(const string &id, const shared_ptr<RdbStore> &rdbStore)
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

    unique_ptr<ResultSet> queryResultSet = rdbStore->Query(absPredicates, columns);
    CHECK_AND_RETURN_RET_LOG(queryResultSet != nullptr, filePath, "Failed to obtain path from database");

    auto ret = queryResultSet->GoToFirstRow();
    CHECK_AND_RETURN_RET_LOG(ret == 0, filePath, "Failed to shift at first row");

    ret = queryResultSet->GetColumnIndex(MEDIA_DATA_DB_FILE_PATH, columnIndex);
    CHECK_AND_RETURN_RET_LOG(ret == 0, filePath, "Failed to obtain column index");

    ret = queryResultSet->GetString(columnIndex, filePath);
    CHECK_AND_RETURN_RET_LOG(ret == 0, filePath, "Failed to obtain file path");

    return filePath;
}

string MediaLibraryDataAbilityUtils::GetIdFromUri(const string &uri)
{
    string rowNum = "-1";

    size_t pos = uri.rfind('/');
    if (pos != std::string::npos) {
        rowNum = uri.substr(pos + 1);
    }

    return rowNum;
}

string MediaLibraryDataAbilityUtils::GetMediaTypeUri(MediaType mediaType)
{
    switch (mediaType) {
        case MEDIA_TYPE_AUDIO:
            return MEDIALIBRARY_AUDIO_URI;
            break;
        case MEDIA_TYPE_VIDEO:
            return MEDIALIBRARY_VIDEO_URI;
            break;
        case MEDIA_TYPE_IMAGE:
            return MEDIALIBRARY_IMAGE_URI;
            break;
        case MEDIA_TYPE_FILE:
        default:
            return MEDIALIBRARY_FILE_URI;
            break;
    }
}
} // namespace Media
} // namespace OHOS