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
#define MLOG_TAG "AlbumOperation"

#include "medialibrary_album_operations.h"

#include "directory_ex.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_asset_operations.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_notify.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_rdb_transaction.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_tracer.h"
#include "medialibrary_unistore_manager.h"
#include "photo_album_column.h"
#include "photo_map_column.h"

#include "result_set_utils.h"
#include "values_bucket.h"

using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;
using namespace OHOS::RdbDataShareAdapter;

namespace OHOS::Media {
using ChangeType = AAFwk::ChangeInfo::ChangeType;
constexpr int32_t AFTER_AGR_SIZE = 2;
constexpr int32_t THAN_AGR_SIZE = 1;
constexpr int32_t MERGE_ALBUM_COUNT = 2;
constexpr int32_t E_INDEX = -1;
constexpr int32_t PORTRAIT_FIRST_PAGE_MIN_COUNT = 50;
constexpr int32_t PORTRAIT_FIRST_PAGE_MIN_COUNT_RELATED_ME = 20;
constexpr int32_t PORTRAIT_SECOND_PAGE_MIN_PICTURES_COUNT = 10;
constexpr int32_t SUPPORT_QUERY_ISME_MIN_COUNT = 80;
constexpr int32_t PERCENTAGE_FOR_SUPPORT_QUERY_ISME = 100;

int32_t MediaLibraryAlbumOperations::CreateAlbumOperation(MediaLibraryCommand &cmd)
{
    int64_t outRow = -1;
    int32_t errCode = MediaLibraryObjectUtils::CreateDirObj(cmd, outRow);
    if (errCode == E_SUCCESS) {
        return outRow;
    }
    return errCode;
}

// only support modify in the same parent folder, like: a/b/c --> a/b/d
int32_t MediaLibraryAlbumOperations::ModifyAlbumOperation(MediaLibraryCommand &cmd)
{
    string strId = cmd.GetOprnFileId();
    string srcDirPath = MediaLibraryObjectUtils::GetPathByIdFromDb(strId);
    if (srcDirPath.empty()) {
        MEDIA_ERR_LOG("Get path of id %{private}s from database file!", strId.c_str());
        return E_INVALID_PATH;
    }

    auto values = cmd.GetValueBucket();
    string dstDirName;
    ValueObject valueObject;
    if (values.GetObject(MEDIA_DATA_DB_NAME, valueObject)) {
        valueObject.GetString(dstDirName);
    }
    int ret;
    if (dstDirName.empty() && !values.IsEmpty()) {
        ret = MediaLibraryObjectUtils::ModifyInfoByIdInDb(cmd);
    } else {
        string dstDirPath = MediaFileUtils::GetParentPath(srcDirPath) + "/" + dstDirName;
        ret = MediaLibraryObjectUtils::RenameDirObj(cmd, srcDirPath, dstDirPath);
    }
    return ret;
}

string MediaLibraryAlbumOperations::GetDistributedAlbumSql(const string &strQueryCondition, const string &tableName)
{
    string distributedAlbumSql = "SELECT * FROM ( " + DISTRIBUTED_ALBUM_COLUMNS + " FROM " + tableName + " " +
        FILE_TABLE + ", " + tableName + " " + ALBUM_TABLE +
        DISTRIBUTED_ALBUM_WHERE_AND_GROUPBY + " )";
    if (!strQueryCondition.empty()) {
        distributedAlbumSql += " WHERE " + strQueryCondition;
    }
    MEDIA_DEBUG_LOG("GetDistributedAlbumSql distributedAlbumSql = %{private}s", distributedAlbumSql.c_str());
    return distributedAlbumSql;
}

#ifdef MEDIALIBRARY_COMPATIBILITY
static void ReplaceRelativePath(string &selection, vector<string> &selectionArgs)
{
    for (size_t pos = 0; pos != string::npos;) {
        pos = selection.find(MEDIA_DATA_DB_RELATIVE_PATH, pos);
        if (pos == string::npos) {
            break;
        }
        size_t argPos = selection.find('?', pos);
        if (argPos == string::npos) {
            break;
        }
        size_t argIndex = 0;
        for (size_t i = 0; i < argPos; i++) {
            if (selection[i] == '?') {
                argIndex++;
            }
        }
        if (argIndex > selectionArgs.size() - 1) {
            MEDIA_WARN_LOG("SelectionArgs size is not valid, selection format maybe incorrect: %{private}s",
                selection.c_str());
            break;
        }
        const string &arg = selectionArgs[argIndex];
        if (!arg.empty()) {
            MEDIA_WARN_LOG("No empty args in ReplaceRelativePath");
            return;
        }
        selection.replace(argPos, 1, "? OR 1=1)");
        selection.replace(pos, MEDIA_DATA_DB_RELATIVE_PATH.length(), "(" + PhotoAlbumColumns::ALBUM_ID);

        selectionArgs[argIndex] = "1";
        pos = argPos + 1;
    }
}

static void ReplaceMediaType(string &selection, vector<string> &selectionArgs)
{
    for (size_t pos = 0; pos != string::npos;) {
        pos = selection.find(MEDIA_DATA_DB_MEDIA_TYPE, pos);
        if (pos == string::npos) {
            break;
        }
        size_t argPos = selection.find('?', pos);
        if (argPos == string::npos) {
            break;
        }
        size_t argIndex = 0;
        for (size_t i = 0; i < argPos; i++) {
            if (selection[i] == '?') {
                argIndex++;
            }
        }
        if (argIndex > selectionArgs.size() - 1) {
            MEDIA_WARN_LOG("SelectionArgs size is not valid, selection format maybe incorrect: %{private}s",
                selection.c_str());
            break;
        }
        selection.replace(argPos, 1, "? OR 1=1)");
        selection.replace(pos, MEDIA_DATA_DB_MEDIA_TYPE.length(), "(" + PhotoAlbumColumns::ALBUM_ID);

        selectionArgs[argIndex] = "1";
        pos = argPos + 1;
    }
}

static void GetSqlArgs(MediaLibraryCommand &cmd, string &sql, vector<string> &selectionArgs,
    const vector<string> &columns)
{
    string clause = cmd.GetAbsRdbPredicates()->GetWhereClause();
    selectionArgs = cmd.GetAbsRdbPredicates()->GetWhereArgs();
    sql = "SELECT ";
    for (size_t i = 0; i < columns.size(); i++) {
        if (i != columns.size() - 1) {
            sql += columns[i] + ",";
        } else {
            sql += columns[i];
        }
    }
    sql += " FROM " + cmd.GetAbsRdbPredicates()->GetTableName();
    sql += " WHERE ";
    ReplaceRelativePath(clause, selectionArgs);
    ReplaceMediaType(clause, selectionArgs);
    sql += clause;
}

static void QueryAlbumDebug(MediaLibraryCommand &cmd, const vector<string> &columns,
    const shared_ptr<MediaLibraryUnistore> &store)
{
    MEDIA_DEBUG_LOG("Querying album, table: %{private}s selections: %{private}s",
        cmd.GetAbsRdbPredicates()->GetTableName().c_str(), cmd.GetAbsRdbPredicates()->GetWhereClause().c_str());
    for (const auto &arg : cmd.GetAbsRdbPredicates()->GetWhereArgs()) {
        MEDIA_DEBUG_LOG("Querying album, arg: %{private}s", arg.c_str());
    }
    for (const auto &col : columns) {
        MEDIA_DEBUG_LOG("Querying album, col: %{private}s", col.c_str());
    }

    auto resultSet = store->Query(cmd, columns);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Failed to query file!");
        return;
    }
    int32_t count = -1;
    int32_t err = resultSet->GetRowCount(count);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to get count, err: %{public}d", err);
        return;
    }
    MEDIA_DEBUG_LOG("Querying album, count: %{public}d", count);
}

static void QuerySqlDebug(const string &sql, const vector<string> &selectionArgs, const vector<string> &columns,
    const shared_ptr<MediaLibraryUnistore> &store)
{
    constexpr int32_t printMax = 512;
    for (size_t pos = 0; pos < sql.size(); pos += printMax) {
        MEDIA_DEBUG_LOG("Quering album sql: %{private}s", sql.substr(pos, printMax).c_str());
    }
    for (const auto &arg : selectionArgs) {
        MEDIA_DEBUG_LOG("Quering album, arg: %{private}s", arg.c_str());
    }
    for (const auto &col : columns) {
        MEDIA_DEBUG_LOG("Quering album, col: %{private}s", col.c_str());
    }
    auto resultSet = store->QuerySql(sql, selectionArgs);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Failed to query album!");
        return;
    }
    int32_t count = -1;
    int32_t err = resultSet->GetRowCount(count);
    if (err != E_OK) {
        MEDIA_ERR_LOG("Failed to get count, err: %{public}d", err);
        return;
    }
    MEDIA_DEBUG_LOG("Quering album, count: %{public}d", count);
}
#endif

shared_ptr<ResultSet> MediaLibraryAlbumOperations::QueryAlbumOperation(
    MediaLibraryCommand &cmd, const vector<string> &columns)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr!");
        return nullptr;
    }

    if (cmd.GetOprnObject() == OperationObject::MEDIA_VOLUME) {
        MEDIA_DEBUG_LOG("QUERY_MEDIA_VOLUME = %{private}s", QUERY_MEDIA_VOLUME.c_str());
        return uniStore->QuerySql(QUERY_MEDIA_VOLUME + " UNION " + PhotoColumn::QUERY_MEDIA_VOLUME + " UNION " +
            AudioColumn::QUERY_MEDIA_VOLUME);
    }

#ifdef MEDIALIBRARY_COMPATIBILITY
    string whereClause = cmd.GetAbsRdbPredicates()->GetWhereClause();
    if (whereClause.find(MEDIA_DATA_DB_RELATIVE_PATH) != string::npos ||
        whereClause.find(MEDIA_DATA_DB_MEDIA_TYPE) != string::npos) {
        string sql;
        vector<string> selectionArgs;
        GetSqlArgs(cmd, sql, selectionArgs, columns);
        QuerySqlDebug(sql, selectionArgs, columns, uniStore);
        return uniStore->QuerySql(sql, selectionArgs);
    }

    QueryAlbumDebug(cmd, columns, uniStore);
    return uniStore->Query(cmd, columns);
#else
    string strQueryCondition = cmd.GetAbsRdbPredicates()->GetWhereClause();
    strQueryCondition += " GROUP BY " + MEDIA_DATA_DB_BUCKET_ID;
    cmd.GetAbsRdbPredicates()->SetWhereClause(strQueryCondition);
    string networkId = cmd.GetOprnDevice();
    if (!networkId.empty()) {
        string tableName = cmd.GetTableName();
        MEDIA_INFO_LOG("tableName is %{private}s", tableName.c_str());
        if (!strQueryCondition.empty()) {
            strQueryCondition = MediaLibraryDataManagerUtils::ObtionCondition(strQueryCondition,
                cmd.GetAbsRdbPredicates()->GetWhereArgs());
        }
        string distributedAlbumSql = GetDistributedAlbumSql(strQueryCondition, tableName);
        return uniStore->QuerySql(distributedAlbumSql);
    }

    if (!strQueryCondition.empty()) {
        return uniStore->Query(cmd, columns);
    }
    string querySql = "SELECT * FROM " + cmd.GetTableName();
    return uniStore->QuerySql(querySql);
#endif
}

inline int32_t GetStringObject(const ValuesBucket &values, const string &key, string &value)
{
    value = "";
    ValueObject valueObject;
    if (values.GetObject(key, valueObject)) {
        valueObject.GetString(value);
    } else {
        return -EINVAL;
    }
    return E_OK;
}

inline int32_t GetIntVal(const ValuesBucket &values, const string &key, int32_t &value)
{
    value = 0;
    ValueObject valueObject;
    if (values.GetObject(key, valueObject)) {
        valueObject.GetInt(value);
    } else {
        return -EINVAL;
    }
    return E_OK;
}

static int32_t ObtainMaxAlbumOrder(int32_t &maxAlbumOrder)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr! failed query album order");
        return -E_HAS_DB_ERROR;
    }
    std::string queryMaxOrderSql = "SELECT Max(album_order) FROM " + PhotoAlbumColumns::TABLE;
    auto resultSet = uniStore->QuerySql(queryMaxOrderSql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Failed to query album!");
        return -E_HAS_DB_ERROR;
    }
    return resultSet->GetInt(0, maxAlbumOrder);
}

static void PrepareUserAlbum(const string &albumName, const string &relativePath, ValuesBucket &values)
{
    values.PutString(PhotoAlbumColumns::ALBUM_NAME, albumName);
    values.PutInt(PhotoAlbumColumns::ALBUM_TYPE, PhotoAlbumType::USER);
    values.PutInt(PhotoAlbumColumns::ALBUM_SUBTYPE, PhotoAlbumSubType::USER_GENERIC);
    values.PutLong(PhotoAlbumColumns::ALBUM_DATE_MODIFIED, MediaFileUtils::UTCTimeSeconds());

    if (!relativePath.empty()) {
        values.PutString(PhotoAlbumColumns::ALBUM_RELATIVE_PATH, relativePath);
    }
}

inline void PrepareWhere(const string &albumName, const string &relativePath, RdbPredicates &predicates)
{
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_NAME, albumName);
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_TYPE, to_string(PhotoAlbumType::USER));
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_SUBTYPE, to_string(PhotoAlbumSubType::USER_GENERIC));
    if (relativePath.empty()) {
        predicates.IsNull(PhotoAlbumColumns::ALBUM_RELATIVE_PATH);
    } else {
        predicates.EqualTo(PhotoAlbumColumns::ALBUM_RELATIVE_PATH, relativePath);
    }
}

// Caller is responsible for checking @albumName AND @relativePath
int DoCreatePhotoAlbum(const string &albumName, const string &relativePath)
{
    // Build insert sql
    string sql;
    vector<ValueObject> bindArgs;
    sql.append("INSERT").append(" OR ROLLBACK").append(" INTO ").append(PhotoAlbumColumns::TABLE).append(" ");

    ValuesBucket albumValues;
    PrepareUserAlbum(albumName, relativePath, albumValues);
    MediaLibraryRdbStore::BuildValuesSql(albumValues, bindArgs, sql);

    RdbPredicates wherePredicates(PhotoAlbumColumns::TABLE);
    PrepareWhere(albumName, relativePath, wherePredicates);
    sql.append(" WHERE NOT EXISTS (");
    MediaLibraryRdbStore::BuildQuerySql(wherePredicates, { PhotoAlbumColumns::ALBUM_ID }, bindArgs, sql);
    sql.append(");");
    MEDIA_DEBUG_LOG("DoCreatePhotoAlbum InsertSql: %{private}s", sql.c_str());

    return MediaLibraryRdbStore::ExecuteForLastInsertedRowId(sql, bindArgs);
}

inline int CreatePhotoAlbum(const string &albumName)
{
    int32_t err = MediaFileUtils::CheckAlbumName(albumName);
    if (err < 0) {
        return err;
    }

    return DoCreatePhotoAlbum(albumName, "");
}

int CreatePhotoAlbum(MediaLibraryCommand &cmd)
{
    string albumName;
    string subtype;
    int err = GetStringObject(cmd.GetValueBucket(), PhotoAlbumColumns::ALBUM_NAME, albumName);
    GetStringObject(cmd.GetValueBucket(), PhotoAlbumColumns::ALBUM_SUBTYPE, subtype);
    if (err < 0 && subtype != to_string(PORTRAIT)) {
        return err;
    }
    int rowId;
    if (OperationObject::ANALYSIS_PHOTO_ALBUM == cmd.GetOprnObject()) {
        auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
        if (rdbStore == nullptr) {
            return E_HAS_DB_ERROR;
        }
        int64_t outRowId;
        rdbStore->Insert(cmd, outRowId);
        rowId = outRowId;
    } else {
        rowId = CreatePhotoAlbum(albumName);
    }
    auto watch = MediaLibraryNotify::GetInstance();
    if (rowId > 0) {
        watch->Notify(MediaFileUtils::GetUriByExtrConditions(PhotoAlbumColumns::ALBUM_URI_PREFIX, to_string(rowId)),
            NotifyType::NOTIFY_ADD);
    }
    return rowId;
}

int32_t MediaLibraryAlbumOperations::DeletePhotoAlbum(RdbPredicates &predicates)
{
    // Only user generic albums can be deleted
    predicates.And()->BeginWrap()->EqualTo(PhotoAlbumColumns::ALBUM_TYPE, to_string(PhotoAlbumType::USER));
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_SUBTYPE, to_string(PhotoAlbumSubType::USER_GENERIC));
    predicates.EndWrap();

    int deleteRow = MediaLibraryRdbStore::Delete(predicates);
    auto watch = MediaLibraryNotify::GetInstance();
    for (size_t i = 0; i < predicates.GetWhereArgs().size() - AFTER_AGR_SIZE; i++) {
        if (deleteRow > 0) {
            watch->Notify(MediaFileUtils::GetUriByExtrConditions(PhotoAlbumColumns::ALBUM_URI_PREFIX,
                predicates.GetWhereArgs()[i]), NotifyType::NOTIFY_REMOVE);
        }
    }
    return deleteRow;
}

static void NotifyPortraitAlbum(const vector<int32_t> &changedAlbumIds)
{
    if (changedAlbumIds.size() <= 0) {
        return;
    }
    auto watch = MediaLibraryNotify::GetInstance();
    for (int32_t albumId : changedAlbumIds) {
        watch->Notify(MediaFileUtils::GetUriByExtrConditions(
            PhotoAlbumColumns::ANALYSIS_ALBUM_URI_PREFIX, to_string(albumId)), NotifyType::NOTIFY_UPDATE);
    }
}

int32_t GetIntValueFromResultSet(shared_ptr<ResultSet> resultSet, const string &column, int &value)
{
    int index = E_INDEX;
    resultSet->GetColumnIndex(column, index);
    if (index == E_INDEX) {
        return E_HAS_DB_ERROR;
    }
    if (resultSet->GetInt(index, value) != NativeRdb::E_OK) {
        return E_HAS_DB_ERROR;
    }
    return E_OK;
}

int32_t GetStringValueFromResultSet(shared_ptr<ResultSet> resultSet, const string &column, string &value)
{
    if (resultSet == nullptr) {
        return E_HAS_DB_ERROR;
    }
    int index = E_INDEX;
    resultSet->GetColumnIndex(column, index);
    if (index == E_INDEX) {
        return E_HAS_DB_ERROR;
    }
    if (resultSet->GetString(index, value) != NativeRdb::E_OK) {
        return E_HAS_DB_ERROR;
    }
    return E_OK;
}

void GetDisplayLevelAlbumPredicates(const int32_t value, DataShare::DataSharePredicates &predicates)
{
    string whereClause;
    if (value == FIRST_PAGE) {
        string whereClauseRelatedMe = ALBUM_ID + " IN (SELECT " + MAP_ALBUM + " FROM " + ANALYSIS_PHOTO_MAP_TABLE +
            " WHERE " + MAP_ASSET + " IN (SELECT " + MAP_ASSET + " FROM " + ANALYSIS_PHOTO_MAP_TABLE + " WHERE " +
            MAP_ASSET + " IN (SELECT " + MAP_ASSET + " FROM " + ANALYSIS_PHOTO_MAP_TABLE + " WHERE " + MAP_ALBUM +
            " IN(SELECT " + ALBUM_ID + " FROM " + ANALYSIS_ALBUM_TABLE + " WHERE " + IS_ME + " = 1))" + " GROUP BY " +
            MAP_ASSET + " HAVING count(" + MAP_ASSET + ") > 1)" + " AND " + MAP_ALBUM + " NOT IN (SELECT " + ALBUM_ID +
            " FROM " + ANALYSIS_ALBUM_TABLE + " WHERE " + IS_ME + " = 1)" + " GROUP BY " + MAP_ALBUM +
            " HAVING count(" + MAP_ALBUM + ") > " + to_string(PORTRAIT_FIRST_PAGE_MIN_COUNT_RELATED_ME) + ")";
        string whereClauseDisplay = USER_DISPLAY_LEVEL + " = 1";
        string whereClauseSatifyCount = COUNT + " > " + to_string(PORTRAIT_FIRST_PAGE_MIN_COUNT) + " AND (" +
        USER_DISPLAY_LEVEL + " != 2 OR " + USER_DISPLAY_LEVEL + " IS NULL)";
        whereClause = ALBUM_SUBTYPE + " = " + to_string(PORTRAIT) + " AND ((" + USER_DISPLAY_LEVEL + " != 3 OR " +
            USER_DISPLAY_LEVEL + " IS NULL) AND (" + whereClauseDisplay + " OR " + whereClauseRelatedMe + " OR " +
            whereClauseSatifyCount + ")) GROUP BY " + GROUP_TAG + " ORDER BY CASE WHEN " + ALBUM_NAME +
            " IS NOT NULL THEN 0 ELSE 1 END, " + COUNT + " DESC";
    } else if (value == SECOND_PAGE) {
        whereClause = ALBUM_SUBTYPE + " = " + to_string(PORTRAIT) + " AND (" + USER_DISPLAY_LEVEL + " = 2 OR (" +
            COUNT + " < " + to_string(PORTRAIT_FIRST_PAGE_MIN_COUNT) + " AND " + COUNT + " > " +
            to_string(PORTRAIT_SECOND_PAGE_MIN_PICTURES_COUNT) + " AND (" + USER_DISPLAY_LEVEL + " != 1 OR " +
            USER_DISPLAY_LEVEL + " IS NULL) AND (" + USER_DISPLAY_LEVEL + " != 3 OR " + USER_DISPLAY_LEVEL +
            " IS NULL))) GROUP BY " + GROUP_TAG + " ORDER BY CASE WHEN " + ALBUM_NAME +
            " IS NOT NULL THEN 0 ELSE 1 END, " + COUNT + " DESC";
    } else if (value == FAVORITE_PAGE) {
        whereClause = ALBUM_SUBTYPE + " = " + to_string(PORTRAIT) + " AND (" + USER_DISPLAY_LEVEL + " = 3 )GROUP BY " +
            GROUP_TAG + " ORDER BY " + RANK;
    } else {
        MEDIA_ERR_LOG("The display level is invalid");
        whereClause = "";
    }
    predicates.SetWhereClause(whereClause);
}

int32_t GetPortraitSubtype(const string &subtypeName, const string &whereClause, const vector<string> &whereArgs)
{
    size_t pos = whereClause.find(subtypeName);
    if (pos == string::npos) {
        MEDIA_ERR_LOG("whereClause is invalid");
        return E_INDEX;
    }
    size_t argsIndex = 0;
    for (size_t i = 0; i < pos; i++) {
        if (whereClause[i] == '?') {
            argsIndex++;
        }
    }
    if (argsIndex > whereArgs.size() - 1) {
        MEDIA_ERR_LOG("whereArgs is invalid");
        return E_INDEX;
    }
    return atoi(whereArgs[argsIndex].c_str());
}

bool IsSupportQueryIsMe()
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr! failed query album order");
        return false;
    }
    const std::string queryAnalyzedPic = "SELECT " + MEDIA_COLUMN_COUNT_1 + " FROM " + VISION_TOTAL_TABLE + " WHERE " +
        STATUS + " = 1";
    auto resultSetAnalyzed = uniStore->QuerySql(queryAnalyzedPic);
    if (resultSetAnalyzed == nullptr || resultSetAnalyzed->GoToFirstRow() != NativeRdb::E_OK) {
        return false;
    }
    int analyzedCount;
    if (GetIntValueFromResultSet(resultSetAnalyzed, MEDIA_COLUMN_COUNT_1, analyzedCount) != NativeRdb::E_OK) {
        return false;
    }
    if (analyzedCount <= 0) {
        return false;
    }

    const std::string queryAllPic = "SELECT " + MEDIA_COLUMN_COUNT_1 + " FROM " + VISION_TOTAL_TABLE;
    auto resultSetTotal = uniStore->QuerySql(queryAnalyzedPic);
    if (resultSetTotal == nullptr || resultSetTotal->GoToFirstRow() != NativeRdb::E_OK) {
        return false;
    }
    int totleCount;
    if (GetIntValueFromResultSet(resultSetTotal, MEDIA_COLUMN_COUNT_1, totleCount) != NativeRdb::E_OK) {
        return false;
    }
    if (totleCount == 0 ||
        (analyzedCount * PERCENTAGE_FOR_SUPPORT_QUERY_ISME / totleCount <= SUPPORT_QUERY_ISME_MIN_COUNT)) {
        MEDIA_INFO_LOG("Analyzed proportion less than 80");
        return false;
    }
    return true;
}

void GetIsMeAlbumPredicates(DataShare::DataSharePredicates &predicates)
{
    if (!IsSupportQueryIsMe()) {
        MEDIA_ERR_LOG("Not support to query isMe");
        return;
    }

    string onClause = ANALYSIS_ALBUM_TABLE + "." + ALBUM_ID + " = " + ANALYSIS_PHOTO_MAP_TABLE + "." + MAP_ALBUM;
    predicates.InnerJoin(ANALYSIS_PHOTO_MAP_TABLE)->On({ onClause });
    string selection = "WHERE " + ALBUM_SUBTYPE + " = " + to_string(PORTRAIT) + "AND EXISTS (SELECT 1 FROM " +
        PhotoColumn::PHOTOS_TABLE + " WHERE " + PhotoColumn::PHOTOS_TABLE + "." + FILE_ID + " = " +
        ANALYSIS_PHOTO_MAP_TABLE + "." + MAP_ASSET + " AND " + PhotoColumn::PHOTOS_TABLE + "." +
        PhotoColumn::PHOTO_SHOOTING_MODE + " = 0) GROUP BY " + ANALYSIS_ALBUM_TABLE + "." + GROUP_TAG +
        " ORDER BY COUNT(*) DESC";
    predicates.SetWhereClause(selection);
}

std::shared_ptr<NativeRdb::ResultSet> MediaLibraryAlbumOperations::QueryPortraitAlbum(MediaLibraryCommand &cmd,
    const std::vector<std::string> &columns)
{
    auto predicates = cmd.GetAbsRdbPredicates();
    auto whereClause = predicates->GetWhereClause();
    auto whereArgs = predicates->GetWhereArgs();
    DataShare::DataSharePredicates predicatesPortrait;
    if (whereClause.find(USER_DISPLAY_LEVEL) != string::npos) {
        int32_t value = GetPortraitSubtype(USER_DISPLAY_LEVEL, whereClause, whereArgs);
        if (value == E_INDEX) {
            return nullptr;
        }
        GetDisplayLevelAlbumPredicates(value, predicatesPortrait);
    } else if (whereClause.find(IS_ME) != string::npos) {
        GetIsMeAlbumPredicates(predicatesPortrait);
    } else {
        MEDIA_INFO_LOG("QueryPortraitAlbum whereClause is error");
        return nullptr;
    }
    if (predicatesPortrait.GetWhereClause().empty()) {
        return nullptr;
    }
    auto rdbPredicates = RdbUtils::ToPredicates(predicatesPortrait, ANALYSIS_ALBUM_TABLE);
    return MediaLibraryRdbStore::Query(rdbPredicates, columns);
}

shared_ptr<ResultSet> MediaLibraryAlbumOperations::QueryPhotoAlbum(MediaLibraryCommand &cmd,
    const vector<string> &columns)
{
    if (cmd.GetAbsRdbPredicates()->GetOrder().empty()) {
        cmd.GetAbsRdbPredicates()->OrderByAsc(PhotoAlbumColumns::ALBUM_ORDER);
    }
    return MediaLibraryRdbStore::Query(*(cmd.GetAbsRdbPredicates()), columns);
}

int32_t PrepareUpdateValues(const ValuesBucket &values, ValuesBucket &updateValues)
{
    // Collect albumName if exists and check
    string albumName;
    if (GetStringObject(values, PhotoAlbumColumns::ALBUM_NAME, albumName) == E_OK) {
        int32_t err = MediaFileUtils::CheckAlbumName(albumName);
        if (err < 0) {
            return err;
        }
        updateValues.PutString(PhotoAlbumColumns::ALBUM_NAME, albumName);
    }

    // Collect coverUri if exists
    string coverUri;
    if (GetStringObject(values, PhotoAlbumColumns::ALBUM_COVER_URI, coverUri) == E_OK) {
        updateValues.PutString(PhotoAlbumColumns::ALBUM_COVER_URI, coverUri);
    }

    if (updateValues.IsEmpty()) {
        return -EINVAL;
    }
    updateValues.PutLong(PhotoAlbumColumns::ALBUM_DATE_MODIFIED, MediaFileUtils::UTCTimeSeconds());
    return E_OK;
}

int32_t UpdatePhotoAlbum(const ValuesBucket &values, const DataSharePredicates &predicates)
{
    ValuesBucket rdbValues;
    int32_t err = PrepareUpdateValues(values, rdbValues);
    if (err < 0) {
        return err;
    }

    RdbPredicates rdbPredicates = RdbUtils::ToPredicates(predicates, PhotoAlbumColumns::TABLE);
    // Only user generic albums can be updated
    rdbPredicates.And()->BeginWrap()->EqualTo(PhotoAlbumColumns::ALBUM_TYPE, to_string(PhotoAlbumType::USER));
    rdbPredicates.EqualTo(PhotoAlbumColumns::ALBUM_SUBTYPE, to_string(PhotoAlbumSubType::USER_GENERIC));
    rdbPredicates.Or()->EqualTo(PhotoAlbumColumns::ALBUM_TYPE, to_string(PhotoAlbumType::SMART));
    rdbPredicates.EndWrap();

    int32_t changedRows = MediaLibraryRdbStore::Update(rdbValues, rdbPredicates);
    auto watch = MediaLibraryNotify::GetInstance();
    if (changedRows > 0) {
        for (size_t i = 0; i < rdbPredicates.GetWhereArgs().size() - AFTER_AGR_SIZE; i++) {
            watch->Notify(MediaFileUtils::GetUriByExtrConditions(PhotoAlbumColumns::ALBUM_URI_PREFIX,
                rdbPredicates.GetWhereArgs()[i]), NotifyType::NOTIFY_UPDATE);
        }
    }
    return changedRows;
}

int32_t RecoverPhotoAssets(const DataSharePredicates &predicates)
{
    RdbPredicates rdbPredicates = RdbUtils::ToPredicates(predicates, PhotoColumn::PHOTOS_TABLE);
    rdbPredicates.GreaterThan(MediaColumn::MEDIA_DATE_TRASHED, to_string(0));
    vector<string> whereArgs = rdbPredicates.GetWhereArgs();
    MediaLibraryRdbStore::ReplacePredicatesUriToId(rdbPredicates);

    ValuesBucket rdbValues;
    rdbValues.PutInt(MediaColumn::MEDIA_DATE_TRASHED, 0);

    int32_t changedRows = MediaLibraryRdbStore::Update(rdbValues, rdbPredicates);
    if (changedRows < 0) {
        return changedRows;
    }
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw();
    MediaLibraryRdbUtils::UpdateUserAlbumInternal(rdbStore);
    MediaLibraryRdbUtils::UpdateSystemAlbumInternal(rdbStore);
    MediaLibraryRdbUtils::UpdateHiddenAlbumInternal(rdbStore);
    MediaLibraryRdbUtils::UpdateAnalysisAlbumInternal(rdbStore);

    auto watch = MediaLibraryNotify::GetInstance();
    size_t count = whereArgs.size() - THAN_AGR_SIZE;
    for (size_t i = 0; i < count; i++) {
        string notifyUri = MediaFileUtils::Encode(whereArgs[i]);
        watch->Notify(notifyUri, NotifyType::NOTIFY_ADD);
        watch->Notify(notifyUri, NotifyType::NOTIFY_ALBUM_ADD_ASSERT);
    }
    int trashAlbumId = watch->GetAlbumIdBySubType(PhotoAlbumSubType::TRASH);
    if (trashAlbumId > 0) {
        for (size_t i = 0; i < count; i++) {
            watch->Notify(MediaFileUtils::Encode(whereArgs[i]), NotifyType::NOTIFY_ALBUM_REMOVE_ASSET, trashAlbumId);
        }
    }
    return changedRows;
}

static inline int32_t DeletePhotoAssets(const DataSharePredicates &predicates,
    const bool isAging, const bool compatible)
{
    RdbPredicates rdbPredicates = RdbUtils::ToPredicates(predicates, PhotoColumn::PHOTOS_TABLE);
    return MediaLibraryAssetOperations::DeleteFromDisk(rdbPredicates, isAging, compatible);
}

int32_t AgingPhotoAssets(shared_ptr<int> countPtr)
{
    auto time = MediaFileUtils::UTCTimeSeconds();
    DataSharePredicates predicates;
    predicates.GreaterThan(MediaColumn::MEDIA_DATE_TRASHED, to_string(0));
    predicates.And()->LessThanOrEqualTo(MediaColumn::MEDIA_DATE_TRASHED, to_string(time - AGING_TIME));
    int32_t ret = DeletePhotoAssets(predicates, true, false);
    if (ret < 0) {
        return ret;
    }
    if (countPtr != nullptr) {
        *countPtr = ret;
    }
    return E_OK;
}

static int32_t ObtainAlbumOrders(const int32_t &currentAlbumId, const int32_t referenceAlbumId,
    int32_t &currentAlbumOrder, int32_t &referenceAlbumOrder)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr! failed query album order");
        return E_HAS_DB_ERROR;
    }
    const std::string queryCurrentAlbumOrder = "SELECT " + PhotoAlbumColumns::ALBUM_ORDER + " FROM " +
        PhotoAlbumColumns::TABLE + " WHERE " + PhotoAlbumColumns::ALBUM_ID + " = " + to_string(currentAlbumId);
    const std::string queryReferenceAlbumOrder = "SELECT " + PhotoAlbumColumns::ALBUM_ORDER + " FROM " +
        PhotoAlbumColumns::TABLE + " WHERE " + PhotoAlbumColumns::ALBUM_ID + " = " + to_string(referenceAlbumId);
    auto resultSet = uniStore->QuerySql(queryCurrentAlbumOrder);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return E_HAS_DB_ERROR;
    }
    int colIndex = -1;
    resultSet->GetColumnIndex(PhotoAlbumColumns::ALBUM_ORDER, colIndex);
    if (resultSet->GetInt(colIndex, currentAlbumOrder) != NativeRdb::E_OK) {
        return E_HAS_DB_ERROR;
    }
    resultSet = uniStore->QuerySql(queryReferenceAlbumOrder);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK
        || resultSet->GetInt(colIndex, referenceAlbumOrder) != NativeRdb::E_OK) {
        return E_HAS_DB_ERROR;
    }
    return E_OK;
}

static int32_t ExecSqls(const vector<string> &sqls, const shared_ptr<MediaLibraryUnistore> &store)
{
    int32_t err = NativeRdb::E_OK;
    for (const auto &sql : sqls) {
        err = store->ExecuteSql(sql);
        if (err != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Failed to exec: %{private}s", sql.c_str());
            break;
        }
    }
    return NativeRdb::E_OK;
}

static int32_t ObtainNotifyAlbumIds(int32_t &currentAlbumOrder, int32_t referenceAlbumOrder,
    vector<int32_t> &changedAlbumIds)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr! failed query album order");
        return E_DB_FAIL;
    }
    std::string queryAlbumIds = "";
    if (currentAlbumOrder < referenceAlbumOrder) {
        queryAlbumIds = "SELECT " + PhotoAlbumColumns::ALBUM_ID + " FROM " +
            PhotoAlbumColumns::TABLE + " WHERE " + PhotoAlbumColumns::ALBUM_ORDER + " >= " +
            to_string(currentAlbumOrder) + " AND " + PhotoAlbumColumns::ALBUM_ORDER +
            " < " + to_string(referenceAlbumOrder);
    } else {
        queryAlbumIds = "SELECT " + PhotoAlbumColumns::ALBUM_ID + " FROM " +
            PhotoAlbumColumns::TABLE + " WHERE " + PhotoAlbumColumns::ALBUM_ORDER + " >= " +
            to_string(referenceAlbumOrder) + " AND " + PhotoAlbumColumns::ALBUM_ORDER +
            " <= " + to_string(currentAlbumOrder);
    }
    auto resultSet = uniStore->QuerySql(queryAlbumIds);
    if (resultSet == nullptr) {
        return E_DB_FAIL;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        changedAlbumIds.push_back(GetInt32Val(PhotoAlbumColumns::ALBUM_ID, resultSet));
    }
    return E_OK;
}

static void NotifyOrderChange(vector<int32_t> &changedAlbumIds)
{
    if (changedAlbumIds.size() <= 0) {
        return;
    }
    auto watch = MediaLibraryNotify::GetInstance();
    for (int32_t &albumId : changedAlbumIds) {
        watch->Notify(MediaFileUtils::GetUriByExtrConditions(
            PhotoAlbumColumns::ALBUM_URI_PREFIX, to_string(albumId)), NotifyType::NOTIFY_UPDATE);
    }
}

static int32_t UpdateSortedOrder(const int32_t &currentAlbumId, const int32_t referenceAlbumId,
    int32_t &currentAlbumOrder, int32_t &referenceAlbumOrder)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr! failed query album order");
        return E_DB_FAIL;
    }
    std::string updateOtherAlbumOrder = "";
    std::string updateCurrentAlbumOrder = "";
    if (currentAlbumOrder < referenceAlbumOrder) {
        updateOtherAlbumOrder = "UPDATE " + PhotoAlbumColumns::TABLE +
            " SET " + PhotoAlbumColumns::ALBUM_ORDER + " = " +
            PhotoAlbumColumns::ALBUM_ORDER + " -1 WHERE " + PhotoAlbumColumns::ALBUM_ORDER +
            " > " + to_string(currentAlbumOrder) +
            " and " + PhotoAlbumColumns::ALBUM_ORDER + " < " + to_string(referenceAlbumOrder);
        updateCurrentAlbumOrder = "UPDATE " + PhotoAlbumColumns::TABLE + " SET " + PhotoAlbumColumns::ALBUM_ORDER +
            " = " + to_string(referenceAlbumOrder) + " -1 WHERE " +
            PhotoAlbumColumns::ALBUM_ID + " = " + to_string(currentAlbumId);
    } else {
        updateOtherAlbumOrder = "UPDATE " + PhotoAlbumColumns::TABLE +
            " SET " + PhotoAlbumColumns::ALBUM_ORDER + " = " +
            PhotoAlbumColumns::ALBUM_ORDER + " +1 WHERE " + PhotoAlbumColumns::ALBUM_ORDER + " >= " +
            to_string(referenceAlbumOrder) + " AND " + PhotoAlbumColumns::ALBUM_ORDER +
            " < " + to_string(currentAlbumOrder);
        updateCurrentAlbumOrder = "UPDATE " + PhotoAlbumColumns::TABLE +
            " SET " + PhotoAlbumColumns::ALBUM_ORDER + " = " +
            to_string(referenceAlbumOrder) + " WHERE " +
            PhotoAlbumColumns::ALBUM_ID + " = " + to_string(currentAlbumId);
    }
    vector<string> updateSortedAlbumsSqls = { updateOtherAlbumOrder, updateCurrentAlbumOrder};
    return ExecSqls(updateSortedAlbumsSqls, uniStore);
}

static int32_t ObtainCurrentAlbumOrder(const int32_t &albumId, int32_t &albumOrder)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr! failed query album order");
        return E_HAS_DB_ERROR;
    }
    const std::string queryAlbumOrder = "SELECT " + PhotoAlbumColumns::ALBUM_ORDER + " FROM " +
        PhotoAlbumColumns::TABLE + " WHERE " + PhotoAlbumColumns::ALBUM_ID + " = " + to_string(albumId);
    auto resultSet = uniStore->QuerySql(queryAlbumOrder);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return E_HAS_DB_ERROR;
    }
    int colIndex = -1;
    resultSet->GetColumnIndex(PhotoAlbumColumns::ALBUM_ORDER, colIndex);
    if (resultSet->GetInt(colIndex, albumOrder) != NativeRdb::E_OK) {
        return E_HAS_DB_ERROR;
    }
    return E_OK;
}

static int32_t UpdateNullReferenceOrder(const int32_t &currentAlbumId,
    const int32_t &currentAlbumOrder, const int32_t &maxAlbumOrder)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr! failed query album order");
        return E_DB_FAIL;
    }
    std::string updateOtherAlbumOrder = "UPDATE " + PhotoAlbumColumns::TABLE + " SET " +
        PhotoAlbumColumns::ALBUM_ORDER + " = " + PhotoAlbumColumns::ALBUM_ORDER + " -1 WHERE " +
        PhotoAlbumColumns::ALBUM_ORDER + " > " + to_string(currentAlbumOrder) + " and " +
        PhotoAlbumColumns::ALBUM_ORDER + " <= " + to_string(maxAlbumOrder);
    std::string updateCurrentAlbumOrder = "UPDATE " + PhotoAlbumColumns::TABLE +
        " SET " + PhotoAlbumColumns::ALBUM_ORDER + " = " + to_string(maxAlbumOrder) +
        " WHERE " + PhotoAlbumColumns::ALBUM_ID + " = " + to_string(currentAlbumId);
    vector<string> updateSortedAlbumsSqls = { updateOtherAlbumOrder, updateCurrentAlbumOrder};
    return ExecSqls(updateSortedAlbumsSqls, uniStore);
}

static int32_t HandleNullReferenceCondition(const int32_t &currentAlbumId)
{
    int32_t maxAlbumOrder = 0;
    int err = ObtainMaxAlbumOrder(maxAlbumOrder);
    if (err != E_OK) {
        return E_HAS_DB_ERROR;
    }
    int32_t currentAlbumOrder = -1;
    err = ObtainCurrentAlbumOrder(currentAlbumId, currentAlbumOrder);
    if (err != E_OK) {
        return err;
    }
    vector<int32_t> changedAlbumIds;
    ObtainNotifyAlbumIds(currentAlbumOrder, maxAlbumOrder + 1, changedAlbumIds); // 1: move order curosr to the end
    err = UpdateNullReferenceOrder(currentAlbumId, currentAlbumOrder, maxAlbumOrder);
    if (err == E_OK) {
        NotifyOrderChange(changedAlbumIds);
    }
    return err;
}

static int32_t UpdatePortraitNullReferenceOrder(const int32_t currentAlbumId,
    const int32_t currentAlbumOrder, const int32_t maxAlbumOrder)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr! failed query album order");
        return E_DB_FAIL;
    }
    std::string updateOtherAlbumOrder = "UPDATE " + ANALYSIS_ALBUM_TABLE + " SET " +
        RANK + " = " + RANK + " -1 WHERE " +
        RANK + " > " + to_string(currentAlbumOrder) + " and " +
        RANK + " <= " + to_string(maxAlbumOrder);
    std::string updateCurrentAlbumOrder = "UPDATE " + ANALYSIS_ALBUM_TABLE +
        " SET " + RANK + " = " + to_string(maxAlbumOrder) +
        " WHERE " + GROUP_TAG + " IN (SELECT " + GROUP_TAG + " FROM " + ANALYSIS_ALBUM_TABLE +
        " WHERE " + ALBUM_ID + " = " + to_string(currentAlbumId) + ")";
    vector<string> updateSortedAlbumsSqls = { updateOtherAlbumOrder, updateCurrentAlbumOrder };
    return ExecSqls(updateSortedAlbumsSqls, uniStore);
}

static int32_t ObtainNotifyPortraitAlbumIds(const int32_t currentAlbumOrder, const int32_t referenceAlbumOrder,
    vector<int32_t> &changedAlbumIds)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr! failed query album order");
        return E_DB_FAIL;
    }
    std::string queryAlbumIds = "";
    if (currentAlbumOrder < referenceAlbumOrder) {
        queryAlbumIds = "SELECT " + ALBUM_ID + " FROM " + ANALYSIS_ALBUM_TABLE + " WHERE " + RANK + " >= " +
            to_string(currentAlbumOrder) + " AND " + RANK + " < " + to_string(referenceAlbumOrder);
    } else {
        queryAlbumIds = "SELECT " + ALBUM_ID + " FROM " + ANALYSIS_ALBUM_TABLE + " WHERE " + RANK + " >= " +
            to_string(referenceAlbumOrder) + " AND " + RANK + " <= " + to_string(currentAlbumOrder);
    }
    auto resultSet = uniStore->QuerySql(queryAlbumIds);
    if (resultSet == nullptr) {
        return E_DB_FAIL;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        changedAlbumIds.push_back(GetInt32Val(ALBUM_ID, resultSet));
    }
    return E_OK;
}

static int32_t ObtainCurrentPortraitAlbumOrder(const int32_t albumId, int32_t &albumOrder)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr! failed query album order");
        return E_HAS_DB_ERROR;
    }
    const std::string queryAlbumOrder = "SELECT " + RANK + " FROM " + ANALYSIS_ALBUM_TABLE + " WHERE " +
        PhotoAlbumColumns::ALBUM_ID + " = " + to_string(albumId);
    auto resultSet = uniStore->QuerySql(queryAlbumOrder);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return E_HAS_DB_ERROR;
    }
    return GetIntValueFromResultSet(resultSet, RANK, albumOrder);
}

static int32_t ObtainMaxPortraitAlbumOrder(int32_t &maxAlbumOrder)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr! failed query album order");
        return -E_HAS_DB_ERROR;
    }
    std::string queryMaxOrderSql = "SELECT Max(rank) FROM " + ANALYSIS_ALBUM_TABLE;
    auto resultSet = uniStore->QuerySql(queryMaxOrderSql);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Failed to query album!");
        return -E_HAS_DB_ERROR;
    }

    return resultSet->GetInt(0, maxAlbumOrder);
}

static int32_t HandlePortraitNullReferenceCondition(const int32_t currentAlbumId)
{
    int32_t maxAlbumOrder = 0;
    int err = ObtainMaxPortraitAlbumOrder(maxAlbumOrder);
    if (err != E_OK) {
        return E_HAS_DB_ERROR;
    }
    int32_t currentAlbumOrder = -1;
    err = ObtainCurrentPortraitAlbumOrder(currentAlbumId, currentAlbumOrder);
    if (err != E_OK) {
        return err;
    }
    vector<int32_t> changedAlbumIds;
     // move order curosr to the end
    ObtainNotifyPortraitAlbumIds(currentAlbumOrder, maxAlbumOrder + 1, changedAlbumIds);
    err = UpdatePortraitNullReferenceOrder(currentAlbumId, currentAlbumOrder, maxAlbumOrder);
    if (err == E_OK) {
        NotifyPortraitAlbum(changedAlbumIds);
    }
    return err;
}

static int32_t ObtainPortraitAlbumOrders(const int32_t currentAlbumId, const int32_t referenceAlbumId,
    int32_t &currentAlbumOrder, int32_t &referenceAlbumOrder)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr! failed query album order");
        return E_HAS_DB_ERROR;
    }
    const std::string queryCurrentAlbumOrder = "SELECT " + RANK + " FROM " +
        ANALYSIS_ALBUM_TABLE + " WHERE " + ALBUM_ID + " = " + to_string(currentAlbumId);
    auto resultSet = uniStore->QuerySql(queryCurrentAlbumOrder);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return E_HAS_DB_ERROR;
    }
    if (GetIntValueFromResultSet(resultSet, RANK, currentAlbumOrder) != NativeRdb::E_OK) {
        return E_HAS_DB_ERROR;
    }

    const std::string queryReferenceAlbumOrder = "SELECT " + RANK + " FROM " +
        ANALYSIS_ALBUM_TABLE + " WHERE " + ALBUM_ID + " = " + to_string(referenceAlbumId);
    resultSet = uniStore->QuerySql(queryReferenceAlbumOrder);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return E_HAS_DB_ERROR;
    }
    if (GetIntValueFromResultSet(resultSet, RANK, referenceAlbumOrder) != NativeRdb::E_OK) {
        return E_HAS_DB_ERROR;
    }
    return E_OK;
}

static int32_t UpdatePortraitSortedOrder(const int32_t currentAlbumId, const int32_t referenceAlbumId,
    const int32_t currentAlbumOrder, const int32_t referenceAlbumOrder)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr! failed query album order");
        return E_DB_FAIL;
    }
    std::string updateOtherAlbumOrder = "";
    std::string updateCurrentAlbumOrder = "";
    if (currentAlbumOrder < referenceAlbumOrder) {
        updateOtherAlbumOrder = "UPDATE " + ANALYSIS_ALBUM_TABLE + " SET " + RANK + " = " + RANK + " -1 WHERE " +
            RANK + " > " + to_string(currentAlbumOrder) + " and " + RANK + " < " + to_string(referenceAlbumOrder);
        updateCurrentAlbumOrder = "UPDATE " + ANALYSIS_ALBUM_TABLE + " SET " + RANK + " = " +
            to_string(referenceAlbumOrder) + " -1 WHERE " + GROUP_TAG + " IN (SELECT " + GROUP_TAG + " FROM " +
            ANALYSIS_ALBUM_TABLE + " WHERE " + ALBUM_ID + " = " + to_string(currentAlbumId) + ")";
    } else {
        updateOtherAlbumOrder = "UPDATE " + ANALYSIS_ALBUM_TABLE + " SET " + RANK + " = " + RANK + " +1 WHERE " +
            RANK + " >= " + to_string(referenceAlbumOrder) + " AND " + RANK + " < " + to_string(currentAlbumOrder);
        updateCurrentAlbumOrder = "UPDATE " + ANALYSIS_ALBUM_TABLE + " SET " + RANK + " = " +
            to_string(referenceAlbumOrder) + " WHERE " + GROUP_TAG + " IN (SELECT " + GROUP_TAG + " FROM " +
            ANALYSIS_ALBUM_TABLE + " WHERE " + ALBUM_ID + " = " + to_string(currentAlbumId) + ")";
    }
    vector<string> updateSortedAlbumsSqls = { updateOtherAlbumOrder, updateCurrentAlbumOrder};
    return ExecSqls(updateSortedAlbumsSqls, uniStore);
}

bool CheckIsFavoritePortraitAlbum(const int32_t currentAlbumId, const int32_t referenceAlbumId)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr! failed query album order");
        return false;
    }
    std::string queryDisplayLevel = "SELECT " + USER_DISPLAY_LEVEL + " FROM " + ANALYSIS_ALBUM_TABLE + " WHERE " +
        ALBUM_ID + " IN (" + to_string(currentAlbumId) + "," + to_string(referenceAlbumId) + ")";
    auto resultSet = uniStore->QuerySql(queryDisplayLevel);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Failed to query display level!");
        return false;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        int32_t displayLevel;
        if (GetIntValueFromResultSet(resultSet, USER_DISPLAY_LEVEL, displayLevel) != E_OK) {
            MEDIA_ERR_LOG("Get display level fail");
            return false;
        }
        if (displayLevel != FAVORITE_PAGE) {
            MEDIA_ERR_LOG("this album is not favorite portrait album");
            return false;
        }
    }
    return true;
}

int32_t OrderPortraitFavoriteAlbum(const int32_t currentAlbumId, const int32_t referenceAlbumId)
{
    if (!CheckIsFavoritePortraitAlbum(currentAlbumId, referenceAlbumId)) {
        return E_INVALID_VALUES;
    }
    if (referenceAlbumId == NULL_REFERENCE_ALBUM_ID) {
        return HandlePortraitNullReferenceCondition(currentAlbumId);
    }

    int32_t currentAlbumOrder = -1; // -1: default invalid value
    int32_t referenceAlbumOrder = -1; // -1: default invalid value
    int err = ObtainPortraitAlbumOrders(currentAlbumId, referenceAlbumId, currentAlbumOrder, referenceAlbumOrder);
    if (err != E_OK) {
        MEDIA_ERR_LOG("obtains album order error");
        return err;
    }
    vector<int32_t> changedAlbumIds;
    ObtainNotifyPortraitAlbumIds(currentAlbumOrder, referenceAlbumOrder, changedAlbumIds);
    err = UpdatePortraitSortedOrder(currentAlbumId, referenceAlbumId, currentAlbumOrder, referenceAlbumOrder);
    if (err == E_OK) {
        NotifyPortraitAlbum(changedAlbumIds);
    }
    return E_OK;
}

/**
 * Place the current album before the reference album
 * @param values contains current and reference album_id
 */
int32_t OrderSingleAlbum(const ValuesBucket &values)
{
    int32_t currentAlbumId;
    int32_t referenceAlbumId;
    int err = GetIntVal(values, PhotoAlbumColumns::ALBUM_ID, currentAlbumId);
    if (err < 0 || currentAlbumId <= 0) {
        MEDIA_ERR_LOG("invalid album id");
        return E_INVALID_VALUES;
    }
    err = GetIntVal(values, PhotoAlbumColumns::REFERENCE_ALBUM_ID, referenceAlbumId);
    if (err < 0 || referenceAlbumId == 0 || referenceAlbumId < NULL_REFERENCE_ALBUM_ID) {
        MEDIA_ERR_LOG("invalid reference album id");
        return E_INVALID_VALUES;
    }
    if (currentAlbumId == referenceAlbumId) { // same album, no need to order
        return E_OK;
    }

    int32_t albumType;
    int32_t albumSubtype;
    err = GetIntVal(values, PhotoAlbumColumns::ALBUM_TYPE, albumType);
    int errorSubtype = GetIntVal(values, PhotoAlbumColumns::ALBUM_SUBTYPE, albumSubtype);
    if (err == E_OK && errorSubtype == E_OK && (albumType == PhotoAlbumType::SMART && albumSubtype == PORTRAIT)) {
        return OrderPortraitFavoriteAlbum(currentAlbumId, referenceAlbumId);
    }
    if (referenceAlbumId == NULL_REFERENCE_ALBUM_ID) {
        return HandleNullReferenceCondition(currentAlbumId);
    }
    int32_t currentAlbumOrder = -1; // -1: default invalid value
    int32_t referenceAlbumOrder = -1;
    err = ObtainAlbumOrders(currentAlbumId, referenceAlbumId, currentAlbumOrder, referenceAlbumOrder);
    if (err != E_OK) {
        MEDIA_ERR_LOG("obtains album order error");
        return err;
    }
    vector<int32_t> changedAlbumIds;
    ObtainNotifyAlbumIds(currentAlbumOrder, referenceAlbumOrder, changedAlbumIds);
    err = UpdateSortedOrder(currentAlbumId, referenceAlbumId, currentAlbumOrder, referenceAlbumOrder);
    if (err == E_OK) {
        NotifyOrderChange(changedAlbumIds);
    }
    return E_OK;
}

inline int32_t GetStringVal(const ValuesBucket &values, const string &key, string &value)
{
    value = "";
    ValueObject valueObject;
    if (values.GetObject(key, valueObject)) {
        valueObject.GetString(value);
    } else {
        return -EINVAL;
    }
    return E_OK;
}

int GetMergeAlbumCount(const int32_t currentAlbumId, const int32_t targetAlbumId)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr! failed query merge album info");
        return E_DB_FAIL;
    }

    string queryCount = "SELECT COUNT(DISTINCT file_id) FROM " + PhotoColumn::PHOTOS_TABLE + " p INNER JOIN " +
        ANALYSIS_PHOTO_MAP_TABLE + " apm ON p." + PhotoColumn::MEDIA_ID + " = apm." + MAP_ASSET + " INNER JOIN " +
        ANALYSIS_ALBUM_TABLE + " aa ON aa." + ALBUM_ID + " = apm." + MAP_ALBUM + " INNER JOIN (SELECT " + GROUP_TAG +
        " FROM "+ ANALYSIS_ALBUM_TABLE + " WHERE " + ALBUM_ID + " IN (" + to_string(currentAlbumId) + "," +
        to_string(targetAlbumId) + ")) ag ON ag." + GROUP_TAG + " = " + " aa." + GROUP_TAG + " WHERE " +
        PhotoColumn::MEDIA_DATE_TRASHED + " = 0 AND " + PhotoColumn::MEDIA_TIME_PENDING + " = 0 AND " +
        PhotoColumn::MEDIA_HIDDEN + " = 0";
    auto resultSet = uniStore->QuerySql(queryCount);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Failed to query album!");
        return E_HAS_DB_ERROR;
    }
    int count;
    if (resultSet->GetInt(0, count) != E_OK) {
        return E_HAS_DB_ERROR;
    }
    return count;
}

string ParseFileIdFromCoverUri(const string &uri)
{
    if (PhotoColumn::PHOTO_URI_PREFIX.size() >= uri.size()) {
        return "";
    }
    string midStr = uri.substr(PhotoColumn::PHOTO_URI_PREFIX.size());
    string delimiter = "/";
    size_t pos = midStr.find(delimiter);
    if (pos == string::npos) {
        MEDIA_ERR_LOG("ParseFileIdFromCoverUri fail");
        return "";
    }
    return midStr.substr(0, pos);
}

static int32_t UpdateForReduceOneOrder(const int32_t referenceOrder)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr! failed query album order");
        return E_DB_FAIL;
    }
    std::string updateOtherAlbumOrder = "UPDATE " + ANALYSIS_ALBUM_TABLE + " SET " + RANK + " = " + RANK +
        " -1 WHERE " + RANK + " > " + to_string(referenceOrder);
    vector<string> updateSortedAlbumsSqls = { updateOtherAlbumOrder};
    return ExecSqls(updateSortedAlbumsSqls, uniStore);
}

int32_t UpdateForMergeAlbums(const MergeAlbumInfo &updateAlbumInfo, const int32_t currentAlbumId,
    const int32_t targetAlbumId)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr! failed update for merge albums");
        return E_DB_FAIL;
    }

    std::string updateForMergeAlbums = "UPDATE " + ANALYSIS_ALBUM_TABLE + " SET " + GROUP_TAG + " = " +
        updateAlbumInfo.groupTag + "," + COUNT + " = " + to_string(updateAlbumInfo.count) + "," + IS_ME + " = " +
        to_string(updateAlbumInfo.isMe) + "," + COVER_URI + " = " + updateAlbumInfo.coverUri + "," +
        USER_DISPLAY_LEVEL + " = " + to_string(updateAlbumInfo.userDisplayLevel) + "," + RANK + " = " +
        to_string(updateAlbumInfo.rank) + "," + USER_OPERATION + " = " + to_string(updateAlbumInfo.userOperation) +
        "," + RENAME_OPERATION + " = " + to_string(updateAlbumInfo.renameOperation) +
        " WHERE " + GROUP_TAG + " IN(SELECT " + GROUP_TAG + " FROM " + ANALYSIS_ALBUM_TABLE + " WHERE " + ALBUM_ID +
        " = " + to_string(currentAlbumId) + " OR " + ALBUM_ID + " = " + to_string(targetAlbumId) + ")";
    vector<string> updateSqls = { updateForMergeAlbums};
    return ExecSqls(updateSqls, uniStore);
}

int32_t GetMergeAlbumsInfo(vector<MergeAlbumInfo> &mergeAlbumInfo, const int32_t currentAlbumId,
    const int32_t targetAlbumId)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr! failed query merge album info");
        return E_DB_FAIL;
    }
    const std::string queryAlbumInfo = "SELECT " + ALBUM_ID + "," + GROUP_TAG + "," + COUNT + "," + IS_ME + "," +
        COVER_URI + "," + USER_DISPLAY_LEVEL + "," + RANK + "," + USER_OPERATION + "," + RENAME_OPERATION + " FROM " +
        ANALYSIS_ALBUM_TABLE + " WHERE " + ALBUM_ID + " = " + to_string(currentAlbumId) + " OR " +
        ALBUM_ID + " = " + to_string(targetAlbumId);

    auto resultSet = uniStore->QuerySql(queryAlbumInfo);
    if (resultSet == nullptr) {
        return E_HAS_DB_ERROR;
    }
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        MergeAlbumInfo albumInfo;
        if (GetIntValueFromResultSet(resultSet, ALBUM_ID, albumInfo.albumId) != E_OK ||
            GetStringValueFromResultSet(resultSet, GROUP_TAG, albumInfo.groupTag) != E_OK ||
            GetIntValueFromResultSet(resultSet, COUNT, albumInfo.count) != E_OK ||
            GetIntValueFromResultSet(resultSet, IS_ME, albumInfo.isMe) != E_OK ||
            GetStringValueFromResultSet(resultSet, GROUP_TAG, albumInfo.groupTag) != E_OK ||
            GetStringValueFromResultSet(resultSet, COVER_URI, albumInfo.coverUri) != E_OK ||
            GetIntValueFromResultSet(resultSet, USER_DISPLAY_LEVEL, albumInfo.userDisplayLevel) != E_OK ||
            GetIntValueFromResultSet(resultSet, RANK, albumInfo.rank) != E_OK ||
            GetIntValueFromResultSet(resultSet, RENAME_OPERATION, albumInfo.renameOperation) != E_OK) {
                MEDIA_ERR_LOG("GetMergeAlbumsInfo db fail");
                return E_HAS_DB_ERROR;
            }
        mergeAlbumInfo.push_back(albumInfo);
    }
    return E_OK;
}

int32_t GetMergeAlbumCoverUri(MergeAlbumInfo &updateAlbumInfo, const string &currentAlbumCoverUri,
    const string &targetAlbumCoverUri)
{
    string currentFileId = ParseFileIdFromCoverUri(currentAlbumCoverUri);
    string targetFileId = ParseFileIdFromCoverUri(targetAlbumCoverUri);
    if (currentFileId.empty() || targetFileId.empty()) {
        return E_DB_FAIL;
    }
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr! failed query get merge album cover uri");
        return E_DB_FAIL;
    }
    const std::string queryAlbumInfo = "SELECT " + MediaColumn::MEDIA_ID + "," + MediaColumn::MEDIA_TITLE + "," +
        MediaColumn::MEDIA_NAME + ", MAX(" + MediaColumn::MEDIA_DATE_MODIFIED + ") FROM " + PhotoColumn::PHOTOS_TABLE +
        " WHERE " + MediaColumn::MEDIA_ID + " = " + currentFileId + " OR " + MediaColumn::MEDIA_ID + " = " +
        targetFileId;

    auto resultSet = uniStore->QuerySql(queryAlbumInfo);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("resultSet is nullptr! failed query get merge album cover uri");
        return E_HAS_DB_ERROR;
    }
    int mergeFileId;
    if (GetIntValueFromResultSet(resultSet, MediaColumn::MEDIA_ID, mergeFileId) != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("resultSet is error! failed query get merge album cover uri");
        return E_HAS_DB_ERROR;
    }

    string mergeTitle;
    if (GetStringValueFromResultSet(resultSet, MediaColumn::MEDIA_TITLE, mergeTitle) != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("resultSet is error! failed query get merge album cover uri");
        return E_HAS_DB_ERROR;
    }

    string mergeDisplayName;
    if (GetStringValueFromResultSet(resultSet, MediaColumn::MEDIA_NAME, mergeDisplayName) != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("resultSet is error! failed query get merge album cover uri");
        return E_HAS_DB_ERROR;
    }
    updateAlbumInfo.coverUri = "'file://media/Photo/" + to_string(mergeFileId) + "/" + mergeTitle + "/" +
        mergeDisplayName + "'";
    return E_OK;
}

int32_t UpdateMergeAlbumsInfo(const vector<MergeAlbumInfo> &mergeAlbumInfo)
{
    MergeAlbumInfo updateAlbumInfo;
    if (GetMergeAlbumCoverUri(updateAlbumInfo, mergeAlbumInfo[0].coverUri, mergeAlbumInfo[1].coverUri) != E_OK) {
        return E_HAS_DB_ERROR;
    }
    updateAlbumInfo.count = GetMergeAlbumCount(mergeAlbumInfo[0].albumId, mergeAlbumInfo[1].albumId);
    updateAlbumInfo.groupTag = "'" + mergeAlbumInfo[0].groupTag + "|" + mergeAlbumInfo[1].groupTag + "'";
    updateAlbumInfo.isMe = (mergeAlbumInfo[0].isMe == 1 || mergeAlbumInfo[1].isMe == 1) ? 1 : 0;
    updateAlbumInfo.userOperation = 1;
    updateAlbumInfo.renameOperation = 1;
    int currentLevel = mergeAlbumInfo[0].userDisplayLevel;
    int targetLevel = mergeAlbumInfo[1].userDisplayLevel;
    if ((currentLevel == targetLevel) && (currentLevel == FIRST_PAGE || currentLevel == SECOND_PAGE ||
        currentLevel == UNFAVORITE_PAGE)) {
        updateAlbumInfo.userDisplayLevel = currentLevel;
        updateAlbumInfo.rank = 0;
    } else if ((currentLevel == targetLevel) && (currentLevel == FAVORITE_PAGE)) {
        updateAlbumInfo.userDisplayLevel = currentLevel;
        updateAlbumInfo.rank = min(mergeAlbumInfo[0].rank, mergeAlbumInfo[1].rank);
        if (UpdateForReduceOneOrder(max(mergeAlbumInfo[0].rank, mergeAlbumInfo[1].rank)) != E_OK) {
            return E_HAS_DB_ERROR;
        }
    } else if (currentLevel == FAVORITE_PAGE || targetLevel == FAVORITE_PAGE) {
        updateAlbumInfo.userDisplayLevel = FAVORITE_PAGE;
        updateAlbumInfo.rank = max(mergeAlbumInfo[0].rank, mergeAlbumInfo[1].rank);
    } else if (currentLevel == FIRST_PAGE || targetLevel == FIRST_PAGE) {
        updateAlbumInfo.userDisplayLevel = FIRST_PAGE;
        updateAlbumInfo.rank = 0;
    } else {
        updateAlbumInfo.userDisplayLevel = SECOND_PAGE;
        updateAlbumInfo.rank = 0;
    }
    return UpdateForMergeAlbums(updateAlbumInfo, mergeAlbumInfo[0].albumId, mergeAlbumInfo[1].albumId);
}

/**
 * Merge album
 * @param values contains current and target album_id
 */
int32_t MergeAlbum(const ValuesBucket &values)
{
    int32_t currentAlbumId;
    int32_t targetAlbumId;
    int err = GetIntVal(values, ALBUM_ID, currentAlbumId);
    if (err < 0 || currentAlbumId <= 0) {
        MEDIA_ERR_LOG("invalid album id");
        return E_INVALID_VALUES;
    }
    err = GetIntVal(values, TARGET_ALBUM_ID, targetAlbumId);
    if (err < 0 || targetAlbumId <= 0) {
        MEDIA_ERR_LOG("invalid target album id");
        return E_INVALID_VALUES;
    }
    if (currentAlbumId == targetAlbumId) { // same album, no need to merge
        return E_OK;
    }
    vector<MergeAlbumInfo> mergeAlbumInfo;
    if (GetMergeAlbumsInfo(mergeAlbumInfo, currentAlbumId, targetAlbumId)) {
        return E_HAS_DB_ERROR;
    }
    if (mergeAlbumInfo.size() != MERGE_ALBUM_COUNT) { // merge album count
        MEDIA_ERR_LOG("invalid mergeAlbumInfo size");
        return E_INVALID_VALUES;
    }
    return UpdateMergeAlbumsInfo(mergeAlbumInfo);
}

static int32_t UpdateDisplayLevel(const int32_t value, const int32_t albumId)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr! failed query album order");
        return E_DB_FAIL;
    }
    std::string updateDisplayLevel = "UPDATE " + ANALYSIS_ALBUM_TABLE + " SET " + USER_DISPLAY_LEVEL + " = " +
        to_string(value) + " WHERE " + GROUP_TAG + " IN (SELECT " + GROUP_TAG + " FROM " + ANALYSIS_ALBUM_TABLE +
        " WHERE " + ALBUM_ID + " = " + to_string(albumId) + ")";
    vector<string> updateDisplayLevelAlbumsSqls = { updateDisplayLevel };
    return ExecSqls(updateDisplayLevelAlbumsSqls, uniStore);
}

static int32_t UpdateFavoritesOrder(const int32_t value, const int32_t currentAlbumId)
{
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr! failed query album order");
        return E_DB_FAIL;
    }
    std::string updateOtherAlbumOrder;
    std::string updateCurrentAlbumOrder;
    if (value == FAVORITE_PAGE) {
        updateOtherAlbumOrder = "UPDATE " + ANALYSIS_ALBUM_TABLE + " SET " + RANK + " = " + RANK + " +1 WHERE " +
            USER_DISPLAY_LEVEL + " = " + to_string(FAVORITE_PAGE);
        updateCurrentAlbumOrder = "UPDATE " + ANALYSIS_ALBUM_TABLE + " SET " + RANK + " = 1" + " WHERE " + GROUP_TAG +
            " IN (SELECT " + GROUP_TAG + " FROM " + ANALYSIS_ALBUM_TABLE +
            " WHERE " + ALBUM_ID + " = " + to_string(currentAlbumId) + ")";
    } else {
        int rank;
        int err = ObtainCurrentPortraitAlbumOrder(currentAlbumId, rank);
        if (err != E_OK) {
            return err;
        }
        updateOtherAlbumOrder = "UPDATE " + ANALYSIS_ALBUM_TABLE + " SET " + RANK + " = " + RANK + " -1 WHERE " +
            USER_DISPLAY_LEVEL + " = " + to_string(FAVORITE_PAGE) + " AND " + RANK + ">" + to_string(rank);
        updateCurrentAlbumOrder = "UPDATE " + ANALYSIS_ALBUM_TABLE + " SET " + RANK + " = 0" +
            " WHERE " + GROUP_TAG + " IN (SELECT " + GROUP_TAG + " FROM " + ANALYSIS_ALBUM_TABLE +
            " WHERE " + ALBUM_ID + " = " + to_string(currentAlbumId) + ")";
    }
    vector<string> updateSortedAlbumsSqls = { updateOtherAlbumOrder, updateCurrentAlbumOrder};
    return ExecSqls(updateSortedAlbumsSqls, uniStore);
}

static int32_t UpdateFavorites(const int32_t value, const int32_t albumId)
{
    int err = UpdateFavoritesOrder(value, albumId);
    if (err != E_OK) {
        MEDIA_ERR_LOG("UpdateFavoritesOrder fail");
        return E_DB_FAIL;
    }
    return UpdateDisplayLevel(value, albumId);
}

int32_t SetDisplayLevel(const ValuesBucket &values, const DataSharePredicates &predicates)
{
    int32_t displayLevelValue;
    int err = GetIntVal(values, USER_DISPLAY_LEVEL, displayLevelValue);
    if (err < 0 || !MediaFileUtils::CheckDisplayLevel(displayLevelValue)) {
        MEDIA_ERR_LOG("invalid display level");
        return E_INVALID_VALUES;
    }

    RdbPredicates rdbPredicates = RdbUtils::ToPredicates(predicates, ANALYSIS_ALBUM_TABLE);
    auto whereArgs = rdbPredicates.GetWhereArgs();
    if (whereArgs.size() == 0) {
        MEDIA_ERR_LOG("no target album id");
        return E_INVALID_VALUES;
    }
    int32_t albumId = atoi(whereArgs[0].c_str());
    if (albumId <= 0) {
        MEDIA_ERR_LOG("invalid album id");
        return E_INVALID_VALUES;
    }

    vector<int32_t> changedAlbumIds;
    if (displayLevelValue == FIRST_PAGE || displayLevelValue == SECOND_PAGE) {
        err = UpdateDisplayLevel(displayLevelValue, albumId);
        changedAlbumIds.push_back(albumId);
    } else {
        err = UpdateFavorites(displayLevelValue, albumId);
        changedAlbumIds.push_back(albumId);
    }
    if (err == E_OK) {
        NotifyPortraitAlbum(changedAlbumIds);
    }
    return err;
}

/**
 * set target album is me
 * @param values is_me
 * @param predicates target album
 */
int32_t SetIsMe(const ValuesBucket &values, const DataSharePredicates &predicates)
{
    RdbPredicates rdbPredicates = RdbUtils::ToPredicates(predicates, ANALYSIS_ALBUM_TABLE);
    auto whereArgs = rdbPredicates.GetWhereArgs();
    if (whereArgs.size() == 0) {
        MEDIA_ERR_LOG("no target album id");
        return E_INVALID_VALUES;
    }
    string targetAlbumId = whereArgs[0];
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr! failed update for merge albums");
        return E_DB_FAIL;
    }

    std::string updateForSetIsMe = "UPDATE " + ANALYSIS_ALBUM_TABLE + " SET " + IS_ME + " = 1" + " WHERE " +
        GROUP_TAG + " IN(SELECT " + GROUP_TAG + " FROM " + ANALYSIS_ALBUM_TABLE + " WHERE " + ALBUM_ID + " = " +
        targetAlbumId + ")";
    vector<string> updateSqls = { updateForSetIsMe};
    int32_t err = ExecSqls(updateSqls, uniStore);
    if (err == E_OK) {
        vector<int32_t> changeAlbumIds = { atoi(targetAlbumId.c_str()) };
        NotifyPortraitAlbum(changeAlbumIds);
    }
    return err;
}

/**
 * set target album name
 * @param values album_name
 * @param predicates target album
 */
int32_t SetAlbumName(const ValuesBucket &values, const DataSharePredicates &predicates)
{
    RdbPredicates rdbPredicates = RdbUtils::ToPredicates(predicates, ANALYSIS_ALBUM_TABLE);
    auto whereArgs = rdbPredicates.GetWhereArgs();
    if (whereArgs.size() == 0) {
        MEDIA_ERR_LOG("no target album id");
        return E_INVALID_VALUES;
    }
    string targetAlbumId = whereArgs[0];
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr! failed update for set album name");
        return E_DB_FAIL;
    }
    string albumName;
    int err = GetStringVal(values, ALBUM_NAME, albumName);
    if (err < 0 || albumName.empty()) {
        MEDIA_ERR_LOG("invalid album name");
        return E_INVALID_VALUES;
    }
    std::string updateForSetAlbumName = "UPDATE " + ANALYSIS_ALBUM_TABLE + " SET " + ALBUM_NAME + " = '" + albumName +
        "' WHERE " + GROUP_TAG + " IN(SELECT " + GROUP_TAG + " FROM " + ANALYSIS_ALBUM_TABLE + " WHERE " + ALBUM_ID +
        " = " + targetAlbumId + ")";
    vector<string> updateSqls = { updateForSetAlbumName};
    err = ExecSqls(updateSqls, uniStore);
    if (err == E_OK) {
        vector<int32_t> changeAlbumIds = { atoi(targetAlbumId.c_str()) };
        NotifyPortraitAlbum(changeAlbumIds);
    }
    return err;
}

/**
 * set target album uri
 * @param values cover_uri
 * @param predicates target album
 */
int32_t SetCoverUri(const ValuesBucket &values, const DataSharePredicates &predicates)
{
    RdbPredicates rdbPredicates = RdbUtils::ToPredicates(predicates, ANALYSIS_ALBUM_TABLE);
    auto whereArgs = rdbPredicates.GetWhereArgs();
    if (whereArgs.size() == 0) {
        MEDIA_ERR_LOG("no target album id");
        return E_INVALID_VALUES;
    }
    string targetAlbumId = whereArgs[0];
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("uniStore is nullptr! failed update for set album cover uri");
        return E_DB_FAIL;
    }
    string coverUri;
    int err = GetStringVal(values, COVER_URI, coverUri);
    if (err < 0 || coverUri.empty()) {
        MEDIA_ERR_LOG("invalid album cover uri");
        return E_INVALID_VALUES;
    }
    std::string updateForSetCoverUri = "UPDATE " + ANALYSIS_ALBUM_TABLE + " SET " + COVER_URI + " = '" + coverUri +
        "' WHERE " + GROUP_TAG + " IN(SELECT " + GROUP_TAG + " FROM " + ANALYSIS_ALBUM_TABLE + " WHERE " + ALBUM_ID +
        " = " + targetAlbumId + ")";
    vector<string> updateSqls = { updateForSetCoverUri};
    err = ExecSqls(updateSqls, uniStore);
    if (err == E_OK) {
        vector<int32_t> changeAlbumIds = { atoi(targetAlbumId.c_str()) };
        NotifyPortraitAlbum(changeAlbumIds);
    }
    return err;
}

int32_t MediaLibraryAlbumOperations::HandleAnalysisPhotoAlbum(const OperationType &opType,
    const NativeRdb::ValuesBucket &values, const DataShare::DataSharePredicates &predicates,
    std::shared_ptr<int> countPtr)
{
    switch (opType) {
        case OperationType::PORTRAIT_DISPLAY_LEVEL:
            return SetDisplayLevel(values, predicates);
        case OperationType::PORTRAIT_MERGE_ALBUM:
            return MergeAlbum(values);
        case OperationType::PORTRAIT_IS_ME:
            return SetIsMe(values, predicates);
        case OperationType::PORTRAIT_ALBUM_NAME:
            return SetAlbumName(values, predicates);
        case OperationType::PORTRAIT_COVER_URI:
            return SetCoverUri(values, predicates);
        default:
            MEDIA_ERR_LOG("Unknown operation type: %{public}d", opType);
            return E_ERR;
    }
}

int32_t MediaLibraryAlbumOperations::HandlePhotoAlbum(const OperationType &opType, const ValuesBucket &values,
    const DataSharePredicates &predicates, shared_ptr<int> countPtr)
{
    switch (opType) {
        case OperationType::UPDATE:
            return UpdatePhotoAlbum(values, predicates);
        case OperationType::ALBUM_RECOVER_ASSETS:
            return RecoverPhotoAssets(predicates);
        case OperationType::ALBUM_DELETE_ASSETS:
            return DeletePhotoAssets(predicates, false, false);
        case OperationType::COMPAT_ALBUM_DELETE_ASSETS:
            return DeletePhotoAssets(predicates, false, true);
        case OperationType::AGING:
            return AgingPhotoAssets(countPtr);
        case OperationType::ALBUM_ORDER:
            return OrderSingleAlbum(values);
        default:
            MEDIA_ERR_LOG("Unknown operation type: %{public}d", opType);
            return E_ERR;
    }
}

int MediaLibraryAlbumOperations::HandlePhotoAlbumOperations(MediaLibraryCommand &cmd)
{
    switch (cmd.GetOprnType()) {
        case OperationType::CREATE:
            return CreatePhotoAlbum(cmd);
        default:
            MEDIA_ERR_LOG("Unknown operation type: %{public}d", cmd.GetOprnType());
            return E_ERR;
    }
}
} // namespace OHOS::Media
