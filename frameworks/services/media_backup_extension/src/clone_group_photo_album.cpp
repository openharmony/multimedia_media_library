/*
 * Copyright (C) 2023-2025 Huawei Device Co., Ltd.
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
#define MLOG_TAG "CloneGroupPhotoAlbum"

#include "clone_group_photo_album.h"
#include "backup_const_column.h"
#include "backup_const_map.h"
#include "backup_database_utils.h"
#include "backup_file_utils.h"
#include "backup_log_utils.h"
#include "database_report.h"
#include "cloud_sync_helper.h"
#include "exif_rotate_utils.h"
#include "gallery_db_upgrade.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_errno.h"
#include "medialibrary_rdb_transaction.h"
#include "photo_album_restore.h"
#include "photos_dao.h"
#include "photos_restore.h"
#include "result_set_utils.h"
#include "upgrade_restore_task_report.h"
#include "userfile_manager_types.h"
#include "vision_album_column.h"
#include "vision_column.h"
#include "vision_face_tag_column.h"
#include "vision_image_face_column.h"
#include "vision_photo_map_column.h"

namespace OHOS {
namespace Media {
CloneGroupPhotoAlbum::CloneGroupPhotoAlbum(std::shared_ptr<NativeRdb::RdbStore> galleryRdb,
    std::shared_ptr<NativeRdb::RdbStore> mediaLibraryRdb)
{
    mediaLibraryRdb_ = mediaLibraryRdb;
    galleryRdb_ = galleryRdb;
}

static std::vector<std::string> GroupTagSplit(const std::string& str, const std::string& delimiter)
{
    std::vector<std::string> result;
    size_t start = 0;
    size_t end = str.find(delimiter);

    while (end != std::string::npos) {
        result.emplace_back(str.substr(start, end - start));
        start = end + delimiter.length();
        end = str.find(delimiter, start);
    }
    result.emplace_back(str.substr(start));

    return result;
}

static std::string JoinGroupTag(const std::map<std::string, std::vector<std::string>>& groupTagMap)
{
    string groupTagId = "";
    CHECK_AND_RETURN_RET(groupTagMap.size() != 0, groupTagId);
    std::vector<std::string> tagVector;
    for (const auto& tagIt : groupTagMap) {
        CHECK_AND_CONTINUE(tagIt.second.size() != 0);
        if (tagIt.second.size() > 1) {
            tagVector.emplace_back(BackupDatabaseUtils::JoinValues(tagIt.second, "|"));
        } else {
            tagVector.emplace_back(tagIt.second[0]);
        }
    }
    groupTagId = BackupDatabaseUtils::JoinValues(tagVector, ",");
    return groupTagId;
}

bool CloneGroupPhotoAlbum::GetFileIdsByGroupTag(GroupAlbumInfo& info)
{
    std::map<std::string, std::string> tagMap = info.tagIdMap;
    CHECK_AND_RETURN_RET_LOG(!tagMap.empty(), false, "tagMap is empty.");
    std::string querySql =  R"(SELECT DISTINCT file_id FROM tab_analysis_image_face WHERE 1=1 )";
    std::string firstSql = R"(AND file_id IN (SELECT file_id FROM tab_analysis_image_face
        face JOIN tab_analysis_face_tag tag ON face.tag_id = tag.tag_id WHERE tag.tag_id IN ()";
    std::string lastSql = R"() AND (face.total_faces = 0 OR face.total_faces = )";
    std::string groupSql = R"( ORDER BY file_id DESC)";
    for (const auto& tagIt : tagMap) {
        querySql += firstSql + tagIt.second + lastSql + std::to_string(tagMap.size()) + "))";
    }
    querySql += groupSql;
    MEDIA_INFO_LOG("querySql = %{public}s", querySql.c_str());
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaLibraryRdb_, querySql);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, false, "Query resultSql is null.");
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        info.fileIdVec.emplace_back(GetInt32Val(MediaColumn::MEDIA_ID, resultSet));
    }
    info.fileIdCount = info.fileIdVec.size();
    resultSet->Close();
    CHECK_AND_RETURN_RET_LOG(info.fileIdCount > 0, false, "mediaLibraryRdb do not find any fileId.");
    return true;
}

bool CloneGroupPhotoAlbum::QueryTagIdFromMergeTag(GroupAlbumInfo& info)
{
    std::string querySql = "SELECT " + GALLERY_MERGE_TAG_TAG_ID + " FROM merge_tag WHERE " +
        GALLERY_GROUP_TAG + " = ?";
    std::vector<std::string> tagVector = info.groupTagVec;
    CHECK_AND_RETURN_RET_LOG(!tagVector.empty(), false, "tagVector is empty.");
    for (const auto& tag : tagVector) {
        auto resultSet = BackupDatabaseUtils::GetQueryResultSet(galleryRdb_, querySql, { tag });
        CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, false, "Query resultSql is null.");
        std::vector<std::string> tagIdVec;
        std::vector<std::string> tagIdVector;
        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            std::string tagId = GetStringVal(GALLERY_MERGE_TAG_TAG_ID, resultSet);
            tagIdVector.emplace_back("'" + tagId + "'");
            tagIdVec.emplace_back(std::move(tagId));
        }
        CHECK_AND_RETURN_RET_LOG(tagIdVec.size() != 0, false, "mergeTag do not find any tag_id.");
        info.groupTagMap.insert(std::make_pair(tag, tagIdVec));
        info.tagIdMap.insert(std::make_pair(tag, BackupDatabaseUtils::JoinValues(tagIdVector, ",")));
        resultSet->Close();
    }
    return true;
}

std::vector<GroupAlbumInfo> CloneGroupPhotoAlbum::GetGroupPhotoAlbumInfo()
{
    MEDIA_INFO_LOG("Start GetGroupPhotoAlbumInfo.");
    std::string querySql = "SELECT " + GALLERY_MERGE_TAG_TAG_ID + ", " + GALLERY_GROUP_TAG + ", " +
        GALLERY_TAG_NAME + ", " + GALLERY_USER_OPERATION + ", " + GALLERY_RENAME_OPERATION +
        " FROM merge_tag WHERE group_Tag LIKE '%|%'";
    std::vector<GroupAlbumInfo> result;
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(galleryRdb_, querySql);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, result, "Query resultSql is null.");
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        GroupAlbumInfo info;
        std::vector<std::string> tagVector;
        string groupTag = GetStringVal(GALLERY_GROUP_TAG, resultSet);
        CHECK_AND_CONTINUE(!groupTag.empty());
        tagVector = GroupTagSplit(groupTag, "|");
        info.groupTagVec = tagVector;
        CHECK_AND_CONTINUE(QueryTagIdFromMergeTag(info));
        CHECK_AND_CONTINUE(GetFileIdsByGroupTag(info));
        info.groupTag = JoinGroupTag(info.groupTagMap);
        MEDIA_INFO_LOG("info.groupTag = %{public}s", info.groupTag.c_str());
        info.tagId = info.groupTag;
        info.tagName = GetStringVal(GALLERY_TAG_NAME, resultSet);
        info.userOperation = GetInt32Val(GALLERY_USER_OPERATION, resultSet);
        info.renameOperation = (!info.tagName.empty() ? RENAME_OPERATION_RENAMED : 0);
        result.emplace_back(info);
    }
    resultSet->Close();
    MEDIA_INFO_LOG("GetGroupPhotoAlbumInfo end.");
    return result;
}

void CloneGroupPhotoAlbum::QueryGroupPhotoAlbum(std::vector<GroupAlbumInfo> &groupPhotoAlbumInfos,
    std::map<int32_t, std::vector<int32_t>> &groupPhotoMap)
{
    std::string querySql = "SELECT " + ALBUM_ID + " FROM " + ANALYSIS_ALBUM_TABLE + " WHERE " +
        GROUP_TAG + " IS NOT NULL" + " AND " + GROUP_TAG + " = ?";
    for (const auto& info : groupPhotoAlbumInfos) {
        std::vector<std::string> params = { info.groupTag };
        auto resultSet = BackupDatabaseUtils::GetQueryResultSet(mediaLibraryRdb_, querySql, params);
        CHECK_AND_RETURN_LOG(resultSet != nullptr, "Query resultSql is null.");
        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            int32_t albumId = GetInt32Val(ALBUM_ID, resultSet);
            groupPhotoMap[albumId] = info.fileIdVec;
        }
        resultSet->Close();
    }
}

bool CloneGroupPhotoAlbum::ExecuteBatchSql(const std::string& sql, const std::string& updateSql)
{
    MEDIA_INFO_LOG("sql = %{public}s", sql.c_str());
    MEDIA_INFO_LOG("updateSql = %{public}s", updateSql.c_str());
    int32_t ret = BackupDatabaseUtils::ExecuteSQL(mediaLibraryRdb_, sql);
    CHECK_AND_RETURN_RET_LOG(ret >= 0, false, "execute insert AnalysisPhotoMap failed, ret=%{public}d", ret);
    ret = BackupDatabaseUtils::ExecuteSQL(mediaLibraryRdb_, updateSql + ")");
    CHECK_AND_RETURN_RET_LOG(ret >= 0, false, "execute update image_face failed, ret=%{public}d", ret);
    return true;
}

void CloneGroupPhotoAlbum::InsertAnalysisPhotoMap(const std::map<int32_t, std::vector<int32_t>> &groupPhotoMap)
{
    const int32_t BATCH_SIZE = 100;
    std::string baseSql = "INSERT OR REPLACE INTO AnalysisPhotoMap (map_album, map_asset) VALUES ";
    std::string baseUpdateSql = "UPDATE tab_analysis_image_face SET group_version = '1' WHERE file_id IN (";

    int32_t currentBatchSize = 0;
    string sql = baseSql;
    string updateSql = baseUpdateSql;
    bool isFirst = true;
    bool isFirstUpdate = true;

    for (const auto& [albumId, fileIds] : groupPhotoMap) {
        for (int fileId : fileIds) {
            if (!isFirst) {
                sql += ", ";
            }
            sql += "(" + to_string(albumId) + ", " + to_string(fileId) + ")";
            isFirst = false;
            if (!isFirstUpdate) {
                updateSql += ", ";
            }
            updateSql += to_string(fileId);
            isFirstUpdate = false;
            currentBatchSize++;
            if (currentBatchSize >= BATCH_SIZE) {
                CHECK_AND_RETURN(ExecuteBatchSql(sql, updateSql));
                sql = baseSql;
                updateSql = baseUpdateSql;
                currentBatchSize = 0;
                isFirst = true;
                isFirstUpdate = true;
            }
        }
    }
    if (currentBatchSize > 0) {
        ExecuteBatchSql(sql, updateSql);
    }
}

int32_t CloneGroupPhotoAlbum::BatchInsertWithRetry(const std::string &tableName,
    std::vector<NativeRdb::ValuesBucket> &values, int64_t &rowNum)
{
    if (values.empty()) {
        return 0;
    }

    int32_t errCode = E_ERR;
    TransactionOperations trans{ __func__ };
    trans.SetBackupRdbStore(mediaLibraryRdb_);
    std::function<int(void)> func = [&]()->int {
        errCode = trans.BatchInsert(rowNum, tableName, values);
        CHECK_AND_PRINT_LOG(errCode == E_OK,
            "InsertSql failed, errCode: %{public}d, rowNum: %{public}ld.", errCode, (long)rowNum);
        return errCode;
    };
    errCode = trans.RetryTrans(func, true);
    CHECK_AND_PRINT_LOG(errCode == E_OK, "BatchInsertWithRetry: tans finish fail!, ret:%{public}d", errCode);
    return errCode;
}

void CloneGroupPhotoAlbum::UpdateGroupPhoto()
{
    MEDIA_INFO_LOG("Start to update group photo album.");
    std::vector<GroupAlbumInfo> result;
    int64_t start = MediaFileUtils::UTCTimeMilliSeconds();
    result = GetGroupPhotoAlbumInfo();
    CHECK_AND_RETURN_LOG(result.size() != 0, "Query resultSql is null.");
    std::vector<NativeRdb::ValuesBucket> values;
    for (const auto& info : result) {
        NativeRdb::ValuesBucket valuesBucket;
        valuesBucket.PutInt(ALBUM_TYPE, PhotoAlbumType::SMART);
        valuesBucket.PutString(ALBUM_NAME, info.tagName);
        valuesBucket.PutInt(ALBUM_SUBTYPE, PhotoAlbumSubType::GROUP_PHOTO);
        valuesBucket.PutString(GROUP_TAG, info.groupTag);
        valuesBucket.PutString(TAG_ID, info.tagId);
        valuesBucket.PutInt(USER_OPERATION, info.userOperation);
        valuesBucket.PutInt(IS_LOCAL, IS_LOCAL_TRUE);
        valuesBucket.PutInt(COUNT, info.fileIdCount);
        valuesBucket.PutInt(USER_DISPLAY_LEVEL, info.userDisplayLevel);
        values.emplace_back(valuesBucket);
    }
    int64_t rowNum = 0;
    int32_t errCode = BatchInsertWithRetry(ANALYSIS_ALBUM_TABLE, values, rowNum);
    CHECK_AND_RETURN(errCode == E_OK);
    std::map<int32_t, std::vector<int32_t>> groupPhotoMap;
    QueryGroupPhotoAlbum(result, groupPhotoMap);
    CHECK_AND_RETURN(groupPhotoMap.size() != 0);
    InsertAnalysisPhotoMap(groupPhotoMap);
    int64_t end = MediaFileUtils::UTCTimeMilliSeconds();
    int64_t sumTime = end - start;
    MEDIA_INFO_LOG("End UpdateGroupPhoto. sumTime = %{public}" PRId64, sumTime);
}
}
}  // namespace OHOS