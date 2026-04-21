/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#define MLOG_TAG "PortraitNickRepo"

#include "portrait_nickname_repository.h"

#include "analysis_album_attribute_const.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "photo_album_column.h"
#include "result_set_utils.h"
#include "userfile_manager_types.h"
#include "vision_portrait_nickname_column.h"

namespace OHOS::Media {
using namespace OHOS::NativeRdb;

PortraitNickNameRepository::PortraitNickNameRepository(const std::shared_ptr<MediaLibraryRdbStore> &rdbStore)
    : rdbStore_(rdbStore)
{
}

bool PortraitNickNameRepository::Exists(const std::string &albumId) const
{
    CHECK_AND_RETURN_RET_LOG(rdbStore_ != nullptr, false, "rdbStore is nullptr");
    const std::string sql =
        "SELECT album_id FROM AnalysisAlbum WHERE album_id = ? AND album_type = ? AND album_subtype = ? LIMIT 1";
    std::vector<std::string> bindArgs = {
        albumId,
        std::to_string(static_cast<int32_t>(PhotoAlbumType::SMART)),
        std::to_string(static_cast<int32_t>(PhotoAlbumSubType::PORTRAIT)),
    };
    auto resultSet = rdbStore_->QuerySql(sql, bindArgs);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, false, "query portrait album failed");
    return resultSet->GoToFirstRow() == NativeRdb::E_OK;
}

int32_t PortraitNickNameRepository::QueryNickNameCount(const std::string &albumId, int32_t &count) const
{
    CHECK_AND_RETURN_RET_LOG(rdbStore_ != nullptr, E_HAS_DB_ERROR, "rdbStore is nullptr");
    const std::string sql = "SELECT COUNT(1) AS count FROM tab_analysis_nick_name WHERE album_id = ?";
    std::vector<std::string> bindArgs = { albumId };
    auto resultSet = rdbStore_->QuerySql(sql, bindArgs);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_HAS_DB_ERROR, "resultSet is empty");
    CHECK_AND_RETURN_RET_LOG(TryToGoToFirstRow(resultSet), E_HAS_DB_ERROR, "go to first row failed");
    count = GetInt32Val("count", resultSet);
    return E_OK;
}

int32_t PortraitNickNameRepository::QueryExistingNickNameCount(const std::string &albumId,
    const std::vector<std::string> &nickNames, int32_t &count) const
{
    CHECK_AND_RETURN_RET_LOG(rdbStore_ != nullptr, E_HAS_DB_ERROR, "rdbStore is nullptr");
    std::string sql = "SELECT COUNT(1) AS count FROM tab_analysis_nick_name WHERE album_id = ? AND nick_name IN (";
    std::vector<std::string> bindArgs = { albumId };
    for (size_t i = 0; i < nickNames.size(); i++) {
        sql += "?";
        if (i + 1 < nickNames.size()) {
            sql += ", ";
        }
        bindArgs.emplace_back(nickNames[i]);
    }
    sql += ")";
    auto resultSet = rdbStore_->QuerySql(sql, bindArgs);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_HAS_DB_ERROR, "resultSet is empty");
    CHECK_AND_RETURN_RET_LOG(TryToGoToFirstRow(resultSet), E_HAS_DB_ERROR, "go to first row failed");
    count = GetInt32Val("count", resultSet);
    return E_OK;
}

int32_t PortraitNickNameRepository::CheckNickNameLimit(const std::string &albumId,
    const std::vector<std::string> &nickNames) const
{
    int32_t currentCount = 0;
    CHECK_AND_RETURN_RET_LOG(QueryNickNameCount(albumId, currentCount) == E_OK,
        E_HAS_DB_ERROR, "query portrait nickname count failed");
    int32_t existingCount = 0;
    CHECK_AND_RETURN_RET_LOG(QueryExistingNickNameCount(albumId, nickNames, existingCount) == E_OK,
        E_HAS_DB_ERROR, "query existing portrait nicknames failed");
    size_t increasedCount = nickNames.size() - static_cast<size_t>(existingCount);
    CHECK_AND_RETURN_RET_LOG(currentCount + static_cast<int32_t>(increasedCount) <=
        static_cast<int32_t>(ANALYSIS_ALBUM_MAX_NICK_NAME_COUNT), E_OPERATION_NOT_SUPPORT,
        "portrait nickname count exceeds limit, albumId: %{public}s", albumId.c_str());
    return E_OK;
}

int32_t PortraitNickNameRepository::InsertNickNames(const std::string &albumId,
    const std::vector<std::string> &nickNames) const
{
    CHECK_AND_RETURN_RET_LOG(!nickNames.empty(), E_INVALID_VALUES, "nickNames is empty");
    CHECK_AND_RETURN_RET_LOG(rdbStore_ != nullptr, E_HAS_DB_ERROR, "rdbStore is nullptr");
    std::string sql = "INSERT OR IGNORE INTO tab_analysis_nick_name (album_id, nick_name) VALUES ";
    std::vector<NativeRdb::ValueObject> bindArgs;
    for (size_t i = 0; i < nickNames.size(); i++) {
        sql += "(?, ?)";
        if (i + 1 < nickNames.size()) {
            sql += ", ";
        }
        bindArgs.emplace_back(albumId);
        bindArgs.emplace_back(nickNames[i]);
    }
    int32_t ret = rdbStore_->ExecuteSql(sql, bindArgs);
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, E_HAS_DB_ERROR, "add portrait nickname failed");
    return E_OK;
}

int32_t PortraitNickNameRepository::QueryNickNames(const std::vector<std::string> &albumIds,
    std::vector<std::string> &nickNames) const
{
    CHECK_AND_RETURN_RET_LOG(!albumIds.empty(), E_INVALID_VALUES, "albumIds is empty");
    CHECK_AND_RETURN_RET_LOG(rdbStore_ != nullptr, E_HAS_DB_ERROR, "rdbStore is nullptr");
    std::string sql = "SELECT nick_name FROM tab_analysis_nick_name WHERE album_id IN (";
    std::vector<NativeRdb::ValueObject> bindArgs;
    for (size_t i = 0; i < albumIds.size(); i++) {
        sql += "?";
        if (i + 1 < albumIds.size()) {
            sql += ", ";
        }
        bindArgs.emplace_back(albumIds[i]);
    }
    sql += ") ORDER BY album_id, nick_name";
    auto resultSet = rdbStore_->QuerySql(sql, bindArgs);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_HAS_DB_ERROR, "query portrait nicknames failed");
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        nickNames.emplace_back(GetStringVal(NICK_NAME, resultSet));
    }
    return E_OK;
}

int32_t PortraitNickNameRepository::DeleteNickNames(const std::vector<std::string> &albumIds) const
{
    CHECK_AND_RETURN_RET_LOG(!albumIds.empty(), E_INVALID_VALUES, "albumIds is empty");
    CHECK_AND_RETURN_RET_LOG(rdbStore_ != nullptr, E_HAS_DB_ERROR, "rdbStore is nullptr");
    std::string sql = "DELETE FROM tab_analysis_nick_name WHERE album_id IN (";
    std::vector<NativeRdb::ValueObject> bindArgs;
    for (size_t i = 0; i < albumIds.size(); i++) {
        sql += "?";
        if (i + 1 < albumIds.size()) {
            sql += ", ";
        }
        bindArgs.emplace_back(albumIds[i]);
    }
    sql += ")";
    int32_t ret = rdbStore_->ExecuteSql(sql, bindArgs);
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, E_HAS_DB_ERROR, "delete portrait nicknames failed");
    return E_OK;
}

int32_t PortraitNickNameRepository::DeleteNickNames(const std::vector<std::string> &albumIds,
    const std::vector<std::string> &nickNames) const
{
    CHECK_AND_RETURN_RET_LOG(!albumIds.empty(), E_INVALID_VALUES, "albumIds is empty");
    CHECK_AND_RETURN_RET_LOG(!nickNames.empty(), E_INVALID_VALUES, "nickNames is empty");
    CHECK_AND_RETURN_RET_LOG(rdbStore_ != nullptr, E_HAS_DB_ERROR, "rdbStore is nullptr");
    std::string sql = "DELETE FROM tab_analysis_nick_name WHERE album_id IN (";
    std::vector<NativeRdb::ValueObject> bindArgs;
    for (size_t i = 0; i < albumIds.size(); i++) {
        sql += "?";
        if (i + 1 < albumIds.size()) {
            sql += ", ";
        }
        bindArgs.emplace_back(albumIds[i]);
    }
    sql += ") AND nick_name IN (";
    for (size_t i = 0; i < nickNames.size(); i++) {
        sql += "?";
        if (i + 1 < nickNames.size()) {
            sql += ", ";
        }
        bindArgs.emplace_back(nickNames[i]);
    }
    sql += ")";
    int32_t ret = rdbStore_->ExecuteSql(sql, bindArgs);
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, E_HAS_DB_ERROR, "delete portrait nicknames by values failed");
    return E_OK;
}
} // namespace OHOS::Media
