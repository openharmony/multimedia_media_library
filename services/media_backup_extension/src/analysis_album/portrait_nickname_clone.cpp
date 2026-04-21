/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#define MLOG_TAG "MediaLibraryCloneRestoreNickNameTbl"

#include "portrait_nickname_clone.h"

#include <algorithm>
#include <utility>

#include "backup_database_utils.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "result_set_utils.h"
#include "vision_album_column.h"
#include "vision_portrait_nickname_column.h"

namespace OHOS::Media {
PortraitNickNameClone::PortraitNickNameClone(const std::shared_ptr<NativeRdb::RdbStore>& sourceRdb,
    const std::shared_ptr<NativeRdb::RdbStore>& destRdb,
    std::unordered_map<int32_t, int32_t> analysisAlbumIdMap, bool isCloudRestoreSatisfied)
    : sourceRdb_(sourceRdb), destRdb_(destRdb), analysisAlbumIdMap_(std::move(analysisAlbumIdMap)),
      isCloudRestoreSatisfied_(isCloudRestoreSatisfied)
{
}

bool PortraitNickNameClone::Clone()
{
    int64_t start = MediaFileUtils::UTCTimeMilliSeconds();
    if (!IsReadyForClone()) {
        totalTimeCost_ = MediaFileUtils::UTCTimeMilliSeconds() - start;
        return true;
    }

    std::vector<int32_t> oldAlbumIds;
    oldAlbumIds.reserve(analysisAlbumIdMap_.size());
    for (const auto& [oldAlbumId, newAlbumId] : analysisAlbumIdMap_) {
        if (oldAlbumId <= 0 || newAlbumId <= 0 || !IsMappedPortraitAlbumReady(oldAlbumId)) {
            continue;
        }
        oldAlbumIds.push_back(oldAlbumId);
    }
    std::sort(oldAlbumIds.begin(), oldAlbumIds.end());
    if (oldAlbumIds.empty()) {
        totalTimeCost_ = MediaFileUtils::UTCTimeMilliSeconds() - start;
        MEDIA_INFO_LOG("analysisAlbumIdMap_ has no valid album mapping, skip portrait nickname clone");
        return true;
    }

    for (size_t index = 0; index < oldAlbumIds.size(); index += SQL_BATCH_SIZE) {
        auto batchBegin = oldAlbumIds.begin() + index;
        auto batchEnd = (index + SQL_BATCH_SIZE < oldAlbumIds.size()) ?
            (oldAlbumIds.begin() + index + SQL_BATCH_SIZE) : oldAlbumIds.end();
        std::vector<int32_t> batchOldAlbumIds(batchBegin, batchEnd);
        if (batchOldAlbumIds.empty()) {
            continue;
        }

        std::string albumIdClause = "(" + BackupDatabaseUtils::JoinValues<int32_t>(batchOldAlbumIds, ", ") + ")";
        std::vector<PortraitNickNameRecord> records = QueryPortraitNickNameRecords(albumIdClause);
        if (records.empty()) {
            continue;
        }

        RemapAlbumIds(records);
        BatchInsertPortraitNickNameRecords(records);
    }

    totalTimeCost_ = MediaFileUtils::UTCTimeMilliSeconds() - start;
    MEDIA_INFO_LOG("PortraitNickNameClone::Clone completed. Migrated %{public}lld records. Total time: "
        "%{public}lld ms", static_cast<long long>(migratedCount_), static_cast<long long>(totalTimeCost_));
    return true;
}

bool PortraitNickNameClone::IsReadyForClone() const
{
    if (analysisAlbumIdMap_.empty()) {
        MEDIA_INFO_LOG("analysisAlbumIdMap_ is empty, no portrait nickname entries to clone");
        return false;
    }

    bool sourceTableExists = false;
    bool destTableExists = false;
    CHECK_AND_RETURN_RET_LOG(
        BackupDatabaseUtils::isTableExist(sourceRdb_, ANALYSIS_NICK_NAME_TABLE, sourceTableExists), false,
        "Failed to query source portrait nickname table");
    CHECK_AND_RETURN_RET_LOG(
        BackupDatabaseUtils::isTableExist(destRdb_, ANALYSIS_NICK_NAME_TABLE, destTableExists), false,
        "Failed to query destination portrait nickname table");
    if (!sourceTableExists || !destTableExists) {
        MEDIA_INFO_LOG("portrait nickname table missing, sourceExists=%{public}d, destExists=%{public}d",
            sourceTableExists, destTableExists);
        return false;
    }
    return true;
}

std::string PortraitNickNameClone::BuildReadyPortraitAlbumSql() const
{
    const std::string positionClause = isCloudRestoreSatisfied_ ? " IN (1, 2, 3) " : " IN (1, 3) ";
    return "SELECT COUNT(1) AS count FROM AnalysisAlbum WHERE album_id = ? "
        "AND album_type = 4096 AND album_subtype = 4102 "
        "AND EXISTS (SELECT 1 FROM AnalysisPhotoMap WHERE map_album = AnalysisAlbum.album_id "
        "AND EXISTS (SELECT 1 FROM Photos WHERE file_id = map_asset "
        "AND position" + positionClause +
        "AND sync_status = 0 AND clean_flag = 0 AND time_pending = 0 AND is_temp = 0))";
}

bool PortraitNickNameClone::IsMappedPortraitAlbumReady(int32_t oldAlbumId) const
{
    std::vector<NativeRdb::ValueObject> args = { oldAlbumId };
    return BackupDatabaseUtils::QueryInt(sourceRdb_, BuildReadyPortraitAlbumSql(), "count", args) > 0;
}

std::vector<PortraitNickNameRecord> PortraitNickNameClone::QueryPortraitNickNameRecords(
    const std::string& albumIdClause) const
{
    std::vector<PortraitNickNameRecord> records;
    std::string querySql = "SELECT album_id, nick_name FROM tab_analysis_nick_name WHERE album_id IN " +
        albumIdClause + " ORDER BY album_id, rowid";
    auto resultSet = BackupDatabaseUtils::GetQueryResultSet(sourceRdb_, querySql);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, records, "Query result for portrait nickname is null");

    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        PortraitNickNameRecord record;
        ParsePortraitNickNameResultSet(resultSet, record);
        records.emplace_back(std::move(record));
    }
    resultSet->Close();
    return records;
}

void PortraitNickNameClone::ParsePortraitNickNameResultSet(const std::shared_ptr<NativeRdb::ResultSet>& resultSet,
    PortraitNickNameRecord& record) const
{
    record.albumId = GetInt32Val(ALBUM_ID, resultSet);
    record.nickName = GetStringVal(NICK_NAME, resultSet);
}

void PortraitNickNameClone::RemapAlbumIds(std::vector<PortraitNickNameRecord>& records) const
{
    auto newEnd = std::remove_if(records.begin(), records.end(), [this](PortraitNickNameRecord& record) {
        auto it = analysisAlbumIdMap_.find(record.albumId);
        if (it == analysisAlbumIdMap_.end() || it->second <= 0) {
            return true;
        }
        record.albumId = it->second;
        return record.nickName.empty();
    });
    records.erase(newEnd, records.end());
    std::stable_sort(records.begin(), records.end(), [](const PortraitNickNameRecord& lhs,
        const PortraitNickNameRecord& rhs) {
        if (lhs.albumId != rhs.albumId) {
            return lhs.albumId < rhs.albumId;
        }
        return lhs.nickName < rhs.nickName;
    });
}

void PortraitNickNameClone::BatchInsertPortraitNickNameRecords(const std::vector<PortraitNickNameRecord>& records)
{
    std::vector<NativeRdb::ValuesBucket> valuesBuckets;
    valuesBuckets.reserve(records.size());
    for (const auto& record : records) {
        valuesBuckets.push_back(CreateValuesBucket(record));
    }
    CHECK_AND_RETURN_LOG(!valuesBuckets.empty(), "No valid portrait nickname data to insert");

    int64_t rowNum = 0;
    int32_t ret = BackupDatabaseUtils::BatchInsert(destRdb_, ANALYSIS_NICK_NAME_TABLE, valuesBuckets, rowNum,
        NativeRdb::ConflictResolution::ON_CONFLICT_IGNORE);
    CHECK_AND_RETURN_LOG(ret == E_OK, "Failed to batch insert portrait nickname records");
    migratedCount_ += rowNum;
}

NativeRdb::ValuesBucket PortraitNickNameClone::CreateValuesBucket(const PortraitNickNameRecord& record) const
{
    NativeRdb::ValuesBucket values;
    values.PutInt(ALBUM_ID, record.albumId);
    values.PutString(NICK_NAME, record.nickName);
    return values;
}
} // namespace OHOS::Media
