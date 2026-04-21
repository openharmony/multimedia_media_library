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

#ifndef PORTRAIT_NICKNAME_CLONE_H
#define PORTRAIT_NICKNAME_CLONE_H

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "backup_const.h"
#include "rdb_store.h"

namespace OHOS::Media {
struct PortraitNickNameRecord {
    int32_t albumId = 0;
    std::string nickName;
};

class PortraitNickNameClone {
public:
    PortraitNickNameClone(const std::shared_ptr<NativeRdb::RdbStore>& sourceRdb,
        const std::shared_ptr<NativeRdb::RdbStore>& destRdb,
        std::unordered_map<int32_t, int32_t> analysisAlbumIdMap, bool isCloudRestoreSatisfied);

    bool Clone();

    int64_t GetMigratedCount() const
    {
        return migratedCount_;
    }

    int64_t GetTotalTimeCost() const
    {
        return totalTimeCost_;
    }

private:
    bool IsReadyForClone() const;
    bool IsMappedPortraitAlbumReady(int32_t oldAlbumId) const;
    std::string BuildReadyPortraitAlbumSql() const;
    std::vector<PortraitNickNameRecord> QueryPortraitNickNameRecords(const std::string& albumIdClause) const;
    void ParsePortraitNickNameResultSet(const std::shared_ptr<NativeRdb::ResultSet>& resultSet,
        PortraitNickNameRecord& record) const;
    void RemapAlbumIds(std::vector<PortraitNickNameRecord>& records) const;
    void BatchInsertPortraitNickNameRecords(const std::vector<PortraitNickNameRecord>& records);
    NativeRdb::ValuesBucket CreateValuesBucket(const PortraitNickNameRecord& record) const;

private:
    std::shared_ptr<NativeRdb::RdbStore> sourceRdb_;
    std::shared_ptr<NativeRdb::RdbStore> destRdb_;
    std::unordered_map<int32_t, int32_t> analysisAlbumIdMap_;
    bool isCloudRestoreSatisfied_ = false;
    int64_t migratedCount_ = 0;
    int64_t totalTimeCost_ = 0;
};
} // namespace OHOS::Media

#endif // PORTRAIT_NICKNAME_CLONE_H
