/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "analysis_album_batch_update_helper.h"

#include "media_log.h"
#include "photo_album_column.h"
#include "userfile_manager_types.h"
#include "vision_column.h"

namespace OHOS {
namespace Media {
namespace AccurateRefresh {

const std::string IS_COVER_SATISFIED = "is_cover_satisfied";

// 内部规则，无需暴露
struct FieldRule {
    std::string column;
    std::function<bool(const BatchUpdateItem&)> needUpdate;
    std::function<void(const BatchUpdateItem&, std::string&, std::vector<NativeRdb::ValueObject>&)> applySql;
};

// 字段规则全部放在 cpp 内，集中管理
static const FieldRule COUNT_RULE = {
    PhotoAlbumColumns::ALBUM_COUNT,
    [](const BatchUpdateItem &item) {
        return item.shouldUpdateCount;
    },
    [](const BatchUpdateItem &item, std::string &sql, std::vector<NativeRdb::ValueObject>&) {
        sql += "WHEN " + std::to_string(item.albumId) +
            " THEN " + std::to_string(item.newCount) + " ";
    }
};

static const FieldRule COVER_RULE = {
    PhotoAlbumColumns::ALBUM_COVER_URI,
    [](const BatchUpdateItem &item) {
        return item.shouldUpdateCover;
    },
    [](const BatchUpdateItem &item, std::string &sql, std::vector<NativeRdb::ValueObject> &bindArgs) {
        sql += "WHEN " + std::to_string(item.albumId) + " THEN ? ";
        bindArgs.emplace_back(item.newCover);
    }
};

static const FieldRule COVER_SATISFIED_RULE = {
    IS_COVER_SATISFIED,
    [](const BatchUpdateItem &item) {
        return item.shouldUpdateCover &&
            (item.albumSubType == PhotoAlbumSubType::PORTRAIT || item.albumSubType == PhotoAlbumSubType::GROUP_PHOTO);
    },
    [](const BatchUpdateItem &item, std::string &sql, std::vector<NativeRdb::ValueObject> &bindArgs) {
        sql += "WHEN " + std::to_string(item.albumId) +
            " THEN " + std::to_string(static_cast<int32_t>(CoverSatisfiedType::DEFAULT_SETTING)) + " ";
    }
};

static const std::vector<FieldRule> UPDATE_RULES = {
    COUNT_RULE,
    COVER_RULE,
    COVER_SATISFIED_RULE
};

bool AnalysisAlbumBatchUpdateHelper::BuildCaseSql(const std::vector<BatchUpdateItem>& items, std::string& sql,
    vector<NativeRdb::ValueObject>& bindArgs)
{
    CHECK_AND_RETURN_RET_LOG(!items.empty(), false, "Invalid input items");

    std::stringstream setSql;
    bool isFirstField = true;
    std::unordered_set<int32_t> idSet;

    for (const auto& rule : UPDATE_RULES) {
        std::string caseSql = "CASE album_id ";
        bool hasUpdateValue = false;
        std::unordered_set<int32_t> ruleAlbumSet;

        for (const auto& item : items) {
            CHECK_AND_CONTINUE(rule.needUpdate(item));
            CHECK_AND_CONTINUE(ruleAlbumSet.insert(item.albumId).second);
            hasUpdateValue = true;
            rule.applySql(item, caseSql, bindArgs);
            idSet.insert(item.albumId);
        }

        CHECK_AND_CONTINUE(hasUpdateValue);
        caseSql += "ELSE " + rule.column + " ";
        caseSql += "END";
        setSql << (isFirstField ? "" : ", ") << rule.column << "=" << caseSql;
        isFirstField = false;
    }
    CHECK_AND_RETURN_RET_LOG(!isFirstField, false, "No field to update");

    // idList赋值时会携带",", 需要消除最后一个",""
    std::stringstream idList;
    for (int32_t id : idSet) {
        idList << id << ",";
    }
    std::string ids = idList.str();
    CHECK_AND_RETURN_RET_LOG(!ids.empty(), false, "No valid albumId");
    ids.pop_back();

    sql = "UPDATE " + ANALYSIS_ALBUM_TABLE + " SET " + setSql.str() +
        " WHERE " + PhotoAlbumColumns::ALBUM_ID + " IN (" + ids + ")";
    return true;
}

} // namespace AccurateRefresh
} // namespace Media
} // namespace OHOS::Media::AccurateRefresh
