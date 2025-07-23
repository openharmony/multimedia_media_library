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

#ifndef OHOS_MEDIA_DFX_REFRESH_MANAGER_H
#define OHOS_MEDIA_DFX_REFRESH_MANAGER_H


#include <string>
#include <vector>
#include <mutex>
#include <map>
#include "medialibrary_command.h"
#include "abs_rdb_predicates.h"

namespace OHOS {
namespace Media::AccurateRefresh {
#define EXPORT __attribute__ ((visibility ("default")))

class EXPORT DfxRefreshManager {
public:
    DfxRefreshManager(){};
    DfxRefreshManager(const std::string &targetBusiness);

    EXPORT void SetOperationTotalTime(const std::string &tableName);
    EXPORT void SetOperationStartTime();
    EXPORT void SetOptEndTimeAndSql(std::string tableName);
    EXPORT void SetOptEndTimeAndSql(MediaLibraryCommand &cmd);
    EXPORT void SetOptEndTimeAndSql(const NativeRdb::AbsRdbPredicates &predicates);
    EXPORT void SetAlbumIdAndOptTime(int32_t albumId, bool isHidden);
    EXPORT void DfxRefreshReport();
    EXPORT void SetEndTotalTime();
    EXPORT void SetEndTime();
    EXPORT static void QueryStatementReport(
        const std::string &targetBusiness, int32_t totalCostTime, const std::string &sqlStr);
    std::string MapToJson(const std::unordered_map<int32_t, int32_t>& map);
    void SetStartTime();
    void SetAlbumId(int32_t albumId);
    void SetAlbumId(std::vector<int> albumIds);

private:
    int64_t startTime_ = 0;
    std::string sqlStr_;
    int32_t totalCostTime_ = 0;
    int64_t OperationStartTime_ = 0;
    int32_t photoOperationTotalTime_ = 0;
    int32_t albumOperationTotalTime_ = 0;
    std::unordered_set<int32_t> albumIds_;
    std::string targetBusiness_;
    std::unordered_map<int32_t, int32_t> albumOperationTime_;
    std::unordered_map<int32_t, int32_t> albumHiddenInfoOperationTime_;
    int64_t endTime_ = 0;
    bool isReport_ = false;
    bool isPrintLog_ = false;
};

} // namespace Media
} // namespace OHOS

#endif
