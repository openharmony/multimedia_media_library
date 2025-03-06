/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_FOREGROUND_ANALYSIS_META_H
#define OHOS_MEDIA_FOREGROUND_ANALYSIS_META_H

#include <string>

#include "abs_shared_result_set.h"
#include "datashare_predicates.h"
#include "medialibrary_async_worker.h"
#include "medialibrary_command.h"

namespace OHOS::Media {
enum ForegroundAnalysisOpType : int32_t {
    FOREGROUND_NOT_HANDLE = 0,
    OCR_AND_LABEL = 0X01,
    SEARCH_INDEX = 0X02
};

static constexpr const char *FOREGROUND_ANALYSIS_TYPE = "foreground_analysis_type";
static constexpr const char *FOREGROUND_ANALYSIS_TASK_ID = "foreground_analysis_task_id";
class ForegroundAnalysisMeta {
public:
    ForegroundAnalysisMeta() = default;
    ForegroundAnalysisMeta(std::shared_ptr<NativeRdb::ResultSet> result);
    ~ForegroundAnalysisMeta();
    int32_t GenerateOpType(MediaLibraryCommand &cmd);
    void StartAnalysisService();

    static int32_t GetIncTaskId()
    {
        static std::atomic<int32_t> incTaskId {1};
        return incTaskId.fetch_add(1, std::memory_order_relaxed);
    }

private:
    bool IsMetaDirtyed();
    int32_t RefreshMeta();
    int32_t CheckCvAnalysisCondition(MediaLibraryCommand &cmd);
    int32_t CheckIndexAnalysisCondition(MediaLibraryCommand &cmd);
    int32_t QueryPendingAnalyzeFileIds(MediaLibraryCommand &cmd, std::vector<std::string> &fileIds);
    int32_t QueryPendingIndexCount(MediaLibraryCommand &cmd, int32_t &count);
    void AppendAnalysisTypeOnWhereClause(int32_t type, std::string &whereClause);
    int32_t GetCurTaskId(MediaLibraryCommand &cmd);

    int frontIndexLimit_ = 0;
    int64_t frontIndexModified_ = 0L;
    int frontIndexCount_ = 0;
    int64_t frontCvModified_ = 0L;
    int frontCvCount_ = 0;
    bool isInit_ = false;
    int32_t opType_ = ForegroundAnalysisOpType::FOREGROUND_NOT_HANDLE;
    std::vector<std::string> fileIds_;
    int32_t taskId_ = -1;
};
} // namespace OHOS::Media
#endif // OHOS_MEDIA_FOREGROUND_ANALYSIS_META_H