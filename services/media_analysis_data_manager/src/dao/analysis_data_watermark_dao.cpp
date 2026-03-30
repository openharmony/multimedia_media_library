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

#include "analysis_data_watermark_dao.h"
#include "medialibrary_unistore_manager.h"
#include "vision_column.h"
#include "media_log.h"

namespace OHOS::Media::AnalysisData {
void AnalysisDataWatermarkDao::DeleteAnalysisWatermark(const std::string &fileId)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_LOG(rdbStore != nullptr, "Delete watermark failed, RdbStore is null");
    CHECK_AND_RETURN_LOG(!fileId.empty(), "Delete watermark failed, fileId is empty");

    const std::vector<NativeRdb::ValueObject> bindArgs = {fileId};
    std::string watermarkSql = DELETE_WATERMARK_STATUS_BY_FILE_ID;
    auto errCode = rdbStore->ExecuteSql(watermarkSql, bindArgs);
    CHECK_AND_RETURN_INFO_LOG(errCode == NativeRdb::E_OK,
        "Delete watermark table failed, fileId: %{public}s, errCode: %{public}d", fileId.c_str(), errCode);

    MEDIA_DEBUG_LOG("Delete watermark table success, fileId: %{public}s", fileId.c_str());
}
} // namespace OHOS::Media::AnalysisData