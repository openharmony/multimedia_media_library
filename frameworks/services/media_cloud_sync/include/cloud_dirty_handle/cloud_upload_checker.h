/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_CLOUD_UPLOAD_CHECKER_H
#define OHOS_CLOUD_UPLOAD_CHECKER_H

#include <stdint.h>
#include <string>
#include <vector>

#include "rdb_predicates.h"

namespace OHOS {
namespace Media {
struct CheckedPhotoInfo {
    int32_t fileId;
    std::string path;
};

class CloudUploadChecker {
public:
    static void HandleNoOriginPhoto();
    static void RepairNoOriginButLcd();
    static void RepairNoDetailTime();

private:
    static int32_t GetPhotoCount(int32_t startFileId);
    static std::vector<CheckedPhotoInfo> QueryPhotoInfo(int32_t startFiled, int32_t &outFileId);
    static std::string GetQuerySql(int32_t startFileId, std::string mediaColumns);
    static void HandlePhotoInfos(std::vector<CheckedPhotoInfo>);
    static void UpdateDirty(std::vector<std::string> idList, int32_t dirtyType);
    static int32_t QueryLcdPhotoCount(int32_t startFileId);
    static void QueryLcdAndRepair(int32_t startFileId, int32_t &outFileId);
    static void RecordRepairIdList(const std::vector<int32_t>& repairedIdList);
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_CLOUD_UPLOAD_CHECKER_H
