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

#ifndef MAP_CODE_UPLOAD_CHECKER_H
#define MAP_CODE_UPLOAD_CHECKER_H

#include "rdb_predicates.h"

#include <mutex>
#include <stdint.h>
#include <string>
#include <vector>

namespace OHOS {
namespace Media {
struct CheckedMapCodeInfo {
    int32_t fileId;
    double latitude;
    double longitude;
};

class MapCodeUploadChecker {
public:
    static bool RepairNoMapCodePhoto();

private:
    static void HandleMapCodePhoto();
    static std::vector<CheckedMapCodeInfo> QueryMapCodeInfo(int32_t startFileId);
    static void HandleMapCodeInfos(const std::vector<CheckedMapCodeInfo> &mapCodeInfos, int32_t &curFileId);
    static int32_t QueryMapCodeCount(int32_t startFileId);

private:
    static std::mutex mutex_;
};
}  // namespace Media
}  // namespace OHOS
#endif  // MAP_CODE_UPLOAD_CHECKER_H