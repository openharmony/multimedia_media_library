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
 
#ifndef OHOS_MEDIALIBRARY_DFX_REFRESH_HANDER_H
#define OHOS_MEDIALIBRARY_DFX_REFRESH_HANDER_H
 
 
#include <string>
#include <vector>
#include <mutex>
#include "dfx_refresh_manager.h"
#include "abs_rdb_predicates.h"
#include "medialibrary_command.h"
 
namespace OHOS {
namespace Media::AccurateRefresh {
#define EXPORT __attribute__ ((visibility ("default")))
 
 
class EXPORT DfxRefreshHander {
public:
    DfxRefreshHander();
    ~DfxRefreshHander();
    EXPORT static void SetOperationStartTimeHander(std::shared_ptr<DfxRefreshManager> dfxRefreshManager);
    EXPORT static void SetOptEndTimeHander(
        std::string tableName, std::shared_ptr<DfxRefreshManager> dfxRefreshManager);
    EXPORT static void SetOptEndTimeHander(
        MediaLibraryCommand &cmd, std::shared_ptr<DfxRefreshManager> dfxRefreshManager);
    EXPORT static void SetOptEndTimeHander(
        const NativeRdb::AbsRdbPredicates &predicates, std::shared_ptr<DfxRefreshManager> dfxRefreshManager);
    EXPORT static void SetAlbumIdAndOptTimeHander(
        int32_t albumId, bool isHidden, std::shared_ptr<DfxRefreshManager> dfxRefreshManager);
    EXPORT static void SetAlbumIdHander(int64_t albumId, std::shared_ptr<DfxRefreshManager> dfxRefreshManager);
    EXPORT static void SetAlbumIdHander(const std::vector<int> &albumIds,
        std::shared_ptr<DfxRefreshManager> dfxRefreshManager);
    EXPORT static void SetEndTimeHander(std::shared_ptr<DfxRefreshManager> dfxRefreshManager);
    EXPORT static void DfxRefreshReportHander(std::shared_ptr<DfxRefreshManager> dfxRefreshManager);
};
} // namespace Media
} // namespace OHOS
 
#endif  // OHOS_MEDIA_DFX_MANAGER_H