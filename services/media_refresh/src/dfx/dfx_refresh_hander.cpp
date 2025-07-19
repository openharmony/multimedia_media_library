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
 
#define MLOG_TAG "AccurateRefresh::DfxRefreshHander"
 
#include "dfx_refresh_hander.h"
#include "dfx_refresh_manager.h"
#include "media_log.h"
#include "photo_album_column.h"
 
using namespace std;
 
 
namespace OHOS {
namespace Media::AccurateRefresh {
DfxRefreshHander::DfxRefreshHander()
{}
DfxRefreshHander::~DfxRefreshHander()
{}

void DfxRefreshHander::SetOperationStartTimeHander(std::shared_ptr<DfxRefreshManager> dfxRefreshManager)
{
    if (dfxRefreshManager == nullptr) {
        return;
    }
    dfxRefreshManager->SetOperationStartTime();
}
 
void DfxRefreshHander::SetOptEndTimeHander(
    std::string tableName, std::shared_ptr<DfxRefreshManager> dfxRefreshManager)
{
    if (dfxRefreshManager == nullptr) {
        return;
    }
    dfxRefreshManager->SetOptEndTimeAndSql(tableName);
}
 
void DfxRefreshHander::SetOptEndTimeHander(
    MediaLibraryCommand &cmd, std::shared_ptr<DfxRefreshManager> dfxRefreshManager)
{
    if (dfxRefreshManager == nullptr) {
        return;
    }
    dfxRefreshManager->SetOptEndTimeAndSql(cmd);
}
 
void DfxRefreshHander::SetOptEndTimeHander(
    const NativeRdb::AbsRdbPredicates &predicates, std::shared_ptr<DfxRefreshManager> dfxRefreshManager)
{
    if (dfxRefreshManager == nullptr) {
        return;
    }
    dfxRefreshManager->SetOptEndTimeAndSql(predicates);
}
 
void DfxRefreshHander::SetAlbumIdAndOptTimeHander(
    int32_t albumId, bool isHidden, std::shared_ptr<DfxRefreshManager> dfxRefreshManager)
{
    if (dfxRefreshManager == nullptr) {
        return;
    }
    dfxRefreshManager->SetAlbumIdAndOptTime(albumId, isHidden);
}

void DfxRefreshHander::SetAlbumIdHander(int64_t albumId, std::shared_ptr<DfxRefreshManager> dfxRefreshManager)
{
    if (dfxRefreshManager == nullptr) {
        return;
    }
    dfxRefreshManager->SetAlbumId(albumId);
}

void DfxRefreshHander::SetAlbumIdHander(
    const std::vector<int> &albumIds, std::shared_ptr<DfxRefreshManager> dfxRefreshManager)
{
    if (dfxRefreshManager == nullptr) {
        return;
    }
    dfxRefreshManager->SetAlbumId(albumIds);
}

void DfxRefreshHander::SetEndTimeHander(std::shared_ptr<DfxRefreshManager> dfxRefreshManager)
{
    if (dfxRefreshManager == nullptr) {
        return;
    }
    dfxRefreshManager->SetEndTime();
}

void DfxRefreshHander::DfxRefreshReportHander(std::shared_ptr<DfxRefreshManager> dfxRefreshManager)
{
    if (dfxRefreshManager == nullptr) {
        return;
    }
    dfxRefreshManager->DfxRefreshReport();
}
 
}  // namespace Media::AccurateRefresh
}  // namespace OHOS