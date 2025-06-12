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

#define MLOG_TAG "AccurateRefresh::AssetDataManager"

#include <sstream>

#include "asset_data_manager.h"
#include "medialibrary_unistore_manager.h"
#include "accurate_debug_log.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media::AccurateRefresh {

int32_t AssetDataManager::UpdateModifiedDatas()
{
    return ACCURATE_REFRESH_RET_OK;
}

int32_t AssetDataManager::GetChangeInfoKey(const PhotoAssetChangeInfo &changeInfo)
{
    return changeInfo.fileId_;
}

std::vector<PhotoAssetChangeInfo> AssetDataManager::GetInfoByKeys(const std::vector<int32_t> &fileIds)
{
    AbsRdbPredicates rbdPredicates(PhotoColumn::PHOTOS_TABLE);
    vector<string> fileIdStrs;
    for (const auto &fileId : fileIds) {
        fileIdStrs.push_back(to_string(fileId));
        ACCURATE_DEBUG("fileId: %{public}d", fileId);
    }
    rbdPredicates.In(PhotoColumn::MEDIA_ID, fileIdStrs);
    return GetInfosByPredicates(rbdPredicates);
}

vector<PhotoAssetChangeInfo> AssetDataManager::GetInfosByPredicates(const AbsRdbPredicates &predicates)
{
    shared_ptr<ResultSet> resultSet;
    if (trans_ != nullptr) {
        resultSet = trans_->QueryByStep(predicates, PhotoAssetChangeInfo::GetPhotoAssetClolumns());
    } else {
        auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
        CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, vector<PhotoAssetChangeInfo>(), "rdbStore null");
        resultSet = rdbStore->QueryByStep(predicates, PhotoAssetChangeInfo::GetPhotoAssetClolumns());
    }
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, vector<PhotoAssetChangeInfo>(), "resultSet null");

    ACCURATE_DEBUG("start");
    auto ret = GetInfosByResult(resultSet);
    ACCURATE_DEBUG("end, size:%{public}zu", ret.size());
    resultSet->Close();
    return ret;
}

vector<PhotoAssetChangeInfo> AssetDataManager::GetInfosByResult(const shared_ptr<ResultSet> &resultSet)
{
    // 根据resultSet转PhotoAssetChangeInfo
    return PhotoAssetChangeInfo::GetInfoFromResult(resultSet, PhotoAssetChangeInfo::GetPhotoAssetClolumns());
}

vector<int32_t> AssetDataManager::GetInitKeys()
{
    stringstream ss;
    ss << "GetInitKeys:";
    vector<int32_t> fileIds;
    for (auto &changeData : changeDatas_) {
        fileIds.push_back(changeData.first);
        ss << " " << changeData.first;
    }

    ACCURATE_DEBUG("%{public}s", ss.str().c_str());
    return fileIds;
}

int32_t AssetDataManager::SetContentChanged(int32_t fileId, bool isChanged)
{
    auto iter = contentInfos.find(fileId);
    if (iter == contentInfos.end()) {
        PhotoAssetContentInfo contentInfo;
        contentInfo.isContentChanged_ = isChanged;
        contentInfos.emplace(fileId, contentInfo);
        ACCURATE_DEBUG("add fileId: %{public}d, isChanged %{public}d", fileId, isChanged);
    } else {
        iter->second.isContentChanged_ = isChanged;
        ACCURATE_DEBUG("update fileId: %{public}d, isChanged %{public}d", fileId, isChanged);
    }
    return ACCURATE_REFRESH_RET_OK;
}

int32_t AssetDataManager::SetThumbnailStatus(int32_t fileId, int32_t status)
{
    auto iter = contentInfos.find(fileId);
    if (iter == contentInfos.end()) {
        PhotoAssetContentInfo contentInfo;
        contentInfo.thumbnailChangeStatus_ = status;
        contentInfos.emplace(fileId, contentInfo);
        ACCURATE_DEBUG("add fileId: %{public}d, status: %{public}d", fileId, status);
    } else {
        iter->second.thumbnailChangeStatus_ = status;
        ACCURATE_DEBUG("update fileId: %{public}d, status: %{public}d", fileId, status);
    }
    return ACCURATE_REFRESH_RET_OK;
}

int32_t AssetDataManager::UpdateNotifyInfo()
{
    for (auto const &contentInfo : contentInfos) {
        auto fileId = contentInfo.first;
        const PhotoAssetContentInfo &content = contentInfo.second;
        auto iter = changeDatas_.find(fileId);
        if (iter == changeDatas_.end()) {
            MEDIA_ERR_LOG("no changeDatas: %{public}d.", fileId);
            continue;
        }
        iter->second.isContentChanged_ = content.isContentChanged_;
        iter->second.thumbnailChangeStatus_ = content.thumbnailChangeStatus_;
        ACCURATE_DEBUG("update fileId:%{public}d, content(%{public}d, %{public}d)", fileId, content.isContentChanged_,
            content.thumbnailChangeStatus_);
    }
    return ACCURATE_REFRESH_RET_OK;
}

} // namespace Media
} // namespace OHOS
