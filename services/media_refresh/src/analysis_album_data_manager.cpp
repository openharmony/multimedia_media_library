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

#define MLOG_TAG "AccurateRefresh::AnalysisAlbumDataManager"

#include "analysis_album_data_manager.h"

#include "accurate_debug_log.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_tracer.h"
#include "media_file_utils.h"
#include "vision_column.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
namespace AccurateRefresh {

int32_t AnalysisAlbumDataManager::UpdateModifiedDatas()
{
    return ACCURATE_REFRESH_RET_OK;
}

int32_t AnalysisAlbumDataManager::PostProcessModifiedDatas(const std::vector<int32_t> &keys)
{
    MediaLibraryTracer tracer;
    tracer.Start("AnalysisAlbumDataManager::PostProcessModifiedDatas");
    for (auto &key : keys) {
        auto item = changeDatas_.find(key);
        if (item == changeDatas_.end()) {
            MEDIA_WARN_LOG("no data, albumId[%{public}d].", key);
            continue;
        }
        auto &before = item->second.infoBeforeChange_;
        auto &after = item->second.infoAfterChange_;
        // 更新cover相关信息
        if (before.coverUri_ != after.coverUri_) {
            after.isCoverChange_ = true;
        }
    }
    return ACCURATE_REFRESH_RET_OK;
}

vector<int32_t> AnalysisAlbumDataManager::GetInitKeys()
{
    stringstream ss;
    ss << "GetInitKeys:";
    vector<int32_t> albumIds;
    for (auto &changeData : changeDatas_) {
        albumIds.push_back(changeData.first);
        ss << " " << changeData.first;
    }

    ACCURATE_DEBUG("%{public}s", ss.str().c_str());
    return albumIds;
}

int32_t AnalysisAlbumDataManager::GetChangeInfoKey(const AlbumChangeInfo &changeInfo)
{
    return changeInfo.albumId_;
}

bool AnalysisAlbumDataManager::CheckIsForRecheck()
{
    return isForRecheck_ || CheckIsExceed();
}

vector<AlbumChangeInfo> AnalysisAlbumDataManager::GetInfoByKeys(const vector<int32_t> &albumIds)
{
    vector<AlbumChangeInfo> albumInfos;
    if (albumIds.empty()) {
        MEDIA_WARN_LOG("AlbumIds input is empty.");
        return albumInfos;
    }
    vector<string> albumIdStrs;
    for (auto const &albumId : albumIds) {
        albumIdStrs.push_back(to_string(static_cast<int> (albumId)));
    }
    vector<AlbumChangeInfo> albumIdInfos;
    RdbPredicates predicates(ANALYSIS_ALBUM_TABLE);
    predicates.In(PhotoAlbumColumns::ALBUM_ID, albumIdStrs);
    albumInfos = GetInfosByPredicates(predicates);
    return albumInfos;
}

vector<AlbumChangeInfo> AnalysisAlbumDataManager::GetInfosByPredicates(const AbsRdbPredicates &predicates)
{
    MediaLibraryTracer tracer;
    tracer.Start("AnalysisAlbumDataManager::GetInfosByPredicates");
    shared_ptr<ResultSet> resultSet;
    if (CanTransOperate()) {
        resultSet = trans_->QueryByStep(predicates, AlbumChangeInfo::GetAnalysisAlbumInfoColumns());
    } else {
        auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
        CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, vector<AlbumChangeInfo>(), "rdbStore null");
        resultSet = rdbStore->QueryByStep(predicates, AlbumChangeInfo::GetAnalysisAlbumInfoColumns());
    }
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, vector<AlbumChangeInfo>(), "resultSet null");
    
    // 根据resultSet转AlbumChangeInfo
    auto albumInfos = GetInfosByResult(resultSet);
    resultSet->Close();
    
    return albumInfos;
}

vector<AlbumChangeInfo> AnalysisAlbumDataManager::GetInfosByResult(const shared_ptr<ResultSet> &resultSet)
{
    return AlbumChangeInfo::GetAnalysisAlbumInfoFromResult(resultSet);
}

void AnalysisAlbumDataManager::ClearChangeDatas()
{
    this->changeDatas_.clear();
}

int32_t AnalysisAlbumDataManager::SetAlbumIdsByPredicates(const AbsRdbPredicates &predicates)
{
    // 直接更新操作相册，无需保存存相册id
    return NativeRdb::E_OK;
}

int32_t AnalysisAlbumDataManager::SetAlbumIdsBySql(const std::string &sql,
    const std::vector<ValueObject> &bindArgs)
{
    // 直接更新操作相册，无需保存存相册id
    return NativeRdb::E_OK;
}

int32_t AnalysisAlbumDataManager::SetAlbumIdsByFileds(const std::vector<int32_t> &fileIds)
{
    // 直接更新操作相册，无需保存存相册id
    return NativeRdb::E_OK;
}

// 暂时无需超限处理逻辑
bool AnalysisAlbumDataManager::CheckIsExceed(bool isLengthChanged)
{
    if (!isLengthChanged) {
        return isExceed_;
    }

    if (isExceed_) {
        return true;
    }

    isExceed_ = this->changeDatas_.size() >= MAX_DATA_LENGTH;
    if (isExceed_) {
        this->changeDatas_.clear();
    }
    return isExceed_;
};

bool AnalysisAlbumDataManager::CheckIsExceed(const AbsRdbPredicates &predicates, bool isLengthChanged)
{
    return CheckIsExceed(isLengthChanged);
};

bool AnalysisAlbumDataManager::CheckIsExceed(const string &sql,
    const vector<ValueObject> &bindArgs, bool isLengthChanged)
{
    return CheckIsExceed(isLengthChanged);
};

bool AnalysisAlbumDataManager::CheckIsExceed(size_t length)
{
    if (length >= MAX_DATA_LENGTH) {
        isExceed_ = true;
        this->changeDatas_.clear();
    }
    return isExceed_;
}

bool AnalysisAlbumDataManager::CheckIsExceed(const vector<int32_t> &keys)
{
    if (keys.size() >= MAX_DATA_LENGTH) {
        isExceed_ = true;
        this->changeDatas_.clear();
    }
    return isExceed_;
}

} // namespace AccurateRefresh
} // namespace Media
} // namespace OHOS
