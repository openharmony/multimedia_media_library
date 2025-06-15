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

#define MLOG_TAG "AccurateRefresh::AlbumDataManager"

#include "album_data_manager.h"
#include "medialibrary_unistore_manager.h"
#include "accurate_debug_log.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media::AccurateRefresh {

int32_t AlbumDataManager::InitAlbumInfos(const std::vector<PhotoAlbumSubType> &systemTypes, const vector<int> &albumIds)
{
    if (systemTypes.empty() && albumIds.empty()) {
        MEDIA_WARN_LOG("systemTypes and albumIds empty.");
        return ACCURATE_REFRESH_INPUT_PARA_ERR;
    }

    vector<string> systemTypesStr;
    for (auto const &type : systemTypes) {
        systemTypesStr.push_back(to_string(static_cast<int> (type)));
    }

    auto initDatas = GetAlbumInfos(albumIds, systemTypesStr);
    if (initDatas.empty()) {
        MEDIA_WARN_LOG("initDatas empty.");
    } else {
        InsertInitChangeInfos(initDatas);
    }

    return ACCURATE_REFRESH_RET_OK;
}


int32_t AlbumDataManager::UpdateModifiedDatas()
{
    return ACCURATE_REFRESH_RET_OK;
}

int32_t AlbumDataManager::UpdateCommonModifiedDatas(const std::vector<int32_t> &keys)
{
    return ACCURATE_REFRESH_RET_OK;
}

int32_t AlbumDataManager::GetChangeInfoKey(const AlbumChangeInfo &changeInfo)
{
    return changeInfo.albumId_;
}

vector<AlbumChangeInfo> AlbumDataManager::GetInfoByKeys(const vector<int32_t> &albumIds)
{
    return GetAlbumInfos(albumIds);
}

vector<AlbumChangeInfo> AlbumDataManager::GetInfosByPredicates(const AbsRdbPredicates &predicates)
{
    shared_ptr<ResultSet> resultSet;
    if (trans_ != nullptr) {
        resultSet = trans_->QueryByStep(predicates, AlbumChangeInfo::GetAlbumInfoColumns());
    } else {
        auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
        CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, vector<AlbumChangeInfo>(), "rdbStore null");
        resultSet = rdbStore->QueryByStep(predicates, AlbumChangeInfo::GetAlbumInfoColumns());
    }
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, vector<AlbumChangeInfo>(), "resultSet null");
    
    // 根据resultSet转AlbumChangeInfo
    auto albumInfos = GetInfosByResult(resultSet);
    ACCURATE_DEBUG("GetInfosByPredicates size: %{public}zu", albumInfos.size());
    resultSet->Close();
    
    return albumInfos;
}

vector<AlbumChangeInfo> AlbumDataManager::GetInfosByResult(const shared_ptr<ResultSet> &resultSet)
{
    return AlbumChangeInfo::GetInfoFromResult(resultSet, AlbumChangeInfo::GetAlbumInfoColumns());
}

vector<AlbumChangeInfo> AlbumDataManager::GetAlbumInfos(const vector<int32_t> &albumIds,
    const vector<string> systemTypes)
{
    vector<AlbumChangeInfo> albumInfos;
    if (!systemTypes.empty()) {
        RdbPredicates predicates(PhotoAlbumColumns::TABLE);
        predicates.In(PhotoAlbumColumns::ALBUM_SUBTYPE, systemTypes);
        albumInfos = GetInfosByPredicates(predicates);
    }

    if (!albumIds.empty()) {
        vector<string> albumIdStrs;
        stringstream ss;
        for (auto const &albumId : albumIds) {
            albumIdStrs.push_back(to_string(static_cast<int> (albumId)));
            ss << " " << albumId;
        }
        ACCURATE_DEBUG("Insert key: %{public}s", ss.str().c_str());
        vector<AlbumChangeInfo> albumIdInfos;
        RdbPredicates predicates(PhotoAlbumColumns::TABLE);
        predicates.In(PhotoAlbumColumns::ALBUM_ID, albumIdStrs);
        albumIdInfos = GetInfosByPredicates(predicates);
        albumInfos.insert(albumInfos.end(), albumIdInfos.begin(), albumIdInfos.end());
    }
    return albumInfos;
}

map<int32_t, AlbumChangeInfo> AlbumDataManager::GetInitAlbumInfos()
{
    map<int32_t, AlbumChangeInfo> initAlbumInfos;
    for (auto &item : changeDatas_) {
        initAlbumInfos.emplace(item.first, item.second.infoBeforeChange_);
    }
    return initAlbumInfos;
}

vector<int32_t> AlbumDataManager::GetInitKeys()
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

} // namespace Media
} // namespace OHOS
