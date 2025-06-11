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

#define MLOG_TAG "AccurateRefresh::AlbumRefreshExecution"

#include <sstream>

#include "album_refresh_execution.h"
#include "owner_album_info_calculation.h"
#include "cloud_enhancement_asset_helper.h"
#include "favorite_asset_helper.h"
#include "hidden_asset_helper.h"
#include "image_asset_helper.h"
#include "trash_asset_helper.h"
#include "video_asset_helper.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_unistore_manager.h"
#include "accurate_debug_log.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media::AccurateRefresh {

std::map<PhotoAlbumSubType, SystemAlbumInfoCalculation> AlbumRefreshExecution::systemAlbumCalculations_ = {
    { PhotoAlbumSubType::FAVORITE, { FavoriteAssetHelper::IsAsset, FavoriteAssetHelper::IsVideoAsset,
        FavoriteAssetHelper::IsHiddenAsset, FavoriteAssetHelper::IsNewerAsset,
        FavoriteAssetHelper::IsNewerHiddenAsset, PhotoAlbumSubType::FAVORITE }},
    { PhotoAlbumSubType::VIDEO, { VideoAssetHelper::IsAsset, VideoAssetHelper::IsVideoAsset,
        VideoAssetHelper::IsHiddenAsset, VideoAssetHelper::IsNewerAsset,
        VideoAssetHelper::IsNewerHiddenAsset, PhotoAlbumSubType::VIDEO }},
    { PhotoAlbumSubType::HIDDEN, { HiddenAssetHelper::IsAsset, HiddenAssetHelper::IsVideoAsset,
        HiddenAssetHelper::IsHiddenAsset, HiddenAssetHelper::IsNewerAsset,
        HiddenAssetHelper::IsNewerHiddenAsset, PhotoAlbumSubType::HIDDEN }},
    { PhotoAlbumSubType::TRASH, { TrashAssetHelper::IsAsset, TrashAssetHelper::IsVideoAsset,
        TrashAssetHelper::IsHiddenAsset, TrashAssetHelper::IsNewerAsset,
        TrashAssetHelper::IsNewerHiddenAsset, PhotoAlbumSubType::TRASH }},
    { PhotoAlbumSubType::IMAGE, { ImageAssetHelper::IsAsset, ImageAssetHelper::IsVideoAsset,
        ImageAssetHelper::IsHiddenAsset, ImageAssetHelper::IsNewerAsset,
        ImageAssetHelper::IsNewerHiddenAsset, PhotoAlbumSubType::IMAGE }},
    { PhotoAlbumSubType::CLOUD_ENHANCEMENT, { CloudEnhancementAssetHelper::IsAsset,
        CloudEnhancementAssetHelper::IsVideoAsset, CloudEnhancementAssetHelper::IsHiddenAsset,
        CloudEnhancementAssetHelper::IsNewerAsset, CloudEnhancementAssetHelper::IsNewerHiddenAsset,
        PhotoAlbumSubType::CLOUD_ENHANCEMENT }}
};

int32_t AlbumRefreshExecution::RefreshAlbum(const vector<PhotoAssetChangeData> &assetChangeDatas)
{
    // 初始化
    if (!albumRefresh_) {
        albumRefresh_ = make_shared<AlbumAccurateRefresh>();
    }
    // 计算影响相册和refresh info，结果放入systemAlbumInfos_和ownerAlbumInfos_
    CalAlbumsRefreshInfo(assetChangeDatas);

    // 相册执行逻辑只能串行执行
    lock_guard<mutex> lock(albumRefreshMtx_);

    // 计算相册信息
    CalRefreshAlbumInfos();

    // 更新相册
    RefreshAlbumInfos();

    return ACCURATE_REFRESH_RET_OK;
}

int32_t AlbumRefreshExecution::CalAlbumsRefreshInfo(const vector<PhotoAssetChangeData> &assetChangeDatas)
{
    // 计算系统相册信息
    for (auto &item : systemAlbumCalculations_) {
        for (auto const &assetChangeData : assetChangeDatas) {
            const PhotoAlbumSubType &subType = item.first;
            SystemAlbumInfoCalculation &calculation = item.second;
            auto subTypeInfoIter = systemAlbumInfos_.find(subType);
            if (subTypeInfoIter != systemAlbumInfos_.end()) {
                calculation.CalAlbumRefreshInfo(assetChangeData, subTypeInfoIter->second);
                continue;
            }
            AlbumRefreshInfo refreshInfo;
            if (calculation.CalAlbumRefreshInfo(assetChangeData, refreshInfo)) {
                systemAlbumInfos_.emplace(subType, refreshInfo);
                ACCURATE_DEBUG("add new subType: %{public}d, assetInfo before:%{public}s, after:%{public}s",
                    static_cast<int32_t> (subType), assetChangeData.infoBeforeChange_.ToString().c_str(),
                    assetChangeData.infoAfterChange_.ToString().c_str());
            }
        }
    }
    // 计算用户和来源相册
    ownerAlbumInfos_ = OwnerAlbumInfoCalculation::CalOwnerAlbumInfo(assetChangeDatas);
    ACCURATE_DEBUG("owner albums size: %{public}zu", ownerAlbumInfos_.size());
    if (IS_ACCURATE_DEBUG) {
        for (auto const &systemInfo : systemAlbumInfos_) {
            ACCURATE_INFO("subType: %{public}d, refreshInfo: %{public}s", systemInfo.first,
                systemInfo.second.ToString().c_str());
        }
        for (auto const &ownerInfo : ownerAlbumInfos_) {
            ACCURATE_INFO("albumId: %{public}d, refreshInfo: %{public}s", ownerInfo.first,
                ownerInfo.second.ToString().c_str());
        }
    }

    return ACCURATE_REFRESH_RET_OK;
}

int32_t AlbumRefreshExecution::CalRefreshAlbumInfos()
{
    // 查询相册数据
    albumRefresh_->Init(GetAlbumSubTypes(), GetOwnerAlbumIds());
    initAlbumInfos_ = albumRefresh_->GetInitAlbumInfos();
    if (initAlbumInfos_.empty()) {
        ACCURATE_DEBUG("empty album Info, insert.");
        return ACCURATE_REFRESH_RET_OK;
    }

    // 修改数据
    for (auto item : initAlbumInfos_) {
        auto &albumInfo = item.second;
        auto subType = albumInfo.albumSubType_;
        auto calAlbumInfoIter = systemAlbumInfos_.find(static_cast<PhotoAlbumSubType>(subType));
        AlbumRefreshInfo refreshInfo;
        
        if (calAlbumInfoIter == systemAlbumInfos_.end()) {
            auto albumId = albumInfo.albumId_;
            auto calOwnerAlbumInfoIter = ownerAlbumInfos_.find(albumId);
            if (calOwnerAlbumInfoIter == ownerAlbumInfos_.end()) {
                MEDIA_ERR_LOG("no album found");
                return ACCURATE_REFRESH_ALBUM_NO_MATCH;
            }
            refreshInfo = calOwnerAlbumInfoIter->second;
        } else {
            refreshInfo = calAlbumInfoIter->second;
        }
        auto albumInfoBefore = albumInfo;
        UpdateRefreshAlbumInfo(albumInfo, refreshInfo, subType);
        ACCURATE_INFO("before albumInfo: %{public}s", albumInfoBefore.ToString(true).c_str());
        ACCURATE_INFO("refresh info: %{public}s", refreshInfo.ToString().c_str());
        ACCURATE_INFO("after albumInfo: %{public}s", albumInfo.ToString(true).c_str());
    }

    return ACCURATE_REFRESH_RET_OK;
}

int32_t AlbumRefreshExecution::Notify()
{
    albumRefresh_->Notify();
    return ACCURATE_REFRESH_RET_OK;
}

vector<PhotoAlbumSubType> AlbumRefreshExecution::GetAlbumSubTypes()
{
    stringstream ss;
    ss << "GetAlbumSubTypes:";
    vector<PhotoAlbumSubType> systemTypes;
    for (auto const &item : systemAlbumInfos_) {
        systemTypes.push_back(item.first);
        ss << " " << item.first;
    }
    ACCURATE_DEBUG("%{public}s", ss.str().c_str());
    return systemTypes;
}

vector<int32_t> AlbumRefreshExecution::GetOwnerAlbumIds()
{
    stringstream ss;
    ss << "GetOwnerAlbumIds:";
    vector<int32_t> albumIds;
    for (auto const &item : ownerAlbumInfos_) {
        albumIds.push_back(item.first);
        ss << " " << item.first;
    }
    ACCURATE_DEBUG("%{public}s", ss.str().c_str());
    return albumIds;
}

int32_t AlbumRefreshExecution::RefreshAlbumInfos()
{
    for (auto &albumId : forceRefreshAlbums_) {
        // 封装刷新处理；全量刷新指定的相册（系统相册、用户相册、来源相册）
        ForceRefreshAlbumInfo(albumId, false);
    }

    for (auto &albumId : forceRefreshHiddenAlbums_) {
        // 封装刷新处理；全量刷新指定的隐藏相册
        ForceRefreshAlbumInfo(albumId, true);
    }

    RefreshAlbumInfo();
    
    return ACCURATE_REFRESH_RET_OK;
}

int32_t AlbumRefreshExecution::ForceRefreshAlbumInfo(int32_t albumId, bool isHidden)
{
    const auto &iter = initAlbumInfos_.find(albumId);
    if (iter == initAlbumInfos_.end()) {
        MEDIA_WARN_LOG("no album info.");
        return ACCURATE_REFRESH_ALBUM_INFO_NULL;
    }

    auto &albumInfo = iter->second;
    PhotoAlbumSubType subtype = static_cast<PhotoAlbumSubType>(albumInfo.albumSubType_);
    ValuesBucket values;
    GetUpdateValues(values, albumInfo, isHidden);
    if (values.IsEmpty()) {
        MEDIA_ERR_LOG("no need update.");
        return ACCURATE_REFRESH_RET_OK;
    }

    RdbPredicates predicates(PhotoAlbumColumns::TABLE);
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_SUBTYPE, to_string(subtype));
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, to_string(albumInfo.albumId_));
    int32_t changedRows = 0;

    albumRefresh_->Update(changedRows, values, predicates);
    ACCURATE_DEBUG("Update type: %{public}d, albumId: %{public}d, isHidden: %{public}d", albumInfo.albumSubType_,
        albumInfo.albumId_, isHidden);
    return ACCURATE_REFRESH_RET_OK;
}

int32_t AlbumRefreshExecution::GetUpdateValues(ValuesBucket &values, const AlbumChangeInfo &albumInfo, bool isHidden)
{
    PhotoAlbumSubType subtype = static_cast<PhotoAlbumSubType>(albumInfo.albumSubType_);
    struct UpdateAlbumData data;
    data.albumId = albumInfo.albumId_;
    data.hiddenCount = albumInfo.hiddenCount_;
    data.albumCount = albumInfo.count_;
    data.albumImageCount = albumInfo.imageCount_;
    data.albumVideoCount = albumInfo.videoCount_;
    data.hiddenCover = albumInfo.hiddenCoverUri_;
    data.albumCoverUri = albumInfo.coverUri_;
    data.coverDateTime = albumInfo.coverDateTime_;
    data.hiddenCoverDateTime = albumInfo.hiddenCoverDateTime_;
    ACCURATE_DEBUG("init albumInfo:%{public}s", albumInfo.ToString().c_str());
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore null");
        return ACCURATE_REFRESH_RDB_NULL;
    }

    return MediaLibraryRdbUtils::GetUpdateValues(rdbStore, data, values, subtype, isHidden);
}

int32_t AlbumRefreshExecution::RefreshAlbumInfo()
{
    for (auto &iter : refreshAlbums_) {
        auto &albumInfo = iter.second;
        ACCURATE_DEBUG("## Update type: %{public}d, albumId: %{public}d start", albumInfo.albumSubType_,
            albumInfo.albumId_);
        const auto &initIter = initAlbumInfos_.find(albumInfo.albumId_);
        if (initIter == initAlbumInfos_.end()) {
            MEDIA_WARN_LOG("no album info.");
            return ACCURATE_REFRESH_ALBUM_INFO_NULL;
        }

        auto &initAlbumInfo = initIter->second;
        ValuesBucket values = albumInfo.GetUpdateValues(initAlbumInfo);

        /***************************************************************************/
        if (forceRefreshAlbums_.find(albumInfo.albumId_) == forceRefreshAlbums_.end()) {
            CheckUpdateAlbumInfo(albumInfo, false);
        }
        if (forceRefreshHiddenAlbums_.find(albumInfo.albumId_) == forceRefreshHiddenAlbums_.end()) {
            CheckUpdateAlbumInfo(albumInfo, true);
        }
        /***************************************************************************/

        if (values.IsEmpty()) {
            MEDIA_ERR_LOG("no need update.");
            continue;
        }
        RdbPredicates predicates(PhotoAlbumColumns::TABLE);
        predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, to_string(albumInfo.albumId_));
        int32_t changedRows = 0;
        
        albumRefresh_->Update(changedRows, values, predicates);
        ACCURATE_DEBUG("## Update type: %{public}d, albumId: %{public}d end", albumInfo.albumSubType_,
            albumInfo.albumId_);
    }
    return ACCURATE_REFRESH_RET_OK;
}

void AlbumRefreshExecution::CheckUpdateAlbumInfo(const AlbumChangeInfo &albumInfo, bool isHidden)
{
    ValuesBucket values;
    GetUpdateValues(values, albumInfo, isHidden);
    if (values.IsEmpty()) {
        ACCURATE_INFO("album info success albumId[%{public}d], isHiden[%{public}d].", albumInfo.albumId_, isHidden);
        return;
    }
    stringstream ss;
    ValueObject value;
    if (isHidden) {
        int32_t hiddenCount;
        if (values.GetObject(PhotoAlbumColumns::HIDDEN_COUNT, value)) {
            value.GetInt(hiddenCount);
            ss << " hiddenCount: " << hiddenCount;
        }
        string hiddenCover;
        if (values.GetObject(PhotoAlbumColumns::HIDDEN_COVER, value)) {
            value.GetString(hiddenCover);
            ss << " hiddenCover: " << hiddenCover;
        }
        int64_t hiddenCoverDateTime;
        if (values.GetObject(PhotoAlbumColumns::HIDDEN_COVER_DATE_TIME, value)) {
            value.GetLong(hiddenCoverDateTime);
            ss << " hiddenCoverDateTime: " << hiddenCoverDateTime;
        }
        int32_t containHidden;
        if (values.GetObject(PhotoAlbumColumns::CONTAINS_HIDDEN, value)) {
            value.GetInt(containHidden);
            ss << " containHidden: " << containHidden;
        }
    } else {
        int32_t count;
        if (values.GetObject(PhotoAlbumColumns::ALBUM_COUNT, value)) {
            value.GetInt(count);
            ss << " count: " << count;
        }
        string cover;
        if (values.GetObject(PhotoAlbumColumns::ALBUM_COVER_URI, value)) {
            value.GetString(cover);
            ss << " cover: " << cover;
        }
        int64_t coverDateTime;
        if (values.GetObject(PhotoAlbumColumns::COVER_DATE_TIME, value)) {
            value.GetLong(coverDateTime);
            ss << " coverDateTime: " << coverDateTime;
        }

        int32_t videoCount;
        if (values.GetObject(PhotoAlbumColumns::ALBUM_VIDEO_COUNT, value)) {
            value.GetInt(videoCount);
            ss << " videoCount: " << videoCount;
        }

        int32_t imageCount;
        if (values.GetObject(PhotoAlbumColumns::ALBUM_IMAGE_COUNT, value)) {
            value.GetInt(imageCount);
            ss << " imageCount: " << imageCount;
        }
    }

    int64_t dateModified;
    if (values.GetObject(PhotoAlbumColumns::ALBUM_DATE_MODIFIED, value)) {
        value.GetLong(dateModified);
        ss << "dateModified: " << dateModified;
    }

    ACCURATE_INFO("album cal wrong, albumId[%{public}d], isHiden[%{public}d]: %{public}s", albumInfo.albumId_,
        isHidden, ss.str().c_str());
}

void AlbumRefreshExecution::UpdateAlbumCount(AlbumChangeInfo &albumInfo, const AlbumRefreshInfo &refreshInfo)
{
    // count 更新
    albumInfo.count_ += refreshInfo.deltaCount_;
    albumInfo.videoCount_ += refreshInfo.deltaVideoCount_;
    albumInfo.imageCount_ += (refreshInfo.deltaCount_ - refreshInfo.deltaVideoCount_);
    albumInfo.hiddenCount_ += refreshInfo.deltaHiddenCount_;
}

bool AlbumRefreshExecution::IsValidCover(const PhotoAssetChangeInfo &assetInfo)
{
    return assetInfo.fileId_ != INVALID_INT32_VALUE;
}

int32_t AlbumRefreshExecution::UpdateRefreshAlbumInfo(AlbumChangeInfo &albumInfo, const AlbumRefreshInfo &refreshInfo,
    int32_t subType)
{
    // 更新count
    UpdateAlbumCount(albumInfo, refreshInfo);
    // 更新uri、dateTimeForCover
    bool isRefreshAlbumCover = UpdateAlbumCover(albumInfo, refreshInfo, subType);
    bool isRefreshAlbumCount = refreshInfo.deltaCount_ != 0 || refreshInfo.deltaVideoCount_ !=0;
    bool needRefreshAblum = isRefreshAlbumCover ||
        (forceRefreshAlbums_.find(albumInfo.albumId_) == forceRefreshAlbums_.end() && isRefreshAlbumCount);

    // 更新hiddenCoverUri、dateTimeForHiddenCover
    bool isRefreshHiddenAlbumCover = UpdateAlbumHiddenCover(albumInfo, refreshInfo);
    bool isRefreshHiddenAlbumCount = refreshInfo.deltaHiddenCount_ != 0;
    bool needRefreshHiddenAlbum = isRefreshHiddenAlbumCover ||
        (forceRefreshHiddenAlbums_.find(albumInfo.albumId_) == forceRefreshHiddenAlbums_.end() &&
        isRefreshHiddenAlbumCount);
    if (needRefreshAblum || needRefreshHiddenAlbum) {
        refreshAlbums_.emplace(albumInfo.albumId_, albumInfo);
    }

    return ACCURATE_REFRESH_RET_OK;
}

bool AlbumRefreshExecution::UpdateAlbumCover(AlbumChangeInfo &albumInfo, const AlbumRefreshInfo &refreshInfo,
    int32_t subType)
{
    bool isRefreshAlbum = false;
    // 系统相册、用户、来源资产对比默认为date_taken
    auto dateTimeForAddCover = refreshInfo.deltaAddCover_.dateTakenMs_;
    auto dateTimeForRemoveCover = refreshInfo.deltaRemoveCover_.dateTakenMs_;
    if (subType == static_cast<int32_t>(PhotoAlbumSubType::VIDEO) ||
        subType == static_cast<int32_t>(PhotoAlbumSubType::IMAGE)) {
        // date_added
        dateTimeForAddCover = refreshInfo.deltaAddCover_.dateAddedMs_;
        dateTimeForRemoveCover = refreshInfo.deltaRemoveCover_.dateAddedMs_;
    } else if (subType == static_cast<int32_t>(PhotoAlbumSubType::HIDDEN)) {
        // hidden_time
        dateTimeForAddCover = refreshInfo.deltaAddCover_.hiddenTime_;
        dateTimeForRemoveCover = refreshInfo.deltaRemoveCover_.hiddenTime_;
    }

    // 普通cover 更新
    if (IsValidCover(refreshInfo.deltaAddCover_) && !IsValidCover(refreshInfo.deltaRemoveCover_)) { // 新增场景
        bool isRefresh = dateTimeForAddCover >= albumInfo.coverDateTime_;
        if (isRefresh) {
            albumInfo.coverInfo_ = refreshInfo.deltaAddCover_;
            albumInfo.coverDateTime_ = dateTimeForAddCover;
            // 更新coverUri
            albumInfo.coverUri_ = refreshInfo.deltaAddCover_.uri_;
            isRefreshAlbum = true;
        }
        ACCURATE_DEBUG("Add[%{public}d], refresh[%{public}d], albumInfo cover id: %{public}d, addCover id: %{public}d",
            albumInfo.albumId_, isRefresh, albumInfo.coverInfo_.fileId_, refreshInfo.deltaAddCover_.fileId_);
    } else if (!IsValidCover(refreshInfo.deltaAddCover_) && IsValidCover(refreshInfo.deltaRemoveCover_)) { // 删除场景
        // 当前cover没有removeCover新
        bool isForceRefresh = dateTimeForRemoveCover >= albumInfo.coverDateTime_;
        if (isForceRefresh) {
            forceRefreshAlbums_.insert(albumInfo.albumId_);
            ClearAlbumInfo(albumInfo);
        }
        ACCURATE_DEBUG(
            "Del[%{public}d], forceRefresh[%{public}d], time[%{public}" PRId64 ", %{public}" PRId64 "], \
            removeCover id:%{public}d", albumInfo.albumId_, isForceRefresh, dateTimeForRemoveCover,
            albumInfo.coverDateTime_, refreshInfo.deltaRemoveCover_.fileId_);
    } else if (IsValidCover(refreshInfo.deltaAddCover_) && IsValidCover(refreshInfo.deltaRemoveCover_)) {
        // 异常场景：同一个相册中cover既有新增又有删除;同一个相册中没有新增也没有删除
        // 全量刷新指定的系统相册
        forceRefreshAlbums_.insert(albumInfo.albumId_);
        ClearAlbumInfo(albumInfo);
        ACCURATE_ERR("Abnormal[%{public}d], forceRefresh, addCover: %{public}s, removeCover: %{public}s",
            albumInfo.albumId_, refreshInfo.deltaAddCover_.ToString().c_str(),
            refreshInfo.deltaRemoveCover_.ToString().c_str());
    }
    return isRefreshAlbum;
}

bool AlbumRefreshExecution::UpdateAlbumHiddenCover(AlbumChangeInfo &albumInfo, const AlbumRefreshInfo &refreshInfo)
{
    ACCURATE_DEBUG("albumInfo: %{public}s, hiddenCover: %{public}s, removeHiddenCover: %{public}s",
        albumInfo.ToString().c_str(), refreshInfo.deltaAddHiddenCover_.ToString().c_str(),
        refreshInfo.deltaRemoveHiddenCover_.ToString().c_str());
    bool isRefreshHiddenAlbum = false;
    if (IsValidCover(refreshInfo.deltaAddHiddenCover_) && !IsValidCover(refreshInfo.deltaRemoveHiddenCover_)) {
        // 新增场景
        bool isRefresh = refreshInfo.deltaAddHiddenCover_.hiddenTime_ >= albumInfo.hiddenCoverDateTime_;
        if (isRefresh) {
            albumInfo.hiddenCoverInfo_ = refreshInfo.deltaAddHiddenCover_;
            albumInfo.hiddenCoverDateTime_ = refreshInfo.deltaAddHiddenCover_.hiddenTime_;
            // 更新coverUri
            albumInfo.hiddenCoverUri_ = refreshInfo.deltaAddHiddenCover_.uri_;
            isRefreshHiddenAlbum = true;
        }
        ACCURATE_DEBUG("Add hidden[%{public}d], refresh[%{public}d] album hidden cover id[%{public}d, %{public}d]",
            albumInfo.albumId_, isRefresh, albumInfo.hiddenCoverInfo_.fileId_,
            refreshInfo.deltaAddHiddenCover_.fileId_);
    } else if (!IsValidCover(refreshInfo.deltaAddHiddenCover_) && IsValidCover(refreshInfo.deltaRemoveHiddenCover_)) {
        // 删除场景
        // 当前cover没有removeCover新
        bool isRefresh = refreshInfo.deltaRemoveHiddenCover_.hiddenTime_ >= albumInfo.hiddenCoverDateTime_;
        if (isRefresh) {
            forceRefreshHiddenAlbums_.insert(albumInfo.albumId_);
            ClearHiddenAlbumInfo(albumInfo);
        }
        ACCURATE_DEBUG("Del hidden[%{public}d], forceRefresh[%{public}d]", albumInfo.albumId_, isRefresh);
    } else if (IsValidCover(refreshInfo.deltaAddHiddenCover_) && IsValidCover(refreshInfo.deltaRemoveHiddenCover_)) {
        // 异常场景：同一个相册中cover既有新增又有删除
        // 全量刷新指定的系统相册
        forceRefreshHiddenAlbums_.insert(albumInfo.albumId_);
        ClearHiddenAlbumInfo(albumInfo);
        ACCURATE_DEBUG("Abnormal hidden[%{public}d], force: %{public}s, add/remove[%{public}s/%{public}s]",
            albumInfo.albumId_, albumInfo.ToString().c_str(), refreshInfo.deltaAddHiddenCover_.ToString().c_str(),
            refreshInfo.deltaRemoveHiddenCover_.ToString().c_str());
    }
    return isRefreshHiddenAlbum;
}

void AlbumRefreshExecution::ClearAlbumInfo(AlbumChangeInfo &albumInfo)
{
    albumInfo.imageCount_ = INVALID_INT32_VALUE;
    albumInfo.videoCount_ = INVALID_INT32_VALUE;
    albumInfo.count_ = INVALID_INT32_VALUE;
    albumInfo.coverUri_ = EMPTY_STR;
    albumInfo.coverDateTime_ = INVALID_INT64_VALUE;
}

void AlbumRefreshExecution::ClearHiddenAlbumInfo(AlbumChangeInfo &albumInfo)
{
    albumInfo.hiddenCount_ = INVALID_INT32_VALUE;
    albumInfo.hiddenCoverUri_ = EMPTY_STR;
    albumInfo.hiddenCoverDateTime_ = INVALID_INT64_VALUE;
}

} // namespace Media
} // namespace OHOS