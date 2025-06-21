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
#include "medialibrary_notify.h"
#include "album_accurate_refresh_manager.h"
#include "medialibrary_data_manager_utils.h"
#include "media_file_utils.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media::AccurateRefresh {

mutex AlbumRefreshExecution::albumRefreshMtx_;

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

int32_t AlbumRefreshExecution::RefreshAlbum(const vector<PhotoAssetChangeData> &assetChangeDatas,
    NotifyAlbumType notifyAlbumType)
{
    // 计算影响相册和refresh info，结果放入systemAlbumInfos_和ownerAlbumInfos_
    CalRefreshInfos(assetChangeDatas);

    // 相册执行逻辑只能串行执行
    lock_guard<mutex> lock(albumRefreshMtx_);

    // 计算相册信息
    CalAlbumsInfos();

    // 更新相册
    UpdateAllAlbums(notifyAlbumType);

    return ACCURATE_REFRESH_RET_OK;
}

int32_t AlbumRefreshExecution::CalRefreshInfos(const vector<PhotoAssetChangeData> &assetChangeDatas)
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
            }
        }
    }
    // 计算用户和来源相册
    ownerAlbumInfos_ = OwnerAlbumInfoCalculation::CalOwnerAlbumInfo(assetChangeDatas);
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

int32_t AlbumRefreshExecution::CalAlbumsInfos()
{
    // 查询相册数据
    albumRefresh_.Init(GetAlbumSubTypes(), GetOwnerAlbumIds());
    initAlbumInfos_ = albumRefresh_.GetInitAlbumInfos();
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
        CalAlbumInfos(albumInfo, refreshInfo, subType);
        ACCURATE_INFO("before albumInfo: %{public}s", albumInfoBefore.ToString(true).c_str());
        ACCURATE_INFO("refresh info: %{public}s", refreshInfo.ToString().c_str());
        ACCURATE_INFO("after albumInfo: %{public}s", albumInfo.ToString(true).c_str());
    }

    return ACCURATE_REFRESH_RET_OK;
}

int32_t AlbumRefreshExecution::Notify()
{
    albumRefresh_.Notify();
    return ACCURATE_REFRESH_RET_OK;
}

vector<PhotoAlbumSubType> AlbumRefreshExecution::GetAlbumSubTypes()
{
    vector<PhotoAlbumSubType> systemTypes;
    for (auto const &item : systemAlbumInfos_) {
        systemTypes.push_back(item.first);
    }
    return systemTypes;
}

vector<int32_t> AlbumRefreshExecution::GetOwnerAlbumIds()
{
    vector<int32_t> albumIds;
    for (auto const &item : ownerAlbumInfos_) {
        albumIds.push_back(item.first);
    }
    return albumIds;
}

int32_t AlbumRefreshExecution::UpdateAllAlbums(NotifyAlbumType notifyAlbumType)
{
    for (auto &albumId : forceRefreshAlbums_) {
        // 封装刷新处理；全量刷新指定的相册（系统相册、用户相册、来源相册）
        ForceUpdateAlbums(albumId, false, notifyAlbumType);
    }

    for (auto &albumId : forceRefreshHiddenAlbums_) {
        // 封装刷新处理；全量刷新指定的隐藏相册
        ForceUpdateAlbums(albumId, true, notifyAlbumType);
    }

    AccurateUpdateAlbums(notifyAlbumType);
    return ACCURATE_REFRESH_RET_OK;
}

int32_t AlbumRefreshExecution::ForceUpdateAlbums(int32_t albumId, bool isHidden, NotifyAlbumType notifyAlbumType)
{
    const auto &iter = initAlbumInfos_.find(albumId);
    if (iter == initAlbumInfos_.end()) {
        MEDIA_WARN_LOG("no album info.");
        return ACCURATE_REFRESH_ALBUM_INFO_NULL;
    }

    auto &albumInfo = iter->second;
    PhotoAlbumSubType subtype = static_cast<PhotoAlbumSubType>(albumInfo.albumSubType_);
    ValuesBucket values;
    NotifyType type = NOTIFY_INVALID;
    GetUpdateValues(values, albumInfo, isHidden, type);
    if (values.IsEmpty()) {
        MEDIA_ERR_LOG("albumId[%{public}d], subType[%{public}d], hidden[%{public}d] no need update.", albumId, subtype,
            isHidden);
        return ACCURATE_REFRESH_RET_OK;
    }

    RdbPredicates predicates(PhotoAlbumColumns::TABLE);
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_SUBTYPE, to_string(subtype));
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, to_string(albumInfo.albumId_));
    int32_t changedRows = 0;
    auto ret = albumRefresh_.Update(changedRows, values, predicates);
    ACCURATE_DEBUG("Update[%{public}d, %{public}d] type: %{public}d, albumId: %{public}d, isHidden: %{public}d", ret,
        changedRows, albumInfo.albumSubType_, albumInfo.albumId_, isHidden);
    if (ret == ACCURATE_REFRESH_RET_OK) {
        CheckNotifyOldNotification(notifyAlbumType, albumInfo, type);
        AlbumAccurateRefreshManager::GetInstance().SetAlbumAccurateRefresh(albumInfo.albumId_, isHidden);
    } else {
        AlbumAccurateRefreshManager::GetInstance().RemoveAccurateRefreshAlbum(albumInfo.albumId_, isHidden);
    }

    return ACCURATE_REFRESH_RET_OK;
}

int32_t AlbumRefreshExecution::GetUpdateValues(ValuesBucket &values, const AlbumChangeInfo &albumInfo,
    bool isHidden, NotifyType &type)
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
    data.coverUriSource = albumInfo.coverUriSource_;
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore null");
        return ACCURATE_REFRESH_RDB_NULL;
    }
    type = data.albumCount < data.newTotalCount ? NOTIFY_ALBUM_ADD_ASSET :
        (data.albumCount > data.newTotalCount ? NOTIFY_ALBUM_REMOVE_ASSET : NOTIFY_UPDATE);
    return MediaLibraryRdbUtils::GetUpdateValues(rdbStore, data, values, subtype, isHidden);
}

int32_t AlbumRefreshExecution::AccurateUpdateAlbums(NotifyAlbumType notifyAlbumType)
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
        NotifyType type = NOTIFY_INVALID;
        ValuesBucket values = albumInfo.GetUpdateValues(initAlbumInfo, type);

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
        
        albumRefresh_.Update(changedRows, values, predicates);
        CheckNotifyOldNotification(notifyAlbumType, albumInfo, type);
        ACCURATE_DEBUG("## Update type: %{public}d, albumId: %{public}d end", albumInfo.albumSubType_,
            albumInfo.albumId_);
    }
    return ACCURATE_REFRESH_RET_OK;
}

void AlbumRefreshExecution::CheckHiddenAlbumInfo(ValuesBucket &values, stringstream &ss)
{
    int32_t hiddenCount;
    ValueObject value;
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
}

void AlbumRefreshExecution::CheckAlbumInfo(ValuesBucket &values, stringstream &ss)
{
    int32_t count;
    ValueObject value;
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

void AlbumRefreshExecution::CheckUpdateAlbumInfo(const AlbumChangeInfo &albumInfo, bool isHidden)
{
    ValuesBucket values;
    NotifyType type;
    GetUpdateValues(values, albumInfo, isHidden, type);
    if (values.IsEmpty()) {
        return;
    }
    stringstream ss;
    ValueObject value;
    if (isHidden) {
        CheckHiddenAlbumInfo(values, ss);
    } else {
        CheckAlbumInfo(values, ss);
    }

    int64_t dateModified;
    if (values.GetObject(PhotoAlbumColumns::ALBUM_DATE_MODIFIED, value)) {
        value.GetLong(dateModified);
        ss << "dateModified: " << dateModified;
    }

    ACCURATE_INFO("album cal wrong, albumId[%{public}d], isHiden[%{public}d]: %{public}s", albumInfo.albumId_,
        isHidden, ss.str().c_str());
}

bool AlbumRefreshExecution::CalAlbumHiddenCount(AlbumChangeInfo &albumInfo, const AlbumRefreshInfo &refreshInfo)
{
    albumInfo.hiddenCount_ += refreshInfo.deltaHiddenCount_;
    return refreshInfo.deltaHiddenCount_ != 0;
}

bool AlbumRefreshExecution::CalAlbumCount(AlbumChangeInfo &albumInfo, const AlbumRefreshInfo &refreshInfo)
{
    // count 更新
    albumInfo.count_ += refreshInfo.deltaCount_;
    albumInfo.videoCount_ += refreshInfo.deltaVideoCount_;
    albumInfo.imageCount_ += (refreshInfo.deltaCount_ - refreshInfo.deltaVideoCount_);
    return refreshInfo.deltaCount_ != 0 || refreshInfo.deltaVideoCount_ != 0;
}

bool AlbumRefreshExecution::IsValidCover(const PhotoAssetChangeInfo &assetInfo)
{
    return assetInfo.fileId_ != INVALID_INT32_VALUE;
}

bool AlbumRefreshExecution::CalAlbumInfos(AlbumChangeInfo &albumInfo, const AlbumRefreshInfo &refreshInfo,
    int32_t subType)
{
    bool needRefreshAblum = CalAlbumInfo(albumInfo, refreshInfo, subType);
    bool needRefreshHiddenAlbum = CalHiddenAlbumInfo(albumInfo, refreshInfo, subType);
    // 相册的普通信息和隐藏信息在同一个albumInfo中，只刷新其中一类信息时，另一类信息为无效值
    if (needRefreshAblum || needRefreshHiddenAlbum) {
        refreshAlbums_.emplace(albumInfo.albumId_, albumInfo);
        return true;
    }
    return false;
}

bool AlbumRefreshExecution::CalAlbumInfo(AlbumChangeInfo &albumInfo, const AlbumRefreshInfo &refreshInfo,
    int32_t subType)
{
    // 普通信息需要刷新 && 不能增量刷新
    if (refreshInfo.IsAlbumInfoRefresh() &&
        !AlbumAccurateRefreshManager::GetInstance().IsAlbumAccurateRefresh(albumInfo.albumId_, false)) {
        forceRefreshAlbums_.insert(albumInfo.albumId_);
        ClearAlbumInfo(albumInfo);
        ACCURATE_DEBUG("force update album[%{public}d] info", albumInfo.albumId_);
        return false;
    }

    // 更新count
    bool isRefreshAlbumCount = CalAlbumCount(albumInfo, refreshInfo);
    // 更新uri、dateTimeForCover
    bool isRefreshAlbumCover = CalAlbumCover(albumInfo, refreshInfo, subType);

    // 增量刷新场景：不强制刷新 && count/video count/cover无变化
    return forceRefreshAlbums_.find(albumInfo.albumId_) == forceRefreshAlbums_.end() &&
        (isRefreshAlbumCover || isRefreshAlbumCount);
}

bool AlbumRefreshExecution::CalHiddenAlbumInfo(AlbumChangeInfo &albumInfo, const AlbumRefreshInfo &refreshInfo,
    int32_t subType)
{
    // 隐藏信息需要刷新 && 不能增量刷新
    if (refreshInfo.IsAlbumHiddenInfoRefresh() &&
        !AlbumAccurateRefreshManager::GetInstance().IsAlbumAccurateRefresh(albumInfo.albumId_, true)) {
        forceRefreshHiddenAlbums_.insert(albumInfo.albumId_);
        ClearHiddenAlbumInfo(albumInfo);
        ACCURATE_DEBUG("force update album[%{public}d] hidden info", albumInfo.albumId_);
        return false;
    }
    bool isRefreshHiddenAlbumCount = CalAlbumHiddenCount(albumInfo, refreshInfo);
    // 更新hiddenCoverUri、dateTimeForHiddenCover
    bool isRefreshHiddenAlbumCover = CalAlbumHiddenCover(albumInfo, refreshInfo);
    
    // 增量刷新场景：不强制刷新 && hidden count/cover无变化
    return forceRefreshHiddenAlbums_.find(albumInfo.albumId_) ==
        forceRefreshHiddenAlbums_.end() && (isRefreshHiddenAlbumCover || isRefreshHiddenAlbumCount);
}

bool AlbumRefreshExecution::CheckCoverSet(AlbumChangeInfo &albumInfo, const AlbumRefreshInfo &refreshInfo,
    int32_t coverFileId)
{
    if (albumInfo.coverUriSource_ > 0) {
        if (refreshInfo.removeFileIds.find(coverFileId) != refreshInfo.removeFileIds.end()) {
            forceRefreshAlbums_.insert(albumInfo.albumId_);
            ClearAlbumInfo(albumInfo);
            ACCURATE_DEBUG("cover already set, refresh album for setcover.");
            return false;
        } else {
            ACCURATE_DEBUG("cover already set, no need cal album cover.");
            return false;
        }
    }
    return true;
}

bool AlbumRefreshExecution::CalAlbumCover(AlbumChangeInfo &albumInfo, const AlbumRefreshInfo &refreshInfo,
    int32_t subType)
{
    auto fileIdStr = MediaLibraryDataManagerUtils::GetFileIdFromPhotoUri(albumInfo.coverUri_);
    if (!MediaFileUtils::IsValidInteger(fileIdStr)) {
        ACCURATE_ERR("CalAlbumCover fileId err, albumInfo.coverUri:%{public}s", albumInfo.coverUri_.c_str());
        return false;
    }
    auto coverFileId = stoi(fileIdStr);
    if (!CheckCoverSet(albumInfo, refreshInfo, coverFileId)) {
        return false;
    }
    bool isRefreshAlbum = false;
    // 系统相册、用户、来源资产对比默认为date_taken
    auto dateTimeForAddCover = refreshInfo.deltaAddCover_.dateTakenMs_;
    if (subType == static_cast<int32_t>(PhotoAlbumSubType::VIDEO) ||
        subType == static_cast<int32_t>(PhotoAlbumSubType::IMAGE)) {
        // date_added
        dateTimeForAddCover = refreshInfo.deltaAddCover_.dateAddedMs_;
    } else if (subType == static_cast<int32_t>(PhotoAlbumSubType::HIDDEN)) {
        // hidden_time
        dateTimeForAddCover = refreshInfo.deltaAddCover_.hiddenTime_;
    }

    // 普通cover 更新
    if (IsValidCover(refreshInfo.deltaAddCover_) && refreshInfo.removeFileIds.size() == 0) { // 新增场景
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
    } else if (!IsValidCover(refreshInfo.deltaAddCover_) && refreshInfo.removeFileIds.size() > 0) { // 删除场景
        // 当前cover没有removeCover新
        bool isForceRefresh = refreshInfo.removeFileIds.find(coverFileId) != refreshInfo.removeFileIds.end();
        if (isForceRefresh) {
            forceRefreshAlbums_.insert(albumInfo.albumId_);
            ClearAlbumInfo(albumInfo);
        }
        ACCURATE_DEBUG(
            "Del[%{public}d], forceRefresh[%{public}d], old cover fileId[%{public}d]",
            albumInfo.albumId_, isForceRefresh, coverFileId);
    } else if (IsValidCover(refreshInfo.deltaAddCover_) && refreshInfo.removeFileIds.size() > 0) {
        // 异常场景：同一个相册中cover既有新增又有删除;同一个相册中没有新增也没有删除
        // 全量刷新指定的系统相册
        forceRefreshAlbums_.insert(albumInfo.albumId_);
        ClearAlbumInfo(albumInfo);
        ACCURATE_ERR("Abnormal[%{public}d], forceRefresh, addCover: %{public}s, remove size: %{public}zu",
            albumInfo.albumId_, refreshInfo.deltaAddCover_.ToString().c_str(),
            refreshInfo.removeFileIds.size());
    }
    return isRefreshAlbum;
}

bool AlbumRefreshExecution::CalAlbumHiddenCover(AlbumChangeInfo &albumInfo, const AlbumRefreshInfo &refreshInfo)
{
    ACCURATE_DEBUG("albumInfo: %{public}s, hiddenCover: %{public}s, remove Hidden size: %{public}zu",
        albumInfo.ToString().c_str(), refreshInfo.deltaAddHiddenCover_.ToString().c_str(),
        refreshInfo.removeHiddenFileIds.size());
    bool isRefreshHiddenAlbum = false;
    if (IsValidCover(refreshInfo.deltaAddHiddenCover_) && refreshInfo.removeHiddenFileIds.size() == 0) {
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
    } else if (!IsValidCover(refreshInfo.deltaAddHiddenCover_) && refreshInfo.removeHiddenFileIds.size() > 0) {
        // 删除场景
        // 当前cover没有removeCover新
        auto coverFileId = stoi(MediaLibraryDataManagerUtils::GetFileIdFromPhotoUri(albumInfo.hiddenCoverUri_));
        bool isRefresh = refreshInfo.removeHiddenFileIds.find(coverFileId) != refreshInfo.removeHiddenFileIds.end();
        if (isRefresh) {
            forceRefreshHiddenAlbums_.insert(albumInfo.albumId_);
            ClearHiddenAlbumInfo(albumInfo);
        }
        ACCURATE_DEBUG("Del hidden[%{public}d], forceRefresh[%{public}d], coverFileId[%{public}d]",
            albumInfo.albumId_, isRefresh, coverFileId);
    } else if (IsValidCover(refreshInfo.deltaAddHiddenCover_) && refreshInfo.removeHiddenFileIds.size() > 0) {
        // 异常场景：同一个相册中cover既有新增又有删除
        // 全量刷新指定的系统相册
        forceRefreshHiddenAlbums_.insert(albumInfo.albumId_);
        ClearHiddenAlbumInfo(albumInfo);
        ACCURATE_DEBUG("Abnormal hidden[%{public}d], force: %{public}s, add/remove[%{public}s/%{public}zu]",
            albumInfo.albumId_, albumInfo.ToString().c_str(), refreshInfo.deltaAddHiddenCover_.ToString().c_str(),
            refreshInfo.removeHiddenFileIds.size());
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

void AlbumRefreshExecution::CheckNotifyOldNotification(NotifyAlbumType notifyAlbumType,
    const AlbumChangeInfo &albumInfo, NotifyType type)
{
    if (notifyAlbumType == NotifyAlbumType::NO_NOTIFY || notifyAlbumType == NotifyAlbumType::ANA_ALBUM) {
        ACCURATE_DEBUG("no need old notification");
        return;
    }
    if (type == NotifyType::NOTIFY_INVALID) {
        ACCURATE_ERR("invalid notify type.");
        return;
    }

    if (albumInfo.albumSubType_ == static_cast<int32_t>(PhotoAlbumSubType::TRASH) ||
        albumInfo.albumSubType_ == static_cast<int32_t>(PhotoAlbumSubType::HIDDEN)) {
        ACCURATE_DEBUG("subtype[%{public}d] no need old notification.", albumInfo.albumId_);
        return;
    }

    auto watch = MediaLibraryNotify::GetInstance();
    if (watch == nullptr) {
        ACCURATE_ERR("watch nullptr no old notification");
        return;
    }
    bool needSystemNotify = notifyAlbumType & NotifyAlbumType::SYS_ALBUM;
    bool isSystemAlbum = albumInfo.albumType_ == static_cast<int32_t>(PhotoAlbumType::SYSTEM) &&
        (albumInfo.albumSubType_ == static_cast<int32_t>(PhotoAlbumSubType::FAVORITE) ||
        albumInfo.albumSubType_ == static_cast<int32_t>(PhotoAlbumSubType::VIDEO) ||
        albumInfo.albumSubType_ == static_cast<int32_t>(PhotoAlbumSubType::IMAGE) ||
        albumInfo.albumSubType_ == static_cast<int32_t>(PhotoAlbumSubType::CLOUD_ENHANCEMENT));

    bool needUserNotify = notifyAlbumType & NotifyAlbumType::USER_ALBUM;
    bool isUserAlbum = albumInfo.albumType_ == static_cast<int32_t>(PhotoAlbumType::USER) &&
        albumInfo.albumSubType_ == static_cast<int32_t>(PhotoAlbumSubType::USER_GENERIC);

    bool needSourceNotify = notifyAlbumType & NotifyAlbumType::SOURCE_ALBUM;
    bool isSourceAlbum = albumInfo.albumType_ == static_cast<int32_t>(PhotoAlbumType::SOURCE) &&
        albumInfo.albumSubType_ == static_cast<int32_t>(PhotoAlbumSubType::SOURCE_GENERIC);

    bool needNotify = (needSystemNotify && isSystemAlbum) || (needUserNotify && isUserAlbum)
        || (needSourceNotify && isSourceAlbum);
    if (needNotify) {
        watch->Notify(PhotoColumn::PHOTO_URI_PREFIX, type, albumInfo.albumId_);
        ACCURATE_DEBUG("old notification: type[%{public}d], albumId[%{public}d], notifyAlbumType[0x%{public}x]",
            type, albumInfo.albumId_, notifyAlbumType);
    } else {
        ACCURATE_DEBUG("no notification albumType[%{public}d], subType[%{public}d], notifyAlbumType[0x%{public}x]",
            albumInfo.albumType_, albumInfo.albumSubType_, notifyAlbumType);
    }
}
} // namespace Media
} // namespace OHOS