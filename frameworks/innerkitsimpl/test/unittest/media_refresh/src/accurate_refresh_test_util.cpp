/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define MLOG_TAG "accurate_refresh_test_util"
#include "accurate_refresh_test_util.h"
#include "result_set_utils.h"
#include "accurate_debug_log.h"

namespace OHOS {
namespace Media::AccurateRefresh {
using namespace std;
using namespace OHOS::NativeRdb;
ValuesBucket GetPhotoAlbumInsertValue(const AlbumChangeInfo &albumInfo)
{
    ValuesBucket value;
    value.PutInt(PhotoAlbumColumns::ALBUM_ID, albumInfo.albumId_);
    value.PutInt(PhotoAlbumColumns::ALBUM_TYPE, albumInfo.albumType_);
    value.PutInt(PhotoAlbumColumns::ALBUM_SUBTYPE, albumInfo.albumSubType_);
    value.PutInt(PhotoAlbumColumns::ALBUM_COUNT, albumInfo.count_);
    value.PutInt(PhotoAlbumColumns::ALBUM_IMAGE_COUNT, albumInfo.imageCount_);
    value.PutInt(PhotoAlbumColumns::ALBUM_VIDEO_COUNT, albumInfo.videoCount_);
    value.PutString(PhotoAlbumColumns::ALBUM_COVER_URI, albumInfo.coverUri_);
    value.PutInt(PhotoAlbumColumns::HIDDEN_COUNT, albumInfo.hiddenCount_);
    value.PutString(PhotoAlbumColumns::HIDDEN_COVER, albumInfo.hiddenCoverUri_);
    value.PutLong(PhotoAlbumColumns::COVER_DATE_TIME, albumInfo.coverDateTime_);
    value.PutLong(PhotoAlbumColumns::HIDDEN_COVER_DATE_TIME, albumInfo.hiddenCoverDateTime_);
    value.PutInt(PhotoAlbumColumns::ALBUM_DIRTY, albumInfo.dirty_);
    value.PutString(PhotoAlbumColumns::ALBUM_NAME, albumInfo.albumName_);
    return value;
}

ValuesBucket GetFavoriteInsertAlbum()
{
    return GetPhotoAlbumInsertValue(FAVORITE_ALBUM_INFO);
}

ValuesBucket GetHiddenInsertAlbum()
{
    return GetPhotoAlbumInsertValue(HIDDEN_ALBUM_INFO);
}

bool IsEqualAlbumInfo(const AlbumChangeInfo &albumInfo1, const AlbumChangeInfo &albumInfo2)
{
    ACCURATE_DEBUG("%{public}s", albumInfo1.ToString().c_str());
    ACCURATE_DEBUG("%{public}s", albumInfo2.ToString().c_str());
    return albumInfo1.albumId_ == albumInfo2.albumId_ && albumInfo1.albumType_ == albumInfo2.albumType_ &&
           albumInfo1.albumSubType_ == albumInfo2.albumSubType_ && albumInfo1.count_ == albumInfo2.count_ &&
           albumInfo1.imageCount_ == albumInfo2.imageCount_ && albumInfo1.videoCount_ == albumInfo2.videoCount_ &&
           albumInfo1.coverUri_ == albumInfo2.coverUri_ && albumInfo1.hiddenCount_ == albumInfo2.hiddenCount_ &&
           albumInfo1.hiddenCoverUri_ == albumInfo2.hiddenCoverUri_ &&
           albumInfo1.coverDateTime_ == albumInfo2.coverDateTime_ &&
           albumInfo1.hiddenCoverDateTime_ == albumInfo2.hiddenCoverDateTime_ && albumInfo1.dirty_ == albumInfo2.dirty_;
}

ValuesBucket GetTrashInsertAlbum()
{
    return GetPhotoAlbumInsertValue(TRASH_ALBUM_INFO);
}

ValuesBucket GetVideoInsertAlbum()
{
    return GetPhotoAlbumInsertValue(VIDEO_ALBUM_INFO);
}

ValuesBucket GetImageInsertAlbum()
{
    return GetPhotoAlbumInsertValue(IMAGE_ALBUM_INFO);
}

ValuesBucket GetCloudEnhancementInsertAlbum()
{
    return GetPhotoAlbumInsertValue(CLOUD_ENHANCEMENT_ALBUM_INFO);
}

AlbumChangeInfo GetUserInsertInfo(int32_t albumId)
{
    AlbumChangeInfo albumInfo = USER_ALBUM_INFO;
    albumInfo.albumId_ = albumId;
    albumInfo.albumUri_ = PhotoAlbumColumns::ALBUM_URI_PREFIX + to_string(albumId);
    return albumInfo;
}

ValuesBucket GetUserInsertAlbum(int32_t albumId)
{
    return GetPhotoAlbumInsertValue(GetUserInsertInfo(albumId));
}

AlbumChangeInfo GetSourceInsertInfo(int32_t albumId)
{
    AlbumChangeInfo albumInfo = SOURCE_ALBUM_INFO;
    albumInfo.albumId_ = albumId;
    albumInfo.albumUri_ = PhotoAlbumColumns::ALBUM_URI_PREFIX + to_string(albumId);
    return albumInfo;
}

ValuesBucket GetSourceInsertAlbum(int32_t albumId)
{
    return GetPhotoAlbumInsertValue(GetSourceInsertInfo(albumId));
}

int32_t GetAlbumCount(PhotoAlbumSubType subType, shared_ptr<MediaLibraryRdbStore> rdbStore)
{
    RdbPredicates queryPredicates(PhotoAlbumColumns::TABLE);
    queryPredicates.EqualTo(PhotoAlbumColumns::ALBUM_TYPE, to_string(PhotoAlbumType::SYSTEM));
    queryPredicates.EqualTo(PhotoAlbumColumns::ALBUM_SUBTYPE, to_string(subType));
    auto resultSet =
        rdbStore->QueryByStep(queryPredicates, {PhotoAlbumColumns::ALBUM_ID, PhotoAlbumColumns::ALBUM_COUNT});
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, 0, "resultSet nullptr");
    int32_t queryCount;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        auto queryAlbumId =
            get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_ID, resultSet, TYPE_INT32));
        queryCount =
            get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_COUNT, resultSet, TYPE_INT32));
        MEDIA_INFO_LOG("queryCount: %{public}d, queryAlbumId: %{public}d", queryCount, queryAlbumId);
    }
    resultSet->Close();
    return queryCount;
}

int32_t GetAlbumDirtyType(PhotoAlbumSubType subType, shared_ptr<MediaLibraryRdbStore> rdbStore)
{
    RdbPredicates queryPredicates(PhotoAlbumColumns::TABLE);
    queryPredicates.EqualTo(PhotoAlbumColumns::ALBUM_TYPE, to_string(PhotoAlbumType::SYSTEM));
    queryPredicates.EqualTo(PhotoAlbumColumns::ALBUM_SUBTYPE, to_string(subType));
    auto resultSet =
        rdbStore->QueryByStep(queryPredicates, {PhotoAlbumColumns::ALBUM_ID, PhotoAlbumColumns::ALBUM_DIRTY});
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, -1, "resultSet nullptr");
    int32_t dirtyType;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        auto queryAlbumId =
            get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_ID, resultSet, TYPE_INT32));
        dirtyType =
            get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_DIRTY, resultSet, TYPE_INT32));
        MEDIA_INFO_LOG("dirtyType: %{public}d, queryAlbumId: %{public}d", dirtyType, queryAlbumId);
    }
    resultSet->Close();
    return dirtyType;
}

AlbumChangeInfo GetAlbumInfo(PhotoAlbumSubType subType, shared_ptr<MediaLibraryRdbStore> rdbStore)
{
    RdbPredicates queryPredicates(PhotoAlbumColumns::TABLE);
    queryPredicates.EqualTo(PhotoAlbumColumns::ALBUM_TYPE, to_string(PhotoAlbumType::SYSTEM));
    queryPredicates.EqualTo(PhotoAlbumColumns::ALBUM_SUBTYPE, to_string(subType));
    auto resultSet = rdbStore->QueryByStep(queryPredicates, AlbumChangeInfo::GetAlbumInfoColumns());
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, AlbumChangeInfo(), "resultSet nullptr");
    auto albumInfos = AlbumChangeInfo::GetInfoFromResult(resultSet, AlbumChangeInfo::GetAlbumInfoColumns());
    if (albumInfos.size() == 1) {
        return albumInfos[0];
    }

    return AlbumChangeInfo();
}

AlbumChangeInfo GetAlbumInfo(int32_t albumId, std::shared_ptr<MediaLibraryRdbStore> rdbStore)
{
    RdbPredicates queryPredicates(PhotoAlbumColumns::TABLE);
    queryPredicates.EqualTo(PhotoAlbumColumns::ALBUM_ID, to_string(albumId));
    auto resultSet = rdbStore->QueryByStep(queryPredicates, AlbumChangeInfo::GetAlbumInfoColumns());
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, AlbumChangeInfo(), "resultSet nullptr");
    auto albumInfos = AlbumChangeInfo::GetInfoFromResult(resultSet, AlbumChangeInfo::GetAlbumInfoColumns());
    if (albumInfos.size() == 1) {
        return albumInfos[0];
    }

    return AlbumChangeInfo();
}

bool CheckAlbumChangeData(const AlbumChangeData &changeData, RdbOperation operation, const AlbumChangeInfo &infoBefore,
    const AlbumChangeInfo &infoAfter, bool isDelete)
{
    ACCURATE_DEBUG("operation_: %{public}d isDelete: %{public}d", changeData.operation_, changeData.isDelete_);
    ACCURATE_DEBUG("before: %{public}s", changeData.infoBeforeChange_.ToString().c_str());
    ACCURATE_DEBUG("after: %{public}s", changeData.infoAfterChange_.ToString().c_str());
    if (operation != RDB_OPERATION_UNDEFINED && changeData.operation_ != operation) {
        MEDIA_ERR_LOG("operation error (%{public}d/%{public}d)", changeData.operation_, operation);
        return false;
    }
    auto dmInfoBefore = changeData.infoBeforeChange_;
    ACCURATE_DEBUG("infoBefore: %{public}s", dmInfoBefore.ToString().c_str());
    if (!IsEqualAlbumInfo(dmInfoBefore, infoBefore)) {
        MEDIA_ERR_LOG("info before error");
        return false;
    }

    auto dmInfoAfter = changeData.infoAfterChange_;
    ACCURATE_DEBUG("dmInfoAfter: %{public}s", dmInfoAfter.ToString().c_str());
    if (!IsEqualAlbumInfo(dmInfoAfter, infoAfter)) {
        MEDIA_ERR_LOG("album info not expected.");
        return false;
    }

    if (changeData.isDelete_ != isDelete) {
        MEDIA_ERR_LOG("isDelete_ wrong.");
        return false;
    }

    return true;
}
}  // namespace Media::AccurateRefresh
}  // namespace OHOS