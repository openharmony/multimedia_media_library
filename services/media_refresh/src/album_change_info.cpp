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

#define MLOG_TAG "AccurateRefresh::AlbumChangeInfo"

#include <sstream>

#include "album_change_info.h"
#include "result_set_utils.h"
#include "media_file_utils.h"
#include "accurate_debug_log.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media::AccurateRefresh {

const map<std::string, ResultSetDataType> AlbumChangeInfo::albumInfoCloumnTypes_ = {
    { PhotoAlbumColumns::ALBUM_LPATH, TYPE_STRING },
    { PhotoAlbumColumns::ALBUM_IMAGE_COUNT, TYPE_INT32 },
    { PhotoAlbumColumns::ALBUM_VIDEO_COUNT, TYPE_INT32 },
    { PhotoAlbumColumns::ALBUM_TYPE, TYPE_INT32 },
    { PhotoAlbumColumns::ALBUM_SUBTYPE, TYPE_INT32 },
    { PhotoAlbumColumns::ALBUM_NAME, TYPE_STRING },
    { PhotoAlbumColumns::ALBUM_COUNT, TYPE_INT32 },
    { PhotoAlbumColumns::ALBUM_COVER_URI, TYPE_STRING },
    { PhotoAlbumColumns::HIDDEN_COUNT, TYPE_INT32 },
    { PhotoAlbumColumns::HIDDEN_COVER, TYPE_STRING },
    { PhotoAlbumColumns::ALBUM_ID, TYPE_INT32 },
    { PhotoAlbumColumns::COVER_DATE_TIME, TYPE_INT64 },
    { PhotoAlbumColumns::HIDDEN_COVER_DATE_TIME, TYPE_INT64 },
    { PhotoAlbumColumns::ALBUM_DIRTY, TYPE_INT32 },
};

vector<std::string> AlbumChangeInfo::albumInfoColumns_;

const std::vector<std::string>& AlbumChangeInfo::GetAlbumInfoColumns()
{
    if (albumInfoColumns_.empty()) {
        for (const auto &item : albumInfoCloumnTypes_) {
            albumInfoColumns_.push_back(item.first);
        }
    }
    return albumInfoColumns_;
}

vector<AlbumChangeInfo> AlbumChangeInfo::GetInfoFromResult(
    const shared_ptr<NativeRdb::ResultSet> &resultSet, const std::vector<std::string> &columns)
{
    vector<AlbumChangeInfo> albumChangeInfos;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        AlbumChangeInfo albumChangeInfo;
        albumChangeInfo.lpath_ = get<string>(ResultSetUtils::GetValFromColumn(
            PhotoAlbumColumns::ALBUM_LPATH, resultSet, GetDataType(PhotoAlbumColumns::ALBUM_LPATH)));
        albumChangeInfo.imageCount_ = get<int32_t>(ResultSetUtils::GetValFromColumn(
            PhotoAlbumColumns::ALBUM_IMAGE_COUNT, resultSet, GetDataType(PhotoAlbumColumns::ALBUM_IMAGE_COUNT)));
        albumChangeInfo.videoCount_ = get<int32_t>(ResultSetUtils::GetValFromColumn(
            PhotoAlbumColumns::ALBUM_VIDEO_COUNT, resultSet, GetDataType(PhotoAlbumColumns::ALBUM_VIDEO_COUNT)));
        albumChangeInfo.albumType_ = get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_TYPE,
            resultSet, GetDataType(PhotoAlbumColumns::ALBUM_TYPE)));
        albumChangeInfo.albumSubType_ = get<int32_t>(ResultSetUtils::GetValFromColumn(
            PhotoAlbumColumns::ALBUM_SUBTYPE, resultSet, GetDataType(PhotoAlbumColumns::ALBUM_SUBTYPE)));
        albumChangeInfo.albumName_ = get<string>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_NAME,
            resultSet, GetDataType(PhotoAlbumColumns::ALBUM_NAME)));
        albumChangeInfo.count_ = get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_COUNT,
            resultSet, GetDataType(PhotoAlbumColumns::ALBUM_COUNT)));
        albumChangeInfo.coverUri_ = get<string>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_COVER_URI,
            resultSet, GetDataType(PhotoAlbumColumns::ALBUM_COVER_URI)));
        albumChangeInfo.hiddenCount_ = get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::HIDDEN_COUNT,
            resultSet, GetDataType(PhotoAlbumColumns::HIDDEN_COUNT)));
        albumChangeInfo.hiddenCoverUri_ = get<string>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::HIDDEN_COVER,
            resultSet, GetDataType(PhotoAlbumColumns::HIDDEN_COVER)));
        albumChangeInfo.albumId_ = get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_ID,
            resultSet, GetDataType(PhotoAlbumColumns::ALBUM_ID)));
        albumChangeInfo.albumUri_ = MediaFileUtils::GetUriByExtrConditions(PhotoAlbumColumns::ALBUM_URI_PREFIX,
            to_string(albumChangeInfo.albumId_));
        albumChangeInfo.coverDateTime_ = get<int64_t>(ResultSetUtils::GetValFromColumn(
            PhotoAlbumColumns::COVER_DATE_TIME, resultSet, GetDataType(PhotoAlbumColumns::COVER_DATE_TIME)));
        albumChangeInfo.hiddenCoverDateTime_ = get<int64_t>(ResultSetUtils::GetValFromColumn(
            PhotoAlbumColumns::HIDDEN_COVER_DATE_TIME, resultSet,
            GetDataType(PhotoAlbumColumns::HIDDEN_COVER_DATE_TIME)));
        albumChangeInfo.dirty_ = get<int32_t>(ResultSetUtils::GetValFromColumn(PhotoAlbumColumns::ALBUM_DIRTY,
            resultSet, GetDataType(PhotoAlbumColumns::ALBUM_DIRTY)));
        albumChangeInfos.push_back(albumChangeInfo);
    }

    return albumChangeInfos;
}

string AlbumChangeInfo::ToString(bool isDetail) const
{
    stringstream ss;
    if (isDetail) {
        ss << "albumId_: " << albumId_ << ", albumSubType_: "<< albumSubType_ << ", count_: " << count_;
        ss << ", imageCount_: " << imageCount_ << ", videoCount_: " << videoCount_;
        ss << ", hiddenCount_: " << hiddenCount_ << ", albumType_: " << albumType_  << ", albumName_: " << albumName_;
        ss << ", albumUri_: " << albumUri_ << ", coverUri_: " << coverUri_;
        ss <<  ", hiddenCoverUri_: " << hiddenCoverUri_;
        ss << ", isCoverChange_: " << isCoverChange_ << ", isHiddenCoverChange_: " << isHiddenCoverChange_;
        ss << ", coverDateTime_: " << coverDateTime_ << ", hiddenCoverDateTime_: " << hiddenCoverDateTime_;
        ss << ", dirty_: " << dirty_;
    } else {
        ss << "albumId_: " << albumId_ << ", albumSubType_: "<< albumSubType_;
    }

    return ss.str();
}

ResultSetDataType AlbumChangeInfo::GetDataType(const std::string &column)
{
    auto const &item = albumInfoCloumnTypes_.find(column);
    if (item == albumInfoCloumnTypes_.end()) {
        return TYPE_NULL;
    }
    return item->second;
}

ValuesBucket AlbumChangeInfo::GetUpdateValues(const AlbumChangeInfo &oldAlbumInfo, NotifyType &type)
{
    stringstream ss;
    ValuesBucket values;
    if (imageCount_ != oldAlbumInfo.imageCount_ && imageCount_ != INVALID_INT32_VALUE) {
        values.PutInt(PhotoAlbumColumns::ALBUM_IMAGE_COUNT, imageCount_);
        ss << "imageCount_: " << oldAlbumInfo.imageCount_ << " -> " << imageCount_ << ", ";
    }
    if (videoCount_ != oldAlbumInfo.videoCount_ && videoCount_ != INVALID_INT32_VALUE) {
        values.PutInt(PhotoAlbumColumns::ALBUM_VIDEO_COUNT, videoCount_);
        ss << "videoCount_: " << oldAlbumInfo.videoCount_ << " -> " << videoCount_ << ", ";
    }
    if (count_ != oldAlbumInfo.count_ && count_ != INVALID_INT32_VALUE) {
        values.PutInt(PhotoAlbumColumns::ALBUM_COUNT, count_);
        ss << "count_: " << oldAlbumInfo.count_ << " -> " << count_ << ", ";
    }
    if (hiddenCount_ != oldAlbumInfo.hiddenCount_ && hiddenCount_ != INVALID_INT32_VALUE) {
        values.PutInt(PhotoAlbumColumns::HIDDEN_COUNT, hiddenCount_);
        ss << "hiddenCount_: " << oldAlbumInfo.hiddenCount_ << " -> " << hiddenCount_ << ", ";
        values.PutInt(PhotoAlbumColumns::CONTAINS_HIDDEN, hiddenCount_ != 0);
        ss << "contains_hidden: true, ";
    }
    if (coverUri_ != oldAlbumInfo.coverUri_ && coverUri_ != EMPTY_STR) {
        values.PutString(PhotoAlbumColumns::ALBUM_COVER_URI, coverUri_);
        ss << "coverUri_: " << oldAlbumInfo.coverUri_ << " -> " << coverUri_ << ", ";
    }
    if (hiddenCoverUri_ != oldAlbumInfo.hiddenCoverUri_ && hiddenCoverUri_ != EMPTY_STR) {
        values.PutString(PhotoAlbumColumns::HIDDEN_COVER, hiddenCoverUri_);
        ss << "hiddenCoverUri_: " << oldAlbumInfo.hiddenCoverUri_ << " -> " << hiddenCoverUri_ << ", ";
    }
    if (coverDateTime_ != oldAlbumInfo.coverDateTime_ && coverDateTime_ != INVALID_INT64_VALUE) {
        values.PutLong(PhotoAlbumColumns::COVER_DATE_TIME, coverDateTime_);
        ss << "coverDateTime_: " << oldAlbumInfo.coverDateTime_ << " -> " << coverDateTime_ << ", ";
    }
    if (hiddenCoverDateTime_ != oldAlbumInfo.hiddenCoverDateTime_ && hiddenCoverDateTime_ != INVALID_INT64_VALUE) {
        values.PutLong(PhotoAlbumColumns::HIDDEN_COVER_DATE_TIME, hiddenCoverDateTime_);
        ss << "hiddenCoverDateTime_: " << oldAlbumInfo.hiddenCoverDateTime_ << " -> " << hiddenCoverDateTime_;
    }
    type = oldAlbumInfo.count_ < count_ ? NOTIFY_ALBUM_ADD_ASSET :
        (oldAlbumInfo.count_ > count_ ? NOTIFY_ALBUM_REMOVE_ASSET : NOTIFY_UPDATE);
    ACCURATE_INFO("Update albumInfo[%{public}d], notifyType[%{public}d]: %{public}s", oldAlbumInfo.albumId_,
        static_cast<int32_t>(type), ss.str().c_str());
    return values;
}

bool AlbumChangeInfo::Marshalling(Parcel &parcel) const
{
    return Marshalling(parcel, false);
}

bool AlbumChangeInfo::Marshalling(Parcel &parcel, bool isSystem) const
{
    bool ret = parcel.WriteInt32(imageCount_);
    ret = ret && parcel.WriteInt32(videoCount_);
    ret = ret && parcel.WriteInt32(albumType_);
    ret = ret && parcel.WriteInt32(albumSubType_);
    ret = ret && parcel.WriteString(albumName_);
    ret = ret && parcel.WriteString(albumUri_);
    ret = ret && parcel.WriteInt32(count_);
    ret = ret && parcel.WriteString(coverUri_);
    ret = ret && parcel.WriteBool(isSystem);
    if (isSystem) {
        ret = ret && parcel.WriteInt32(hiddenCount_);
        ret = ret && parcel.WriteString(hiddenCoverUri_);
        ret = ret && parcel.WriteBool(isCoverChange_);
        if (isCoverChange_) {
            ret = ret && coverInfo_.Marshalling(parcel);
        }

        ret = ret && parcel.WriteBool(isHiddenCoverChange_);
        if (isHiddenCoverChange_) {
            ret = ret && hiddenCoverInfo_.Marshalling(parcel);
        }
        ret = ret && parcel.WriteInt32(albumId_);
    }
    return ret;
}

bool AlbumChangeInfo::ReadFromParcel(Parcel &parcel)
{
    bool ret = parcel.ReadInt32(imageCount_);
    ret = ret && parcel.ReadInt32(videoCount_);
    ret = ret && parcel.ReadInt32(albumType_);
    ret = ret && parcel.ReadInt32(albumSubType_);
    ret = ret && parcel.ReadString(albumName_);
    ret = ret && parcel.ReadString(albumUri_);
    ret = ret && parcel.ReadInt32(count_);
    ret = ret && parcel.ReadString(coverUri_);
    ret = ret && parcel.ReadBool(isSystem_);
    if (isSystem_) {
        ret = ret && parcel.ReadInt32(hiddenCount_);
        ret = ret && parcel.ReadString(hiddenCoverUri_);
        ret = ret && parcel.ReadBool(isCoverChange_);
        if (ret && isCoverChange_) {
            ret = ret && coverInfo_.ReadFromParcel(parcel);
        }
        ret = ret && parcel.ReadBool(isHiddenCoverChange_);
        if (ret && isHiddenCoverChange_) {
            ret = ret && hiddenCoverInfo_.ReadFromParcel(parcel);
        }
        ret = ret && parcel.ReadInt32(albumId_);
    }
    return true;
}

shared_ptr<AlbumChangeInfo> AlbumChangeInfo::Unmarshalling(Parcel &parcel)
{
    shared_ptr<AlbumChangeInfo> albumChangeInfo = make_shared<AlbumChangeInfo>();
    if (albumChangeInfo->ReadFromParcel(parcel)) {
        return albumChangeInfo;
    }
    return nullptr;
}

shared_ptr<AlbumChangeData> AlbumChangeData::Unmarshalling(Parcel &parcel)
{
    shared_ptr<AlbumChangeData> albumChangeData = make_shared<AlbumChangeData>();
    if (albumChangeData->ReadFromParcel(parcel)) {
        return albumChangeData;
    }
    return nullptr;
}

string AlbumRefreshInfo::ToString() const
{
    stringstream ss;
    ss << "deltaCount_: " << deltaCount_ << ", deltaVideoCount_: " << deltaVideoCount_ << ", deltaHiddenCount_: ";
    ss << deltaHiddenCount_;
    ss << ", deltaAddCover_ fileId: " << deltaAddCover_.fileId_ << ", deltaRemoveCover_ fileId: ";
    ss << deltaRemoveCover_.fileId_;
    ss << ", deltaAddHiddenCover_ fileId: " << deltaAddHiddenCover_.fileId_ << ", deltaRemoveHiddenCover_ fileId: ";
    ss << deltaRemoveHiddenCover_.fileId_;
    return ss.str();
}

} // namespace Media
} // namespace OHOS
