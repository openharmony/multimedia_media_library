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

#ifndef OHOS_MEDIALIBRARY_PHOTO_ASSET_CHCNAGE_INFO_H
#define OHOS_MEDIALIBRARY_PHOTO_ASSET_CHCNAGE_INFO_H

#include <string>
#include <vector>

#include "accurate_common_data.h"
#include "abs_rdb_predicates.h"
#include "result_set.h"
#include "media_column.h"
#include "medialibrary_type_const.h"

namespace OHOS {
namespace Media::AccurateRefresh {
#define EXPORT __attribute__ ((visibility ("default")))

class EXPORT PhotoAssetChangeInfo : public Parcelable {
public:
    PhotoAssetChangeInfo() { }
    PhotoAssetChangeInfo(int32_t fileId, std::string uri, std::string dateDay, std::string ownerAlbumUri,
        bool isFavorite, int32_t mediaType, bool isHidden, int64_t dateTrashedMs, int32_t strongAssociation,
        int32_t thumbnailVisible, int64_t dateAddedMs, int64_t dateTakenMs, int32_t subType,
        int32_t syncStatus, int32_t cleanFlag, int32_t timePending, bool isTemp, int32_t burstCoverLevel,
        int32_t ownerAlbumId, int64_t hiddenTime, int64_t thumbnailReady, std::string displayName,
        std::string path) : fileId_(fileId), uri_(uri), dateDay_(dateDay), ownerAlbumUri_(ownerAlbumUri),
        isFavorite_(isFavorite), mediaType_(mediaType), isHidden_(isHidden), dateTrashedMs_(dateTrashedMs),
        strongAssociation_(strongAssociation), thumbnailVisible_(thumbnailVisible), dateAddedMs_(dateAddedMs),
        dateTakenMs_(dateTakenMs), subType_(subType), syncStatus_(syncStatus), cleanFlag_(cleanFlag),
        timePending_(timePending), isTemp_(isTemp), burstCoverLevel_(burstCoverLevel), ownerAlbumId_(ownerAlbumId),
        hiddenTime_(hiddenTime), thumbnailReady_(thumbnailReady), displayName_(displayName), path_(path) {}
        
public:
    int32_t fileId_ = INVALID_INT32_VALUE;
    std::string uri_ = EMPTY_STR;
    std::string dateDay_ = EMPTY_STR;

    // 相册相关
    std::string ownerAlbumUri_; // todo 或者使用ownerAlbumId
    bool isFavorite_ = false;
    int32_t mediaType_ = INVALID_INT32_VALUE;
    bool isHidden_ = false;
    int64_t dateTrashedMs_ = INVALID_INT64_VALUE;
    int32_t strongAssociation_ = INVALID_INT32_VALUE;
    int32_t thumbnailVisible_ = INVALID_INT32_VALUE;
    
    int64_t dateAddedMs_ = INVALID_INT64_VALUE;
    int64_t dateTakenMs_ = INVALID_INT64_VALUE;

    // 内部使用
    int32_t subType_ = INVALID_INT32_VALUE;
    int32_t syncStatus_ = INVALID_INT32_VALUE;
    int32_t cleanFlag_ = INVALID_INT32_VALUE;
    int32_t timePending_ = INVALID_INT32_VALUE;
    bool isTemp_ = false;
    int32_t burstCoverLevel_ = INVALID_INT32_VALUE;
    int32_t ownerAlbumId_ = INVALID_INT32_VALUE;
    int64_t hiddenTime_ = INVALID_INT64_VALUE;
    int64_t thumbnailReady_ = INVALID_INT64_VALUE;
    std::string displayName_ = EMPTY_STR;
    std::string path_ = EMPTY_STR;
    int32_t dirty_ = INVALID_INT32_VALUE;

    std::string ToString(bool isDetail = false) const;
    bool Marshalling(Parcel &parcel) const override;
    bool Marshalling(Parcel &parcel, bool isSystem) const;
    bool ReadFromParcel(Parcel &parcel);
    static std::shared_ptr<PhotoAssetChangeInfo> Unmarshalling(Parcel &parcel);

    static const std::vector<std::string>& GetPhotoAssetColumns();
    static std::vector<PhotoAssetChangeInfo> GetInfoFromResult(const std::shared_ptr<NativeRdb::ResultSet> &resultSet,
        const std::vector<std::string> &columns);
    static ResultSetDataType GetDataType(const std::string &column);
    
    PhotoAssetChangeInfo(const PhotoAssetChangeInfo &info) = default;
    PhotoAssetChangeInfo& operator=(const PhotoAssetChangeInfo &info);
    bool operator==(const PhotoAssetChangeInfo &info) const;
    bool operator!=(const PhotoAssetChangeInfo &info) const;

private:
    static const std::vector<std::string> photoAssetColumns_;
    static const std::map<std::string, ResultSetDataType> photoAssetCloumnTypes_;
    bool isSystem_ = false;
};

enum ThumbnailChangeStatus : int32_t {
    THUMBNAIL_NOT_CHANGE = 0,
    THUMBNAIL_NOT_EXISTS,
    THUMBNAIL_ADD,
    THUMBNAIL_UPDATE,
};

class EXPORT PhotoAssetChangeData : public AccurateRefreshChangeData<PhotoAssetChangeInfo> {
public:
    bool Marshalling(Parcel &parcel) const override;
    bool Marshalling(Parcel &parcel, bool isSystem) const;
    bool ReadFromParcel(Parcel &parcel) override;
    static std::shared_ptr<PhotoAssetChangeData> Unmarshalling(Parcel &parcel);
    std::string ToString(bool isDetail = false) const override
    {
        return AccurateRefreshChangeData::ToString(isDetail) + ", isContentChanged_: " +
            std::to_string(isContentChanged_) + ", thumbnailChangeStatus_: " +
            std::to_string(thumbnailChangeStatus_);
    }

public:
    bool isContentChanged_ = false;
    int32_t thumbnailChangeStatus_ = 0;
};

class PhotoAssetContentInfo {
public:
    bool isContentChanged_ = false;
    int32_t thumbnailChangeStatus_ = 0;
};

} // namespace Media
} // namespace OHOS

#endif