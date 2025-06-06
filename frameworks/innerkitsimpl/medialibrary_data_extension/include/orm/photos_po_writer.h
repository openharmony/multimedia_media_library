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

#ifndef OHOS_MEDIA_ORM_PHOTOS_PO_WRITER_H
#define OHOS_MEDIA_ORM_PHOTOS_PO_WRITER_H

#include <string>
#include <map>

#include "media_column.h"
#include "i_object_writer.h"
#include "medialibrary_errno.h"
#include "media_log.h"

namespace OHOS::Media::ORM {
class PhotosPoWriter : public IObjectWriter {
private:
    PhotosPo &photosPo_;

public:
    PhotosPoWriter(PhotosPo &photosPo) : photosPo_(photosPo)
    {}
    virtual ~PhotosPoWriter() = default;

public:
    std::map<std::string, MediaColumnType::DataType> GetColumns() override
    {
        return MediaColumnType::PHOTOS_COLUMNS;
    }

    int32_t SetMemberVariable(
        const std::string &name, std::variant<int32_t, int64_t, double, std::string> &val) override
    {
        auto it = this->HANDLERS.find(name);
        bool errConn = it == this->HANDLERS.end();
        CHECK_AND_RETURN_RET(!errConn, E_ERR);
        (this->*(it->second))(val);
        return E_OK;
    }

private:
    using Handle = void (PhotosPoWriter::*)(std::variant<int32_t, int64_t, double, std::string> &);
    const std::map<std::string, Handle> HANDLERS = {
        {PhotoColumn::MEDIA_FILE_PATH, &PhotosPoWriter::SetMediaFilePath},
        {PhotoColumn::MEDIA_TITLE, &PhotosPoWriter::SetMediaTitle},
        {PhotoColumn::MEDIA_SIZE, &PhotosPoWriter::SetMediaSize},
        {PhotoColumn::MEDIA_NAME, &PhotosPoWriter::SetMediaName},
        {PhotoColumn::MEDIA_TYPE, &PhotosPoWriter::SetMediaType},
        {PhotoColumn::MEDIA_MIME_TYPE, &PhotosPoWriter::SetMediaMimeType},
        {PhotoColumn::MEDIA_DEVICE_NAME, &PhotosPoWriter::SetMediaDeviceName},
        {PhotoColumn::MEDIA_DATE_ADDED, &PhotosPoWriter::SetMediaDataAdded},
        {PhotoColumn::MEDIA_DATE_MODIFIED, &PhotosPoWriter::SetDataModified},
        {PhotoColumn::MEDIA_DATE_TAKEN, &PhotosPoWriter::SetDataTaken},
        {PhotoColumn::MEDIA_DURATION, &PhotosPoWriter::SetDuration},
        {PhotoColumn::MEDIA_IS_FAV, &PhotosPoWriter::SetIsFavorite},
        {PhotoColumn::MEDIA_DATE_TRASHED, &PhotosPoWriter::SetDataTrashed},
        {PhotoColumn::MEDIA_HIDDEN, &PhotosPoWriter::SetHidden},
        {PhotoColumn::PHOTO_HIDDEN_TIME, &PhotosPoWriter::SetHiddenTime},
        {PhotoColumn::MEDIA_RELATIVE_PATH, &PhotosPoWriter::SetRelativePath},
        {PhotoColumn::MEDIA_VIRTURL_PATH, &PhotosPoWriter::SetVirtualPath},
        {PhotoColumn::PHOTO_META_DATE_MODIFIED, &PhotosPoWriter::SetMetaDataModified},
        {PhotoColumn::PHOTO_ORIENTATION, &PhotosPoWriter::SetOrientation},
        {PhotoColumn::PHOTO_LATITUDE, &PhotosPoWriter::SetLatitude},
        {PhotoColumn::PHOTO_LONGITUDE, &PhotosPoWriter::SetLongitude},
        {PhotoColumn::PHOTO_HEIGHT, &PhotosPoWriter::SetHeight},
        {PhotoColumn::PHOTO_WIDTH, &PhotosPoWriter::SetWidth},
        {PhotoColumn::PHOTO_SUBTYPE, &PhotosPoWriter::SetSubType},
        {PhotoColumn::PHOTO_BURST_COVER_LEVEL, &PhotosPoWriter::SetBurstCoverLevel},
        {PhotoColumn::PHOTO_BURST_KEY, &PhotosPoWriter::SetBurstKey},
        {PhotoColumn::PHOTO_DATE_YEAR, &PhotosPoWriter::SetDataYear},
        {PhotoColumn::PHOTO_DATE_MONTH, &PhotosPoWriter::SetDataMonth},
        {PhotoColumn::PHOTO_DATE_DAY, &PhotosPoWriter::SetDataDay},
        {PhotoColumn::PHOTO_USER_COMMENT, &PhotosPoWriter::SetUserCommnt},
        {PhotoColumn::PHOTO_THUMB_STATUS, &PhotosPoWriter::SetThumbStatus},
        {PhotoColumn::PHOTO_SYNC_STATUS, &PhotosPoWriter::SetSyncStatus},
        {PhotoColumn::PHOTO_SHOOTING_MODE, &PhotosPoWriter::SetShootingMode},
        {PhotoColumn::PHOTO_SHOOTING_MODE_TAG, &PhotosPoWriter::SetShootingModeTag},
        {PhotoColumn::PHOTO_DYNAMIC_RANGE_TYPE, &PhotosPoWriter::SetDynamicRangType},
        {PhotoColumn::PHOTO_FRONT_CAMERA, &PhotosPoWriter::SetFrontCamera},
        {PhotoColumn::PHOTO_DETAIL_TIME, &PhotosPoWriter::SetDetailTime},
        {PhotoColumn::PHOTO_EDIT_TIME, &PhotosPoWriter::SetEditTime},
        {PhotoColumn::PHOTO_ORIGINAL_SUBTYPE, &PhotosPoWriter::SetOriginalSubtype},
        {PhotoColumn::PHOTO_COVER_POSITION, &PhotosPoWriter::SetCoverPosition},
        {PhotoColumn::PHOTO_IS_RECTIFICATION_COVER, &PhotosPoWriter::SetIsRectificationCover},
        {PhotoColumn::MOVING_PHOTO_EFFECT_MODE, &PhotosPoWriter::SetPhotoEffectMode},
        {PhotoColumn::PHOTO_OWNER_ALBUM_ID, &PhotosPoWriter::SetOwnerAlbumId},
        {PhotoColumn::PHOTO_ORIGINAL_ASSET_CLOUD_ID, &PhotosPoWriter::SetOriginalAssetCloudId},
        {PhotoColumn::PHOTO_SOURCE_PATH, &PhotosPoWriter::SetSourcePath},
        {PhotoColumn::SUPPORTED_WATERMARK_TYPE, &PhotosPoWriter::SetSupportedWatermarkType},
        {PhotoColumn::PHOTO_STRONG_ASSOCIATION, &PhotosPoWriter::SetStrongAssociation},
        {MediaColumn::MEDIA_ID, &PhotosPoWriter::SetMediaId},
        {PhotoColumn::PHOTO_CLOUD_ID, &PhotosPoWriter::SetCloudId},
        {PhotoColumn::PHOTO_DIRTY, &PhotosPoWriter::SetDirty},
        {PhotoColumn::PHOTO_POSITION, &PhotosPoWriter::SetPosition},
        {PhotoColumn::PHOTO_CLOUD_VERSION, &PhotosPoWriter::SetCloudVersion},
        {"album_cloud_id", &PhotosPoWriter::SetAlbumCloudId},
        {"lpath", &PhotosPoWriter::SetlPath},
    };

private:
    void SetMediaFilePath(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<std::string>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.data = std::get<std::string>(val);
    }
    void SetMediaTitle(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<std::string>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.title = std::get<std::string>(val);
    }
    void SetMediaSize(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<int64_t>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.size = std::get<int64_t>(val);
    }
    void SetMediaName(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<std::string>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.displayName = std::get<std::string>(val);
    }
    void SetMediaType(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<int32_t>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.mediaType = std::get<int32_t>(val);
    }
    void SetMediaMimeType(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<std::string>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.mimeType = std::get<std::string>(val);
    }
    void SetMediaDeviceName(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<std::string>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.deviceName = std::get<std::string>(val);
    }
    void SetMediaDataAdded(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<int64_t>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.dateAdded = std::get<int64_t>(val);
    }
    void SetDataModified(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<int64_t>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.dateModified = std::get<int64_t>(val);
    }
    void SetDataTaken(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<int64_t>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.dateTaken = std::get<int64_t>(val);
    }
    void SetDuration(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<int32_t>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.duration = std::get<int32_t>(val);
    }
    void SetIsFavorite(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<int32_t>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.isFavorite = std::get<int32_t>(val);
    }
    void SetDataTrashed(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<int64_t>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.dateTrashed = std::get<int64_t>(val);
    }
    void SetHidden(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<int32_t>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.hidden = std::get<int32_t>(val);
    }
    void SetHiddenTime(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<int64_t>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.hiddenTime = std::get<int64_t>(val);
    }
    void SetRelativePath(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<std::string>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.relativePath = std::get<std::string>(val);
    }
    void SetVirtualPath(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<std::string>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.virtualPath = std::get<std::string>(val);
    }
    void SetMetaDataModified(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<int64_t>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.metaDateModified = std::get<int64_t>(val);
    }
    void SetOrientation(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<int32_t>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.orientation = std::get<int32_t>(val);
    }
    void SetLatitude(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<double>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.latitude = std::get<double>(val);
    }
    void SetLongitude(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<double>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.longitude = std::get<double>(val);
    }
    void SetHeight(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<int32_t>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.height = std::get<int32_t>(val);
    }
    void SetWidth(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<int32_t>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.width = std::get<int32_t>(val);
    }
    void SetSubType(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<int32_t>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.subtype = std::get<int32_t>(val);
    }
    void SetBurstCoverLevel(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<int32_t>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.burstCoverLevel = std::get<int32_t>(val);
    }
    void SetBurstKey(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<std::string>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.burstKey = std::get<std::string>(val);
    }
    void SetDataYear(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<std::string>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.dateYear = std::get<std::string>(val);
    }
    void SetDataMonth(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<std::string>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.dateMonth = std::get<std::string>(val);
    }
    void SetDataDay(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<std::string>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.dateDay = std::get<std::string>(val);
    }
    void SetUserCommnt(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<std::string>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.userComment = std::get<std::string>(val);
    }
    void SetThumbStatus(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<int32_t>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.thumbStatus = std::get<int32_t>(val);
    }
    void SetSyncStatus(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<int32_t>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.syncStatus = std::get<int32_t>(val);
    }
    void SetShootingMode(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<std::string>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.shootingMode = std::get<std::string>(val);
    }
    void SetShootingModeTag(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<std::string>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.shootingModeTag = std::get<std::string>(val);
    }
    void SetDynamicRangType(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<int32_t>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.dynamicRangeType = std::get<int32_t>(val);
    }
    void SetFrontCamera(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<std::string>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.frontCamera = std::get<std::string>(val);
    }
    void SetDetailTime(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<std::string>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.detailTime = std::get<std::string>(val);
    }
    void SetEditTime(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<int64_t>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.editTime = std::get<int64_t>(val);
    }
    void SetOriginalSubtype(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<int32_t>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.originalSubtype = std::get<int32_t>(val);
    }
    void SetCoverPosition(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<int64_t>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.coverPosition = std::get<int64_t>(val);
    }
    void SetIsRectificationCover(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<int32_t>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.isRectificationCover = std::get<int32_t>(val);
    }
    void SetPhotoEffectMode(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<int32_t>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.movingPhotoEffectMode = std::get<int32_t>(val);
    }
    void SetOwnerAlbumId(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<int32_t>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.ownerAlbumId = std::get<int32_t>(val);
    }
    void SetOriginalAssetCloudId(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<std::string>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.originalAssetCloudId = std::get<std::string>(val);
    }
    void SetSourcePath(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<std::string>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.sourcePath = std::get<std::string>(val);
    }
    void SetSupportedWatermarkType(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<int32_t>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.supportedWatermarkType = std::get<int32_t>(val);
    }
    void SetStrongAssociation(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<int32_t>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.strongAssociation = std::get<int32_t>(val);
    }
    void SetMediaId(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<int32_t>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.fileId = std::get<int32_t>(val);
    }
    void SetCloudId(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<std::string>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.cloudId = std::get<std::string>(val);
    }
    void SetDirty(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<int32_t>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.dirty = std::get<int32_t>(val);
    }
    void SetPosition(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<int32_t>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.position = std::get<int32_t>(val);
    }
    void SetCloudVersion(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<int64_t>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.cloudVersion = std::get<int64_t>(val);
    }
    void SetAlbumCloudId(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<std::string>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.albumCloudId = std::get<std::string>(val);
    }
    void SetlPath(std::variant<int32_t, int64_t, double, std::string> &val)
    {
        bool errConn = !std::holds_alternative<std::string>(val);
        CHECK_AND_RETURN(!errConn);
        this->photosPo_.albumLPath = std::get<std::string>(val);
    }
};
}  // namespace OHOS::Media::ORM
#endif  // OHOS_MEDIA_ORM_PHOTOS_PO_WRITER_H
