/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_CLOUD_SYNC_MDK_RECORD_PHOTOS_DATA_H
#define OHOS_MEDIA_CLOUD_SYNC_MDK_RECORD_PHOTOS_DATA_H

#include <map>
#include <vector>

#include "mdk_record.h"
#include "mdk_reference.h"
#include "mdk_database.h"
#include "mdk_record_reader.h"

namespace OHOS::Media::CloudSync {
#define EXPORT __attribute__ ((visibility ("default")))
class EXPORT MDKRecordPhotosData {
private:  // data member
    MDKRecord record_;
    std::map<std::string, MDKRecordField> fields_;
    std::map<std::string, MDKRecordField> properties_;
    std::map<std::string, MDKRecordField> attributes_;

private:  // composited class
    MDKRecordReader recordReader_;

public:  // constructor & destructor
    MDKRecordPhotosData() = default;
    MDKRecordPhotosData(const MDKRecord &record)
    {
        this->UnMarshalling(record);
    }
    virtual ~MDKRecordPhotosData() = default;

private:  // Marshalling & UnMarshalling
    void UnMarshalling(const MDKRecord &record)
    {
        this->record_ = record;
        this->record_.GetRecordData(this->fields_);
        if (this->fields_.find(this->KEY_PROPERTIES) != this->fields_.end()) {
            this->fields_[this->KEY_PROPERTIES].GetRecordMap(this->properties_);
        }
        if (this->fields_.find(this->KEY_ATTRIBUTES) != this->fields_.end()) {
            this->fields_[this->KEY_ATTRIBUTES].GetRecordMap(this->attributes_);
        }
    }
    void Marshalling()
    {
        if (this->properties_.size() > 0) {
            this->fields_[this->KEY_PROPERTIES] = MDKRecordField(this->properties_);
        }
        if (this->attributes_.size() > 0) {
            this->fields_[this->KEY_ATTRIBUTES] = MDKRecordField(this->attributes_);
        }
        this->record_.SetRecordData(this->fields_);
        this->record_.SetRecordType(this->VALUE_RECORD_TYPE);
    }

public:  // getter & setter
    MDKRecord GetDKRecord()
    {
        this->Marshalling();
        return this->record_;
    }
    void SetDKRecord(MDKRecord &record)
    {
        this->record_ = record;
        record.GetRecordData(this->fields_);
    }
    std::optional<std::string> GetType()  const
    {
        return this->recordReader_.GetStringValue(this->fields_, this->KEY_TYPE);
    }
    // type, "directory" or "file"
    void SetType(const std::string &type)
    {
        this->fields_[this->KEY_TYPE] = MDKRecordField(type);
    }

public:  // record data getter & setter - gallery-specific or shared fileds
    std::optional<int32_t> GetFileId()  const
    {
        return this->recordReader_.GetIntValue(this->attributes_, FILE_ID);
    }
    MDKRecordPhotosData &SetFileId(const int32_t fileId)
    {
        this->attributes_[FILE_ID] = MDKRecordField(fileId);
        return *this;
    }
    std::optional<int32_t> GetLocalId()  const
    {
        return this->recordReader_.GetIntValue(this->fields_, FILE_LOCAL_ID);
    }
    MDKRecordPhotosData &SetLocalId(const int32_t localId)
    {
        this->fields_[FILE_LOCAL_ID] = MDKRecordField(localId);
        return *this;
    }
    std::optional<int32_t> GetFileType()  const
    {
        return this->recordReader_.GetIntValue(this->fields_, "fileType");
    }
    MDKRecordPhotosData &SetFileType(const int32_t &fileType)
    {
        this->fields_["fileType"] = MDKRecordField(fileType);
        return *this;
    }
    std::optional<std::string> GetFileName()  const
    {
        return this->recordReader_.GetStringValue(this->fields_, "fileName");
    }
    void SetFileName(const std::string &fileName)
    {
        this->fields_["fileName"] = MDKRecordField(fileName);
    }
    std::optional<int64_t> GetCreatedTime()  const
    {
        return this->recordReader_.GetLongValue(this->fields_, "createdTime");
    }
    void SetCreatedTime(const int64_t &createdTime)
    {
        this->fields_["createdTime"] = MDKRecordField(createdTime);
    }
    std::optional<std::string> GetHashId()  const
    {
        return this->recordReader_.GetStringValue(this->fields_, "hashId");
    }
    void SetHashId(const std::string &hashId)
    {
        this->fields_["hashId"] = MDKRecordField(hashId);
    }
    std::optional<int64_t> GetSize()  const
    {
        return this->recordReader_.GetLongValue(this->fields_, "size");
    }
    void SetSize(const int64_t &size)
    {
        this->fields_["size"] = MDKRecordField(size);
    }
    std::optional<std::string> GetSource()  const
    {
        return this->recordReader_.GetStringValue(this->fields_, "source");
    }
    void SetSource(const std::string &source)
    {
        this->fields_["source"] = MDKRecordField(source);
    }
    std::optional<bool> GetRecycled() const
    {
        return this->recordReader_.GetBoolValue(this->fields_, "recycled");
    }
    void SetRecycled(const bool &recycled)
    {
        this->fields_["recycled"] = MDKRecordField(recycled);
    }
    std::optional<int64_t> GetRecycledTime()  const
    {
        return this->recordReader_.GetLongValue(this->fields_, "recycledTime");
    }
    void SetRecycledTime(const int64_t &recycledTime)
    {
        this->fields_["recycledTime"] = MDKRecordField(recycledTime);
    }
    std::optional<bool> GetFavorite()  const
    {
        return this->recordReader_.GetBoolValue(this->fields_, "favorite");
    }
    void SetFavorite(const bool &favorite)
    {
        this->fields_["favorite"] = MDKRecordField(favorite);
    }
    std::optional<std::string> GetDescription()  const
    {
        return this->recordReader_.GetStringValue(this->fields_, "description");
    }
    void SetDescription(const std::string &description)
    {
        this->fields_["description"] = MDKRecordField(description);
    }
    std::optional<std::string> GetMimeType()  const
    {
        return this->recordReader_.GetStringValue(this->fields_, FILE_MIME_TYPE);
    }
    void SetMimeType(const std::string &mimeType)
    {
        this->fields_[MediaColumn::MEDIA_MIME_TYPE] = MDKRecordField(mimeType);
    }
    std::optional<MDKAsset> GetFileContent()  const
    {
        return this->recordReader_.GetAssetValue(this->fields_, FILE_CONTENT);
    }
    void SetFileContent(const MDKAsset &asset)
    {
        this->fields_[FILE_CONTENT] = MDKRecordField(asset);
    }
    std::optional<MDKAsset> GetFileRaw()  const
    {
        return this->recordReader_.GetAssetValue(this->fields_, FILE_RAW);
    }
    void SetFileRaw(const MDKAsset &asset)
    {
        this->fields_[FILE_RAW] = MDKRecordField(asset);
    }
    std::optional<MDKAsset> GetFileEditData()  const
    {
        return this->recordReader_.GetAssetValue(this->fields_, FILE_EDIT_DATA);
    }
    void SetFileEditData(const MDKAsset &asset)
    {
        this->fields_[FILE_EDIT_DATA] = MDKRecordField(asset);
    }

public:  // attributes getter & setter
    std::optional<std::string> GetTitle()  const
    {
        return this->recordReader_.GetStringValue(this->attributes_, PhotoColumn::MEDIA_TITLE);
    }
    MDKRecordPhotosData &SetTitle(const std::string &title)
    {
        this->attributes_[PhotoColumn::MEDIA_TITLE] = MDKRecordField(title);
        return *this;
    }
    std::optional<int32_t> GetMediaType()  const
    {
        return this->recordReader_.GetIntValue(this->attributes_, PhotoColumn::MEDIA_TYPE);
    }
    MDKRecordPhotosData &SetMediaType(const int32_t mediaType)
    {
        this->attributes_[PhotoColumn::MEDIA_TYPE] = MDKRecordField(mediaType);
        return *this;
    }
    std::optional<int32_t> GetDuration()  const
    {
        return this->recordReader_.GetIntValue(this->attributes_, PhotoColumn::MEDIA_DURATION);
    }
    MDKRecordPhotosData &SetDuration(const int32_t duration)
    {
        this->attributes_[PhotoColumn::MEDIA_DURATION] = MDKRecordField(duration);
        return *this;
    }
    std::optional<int32_t> GetHidden()  const
    {
        return this->recordReader_.GetIntValue(this->attributes_, PhotoColumn::MEDIA_HIDDEN);
    }
    MDKRecordPhotosData &SetHidden(const int32_t hidden)
    {
        this->attributes_[PhotoColumn::MEDIA_HIDDEN] = MDKRecordField(hidden);
        return *this;
    }
    std::optional<int64_t> GetHiddenTime()  const
    {
        return this->recordReader_.GetLongValue(this->attributes_, PhotoColumn::PHOTO_HIDDEN_TIME);
    }
    MDKRecordPhotosData &SetHiddenTime(const int64_t hiddenTime)
    {
        this->attributes_[PhotoColumn::PHOTO_HIDDEN_TIME] = MDKRecordField(hiddenTime);
        return *this;
    }
    std::optional<std::string> GetRelativePath()  const
    {
        return this->recordReader_.GetStringValue(this->attributes_, PhotoColumn::MEDIA_RELATIVE_PATH);
    }
    MDKRecordPhotosData &SetRelativePath(const std::string &relativePath)
    {
        this->attributes_[PhotoColumn::MEDIA_RELATIVE_PATH] = MDKRecordField(relativePath);
        return *this;
    }
    std::optional<std::string> GetVirtualPath()  const
    {
        return this->recordReader_.GetStringValue(this->attributes_, PhotoColumn::MEDIA_VIRTURL_PATH);
    }
    MDKRecordPhotosData &SetVirtualPath(const std::string &virtualPath)
    {
        this->attributes_[PhotoColumn::MEDIA_VIRTURL_PATH] = MDKRecordField(virtualPath);
        return *this;
    }
    std::optional<int64_t> GetDateModified()  const
    {
        return this->recordReader_.GetLongValue(this->attributes_, PhotoColumn::MEDIA_DATE_MODIFIED);
    }
    MDKRecordPhotosData &SetDateModified(const int64_t dateModified)
    {
        this->attributes_[PhotoColumn::MEDIA_DATE_MODIFIED] = MDKRecordField(dateModified);
        return *this;
    }
    std::optional<int64_t> GetPhotoMetaDateModified()  const
    {
        return this->recordReader_.GetLongValue(this->attributes_, PhotoColumn::PHOTO_META_DATE_MODIFIED);
    }
    MDKRecordPhotosData &SetPhotoMetaDateModified(const int64_t dateModified)
    {
        this->attributes_[PhotoColumn::PHOTO_META_DATE_MODIFIED] = MDKRecordField(dateModified);
        return *this;
    }
    std::optional<int32_t> GetSubType()  const
    {
        return this->recordReader_.GetIntValue(this->attributes_, PhotoColumn::PHOTO_SUBTYPE);
    }
    MDKRecordPhotosData &SetSubType(const int32_t subType)
    {
        this->attributes_[PhotoColumn::PHOTO_SUBTYPE] = MDKRecordField(subType);
        return *this;
    }
    std::optional<int32_t> GetBurstCoverLevel()  const
    {
        return this->recordReader_.GetIntValue(this->attributes_, PhotoColumn::PHOTO_BURST_COVER_LEVEL);
    }
    MDKRecordPhotosData &SetBurstCoverLevel(const int32_t burstCoverLevel)
    {
        this->attributes_[PhotoColumn::PHOTO_BURST_COVER_LEVEL] = MDKRecordField(burstCoverLevel);
        return *this;
    }
    std::optional<std::string> GetBurstKey()  const
    {
        return this->recordReader_.GetStringValue(this->attributes_, PhotoColumn::PHOTO_BURST_KEY);
    }
    MDKRecordPhotosData &SetBurstKey(const std::string &burstKey)
    {
        this->attributes_[PhotoColumn::PHOTO_BURST_KEY] = MDKRecordField(burstKey);
        return *this;
    }
    std::optional<std::string> GetDateYear()  const
    {
        return this->recordReader_.GetStringValue(this->attributes_, PhotoColumn::PHOTO_DATE_YEAR);
    }
    MDKRecordPhotosData &SetDateYear(const std::string &dateYear)
    {
        this->attributes_[PhotoColumn::PHOTO_DATE_YEAR] = MDKRecordField(dateYear);
        return *this;
    }
    std::optional<std::string> GetDateMonth()  const
    {
        return this->recordReader_.GetStringValue(this->attributes_, PhotoColumn::PHOTO_DATE_MONTH);
    }
    MDKRecordPhotosData &SetDateMonth(const std::string &dateMonth)
    {
        this->attributes_[PhotoColumn::PHOTO_DATE_MONTH] = MDKRecordField(dateMonth);
        return *this;
    }
    std::optional<std::string> GetDateDay()  const
    {
        return this->recordReader_.GetStringValue(this->attributes_, PhotoColumn::PHOTO_DATE_DAY);
    }
    MDKRecordPhotosData &SetDateDay(const std::string &dateDay)
    {
        this->attributes_[PhotoColumn::PHOTO_DATE_DAY] = MDKRecordField(dateDay);
        return *this;
    }
    std::optional<std::string> GetShootingMode()  const
    {
        return this->recordReader_.GetStringValue(this->attributes_, PhotoColumn::PHOTO_SHOOTING_MODE);
    }
    MDKRecordPhotosData &SetShootingMode(const std::string &shootingMode)
    {
        this->attributes_[PhotoColumn::PHOTO_SHOOTING_MODE] = MDKRecordField(shootingMode);
        return *this;
    }
    std::optional<std::string> GetShootingModeTag()  const
    {
        return this->recordReader_.GetStringValue(this->attributes_, PhotoColumn::PHOTO_SHOOTING_MODE_TAG);
    }
    MDKRecordPhotosData &SetShootingModeTag(const std::string &shootingModeTag)
    {
        this->attributes_[PhotoColumn::PHOTO_SHOOTING_MODE_TAG] = MDKRecordField(shootingModeTag);
        return *this;
    }
    std::optional<int32_t> GetDynamicRangeType()  const
    {
        return this->recordReader_.GetIntValue(this->attributes_, PhotoColumn::PHOTO_DYNAMIC_RANGE_TYPE);
    }
    MDKRecordPhotosData &SetDynamicRangeType(const int32_t dynamicRangeType)
    {
        this->attributes_[PhotoColumn::PHOTO_DYNAMIC_RANGE_TYPE] = MDKRecordField(dynamicRangeType);
        return *this;
    }
    std::optional<std::string> GetFrontCamera()  const
    {
        return this->recordReader_.GetStringValue(this->attributes_, PhotoColumn::PHOTO_FRONT_CAMERA);
    }
    MDKRecordPhotosData &SetFrontCamera(const std::string &frontCamera)
    {
        this->attributes_[PhotoColumn::PHOTO_FRONT_CAMERA] = MDKRecordField(frontCamera);
        return *this;
    }
    std::optional<int64_t> GetEditTime()  const
    {
        return this->recordReader_.GetLongValue(this->attributes_, PhotoColumn::PHOTO_EDIT_TIME);
    }
    MDKRecordPhotosData &SetEditTime(const int64_t editTime)
    {
        this->attributes_[PhotoColumn::PHOTO_EDIT_TIME] = MDKRecordField(editTime);
        return *this;
    }
    std::optional<int32_t> GetOriginalSubType()  const
    {
        return this->recordReader_.GetIntValue(this->attributes_, PhotoColumn::PHOTO_ORIGINAL_SUBTYPE);
    }
    MDKRecordPhotosData &SetOriginalSubType(const int32_t originalSubType)
    {
        this->attributes_[PhotoColumn::PHOTO_ORIGINAL_SUBTYPE] = MDKRecordField(originalSubType);
        return *this;
    }
    std::optional<int64_t> GetCoverPosition()  const
    {
        return this->recordReader_.GetLongValue(this->attributes_, PhotoColumn::PHOTO_COVER_POSITION);
    }
    MDKRecordPhotosData &SetCoverPosition(const int64_t coverPosition)
    {
        this->attributes_[PhotoColumn::PHOTO_COVER_POSITION] = MDKRecordField(coverPosition);
        return *this;
    }
    std::optional<int32_t> GetMovingPhotoEffectMode()  const
    {
        return this->recordReader_.GetIntValue(this->attributes_, PhotoColumn::MOVING_PHOTO_EFFECT_MODE);
    }
    MDKRecordPhotosData &SetMovingPhotoEffectMode(const int32_t movingPhotoEffectMode)
    {
        this->attributes_[PhotoColumn::MOVING_PHOTO_EFFECT_MODE] = MDKRecordField(movingPhotoEffectMode);
        return *this;
    }
    std::optional<int32_t> GetSupportedWatermarkType()  const
    {
        return this->recordReader_.GetIntValue(this->attributes_, PhotoColumn::SUPPORTED_WATERMARK_TYPE);
    }
    MDKRecordPhotosData &SetSupportedWatermarkType(const int32_t supportedWatermarkType)
    {
        this->attributes_[PhotoColumn::SUPPORTED_WATERMARK_TYPE] = MDKRecordField(supportedWatermarkType);
        return *this;
    }
    std::optional<int32_t> GetStrongAssociation()  const
    {
        return this->recordReader_.GetIntValue(this->attributes_, PhotoColumn::PHOTO_STRONG_ASSOCIATION);
    }
    MDKRecordPhotosData &SetStrongAssociation(const int32_t strongAssociation)
    {
        this->attributes_[PhotoColumn::PHOTO_STRONG_ASSOCIATION] = MDKRecordField(strongAssociation);
        return *this;
    }
    std::optional<int32_t> GetCloudFileId()  const
    {
        return this->recordReader_.GetIntValue(this->attributes_, MediaColumn::MEDIA_ID);
    }
    MDKRecordPhotosData &SetCloudFileId(const int32_t fileId)
    {
        this->attributes_[MediaColumn::MEDIA_ID] = MDKRecordField(fileId);
        return *this;
    }
    std::optional<std::string> GetCloudId()  const
    {
        return this->recordReader_.GetStringValue(this->attributes_, PhotoColumn::PHOTO_CLOUD_ID);
    }
    MDKRecordPhotosData &SetCloudId(const std::string &cloudId)
    {
        this->attributes_[PhotoColumn::PHOTO_CLOUD_ID] = MDKRecordField(cloudId);
        return *this;
    }
    std::optional<std::string> GetOriginalAssetCloudId()  const
    {
        return this->recordReader_.GetStringValue(this->attributes_, PhotoColumn::PHOTO_ORIGINAL_ASSET_CLOUD_ID);
    }
    MDKRecordPhotosData &SetOriginalAssetCloudId(const std::string &originalAssetCloudId)
    {
        this->attributes_[PhotoColumn::PHOTO_ORIGINAL_ASSET_CLOUD_ID] = MDKRecordField(originalAssetCloudId);
        return *this;
    }
    std::optional<std::string> GetFilePath()  const
    {
        return this->recordReader_.GetStringValue(this->attributes_, PhotoColumn::MEDIA_FILE_PATH);
    }
    MDKRecordPhotosData &SetFilePath(const std::string &filePath)
    {
        this->attributes_[PhotoColumn::MEDIA_FILE_PATH] = MDKRecordField(filePath);
        return *this;
    }
    std::optional<int64_t> GetDateAdded()  const
    {
        return this->recordReader_.GetLongValue(this->attributes_, PhotoColumn::MEDIA_DATE_ADDED);
    }
    MDKRecordPhotosData &SetDateAdded(const int64_t dateAdded)
    {
        this->attributes_[PhotoColumn::MEDIA_DATE_ADDED] = MDKRecordField(dateAdded);
        return *this;
    }
    // std::optional<int64_t> GetDateModified()  const
    // {
    //     return this->recordReader_.GetLongValue(this->attributes_, PhotoColumn::MEDIA_DATE_MODIFIED);
    // }
    // MDKRecordPhotosData &SetDateModified(const int64_t dateModified)
    // {
    //     this->attributes_[PhotoColumn::MEDIA_DATE_MODIFIED] = MDKRecordField(dateModified);
    //     return *this;
    // }
    std::optional<int32_t> GetOwnerAlbumId()  const
    {
        return this->recordReader_.GetIntValue(this->attributes_, PhotoColumn::PHOTO_OWNER_ALBUM_ID);
    }
    MDKRecordPhotosData &SetOwnerAlbumId(const int32_t ownerAlbumId)
    {
        this->attributes_[PhotoColumn::PHOTO_OWNER_ALBUM_ID] = MDKRecordField(ownerAlbumId);
        return *this;
    }
    std::optional<int64_t> GetFixVersion()  const
    {
        return this->recordReader_.GetLongValue(this->attributes_, FILE_FIX_VERSION);
    }
    MDKRecordPhotosData &SetFixVersion(const int64_t fixVersion)
    {
        this->attributes_[FILE_FIX_VERSION] = MDKRecordField(fixVersion);
        return *this;
    }
    std::optional<int64_t> GetLcdSize()  const
    {
        return this->recordReader_.GetLongValue(this->attributes_, "lcd_size");
    }
    MDKRecordPhotosData &SetLcdSize(const int64_t lcdSize)
    {
        this->attributes_["lcd_size"] = MDKRecordField(lcdSize);
        return *this;
    }
    std::optional<int64_t> GetThmSize()  const
    {
        return this->recordReader_.GetLongValue(this->attributes_, "thumb_size");
    }
    MDKRecordPhotosData &SetThmSize(const int64_t thmSize)
    {
        this->attributes_["thumb_size"] = MDKRecordField(thmSize);
        return *this;
    }
    std::optional<std::string> GetFileEditDataCamera()  const
    {
        return this->recordReader_.GetStringValue(this->attributes_, FILE_EDIT_DATA_CAMERA);
    }
    MDKRecordPhotosData &SetFileEditDataCamera(const std::string &fileEditDataCamera)
    {
        this->attributes_[FILE_EDIT_DATA_CAMERA] = MDKRecordField(fileEditDataCamera);
        return *this;
    }
    std::optional<int64_t> GetEditTimeMs()  const
    {
        return this->recordReader_.GetLongValue(this->attributes_, "editedTime_ms");
    }
    void SetEditTimeMs(int64_t editedTimeMs)
    {
        this->attributes_["editedTime_ms"] = MDKRecordField(editedTimeMs);
    }
    std::optional<std::string> GetEditDataCamera()  const
    {
        return this->recordReader_.GetStringValue(this->attributes_, "editDataCamera");
    }
    MDKRecordPhotosData &SetEditDataCamera(const std::string &editDataCamera)
    {
        this->attributes_["editDataCamera"] = MDKRecordField(editDataCamera);
        return *this;
    }

public:  // properties getter & setter - gallery expand fields
    std::optional<std::string> GetSourcePath()  const
    {
        return this->recordReader_.GetStringValue(this->properties_, "sourcePath");
    }
    void SetSourcePath(const std::string &sourcePath)
    {
        this->properties_["sourcePath"] = MDKRecordField(sourcePath);
    }
    std::optional<std::string> GetSourceFileName()  const
    {
        return this->recordReader_.GetStringValue(this->properties_, "sourceFileName");
    }
    void SetSourceFileName(const std::string &sourceFileName)
    {
        this->properties_["sourceFileName"] = MDKRecordField(sourceFileName);
    }
    std::optional<std::string> GetFirstUpdateTime()  const
    {
        return this->recordReader_.GetStringValue(this->properties_, "first_update_time");
    }
    void SetFirstUpdateTime(const std::string firstUpdateTime)
    {
        this->properties_["first_update_time"] = MDKRecordField(firstUpdateTime);
    }
    std::optional<std::string> GetFileCreateTime()  const
    {
        return this->recordReader_.GetStringValue(this->properties_, "fileCreateTime");
    }
    void SetFileCreateTime(const std::string &fileCreateTime)
    {
        this->properties_["fileCreateTime"] = MDKRecordField(fileCreateTime);
    }
    // std::optional<int64_t> GetEditTimeMs()  const
    // {
    //     return this->recordReader_.GetLongValue(this->properties_, "editedTime_ms");
    // }
    // void SetEditTimeMs(int64_t editedTimeMs)
    // {
    //     this->properties_["editedTime_ms"] = MDKRecordField(editedTimeMs);
    // }
    std::optional<std::string> GetDetailTime()  const
    {
        return this->recordReader_.GetStringValue(this->properties_, "detail_time");
    }
    void SetDetailTime(const std::string &detailTime)
    {
        this->properties_["detail_time"] = MDKRecordField(detailTime);
    }
    // std::optional<int32_t> GetDuration()  const
    // {
    //     return this->recordReader_.GetIntValue(this->properties_, "duration");
    // }
    // void SetDuration(const int32_t &duration)
    // {
    //     this->properties_["duration"] = MDKRecordField(duration);
    // }
    std::optional<int32_t> GetHeight()  const
    {
        return this->recordReader_.GetIntValue(this->properties_, "height");
    }
    void SetHeight(const int32_t &height)
    {
        this->properties_["height"] = MDKRecordField(height);
    }
    std::optional<int32_t> GetWidth()  const
    {
        return this->recordReader_.GetIntValue(this->properties_, "width");
    }
    void SetWidth(const int32_t &width)
    {
        this->properties_["width"] = MDKRecordField(width);
    }
    std::optional<std::string> GetFilePosition()  const
    {
        return this->recordReader_.GetStringValue(this->properties_, "file_position");
    }
    void SetFilePosition(const std::string &position)
    {
        this->properties_["file_position"] = MDKRecordField(position);
    }

    std::optional<std::string> GetPosition()  const
    {
        return this->recordReader_.GetStringValue(this->properties_, "position");
    }

    void SetPosition(const std::string &position)
    {
        this->properties_["position"] = MDKRecordField(position);
    }

    std::optional<int32_t> GetRotate()  const
    {
        return this->recordReader_.GetIntValue(this->properties_, "rotate");
    }
    void SetRotate(const int32_t &rotate)
    {
        this->properties_["rotate"] = MDKRecordField(rotate);
    }

private:
    const std::string VALUE_RECORD_TYPE = "album";
    /* basic */
    const std::string KEY_PROPERTIES = "properties";
    const std::string KEY_TYPE = "type";
    const std::string KEY_ATTRIBUTES = "attributes";
    const std::string FILE_LOCAL_ID = "local_id";
    const std::string FILE_ID = "file_id";
    const std::string FILE_CONTENT = "content";
    const std::string FILE_RAW = "raw";
    const std::string FILE_THUMBNAIL = "thumbnail";
    const std::string FILE_LCD = "lcdThumbnail";
    const std::string FILE_EDIT_DATA = "editData";
    const std::string FILE_MIME_TYPE = "mimeType";
    const std::string FILE_EDIT_DATA_CAMERA = "editDataCamera";

    /* attributes */
    const std::string FILE_FIX_VERSION = "fix_version";
};
}  // namespace OHOS::Media::CloudSync
#endif  // OHOS_MEDIA_CLOUD_SYNC_MDK_RECORD_PHOTOS_DATA_H