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

#define MLOG_TAG "Media_Cloud_Vo"

#include "cloud_mdkrecord_photos_vo.h"

#include <sstream>

#include "media_itypes_utils.h"
#include "media_log.h"
#include "itypes_util.h"

namespace OHOS::Media::CloudSync {
bool CloudMdkRecordPhotosVo::MarshallingBasicInfo(Parcel &parcel) const
{
    CHECK_AND_RETURN_RET(parcel.WriteString(title), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(mediaType), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(duration), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(hidden), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt64(hiddenTime), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(relativePath), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(virtualPath), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt64(metaDateModified), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(subtype), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(burstCoverLevel), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(burstKey), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(dateYear), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(dateMonth), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(dateDay), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(shootingMode), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(shootingModeTag), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(dynamicRangeType), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(hdrMode), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(videoMode), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(frontCamera), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt64(editTime), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(originalSubtype), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt64(coverPosition), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(isRectificationCover), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(exifRotate), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(movingPhotoEffectMode), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(supportedWatermarkType), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(strongAssociation), false);
    return true;
}
bool CloudMdkRecordPhotosVo::MarshallingAttributesInfo(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET(parcel.WriteInt32(fileId), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(cloudId), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(originalAssetCloudId), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(data), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt64(dateAdded), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt64(dateModified), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(ownerAlbumId), false);
    CHECK_AND_RETURN_RET(parcel.WriteDouble(latitude), false);
    CHECK_AND_RETURN_RET(parcel.WriteDouble(longitude), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(sourcePath), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(displayName), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt64(dateTaken), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(detailTime), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(height), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(width), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(deviceName), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt64(dateTrashed), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(isFavorite), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(userComment), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(dirty), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(orientation), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt64(size), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt64(baseVersion), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(mimeType), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(albumCloudId), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(albumLPath), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(recordType), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(recordId), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(fileSourceType), false);
    CHECK_AND_RETURN_RET(parcel.WriteString(storagePath), false);
    CHECK_AND_RETURN_RET(ITypesUtil::Marshalling(stringfields, parcel), false);
    return true;
}
bool CloudMdkRecordPhotosVo::ReadBasicInfo(Parcel &parcel)
{
    CHECK_AND_RETURN_RET(parcel.ReadString(title), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(mediaType), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(duration), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(hidden), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt64(hiddenTime), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(relativePath), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(virtualPath), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt64(metaDateModified), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(subtype), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(burstCoverLevel), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(burstKey), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(dateYear), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(dateMonth), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(dateDay), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(shootingMode), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(shootingModeTag), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(dynamicRangeType), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(hdrMode), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(videoMode), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(frontCamera), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt64(editTime), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(originalSubtype), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt64(coverPosition), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(isRectificationCover), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(exifRotate), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(movingPhotoEffectMode), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(supportedWatermarkType), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(strongAssociation), false);
    return true;
}
bool CloudMdkRecordPhotosVo::ReadAttributesInfo(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET(parcel.ReadInt32(fileId), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(cloudId), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(originalAssetCloudId), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(data), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt64(dateAdded), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt64(dateModified), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(ownerAlbumId), false);
    CHECK_AND_RETURN_RET(parcel.ReadDouble(latitude), false);
    CHECK_AND_RETURN_RET(parcel.ReadDouble(longitude), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(sourcePath), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(displayName), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt64(dateTaken), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(detailTime), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(height), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(width), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(deviceName), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt64(dateTrashed), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(isFavorite), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(userComment), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(dirty), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(orientation), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt64(size), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt64(baseVersion), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(mimeType), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(albumCloudId), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(albumLPath), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(recordType), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(recordId), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(fileSourceType), false);
    CHECK_AND_RETURN_RET(parcel.ReadString(storagePath), false);
    CHECK_AND_RETURN_RET(ITypesUtil::Unmarshalling(stringfields, parcel), false);
    return true;
}
bool CloudMdkRecordPhotosVo::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET(this->MarshallingBasicInfo(parcel), false);
    CHECK_AND_RETURN_RET(this->MarshallingAttributesInfo(parcel), false);
    CHECK_AND_RETURN_RET(IPC::ITypeMediaUtil::Marshalling<std::string>(this->removeAlbumCloudId, parcel), false);
    return true;
}

bool CloudMdkRecordPhotosVo::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET(this->ReadBasicInfo(parcel), false);
    CHECK_AND_RETURN_RET(this->ReadAttributesInfo(parcel), false);
    CHECK_AND_RETURN_RET(IPC::ITypeMediaUtil::Unmarshalling<std::string>(this->removeAlbumCloudId, parcel), false);
    return true;
}

void CloudMdkRecordPhotosVo::GetAlbumInfo(std::stringstream &ss) const
{
    ss << "\"albumCloudId\": " << albumCloudId << "\","
       << "\"albumLPath\": " << albumLPath << ",";
}

void CloudMdkRecordPhotosVo::GetBasicInfo(std::stringstream &ss) const
{
    ss << "\"orientation\": \"" << orientation << "\","
       << "\"size\": " << size << ","
       << "\"hidden\": " << hidden << ","
       << "\"dirty\": " << dirty << ","
       << "\"dateTrashed\": " << dateTrashed << ","
       << "\"isFavorite\": " << isFavorite << ","
       << "\"mediaType\": " << mediaType << ","
       << "\"subtype\": " << subtype << ","
       << "\"ownerAlbumId\": " << ownerAlbumId << ",";
}

void CloudMdkRecordPhotosVo::GetPropertiesInfo(std::stringstream &ss) const
{
    ss << "\"editTime\": " << editTime << ","
       << "\"fileId\": " << fileId << ","
       << "\"cloudId\": \"" << cloudId << "\","
       << "\"originalAssetCloudId\": \"" << originalAssetCloudId << "\","
       << "\"dateAdded\": " << dateAdded << ","
       << "\"dateModified\": " << dateModified << ","
       << "\"dateTaken\": " << dateTaken << ","
       << "\"dateYear\": \"" << dateYear << "\","
       << "\"dateMonth\": \"" << dateMonth << "\","
       << "\"dateDay\": \"" << dateDay << "\","
       << "\"detailTime\": \"" << detailTime << "\","
       << "\"metaDateModified\": " << metaDateModified << ",";
}

void CloudMdkRecordPhotosVo::GetCloudInfo(std::stringstream &ss) const
{
    ss << "\"recordType\": \"" << recordType << "\","
       << "\"recordId\": \"" << recordId << ",\""
       << "\"isNew\": " << isNew << ","
       << "\"baseVersion\": " << baseVersion << ","
       << "\"originalSubtype\": " << originalSubtype << ","
       << "\"hiddenTime\": " << hiddenTime << ",";
}

void CloudMdkRecordPhotosVo::GetAttributesInfo(std::stringstream &ss) const
{
    ss << "\"duration\": " << duration << ","
       << "\"relativePath\": \"" << relativePath << "\","
       << "\"virtualPath\": \"" << virtualPath << "\","
       << "\"burstCoverLevel\": " << burstCoverLevel << ","
       << "\"burstKey\": \"" << burstKey << "\","
       << "\"shootingMode\": \"" << shootingMode << "\","
       << "\"shootingModeTag\": \"" << shootingModeTag << "\","
       << "\"dynamicRangeType\": " << dynamicRangeType << ","
       << "\"hdrMode\": " << hdrMode << ","
       << "\"videoMode\": " << videoMode << ","
       << "\"frontCamera\": \"" << frontCamera << "\","
       << "\"coverPosition\": " << coverPosition << ","
       << "\"isRectificationCover\": " << isRectificationCover << ","
       << "\"exifRotate\": " << exifRotate << ","
       << "\"movingPhotoEffectMode\": " << movingPhotoEffectMode << ","
       << "\"supportedWatermarkType\": " << supportedWatermarkType << ","
       << "\"strongAssociation\": " << strongAssociation << ","
       << "\"data\": \"" << data << "\","
       << "\"latitude_has_value\": " << (latitude != 0) << ","
       << "\"longitude_has_value\": " << (longitude != 0) << ","
       << "\"height\": " << height << ","
       << "\"width\": " << width << ","
       << "\"deviceName\": \"" << deviceName << "\","
       << "\"userComment\": \"" << userComment << "\","
       << "\"mimeType\": " << mimeType << ",";
}

void CloudMdkRecordPhotosVo::GetRemoveAlbumInfo(std::stringstream &ss) const
{
    ss << "[";
    for (uint32_t i = 0; i < removeAlbumCloudId.size(); i++) {
        ss << removeAlbumCloudId[i];
        if (i != removeAlbumCloudId.size() - 1) {
            ss << ",";
        }
    }
    ss << "]";
}

std::string CloudMdkRecordPhotosVo::ToString() const
{
    std::stringstream ss;
    ss << "{";
    this->GetAlbumInfo(ss);
    this->GetBasicInfo(ss);
    this->GetPropertiesInfo(ss);
    this->GetCloudInfo(ss);
    this->GetAttributesInfo(ss);
    this->GetRemoveAlbumInfo(ss);
    this->GetAttributesHashMap(ss);
    ss << "}";
    return ss.str();
}

bool CloudMdkRecordPhotosReqBody::Unmarshalling(MessageParcel &parcel)
{
    CHECK_AND_RETURN_RET(parcel.ReadInt32(this->size), false);
    CHECK_AND_RETURN_RET(parcel.ReadInt32(this->dirtyType), false);
    return true;
}

bool CloudMdkRecordPhotosReqBody::Marshalling(MessageParcel &parcel) const
{
    CHECK_AND_RETURN_RET(parcel.WriteInt32(this->size), false);
    CHECK_AND_RETURN_RET(parcel.WriteInt32(this->dirtyType), false);
    return true;
}

std::string CloudMdkRecordPhotosReqBody::ToString() const
{
    std::stringstream ss;
    ss << "{";
    ss << "\"size\":" << this->size << ",";
    ss << "\"dirtyType\":" << this->dirtyType << ",";
    ss << "}";
    return ss.str();
}

std::vector<CloudMdkRecordPhotosVo> CloudMdkRecordPhotosRespBody::GetPhotosRecords()
{
    return this->cloudPhotosUploadRecord;
}

bool CloudMdkRecordPhotosRespBody::Marshalling(MessageParcel &parcel) const
{
    if (cloudPhotosUploadRecord.size() == 0) {
        return false;
    }
    CHECK_AND_RETURN_RET(parcel.WriteInt32(static_cast<int32_t>(cloudPhotosUploadRecord.size())), false);
    for (const auto &entry : cloudPhotosUploadRecord) {
        if (!entry.Marshalling(parcel)) {
            return false;
        }
    }
    return true;
}

// 服务端->客户端；在客户端反序列化
bool CloudMdkRecordPhotosRespBody::GetRecords(std::vector<CloudMdkRecordPhotosVo> &val, MessageParcel &parcel)
{
    int32_t len = parcel.ReadInt32();
    if (len < 0) {
        return false;
    }
    size_t readAbleSize = parcel.GetReadableBytes();
    size_t size = static_cast<size_t>(len);
    if ((size > readAbleSize) || (size > val.max_size())) {
        return false;
    }

    val.clear();
    bool isValid;
    for (size_t i = 0; i < size; i++) {
        CloudMdkRecordPhotosVo nodeObj;
        isValid = nodeObj.Unmarshalling(parcel);
        CHECK_AND_RETURN_RET(isValid, false);
        val.emplace_back(nodeObj);
    }
    return true;
}

bool CloudMdkRecordPhotosRespBody::Unmarshalling(MessageParcel &parcel)
{
    return GetRecords(this->cloudPhotosUploadRecord, parcel);
}

std::string CloudMdkRecordPhotosRespBody::ToString() const
{
    return "";
}

void CloudMdkRecordPhotosVo::GetAttributesHashMap(std::stringstream &ss) const
{
    ss << "\"stringfields\": {";
    for (const auto &node : this->stringfields) {
        ss << "\"" << node.first << "\": ";
        ss << "\"" << node.second << "\", ";
    }
    ss << "}";
    return;
}

size_t CloudMdkRecordPhotosRespBody::GetDataSize() const
{
    return this->cloudPhotosUploadRecord.size();
}

bool CloudMdkRecordPhotosRespBody::TruncateDataBy200K()
{
    CHECK_AND_RETURN_RET(!this->cloudPhotosUploadRecord.empty(), false);
    constexpr size_t PARCEL_GAP = 4800;
    constexpr size_t MAX_CAPACITY = 204800;
    const size_t parcelCapacity = MAX_CAPACITY - PARCEL_GAP;
    const size_t originalSize = this->cloudPhotosUploadRecord.size();
    size_t parcelSize = 0;
    size_t elementSize = 0;
    std::vector<CloudMdkRecordPhotosVo> resultList;
    for (size_t index = 0; index < originalSize; index++) {
        MessageParcel tempParcel;
        // Try marshalling into MessageParcel.
        CHECK_AND_BREAK_ERR_LOG(this->cloudPhotosUploadRecord[index].Marshalling(tempParcel),
            "Marshalling error, truncate stop. "
            "index: %{public}zu, resultList: %{public}zu, originalSize: %{public}zu",
            index,
            resultList.size(),
            originalSize);
        // Check the dataSize not exceed capacity.
        elementSize = tempParcel.GetDataSize();
        parcelSize += elementSize;
        CHECK_AND_BREAK_ERR_LOG(parcelSize <= parcelCapacity,
            "exceed capacity, truncate it. "
            "elementSize: %{public}zu, index: %{public}zu, resultList: %{public}zu, originalSize: %{public}zu, "
            "parcelSize: %{public}zu, parcelCapacity: %{public}zu",
            elementSize,
            index,
            resultList.size(),
            originalSize,
            parcelSize,
            parcelCapacity);
        resultList.emplace_back(this->cloudPhotosUploadRecord[index]);
    }
    // No need to truncate body.
    CHECK_AND_RETURN_RET(resultList.size() != originalSize, true);
    this->cloudPhotosUploadRecord = resultList;
    MEDIA_INFO_LOG("TruncateDataBy200K completed, "
        "resultList: %{public}zu, originalSize: %{public}zu, "
        "parcelSize: %{public}zu, parcelCapacity: %{public}zu",
        resultList.size(),
        originalSize,
        parcelSize,
        parcelCapacity);
    return true;
}
}  // namespace OHOS::Media::CloudSync