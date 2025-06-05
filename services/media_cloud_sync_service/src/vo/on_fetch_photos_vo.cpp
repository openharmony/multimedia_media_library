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

#include "on_fetch_photos_vo.h"

#include <sstream>

#include "media_itypes_utils.h"

namespace OHOS::Media::CloudSync {
bool OnFetchPhotosVo::MarshallingBasicInfo(Parcel &parcel) const
{
    parcel.WriteString(this->cloudId);
    parcel.WriteString(this->fileName);
    parcel.WriteString(this->fileSourcePath);
    parcel.WriteString(this->mimeType);
    parcel.WriteString(this->firstVisitTime);
    parcel.WriteString(this->detailTime);
    parcel.WriteString(this->frontCamera);
    parcel.WriteString(this->editDataCamera);
    parcel.WriteString(this->title);
    parcel.WriteString(this->relativePath);
    parcel.WriteString(this->virtualPath);
    parcel.WriteString(this->dateYear);
    parcel.WriteString(this->dateMonth);
    parcel.WriteString(this->dateDay);
    parcel.WriteString(this->shootingMode);
    parcel.WriteString(this->shootingModeTag);
    parcel.WriteString(this->burstKey);
    parcel.WriteString(this->localPath);
    parcel.WriteString(this->position);
    parcel.WriteString(this->description);
    parcel.WriteString(this->source);
    return true;
}

bool OnFetchPhotosVo::MarshallingAttributesInfo(Parcel &parcel) const
{
    parcel.WriteInt32(this->fileId);
    parcel.WriteInt32(this->mediaType);
    parcel.WriteInt32(this->fileType);
    parcel.WriteInt32(this->rotation);
    parcel.WriteInt32(this->photoHeight);
    parcel.WriteInt32(this->photoWidth);
    parcel.WriteInt32(this->duration);
    parcel.WriteInt32(this->hidden);
    parcel.WriteInt32(this->burstCoverLevel);
    parcel.WriteInt32(this->subtype);
    parcel.WriteInt32(this->originalSubtype);
    parcel.WriteInt32(this->dynamicRangeType);
    parcel.WriteInt32(this->movingPhotoEffectMode);
    parcel.WriteInt32(this->supportedWatermarkType);
    parcel.WriteInt32(this->strongAssociation);
    parcel.WriteInt64(this->fixVersion);
    parcel.WriteInt64(this->version);
    parcel.WriteInt64(this->size);
    parcel.WriteInt64(this->lcdSize);
    parcel.WriteInt64(this->thmSize);
    parcel.WriteInt64(this->createTime);
    parcel.WriteInt64(this->metaDateModified);
    parcel.WriteInt64(this->dualEditTime);
    parcel.WriteInt64(this->editTime);
    parcel.WriteInt64(this->editedTimeMs);
    parcel.WriteInt64(this->recycledTime);
    parcel.WriteInt64(this->hiddenTime);
    parcel.WriteInt64(this->coverPosition);
    parcel.WriteInt32(this->isRectificationCover);
    parcel.WriteBool(this->isDelete);
    return true;
}

bool OnFetchPhotosVo::ReadBasicInfo(Parcel &parcel)
{
    parcel.ReadString(this->cloudId);
    parcel.ReadString(this->fileName);
    parcel.ReadString(this->fileSourcePath);
    parcel.ReadString(this->mimeType);
    parcel.ReadString(this->firstVisitTime);
    parcel.ReadString(this->detailTime);
    parcel.ReadString(this->frontCamera);
    parcel.ReadString(this->editDataCamera);
    parcel.ReadString(this->title);
    parcel.ReadString(this->relativePath);
    parcel.ReadString(this->virtualPath);
    parcel.ReadString(this->dateYear);
    parcel.ReadString(this->dateMonth);
    parcel.ReadString(this->dateDay);
    parcel.ReadString(this->shootingMode);
    parcel.ReadString(this->shootingModeTag);
    parcel.ReadString(this->burstKey);
    parcel.ReadString(this->localPath);
    parcel.ReadString(this->position);
    parcel.ReadString(this->description);
    parcel.ReadString(this->source);
    return true;
}

bool OnFetchPhotosVo::ReadAttributesInfo(Parcel &parcel)
{
    parcel.ReadInt32(this->fileId);
    parcel.ReadInt32(this->mediaType);
    parcel.ReadInt32(this->fileType);
    parcel.ReadInt32(this->rotation);
    parcel.ReadInt32(this->photoHeight);
    parcel.ReadInt32(this->photoWidth);
    parcel.ReadInt32(this->duration);
    parcel.ReadInt32(this->hidden);
    parcel.ReadInt32(this->burstCoverLevel);
    parcel.ReadInt32(this->subtype);
    parcel.ReadInt32(this->originalSubtype);
    parcel.ReadInt32(this->dynamicRangeType);
    parcel.ReadInt32(this->movingPhotoEffectMode);
    parcel.ReadInt32(this->supportedWatermarkType);
    parcel.ReadInt32(this->strongAssociation);
    parcel.ReadInt64(this->fixVersion);
    parcel.ReadInt64(this->version);
    parcel.ReadInt64(this->size);
    parcel.ReadInt64(this->lcdSize);
    parcel.ReadInt64(this->thmSize);
    parcel.ReadInt64(this->createTime);
    parcel.ReadInt64(this->metaDateModified);
    parcel.ReadInt64(this->dualEditTime);
    parcel.ReadInt64(this->editTime);
    parcel.ReadInt64(this->editedTimeMs);
    parcel.ReadInt64(this->recycledTime);
    parcel.ReadInt64(this->hiddenTime);
    parcel.ReadInt64(this->coverPosition);
    parcel.ReadInt32(this->isRectificationCover);
    parcel.ReadBool(this->isDelete);
    return true;
}

bool OnFetchPhotosVo::Unmarshalling(MessageParcel &parcel)
{
    this->ReadBasicInfo(parcel);
    this->ReadAttributesInfo(parcel);
    parcel.ReadBool(this->hasAttributes);
    parcel.ReadBool(this->hasproperties);
    parcel.ReadBool(this->isFavorite);
    parcel.ReadBool(this->isRecycle);
    IPC::ITypeMediaUtil::Unmarshalling<std::string>(this->sourceAlbumIds, parcel);
    return true;
}

bool OnFetchPhotosVo::Marshalling(MessageParcel &parcel) const
{
    this->MarshallingBasicInfo(parcel);
    this->MarshallingAttributesInfo(parcel);
    parcel.WriteBool(this->hasAttributes);
    parcel.WriteBool(this->hasproperties);
    parcel.WriteBool(this->isFavorite);
    parcel.WriteBool(this->isRecycle);
    IPC::ITypeMediaUtil::Marshalling<std::string>(this->sourceAlbumIds, parcel);
    return true;
}

void OnFetchPhotosVo::GetBasicInfo(std::stringstream &ss) const
{
    ss << "\"cloudId\": \"" << cloudId << "\","
       << "\"mimeType\": \"" << mimeType << "\","
       << "\"firstVisitTime\": \"" << firstVisitTime << "\","
       << "\"detailTime\": \"" << detailTime << "\","
       << "\"frontCamera\": \"" << frontCamera << "\","
       << "\"editDataCamera\": \"" << editDataCamera << "\","
       << "\"relativePath\": \"" << relativePath << "\","
       << "\"virtualPath\": \"" << virtualPath << "\","
       << "\"dateYear\": \"" << dateYear << "\","
       << "\"dateMonth\": \"" << dateMonth << "\","
       << "\"dateDay\": \"" << dateDay << "\","
       << "\"shootingMode\": \"" << shootingMode << "\","
       << "\"shootingModeTag\": \"" << shootingModeTag << "\","
       << "\"burstKey\": \"" << burstKey << "\","
       << "\"fileId\": \"" << fileId << "\","
       << "\"mediaType\": \"" << mediaType << "\","
       << "\"fileType\": \"" << fileType << "\","
       << "\"rotation\": \"" << rotation << "\","
       << "\"fixVersion\": \"" << fixVersion << "\","
       << "\"photoHeight\": \"" << photoHeight << "\","
       << "\"photoWidth\": \"" << photoWidth << "\","
       << "\"duration\": \"" << duration << "\","
       << "\"hidden\": \"" << hidden << "\",";
    return;
}

void OnFetchPhotosVo::GetAttributesInfo(std::stringstream &ss) const
{
    ss << "\"burstCoverLevel\": \"" << burstCoverLevel << "\","
       << "\"subtype\": \"" << subtype << "\","
       << "\"originalSubtype\": \"" << originalSubtype << "\","
       << "\"dynamicRangeType\": \"" << dynamicRangeType << "\","
       << "\"movingPhotoEffectMode\": \"" << movingPhotoEffectMode << "\","
       << "\"version\": \"" << version << "\","
       << "\"size\": \"" << size << "\","
       << "\"lcdSize\": \"" << lcdSize << "\","
       << "\"thmSize\": \"" << thmSize << "\","
       << "\"createTime\": \"" << createTime << "\","
       << "\"metaDateModified\": \"" << metaDateModified << "\","
       << "\"dualEditTime\": \"" << dualEditTime << "\","
       << "\"editTime\": \"" << editTime << "\","
       << "\"editedTimeMs\": \"" << editedTimeMs << "\","
       << "\"recycledTime\": \"" << recycledTime << "\","
       << "\"hiddenTime\": \"" << hiddenTime << "\","
       << "\"coverPosition\": \"" << coverPosition << "\","
       << "\"isRectificationCover\": \"" << isRectificationCover << "\","
       << "\"isDelete\": \"" << isDelete << "\","
       << "\"hasAttributes\": \"" << hasAttributes << "\","
       << "\"hasproperties\": \"" << hasproperties << "\","
       << "\"isFavorite\": \"" << isFavorite << "\","
       << "\"isRecycle\": \"" << isRecycle << "\","
       << "\"description\": \"" << description << "\","
       << "\"DeviceName\": \"" << source << "\",";
    return;
}

std::string OnFetchPhotosVo::ToString() const
{
    std::stringstream ss;
    ss << "{";
    this->GetBasicInfo(ss);
    this->GetAttributesInfo(ss);
    ss << "AlbumIds:[";
    for (uint32_t i = 0; i < sourceAlbumIds.size(); i++) {
        if (i != sourceAlbumIds.size() - 1) {
            ss << "\"" << sourceAlbumIds[i] << "\",";
            continue;
        }
        ss << "\"" << sourceAlbumIds[i] << "\"";
    }
    ss << "]}";
    return ss.str();
}
}  // namespace OHOS::Media::CloudSync