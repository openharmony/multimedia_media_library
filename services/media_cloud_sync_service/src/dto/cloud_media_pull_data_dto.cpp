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

#define MLOG_TAG "MEDIA_CLOUD_DTO"

#include "cloud_media_pull_data_dto.h"

#include <sstream>

namespace OHOS::Media::CloudSync {
void CloudMediaPullDataDto::GetBasicInfo(std::stringstream &ss)
{
    ss << "\"cloudId\": \"" << cloudId << "\","
       << "\"basicIsDelete\": " << std::to_string(basicIsDelete) << ","
       << "\"basicSize\": " << basicSize << ","
       << "\"basicMimeType\": \"" << basicMimeType << "\","
       << "\"basicDeviceName\": \"" << basicDeviceName << "\","
       << "\"basicEditedTime\": " << basicEditedTime << ","
       << "\"basicCreatedTime\": " << basicCreatedTime << ","
       << "\"dateTaken\": " << dateTaken << ","
       << "\"basicIsFavorite\": " << basicIsFavorite << ","
       << "\"basicIsRecycle\": " << basicIsRecycle << ","
       << "\"basicRecycledTime\": " << basicRecycledTime << ","
       << "\"basicDescription\": \"" << basicDescription << "\","
       << "\"basicFileType\": " << basicFileType << ","
       << "\"basicCloudVersion\": " << basicCloudVersion << ","
       << "\"hasAttributes\": " << std::to_string(hasAttributes) << ","
       << "\"attributesMediaType\": " << attributesMediaType << ","
       << "\"duration\": " << duration << ","
       << "\"attributesHidden\": " << attributesHidden << ","
       << "\"attributesHiddenTime\": " << attributesHiddenTime << ","
       << "\"attributesRelativePath\": \"" << attributesRelativePath << "\","
       << "\"attributesVirtualPath\": \"" << attributesVirtualPath << "\","
       << "\"attributesMetaDateModified\": " << attributesMetaDateModified << ","
       << "\"attributesSubtype\": " << attributesSubtype << ",";
}
void CloudMediaPullDataDto::GetAttributesInfo(std::stringstream &ss)
{
    ss << "\"attributesBurstCoverLevel\": " << attributesBurstCoverLevel << ","
       << "\"attributesBurstKey\": \"" << attributesBurstKey << "\","
       << "\"attributesDateYear\": \"" << attributesDateYear << "\","
       << "\"attributesDateMonth\": \"" << attributesDateMonth << "\","
       << "\"attributesDateDay\": \"" << attributesDateDay << "\","
       << "\"attributesShootingMode\": \"" << attributesShootingMode << "\","
       << "\"attributesShootingModeTag\": \"" << attributesShootingModeTag << "\","
       << "\"attributesDynamicRangeType\": " << attributesDynamicRangeType << ","
       << "\"attributesFrontCamera\": " << attributesFrontCamera << ","
       << "\"attributesEditTime\": " << attributesEditTime << ","
       << "\"attributesOriginalSubtype\": " << attributesOriginalSubtype << ","
       << "\"attributesCoverPosition\": " << attributesCoverPosition << ","
       << "\"attributesIsRectificationCover\": " << attributesIsRectificationCover << ","
       << "\"attributesMovingPhotoEffectMode\": " << attributesMovingPhotoEffectMode << ","
       << "\"attributesSupportedWatermarkType\": " << attributesSupportedWatermarkType << ","
       << "\"attributesStrongAssociation\": " << attributesStrongAssociation << ","
       << "\"attributesFileId\": " << attributesFileId << ","
       << "\"attributesEditedTimeMs\": " << attributesEditedTimeMs << ","
       << "\"attributesFixVersion\": " << attributesFixVersion << ","
       << "\"attributesEditDataCamera\": \"" << attributesEditDataCamera << "\",";
}
void CloudMediaPullDataDto::GetPropertiesInfo(std::stringstream &ss)
{
    ss << "\"hasProperties\": " << std::to_string(hasProperties) << ","
       << "\"propertiesRotate\": " << propertiesRotate << ","
       << "\"propertiesHeight\": " << propertiesHeight << ","
       << "\"propertiesWidth\": " << propertiesWidth << ","
       << "\"propertiesFirstUpdateTime\": \"" << propertiesFirstUpdateTime << "\","
       << "\"propertiesDetailTime\": \"" << propertiesDetailTime << "\","
       << "\"localFileId\": " << localFileId << ","
       << "\"localPath\": \"" << localPath << "\","
       << "\"localSize\": " << localSize << ","
       << "\"lcdSize\": " << lcdSize << ","
       << "\"thmSize\": " << thmSize << ","
       << "\"localMediaType\": " << localMediaType << ","
       << "\"localDateAdded\": \"" << localDateAdded << "\","
       << "\"localDateModified\": \"" << localDateModified << "\","
       << "\"localDirty\": " << localDirty << ","
       << "\"localPosition\": " << localPosition << ","
       << "\"localOwnerAlbumId\": \"" << localOwnerAlbumId << "\","
       << "\"localOrientation\": " << localOrientation << ","
       << "\"localThumbState\": " << localThumbState;
}
void CloudMediaPullDataDto::GetCloudInfo(std::stringstream &ss)
{
    ss << "\"attributesCloudId\": \"" << attributesCloudId << "\","
       << "\"attributesOriginCloudId\": \"" << attributesOriginCloudId << "\",";
}
void CloudMediaPullDataDto::GetAlbumIds(std::stringstream &ss)
{
    ss << "[";
    for (uint32_t i = 0; i < attributesSrcAlbumIds.size(); ++i) {
        if (i != attributesSrcAlbumIds.size() - 1) {
            ss << "\"" << attributesSrcAlbumIds[i] << "\",";
            continue;
        }
        ss << "\"" << attributesSrcAlbumIds[i] << "\"";
    }
    ss << "],";
}
std::string CloudMediaPullDataDto::ToString()
{
    std::stringstream ss;
    ss << "{";
    this->GetBasicInfo(ss);
    this->GetAttributesInfo(ss);
    this->GetPropertiesInfo(ss);
    this->GetCloudInfo(ss);
    this->GetAlbumIds(ss);
    ss << "}";
    return ss.str();
}
}  // namespace OHOS::Media::CloudSync