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

#include "media_itypes_utils.h"
#include "media_log.h"
#include "userfile_manager_types.h"

// namespace OHOS::ITypesUtil {
// using namespace OHOS::Media;
// using namespace OHOS::Media::CloudSync;
// template <>
// bool Marshalling(const CloudCheckData &cloudCheckData, MessageParcel &parcel)
// {
//     return ITypesUtil::Marshal(parcel, cloudCheckData.fileName, cloudCheckData.filePath, cloudCheckData.size);
// }

// template <>
// bool Unmarshalling(CloudCheckData &cloudCheckData, MessageParcel &parcel)
// {
//     std::string fileName;
//     std::string filePath;
//     int64_t size = 0;
//     if (!ITypesUtil::Unmarshal(parcel, fileName, filePath, size)) {
//         return false;
//     }
//     CloudCheckData tmpCloudCheckData;
//     tmpCloudCheckData.fileName = fileName;
//     tmpCloudCheckData.filePath = filePath;
//     tmpCloudCheckData.size = size;
//     cloudCheckData = tmpCloudCheckData;
//     return true;
// }

// template <>
// bool Marshalling(const CloudFileData &cloudFileData, MessageParcel &parcel)
// {
//     return ITypesUtil::Marshal(parcel, cloudFileData.fileName, cloudFileData.filePath, cloudFileData.size);
// }

// template <>
// bool Unmarshalling(CloudFileData &cloudFileData, MessageParcel &parcel)
// {
//     std::string fileName;
//     std::string filePath;
//     int64_t size = 0;
//     if (!ITypesUtil::Unmarshal(parcel, fileName, filePath, size)) {
//         return false;
//     }
//     CloudFileData tmpCloudFileData;
//     tmpCloudFileData.fileName = fileName;
//     tmpCloudFileData.filePath = filePath;
//     tmpCloudFileData.size = size;
//     return true;
// }

// template <>
// bool Marshalling(const CloudMetaData &cloudMetaData, MessageParcel &parcel)
// {
//     return ITypesUtil::Marshal(parcel,
//         cloudMetaData.cloudId,
//         cloudMetaData.size,
//         cloudMetaData.path,
//         cloudMetaData.fileName,
//         static_cast<int32_t>(cloudMetaData.type),
//         cloudMetaData.attachment);
// }

// template <>
// bool Unmarshalling(CloudMetaData &cloudMetaData, MessageParcel &parcel)
// {
//     std::string cloudId;
//     int64_t size;
//     std::string path;
//     std::string fileName;
//     int32_t type;
//     std::map<std::string, CloudFileData> attachment;
//     if (!ITypesUtil::Unmarshal(parcel, cloudId, size, path, fileName, type, attachment)) {
//         return false;
//     }
//     CloudMetaData tmpCloudMetaData;
//     tmpCloudMetaData.cloudId = cloudId;
//     tmpCloudMetaData.size = size;
//     tmpCloudMetaData.fileName = fileName;
//     tmpCloudMetaData.type = static_cast<MediaType>(type);
//     tmpCloudMetaData.attachment = attachment;

//     cloudMetaData = tmpCloudMetaData;
//     return true;
// }

// template <>
// bool Marshalling(const PhotoAlbumVo &photoAlbumVo, MessageParcel &parcel)
// {
//     return true;
// }

// template <>
// bool Unmarshalling(PhotoAlbumVo &photoAlbumVo, MessageParcel &parcel)
// {
//     return true;
// }

// template <>
// bool Marshalling(const PhotosVo &photosVo, MessageParcel &parcel)
// {
//     return ITypesUtil::Marshal(parcel,
//         photosVo.cloudId,
//         photosVo.size,
//         photosVo.path,
//         photosVo.fileName,
//         static_cast<int32_t>(photosVo.type),
//         photosVo.attachment);
// }

// template <>
// bool Unmarshalling(PhotosVo &photosVo, MessageParcel &parcel)
// {
//     std::string cloudId;
//     int64_t size;
//     std::string path;
//     std::string fileName;
//     int32_t type;
//     // std::map<std::string, CloudFileData> attachment;
//     // if (!ITypesUtil::Unmarshal(parcel, cloudId, size, path, fileName, type, attachment)) {
//     //     return false;
//     // }
//     PhotosVo tmpPhotosVo;
//     tmpPhotosVo.cloudId = cloudId;
//     tmpPhotosVo.size = size;
//     tmpPhotosVo.fileName = fileName;
//     tmpPhotosVo.type = static_cast<MediaType>(type);
//     // tmpPhotosVo.attachment = attachment;

//     photosVo = tmpPhotosVo;
//     return true;
// }
// }  // namespace OHOS::ITypesUtil