/*
* Copyright (C) 2022 Huawei Device Co., Ltd.
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
#ifndef FRAMEWORKS_SERVICES_MEDIA_MTP_INCLUDE_MTP_MEDIALIBRARY_MANAGER_H_
#define FRAMEWORKS_SERVICES_MEDIA_MTP_INCLUDE_MTP_MEDIALIBRARY_MANAGER_H_

#include <filesystem>
#include <sys/stat.h>
#include "avmetadatahelper.h"
#include "datashare_helper.h"
#include "file_asset.h"
#include "mtp_operation_context.h"
#include "object_info.h"
#include "property.h"

namespace OHOS {
namespace Media {
namespace sf = std::filesystem;
class MtpMedialibraryManager {
public:
    MtpMedialibraryManager();
    ~MtpMedialibraryManager();
    static std::shared_ptr<MtpMedialibraryManager> GetInstance();
    void Init(const sptr<IRemoteObject> &token);
    void Clear();
    void SetContext(const std::shared_ptr<MtpOperationContext> &context);
    int32_t GetHandles(int32_t parentId, std::vector<int> &outHandles, MediaType mediaType = MEDIA_TYPE_DEFAULT);
    int32_t GetHandles(const std::shared_ptr<MtpOperationContext> &context, std::shared_ptr<UInt32List> &outHandles);
    int32_t GetObjectInfo(const std::shared_ptr<MtpOperationContext> &context,
        std::shared_ptr<ObjectInfo> &outObjectInfo);
    int32_t GetFd(const std::shared_ptr<MtpOperationContext> &context, int32_t &outFd);
    int32_t GetThumb(const std::shared_ptr<MtpOperationContext> &context, std::shared_ptr<UInt8List> &outThumb);
    int32_t SendObjectInfo(const std::shared_ptr<MtpOperationContext> &context,
        uint32_t &outStorageID, uint32_t &outParent, uint32_t &outHandle);
    int32_t GetPathById(const int32_t id, std::string &outPath);
    int32_t GetIdByPath(const std::string &path, uint32_t &outId);
    int32_t MoveObject(const std::shared_ptr<MtpOperationContext> &context);
    int32_t CopyObject(const std::shared_ptr<MtpOperationContext> &context, uint32_t &outObjectHandle);
    int32_t DeleteObject(const std::shared_ptr<MtpOperationContext> &context);
    int32_t SetObjectPropValue(const std::shared_ptr<MtpOperationContext> &context);
    int32_t CloseFd(const std::shared_ptr<MtpOperationContext> &context, int32_t fd);
    int32_t CloseFdForGet(const std::shared_ptr<MtpOperationContext> &context, int32_t fd);
    int32_t GetObjectPropList(const std::shared_ptr<MtpOperationContext> &context,
        std::shared_ptr<std::vector<Property>> &outProps);
    int32_t GetObjectPropValue(const std::shared_ptr<MtpOperationContext> &context,
        uint64_t &outIntVal, uint128_t &outLongVal, std::string &outStrVal);
    void CondCloseFd(const bool condition, const int fd);
    int32_t GetPictureThumb(const std::shared_ptr<MtpOperationContext> &context,
        std::shared_ptr<UInt8List> &outThumb);
    int32_t GetVideoThumb(const std::shared_ptr<MtpOperationContext> &context,
        std::shared_ptr<UInt8List> &outThumb);
    void DeleteCanceledObject(uint32_t id);
private:
    int32_t SetObjectInfo(const std::unique_ptr<FileAsset> &fileAsset, std::shared_ptr<ObjectInfo> &outObjectInfo);
    int32_t SetObject(const std::shared_ptr<DataShare::DataShareResultSet> &resultSet,
        const std::shared_ptr<MtpOperationContext> &context, std::shared_ptr<ObjectInfo> &outObjectInfo);
    bool CompressImage(std::unique_ptr<PixelMap> &pixelMap, Size &size, std::vector<uint8_t> &data);
    int32_t GetAssetById(const int32_t id, std::shared_ptr<FileAsset> &outFileAsset);
    int32_t GetAssetByPath(const std::string &path, std::shared_ptr<FileAsset> &outFileAsset);
    int32_t GetAssetByPredicates(const DataShare::DataSharePredicates &predicates,
        std::shared_ptr<FileAsset> &outFileAsset);
    std::shared_ptr<DataShare::DataShareResultSet> GetAlbumInfo(const std::shared_ptr<MtpOperationContext> &context,
        bool isHandle);
    std::shared_ptr<DataShare::DataShareResultSet> GetPhotosInfo(const std::shared_ptr<MtpOperationContext> &context,
        bool isHandle);
    int32_t HaveMovingPhotesHandle(const std::shared_ptr<DataShare::DataShareResultSet> resultSet,
        std::shared_ptr<UInt32List> &outHandles, const uint32_t parent);
    uint32_t GetSizeFromOfft(const off_t &size);
    std::vector<std::string> GetBurstKeyFromPhotosInfo();
private:
    static std::mutex mutex_;
    static std::shared_ptr<MtpMedialibraryManager> instance_;
    static std::shared_ptr<DataShare::DataShareHelper> dataShareHelper_;
    std::shared_ptr<MtpOperationContext> context_ = nullptr;
};
} // namespace Media
} // namespace OHOS
#endif  // FRAMEWORKS_SERVICES_MEDIA_MTP_INCLUDE_MTP_MEDIALIBRARY_MANAGER_H_
