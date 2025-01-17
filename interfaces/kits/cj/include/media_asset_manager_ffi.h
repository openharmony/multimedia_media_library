/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#ifndef MEDIA_ASSET_MANAGER_IMPL_H
#define MEDIA_ASSET_MANAGER_IMPL_H

#include <mutex>
#include <vector>
#include <map>

#include "data_ability_helper.h"
#include "data_ability_observer_stub.h"
#include "data_ability_predicates.h"
#include "media_file_utils.h"
#include "photo_accesshelper_impl.h"

namespace OHOS {
namespace Media {
enum class MultiStagesCapturePhotoStatus {
    QUERY_INNER_FAIL = 0,
    HIGH_QUALITY_STATUS,
    LOW_QUALITY_STATUS,
};

enum class NotifyMode : int32_t {
    FAST_NOTIFY = 0,
    WAIT_FOR_HIGH_QUALITY,
};

enum class CompatibleMode {
    ORIGINAL_FORMAT_MODE = 0,
    COMPATIBLE_FORMAT_MODE = 1,
};

struct AssetHandler {
    std::string photoId;
    std::string requestId;
    std::string requestUri;
    std::string destUri;
    int64_t dataHandler;
    ReturnDataType returnDataType;
    NotifyMode notifyMode = NotifyMode::FAST_NOTIFY;
    SourceMode sourceMode = SourceMode::ORIGINAL_MODE;
    CompatibleMode compatibleMode = CompatibleMode::ORIGINAL_FORMAT_MODE;
    MultiStagesCapturePhotoStatus photoQuality = MultiStagesCapturePhotoStatus::HIGH_QUALITY_STATUS;
    bool needsExtraInfo = false;

    AssetHandler(const std::string &photoId, const std::string &requestId, const std::string &uri,
        int64_t funcId, ReturnDataType returnDataType)
        : photoId(photoId), requestId(requestId),
        requestUri(uri), dataHandler(funcId), returnDataType(returnDataType) {}
};

struct RetProgressValue {
    int32_t progress;
    int32_t type;
    std::string errorMsg;
};

struct ProgressHandler {
    std::string requestId;
    RetProgressValue retProgressValue;
    int64_t progressFunc;
    ProgressHandler(const std::string &requestId,
        RetProgressValue &retProgressValue) : requestId(requestId),
        retProgressValue(retProgressValue) {}
};

class MultiStagesTaskObserver : public DataShare::DataShareObserver {
public:
    MultiStagesTaskObserver(int fileId)
        : fileId_(fileId) {};
    void OnChange(const ChangeInfo &changelnfo) override;
private:
    int fileId_;
};

struct WriteData {
    std::string requestUri;
    std::string destUri;
    bool isSource;
    CompatibleMode compatibleMode;
};

struct MediaAssetManagerContext {
    int fileId = -1; // default value of request file id
    std::string photoUri;
    std::string photoId;
    std::string displayName;
    std::string photoPath;
    std::string requestId;
    std::string destUri;
    DeliveryMode deliveryMode;
    SourceMode sourceMode;
    ReturnDataType returnDataType;
    PhotoSubType subType;
    bool hasReadPermission;
    bool needsExtraInfo = true;
    bool hasProcessPhoto;
    int64_t dataHandler;
    AssetHandler *assetHandler = nullptr;
    CompatibleMode compatibleMode = CompatibleMode::ORIGINAL_FORMAT_MODE;
    MultiStagesCapturePhotoStatus photoQuality = MultiStagesCapturePhotoStatus::HIGH_QUALITY_STATUS;
};

class MediaAssetManagerImpl {
public:
    static bool ParseRequestMediaArgs(int64_t photoAssetId,
    RequestOptions &requestOptions, std::unique_ptr<MediaAssetManagerContext> &asyncContext);
    static char* RequestImage(int64_t contextId, int64_t photoAssetId,
        RequestOptions requestOptions, int64_t funcId, int32_t &errCode);
    static char* RequestImageData(int64_t contextId, int64_t photoAssetId,
        RequestOptions requestOptions, int64_t funcId, int32_t &errCode);
    static char* RequestMovingPhoto(int64_t contextId, int64_t photoAssetId,
        RequestOptions requestOptions, int64_t funcId, int32_t &errCode);
    static char* RequestVideoFile(int64_t contextId, int64_t photoAssetId,
        RequestOptions requestOptions, char* fileUri, int64_t funcId, int32_t &errCode);
    static void CancelRequest(int64_t contextId, char* cRequestId, int32_t &errCode);
    static int64_t LoadMovingPhoto(int64_t contextId, char* cImageFileUri, char* cVideoFileUri, int32_t &errCode);
    static void OnHandleRequestImage(std::unique_ptr<MediaAssetManagerContext> &asyncContext);
    static MultiStagesCapturePhotoStatus QueryPhotoStatus(int fileId, const std::string& photoUri,
        std::string &photoId, bool hasReadPermission);
    static void NotifyDataPreparedWithoutRegister(std::unique_ptr<MediaAssetManagerContext> &asyncContext);
    static void RegisterTaskObserver(std::unique_ptr<MediaAssetManagerContext> &asyncContext);
    static void ProcessImage(const int fileId, const int deliveryMode);
    static void GetByteArrayObject(const std::string &requestUri, MediaObject &mediaObject, bool isSource);
    static void GetImageSourceObject(const std::string &requestUri, MediaObject &mediaObject, bool isSource);
    static void GetMovingPhotoObject(const std::string &requestUri, SourceMode sourceMode, MediaObject &mediaObject);
    static void SendFile(MediaObject &mediaObject, WriteData &writeData, int srcFd, int destFd, off_t fileSize);
    static int32_t GetFdFromSandBoxUri(const std::string &sandBoxUri);
    static void WriteDataToDestPath(WriteData &writeData, MediaObject &mediaObject, std::string requestId);
    static void NotifyMediaDataPrepared(AssetHandler *assetHandler);
    static void NotifyOnProgress(int32_t type, int32_t progress, std::string requestId);
    static void OnHandleRequestVideo(std::unique_ptr<MediaAssetManagerContext> &asyncContext);
    static void OnHandleProgress(unique_ptr<MediaAssetManagerContext> &asyncContext);
    static void CancelProcessImage(const std::string &photoId);

    std::mutex sMediaAssetMutex_;
};
}
}
#endif