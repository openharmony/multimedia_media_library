/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "medialibrarymediaassetscontrollerservice3_fuzzer.h"

#include <cstdint>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "media_assets_controller_service.h"
#undef private
#include "user_define_ipc.h"
#include "asset_change_vo.h"
#include "add_image_vo.h"
#include "save_camera_photo_vo.h"
#include "get_assets_vo.h"
#include "create_asset_vo.h"
#include "modify_assets_vo.h"
#include "cloud_enhancement_vo.h"

#include "media_old_photos_column.h"
#include "media_column.h"
#include "message_parcel.h"
#include "rdb_utils.h"

namespace OHOS {
using namespace std;
using namespace OHOS::Media;
static const int32_t NUM_BYTES = 8;
FuzzedDataProvider* FDP;
shared_ptr<MediaAssetsControllerService> mediaAssetsControllerService = nullptr;

static void AssetChangeAddImageFuzzer()
{
    AddImageReqBody reqBody;
    reqBody.fileId = FDP->ConsumeIntegral<int32_t>();
    reqBody.photoId = "20250527162718617";
    reqBody.deferredProcType = FDP->ConsumeIntegral<int32_t>();
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->AssetChangeAddImage(data, reply);
}

static void SetCameraShotKeyFuzzer()
{
    AssetChangeReqBody reqBody;
    reqBody.fileId = FDP->ConsumeIntegral<int32_t>();
    reqBody.cameraShotKey = "shot_key_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx_test";
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->SetCameraShotKey(data, reply);
}

static void SaveCameraPhotoFuzzer()
{
    SaveCameraPhotoReqBody reqBody;
    reqBody.fileId = FDP->ConsumeIntegral<int32_t>();
    reqBody.needScan = FDP->ConsumeBool();
    reqBody.path = "file//media/Photo/";
    reqBody.photoSubType = 1;
    reqBody.imageFileType = 1;
    reqBody.supportedWatermarkType = FDP->ConsumeIntegral<int32_t>();
    reqBody.cameraShotKey = "Set";
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->SaveCameraPhoto(data, reply);
}

static void DiscardCameraPhotoFuzzer()
{
    AssetChangeReqBody reqBody;
    reqBody.fileId = FDP->ConsumeIntegral<int32_t>();
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->DiscardCameraPhoto(data, reply);
}

static void SetEffectModeFuzzer()
{
    AssetChangeReqBody reqBody;
    reqBody.fileId = FDP->ConsumeIntegral<int32_t>();
    reqBody.effectMode = FDP->ConsumeIntegral<int32_t>();
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->SetEffectMode(data, reply);
}

static void SetOrientationFuzzer()
{
    AssetChangeReqBody reqBody;
    reqBody.fileId = FDP->ConsumeIntegral<int32_t>();
    reqBody.orientation = FDP->ConsumeIntegral<int32_t>();
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->SetOrientation(data, reply);
}

static void SetVideoEnhancementAttrFuzzer()
{
    AssetChangeReqBody reqBody;
    reqBody.fileId = FDP->ConsumeIntegral<int32_t>();
    reqBody.photoId = "202410011800";
    reqBody.path = "file//media/Photo/";
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->SetVideoEnhancementAttr(data, reply);
}

static void SetSupportedWatermarkTypeFuzzer()
{
    AssetChangeReqBody reqBody;
    reqBody.fileId = FDP->ConsumeIntegral<int32_t>();
    reqBody.watermarkType = FDP->ConsumeIntegral<int32_t>();
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->SetSupportedWatermarkType(data, reply);
}

static void SetCompositeDisplayModeFuzzer()
{
    AssetChangeReqBody reqBody;
    reqBody.fileId = FDP->ConsumeIntegral<int32_t>();
    reqBody.compositeDisplayMode = FDP->ConsumeIntegral<int32_t>();
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->SetCompositeDisplayMode(data, reply);
}

static void DuplicateAssetsFuzzer()
{
    GetAssetsReqBody reqBody;
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->GetAllDuplicateAssets(data, reply);
    mediaAssetsControllerService->GetDuplicateAssetsToDelete(data, reply);
}

static void CreateAssetFuzzer()
{
    CreateAssetReqBody reqBody;
    reqBody.mediaType = MEDIA_TYPE_IMAGE;
    reqBody.title = FDP->ConsumeBytesAsString(NUM_BYTES);
    reqBody.extension = FDP->ConsumeBytesAsString(NUM_BYTES);
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->PublicCreateAsset(data, reply);
    CreateAssetReqBody sysReqBody;
    sysReqBody.mediaType = MEDIA_TYPE_IMAGE;
    sysReqBody.photoSubtype = FDP->ConsumeIntegral<int32_t>();
    sysReqBody.displayName = FDP->ConsumeBytesAsString(NUM_BYTES);
    sysReqBody.cameraShotKey = FDP->ConsumeBytesAsString(NUM_BYTES);
    MessageParcel sysData;
    MessageParcel sysReply;
    sysReqBody.Marshalling(sysData);
    mediaAssetsControllerService->SystemCreateAsset(sysData, sysReply);
}

static void CreateAssetForAppFuzzer()
{
    CreateAssetForAppReqBody reqBody;
    reqBody.tokenId = FDP->ConsumeIntegral<int32_t>();
    reqBody.mediaType = MEDIA_TYPE_IMAGE;
    reqBody.photoSubtype = static_cast<int32_t>(PhotoSubType::DEFAULT);
    reqBody.title = FDP->ConsumeBytesAsString(NUM_BYTES);
    reqBody.extension = FDP->ConsumeBytesAsString(NUM_BYTES);
    reqBody.appId = FDP->ConsumeBytesAsString(NUM_BYTES);
    reqBody.packageName = FDP->ConsumeBytesAsString(NUM_BYTES);
    reqBody.bundleName = FDP->ConsumeBytesAsString(NUM_BYTES);
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->PublicCreateAssetForApp(data, reply);
    mediaAssetsControllerService->SystemCreateAssetForApp(data, reply);
    reqBody.ownerAlbumId = to_string(FDP->ConsumeIntegral<int32_t>());
    MessageParcel album_data;
    MessageParcel album_reply;
    reqBody.Marshalling(album_data);
    mediaAssetsControllerService->CreateAssetForAppWithAlbum(album_data, album_reply);
}

static void SetAssetTitleFuzzer()
{
    ModifyAssetsReqBody reqBody;
    reqBody.fileIds.push_back(FDP->ConsumeIntegral<int32_t>());
    reqBody.title = FDP->ConsumeBytesAsString(NUM_BYTES);
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->SetAssetTitle(data, reply);
}

static void SubmitCloudEnhancementTasksFuzzer()
{
    CloudEnhancementReqBody reqBody;
    reqBody.hasCloudWatermark = FDP->ConsumeBool();
    reqBody.triggerMode = 1;
    reqBody.fileUris = { "file://media/Photo/" + to_string(FDP->ConsumeIntegral<int32_t>()) };
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->SubmitCloudEnhancementTasks(data, reply);
    mediaAssetsControllerService->PrioritizeCloudEnhancementTask(data, reply);
    mediaAssetsControllerService->CancelCloudEnhancementTasks(data, reply);
    mediaAssetsControllerService->CancelAllCloudEnhancementTasks(data, reply);
    mediaAssetsControllerService->SyncCloudEnhancementTaskStatus(data, reply);
}

static void MediaAssetsControllerService3Fuzzer()
{
    AssetChangeAddImageFuzzer();
    SetCameraShotKeyFuzzer();
    SaveCameraPhotoFuzzer();
    DiscardCameraPhotoFuzzer();
    SetEffectModeFuzzer();
    SetOrientationFuzzer();
    SetVideoEnhancementAttrFuzzer();
    SetSupportedWatermarkTypeFuzzer();
    SetCompositeDisplayModeFuzzer();
    DuplicateAssetsFuzzer();
    CreateAssetFuzzer();
    CreateAssetForAppFuzzer();
    SetAssetTitleFuzzer();
    SubmitCloudEnhancementTasksFuzzer();
}

static void Init()
{
    OHOS::mediaAssetsControllerService =
        make_shared<MediaAssetsControllerService>();
}
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::Init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }
    FuzzedDataProvider fdp(data, size);
    OHOS::FDP = &fdp;
    OHOS::MediaAssetsControllerService3Fuzzer();
    return 0;
}