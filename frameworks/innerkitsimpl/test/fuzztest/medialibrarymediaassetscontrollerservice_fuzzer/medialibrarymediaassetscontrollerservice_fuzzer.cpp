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

#include "medialibrarymediaassetscontrollerservice_fuzzer.h"

#include <cstdint>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "media_assets_controller_service.h"
#undef private
#include "user_define_ipc.h"
#include "form_info_vo.h"
#include "commit_edited_asset_vo.h"
#include "trash_photos_vo.h"
#include "delete_photos_vo.h"
#include "delete_photos_completed_vo.h"
#include "asset_change_vo.h"
#include "submit_cache_vo.h"
#include "asset_change_vo.h"

#include "media_old_photos_column.h"
#include "media_column.h"
#include "message_parcel.h"
#include "rdb_utils.h"

namespace OHOS {
using namespace std;
using namespace OHOS::Media;

static const int32_t FORM_INFO_NUM_BYTES = 10;
static const string EDIT_DATA_VALUE = "{\"imageEffect\":{\"filters\":[{\"name\":\"InplaceSticker\",\"values\":"
    "{\"RESOURCE_DIRECTORY\":\"/sys_prod/resource/camera\",\"cameraPosition\":1}}],\"name\":\"imageEdit\"}}";

FuzzedDataProvider* FDP;
shared_ptr<MediaAssetsControllerService> mediaAssetsControllerService = nullptr;

static inline std::vector<std::string> FuzzVector()
{
    return {FDP->ConsumeBytesAsString(FORM_INFO_NUM_BYTES)};
}

static void FormInfoFuzzer()
{
    FormInfoReqBody reqBody;
    reqBody.formIds = FuzzVector();
    string uri = "file://media/Photo/" + to_string(FDP->ConsumeIntegral<int32_t>());
    vector<string> fileUris = { uri };
    reqBody.fileUris = fileUris;
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->SaveFormInfo(data, reply);
    mediaAssetsControllerService->SaveGalleryFormInfo(data, reply);
    mediaAssetsControllerService->RemoveFormInfo(data, reply);
    mediaAssetsControllerService->RemoveGalleryFormInfo(data, reply);
    mediaAssetsControllerService->UpdateGalleryFormInfo(data, reply);
}

static void CommitEditedAssetFuzzer()
{
    CommitEditedAssetReqBody reqBody;
    reqBody.editData = EDIT_DATA_VALUE;
    reqBody.fileId = FDP->ConsumeIntegral<int32_t>();
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->CommitEditedAsset(data, reply);
}

static void SysTrashPhotosFuzzer()
{
    TrashPhotosReqBody reqBody;
    auto uri = "file://media/Photo/" + to_string(FDP->ConsumeIntegral<int32_t>());
    std::vector<std::string> testUris = {uri};
    reqBody.uris = testUris;
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->SysTrashPhotos(data, reply);
    mediaAssetsControllerService->TrashPhotos(data, reply);
}

static void DeletePhotosFuzzer()
{
    DeletePhotosReqBody reqBody;
    std::vector<std::string> testUris = {"file://media/Photo/1/IMG_1748423699_000/IMG_20250528_171318.jpg", ""};
    reqBody.uris = testUris;
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->DeletePhotos(data, reply);
}

static void DeletePhotosCompletedFuzzer()
{
    DeletePhotosCompletedReqBody reqBody;
    reqBody.fileIds = {to_string(FDP->ConsumeIntegral<int32_t>())};
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->DeletePhotosCompleted(data, reply);
}

static void AssetChangeSetFavoriteFuzzer()
{
    AssetChangeReqBody reqBody;
    reqBody.fileId = FDP->ConsumeIntegral<int32_t>();
    reqBody.favorite = FDP->ConsumeBool();
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->AssetChangeSetFavorite(data, reply);
}

static void AssetChangeSetHiddenFuzzer()
{
    AssetChangeReqBody reqBody;
    reqBody.uri = "file://media/Photo/1/IMG_1748423699_000/IMG_20250528_171318.jpg";
    reqBody.hidden = FDP->ConsumeBool();
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->AssetChangeSetHidden(data, reply);
}

static void AssetChangeSetUserCommentFuzzer()
{
    AssetChangeReqBody reqBody;
    reqBody.fileId = FDP->ConsumeIntegral<int32_t>();
    reqBody.userComment = "user comment";
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->AssetChangeSetUserComment(data, reply);
}

static void AssetChangeSetLocationFuzzer()
{
    AssetChangeReqBody reqBody;
    reqBody.fileId = FDP->ConsumeIntegral<int32_t>();
    reqBody.path = "/data/local/tmp/IMG_1501924305_001.jpg";
    reqBody.latitude = FDP->ConsumeFloatingPoint<double>();
    reqBody.longitude = FDP->ConsumeFloatingPoint<double>();
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->AssetChangeSetLocation(data, reply);
}

static void AssetChangeSetTitleFuzzer()
{
    AssetChangeReqBody reqBody;
    reqBody.fileId = FDP->ConsumeIntegral<int32_t>();
    reqBody.title = "title_test";
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->AssetChangeSetTitle(data, reply);
}

static void AssetChangeSetEditDataFuzzer()
{
    AssetChangeReqBody reqBody;
    DataShare::DataShareValuesBucket valuesBucket;
    int fileId = FDP->ConsumeIntegral<int32_t>();
    valuesBucket.Put("file_id", fileId);
    std::string editData = "edit_data";
    valuesBucket.Put("edit_data", editData);
    reqBody.values = RdbDataShareAdapter::RdbUtils::ToValuesBucket(valuesBucket);

    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->AssetChangeSetEditData(data, reply);
}

static void AssetChangeSubmitCacheFuzzer()
{
    SubmitCacheReqBody reqBody;
    DataShare::DataShareValuesBucket valuesBucket;
    int fileId = FDP->ConsumeIntegral<int32_t>();
    valuesBucket.Put("file_id", fileId);
    std::string editData = "edit_data";
    valuesBucket.Put("edit_data", editData);
    reqBody.values = RdbDataShareAdapter::RdbUtils::ToValuesBucket(valuesBucket);
    reqBody.isWriteGpsAdvanced = FDP->ConsumeBool();

    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->AssetChangeSubmitCache(data, reply);
}

static void AssetChangeCreateAssetFuzzer()
{
    AssetChangeReqBody reqBody;
    reqBody.values.Put("extention", "jpg");
    reqBody.values.Put("media_type", MEDIA_TYPE_IMAGE);
    reqBody.values.Put("title", "20250602162718617");
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->AssetChangeCreateAsset(data, reply);
}

static void MediaAssetsControllerServiceFirstFuzzer()
{
    FormInfoFuzzer();
    CommitEditedAssetFuzzer();
    SysTrashPhotosFuzzer();
    DeletePhotosFuzzer();
    DeletePhotosCompletedFuzzer();
    AssetChangeSetFavoriteFuzzer();
    AssetChangeSetHiddenFuzzer();
    AssetChangeSetUserCommentFuzzer();
    AssetChangeSetLocationFuzzer();
    AssetChangeSetTitleFuzzer();
    AssetChangeSetEditDataFuzzer();
    AssetChangeSubmitCacheFuzzer();
    AssetChangeCreateAssetFuzzer();
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
    FuzzedDataProvider fdp(data, size);
    if (data == nullptr) {
        return 0;
    }
    OHOS::FDP = &fdp;
    OHOS::MediaAssetsControllerServiceFirstFuzzer();
    return 0;
}