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

#include "medialibrarymediaassetscontrollerservice2_fuzzer.h"

#include <cstdint>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "media_assets_controller_service.h"
#include "media_analysis_data_controller_service.h"
#undef private
#include "user_define_ipc.h"
#include "get_assets_vo.h"
#include "request_edit_data_vo.h"
#include "is_edited_vo.h"
#include "start_asset_analysis_vo.h"
#include "grant_photo_uri_permission_vo.h"
#include "grant_photo_uris_permission_vo.h"
#include "cancel_photo_uri_permission_vo.h"
#include "stop_thumbnail_creation_task_vo.h"
#include "start_thumbnail_creation_task_vo.h"
#include "request_content_vo.h"
#include "get_cloud_enhancement_pair_vo.h"
#include "query_cloud_enhancement_task_state_vo.h"
#include "query_photo_vo.h"
#include "add_visit_count_vo.h"
#include "adapted_vo.h"
#include "grant_photo_uri_permission_inner_vo.h"
#include "cancel_photo_uri_permission_inner_vo.h"
#include "get_result_set_from_db_vo.h"
#include "get_result_set_from_photos_extend_vo.h"
#include "get_moving_photo_date_modified_vo.h"
#include "get_uri_from_filepath_vo.h"
#include "get_filepath_from_uri_vo.h"
#include "close_asset_vo.h"
#include "check_photo_uri_permission_inner_vo.h"
#include "get_uris_by_old_uris_inner_vo.h"
#include "restore_vo.h"
#include "stop_restore_vo.h"

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
shared_ptr<AnalysisData::MediaAnalysisDataControllerService> analysisDataControllerService = nullptr;

static void RequestEditDataFuzzer()
{
    RequestEditDataReqBody reqBody;
    reqBody.predicates.EqualTo("file_id", "1111111");
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->RequestEditData(data, reply);
}

static void IsEditedFuzzer()
{
    IsEditedReqBody reqBody;
    reqBody.fileId = 1;
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->IsEdited(data, reply);
}

static void StartAssetAnalysisFuzzer()
{
    StartAssetAnalysisReqBody reqBody;
    std::vector<std::string> fileIds{"111111", "222222", to_string(FDP->ConsumeIntegral<int32_t>())};
    reqBody.predicates.In("Photos.file_id", fileIds);
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    analysisDataControllerService->StartAssetAnalysis(data, reply);
}

static void GrantPhotoUriPermissionFuzzer()
{
    GrantUriPermissionReqBody reqBody;
    reqBody.tokenId = FDP->ConsumeIntegral<int64_t>();
    reqBody.srcTokenId = FDP->ConsumeIntegral<int64_t>();
    reqBody.fileId = FDP->ConsumeIntegral<int32_t>();
    reqBody.permissionType = FDP->ConsumeIntegral<int32_t>();
    reqBody.hideSensitiveType = FDP->ConsumeIntegral<int32_t>();
    reqBody.uriType = FDP->ConsumeIntegral<int32_t>();
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->GrantPhotoUriPermission(data, reply);
}

static void GrantPhotoUrisPermissionFuzzer()
{
    GrantUrisPermissionReqBody reqBody;
    reqBody.tokenId = FDP->ConsumeIntegral<int64_t>();
    reqBody.srcTokenId = FDP->ConsumeIntegral<int64_t>();
    reqBody.fileIds = {FDP->ConsumeIntegral<int32_t>()};
    reqBody.permissionType = FDP->ConsumeIntegral<int32_t>();
    reqBody.hideSensitiveType = FDP->ConsumeIntegral<int32_t>();
    reqBody.uriType = FDP->ConsumeIntegral<int32_t>();
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->GrantPhotoUrisPermission(data, reply);
}

static void CancelPhotoUriPermissionFuzzer()
{
    CancelUriPermissionReqBody reqBody;
    reqBody.tokenId = FDP->ConsumeIntegral<int64_t>();
    reqBody.srcTokenId = FDP->ConsumeIntegral<int64_t>();
    reqBody.fileId = FDP->ConsumeIntegral<int32_t>();
    reqBody.permissionType = FDP->ConsumeIntegral<int32_t>();
    reqBody.uriType = FDP->ConsumeIntegral<int32_t>();
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->CancelPhotoUriPermission(data, reply);
}

static void StartThumbnailCreationTaskFuzzer()
{
    StartThumbnailCreationTaskReqBody reqBody;
    reqBody.requestId = FDP->ConsumeIntegral<int32_t>();
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->StartThumbnailCreationTask(data, reply);
}

static void StopThumbnailCreationTaskFuzzer()
{
    StopThumbnailCreationTaskReqBody reqBody;
    reqBody.requestId = FDP->ConsumeIntegral<int32_t>();
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->StopThumbnailCreationTask(data, reply);
}

static void RequestContentFuzzer()
{
    RequestContentReqBody reqBody;
    reqBody.mediaId = to_string(FDP->ConsumeIntegral<int32_t>());
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->RequestContent(data, reply);
}

static void GetCloudEnhancementPairFuzzer()
{
    GetCloudEnhancementPairReqBody reqBody;
    reqBody.photoUri = FDP->ConsumeBytesAsString(NUM_BYTES);

    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->GetCloudEnhancementPair(data, reply);
}

static void QueryCloudEnhancementTaskStateFuzzer()
{
    QueryCloudEnhancementTaskStateReqBody reqBody;
    reqBody.photoUri = FDP->ConsumeBytesAsString(NUM_BYTES);

    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->QueryCloudEnhancementTaskState(data, reply);
}

static void QueryPhotoStatusFuzzer()
{
    QueryPhotoReqBody reqBody;
    reqBody.fileId = std::to_string(FDP->ConsumeIntegral<int32_t>());

    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->QueryPhotoStatus(data, reply);
}

static void LogMovingPhotoFuzzer()
{
    AdaptedReqBody reqBody;
    reqBody.adapted = FDP->ConsumeBool();

    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->LogMovingPhoto(data, reply);
}

static void AddAssetVisitCountFuzzer()
{
    AddAssetVisitCountReqBody reqBody;
    reqBody.fileId = FDP->ConsumeIntegral<int32_t>();
    reqBody.visitType = FDP->ConsumeIntegral<int32_t>();
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->AddAssetVisitCount(data, reply);
}

static void GrantPhotoUriPermissionInnerFuzzer()
{
    GrantUrisPermissionInnerReqBody reqBody;
    reqBody.tokenId = FDP->ConsumeIntegral<int64_t>();
    reqBody.srcTokenId = FDP->ConsumeIntegral<int64_t>();
    reqBody.fileIds = {FDP->ConsumeBytesAsString(NUM_BYTES)};
    reqBody.permissionTypes = {FDP->ConsumeIntegral<int32_t>()};
    reqBody.hideSensitiveType = FDP->ConsumeIntegral<int32_t>();
    reqBody.uriTypes = {FDP->ConsumeIntegral<int32_t>()};
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->GrantPhotoUriPermissionInner(data, reply);
}

static void CancelPhotoUriPermissionInnerFuzzer()
{
    CancelUriPermissionInnerReqBody reqBody;
    reqBody.targetTokenId = FDP->ConsumeIntegral<int64_t>();
    reqBody.srcTokenId = FDP->ConsumeIntegral<int64_t>();
    reqBody.fileIds = {FDP->ConsumeBytesAsString(NUM_BYTES)};
    reqBody.uriTypes = {FDP->ConsumeIntegral<int32_t>()};
    reqBody.permissionTypes = {{FDP->ConsumeBytesAsString(NUM_BYTES)}};
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->CancelPhotoUriPermissionInner(data, reply);
}

static void GetResultSetFromDbFuzzer()
{
    GetResultSetFromDbReqBody reqBody;
    reqBody.columnName = FDP->ConsumeBytesAsString(NUM_BYTES);
    reqBody.value = FDP->ConsumeBytesAsString(NUM_BYTES);
    reqBody.columns = {FDP->ConsumeBytesAsString(NUM_BYTES)};
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->GetResultSetFromDb(data, reply);
}

static void GetResultSetFromPhotosExtendFuzzer()
{
    GetResultSetFromPhotosExtendReqBody reqBody;
    reqBody.value = FDP->ConsumeBytesAsString(NUM_BYTES);
    reqBody.columns = {FDP->ConsumeBytesAsString(NUM_BYTES)};
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->GetResultSetFromPhotosExtend(data, reply);
}

static void GetMovingPhotoDateModifiedFuzzer()
{
    GetMovingPhotoDateModifiedReqBody reqBody;
    reqBody.fileId = to_string(FDP->ConsumeIntegral<int32_t>());

    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->GetMovingPhotoDateModified(data, reply);
}

static void GetFilePathFromUriFuzzer()
{
    GetFilePathFromUriReqBody reqBody;
    reqBody.virtualId = to_string(FDP->ConsumeIntegral<int32_t>());

    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->GetFilePathFromUri(data, reply);
}

static void GetUriFromFilePathFuzzer()
{
    GetUriFromFilePathReqBody reqBody;
    reqBody.tempPath = to_string(FDP->ConsumeIntegral<int32_t>());

    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->GetUriFromFilePath(data, reply);
}

static void CloseAssetFuzzer()
{
    CloseAssetReqBody reqBody;
    reqBody.uri = FDP->ConsumeBytesAsString(NUM_BYTES);

    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->CloseAsset(data, reply);
}

static void CheckUriPermissionInnerFuzzer()
{
    CheckUriPermissionInnerReqBody reqBody;
    reqBody.targetTokenId = FDP->ConsumeIntegral<int64_t>();
    reqBody.uriType = FDP->ConsumeBytesAsString(NUM_BYTES);
    reqBody.fileIds = {FDP->ConsumeBytesAsString(NUM_BYTES)};
    reqBody.columns = {FDP->ConsumeBytesAsString(NUM_BYTES)};
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->CheckUriPermissionInner(data, reply);
}

static void GetUrisByOldUrisInnerFuzzer()
{
    GetUrisByOldUrisInnerReqBody reqBody;
    reqBody.uris = {FDP->ConsumeBytesAsString(NUM_BYTES)};
    reqBody.columns.push_back(TabOldPhotosColumn::OLD_PHOTOS_TABLE + "." + "file_id");
    reqBody.columns.push_back(TabOldPhotosColumn::OLD_PHOTOS_TABLE + "." + "data");
    reqBody.columns.push_back(TabOldPhotosColumn::OLD_PHOTOS_TABLE + "." + "old_file_id");
    reqBody.columns.push_back(TabOldPhotosColumn::OLD_PHOTOS_TABLE + "." + "old_data");
    reqBody.columns.push_back(TabOldPhotosColumn::OLD_PHOTOS_TABLE + "." + "clone_sequence");
    reqBody.columns.push_back(PhotoColumn::PHOTOS_TABLE + "." + "display_name");
   
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->GetUrisByOldUrisInner(data, reply);
}

static void RestoreFuzzer()
{
    RestoreReqBody reqBody;
    reqBody.albumLpath = "/" + FDP->ConsumeBytesAsString(NUM_BYTES);
    reqBody.keyPath = FDP->ConsumeBytesAsString(NUM_BYTES);
    reqBody.bundleName = FDP->ConsumeBytesAsString(NUM_BYTES);
    reqBody.appName = FDP->ConsumeBytesAsString(NUM_BYTES);
    reqBody.appId = FDP->ConsumeBytesAsString(NUM_BYTES);
    reqBody.isDeduplication = FDP->ConsumeBool();
   
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->Restore(data, reply);
}

static void StopRestoreFuzzer()
{
    StopRestoreReqBody reqBody;
    reqBody.keyPath = FDP->ConsumeBytesAsString(NUM_BYTES);
   
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->StopRestore(data, reply);
}

static void GetAssetsFuzzer()
{
    GetAssetsReqBody reqBody;
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    OHOS::Media::IPC::IPCContext context(MessageOption(), 0);
    mediaAssetsControllerService->GetAssets(data, reply, context);
}

static void GetBurstAssetsFuzzer()
{
    GetAssetsReqBody reqBody;
    reqBody.burstKey = FDP->ConsumeBytesAsString(NUM_BYTES);
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    OHOS::Media::IPC::IPCContext context(MessageOption(), 0);
    mediaAssetsControllerService->GetBurstAssets(data, reply, context);
}

static void MediaAssetsControllerServiceSecondFuzzer()
{
    RequestEditDataFuzzer();
    IsEditedFuzzer();
    StartAssetAnalysisFuzzer();
    GrantPhotoUriPermissionFuzzer();
    GrantPhotoUrisPermissionFuzzer();
    CancelPhotoUriPermissionFuzzer();
    StartThumbnailCreationTaskFuzzer();
    StopThumbnailCreationTaskFuzzer();
    RequestContentFuzzer();
    GetCloudEnhancementPairFuzzer();
    QueryCloudEnhancementTaskStateFuzzer();
    QueryPhotoStatusFuzzer();
    LogMovingPhotoFuzzer();
    AddAssetVisitCountFuzzer();
    GrantPhotoUriPermissionInnerFuzzer();
    CancelPhotoUriPermissionInnerFuzzer();
    GetResultSetFromDbFuzzer();
    GetResultSetFromPhotosExtendFuzzer();
    GetMovingPhotoDateModifiedFuzzer();
    GetFilePathFromUriFuzzer();
    GetUriFromFilePathFuzzer();
    CloseAssetFuzzer();
    CheckUriPermissionInnerFuzzer();
    GetUrisByOldUrisInnerFuzzer();
    RestoreFuzzer();
    StopRestoreFuzzer();
    GetAssetsFuzzer();
    GetBurstAssetsFuzzer();
    
    MessageParcel dataParcel;
    MessageParcel reply;
    analysisDataControllerService->GetIndexConstructProgress(dataParcel, reply);
    mediaAssetsControllerService->PauseDownloadCloudMedia(dataParcel, reply);
    mediaAssetsControllerService->CancelDownloadCloudMedia(dataParcel, reply);
}

static void Init()
{
    OHOS::mediaAssetsControllerService =
        make_shared<MediaAssetsControllerService>();
    OHOS::analysisDataControllerService =
        make_shared<Media::AnalysisData::MediaAnalysisDataControllerService>();
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
    OHOS::MediaAssetsControllerServiceSecondFuzzer();
    return 0;
}