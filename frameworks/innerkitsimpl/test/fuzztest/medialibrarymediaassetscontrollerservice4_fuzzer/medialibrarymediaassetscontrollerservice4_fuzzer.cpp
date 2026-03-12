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

#include "medialibrarymediaassetscontrollerservice4_fuzzer.h"

#include <cstdint>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "media_assets_controller_service.h"
#include "media_analysis_data_controller_service.h"
#undef private
#include "user_define_ipc.h"
#include "modify_assets_vo.h"
#include "get_asset_analysis_data_vo.h"
#include "clone_asset_vo.h"
#include "revert_to_original_vo.h"
#include "convert_format_vo.h"

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

static void SetAssetPendingFuzzer()
{
    ModifyAssetsReqBody reqBody;
    reqBody.fileIds.push_back(FDP->ConsumeIntegral<int32_t>());
    reqBody.pending = FDP->ConsumeIntegral<int32_t>();
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->SetAssetPending(data, reply);
}

static void SetAssetsFavoriteFuzzer()
{
    ModifyAssetsReqBody reqBody;
    reqBody.fileIds.push_back(FDP->ConsumeIntegral<int32_t>());
    reqBody.favorite = FDP->ConsumeIntegral<int32_t>();
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->SetAssetsFavorite(data, reply);
}

static void SetAssetsHiddenStatusFuzzer()
{
    ModifyAssetsReqBody reqBody;
    reqBody.fileIds.push_back(FDP->ConsumeIntegral<int32_t>());
    reqBody.hiddenStatus = FDP->ConsumeIntegral<int32_t>();
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->SetAssetsHiddenStatus(data, reply);
}

static void SetAssetsRecentShowStatusFuzzer()
{
    ModifyAssetsReqBody reqBody;
    reqBody.fileIds.push_back(FDP->ConsumeIntegral<int32_t>());
    reqBody.recentShowStatus = FDP->ConsumeIntegral<int32_t>();
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->SetAssetsRecentShowStatus(data, reply);
}

static void SetAssetsUserCommentFuzzer()
{
    ModifyAssetsReqBody reqBody;
    reqBody.fileIds.push_back(FDP->ConsumeIntegral<int32_t>());
    reqBody.userComment = FDP->ConsumeBytesAsString(NUM_BYTES);
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->SetAssetsUserComment(data, reply);
}

static void GetAssetAnalysisDataFuzzer()
{
    GetAssetAnalysisDataReqBody reqBody;
    reqBody.fileId = FDP->ConsumeIntegral<int32_t>();
    reqBody.language = "zh-Hans";
    reqBody.analysisType = FDP->ConsumeIntegral<int32_t>();
    reqBody.analysisTotal = FDP->ConsumeBool();
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    analysisDataControllerService->GetAssetAnalysisData(data, reply);
}

static void CloneAssetFuzzer()
{
    CloneAssetReqBody reqBody;
    reqBody.fileId = FDP->ConsumeIntegral<int32_t>();
    reqBody.displayName = FDP->ConsumeBytesAsString(NUM_BYTES);
    reqBody.title = FDP->ConsumeBytesAsString(NUM_BYTES);
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->CloneAsset(data, reply);
}

static void RevertToOriginalFuzzer()
{
    RevertToOriginalReqBody reqBody;
    reqBody.fileId = FDP->ConsumeIntegral<int32_t>();
    reqBody.fileUri = "file://media/Photo/" + to_string(reqBody.fileId);
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->RevertToOriginal(data, reply);
}

static void ConvertFormatFuzzer()
{
    ConvertFormatReqBody reqBody;
    reqBody.fileId = FDP->ConsumeIntegral<int32_t>();
    reqBody.title = FDP->ConsumeBytesAsString(NUM_BYTES);
    reqBody.extension =FDP->ConsumeBytesAsString(NUM_BYTES);
    MessageParcel data;
    MessageParcel reply;
    reqBody.Marshalling(data);
    mediaAssetsControllerService->ConvertFormat(data, reply);
}

static void MediaAssetsControllerService4Fuzzer()
{
    SetAssetPendingFuzzer();
    SetAssetsFavoriteFuzzer();
    SetAssetsHiddenStatusFuzzer();
    SetAssetsRecentShowStatusFuzzer();
    SetAssetsUserCommentFuzzer();
    GetAssetAnalysisDataFuzzer();
    CloneAssetFuzzer();
    RevertToOriginalFuzzer();
    ConvertFormatFuzzer();
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
    if (data == nullptr) {
        return 0;
    }
    FuzzedDataProvider fdp(data, size);
    OHOS::FDP = &fdp;
    OHOS::MediaAssetsControllerService4Fuzzer();
    return 0;
}