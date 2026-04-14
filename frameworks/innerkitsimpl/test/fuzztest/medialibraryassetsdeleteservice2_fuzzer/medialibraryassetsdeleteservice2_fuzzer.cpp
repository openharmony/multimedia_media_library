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

#include "medialibraryassetsdeleteservice2_fuzzer.h"
#include "medialibrary_rdbstore_utils_fuzzer.h"

#include <cstddef>
#include <sstream>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

#include "ability_context_impl.h"
#include "media_assets_delete_service.h"
#include "media_column.h"
#include "media_log.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_unistore.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_kvstore_manager.h"
#include "values_bucket.h"
#include "media_upgrade.h"
#include "photos_po.h"

namespace OHOS {
namespace Media {
namespace Common {
using namespace std;
static constexpr int32_t NUM_BYTES = 1;
static constexpr int32_t MIN_PHOTO_POSITION = 1;
static constexpr int32_t MAX_PHOTO_POSITION = 2;
std::shared_ptr<Media::MediaLibraryRdbStore> g_rdbStore;
FuzzedDataProvider *provider = nullptr;

static inline PhotoPositionType FuzzPhotoPosition()
{
    int32_t value = provider->ConsumeIntegralInRange<int32_t>(MIN_PHOTO_POSITION, MAX_PHOTO_POSITION);
    return static_cast<PhotoPositionType>(value);
}

static inline DirtyType FuzzDirtyType()
{
    int32_t rangeStart = 0;
    int32_t rangeEnd = 2;
    int32_t value = provider->ConsumeIntegralInRange<int32_t>(rangeStart, rangeEnd);
    return static_cast<DirtyType>(value);
}

static inline BurstCoverLevelType FuzzBurstCoverLevelType()
{
    int32_t rangeStart = 0;
    int32_t rangeEnd = 1;
    int32_t value = provider->ConsumeIntegralInRange<int32_t>(rangeStart, rangeEnd);
    return static_cast<BurstCoverLevelType>(value);
}

static void CreatePhotosPo2(PhotosPo& photoInfo)
{
    photoInfo.detailTime = provider->ConsumeBytesAsString(NUM_BYTES);
    photoInfo.editTime = provider->ConsumeIntegral<int64_t>();
    photoInfo.originalSubtype = provider->ConsumeIntegral<int32_t>();
    photoInfo.coverPosition = provider->ConsumeIntegral<int64_t>();
    photoInfo.isRectificationCover = provider->ConsumeIntegral<int32_t>();
    photoInfo.exifRotate = provider->ConsumeIntegral<int32_t>();
    photoInfo.movingPhotoEffectMode = provider->ConsumeIntegral<int32_t>();
    photoInfo.ownerAlbumId = provider->ConsumeIntegral<int32_t>();
    photoInfo.originalAssetCloudId = provider->ConsumeBytesAsString(NUM_BYTES);
    photoInfo.sourcePath = provider->ConsumeBytesAsString(NUM_BYTES);
    photoInfo.supportedWatermarkType = provider->ConsumeIntegral<int32_t>();
    photoInfo.isStylePhoto = provider->ConsumeIntegral<int32_t>();
    photoInfo.strongAssociation = provider->ConsumeIntegral<int32_t>();
    photoInfo.dirty = static_cast<int32_t>(FuzzDirtyType());
    photoInfo.position = static_cast<int32_t>(FuzzPhotoPosition());
    photoInfo.cloudVersion = provider->ConsumeIntegral<int64_t>();
    photoInfo.baseVersion = provider->ConsumeIntegral<int64_t>();
    photoInfo.recordType = provider->ConsumeBytesAsString(NUM_BYTES);
    photoInfo.recordId = provider->ConsumeBytesAsString(NUM_BYTES);
    photoInfo.isNew = provider->ConsumeBool();
    photoInfo.lcdVisitTime = provider->ConsumeIntegral<int64_t>();
    photoInfo.thumbnailReady = provider->ConsumeIntegral<int64_t>();
    photoInfo.timePending = provider->ConsumeIntegral<int64_t>();
    photoInfo.fileSourceType = provider->ConsumeIntegral<int32_t>();
    photoInfo.storagePath = provider->ConsumeBytesAsString(NUM_BYTES);
    photoInfo.lcdSize = provider->ConsumeBytesAsString(NUM_BYTES);
    photoInfo.thumbSize = provider->ConsumeBytesAsString(NUM_BYTES);
    photoInfo.packageName = provider->ConsumeBytesAsString(NUM_BYTES);
    photoInfo.southDeviceType = provider->ConsumeIntegral<int32_t>();
    photoInfo.cloudId = provider->ConsumeBytesAsString(NUM_BYTES);
}

static PhotosPo CreatePhotosPo()
{
    PhotosPo photoInfo;
    photoInfo.fileId = provider->ConsumeIntegral<int32_t>();
    photoInfo.data = provider->ConsumeBytesAsString(NUM_BYTES);
    photoInfo.title = provider->ConsumeBytesAsString(NUM_BYTES);
    photoInfo.size = provider->ConsumeIntegral<int64_t>();
    photoInfo.displayName = provider->ConsumeBytesAsString(NUM_BYTES);
    photoInfo.mediaType = provider->ConsumeIntegral<int32_t>();
    photoInfo.mimeType = provider->ConsumeBytesAsString(NUM_BYTES);
    photoInfo.deviceName = provider->ConsumeBytesAsString(NUM_BYTES);
    photoInfo.dateAdded = provider->ConsumeIntegral<int64_t>();
    photoInfo.dateModified = provider->ConsumeIntegral<int64_t>();
    photoInfo.dateTaken = provider->ConsumeIntegral<int64_t>();
    photoInfo.duration = provider->ConsumeIntegral<int32_t>();
    photoInfo.isFavorite = provider->ConsumeIntegral<int32_t>();
    photoInfo.dateTrashed = provider->ConsumeIntegral<int64_t>();
    photoInfo.hidden = provider->ConsumeIntegral<int32_t>();
    photoInfo.hiddenTime = provider->ConsumeIntegral<int64_t>();
    photoInfo.relativePath = provider->ConsumeBytesAsString(NUM_BYTES);
    photoInfo.virtualPath = provider->ConsumeBytesAsString(NUM_BYTES);
    photoInfo.metaDateModified = provider->ConsumeIntegral<int64_t>();
    photoInfo.orientation = provider->ConsumeIntegral<int32_t>();
    photoInfo.latitude = provider->ConsumeFloatingPoint<double>();
    photoInfo.longitude = provider->ConsumeFloatingPoint<double>();
    photoInfo.height = provider->ConsumeIntegral<int32_t>();
    photoInfo.width = provider->ConsumeIntegral<int32_t>();
    photoInfo.subtype = provider->ConsumeIntegral<int32_t>();
    photoInfo.burstCoverLevel = static_cast<int32_t>(FuzzBurstCoverLevelType());
    photoInfo.burstKey = provider->ConsumeBytesAsString(NUM_BYTES);
    photoInfo.dateYear = provider->ConsumeBytesAsString(NUM_BYTES);
    photoInfo.dateMonth = provider->ConsumeBytesAsString(NUM_BYTES);
    photoInfo.dateDay = provider->ConsumeBytesAsString(NUM_BYTES);
    photoInfo.userComment = provider->ConsumeBytesAsString(NUM_BYTES);
    photoInfo.thumbStatus = provider->ConsumeIntegral<int32_t>();
    photoInfo.syncStatus = provider->ConsumeIntegral<int32_t>();
    photoInfo.shootingMode = provider->ConsumeBytesAsString(NUM_BYTES);
    photoInfo.shootingModeTag = provider->ConsumeBytesAsString(NUM_BYTES);
    photoInfo.dynamicRangeType = provider->ConsumeIntegral<int32_t>();
    photoInfo.hdrMode = provider->ConsumeIntegral<int32_t>();
    photoInfo.videoMode = provider->ConsumeIntegral<int32_t>();
    photoInfo.frontCamera = provider->ConsumeBytesAsString(NUM_BYTES);
    CreatePhotosPo2(photoInfo);
    return photoInfo;
}

static void MoveLocalAssetFileFuzzer()
{
    MEDIA_INFO_LOG("MoveLocalAssetFileFuzzer start");
    MediaAssetsDeleteService deleteService;
    PhotosPo photoInfo = CreatePhotosPo();
    PhotosPo targetPhotoInfo = CreatePhotosPo();
    deleteService.MoveLocalAssetFile(photoInfo, targetPhotoInfo);
    MEDIA_INFO_LOG("MoveLocalAssetFileFuzzer end");
}

static void CreateCloudTrashedPhotosPoFuzzer()
{
    MEDIA_INFO_LOG("CreateCloudTrashedPhotosPoFuzzer start");
    MediaAssetsDeleteService deleteService;
    PhotosPo photoInfo = CreatePhotosPo();
    photoInfo.displayName = "media_assets_delete_service_fuzzer_test2.jpg";
    photoInfo.mediaType = MediaType::MEDIA_TYPE_IMAGE;
    PhotosPo targetPhotoInfo;
    deleteService.CreateCloudTrashedPhotosPo(photoInfo, targetPhotoInfo);
    MEDIA_INFO_LOG("CreateCloudTrashedPhotosPoFuzzer end");
}

static void CreateCloudAssetThumbnailFuzzer()
{
    MEDIA_INFO_LOG("CreateCloudAssetThumbnailFuzzer start");
    MediaAssetsDeleteService deleteService;
    PhotosPo photoInfo = CreatePhotosPo();
    PhotosPo targetPhotoInfo = CreatePhotosPo();
    deleteService.CreateCloudAssetThumbnail(photoInfo, targetPhotoInfo);
    MEDIA_INFO_LOG("CreateCloudAssetThumbnailFuzzer end");
}

static void CreateCloudAssetWithDentryFileFuzzer()
{
    MEDIA_INFO_LOG("CreateCloudAssetWithDentryFileFuzzer start");
    MediaAssetsDeleteService deleteService;
    PhotosPo photoInfo = CreatePhotosPo();
    PhotosPo targetPhotoInfo;
    auto photoRefresh = std::make_shared<AccurateRefresh::AssetAccurateRefresh>();
    deleteService.CreateCloudAssetWithDentryFile(photoInfo, targetPhotoInfo, photoRefresh);
    MEDIA_INFO_LOG("CreateCloudAssetWithDentryFileFuzzer end");
}

static void CreateNewAssetInfoAndReturnFileIdFuzzer()
{
    MEDIA_INFO_LOG("CreateNewAssetInfoAndReturnFileIdFuzzer start");
    MediaAssetsDeleteService deleteService;
    PhotosPo photoInfo = CreatePhotosPo();
    auto photoRefresh = std::make_shared<AccurateRefresh::AssetAccurateRefresh>();
    deleteService.CreateNewAssetInfoAndReturnFileId(photoInfo, photoRefresh);
    MEDIA_INFO_LOG("CreateNewAssetInfoAndReturnFileIdFuzzer end");
}
static void CreateLocalAssetWithLakeFileFuzzer()
{
    MEDIA_INFO_LOG("CreateLocalAssetWithLakeFileFuzzer start");
    MediaAssetsDeleteService deleteService;
    PhotosPo photoInfo = CreatePhotosPo();
    PhotosPo targetPhotoInfo;
    auto photoRefresh = std::make_shared<AccurateRefresh::AssetAccurateRefresh>();
    deleteService.CreateLocalAssetWithLakeFile(photoInfo, targetPhotoInfo, photoRefresh);
    MEDIA_INFO_LOG("CreateLocalAssetWithLakeFileFuzzer end");
}

static void CopyAndMoveMediaLocalAssetToTrashFuzzer()
{
    MEDIA_INFO_LOG("CopyAndMoveMediaLocalAssetToTrashFuzzer start");
    MediaAssetsDeleteService deleteService;
    PhotosPo photoInfo = CreatePhotosPo();
    std::optional<PhotosPo> targetPhotoInfoOp;
    auto photoRefresh = std::make_shared<AccurateRefresh::AssetAccurateRefresh>();
    deleteService.CopyAndMoveMediaLocalAssetToTrash(photoInfo, targetPhotoInfoOp, photoRefresh);
    MEDIA_INFO_LOG("CopyAndMoveMediaLocalAssetToTrashFuzzer end");
}

static void CopyAndMoveLakeLocalAssetToTrashFuzzer()
{
    MEDIA_INFO_LOG("CopyAndMoveLakeLocalAssetToTrashFuzzer start");
    MediaAssetsDeleteService deleteService;
    PhotosPo photoInfo = CreatePhotosPo();
    std::optional<PhotosPo> targetPhotoInfoOp;
    auto photoRefresh = std::make_shared<AccurateRefresh::AssetAccurateRefresh>();
    deleteService.CopyAndMoveLakeLocalAssetToTrash(photoInfo, targetPhotoInfoOp, photoRefresh);
    MEDIA_INFO_LOG("CopyAndMoveLakeLocalAssetToTrashFuzzer end");
}
static void CreateCloudAssetWithoutDentryFileFuzzer()
{
    MEDIA_INFO_LOG("CreateCloudAssetWithoutDentryFileFuzzer start");
    MediaAssetsDeleteService deleteService;
    PhotosPo photoInfo = CreatePhotosPo();
    PhotosPo targetPhotoInfo;
    auto photoRefresh = std::make_shared<AccurateRefresh::AssetAccurateRefresh>();
    deleteService.CreateCloudAssetWithoutDentryFile(photoInfo, targetPhotoInfo, photoRefresh);
    MEDIA_INFO_LOG("CreateCloudAssetWithoutDentryFileFuzzer end");
}
static void CopyAndMoveMediaCloudAssetToTrashFuzzer()
{
    MEDIA_INFO_LOG("CopyAndMoveMediaCloudAssetToTrashFuzzer start");
    MediaAssetsDeleteService deleteService;
    PhotosPo photoInfo = CreatePhotosPo();
    std::optional<PhotosPo> targetPhotoInfoOp;
    auto photoRefresh = std::make_shared<AccurateRefresh::AssetAccurateRefresh>();
    deleteService.CopyAndMoveMediaCloudAssetToTrash(photoInfo, targetPhotoInfoOp, photoRefresh);
    MEDIA_INFO_LOG("CopyAndMoveMediaCloudAssetToTrashFuzzer end");
}
static void CopyAndMoveLakeCloudAssetToTrashFuzzer()
{
    MEDIA_INFO_LOG("CopyAndMoveLakeCloudAssetToTrashFuzzer start");
    MediaAssetsDeleteService deleteService;
    PhotosPo photoInfo = CreatePhotosPo();
    std::optional<PhotosPo> targetPhotoInfoOp;
    auto photoRefresh = std::make_shared<AccurateRefresh::AssetAccurateRefresh>();
    deleteService.CopyAndMoveLakeCloudAssetToTrash(photoInfo, targetPhotoInfoOp, photoRefresh);
    MEDIA_INFO_LOG("CopyAndMoveLakeCloudAssetToTrashFuzzer end");
}

static void GetDentryFileInfoFuzzer()
{
    MEDIA_INFO_LOG("GetDentryFileInfoFuzzer start");
    MediaAssetsDeleteService deleteService;
    PhotosPo photoInfo = CreatePhotosPo();
    FileManagement::CloudSync::DentryFileInfo dentryInfo;
    deleteService.GetDentryFileInfo(photoInfo, dentryInfo);
    MEDIA_INFO_LOG("CopyAndMoveLakeCloudAssetToTrashFuzzer end");
}

static void FindBurstAssetsAndResetBurstKeyFuzzer()
{
    MEDIA_INFO_LOG("FindBurstAssetsAndResetBurstKeyFuzzer start");
    MediaAssetsDeleteService deleteService;
    std::string originalBurstKey = provider->ConsumeBytesAsString(NUM_BYTES);
    std::optional<PhotosPo> coverAsset;
    std::vector<PhotosPo> burstAssets;
    deleteService.FindBurstAssetsAndResetBurstKey(originalBurstKey, coverAsset, burstAssets);
    MEDIA_INFO_LOG("FindBurstAssetsAndResetBurstKeyFuzzer end");
}

static void CheckAndFindBurstAssetsFuzzer()
{
    MEDIA_INFO_LOG("CheckAndFindBurstAssetsFuzzer start");
    MediaAssetsDeleteService deleteService;
    PhotosPo photoInfo = CreatePhotosPo();
    std::optional<PhotosPo> coverAssetOp;
    std::vector<PhotosPo> burstAssets;
    deleteService.CheckAndFindBurstAssets(photoInfo, coverAssetOp, burstAssets);
    MEDIA_INFO_LOG("CheckAndFindBurstAssetsFuzzer end");
}

static void DeleteLocalBurstAssetsFuzzer()
{
    MEDIA_INFO_LOG("DeleteLocalBurstAssetsFuzzer start");
    MediaAssetsDeleteService deleteService;
    PhotosPo photoInfo = CreatePhotosPo();
    std::optional<PhotosPo> targetPhotoInfoOp;
    auto photoRefresh = std::make_shared<AccurateRefresh::AssetAccurateRefresh>();
    deleteService.DeleteLocalBurstAssets(photoInfo, targetPhotoInfoOp, photoRefresh);
    MEDIA_INFO_LOG("DeleteLocalBurstAssetsFuzzer end");
}

static void MediaAssetsDeleteServiceFuzzer()
{
    MEDIA_INFO_LOG("MediaAssetsDeleteServiceFuzzer2 start");
    MoveLocalAssetFileFuzzer();
    CreateCloudTrashedPhotosPoFuzzer();
    CreateCloudAssetThumbnailFuzzer();
    CreateCloudAssetWithDentryFileFuzzer();
    CreateNewAssetInfoAndReturnFileIdFuzzer();
    CreateLocalAssetWithLakeFileFuzzer();
    CopyAndMoveMediaLocalAssetToTrashFuzzer();
    CopyAndMoveLakeLocalAssetToTrashFuzzer();
    CreateCloudAssetWithoutDentryFileFuzzer();
    CopyAndMoveMediaCloudAssetToTrashFuzzer();
    CopyAndMoveLakeCloudAssetToTrashFuzzer();
    GetDentryFileInfoFuzzer();
    FindBurstAssetsAndResetBurstKeyFuzzer();
    CheckAndFindBurstAssetsFuzzer();
    DeleteLocalBurstAssetsFuzzer();
    MEDIA_INFO_LOG("MediaAssetsDeleteServiceFuzzer2 end");
}

void SetTables()
{
    vector<string> createTableSqlList = { PhotoUpgrade::CREATE_PHOTO_TABLE };
    for (auto &createTableSql : createTableSqlList) {
        CHECK_AND_RETURN_LOG(g_rdbStore != nullptr, "g_rdbStore is null.");
        int32_t ret = g_rdbStore->ExecuteSql(createTableSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Execute sql %{private}s failed", createTableSql.c_str());
            return;
        }
        MEDIA_DEBUG_LOG("Execute sql %{private}s success", createTableSql.c_str());
    }
}

static void Init()
{
    auto stageContext = std::make_shared<AbilityRuntime::ContextImpl>();
    auto abilityContextImpl = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    abilityContextImpl->SetStageContext(stageContext);
    auto rdbStore = Media::MediaLibraryRdbStoreUtilsTest::InitMediaLibraryRdbStore(abilityContextImpl);
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return;
    }
    g_rdbStore = rdbStore;
    SetTables();
}

} // namespace Common
} // namespace Media
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::Media::Common::Init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::Media::Common::provider = &fdp;
    if (data == nullptr) {
        return 0;
    }
    OHOS::Media::Common::MediaAssetsDeleteServiceFuzzer();
    return 0;
}