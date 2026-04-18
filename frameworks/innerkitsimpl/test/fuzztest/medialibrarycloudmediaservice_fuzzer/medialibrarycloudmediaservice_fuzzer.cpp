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

#include "medialibrarycloudmediaservice_fuzzer.h"
#include "medialibrary_rdbstore_utils_fuzzer.h"

#include <cstdint>
#include <string>
#include <fstream>
#include <fuzzer/FuzzedDataProvider.h>
#include "cloud_media_photos_service.h"
#include "media_log.h"
#include "cloud_media_operation_code.h"
#include "media_upgrade.h"

namespace OHOS {
using namespace std;
using namespace OHOS::Media;
using namespace OHOS::Media::CloudSync;
const int32_t FILEID = 1;
const int32_t NUM_BYTES = 1;
static const int32_t MXA_CLEAN_TYPE = 1;
static const int32_t MIN_PHOTO_POSITION_TYPE = -1;
static const int32_t MAX_PHOTO_POSITION_TYPE = 3;
static const int32_t MIN_SYNC_STATUS_TYPE = -1;
static const int32_t MAX_SYNC_STATUS_TYPE = 2;
static const int32_t MAX_MEDIA_TYPE = 14;
static const int32_t MAX_THUMB_SATUS = 3;
static const int32_t MAX_PROPERTIES_ROTATE = 8;
static const int32_t MAX_DIRTY_TYPE = 8;
const int32_t MAX_BYTE_VALUE = 256;
const int32_t SEED_SIZE = 1024;
const string PHOTOS_TABLE = "Photos";
FuzzedDataProvider* provider;
std::shared_ptr<Media::MediaLibraryRdbStore> g_rdbStore;

static inline DirtyType FuzzDirtyType()
{
    int32_t value = provider->ConsumeIntegralInRange<int32_t>(0, MAX_DIRTY_TYPE);
    return static_cast<DirtyType>(value);
}

static inline CloudSync::ThumbState FuzzThumbState()
{
    int32_t value = provider->ConsumeIntegralInRange<int32_t>(0, MAX_THUMB_SATUS);
    return static_cast<CloudSync::ThumbState>(value);
}

static inline MediaType FuzzMediaType()
{
    int32_t value = provider->ConsumeIntegralInRange<int32_t>(0, MAX_MEDIA_TYPE);
    return static_cast<MediaType>(value);
}

static inline PhotoPositionType FuzzPhotoPositionType()
{
    int32_t value = provider->ConsumeIntegralInRange<int32_t>(MIN_PHOTO_POSITION_TYPE, MAX_PHOTO_POSITION_TYPE);
    return static_cast<PhotoPositionType>(value);
}

static inline SyncStatusType FuzzSyncStatusType()
{
    int32_t value = provider->ConsumeIntegralInRange<int32_t>(MIN_SYNC_STATUS_TYPE, MAX_SYNC_STATUS_TYPE);
    return static_cast<SyncStatusType>(value);
}

static inline Media::CleanType FuzzCleanType()
{
    int32_t value = provider->ConsumeIntegralInRange<int32_t>(0, MXA_CLEAN_TYPE);
    return static_cast<CleanType>(value);
}

static int32_t InsertQueryAsset()
{
    if (g_rdbStore == nullptr) {
        return E_ERR;
    }
    NativeRdb::ValuesBucket values;
    values.PutInt(PhotoColumn::MEDIA_TYPE, static_cast<int32_t>(FuzzMediaType()));
    values.PutInt(PhotoColumn::PHOTO_POSITION, static_cast<int32_t>(FuzzPhotoPositionType()));
    values.PutInt(PhotoColumn::PHOTO_SYNC_STATUS, static_cast<int32_t>(FuzzSyncStatusType()));
    values.PutInt(PhotoColumn::PHOTO_THUMB_STATUS, static_cast<int32_t>(FuzzThumbState()));
    values.PutInt(PhotoColumn::PHOTO_CLEAN_FLAG, static_cast<int32_t>(FuzzCleanType()));
    values.PutLong(PhotoColumn::MEDIA_DATE_TAKEN, provider->ConsumeIntegral<int64_t>());
    int64_t fileId = 0;
    int32_t ret = g_rdbStore->Insert(fileId, PHOTOS_TABLE, values);
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, E_ERR, "g_rdbStore failed to insert ret=%{public}d", ret);
    return static_cast<int32_t>(fileId);
}

static PhotosDto FuzzPhotosDto()
{
    PhotosDto photo;
    photo.cloudId = "default-album-2";
    photo.fileId = provider->ConsumeIntegral<uint32_t>() & 0xf;
    photo.localId = provider->ConsumeIntegral<int32_t>();
    photo.isSuccess = true;
    return photo;
}

static CloudMediaPullDataDto FuzzCloudMediaPullDataDto(string &cloudId)
{
    CloudMediaPullDataDto pullData;
    pullData.attributesTitle = provider->ConsumeBool() ? provider->ConsumeBytesAsString(NUM_BYTES) : "";
    pullData.hasProperties = true;
    pullData.propertiesSourceFileName = "." + provider->ConsumeBytesAsString(NUM_BYTES);
    pullData.basicFileType = provider->ConsumeBool() ? FILE_TYPE_LIVEPHOTO : FILE_TYPE_VIDEO;
    pullData.basicEditedTime = provider->ConsumeIntegral<int64_t>();
    pullData.basicFileName = "IMG_20250425_123456.jpg";
    pullData.cloudId = cloudId;
    pullData.propertiesSourcePath =  provider->ConsumeBool() ? "/Pictures/Screenshots/DCIM/Camera" : "";
    pullData.hasAttributes = true;
    pullData.attributesMediaType = provider->ConsumeIntegral<int64_t>();
    pullData.duration = provider->ConsumeIntegral<int32_t>();
    pullData.attributesHidden = provider->ConsumeIntegral<int32_t>();
    pullData.attributesHiddenTime = provider->ConsumeIntegral<int64_t>();
    pullData.attributesRelativePath = provider->ConsumeBytesAsString(NUM_BYTES);
    pullData.attributesVirtualPath = provider->ConsumeBytesAsString(NUM_BYTES);
    pullData.attributesMetaDateModified = provider->ConsumeIntegral<int64_t>();
    pullData.attributesSubtype = provider->ConsumeIntegral<int32_t>();
    pullData.attributesBurstCoverLevel = provider->ConsumeIntegral<int32_t>();
    pullData.attributesBurstKey = provider->ConsumeBytesAsString(NUM_BYTES);
    pullData.attributesDateYear = provider->ConsumeBytesAsString(NUM_BYTES);
    pullData.attributesDateMonth = provider->ConsumeBytesAsString(NUM_BYTES);
    pullData.attributesDateDay = provider->ConsumeBytesAsString(NUM_BYTES);
    pullData.attributesShootingMode = provider->ConsumeBytesAsString(NUM_BYTES);
    pullData.attributesShootingModeTag = provider->ConsumeBytesAsString(NUM_BYTES);
    pullData.attributesDynamicRangeType = provider->ConsumeIntegral<int32_t>();
    pullData.attributesFrontCamera = provider->ConsumeBytesAsString(NUM_BYTES);
    pullData.attributesEditTime = provider->ConsumeIntegral<int64_t>();
    pullData.attributesOriginalSubtype = provider->ConsumeIntegral<int32_t>();
    pullData.attributesCoverPosition = provider->ConsumeIntegral<int64_t>();
    pullData.attributesMovingPhotoEffectMode = provider->ConsumeIntegral<int32_t>();
    pullData.attributesSupportedWatermarkType = provider->ConsumeIntegral<int32_t>();
    pullData.attributesStrongAssociation = provider->ConsumeIntegral<int32_t>();
    pullData.attributesFileId = FILEID;
    pullData.localPath = "file://media/Photo/1/IMG_1744362716_000/IMG_1744362716_000.jpg";
    pullData.propertiesRotate = provider->ConsumeIntegralInRange<uint32_t>(0, MAX_PROPERTIES_ROTATE);
    pullData.localThumbState = provider->ConsumeIntegral<int32_t>();
    pullData.localDirty = static_cast<int32_t>(FuzzDirtyType());
    pullData.localDateModified = provider->ConsumeBytesAsString(NUM_BYTES);
    pullData.attributesEditedTimeMs = provider->ConsumeIntegral<int64_t>();
    pullData.localDateAdded = provider->ConsumeBytesAsString(NUM_BYTES);
    pullData.basicSize = -1;
    return pullData;
}

static void HandleRecordFuzzer()
{
    CloudMediaPhotosService service;
    string cloudId = "default-album-2";
    vector<string> cloudIds = { cloudId };
    cloudIds.emplace_back(cloudId);
    std::map<string, CloudMediaPullDataDto> cloudIdRelativeMap = { {"default-album-2", CloudMediaPullDataDto()} };
    vector<PhotosDto> newData;
    vector<PhotosDto> fdirtyData;
    vector<int32_t> stats(5, 0);
    vector<string> failedRecords;
    service.HandleRecord(cloudIds, cloudIdRelativeMap, newData, fdirtyData, stats, failedRecords);

    cloudIdRelativeMap = { {"default-album-2", FuzzCloudMediaPullDataDto(cloudId)} };
    service.HandleRecord(cloudIds, cloudIdRelativeMap, newData, fdirtyData, stats, failedRecords);

    CloudMediaPullDataDto pullData = FuzzCloudMediaPullDataDto(cloudId);
    pullData.basicIsDelete = true;
    cloudIdRelativeMap = { {"default-album-2", pullData} };
    service.HandleRecord(cloudIds, cloudIdRelativeMap, newData, fdirtyData, stats, failedRecords);
}

static void ConvertPullDataToPhotosDtoFuzzer()
{
    CloudMediaPhotosService service;
    PhotosDto photo;
    string cloudId = provider->ConsumeBytesAsString(NUM_BYTES);
    CloudMediaPullDataDto data = FuzzCloudMediaPullDataDto(cloudId);
    service.ConvertPullDataToPhotosDto(data, photo);
}

static void OnCreateRecordSuccessFuzzer()
{
    CloudMediaPhotosService service;
    auto photoRefresh = std::make_shared<AccurateRefresh::AssetAccurateRefresh>();
    PhotosDto record = FuzzPhotosDto();
    service.OnCreateRecordSuccess(record, photoRefresh);
}

static void CloudMediadPhotoServiceFuzzer()
{
    InsertQueryAsset();
    HandleRecordFuzzer();
    ConvertPullDataToPhotosDtoFuzzer();
    OnCreateRecordSuccessFuzzer();
}

void SetTables()
{
    vector<string> createTableSqlList = {
        Media::PhotoUpgrade::CREATE_PHOTO_TABLE,
    };
    for (auto &createTableSql : createTableSqlList) {
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

static int32_t AddSeed()
{
    char *seedData = new char[OHOS::SEED_SIZE];
    for (int i = 0; i < OHOS::SEED_SIZE; i++) {
        seedData[i] = static_cast<char>(i % MAX_BYTE_VALUE);
    }

    const char* filename = "corpus/seed.txt";
    std::ofstream file(filename, std::ios::binary | std::ios::trunc);
    if (!file) {
        MEDIA_ERR_LOG("Cannot open file filename:%{public}s", filename);
        delete[] seedData;
        return Media::E_ERR;
    }
    file.write(seedData, OHOS::SEED_SIZE);
    file.close();
    delete[] seedData;
    MEDIA_INFO_LOG("seedData has been successfully written to file filename:%{public}s", filename);
    return Media::E_OK;
}
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::AddSeed();
    OHOS::Init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    CHECK_AND_RETURN_RET_LOG(data != nullptr, OHOS::Media::E_ERR, "data is nullptr");
    FuzzedDataProvider fdp(data, size);
    OHOS::provider = &fdp;
    CHECK_AND_RETURN_RET_LOG(OHOS::provider != nullptr, OHOS::Media::E_ERR, "provider is nullptr");

    OHOS::CloudMediadPhotoServiceFuzzer();
    return 0;
}