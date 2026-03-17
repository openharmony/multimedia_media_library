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
#define private public
#include "cloud_media_photos_service.h"
#undef private
#include "media_log.h"
#include "cloud_media_operation_code.h"
#include "media_upgrade.h"

namespace OHOS {
using namespace std;
using namespace OHOS::Media;
using namespace OHOS::Media::CloudSync;
const int32_t FILEID = 1;
const int32_t NUM_BYTES = 1;
const int32_t VECTOR_SIZE = 5;
static const int32_t MAX_THUMB_SATUS = 3;
static const int32_t MAX_PROPERTIES_ROTATE = 8;
static const int32_t MAX_DIRTY_TYPE = 8;
const int32_t MAX_BYTE_VALUE = 256;
const int32_t SEED_SIZE = 1024;
const string PHOTOS_TABLE = "Photos";
FuzzedDataProvider* provider;
std::shared_ptr<Media::MediaLibraryRdbStore> g_rdbStore;
shared_ptr<CloudMediaPhotosService> cloudMediaPhotosService = make_shared<CloudMediaPhotosService>();

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

static int32_t InsertQueryAsset()
{
    if (g_rdbStore == nullptr) {
        return E_ERR;
    }
    NativeRdb::ValuesBucket values;
    values.PutInt(PhotoColumn::MEDIA_TYPE, static_cast<int32_t>(MediaType::MEDIA_TYPE_VIDEO));
    values.PutInt(PhotoColumn::MEDIA_ID, 1);
    values.PutInt(PhotoColumn::PHOTO_POSITION, static_cast<int32_t>(PhotoPositionType::CLOUD));
    values.PutInt(PhotoColumn::PHOTO_SYNC_STATUS, static_cast<int32_t>(SyncStatusType::TYPE_VISIBLE));
    values.PutInt(PhotoColumn::PHOTO_THUMB_STATUS, static_cast<int32_t>(FuzzThumbState()));
    values.PutInt(PhotoColumn::PHOTO_CLEAN_FLAG, static_cast<int32_t>(CleanType::TYPE_NOT_CLEAN));
    values.PutLong(PhotoColumn::MEDIA_DATE_TAKEN, provider->ConsumeIntegral<int64_t>());
    values.PutString(PhotoColumn::MEDIA_FILE_PATH, "/storage/cloud/files/Photo/16/IMG_1744362716_000.jpg");
    int64_t fileId = 0;
    g_rdbStore->Insert(fileId, PHOTOS_TABLE, values);
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

static void OnRecordFailedFuzzer()
{
    if (cloudMediaPhotosService == nullptr) {
        MEDIA_ERR_LOG("cloudMediaPhotosService is nuulptr");
        return;
    }
    auto photoRefresh = std::make_shared<AccurateRefresh::AssetAccurateRefresh>();
    PhotosDto photo;
    photo.serverErrorCode = ServerErrorCode::NETWORK_ERROR;
    cloudMediaPhotosService->OnRecordFailed(photo, photoRefresh);

    photo.serverErrorCode = ServerErrorCode::UID_EMPTY;
    cloudMediaPhotosService->OnRecordFailed(photo, photoRefresh);

    photo.serverErrorCode = ServerErrorCode::INVALID_LOCK_PARAM;
    cloudMediaPhotosService->OnRecordFailed(photo, photoRefresh);

    photo.serverErrorCode = ServerErrorCode::RESPONSE_TIME_OUT;
    photo.errorType = ErrorType::TYPE_UNKNOWN;
    cloudMediaPhotosService->OnRecordFailed(photo, photoRefresh);

    photo.errorType = ErrorType::TYPE_NOT_NEED_RETRY;
    cloudMediaPhotosService->OnRecordFailed(photo, photoRefresh);

    photo.serverErrorCode = ServerErrorCode::NO_NETWORK;
    photo.errorType = ErrorType::TYPE_UNKNOWN;
    CloudErrorDetail cloudErrorDetail;
    cloudErrorDetail.detailCode = ErrorDetailCode::SPACE_FULL;
    photo.errorDetails = { cloudErrorDetail };
    cloudMediaPhotosService->OnRecordFailed(photo, photoRefresh);

    cloudErrorDetail.detailCode = ErrorDetailCode::BUSINESS_MODEL_CHANGE_DATA_UPLOAD_FORBIDDEN;
    photo.errorDetails = { cloudErrorDetail };
    cloudMediaPhotosService->OnRecordFailed(photo, photoRefresh);

    cloudErrorDetail.detailCode = ErrorDetailCode::SAME_FILENAME_NOT_ALLOWED;
    photo.errorDetails = { cloudErrorDetail };
    cloudMediaPhotosService->OnRecordFailed(photo, photoRefresh);

    cloudErrorDetail.detailCode = ErrorDetailCode::CONTENT_NOT_FIND;
    photo.errorDetails = { cloudErrorDetail };
    cloudMediaPhotosService->OnRecordFailed(photo, photoRefresh);

    cloudErrorDetail.detailCode = ErrorDetailCode::FILE_REFERENCED;
    photo.errorDetails = { cloudErrorDetail };
    photo.errorType = ErrorType::TYPE_NOT_NEED_RETRY;
    cloudMediaPhotosService->OnRecordFailed(photo, photoRefresh);
}

static void PullDeleteAndUpdateFuzzer()
{
    if (cloudMediaPhotosService == nullptr) {
        MEDIA_ERR_LOG("cloudMediaPhotosService is nuulptr");
        return;
    }
    auto photoRefresh = std::make_shared<AccurateRefresh::AssetAccurateRefresh>();
    std::string cloudId = provider->ConsumeBytesAsString(NUM_BYTES);
    CloudMediaPullDataDto pullData = FuzzCloudMediaPullDataDto(cloudId);
    std::set<string> refreshAlbums;
    vector<PhotosDto> fdirtyData;
    vector<int32_t> stats(VECTOR_SIZE, 0);
    cloudMediaPhotosService->PullDelete(pullData, refreshAlbums, photoRefresh);
    cloudMediaPhotosService->PullUpdate(pullData, refreshAlbums, fdirtyData, stats, photoRefresh);
}

static void GetMergeDataMapFuzzer()
{
    if (cloudMediaPhotosService == nullptr) {
        MEDIA_ERR_LOG("cloudMediaPhotosService is nuulptr");
        return;
    }
    vector<CloudMediaPullDataDto> pullDatas;
    std::string cloudId = provider->ConsumeBytesAsString(NUM_BYTES);
    CloudMediaPullDataDto pullData = FuzzCloudMediaPullDataDto(cloudId);
    pullDatas.emplace_back(pullData);
    std::map<string, KeyData> mergeDataMap;
    cloudMediaPhotosService->GetMergeDataMap(pullDatas, mergeDataMap);
}

static void OnRecordFuzzer()
{
    if (cloudMediaPhotosService == nullptr) {
        MEDIA_ERR_LOG("cloudMediaPhotosService is nuulptr");
        return;
    }
    vector<PhotosDto> photos;
    PhotosDto photo;
    photos.emplace_back(photo);
    int32_t failedSize = -1;
    InsertQueryAsset();
    cloudMediaPhotosService->OnCreateRecords(photos, failedSize);
    cloudMediaPhotosService->OnMdirtyRecords(photos, failedSize);
    cloudMediaPhotosService->OnFdirtyRecords(photos, failedSize);
    cloudMediaPhotosService->OnDeleteRecords(photos, failedSize);
    cloudMediaPhotosService->OnCopyRecords(photos, failedSize);

    photos.clear();
    photo = FuzzPhotosDto();
    photos.emplace_back(photo);
    cloudMediaPhotosService->OnCreateRecords(photos, failedSize);
    cloudMediaPhotosService->OnMdirtyRecords(photos, failedSize);
    cloudMediaPhotosService->OnFdirtyRecords(photos, failedSize);
    cloudMediaPhotosService->OnDeleteRecords(photos, failedSize);
    cloudMediaPhotosService->OnCopyRecords(photos, failedSize);
}

static void CloudMediadPhotoServiceFuzzer()
{
    CHECK_AND_RETURN_LOG(cloudMediaPhotosService != nullptr, "cloudMediaPhotosService is nuulptr");

    MediaOperateResult optRet = {"", 0, ""};
    cloudMediaPhotosService->OnStartSync();
    cloudMediaPhotosService->OnCompleteSync();
    cloudMediaPhotosService->OnCompletePull(optRet);
    cloudMediaPhotosService->OnCompletePush();
    cloudMediaPhotosService->OnCompleteCheck();
    PullDeleteAndUpdateFuzzer();
    GetMergeDataMapFuzzer();

    string cloudId = "default-album-2";
    vector<string> cloudIds = { cloudId };
    int32_t recordsSize = provider->ConsumeIntegral<uint32_t>() & 0xf;
    vector<PhotosPo> photosPo;
    cloudMediaPhotosService->GetCreatedRecords(recordsSize, photosPo);
    int32_t dirtyType = static_cast<int32_t>(FuzzDirtyType());
    cloudMediaPhotosService->GetMetaModifiedRecords(recordsSize, photosPo, dirtyType);
    cloudMediaPhotosService->GetFileModifiedRecords(recordsSize, photosPo);
    cloudMediaPhotosService->GetCopyRecords(recordsSize, photosPo);
    cloudMediaPhotosService->GetRetryRecords(cloudIds);

    PhotosDto photo;
    OnRecordFuzzer();
    OnRecordFailedFuzzer();

    cloudIds.clear();
    cloudIds.emplace_back(cloudId);
    std::map<string, CloudMediaPullDataDto> cloudIdRelativeMap = { {"default-album-2", CloudMediaPullDataDto()} };
    vector<PhotosDto> newData;
    vector<PhotosDto> fdirtyData;
    vector<int32_t> stats(VECTOR_SIZE, 0);
    vector<string> failedRecords;
    cloudMediaPhotosService->HandleRecord(cloudIds, cloudIdRelativeMap, newData, fdirtyData, stats, failedRecords);

    cloudIdRelativeMap = { {"default-album-2", FuzzCloudMediaPullDataDto(cloudId)} };
    cloudMediaPhotosService->HandleRecord(cloudIds, cloudIdRelativeMap, newData, fdirtyData, stats, failedRecords);

    CloudMediaPullDataDto pullData = FuzzCloudMediaPullDataDto(cloudId);
    pullData.basicIsDelete = true;
    cloudIdRelativeMap = { {"default-album-2", pullData} };
    cloudMediaPhotosService->HandleRecord(cloudIds, cloudIdRelativeMap, newData, fdirtyData, stats, failedRecords);

    CloudMediaPullDataDto data = FuzzCloudMediaPullDataDto(cloudId);
    cloudMediaPhotosService->ConvertPullDataToPhotosDto(data, photo);
    vector<CloudMediaPullDataDto> pullDatas = { FuzzCloudMediaPullDataDto(cloudId) };
    cloudMediaPhotosService->OnDentryFileInsert(pullDatas, failedRecords);

    auto photoRefresh = std::make_shared<AccurateRefresh::AssetAccurateRefresh>();
    PhotosDto record = FuzzPhotosDto();
    cloudMediaPhotosService->OnCreateRecordSuccess(record, photoRefresh);

    record.localId = 1;
    cloudMediaPhotosService->OnCreateRecordSuccess(record, photoRefresh);
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
    FuzzedDataProvider fdp(data, size);
    OHOS::provider = &fdp;
    if (data == nullptr) {
        return 0;
    }

    OHOS::CloudMediadPhotoServiceFuzzer();
    return 0;
}