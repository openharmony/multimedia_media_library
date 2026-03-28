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

#include "medialibrarycloudmediaservice4_fuzzer.h"
#include "medialibrary_rdbstore_utils_fuzzer.h"

#include <cstdint>
#include <string>
#include <fstream>
#include <fuzzer/FuzzedDataProvider.h>
#include "media_log.h"
#include "cloud_media_operation_code.h"
#include "media_upgrade.h"

#include "cloud_media_data_service.h"
#include "cloud_media_download_service.h"

namespace OHOS {
using namespace std;
using namespace OHOS::Media;
using namespace OHOS::Media::CloudSync;
static const int32_t MIN_PHOTO_POSITION_TYPE = -1;
static const int32_t MAX_PHOTO_POSITION_TYPE = 3;
static const int32_t MIN_SYNC_STATUS_TYPE = -1;
static const int32_t MAX_SYNC_STATUS_TYPE = 2;
static const int32_t MAX_THUMB_SATUS = 3;
static const int32_t MAX_DIRTY_TYPE = 8;
static const int32_t MAX_MEDIA_TYPE = 14;
static const int32_t MAX_BYTE_VALUE = 256;
static const int32_t SEED_SIZE = 1024;
static const string PHOTOS_TABLE = "Photos";
FuzzedDataProvider* provider;
std::shared_ptr<Media::MediaLibraryRdbStore> g_rdbStore;
shared_ptr<CloudMediaDataService> cloudMediaDataService = make_shared<CloudMediaDataService>();
shared_ptr<CloudMediaDownloadService> cloudMediaDownloadService = make_shared<CloudMediaDownloadService>();

static inline MediaType FuzzMediaType()
{
    int32_t value = provider->ConsumeIntegralInRange<int32_t>(0, MAX_MEDIA_TYPE);
    return static_cast<MediaType>(value);
}

static inline DirtyType FuzzDirtyType()
{
    int32_t value = provider->ConsumeIntegralInRange<int32_t>(0, MAX_DIRTY_TYPE);
    return static_cast<DirtyType>(value);
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

static inline CloudSync::ThumbState FuzzThumbState()
{
    int32_t value = provider->ConsumeIntegralInRange<int32_t>(0, MAX_THUMB_SATUS);
    return static_cast<CloudSync::ThumbState>(value);
}

static inline Media::CloudSync::Clean FuzzClean()
{
    return provider->ConsumeBool() ? CloudSync::Clean::NEED_CLEAN : CloudSync::Clean::NOT_NEED_CLEAN;
}

static int32_t InsertPhotoAsset()
{
    if (g_rdbStore == nullptr) {
        return E_ERR;
    }
    NativeRdb::ValuesBucket values;
    values.PutInt(PhotoColumn::MEDIA_TYPE, static_cast<int32_t>(FuzzMediaType()));
    values.PutInt(PhotoColumn::PHOTO_DIRTY, static_cast<int32_t>(FuzzDirtyType()));
    values.PutInt(PhotoColumn::PHOTO_POSITION, static_cast<int32_t>(FuzzPhotoPositionType()));
    values.PutInt(PhotoColumn::PHOTO_SYNC_STATUS, static_cast<int32_t>(FuzzSyncStatusType()));
    values.PutInt(PhotoColumn::PHOTO_THUMB_STATUS, static_cast<int32_t>(FuzzThumbState()));
    values.PutInt(PhotoColumn::PHOTO_CLEAN_FLAG, static_cast<int32_t>(FuzzClean()));
    values.PutInt(PhotoColumn::PHOTO_ORIENTATION, provider->ConsumeIntegral<int32_t>());
    values.PutLong(PhotoColumn::MEDIA_DATE_TAKEN, provider->ConsumeIntegral<int64_t>());
    values.PutString(PhotoColumn::PHOTO_CLOUD_ID, "default-album-2");
    values.PutString(PhotoColumn::MEDIA_FILE_PATH, "/storage/cloud/files/Photo/16/IMG_1744362716_000.jpg");
    int64_t fileId = 0;
    int32_t ret = g_rdbStore->Insert(fileId, PHOTOS_TABLE, values);
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, E_ERR, "g_rdbStore failed to insert ret=%{public}d", ret);
    return static_cast<int32_t>(fileId);
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

static AgingFileQueryDto FuzzAgingFileQueryDto()
{
    AgingFileQueryDto queryDto;
    queryDto.time = provider->ConsumeIntegral<int64_t>();
    queryDto.mediaType = static_cast<int32_t>(MediaType::MEDIA_TYPE_VIDEO);
    queryDto.sizeLimit = provider->ConsumeIntegral<int32_t>();
    return queryDto;
}

static DownloadThumbnailQueryDto FuzzDownloadThumbnailQueryDto()
{
    DownloadThumbnailQueryDto queryDto;
    queryDto.size = provider->ConsumeIntegral<int32_t>();
    queryDto.type = provider->ConsumeIntegral<int32_t>();
    queryDto.offset  = provider->ConsumeIntegral<int32_t>();
    queryDto.isDownloadDisplayFirst = true;
    return queryDto;
}

static void CloudMediadataServiceFuzzer()
{
    if (cloudMediaDataService == nullptr) {
        MEDIA_ERR_LOG("cloudMediaDataService is nuulptr");
        return;
    }
    InsertPhotoAsset();
    string cloudId = "default-album-2";
    vector<string> cloudIds = { cloudId };
    
    cloudMediaDataService->UpdateDirty(cloudId, static_cast<int32_t>(FuzzDirtyType()));
    cloudMediaDataService->UpdatePosition(cloudIds, static_cast<int32_t>(FuzzPhotoPositionType()));
    cloudMediaDataService->UpdateSyncStatus(cloudId, static_cast<int32_t>(FuzzSyncStatusType()));
    cloudMediaDataService->UpdateThmStatus(cloudId,  static_cast<int32_t>(FuzzThumbState()));

    AgingFileQueryDto queryDto = FuzzAgingFileQueryDto();
    vector<PhotosDto> photosDtos = { FuzzPhotosDto() };
    vector<string> cloudIdList = { cloudId };
    cloudMediaDataService->GetAgingFile(queryDto, photosDtos);
    cloudMediaDataService->GetActiveAgingFile(queryDto, photosDtos);
    cloudMediaDataService->UpdateLocalFileDirty(cloudIdList);

    cloudMediaDataService->GetVideoToCache(photosDtos);

    cloudMediaDataService->GetFilePosStat();
    cloudMediaDataService->GetCloudThmStat();
    std::vector<uint64_t> dirtyTypeStat;
    cloudMediaDataService->GetDirtyTypeStat(dirtyTypeStat);
}

static void CloudMediaDownloadServiceFuzzer()
{
    if (cloudMediaDownloadService == nullptr) {
        MEDIA_ERR_LOG("cloudMediaDownloadService is nuulptr");
        return;
    }
    string cloudId = "default-album-2";
    std::unordered_map<std::string, AdditionFileInfo> lakeInfos = {
        {"id1", AdditionFileInfo()},
    };
    int32_t type = provider->ConsumeIntegral<int32_t>() & 0x7fffffff;
    vector<MediaOperateResultDto> result;
    std::unordered_map<string, int32_t> downloadThumbnailMap = {
        {"thblum", CloudMediaDownloadService::TYPE_THM},
        {"lcd", CloudMediaDownloadService::TYPE_LCD},
        {"thm_and_lcd", CloudMediaDownloadService::TYPE_THM_AND_LCD}
    };
    int32_t totalNum = 0;
    vector<int32_t> fileIds = { 1 };
    DownloadThumbnailQueryDto queryDto = FuzzDownloadThumbnailQueryDto();
    vector<PhotosDto> photosDtos = { FuzzPhotosDto() };
    InsertQueryAsset();
    cloudMediaDownloadService->GetDownloadAsset(fileIds);
    cloudMediaDownloadService->GetDownloadThmsByUri(fileIds, type);
    cloudMediaDownloadService->OnDownloadAsset(cloudIds, result);
    cloudMediaDownloadService->GetDownloadThms(queryDto, photosDtos);
    cloudMediaDownloadService->OnDownloadThms(downloadThumbnailMap, result);
    cloudMediaDownloadService->GetDownloadThmNum(type, totalNum);
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
    if (data == nullptr) {
        return 0;
    }
    FuzzedDataProvider fdp(data, size);
    OHOS::provider = &fdp;

    OHOS::CloudMediadataServiceFuzzer();
    OHOS::CloudMediaDownloadServiceFuzzer();
    return 0;
}