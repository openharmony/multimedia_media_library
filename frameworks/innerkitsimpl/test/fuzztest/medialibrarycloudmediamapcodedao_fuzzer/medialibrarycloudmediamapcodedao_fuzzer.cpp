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

#include "medialibrarycloudmediamapcodedao_fuzzer.h"

#include <cstdint>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "cloud_media_photos_dao.h"
#undef private
#include "ability_context_impl.h"
#include "media_log.h"
#include "medialibrary_command.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_type_const.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_db_const.h"
#include "photo_map_column.h"

#include "cloud_map_code_dao.h"

namespace OHOS {
using namespace std;
using namespace OHOS::Media;
using namespace OHOS::Media::CloudSync;
const int32_t FILEID = 1;
const int32_t NUM_BYTES = 1;
const int32_t INT32_COUNT = 27;
const uint32_t UINT32_COUNT = 2;
const int64_t INT64_COUNT = 15;
const int8_t BOOL_COUNT = 15;
const int8_t STRING_COUNT = 16;
const int MIN_SIZE = sizeof(int32_t) * INT32_COUNT + sizeof(int64_t) * INT64_COUNT +
    sizeof(int8_t) * (BOOL_COUNT + STRING_COUNT) + sizeof(uint32_t) * UINT32_COUNT;
const string PHOTOMAP_TABLE = "PhotoMap";
const string PHOTOS_TABLE = "Photos";
const string ALBUM_TABLE = "PhotoAlbum";
std::shared_ptr<Media::MediaLibraryRdbStore> g_rdbStore;
FuzzedDataProvider* FDP;
std::shared_ptr<CloudMediaPhotosDao> cloudMediaPhotosDao = std::make_shared<CloudMediaPhotosDao>();

std::shared_ptr<CloudMapCodeDao> cloudMediaMapCodeDao = std::make_shared<CloudMapCodeDao>();

static inline Media::DirtyTypes FuzzDirtyTypes()
{
    int32_t value = FDP->ConsumeIntegral<int32_t>() % 8;
    if (value >= static_cast<int32_t>(Media::DirtyTypes::TYPE_SYNCED) &&
        value <= static_cast<int32_t>(Media::DirtyTypes::TYPE_COPY)) {
        return static_cast<Media::DirtyTypes>(value);
    }
    return Media::DirtyTypes::TYPE_SDIRTY;
}

static inline Media::CleanType FuzzCleanType()
{
    return FDP->ConsumeBool() ? Media::CleanType::TYPE_NEED_CLEAN : Media::CleanType::TYPE_NOT_CLEAN;
}

static inline Media::DirtyType FuzzDirtyType()
{
    int32_t value = FDP->ConsumeIntegral<int32_t>() % 8;
    if (value >= static_cast<int32_t>(Media::DirtyType::TYPE_SYNCED) &&
        value <= static_cast<int32_t>(Media::DirtyType::TYPE_COPY)) {
        return static_cast<Media::DirtyType>(value);
    }
    return Media::DirtyType::TYPE_RETRY;
}

static inline Media::CloudFilePosition FuzzCloudFilePosition()
{
    int32_t value = FDP->ConsumeIntegral<int32_t>() % 2;
    if (value >= static_cast<int32_t>(Media::CloudFilePosition::POSITION_LOCAL) &&
        value <= static_cast<int32_t>(Media::CloudFilePosition::POSITION_CLOUD)) {
        return static_cast<Media::CloudFilePosition>(value);
    }
    return Media::CloudFilePosition::POSITION_LOCAL;
}

static inline Media::CloudSync::PhotoPosition FuzzPhotoPosition()
{
    int32_t value = FDP->ConsumeIntegral<int32_t>() % 3;
    if (value >= static_cast<int32_t>(Media::CloudSync::PhotoPosition::POSITION_LOCAL) &&
        value <= static_cast<int32_t>(Media::CloudSync::PhotoPosition::POSITION_BOTH)) {
        return static_cast<Media::CloudSync::PhotoPosition>(value);
    }
    return Media::CloudSync::PhotoPosition::POSITION_BOTH;
}

static inline Media::SyncStatusType FuzzSyncStatusType()
{
    int32_t value = FDP->ConsumeIntegral<int32_t>() % 2;
    if (value >= static_cast<int32_t>(Media::SyncStatusType::TYPE_BACKUP) &&
        value <= static_cast<int32_t>(Media::SyncStatusType::TYPE_UPLOAD)) {
        return static_cast<Media::SyncStatusType>(value);
    }
    return Media::SyncStatusType::TYPE_VISIBLE;
}

static CloudMediaPullDataDto FuzzCloudMediaPullDataDto()
{
    CloudMediaPullDataDto pullData;
    pullData.attributesTitle = FDP->ConsumeBool() ? FDP->ConsumeBytesAsString(NUM_BYTES) : "";
    pullData.hasProperties = true;
    pullData.propertiesSourceFileName = "." + FDP->ConsumeBytesAsString(NUM_BYTES);
    pullData.basicFileType = FDP->ConsumeBool() ? FILE_TYPE_LIVEPHOTO : FILE_TYPE_VIDEO;
    pullData.basicEditedTime = FDP->ConsumeIntegral<int64_t>();
    pullData.basicFileName = "IMG_20250425_123456.jpg";
    pullData.cloudId = "3d4970270f8d4b15b4ced48bd7f25dd44c7ad693ae57426d863fec74422b328e";
    pullData.propertiesSourcePath =  FDP->ConsumeBool() ? "/Pictures/Screenshots/DCIM/Camera" : "";
    pullData.hasAttributes = true;
    pullData.attributesMediaType = FDP->ConsumeIntegral<int64_t>();
    pullData.duration = FDP->ConsumeIntegral<int32_t>();
    pullData.attributesHidden = FDP->ConsumeIntegral<int32_t>();
    pullData.attributesHiddenTime = FDP->ConsumeIntegral<int64_t>();
    pullData.attributesRelativePath = FDP->ConsumeBytesAsString(NUM_BYTES);
    pullData.attributesVirtualPath = FDP->ConsumeBytesAsString(NUM_BYTES);
    pullData.attributesMetaDateModified = FDP->ConsumeIntegral<int64_t>();
    pullData.attributesSubtype = FDP->ConsumeIntegral<int32_t>();
    pullData.attributesBurstCoverLevel = FDP->ConsumeIntegral<int32_t>();
    pullData.attributesBurstKey = FDP->ConsumeBytesAsString(NUM_BYTES);
    pullData.attributesDateYear = FDP->ConsumeBytesAsString(NUM_BYTES);
    pullData.attributesDateMonth = FDP->ConsumeBytesAsString(NUM_BYTES);
    pullData.attributesDateDay = FDP->ConsumeBytesAsString(NUM_BYTES);
    pullData.attributesShootingMode = FDP->ConsumeBytesAsString(NUM_BYTES);
    pullData.attributesShootingModeTag = FDP->ConsumeBytesAsString(NUM_BYTES);
    pullData.attributesDynamicRangeType = FDP->ConsumeIntegral<int32_t>();
    pullData.attributesFrontCamera = FDP->ConsumeBytesAsString(NUM_BYTES);
    pullData.attributesEditTime = FDP->ConsumeIntegral<int64_t>();
    pullData.attributesOriginalSubtype = FDP->ConsumeIntegral<int32_t>();
    pullData.attributesCoverPosition = FDP->ConsumeIntegral<int64_t>();
    pullData.attributesMovingPhotoEffectMode = FDP->ConsumeIntegral<int32_t>();
    pullData.attributesSupportedWatermarkType = FDP->ConsumeIntegral<int32_t>();
    pullData.attributesStrongAssociation = FDP->ConsumeIntegral<int32_t>();
    pullData.attributesFileId = FILEID;
    return pullData;
}

static int32_t InsertPhotoAsset()
{
    if (g_rdbStore == nullptr) {
        return E_ERR;
    }
    NativeRdb::ValuesBucket values;
    values.PutString(PhotoColumn::PHOTO_CLOUD_ID, "3d4970270f8d4b15b4ced48bd7f25dd44c7ad693ae57426d863fec74422b338e");
    values.PutInt(PhotoColumn::PHOTO_DIRTY, static_cast<int32_t>(FuzzDirtyTypes()));
    values.PutInt(PhotoColumn::PHOTO_POSITION, static_cast<int32_t>(FuzzCloudFilePosition()));
    values.PutInt(PhotoColumn::PHOTO_THUMBNAIL_READY, static_cast<int32_t>(ThumbnailReady::GENERATE_THUMB_COMPLETED));
    values.PutInt(PhotoColumn::PHOTO_LCD_VISIT_TIME, static_cast<int32_t>(LcdReady::GENERATE_LCD_COMPLETED));
    values.PutLong(PhotoColumn::MEDIA_DATE_TRASHED, 0);
    values.PutLong(PhotoColumn::MEDIA_TIME_PENDING, 0);
    values.PutString(PhotoColumn::MEDIA_NAME, "IMG_20250425_123456.jpg");
    int64_t fileId = 0;
    g_rdbStore->Insert(fileId, OHOS::PHOTOS_TABLE, values);
    return static_cast<int32_t>(fileId);
}

static int32_t UpdatePhotoAsset()
{
    if (g_rdbStore == nullptr) {
        return E_ERR;
    }
    NativeRdb::ValuesBucket values;
    values.PutString(PhotoColumn::PHOTO_CLOUD_ID, "3d4970270f8d4b15b4ced48bd7f25dd44c7ad693ae57426d863fec74422b358e");
    values.PutInt(PhotoColumn::PHOTO_CLEAN_FLAG, static_cast<int32_t>(FuzzCleanType()));
    values.PutInt(PhotoColumn::PHOTO_DIRTY, static_cast<int32_t>(FuzzDirtyType()));
    values.PutInt(PhotoColumn::PHOTO_POSITION, FuzzPhotoPosition());
    values.PutLong(PhotoColumn::PHOTO_CLOUD_VERSION, 0);
    values.PutInt(PhotoColumn::PHOTO_SYNC_STATUS, static_cast<int32_t>(FuzzSyncStatusType()));
    values.PutNull(PhotoColumn::PHOTO_ORIGINAL_ASSET_CLOUD_ID);
    values.PutLong(PhotoColumn::PHOTO_META_DATE_MODIFIED, FDP->ConsumeIntegral<int32_t>());
    int64_t fileId = 0;
    g_rdbStore->Insert(fileId, OHOS::PHOTOS_TABLE, values);
    return static_cast<int32_t>(fileId);
}

static int32_t QueryPhotoAsset()
{
    if (g_rdbStore == nullptr) {
        return E_ERR;
    }
    NativeRdb::ValuesBucket values;
    values.PutInt(PhotoColumn::MEDIA_SIZE, FDP->ConsumeIntegral<int64_t>());
    values.PutInt(PhotoColumn::PHOTO_OWNER_ALBUM_ID, FDP->ConsumeIntegral<int32_t>());
    values.PutInt(PhotoColumn::MEDIA_HIDDEN, FDP->ConsumeBool());
    values.PutInt(PhotoColumn::PHOTO_ORIENTATION, FDP->ConsumeIntegral<int32_t>());
    values.PutString(PhotoColumn::MEDIA_NAME, "IMG_20250425_123456.jpg");
    int64_t fileId = 0;
    g_rdbStore->Insert(fileId, OHOS::PHOTOS_TABLE, values);
    return static_cast<int32_t>(fileId);
}

static int32_t QueryPhotomapAsset()
{
    if (g_rdbStore == nullptr) {
        return E_ERR;
    }
    NativeRdb::ValuesBucket values;
    values.PutInt(PhotoMap::ASSET_ID, 1);
    int64_t fileId = 0;
    g_rdbStore->Insert(fileId, OHOS::PHOTOMAP_TABLE, values);
    return static_cast<int32_t>(fileId);
}

static int32_t QueryAlbumAsset()
{
    if (g_rdbStore == nullptr) {
        return E_ERR;
    }
    NativeRdb::ValuesBucket values;
    values.PutInt(PhotoAlbumColumns::ALBUM_TYPE, static_cast<int32_t>(PhotoAlbumType::USER));
    values.PutInt(PhotoAlbumColumns::ALBUM_DIRTY, static_cast<int32_t>(DirtyType::TYPE_NEW));
    values.PutString(PhotoAlbumColumns::ALBUM_CLOUD_ID, HIDDEN_ALBUM);
    values.PutString(PhotoAlbumColumns::ALBUM_LPATH, "records");
    int64_t fileId = 0;
    g_rdbStore->Insert(fileId, OHOS::ALBUM_TABLE, values);
    return static_cast<int32_t>(fileId);
}

static int32_t InsertDeleteAsset()
{
    if (g_rdbStore == nullptr) {
        return E_ERR;
    }
    NativeRdb::ValuesBucket values;
    values.PutString(Media::PhotoColumn::PHOTO_CLOUD_ID,
        "3d4970270f8d4b15b4ced48bd7f25dd44c7ad693ae57426d863fec74422b368e");
    values.PutString(MediaColumn::MEDIA_FILE_PATH, FDP->ConsumeBytesAsString(NUM_BYTES));
    int64_t fileId = 0;
    g_rdbStore->Insert(fileId, OHOS::PHOTOS_TABLE, values);
    return static_cast<int32_t>(fileId);
}

static void BatchInsertFileFuzzer()
{
    auto photoRefresh = std::make_shared<AccurateRefresh::AssetAccurateRefresh>();
    std::map<std::string, int> recordAnalysisAlbumMaps;
    recordAnalysisAlbumMaps.insert(std::make_pair(PhotoMap::ALBUM_ID, FDP->ConsumeIntegral<int32_t>()));

    std::map<std::string, std::set<int>> recordAlbumMaps;
    recordAlbumMaps.insert(std::make_pair(PhotoMap::ALBUM_ID, std::set<int>({FDP->ConsumeIntegral<int32_t>()})));
    recordAlbumMaps.insert(std::make_pair(PhotoMap::DIRTY,
        std::set<int>({static_cast<int32_t>(FuzzDirtyTypes())})));

    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(MediaColumn::MEDIA_FILE_PATH, FDP->ConsumeBytesAsString(NUM_BYTES));
    std::vector<NativeRdb::ValuesBucket> insertFiles;
    cloudMediaPhotosDao->BatchInsertFile(recordAnalysisAlbumMaps, recordAlbumMaps, insertFiles, photoRefresh);

    insertFiles.push_back(valuesBucket);
    InsertPhotoAsset();
    cloudMediaPhotosDao->BatchInsertFile(recordAnalysisAlbumMaps, recordAlbumMaps, insertFiles, photoRefresh);
}

static void UpdateRecordToDatabaseFuzzer()
{
    auto photoRefresh = std::make_shared<AccurateRefresh::AssetAccurateRefresh>();
    CloudMediaPullDataDto pullData = FuzzCloudMediaPullDataDto();
    bool isLocal = true;
    bool mtimeChanged = FDP->ConsumeBool();
    std::set<std::string> refreshAlbums;
    int32_t number = 5;
    std::vector<int32_t> stats(number, 0);
    UpdatePhotoAsset();
    QueryPhotomapAsset();
    cloudMediaPhotosDao->UpdateRecordToDatabase(pullData, isLocal, mtimeChanged, refreshAlbums, stats, photoRefresh);
}

static void ConflictDataMergeFuzzer()
{
    auto photoRefresh = std::make_shared<AccurateRefresh::AssetAccurateRefresh>();
    CloudMediaPullDataDto pullData = FuzzCloudMediaPullDataDto();
    std::string fullPath;
    bool cloudStd = FDP->ConsumeBool();
    std::set<int32_t> albumIds;
    std::set<std::string> refreshAlbums;
    cloudMediaPhotosDao->ConflictDataMerge(pullData, fullPath, cloudStd, albumIds, refreshAlbums, photoRefresh);
}

static void GetInsertParamsFuzzer()
{
    CloudMediaPullDataDto pullData = FuzzCloudMediaPullDataDto();
    std::map<std::string, int> recordAnalysisAlbumMaps;
    std::map<std::string, std::set<int>> recordAlbumMaps;
    std::set<std::string> refreshAlbums;
    std::vector<NativeRdb::ValuesBucket> insertFiles;
    cloudMediaPhotosDao->GetInsertParams(pullData, recordAnalysisAlbumMaps, recordAlbumMaps,
        refreshAlbums, insertFiles);
}

static void BatchQueryLocalFuzzer()
{
    vector<CloudMediaPullDataDto> datas;
    CloudMediaPullDataDto pullData = FuzzCloudMediaPullDataDto();
    datas.emplace_back(pullData);
    std::vector<std::string> columns;
    int32_t rowCount = -1;
    cloudMediaPhotosDao->BatchQueryLocal(datas, columns, rowCount);
}

static void GetLocalKeyDataFuzzer()
{
    KeyData localKeyData;
    QueryPhotoAsset();
    NativeRdb::AbsRdbPredicates predicates = NativeRdb::AbsRdbPredicates(PhotoColumn::PHOTOS_TABLE);
    predicates.EqualTo(PhotoColumn::MEDIA_NAME, "IMG_20250425_123456.jpg");
    std::vector<std::string> columns;
    columns.emplace_back(PhotoColumn::PHOTO_OWNER_ALBUM_ID);
    auto resultSet = g_rdbStore->Query(predicates, columns);
    CHECK_AND_RETURN_LOG(resultSet != nullptr, "Failed to query.");
    QueryAlbumAsset();
    cloudMediaPhotosDao->GetLocalKeyData(localKeyData, resultSet);
}

static void JudgeConflictFuzzer()
{
    CloudMediaPullDataDto pullData = FuzzCloudMediaPullDataDto();
    KeyData localKeyData;
    KeyData cloudKeyData;
    cloudMediaPhotosDao->JudgeConflict(pullData, localKeyData, cloudKeyData);

    pullData.attributesSrcAlbumIds.emplace_back("default-album-4");
    cloudMediaPhotosDao->JudgeConflict(pullData, localKeyData, cloudKeyData);

    localKeyData.sourceAlbum = "default-album-4";
    localKeyData.lPath = FDP->ConsumeBool() ? "localKeyData_lPath" : "lPath";
    cloudKeyData.lPath = FDP->ConsumeBool() ? "cloudKeyData_lPath" : "lPath";
    cloudMediaPhotosDao->JudgeConflict(pullData, localKeyData, cloudKeyData);

    localKeyData.isize = FDP->ConsumeIntegral<int64_t>();
    cloudKeyData.isize = FDP->ConsumeIntegral<int64_t>();
    cloudMediaPhotosDao->JudgeConflict(pullData, localKeyData, cloudKeyData);

    localKeyData.lPath = FDP->ConsumeBool() ? "localKeyData_lPath" : "lPath";
    cloudKeyData.lPath = FDP->ConsumeBool() ? "cloudKeyData_lPath" : "lPath";
    cloudMediaPhotosDao->JudgeConflict(pullData, localKeyData, cloudKeyData);

    localKeyData.displayName = "localKeyData_displayName";
    cloudKeyData.displayName = "cloudKeyData_displayName";
    cloudMediaPhotosDao->JudgeConflict(pullData, localKeyData, cloudKeyData);
}

static void GetRecordsFuzzer()
{
    std::vector<std::string> cloudIds;
    InsertPhotoAsset();
    cloudMediaPhotosDao->GetRetryRecords(cloudIds);
    cloudMediaPhotosDao->GetCheckRecords(cloudIds);
    string cloudId = "3d4970270f8d4b15b4ced48bd7f25dd44c7ad693ae57426d863fec74422b378e";
    cloudIds.emplace_back(cloudId);
    cloudIds.emplace_back(FDP->ConsumeBytesAsString(NUM_BYTES));
    cloudMediaPhotosDao->GetRetryRecords(cloudIds);
    cloudMediaPhotosDao->GetCheckRecords(cloudIds);

    int32_t querySize = FDP->ConsumeIntegral<uint32_t>() & 0xf;
    std::vector<PhotosPo> createdRecords;
    std::vector<PhotosPo> cloudRecordPoList;
    std::vector<PhotosPo> copyRecords;
    int32_t dirtyType = static_cast<int32_t>(FuzzDirtyType());
    cloudMediaPhotosDao->GetCreatedRecords(querySize, createdRecords);
    cloudMediaPhotosDao->GetMetaModifiedRecords(querySize, cloudRecordPoList, dirtyType);
    cloudMediaPhotosDao->GetFileModifiedRecords(querySize, cloudRecordPoList);
    cloudMediaPhotosDao->GetCopyRecords(querySize, copyRecords);
}

static void GetDeletedRecordsAssetFuzzer()
{
    int32_t limitSize = FDP->ConsumeBool() ? FDP->ConsumeIntegral<int32_t>() : -1;
    std::vector<PhotosPo> cloudRecordPoList;
    InsertPhotoAsset();
    cloudMediaPhotosDao->GetDeletedRecordsAsset(limitSize, cloudRecordPoList);
}

static void GetPhotoLocalInfoFuzzer()
{
    std::vector<PhotosDto> records;
    PhotosDto photo;
    photo.cloudId = "3d4970270f8d4b15b4ced48bd7f25dd44c7ad693ae57426d863fec74422b388e";
    photo.fileId = FDP->ConsumeIntegral<int32_t>();
    records.emplace_back(photo);
    std::unordered_map<std::string, LocalInfo> infoMap;
    std::string type = FDP->ConsumeBool() ? PhotoColumn::PHOTO_CLOUD_ID : PhotoColumn::PHOTO_CLOUD_VERSION;
    InsertPhotoAsset();
    cloudMediaPhotosDao->GetPhotoLocalInfo(records, infoMap, type);
}

static void UpdateLocalAlbumMapFuzzer()
{
    std::string cloudId = "3d4970270f8d4b15b4ced48bd7f25dd44c7ad693ae57426d863fec74422b398e";
    InsertPhotoAsset();
    cloudMediaPhotosDao->UpdateLocalAlbumMap(cloudId);
}

static void DeleteSameNamePhotoFuzzer()
{
    PhotosDto photo;
    photo.fileId = FDP->ConsumeIntegral<uint32_t>() & 0xf;
    InsertPhotoAsset();
    cloudMediaPhotosDao->DeleteSameNamePhoto(photo);
}

static void GetSameNamePhotoCountFuzzer()
{
    PhotosDto photo;
    photo.displayName = "IMG_20250425_123456.jpg";
    photo.size = FDP->ConsumeIntegral<int64_t>() & 0xff;
    photo.ownerAlbumId = FDP->ConsumeIntegral<int32_t>() & 0xf;
    photo.mediaType = MediaType::MEDIA_TYPE_IMAGE;
    photo.rotation = FDP->ConsumeIntegral<int32_t>() & 0xf;
    bool isHide = FDP->ConsumeBool();
    int32_t count = 1;
    QueryPhotoAsset();
    cloudMediaPhotosDao->GetSameNamePhotoCount(photo, isHide, count);
}

static void UpdatePhotoCreatedRecordFuzzer()
{
    auto photoRefresh = std::make_shared<AccurateRefresh::AssetAccurateRefresh>();
    PhotosDto record;
    record.fileId = FDP->ConsumeIntegral<int32_t>() & 0xf;
    record.cloudId = "3d4970270f8d4b15b4ced48bd7f25dd44c7ad693ae57426d863fec74422b408e";
    record.version = FDP->ConsumeIntegral<int64_t>() & 0xf;
    std::unordered_map<std::string, LocalInfo> localMap;
    UpdatePhotoAsset();
    cloudMediaPhotosDao->UpdatePhotoCreatedRecord(record, localMap, photoRefresh);
}

static void OnModifyPhotoRecordFuzzer()
{
    auto photoRefresh = std::make_shared<AccurateRefresh::AssetAccurateRefresh>();
    PhotosDto record;
    cloudMediaPhotosDao->OnModifyPhotoRecord(record, photoRefresh);

    record.cloudId = "3d4970270f8d4b15b4ced48bd7f25dd44c7ad693ae57426d863fec74422b418e";
    record.version = FDP->ConsumeIntegral<int64_t>();
    UpdatePhotoAsset();
    cloudMediaPhotosDao->OnModifyPhotoRecord(record, photoRefresh);
}

static void UpdateFdirtyVersionFuzzer()
{
    auto photoRefresh = std::make_shared<AccurateRefresh::AssetAccurateRefresh>();
    PhotosDto record;
    record.cloudId = "3d4970270f8d4b15b4ced48bd7f25dd44c7ad693ae57426d863fec74422b428e";
    record.version = FDP->ConsumeIntegral<int64_t>();
    UpdatePhotoAsset();
    cloudMediaPhotosDao->UpdateFdirtyVersion(record, photoRefresh);
}

static void OnDeleteRecordsAssetFuzzer()
{
    auto photoRefresh = std::make_shared<AccurateRefresh::AssetAccurateRefresh>();
    PhotosDto record;
    record.cloudId = "3d4970270f8d4b15b4ced48bd7f25dd44c7ad693ae57426d863fec74422b438e";
    record.version = FDP->ConsumeIntegral<int64_t>();
    UpdatePhotoAsset();
    cloudMediaPhotosDao->OnDeleteRecordsAsset(record, photoRefresh);
}

static void OnCopyPhotoRecordFuzzer()
{
    auto photoRefresh = std::make_shared<AccurateRefresh::AssetAccurateRefresh>();
    PhotosDto record;
    record.cloudId = "3d4970270f8d4b15b4ced48bd7f25dd44c7ad693ae57426d863fec74422b448e";
    record.fileId = FDP->ConsumeIntegral<int32_t>() & 0xf;
    record.path = FDP->ConsumeBytesAsString(NUM_BYTES);
    record.version = FDP->ConsumeIntegral<int64_t>() & 0xf;
    record.cloudVersion = 0;
    UpdatePhotoAsset();
    cloudMediaPhotosDao->OnCopyPhotoRecord(record, photoRefresh);
}

static void ClearCloudInfoFuzzer()
{
    std::string cloudId = "3d4970270f8d4b15b4ced48bd7f25dd44c7ad693ae57426d863fec74422b458e";
    UpdatePhotoAsset();
    cloudMediaPhotosDao->ClearCloudInfo(cloudId);
}

static void DeleteFileNotExistPhotoFuzzer()
{
    auto photoRefresh = std::make_shared<AccurateRefresh::AssetAccurateRefresh>();
    std::string path;
    InsertDeleteAsset();
    cloudMediaPhotosDao->DeleteFileNotExistPhoto(path, photoRefresh);
}

static void HandleSameNameRenameFuzzer()
{
    auto photoRefresh = std::make_shared<AccurateRefresh::AssetAccurateRefresh>();
    PhotosDto photo;
    photo.fileName = "image.jpg";
    UpdatePhotoAsset();
    cloudMediaPhotosDao->HandleSameNameRename(photo, photoRefresh);
}

static void UpdatePhotoVisibleFuzzer()
{
    UpdatePhotoAsset();
    cloudMediaPhotosDao->UpdatePhotoVisible();
}

static void UpdateAlbumInternalFuzzer()
{
    std::set<std::string> refreshAlbums;
    refreshAlbums.insert(FDP->ConsumeBytesAsString(NUM_BYTES));
    cloudMediaPhotosDao->UpdateAlbumInternal(refreshAlbums);
}

static void SetRetryFuzzer()
{
    std::string cloudId = "3d4970270f8d4b15b4ced48bd7f25dd44c7ad693ae57426d863fec74422b468e";
    UpdatePhotoAsset();
    cloudMediaPhotosDao->SetRetry(cloudId);
}

static void DeleteLocalByCloudIdFuzzer()
{
    auto photoRefresh = std::make_shared<AccurateRefresh::AssetAccurateRefresh>();
    std::string cloudId = "3d4970270f8d4b15b4ced48bd7f25dd44c7ad693ae57426d863fec74422b478e";
    InsertDeleteAsset();
    cloudMediaPhotosDao->DeleteLocalByCloudId(cloudId, photoRefresh);
}

static void UpdateFailRecordsCloudIdFuzzer()
{
    auto photoRefresh = std::make_shared<AccurateRefresh::AssetAccurateRefresh>();
    PhotosDto record;
    record.cloudId = "3d4970270f8d4b15b4ced48bd7f25dd44c7ad693ae57426d863fec74422b488e";
    record.fileId = 1;
    std::unordered_map<std::string, LocalInfo> localMap;
    localMap.insert({"1", LocalInfo()});
    cloudMediaPhotosDao->UpdateFailRecordsCloudId(record, localMap, photoRefresh);
}

static void InsertAndRemoveFailedRecordFuzzer()
{
    int32_t fileId = FDP->ConsumeIntegral<int32_t>();
    std::string cloudId = "3d4970270f8d4b15b4ced48bd7f25dd44c7ad693ae57426d863fec74422b438e";
    cloudMediaPhotosDao->InsertPhotoCreateFailedRecord(fileId);
    cloudMediaPhotosDao->InsertPhotoModifyFailedRecord(cloudId);
    cloudMediaPhotosDao->InsertPhotoCopyFailedRecord(fileId);
    cloudMediaPhotosDao->RemovePhotoCreateFailedRecord(fileId);
    cloudMediaPhotosDao->RemovePhotoModifyFailedRecord(cloudId);
    cloudMediaPhotosDao->RemovePhotoCopyFailedRecord(fileId);
    cloudMediaPhotosDao->ClearPhotoFailedRecords();
}

static void InsertMapCodeFuzzer()
{
    vector<CloudMediaPullDataDto> datas;
    CloudMediaPullDataDto pullData = FuzzCloudMediaPullDataDto();
    datas.emplace_back(pullData);
    cloudMediaMapCodeDao->InsertDatasToMapCode(datas);
}

static void UpdateMapCodeFuzzer()
{
    CloudMediaPullDataDto pullData = FuzzCloudMediaPullDataDto();
    cloudMediaMapCodeDao->UpdateDataToMapCode(pullData);
}

static void DeleteMapCodesFuzzer()
{
    vector<CloudMediaPullDataDto> datas;
    CloudMediaPullDataDto pullData = FuzzCloudMediaPullDataDto();
    datas.emplace_back(pullData);
    cloudMediaMapCodeDao->DeleteMapCodesByPullDatas(datas);
}

static void DeleteMapCodeFuzzer()
{
    CloudMediaPullDataDto pullData = FuzzCloudMediaPullDataDto();
    cloudMediaMapCodeDao->DeleteMapCodesByPullData(pullData);
}

static void MediaLibraryCloudMediaPhotosDaoFuzzer()
{
    BatchInsertFileFuzzer();
    UpdateRecordToDatabaseFuzzer();
    ConflictDataMergeFuzzer();
    GetInsertParamsFuzzer();
    BatchQueryLocalFuzzer();
    GetLocalKeyDataFuzzer();
    JudgeConflictFuzzer();
    GetRecordsFuzzer();

    GetDeletedRecordsAssetFuzzer();
    GetPhotoLocalInfoFuzzer();
    UpdateLocalAlbumMapFuzzer();
    DeleteSameNamePhotoFuzzer();
    GetSameNamePhotoCountFuzzer();

    UpdatePhotoCreatedRecordFuzzer();
    OnModifyPhotoRecordFuzzer();
    UpdateFdirtyVersionFuzzer();
    OnDeleteRecordsAssetFuzzer();
    OnCopyPhotoRecordFuzzer();

    InsertMapCodeFuzzer();
    UpdateMapCodeFuzzer();
    DeleteMapCodesFuzzer();
    DeleteMapCodeFuzzer();

    ClearCloudInfoFuzzer();
    DeleteFileNotExistPhotoFuzzer();
    HandleSameNameRenameFuzzer();
    UpdatePhotoVisibleFuzzer();
    UpdateAlbumInternalFuzzer();
    SetRetryFuzzer();
    DeleteLocalByCloudIdFuzzer();
    UpdateFailRecordsCloudIdFuzzer();
    InsertAndRemoveFailedRecordFuzzer();
}

void SetTables()
{
    vector<string> createTableSqlList = {
        PhotoColumn::CREATE_PHOTO_TABLE,
        PhotoAlbumColumns::CREATE_TABLE,
        PhotoMap::CREATE_TABLE,
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
    int32_t sceneCode = 0;
    auto ret = Media::MediaLibraryDataManager::GetInstance()->InitMediaLibraryMgr(abilityContextImpl,
        abilityContextImpl, sceneCode);
    CHECK_AND_RETURN_LOG(ret == NativeRdb::E_OK, "InitMediaLibraryMgr failed, ret: %{public}d", ret);

    auto rdbStore = Media::MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return;
    }
    g_rdbStore = rdbStore;
    SetTables();
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
    OHOS::FDP = &fdp;
    if (data == nullptr || size < OHOS::MIN_SIZE) {
        return 0;
    }
    OHOS::MediaLibraryCloudMediaPhotosDaoFuzzer();
    return 0;
}