/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#define MLOG_TAG "Media_Cloud_Service"

#include "cloud_media_photos_service.h"

#include <string>
#include <vector>

#include "cloud_media_sync_utils.h"
#include "dataobs_mgr_changeinfo.h"
#include "directory_ex.h"
#include "file_ex.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "cloud_media_file_utils.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "on_fetch_records_vo.h"
#include "photos_dto.h"
#include "photo_file_utils.h"
#include "result_set_utils.h"
#include "medialibrary_asset_operations.h"
#include "scanner_utils.h"
#include "medialibrary_notify.h"
#include "cloud_media_dao_const.h"
#include "media_gallery_sync_notify.h"
#include "cloud_media_sync_const.h"

using ChangeType = OHOS::AAFwk::ChangeInfo::ChangeType;
namespace OHOS::Media::CloudSync {
static void NotifyDataChange(ChangeType changeType, int32_t fileId, const std::string &dateAdded)
{
    if (changeType != ChangeType::INVAILD) {
        std::string notifyUri =
            PhotoColumn::PHOTO_GALLERY_CLOUD_URI_PREFIX +
            to_string(fileId);  // PHOTO_GALLERY_CLOUD_URI_PREFIX = "file://cloudsync/gallery/Photo/";
        if (changeType == ChangeType::DELETE) {
            notifyUri += '/' + dateAdded;
        }
        MediaGallerySyncNotify::GetInstance().TryNotify(notifyUri, changeType, to_string(fileId));
    }
}

int32_t CloudMediaPhotosService::PullDelete(const CloudMediaPullDataDto &data, std::set<std::string> &refreshAlbums)
{
    std::string cloudId = data.cloudId;
    MEDIA_INFO_LOG("Delete cloudId: %{public}s.", cloudId.c_str());
    std::string localPath = data.localPath;

    bool isLocal = CloudMediaSyncUtils::FileIsLocal(data.localPosition);
    if (isLocal && CloudMediaSyncUtils::IsLocalDirty(data.localDirty, true)) {
        MEDIA_ERR_LOG("local record dirty, ignore cloud delete");
        return this->photosDao_.ClearCloudInfo(cloudId);
    }

    if (CloudMediaFileUtils::LocalWriteOpen(localPath)) {
        return this->photosDao_.SetRetry(cloudId);
    }
    int32_t ret = this->photosDao_.DeleteLocalByCloudId(cloudId);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("delete in rdb failed, ret:%{public}d", ret);
        return this->photosDao_.SetRetry(cloudId);
    }
    if (!cloudId.empty()) {
        std::string notifyUri =
            PhotoColumn::PHOTO_GALLERY_CLOUD_URI_PREFIX + std::to_string(data.localFileId) + '/' + data.localDateAdded;
        MediaGallerySyncNotify::GetInstance().TryNotify(
            notifyUri, ChangeType::DELETE, std::to_string(data.localFileId));
    }
    refreshAlbums.emplace(data.localOwnerAlbumId);

    std::string prefixCloud = "";
    std::string mergePath = CloudMediaSyncUtils::GetCloudPath(localPath, prefixCloud);
    ret = unlink(mergePath.c_str());
    if (ret != 0) {
        MEDIA_ERR_LOG("unlink local failed.");
    }

    CloudMediaSyncUtils::RemoveThmParentPath(localPath, prefixCloud);       // ?是否是沙箱路径
    CloudMediaSyncUtils::RemoveEditDataParentPath(localPath, prefixCloud);  // ?是否是沙箱路径
    CloudMediaSyncUtils::RemoveMetaDataPath(localPath, prefixCloud);        // ?是否是沙箱路径
    CloudMediaSyncUtils::InvalidVideoCache(localPath);
    CloudMediaSyncUtils::RemoveMovingPhoto(localPath);
    return E_OK;
}

int32_t CloudMediaPhotosService::IsMtimeChanged(const CloudMediaPullDataDto &pullData, bool &changed)
{
    if (!pullData.localDateModified.empty() && pullData.attributesEditedTimeMs != -1) {
        std::string cloudDateModified = std::to_string(pullData.attributesEditedTimeMs);
        MEDIA_INFO_LOG("localDateModified: %{public}s, attributesEditedTimeMs: %{public}s",
            pullData.localDateModified.c_str(),
            cloudDateModified.c_str());
        changed = !(pullData.localDateModified == cloudDateModified);
        return E_OK;
    }

    if (pullData.localDateAdded.empty()) {
        MEDIA_INFO_LOG("CloudMediaPhotosService::IsMtimeChanged pullData.localDateAdded empty");
        return E_CLOUDSYNC_INVAL_ARG;
    }

    std::string createTime = std::to_string(pullData.basicCreatedTime);
    MEDIA_INFO_LOG(
        "localDateAdded: %{public}s, cloudDateAdded: %{public}s", pullData.localDateAdded.c_str(), createTime.c_str());
    changed = !(pullData.localDateAdded == createTime);
    return E_OK;
}

void CloudMediaPhotosService::ExtractEditDataCamera(const CloudMediaPullDataDto &pullData)
{
    std::string editDataCamera = pullData.attributesEditDataCamera;
    CHECK_AND_RETURN_LOG(!editDataCamera.empty(), "Cannot find attributes::editDataCamera.");

    std::string editDataCameraPath = PhotoFileUtils::GetEditDataCameraPath(pullData.localPath);
    MEDIA_INFO_LOG("editDataCameraPath: %{public}s , editDataCamera: %{public}s",
        editDataCameraPath.c_str(),
        editDataCamera.c_str());
    ForceCreateDirectory(MediaFileUtils::GetParentPath(editDataCameraPath));
    if (!SaveStringToFile(editDataCameraPath, editDataCamera)) {
        MEDIA_ERR_LOG("save editDataCamera failed");
    }
}

int32_t CloudMediaPhotosService::PullUpdate(const CloudMediaPullDataDto &pullData, std::set<std::string> &refreshAlbums,
    std::vector<PhotosDto> &fdirtyData, std::vector<int32_t> &stats)
{
    // RETURN_ON_ERR(IsStop());
    std::string cloudId = pullData.cloudId;
    MEDIA_INFO_LOG("Update cloudId: %{public}s.", cloudId.c_str());
    CHECK_AND_RETURN_RET_INFO_LOG(!CloudMediaSyncUtils::IsLocalDirty(pullData.localDirty, false),
        E_OK,
        "local record dirty, ignore cloud update");

    bool mtimeChanged = false;
    int32_t ret = IsMtimeChanged(pullData, mtimeChanged);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("cloudId: %{public}s get mtime changed failed, ret: %{public}d.", cloudId.c_str(), ret);
    }

    bool isLocal = CloudMediaSyncUtils::FileIsLocal(pullData.localPosition);
    if (isLocal && mtimeChanged) {
        if (CloudMediaFileUtils::LocalWriteOpen(pullData.localPath)) {
            return this->photosDao_.SetRetry(cloudId);
        }
    }

    // UpdateRecordToDatabase更新成功，stats[StatsIndex::FILE_MODIFY_RECORDS_COUNT]会增加
    int32_t updateCount = stats[StatsIndex::FILE_MODIFY_RECORDS_COUNT];
    ret = this->photosDao_.UpdateRecordToDatabase(pullData, isLocal, mtimeChanged, refreshAlbums, stats);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("PullUpdate database Error cloudId: %{public}s, ret: %{public}d.", cloudId.c_str(), ret);
        return ret;
    }
    // Notify(PhotoColumn::PHOTO_GALLERY_CLOUD_URI_PREFIX + std::to_string(pullData.localFileId) + "/" +
    //     pullData.localDateAdded, NotifyType::NOTIFY_UPDATE);
    std::string notifyUri = PhotoColumn::PHOTO_GALLERY_CLOUD_URI_PREFIX + std::to_string(pullData.localFileId);
    MediaGallerySyncNotify::GetInstance().TryNotify(
        notifyUri, ChangeType::UPDATE, std::to_string(pullData.localFileId));

    refreshAlbums.emplace(pullData.localOwnerAlbumId);
    ExtractEditDataCamera(pullData);

    if (mtimeChanged && (updateCount != stats[StatsIndex::FILE_MODIFY_RECORDS_COUNT])) {
        PhotosDto dto;
        dto.cloudId = cloudId;
        if (!CloudMediaFileUtils::GetParentPathAndFilename(pullData.localPath, dto.path, dto.displayName)) {
            MEDIA_WARN_LOG("Failed to get parent path and real filename.");
        }
        dto.size = pullData.localSize;
        dto.mediaType = pullData.localMediaType;
        dto.modifiedTime = pullData.modifiedTime;
        dto.originalCloudId = pullData.localOriginalAssetCloudId;
        CloudMediaSyncUtils::FillPhotosDto(
            dto, pullData.localPath, pullData.localOrientation, pullData.localThumbState);
        fdirtyData.emplace_back(dto);
        if (isLocal) {
            CloudMediaSyncUtils::RemoveThmParentPath(pullData.localPath, PhotoColumn::FILES_CLOUD_DIR);
            CloudMediaSyncUtils::RemoveMetaDataPath(pullData.localPath, PhotoColumn::FILES_CLOUD_DIR);
            CloudMediaSyncUtils::RemoveMovingPhoto(pullData.localPath);
            if (pullData.attributesMediaType == static_cast<int32_t>(MediaType::MEDIA_TYPE_VIDEO)) {
                CloudMediaSyncUtils::InvalidVideoCache(pullData.localPath);
            }
        }
    }
    return E_OK;
}

void CloudMediaPhotosService::ConvertRotateValue(int32_t exifRotateValue, int32_t &outRotateValue)
{
    switch (exifRotateValue) {
        case ORIENTATION_NORMAL:
            outRotateValue = ROTATE_ANGLE_0;
            break;
        case ORIENTATION_ROTATE_90:
            outRotateValue = ROTATE_ANGLE_90;
            break;
        case ORIENTATION_ROTATE_180:
            outRotateValue = ROTATE_ANGLE_180;
            break;
        case ORIENTATION_ROTATE_270:
            outRotateValue = ROTATE_ANGLE_270;
            break;
        default:
            outRotateValue = ROTATE_ANGLE_0;
            break;
    }
}

int32_t CloudMediaPhotosService::GetCloudKeyData(const CloudMediaPullDataDto &pullData, KeyData &keyData)
{
    bool ret = (!pullData.hasAttributes || pullData.basicFileName.empty() || pullData.basicSize == -1);
    CHECK_AND_RETURN_RET_LOG(!ret, E_CLOUDSYNC_INVAL_ARG, "PullData cannot find attributes or filename or size");

    keyData.displayName = pullData.basicFileName;

    int64_t singleEditTime = pullData.attributesMetaDateModified;
    int64_t dualEditTime = pullData.basicEditedTime;
    keyData.modifyTime = dualEditTime > singleEditTime ? dualEditTime : singleEditTime;

    keyData.isize = pullData.basicSize;
    keyData.createTime = pullData.basicCreatedTime;

    int32_t exifRotateValue = ORIENTATION_NORMAL;
    if (pullData.propertiesRotate != -1) {
        exifRotateValue = pullData.propertiesRotate;
    }

    keyData.lPath = CloudMediaSyncUtils::GetLpath(pullData);
    ConvertRotateValue(exifRotateValue, keyData.exifRotateValue);

    int32_t fileType = pullData.basicFileType;
    CHECK_AND_RETURN_RET_LOG(fileType != -1, E_CLOUDSYNC_INVAL_ARG, "Cannot find basic::fileType");

    keyData.mediaType = fileType == FILE_TYPE_VIDEO ? static_cast<int32_t>(MediaType::MEDIA_TYPE_VIDEO)
                                                    : static_cast<int32_t>(MediaType::MEDIA_TYPE_IMAGE);
    return E_OK;
}

void CloudMediaPhotosService::GetMergeDataMap(
    const std::vector<CloudMediaPullDataDto> &pullDatas, std::map<std::string, KeyData> &mergeDataMap)
{
    KeyData mergeData;
    for (auto &pullData : pullDatas) {
        auto ret = GetCloudKeyData(pullData, mergeData);
        if (ret != E_OK) {
            MEDIA_ERR_LOG("GetCloudKey data failed");
            continue;
        }
        mergeDataMap.insert(std::make_pair(pullData.cloudId, mergeData));
    }
}

int32_t CloudMediaPhotosService::DoDataMerge(const CloudMediaPullDataDto &pullData, const KeyData &localKeyData,
    const KeyData &cloudKeyData, std::set<std::string> &refreshAlbums)
{
    set<int32_t> cloudMapIds;
    bool cloudStd = false;
    if ((localKeyData.modifyTime != 0) && (cloudKeyData.modifyTime > localKeyData.modifyTime)) {
        MEDIA_INFO_LOG("cloudStd modify");
        cloudStd = true;
    }

    int32_t ret = this->photosDao_.ConflictDataMerge(pullData, cloudStd, cloudMapIds, refreshAlbums);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("Conflict dataMerge fail");
        return ret;
    }
    ret = this->photosDao_.UpdateAssetInPhotoMap(pullData.attributesFileId, cloudMapIds);

    if (cloudStd && localKeyData.createTime != cloudKeyData.createTime) {
        std::string notifyUri = PhotoColumn::PHOTO_CLOUD_URI_PREFIX + to_string(pullData.attributesFileId) + '/' +
                                to_string(localKeyData.createTime) + '/' + to_string(cloudKeyData.createTime);
        // Notify(notifyUri, static_cast<NotifyType>(ExtraChangeType::PHOTO_TIME_UPDATE));
        MediaGallerySyncNotify::GetInstance().TryNotify(notifyUri,
            static_cast<ChangeType>(ExtraChangeType::PHOTO_TIME_UPDATE),
            to_string(pullData.attributesFileId));
    }
    return E_OK;
}

int32_t CloudMediaPhotosService::PullRecordsConflictProc(std::vector<CloudMediaPullDataDto> &allPullDatas,
    std::set<std::string> &refreshAlbums, std::vector<int32_t> &stats, std::vector<std::string> &failedRecords)
{
    MEDIA_INFO_LOG("PullRecordsConflictProc enter");
    int32_t rowCount = 0;
    auto resultSet = this->photosDao_.BatchQueryLocal(allPullDatas, PULL_QUERY_COLUMNS, rowCount);
    CHECK_AND_RETURN_RET_LOG(
        resultSet != nullptr, E_CLOUDSYNC_RDB_QUERY_FAILED, "PullRecordsConflictProc Failed to query.");
    CHECK_AND_RETURN_RET_INFO_LOG(rowCount != 0, E_OK, "PullRecordsConflictProc Normal download process.");
    MEDIA_INFO_LOG("PullRecordsConflictProc same displayName files num: %{public}d", rowCount);

    std::map<std::string, KeyData> mergeDataMap;  // {cloudId: cloudkeydata}
    GetMergeDataMap(allPullDatas, mergeDataMap);

    KeyData localKeyData;
    while (resultSet->GoToNextRow() == 0) {
        this->photosDao_.GetLocalKeyData(localKeyData, resultSet);

        KeyData cloudKeyData;
        for (auto mergeData = allPullDatas.begin(); mergeData != allPullDatas.end();) {
            string id = mergeData->cloudId;
            if (mergeDataMap.find(id) == mergeDataMap.end()) {
                MEDIA_INFO_LOG("PullRecordsConflictProc GetLocalKey Data failed: %{public}s", id.c_str());
                ++mergeData;
                continue;
            }
            cloudKeyData = mergeDataMap[id];
            auto isMatchConflict = this->photosDao_.JudgeConflict(*mergeData, localKeyData, cloudKeyData);
            if (isMatchConflict) {
                MEDIA_INFO_LOG("PullRecordsConflictProc merge record, recordId:%{public}s", id.c_str());
                stats[StatsIndex::MERGE_RECORDS_COUNT]++;
                int32_t ret = DoDataMerge(*mergeData, localKeyData, cloudKeyData, refreshAlbums);
                if (ret != E_OK) {
                    failedRecords.emplace_back(mergeData->cloudId);
                }
                mergeData = allPullDatas.erase(mergeData);  // 把合一数据剔除，剩下的就是纯新增数据
                break;
            } else {
                ++mergeData;
            }
        }
    }
    MEDIA_INFO_LOG("PullRecordsConflictProc end");
    return E_OK;
}

int32_t CloudMediaPhotosService::PullInsert(
    const std::vector<CloudMediaPullDataDto> &pullDatas, std::vector<std::string> &failedRecords)
{
    CHECK_AND_RETURN_RET_INFO_LOG(!pullDatas.empty(), E_OK, "PullInsert No need to pull insert.");

    std::set<std::string> refreshAlbums;
    std::vector<int32_t> stats = {0, 0, 0, 0, 0};
    std::map<std::string, int> recordAnalysisAlbumMaps;
    std::map<std::string, std::set<int>> recordAlbumMaps;
    std::vector<NativeRdb::ValuesBucket> insertFiles;

    int32_t ret;
    std::vector<CloudMediaPullDataDto> allPullDatas = pullDatas;
    PullRecordsConflictProc(allPullDatas, refreshAlbums, stats, failedRecords);
    for (auto insertData : allPullDatas) {
        // RETURN_ON_ERR(IsStop());
        MEDIA_INFO_LOG("PullInsert insert of record %{public}s", insertData.cloudId.c_str());
        ExtractEditDataCamera(insertData);
        ret = this->photosDao_.GetInsertParams(
            insertData, recordAnalysisAlbumMaps, recordAlbumMaps, refreshAlbums, insertFiles);
        if (ret != E_OK) {
            MEDIA_ERR_LOG("PullInsert Get insert params failed %{public}d", ret);
            failedRecords.emplace_back(insertData.cloudId);
            continue;
        }
    }
    /*
    MetaFileMgr::GetInstance().ClearAll();
    */
    MEDIA_INFO_LOG("PullInsert insert %{public}zu, update %{public}d, delete %{public}d, map %{public}zu",
        insertFiles.size(),
        stats[StatsIndex::META_MODIFY_RECORDS_COUNT],
        stats[StatsIndex::DELETE_RECORDS_COUNT],
        recordAlbumMaps.size());
    this->photosDao_.BatchInsertFile(recordAnalysisAlbumMaps, recordAlbumMaps, insertFiles);
    this->photosDao_.UpdateAlbumInternal(refreshAlbums);
    NotifyPhotoInserted(insertFiles);
    return E_OK;
}

void CloudMediaPhotosService::NotifyPhotoInserted(const std::vector<NativeRdb::ValuesBucket> &insertFiles)
{
    MEDIA_INFO_LOG("NotifyPhotoInserted enter %{public}zu", insertFiles.size());
    std::vector<std::string> cloudIds;
    bool ret = false;
    for (auto const &value : insertFiles) {
        if (value.HasColumn(Media::PhotoColumn::PHOTO_CLOUD_ID)) {
            std::string cloudId;
            NativeRdb::ValueObject obj;
            ret = value.GetObject(Media::PhotoColumn::PHOTO_CLOUD_ID, obj);
            if (!ret || obj.GetType() != NativeRdb::ValueObject::TypeId::TYPE_STRING) {
                MEDIA_ERR_LOG("NotifyPhotoInserted ret: %{public}d, type: %{public}d", ret, obj.GetType());
                continue;
            }
            obj.GetString(cloudId);
            MEDIA_INFO_LOG("NotifyPhotoInserted CloudId %{public}s", cloudId.c_str());
            MediaGallerySyncNotify::GetInstance().AddNotify(
                PhotoColumn::PHOTO_GALLERY_CLOUD_URI_PREFIX + cloudId, ChangeType::INSERT, cloudId);
        } else {
            MEDIA_ERR_LOG("NotifyPhotoInserted no CloudId");
        }
    }
    MediaGallerySyncNotify::GetInstance().FinalNotify();
}

void CloudMediaPhotosService::Notify(const std::string &uri, NotifyType type)
{
    auto watcher = MediaLibraryNotify::GetInstance();
    if (watcher == nullptr) {
        return;
    }
    watcher->Notify(uri, type);
}

int32_t CloudMediaPhotosService::CreateEntry(const std::vector<CloudMediaPullDataDto> &pullDatas,
    std::set<std::string> &refreshAlbums, std::vector<PhotosDto> &newData, std::vector<int32_t> &stats,
    std::vector<std::string> &failedRecords)
{
    CHECK_AND_RETURN_RET_INFO_LOG(!pullDatas.empty(), E_OK, "CreateEntry No need to pull insert.");

    std::map<std::string, int> recordAnalysisAlbumMaps;
    std::map<std::string, std::set<int>> recordAlbumMaps;
    std::vector<NativeRdb::ValuesBucket> insertFiles;

    uint64_t dataFail = 0;
    int32_t uniqueId = 0;
    int32_t ret;
    std::vector<CloudMediaPullDataDto> allPullDatas = pullDatas;
    PullRecordsConflictProc(allPullDatas, refreshAlbums, stats, failedRecords);
    ret = MediaLibraryAssetOperations::CreateAssetUniqueIds(MediaType::MEDIA_TYPE_IMAGE, allPullDatas.size(), uniqueId);
    if (ret != E_OK) {
        uniqueId = 0;
    }
    for (auto insertData : allPullDatas) {
        MEDIA_INFO_LOG("CreateEntry insert of record %{public}s", insertData.cloudId.c_str());
        uniqueId++;
        int32_t mediaType =
            (insertData.basicFileType == FILE_TYPE_VIDEO) ? MediaType::MEDIA_TYPE_VIDEO : MediaType::MEDIA_TYPE_IMAGE;
        std::string extension = ScannerUtils::GetFileExtension(insertData.basicFileName);
        ret = MediaLibraryAssetOperations::CreateAssetPathById(uniqueId, mediaType, extension, insertData.localPath);
        if (ret != E_OK) {
            MEDIA_ERR_LOG("CreateEntry Generate File Path err %{public}d", ret);
            dataFail++;
            continue;
        }
        ExtractEditDataCamera(insertData);
        ret = this->photosDao_.GetInsertParams(
            insertData, recordAnalysisAlbumMaps, recordAlbumMaps, refreshAlbums, insertFiles);
        if (ret != E_OK) {
            MEDIA_ERR_LOG("CreateEntry Get insert params failed %{public}d", ret);
            dataFail++;
            continue;
        }
        PhotosDto dto;
        dto.cloudId = insertData.cloudId;
        if (!CloudMediaFileUtils::GetParentPathAndFilename(insertData.localPath, dto.path, dto.fileName)) {
            MEDIA_WARN_LOG("CreateEntry Failed to get parent path and real filename.");
        }
        dto.size = insertData.localSize;
        dto.mediaType = mediaType;
        dto.modifiedTime = insertData.attributesEditedTimeMs;
        // new data 不更新 originalCloudId (无)
        CloudMediaSyncUtils::FillPhotosDto(dto, insertData);
        MEDIA_INFO_LOG("CreateEntry NewData: %{public}s", dto.ToString().c_str());
        newData.emplace_back(dto);
    }
    MEDIA_INFO_LOG("CreateEntry insert %{public}zu, update %{public}d, delete %{public}d, map %{public}zu",
        insertFiles.size(),
        stats[StatsIndex::META_MODIFY_RECORDS_COUNT],
        stats[StatsIndex::DELETE_RECORDS_COUNT],
        recordAlbumMaps.size());
    return E_OK;
}

int32_t CloudMediaPhotosService::HandleRecord(const std::vector<std::string> &cloudIds,
    std::map<std::string, CloudMediaPullDataDto> &cloudIdRelativeMap, std::vector<PhotosDto> &newData,
    std::vector<PhotosDto> &fdirtyData, std::vector<int32_t> &stats, std::vector<std::string> &failedRecords)
{
    std::set<std::string> refreshAlbums;
    std::vector<CloudMediaPullDataDto> insertPullDatas;
    uint64_t rdbFail = 0;
    uint64_t dataFail = 0;
    uint64_t successDelete = 0;
    uint64_t successUpdate = 0;
    int32_t deleteCount = 0;
    int32_t updateCount = 0;
    int32_t ret = E_OK;
    for (auto &cloudId : cloudIds) {
        // RETURN_ON_ERR(IsStop());
        int32_t fileId = 0;
        std::string dateAdded;
        ChangeType changeType = ChangeType::INVAILD;

        CloudMediaPullDataDto pullData = cloudIdRelativeMap.at(cloudId);
        MEDIA_ERR_LOG("HandleRecord pullData: %{public}s", pullData.ToString().c_str());
        if (pullData.localPath.empty() && !pullData.basicIsDelete) {
            insertPullDatas.emplace_back(pullData);
            stats[StatsIndex::NEW_RECORDS_COUNT]++;
        } else if (!pullData.localPath.empty()) {
            if (pullData.basicIsDelete) {
                ret = PullDelete(pullData, refreshAlbums);
                deleteCount++;
                changeType = ChangeType::DELETE;
                stats[StatsIndex::DELETE_RECORDS_COUNT]++;
            } else {
                ret = PullUpdate(pullData, refreshAlbums, fdirtyData, stats);
                updateCount++;
                changeType = ChangeType::UPDATE;
            }
        }
        if (ret == E_STOP) {
            MEDIA_ERR_LOG("HandleRecord stop sync cloudId: %{public}s, error: %{public}d", cloudId.c_str(), ret);
            return ret;
        }
        if (ret != E_OK) {
            MEDIA_ERR_LOG("HandleRecord cloudId: %{public}s, error: %{public}d", cloudId.c_str(), ret);
            if (ret == E_RDB) {
                rdbFail++;
                continue;
            }
            /* might need to specifiy which type error */
            dataFail++;
            failedRecords.emplace_back(pullData.cloudId);
            ret = E_OK;
        } else if (changeType != ChangeType::INSERT && changeType != ChangeType::INVAILD) {
            if (cloudIdRelativeMap.at(cloudId).basicIsDelete) {
                successDelete++;
            } else {
                successUpdate++;
            }
        }
        NotifyDataChange(changeType, fileId, dateAdded);
    }
    /*
    大数据打点
    GetDfxHandler()->InsertRecordtoDB(valuesList);
    UpdateMetaStat(INDEX_DL_META_SUCCESS, successDelete, META_DL_DELETE);
    UpdateMetaStat(INDEX_DL_META_SUCCESS, successUpdate, META_DL_UPDATE);
    UpdateMetaStat(INDEX_DL_META_ERROR_RDB, rdbFail);
    UpdateMetaStat(INDEX_DL_META_ERROR_DATA, dataFail);
    */
    ret = CreateEntry(insertPullDatas, refreshAlbums, newData, stats, failedRecords);
    this->photosDao_.UpdateAlbumInternal(refreshAlbums);
    MediaGallerySyncNotify::GetInstance().FinalNotify();
    MEDIA_ERR_LOG("HandleRecord ret: %{public}d, rdbFail: %{public}" PRId64, ret, rdbFail);
    MEDIA_ERR_LOG("HandleRecord ret: %{public}d, dataFail: %{public}" PRId64, ret, dataFail);
    MEDIA_ERR_LOG("HandleRecord ret: %{public}d, successDelete: %{public}" PRId64, ret, successDelete);
    MEDIA_ERR_LOG("HandleRecord ret: %{public}d, successUpdate: %{public}" PRId64, ret, successUpdate);
    MEDIA_ERR_LOG("HandleRecord ret: %{public}d, deleteCount: %{public}d", ret, deleteCount);
    MEDIA_ERR_LOG("HandleRecord ret: %{public}d, updateCount: %{public}d", ret, updateCount);
    return ret;
}

void CloudMediaPhotosService::ConvertPullDataToPhotosDto(const CloudMediaPullDataDto &data, PhotosDto &dto)
{
    MEDIA_INFO_LOG("ConvertPullDataToPhotosDto enter: %{public}s", data.cloudId.c_str());
    int32_t mediaType =
        (data.basicFileType == FILE_TYPE_VIDEO) ? MediaType::MEDIA_TYPE_VIDEO : MediaType::MEDIA_TYPE_IMAGE;
    dto.cloudId = data.cloudId;
    if (!CloudMediaFileUtils::GetParentPathAndFilename(data.localPath, dto.path, dto.fileName)) {
        MEDIA_WARN_LOG("ConvertPullDataToPhotosDto Failed to get parent path and real filename.");
    }
    dto.size = data.localSize;
    dto.mediaType = mediaType;
    dto.modifiedTime = data.attributesEditedTimeMs;
    // new data 不更新 originalCloudId (无)
    CloudMediaSyncUtils::FillPhotosDto(dto, data.localPath, data.propertiesRotate, data.localThumbState);
    MEDIA_INFO_LOG("ConvertPullDataToPhotosDto NewData: %{public}s", dto.cloudId.c_str());
}

int32_t CloudMediaPhotosService::OnFetchRecords(const std::vector<std::string> &cloudIds,
    std::map<std::string, CloudMediaPullDataDto> &cloudIdRelativeMap, std::vector<PhotosDto> &newData,
    std::vector<PhotosDto> &fdirtyData, std::vector<int32_t> &stats, std::vector<std::string> &failedRecords)
{
    MEDIA_INFO_LOG("OnFetchRecords: %{public}d.", static_cast<int32_t>(cloudIds.size()));

    // std::lock_guard<std::mutex> lock(updateDBMutex_);
    std::vector<PhotosPo> photos;
    int32_t ret = this->commonDao_.QueryLocalByCloudId(cloudIds, PULL_QUERY_COLUMNS, photos);
    if (ret != E_OK) {
        /* 打点 UpdateMetaStat(INDEX_DL_META_ERROR_RDB, recordIds.size());  */
        MEDIA_ERR_LOG("OnFetchRecords query error.");
        return E_CLOUDSYNC_RDB_QUERY_FAILED;
    }
    for (auto it = cloudIdRelativeMap.begin(); it != cloudIdRelativeMap.end(); it++) {
        bool found = false;
        for (auto &photo : photos) {
            std::string cloudId = photo.cloudId.value_or("");
            if (cloudId.empty()) {
                MEDIA_WARN_LOG("OnFetchRecords cloudId: %{public}s.", cloudId.c_str());
                continue;
            }
            if (it->first != cloudId) {
                continue;
            }
            found = true;
            CloudMediaPullDataDto pullData = cloudIdRelativeMap.at(cloudId);
            pullData.localFileId = photo.fileId.value_or(-1);
            pullData.localPath = photo.data.value_or("");
            pullData.localSize = photo.size.value_or(0);
            pullData.localMediaType = photo.mediaType.value_or(-1);
            pullData.localDateAdded = std::to_string(photo.dateAdded.value_or(-1));
            pullData.localDateModified = std::to_string(photo.dateModified.value_or(-1));
            pullData.localDirty = photo.dirty.value_or(-1);
            pullData.localPosition = photo.position.value_or(-1);
            pullData.localOwnerAlbumId = photo.ownerAlbumId.value_or(-1);
            pullData.localOrientation = photo.orientation.value_or(-1);
            pullData.localThumbState = photo.thumbStatus.value_or(-1);
            pullData.modifiedTime = photo.dateModified.value_or(-1);
            pullData.dateTaken =  photo.dateTaken.value_or(0);
            pullData.localOriginalAssetCloudId = photo.originalAssetCloudId.value_or("");
            pullData.cloudId = cloudId;

            cloudIdRelativeMap[cloudId] = pullData;
            MEDIA_INFO_LOG("OnFetchRecords CloudMediaPullData: %{public}s.", pullData.ToString().c_str());
        }
        if (!found) {
            MEDIA_WARN_LOG("OnFetchRecords Record need insert cloudId: %{public}s.", it->first.c_str());
            it->second.localPath = "";
        }
    }
    MEDIA_INFO_LOG("OnFetchRecords cloudIdRelativeMap: %{public}zu.", cloudIdRelativeMap.size());
    ret = HandleRecord(cloudIds, cloudIdRelativeMap, newData, fdirtyData, stats, failedRecords);
    return ret;
}

int32_t CloudMediaPhotosService::OnDentryFileInsert(
    const std::vector<CloudMediaPullDataDto> &pullDatas, std::vector<std::string> &failedRecords)
{
    return PullInsert(pullDatas, failedRecords);
}

int32_t CloudMediaPhotosService::GetRetryRecords(std::vector<std::string> &cloudIds)
{
    MEDIA_INFO_LOG("CloudMediaPhotosService::GetRetryRecords enter");
    int32_t ret = this->photosDao_.GetRetryRecords(cloudIds);
    MEDIA_INFO_LOG("CloudMediaPhotosService::GetRetryRecords end, "
                   "ret: %{public}d, size: %{public}zu",
        ret,
        cloudIds.size());
    return ret;
}

std::vector<PhotosDto> CloudMediaPhotosService::GetCheckRecords(const std::vector<std::string> &cloudIds)
{
    MEDIA_INFO_LOG("CloudMediaPhotosService::GetCheckRecords enter");
    // get & cache local photos data. cloudId -> photosDto
    std::vector<PhotosPo> photosPos = this->photosDao_.GetCheckRecords(cloudIds);
    std::vector<PhotosDto> result = this->processor_.GetPhotosDtos(photosPos);
    return result;
}

int32_t CloudMediaPhotosService::GetCreatedRecords(int32_t size, std::vector<PhotosPo> &createdRecords)
{
    MEDIA_INFO_LOG("CloudMediaPhotosService::GetCreatedRecords enter %{public}d", size);
    int32_t ret = this->photosDao_.GetCreatedRecords(size, createdRecords);
    MEDIA_INFO_LOG("CloudMediaPhotosService::GetCreatedRecords end, ret: %{public}d, size: %{public}zu",
        ret,
        createdRecords.size());
    return ret;
}

int32_t CloudMediaPhotosService::GetMetaModifiedRecords(int32_t size, std::vector<PhotosPo> &modifiedRecords)
{
    MEDIA_INFO_LOG("CloudMediaPhotosService::GetMetaModifiedRecords enter");
    int32_t ret = this->photosDao_.GetMetaModifiedRecords(size, modifiedRecords);
    MEDIA_INFO_LOG("CloudMediaPhotosService::GetMetaModifiedRecords end, ret: %{public}d, size: %{public}zu",
        ret,
        modifiedRecords.size());
    return ret;
}

int32_t CloudMediaPhotosService::GetFileModifiedRecords(int32_t size, std::vector<PhotosPo> &modifiedRecords)
{
    MEDIA_INFO_LOG("CloudMediaPhotosService::GetFileModifiedRecords enter %{public}d", size);
    int32_t ret = this->photosDao_.GetFileModifiedRecords(size, modifiedRecords);
    MEDIA_INFO_LOG("CloudMediaPhotosService::GetFileModifiedRecords end, ret: %{public}d, size: %{public}zu",
        ret,
        modifiedRecords.size());
    return ret;
}

std::vector<PhotosPo> CloudMediaPhotosService::GetDeletedRecords(int32_t size)
{
    MEDIA_INFO_LOG("CloudMediaPhotosService::GetDeletedRecords enter %{public}d", size);
    std::vector<PhotosPo> cloudRecordPoList;
    int32_t ret = this->photosDao_.GetDeletedRecordsAsset(size, cloudRecordPoList);
    if (ret < 0) {
        MEDIA_ERR_LOG("CloudMediaPhotosService::GetDeletedRecords failed to convert");
    }
    return cloudRecordPoList;
}

int32_t CloudMediaPhotosService::GetCopyRecords(int32_t size, std::vector<PhotosPo> &copyRecords)
{
    MEDIA_INFO_LOG("CloudMediaPhotosService::GetCopyRecords enter %{public}d", size);
    int32_t ret = this->photosDao_.GetCopyRecords(size, copyRecords);
    MEDIA_INFO_LOG(
        "CloudMediaPhotosService::GetCopyRecords end, ret: %{public}d, size: %{public}zu", ret, copyRecords.size());
    return ret;
}

int32_t CloudMediaPhotosService::OnCreateRecords(std::vector<PhotosDto> &records, int32_t &failedSize)
{
    MEDIA_ERR_LOG("enter OnCreateRecords");
    std::unordered_map<std::string, LocalInfo> localMap;
    uint64_t success = 0;
    uint64_t failure = 0;

    int32_t ret = this->photosDao_.GetPhotoLocalInfo(records, localMap, PhotoColumn::MEDIA_ID);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("OnCreateRecords get local match info err %{public}d", ret);
        return ret;
    }

    for (auto &record : records) {
        MEDIA_INFO_LOG("OnCreateRecords Record: %{public}s", record.ToString().c_str());
        int32_t err;
        if (record.isSuccess) {
            err = OnCreateRecordSuccess(record, localMap);
        } else {
            err = OnRecordFailed(record);
            this->photosDao_.UpdateFailRecordsCloudId(record, localMap);
            failedSize++;
        }
        if (err != E_OK) {
            this->photosDao_.InsertPhotoCreateFailedRecord(record.fileId);
            MEDIA_ERR_LOG(
                "OnCreateRecords create record fail: file path %{public}d, err %{public}d", record.fileId, err);
            if (record.isSuccess) {
                failedSize++;
            }
        }
        if (err == E_SYNC_STOP || err == E_SYNC_FAILED_NETWORK_NOT_AVAILABLE || err == E_CLOUD_STORAGE_FULL ||
            err == E_STOP || err == E_BUSINESS_MODE_CHANGED) {
            ret = err;
        }
        DeleteTempLivePhotoFile(record);
    }
    return ret;
}

void CloudMediaPhotosService::DeleteTempLivePhotoFile(const PhotosDto &record)
{
    if (unlink(record.livePhotoCachePath.c_str()) != 0 && errno != ENOENT) {
        MEDIA_ERR_LOG("unlink err: %{public}d", errno);
    }
}

int32_t CloudMediaPhotosService::OnCreateRecordSuccess(
    const PhotosDto &record, const std::unordered_map<std::string, LocalInfo> &localMap)
{
    int32_t localId = record.localId;
    if (localId < 0) {
        MEDIA_ERR_LOG("OnCreateRecordSuccess invalid local id %{public}d", localId);
        return E_INVAL_ARG;
    }
    /* local file deleted */
    if (localMap.find(std::to_string(localId)) == localMap.end()) {
        MEDIA_INFO_LOG("OnCreateRecordSuccess local file is deleted %{public}d", localId);
        return E_OK;
    }

    int32_t ret = this->photosDao_.UpdateLocalAlbumMap(record.cloudId);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("OnCreateRecordSuccess update local album map err %{public}d, %{public}d", ret, localId);
    }
    ret = this->photosDao_.UpdatePhotoCreatedRecord(record, localMap);
    if (ret != 0) {
        MEDIA_ERR_LOG("OnCreateRecordSuccess update synced err %{public}d, %{public}d", ret, localId);
        return ret;
    }
    std::string fileId = std::to_string(record.fileId);
    MediaGallerySyncNotify::GetInstance().TryNotify(
        PhotoColumn::PHOTO_CLOUD_URI_PREFIX + fileId, ChangeType::UPDATE, fileId);
    return E_OK;
}

int32_t CloudMediaPhotosService::OnMdirtyRecords(std::vector<PhotosDto> &records, int32_t &failedSize)
{
    MEDIA_INFO_LOG("OnMdirtyRecords enter");
    int32_t ret = E_OK;
    for (auto &photo : records) {
        int32_t err;
        if (photo.isSuccess) {
            err = this->photosDao_.OnModifyPhotoRecord(photo);
        } else {
            err = OnRecordFailed(photo);
        }
        if (err == E_OK) {
            Notify(PhotoColumn::PHOTO_GALLERY_CLOUD_URI_PREFIX + std::to_string(photo.fileId) + "/" +
                       std::to_string(photo.dateAdded),
                NotifyType::NOTIFY_UPDATE);
        }
        if (err != E_OK) {
            failedSize++;
            MEDIA_ERR_LOG("OnMdirtyRecords error %{public}d", err);
            this->photosDao_.InsertPhotoModifyFailedRecord(photo.cloudId);
        }
        if (err == E_SYNC_STOP || err == E_SYNC_FAILED_NETWORK_NOT_AVAILABLE || err == E_CLOUD_STORAGE_FULL ||
            err == E_STOP || err == E_BUSINESS_MODE_CHANGED) {
            ret = err;
        }
    }
    return ret;
}

int32_t CloudMediaPhotosService::OnFdirtyRecords(std::vector<PhotosDto> &records, int32_t &failedSize)
{
    MEDIA_INFO_LOG("OnFdirtyRecords enter");
    std::unordered_map<std::string, LocalInfo> localMap;
    uint64_t success = 0;
    uint64_t failure = 0;

    int32_t ret = this->photosDao_.GetPhotoLocalInfo(records, localMap, PhotoColumn::PHOTO_CLOUD_ID);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("OnFdirtyRecords get local match info err %{public}d", ret);
        return ret;
    }

    for (auto &record : records) {
        MEDIA_INFO_LOG("OnFdirtyRecords Record: %{public}s", record.ToString().c_str());
        int32_t err;
        if (record.isSuccess) {
            err = OnFdirtyRecordSuccess(record, localMap);
        } else {
            err = OnRecordFailed(record);
        }
        if (err != E_OK) {
            failedSize++;
            MEDIA_ERR_LOG("OnFdirtyRecords Error cloudId: %{public}s", record.cloudId.c_str());
            this->photosDao_.InsertPhotoModifyFailedRecord(record.cloudId);
        }
        if (ret == E_OK) {
            Notify(PhotoColumn::PHOTO_GALLERY_CLOUD_URI_PREFIX + std::to_string(record.fileId) + "/" +
                       std::to_string(record.dateAdded),
                NotifyType::NOTIFY_UPDATE);
        }
        if (err == E_SYNC_STOP || err == E_SYNC_FAILED_NETWORK_NOT_AVAILABLE || err == E_CLOUD_STORAGE_FULL ||
            err == E_STOP || err == E_BUSINESS_MODE_CHANGED) {
            ret = err;
        }
    }
    return ret;
}

int32_t CloudMediaPhotosService::OnFdirtyRecordSuccess(
    const PhotosDto &record, const std::unordered_map<string, LocalInfo> &localMap)
{
    MEDIA_INFO_LOG("OnFdirtyRecordSuccess enter");
    std::string cloudId = record.cloudId;

    /* Fix me: might need a transaction to do an atomic update for files and their album maps */
    int32_t ret = this->photosDao_.UpdateLocalAlbumMap(cloudId);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("OnFdirtyRecordSuccess update local album map err %{public}d", ret);
        return ret;
    }
    if (record.metaDateModified == -1) {
        MEDIA_ERR_LOG("OnFdirtyRecordSuccess metaDateModified error");
        return E_INVAL_ARG;
    }
    return this->photosDao_.UpdateFdirtyVersion(record);
}

int32_t CloudMediaPhotosService::OnDeleteRecords(std::vector<PhotosDto> &records, int32_t &failSize)
{
    MEDIA_INFO_LOG("CloudMediaPhotosService::OnDeleteRecords");
    int32_t ret = E_OK;
    for (auto &photo : records) {
        int32_t err;
        MEDIA_INFO_LOG("CloudMediaPhotosService::OnDeleteRecords isSuccess: %{public}d", photo.isSuccess);
        if (photo.isSuccess) {
            err = this->photosDao_.OnDeleteRecordsAsset(photo);
        } else {
            err = OnRecordFailed(photo);
        }
        if (err != E_OK) {
            this->photosDao_.InsertPhotoModifyFailedRecord(photo.cloudId);
        }
        if (ret == E_OK) {
            Notify(PhotoColumn::PHOTO_GALLERY_CLOUD_URI_PREFIX + std::to_string(photo.fileId) + "/" +
                       std::to_string(photo.dateAdded),
                NotifyType::NOTIFY_REMOVE);
        }
        if (err != E_OK) {
            failSize++;
            // modifyFailSet_.PushBack(photo.dkRecordId);
            MEDIA_ERR_LOG("delete record fail: cloud id: %{private}s", photo.dkRecordId.c_str());
        }
        if (err == E_SYNC_STOP || err == E_SYNC_FAILED_NETWORK_NOT_AVAILABLE || err == E_CLOUD_STORAGE_FULL ||
            err == E_STOP || err == E_BUSINESS_MODE_CHANGED) {
            ret = err;
        }
    }
    return ret;
}

int32_t CloudMediaPhotosService::OnCopyRecords(std::vector<PhotosDto> &records, int32_t &failedSize)
{
    int32_t ret = E_OK;
    for (auto &photo : records) {
        int32_t err;
        MEDIA_INFO_LOG("OnCopyRecords photo: %{public}s", photo.ToString().c_str());
        if (photo.isSuccess) {
            err = this->photosDao_.OnCopyPhotoRecord(photo);
        } else {
            err = OnRecordFailed(photo);
        }
        if (err != E_OK) {
            int32_t fileId = photo.fileId;
            if (err != E_OK) {
                failedSize++;
                this->photosDao_.InsertPhotoCopyFailedRecord(photo.fileId);
            }
            if (fileId == 0) {
                // copyFailSet_.PushBack(to_string(fileId));
                MEDIA_ERR_LOG("on copy record fail: file id %{private}d", fileId);
            }
        }
        if (err == E_SYNC_STOP || err == E_SYNC_FAILED_NETWORK_NOT_AVAILABLE || err == E_CLOUD_STORAGE_FULL ||
            err == E_STOP || err == E_BUSINESS_MODE_CHANGED) {
            ret = err;
        }
    }
    return ret;
}

int32_t CloudMediaPhotosService::OnRecordFailed(PhotosDto &photo)
{
    MEDIA_INFO_LOG("OnRecordFailed");
    int32_t serverErrorCode = photo.serverErrorCode;
    MEDIA_INFO_LOG("serverErrorCode %{public}d", serverErrorCode);
    if ((static_cast<ServerErrorCode>(serverErrorCode) == ServerErrorCode::NETWORK_ERROR)) {
        MEDIA_ERR_LOG("Network Error or Response Time Out");
        return E_SYNC_FAILED_NETWORK_NOT_AVAILABLE;
    } else if ((static_cast<ServerErrorCode>(serverErrorCode) == ServerErrorCode::UID_EMPTY) ||
               (static_cast<ServerErrorCode>(serverErrorCode) == ServerErrorCode::SWITCH_OFF)) {
        MEDIA_ERR_LOG("switch off or uid empty");
        return E_STOP;
    } else if (static_cast<ServerErrorCode>(serverErrorCode) == ServerErrorCode::INVALID_LOCK_PARAM) {
        MEDIA_ERR_LOG("Invalid lock param ");
        return E_STOP;
    } else if (static_cast<ServerErrorCode>(serverErrorCode) == ServerErrorCode::RESPONSE_TIME_OUT) {
        MEDIA_ERR_LOG("on record failed response time out");
    }
    ErrorType errorType = photo.errorType;
    if (photo.errorDetails.size() == 0 && errorType != ErrorType::TYPE_NOT_NEED_RETRY) {
        MEDIA_ERR_LOG("errorDetails is empty and errorType is invalid, errorType:%{public}d", errorType);
        return E_INVAL_ARG;
    } else if (photo.errorDetails.size() != 0) {
        auto errorDetailcode = static_cast<ErrorDetailCode>(photo.errorDetails[0].detailCode);
        if (errorDetailcode == ErrorDetailCode::SPACE_FULL) {
            MEDIA_ERR_LOG("Cloud Space Not Enough");
            /* Stop sync */
            return E_CLOUD_STORAGE_FULL;
        }
        if (errorDetailcode == ErrorDetailCode::BUSINESS_MODEL_CHANGE_DATA_UPLOAD_FORBIDDEN) {
            MEDIA_ERR_LOG("Business Mode Change, Upload Fail");
            /* Stop sync */
            return E_BUSINESS_MODE_CHANGED;
        }
        if (errorDetailcode == ErrorDetailCode::SAME_FILENAME_NOT_ALLOWED) {
            return HandleSameNameUploadFail(photo);
        }
        if (errorDetailcode == ErrorDetailCode::CONTENT_NOT_FIND) {
            return HandleNoContentUploadFail(photo);
        }
        if (errorType != ErrorType::TYPE_NOT_NEED_RETRY) {
            MEDIA_ERR_LOG(
                "unknown error code record failed, serverErrorCode = %{public}d, errorDetailcode = %{public}d",
                serverErrorCode,
                errorDetailcode);
            return HandleDetailcode(errorDetailcode);
        }
        MEDIA_ERR_LOG("errorDetailcode = %{public}d, errorType = %{public}d, no need retry",
            errorDetailcode,
            static_cast<int32_t>(errorType));
        return E_STOP;
    } else {
        MEDIA_ERR_LOG("errorType = %{public}d, no need retry", static_cast<int32_t>(errorType));
        return E_STOP;
    }
    return E_UNKNOWN;
}

int32_t CloudMediaPhotosService::HandleNoContentUploadFail(const PhotosDto &photo)
{
    MEDIA_INFO_LOG("HandleNoContentUploadFail");
    std::string path = photo.path;
    int32_t ret = E_OK;
    if (access(path.c_str(), F_OK) == 0) {
        // 本地有图
        MEDIA_INFO_LOG("HandleNoContentUploadFail file found");
        ret = this->photosDao_.ClearCloudInfo(photo.cloudId);
        return E_RDB;
    }
    ret = this->photosDao_.DeleteFileNotExistPhoto(path);
    MEDIA_INFO_LOG("HandleNoContentUploadFail ret is %{public}d", ret);
    if (ret != E_OK) {
        return E_RDB;
    }
    CloudMediaSyncUtils::RemoveThmParentPath(path, "");
    return ret;
}

int32_t CloudMediaPhotosService::HandleDetailcode(ErrorDetailCode &errorCode)
{
    /* Only one record failed, not stop sync */
    return E_UNKNOWN;
}

int32_t CloudMediaPhotosService::HandleSameNameUploadFail(const PhotosDto &photo)
{
    std::string fileId = std::to_string(photo.fileId);
    std::string path = photo.data;
    int32_t ret = this->photosDao_.HandleSameNameRename(photo);
    return ret;
}

int32_t CloudMediaPhotosService::OnStartSync()
{
    MediaGallerySyncNotify::GetInstance().NotifyProgressBegin();
    return this->photosDao_.ClearPhotoFailedRecords();
}

int32_t CloudMediaPhotosService::OnCompleteSync()
{
    MediaGallerySyncNotify::GetInstance().NotifyProgressEnd();
    return 0;
}

int32_t CloudMediaPhotosService::OnCompletePull()
{
    return this->photosDao_.UpdatePhotoVisible();
}

int32_t CloudMediaPhotosService::OnCompletePush()
{
    return this->photosDao_.ClearPhotoFailedRecords();
}

int32_t CloudMediaPhotosService::OnCompleteCheck()
{
    MEDIA_INFO_LOG("enter CloudMediaPhotosService::OnCompleteCheck");
    return 0;
}
}  // namespace OHOS::Media::CloudSync