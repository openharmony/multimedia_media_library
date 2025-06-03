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

#ifndef OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_PHOTOS_SERVICE_H
#define OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_PHOTOS_SERVICE_H

#include <map>
#include <vector>

#include "media_column.h"
#include "rdb_store.h"
#include "photos_dto.h"
#include "photos_po.h"
#include "check_file_data_dto.h"
#include "cloud_media_photo_service_processor.h"
#include "cloud_media_photos_dao.h"
#include "cloud_media_pull_data_dto.h"
#include "cloud_media_common_dao.h"
#include "report_failure_dto.h"
#include "cloud_media_define.h"

namespace OHOS::Media::CloudSync {
class EXPORT CloudMediaPhotosService {
private:
    struct DataMergeResult {
        int32_t mergeCount;
        std::string failCloudId;
        std::string refreshAlbumId;
    };

public:
    std::vector<PhotosDto> GetCheckRecords(const std::vector<std::string> &cloudIds);
    int32_t GetCreatedRecords(int32_t size, std::vector<PhotosPo> &createdRecords);
    int32_t GetMetaModifiedRecords(int32_t size, std::vector<PhotosPo> &modifiedRecords);
    int32_t GetFileModifiedRecords(int32_t size, std::vector<PhotosPo> &modifiedRecords);
    std::vector<PhotosPo> GetDeletedRecords(int32_t size);
    int32_t GetCopyRecords(int32_t size, std::vector<PhotosPo> &copyRecords);
    int32_t OnCreateRecords(std::vector<PhotosDto> &photos, int32_t &failedSize);
    int32_t OnMdirtyRecords(std::vector<PhotosDto> &records, int32_t &failedSize);
    int32_t OnFdirtyRecords(std::vector<PhotosDto> &records, int32_t &failedSize);
    int32_t OnDeleteRecords(std::vector<PhotosDto> &records, int32_t &failSize);
    int32_t OnCopyRecords(std::vector<PhotosDto> &records, int32_t &failedSize);
    int32_t OnFetchRecords(const std::vector<std::string> &cloudIds,
        std::map<std::string, CloudMediaPullDataDto> &cloudIdRelativeMap, std::vector<PhotosDto> &newData,
        std::vector<PhotosDto> &fdirtyData, std::vector<int32_t> &stats, std::vector<std::string> &failedRecords);
    int32_t OnDentryFileInsert(
        const std::vector<CloudMediaPullDataDto> &pullDatas, std::vector<std::string> &failedRecords);
    int32_t GetRetryRecords(std::vector<std::string> &cloudIds);
    int32_t OnStartSync();
    int32_t OnCompleteSync();
    int32_t OnCompletePull();
    int32_t OnCompletePush();
    int32_t OnCompleteCheck();
    int32_t ReportFailure(const ReportFailureDto &reportFailureDto);

private:
    int32_t HandleRecord(const std::vector<std::string> &cloudIds,
        std::map<std::string, CloudMediaPullDataDto> &cloudIdRelativeMap, std::vector<PhotosDto> &newData,
        std::vector<PhotosDto> &fdirtyData, std::vector<int32_t> &stats, std::vector<std::string> &failedRecords);
    int32_t PullUpdate(const CloudMediaPullDataDto &pullData, std::set<std::string> &refreshAlbums,
        std::vector<PhotosDto> &fdirtyData, std::vector<int32_t> &stats);
    int32_t IsMtimeChanged(const CloudMediaPullDataDto &cloudMediaPullData, bool &changed);
    void ExtractEditDataCamera(const CloudMediaPullDataDto &cloudMediaPullData);
    int32_t PullDelete(const CloudMediaPullDataDto &data, std::set<std::string> &refreshAlbums);
    int32_t PullInsert(const std::vector<CloudMediaPullDataDto> &pullDatas, std::vector<std::string> &failedRecords);
    int32_t CreateEntry(const std::vector<CloudMediaPullDataDto> &pullDatas, std::set<std::string> &refreshAlbums,
        std::vector<PhotosDto> &newData, std::vector<int32_t> &stats, std::vector<std::string> &failedRecords);
    int32_t PullRecordsConflictProc(std::vector<CloudMediaPullDataDto> &allPullDatas,
        std::set<std::string> &refreshAlbums, std::vector<int32_t> &stats, std::vector<std::string> &failedRecords);
    int32_t GetCloudKeyData(const CloudMediaPullDataDto &pullData, KeyData &keyData);
    void GetMergeDataMap(
        const std::vector<CloudMediaPullDataDto> &pullDatas, std::map<std::string, KeyData> &mergeDataMap);
    int32_t DoDataMerge(const CloudMediaPullDataDto &pullData, const KeyData &localKeyData, const KeyData &cloudKeyData,
        std::set<std::string> &refreshAlbums);
    int32_t OnRecordFailed(PhotosDto &photo);
    int32_t OnCopyRecordSuccess(PhotosDto &photo);
    int32_t HandleNoContentUploadFail(const PhotosDto &photo);
    int32_t HandleSameNameUploadFail(const PhotosDto &photo);
    int32_t HandleDetailcode(ErrorDetailCode &errorCode);
    int32_t OnFdirtyRecordSuccess(const PhotosDto &record, const std::unordered_map<std::string, LocalInfo> &localMap);
    int32_t OnCreateRecordSuccess(const PhotosDto &record, const std::unordered_map<std::string, LocalInfo> &localMap);
    void DeleteTempLivePhotoFile(const PhotosDto &record);
    void NotifyPhotoInserted(const std::vector<NativeRdb::ValuesBucket> &insertFiles);
    void Notify(const std::string &uri, NotifyType type);
    void ConvertPullDataToPhotosDto(const CloudMediaPullDataDto &data, PhotosDto &dto);
    int32_t NotifyUploadErr(const int32_t errorCode, const std::string fileId);
    int32_t OnRecordFailedErrorDetails(PhotosDto &photo);
    int32_t PullRecordsDataMerge(std::vector<CloudMediaPullDataDto> &allPullDatas, const KeyData &localKeyData,
        std::map<std::string, KeyData> &mergeDataMap, DataMergeResult &mergeResult);
    int32_t ClearLocalData(const CloudMediaPullDataDto &pullData, std::vector<PhotosDto> &fdirtyData);
    int32_t UpdateMetaStat(const std::vector<NativeRdb::ValuesBucket> &insertFiles,
        const std::vector<CloudMediaPullDataDto> &allPullDatas, const uint64_t dataFail);

private:
    CloudMediaPhotoServiceProcessor processor_;
    CloudMediaPhotosDao photosDao_;
    CloudMediaCommonDao commonDao_;
};
}  // namespace OHOS::Media::CloudSync
#endif  // OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_PHOTOS_SERVICE_H