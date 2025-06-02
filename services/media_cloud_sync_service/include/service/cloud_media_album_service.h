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

#ifndef OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_ALBUM_SERVICE_H
#define OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_ALBUM_SERVICE_H

#include <map>
#include <vector>

#include "media_column.h"
#include "rdb_store.h"
#include "photos_dto.h"
#include "photo_album_po.h"
#include "photo_album_dto.h"
#include "on_fetch_records_album_vo.h"
#include "dataobs_mgr_changeinfo.h"
#include "cloud_media_album_dao.h"
#include "cloud_media_define.h"

namespace OHOS::Media::CloudSync {
class EXPORT CloudMediaAlbumService {
public:
    std::vector<PhotoAlbumPo> GetCheckRecords(const std::vector<std::string> &cloudIds);
    std::vector<PhotoAlbumPo> GetAlbumCreatedRecords(int32_t size);
    std::vector<PhotoAlbumPo> GetAlbumMetaModifiedRecords(int32_t size);
    std::vector<PhotoAlbumPo> GetAlbumFileModifiedRecords(int32_t size);  // it's not exist
    std::vector<PhotoAlbumPo> GetAlbumDeletedRecords(int32_t size);
    std::vector<PhotoAlbumPo> GetAlbumCopyRecords(int32_t size);  // it's not exist
    int32_t OnCreateRecords(std::vector<PhotoAlbumDto> &albumDtoList, int32_t &failSize);
    int32_t OnMdirtyRecords(std::vector<PhotoAlbumDto> &albumDtoList, int32_t &failSize);
    int32_t OnFdirtyRecords();
    int32_t OnDeleteRecords(std::vector<PhotoAlbumDto> &albumDtoList, int32_t &failSize);
    int32_t OnCopyRecords();
    int32_t OnFetchRecords(std::vector<PhotoAlbumDto> &albumDtoList, OnFetchRecordsAlbumRespBody &resp);
    int32_t OnDentryFileInsert();
    int32_t OnStartSync();
    int32_t OnCompleteSync();
    int32_t OnCompletePull();
    int32_t OnCompletePush();
    int32_t OnCompleteCheck();

private:
    int32_t OnDeleteAlbums(std::vector<std::string> &failedAlbumIds);
    int32_t OnFetchOldRecords(std::vector<PhotoAlbumDto> &records, OnFetchRecordsAlbumRespBody &resp);
    int32_t OnFetchLPathRecords(std::vector<PhotoAlbumDto> &records, OnFetchRecordsAlbumRespBody &resp);
    int32_t HandleFetchOldRecord(PhotoAlbumDto &record, bool &bContinue,
        OHOS::AAFwk::ChangeInfo::ChangeType &changeType, OnFetchRecordsAlbumRespBody &resp);
    int32_t HandleLPathRecords(PhotoAlbumDto &record, const std::map<std::string, int> &lpathRowIdMap,
        const std::shared_ptr<NativeRdb::ResultSet> &resultSet, OHOS::AAFwk::ChangeInfo::ChangeType &changeType,
        OnFetchRecordsAlbumRespBody &resp);
    int32_t ConvertToSingleScreenshots(PhotoAlbumDto &album, std::vector<PhotoAlbumDto> &records);
    int32_t HandleFetchOldRecordNew(
        PhotoAlbumDto &record, AAFwk::ChangeInfo::ChangeType &changeType, OnFetchRecordsAlbumRespBody &resp);

private:
    CloudMediaAlbumDao albumDao_;
};
}  // namespace OHOS::Media::CloudSync
#endif  // OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_ALBUM_SERVICE_H