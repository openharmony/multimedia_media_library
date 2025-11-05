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

#ifndef OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_ALBUM_DAO_H
#define OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_ALBUM_DAO_H

#include <string>
#include <vector>
#include <unordered_map>

#include "media_column.h"
#include "photos_dto.h"
#include "photos_vo.h"
#include "photos_po.h"
#include "photo_album_po.h"
#include "rdb_store.h"
#include "safe_map.h"
#include "result_set.h"
#include "medialibrary_db_const.h"
#include "cloud_media_sync_const.h"
#include "cloud_media_file_utils.h"
#include "photo_album_dto.h"
#include "medialibrary_rdbstore.h"
#include "safe_vector.h"
#include "cloud_media_dao_const.h"
#include "cloud_media_define.h"
#include "accurate_common_data.h"
#include "asset_accurate_refresh.h"
#include "album_accurate_refresh.h"

namespace OHOS::Media::CloudSync {
using namespace OHOS::Media::ORM;

class EXPORT CloudMediaAlbumDao {
public:
    CloudMediaAlbumDao() = default;
    ~CloudMediaAlbumDao() = default;

public:
    int32_t HandleLPathAndAlbumType(PhotoAlbumDto &record);
    int32_t InsertCloudByLPath(PhotoAlbumDto &record,
        std::shared_ptr<AccurateRefresh::AlbumAccurateRefresh> &albumRefreshHandle);
    int32_t DeleteCloudAlbum(const std::string &field, const std::string &value,
        std::shared_ptr<AccurateRefresh::AlbumAccurateRefresh> &albumRefreshHandle);
    int32_t UpdateCloudAlbum(PhotoAlbumDto &record, const std::string &field, const std::string &value,
        std::shared_ptr<AccurateRefresh::AlbumAccurateRefresh> &albumRefreshHandle);
    std::tuple<std::shared_ptr<NativeRdb::ResultSet>, int> QueryLocalMatchAlbum(std::string &cloudId);
    int32_t InsertCloudByCloudId(PhotoAlbumDto &record,
        std::shared_ptr<AccurateRefresh::AlbumAccurateRefresh> &albumRefreshHandle);
    std::tuple<std::shared_ptr<NativeRdb::ResultSet>, std::map<std::string, int>> QueryLocalAlbum(
        const std::string &key, const std::vector<std::string> &argrs);
    int32_t OnDeleteAlbums(std::vector<std::string> &failedAlbumIds);
    int32_t GetCreatedAlbum(int32_t size, std::vector<PhotoAlbumPo> &cloudRecordPoList);
    int32_t GetMetaModifiedAlbum(int32_t size, std::vector<PhotoAlbumPo> &cloudRecordPoList);
    int32_t GetDeletedRecordsAlbum(int32_t size, std::vector<PhotoAlbumPo> &cloudRecordPoList);
    int32_t HandleNotExistAlbumRecord(const PhotoAlbumDto &album);
    int32_t OnCreateRecord(const PhotoAlbumDto &album);
    int32_t OnCreateRecords(const std::vector<PhotoAlbumDto> &albums, int32_t &failSize);
    int32_t ResetAlbumDirty(
        std::shared_ptr<MediaLibraryRdbStore> rdbStore, const std::string &cloudId, DirtyType dirty);
    int32_t IsEmptyAlbum(std::shared_ptr<MediaLibraryRdbStore> rdbStore, const std::string &cloudId);
    int32_t OnMdirtyAlbumRecords(const std::string &cloudId);
    int32_t OnDeleteAlbumRecords(const std::string &cloudId);
    int32_t GetCopyAlbum(int32_t size, std::vector<PhotoAlbumPo> &cloudRecordPoList);
    void InsertAlbumInsertFailedRecord(const std::string &cloudId);
    void InsertAlbumCreateFailedRecord(const std::string &cloudId);
    void InsertAlbumModifyFailedRecord(const std::string &cloudId);
    void RemoveAlbumInsertFailedRecord(const std::string &cloudId);
    void RemoveAlbumCreateFailedRecord(const std::string &cloudId);
    void RemoveAlbumModifyFailedRecord(const std::string &cloudId);
    int32_t ClearAlbumFailedRecords();
    bool IsCoverIdExist(std::string &cloudId);
    bool IsNeedPullCoverByDateModified(std::string &lPath, std::string &coverCloudId);
    bool GetCoverUriFromCoverCloudId(std::string &coverCloudId, std::string &coverUri);
    bool ReplaceCoverUriCondition(const std::string &coverUri, const std::string &lPath);
    int32_t ReportAbnormalLocalRecords();
private:
    int32_t InsertAlbums(PhotoAlbumDto &record,
        std::shared_ptr<AccurateRefresh::AlbumAccurateRefresh> &albumRefreshHandle);
    int32_t SetSourceValues(PhotoAlbumDto &record, NativeRdb::ValuesBucket &values);
    int32_t MergeAlbumOnConflict(PhotoAlbumDto& record,
        std::shared_ptr<AccurateRefresh::AlbumAccurateRefresh> &albumRefreshHandle);
    bool IsConflict(PhotoAlbumDto& record);
    int32_t QueryConflict(PhotoAlbumDto& record, std::shared_ptr<NativeRdb::ResultSet> &resultSet);
    int32_t ConflictWithPhysicalAlbum(PhotoAlbumDto& record,
        std::shared_ptr<AccurateRefresh::AlbumAccurateRefresh> &albumRefreshHandle);
    std::unordered_map<std::string, MediaAlbumPluginRowData> QueryWhiteList();
    int32_t QuerySameNameAlbum(PhotoAlbumDto& record, int32_t &albumId, std::string &newAlbumName);
    std::unordered_map<std::string, std::string> GetLocalAlbumMap();
    int32_t UpdateCloudAlbumSynced(const std::string &field, const std::string &value,
        std::shared_ptr<AccurateRefresh::AlbumAccurateRefresh> &albumRefreshHandle);
    int32_t UpdateCloudAlbumInner(PhotoAlbumDto &record, const std::string &field, const std::string &value,
        std::shared_ptr<AccurateRefresh::AlbumAccurateRefresh> &albumRefreshHandle);
    void RelateToAlbumPluginInfo(PhotoAlbumPo &record,
        std::unordered_map<std::string, MediaAlbumPluginRowData> &writeListMap);
    int32_t QueryCreatedAlbums(int32_t size, std::vector<PhotoAlbumPo> &resultList);
    int32_t QueryDeleteAlbums(int32_t size, std::vector<PhotoAlbumPo> &resultList);

private:
    /* album failure records */
    std::vector<std::string> albumModifyFailSet_;
    std::vector<std::string> albumCreateFailSet_;
    std::vector<std::string> albumInsertFailSet_;
    const std::vector<std::string> ALBUM_PLUGIN_QUERY_COLUMNS = {
        MEDIA_ALBUM_NAME_EN,
        MEDIA_DUAL_ALBUM_NAME,
        MEDIA_ALBUM_PRIORITY,
        Media::PhotoAlbumColumns::ALBUM_NAME,
        Media::PhotoAlbumColumns::ALBUM_LPATH,
        Media::PhotoAlbumColumns::ALBUM_BUNDLE_NAME,
        Media::PhotoAlbumColumns::ALBUM_CLOUD_ID,
    };
};
}  // namespace OHOS::Media::CloudSync
#endif  // OHOS_MEDIA_CLOUD_SYNC_CLOUD_MEDIA_ALBUM_DAO_H