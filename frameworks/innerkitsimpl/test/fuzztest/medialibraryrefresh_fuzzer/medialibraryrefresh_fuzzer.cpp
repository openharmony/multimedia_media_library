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

#include "medialibraryrefresh_fuzzer.h"

#include <cstdint>
#include <string>
#include <pixel_map.h>

#include <fuzzer/FuzzedDataProvider.h>
#include "medialibrary_restore.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "media_file_utils.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "notification_classification.h"
#include "notify_info_inner.h"
#include "media_change_info.h"
#include "notification_merging.h"
#include "notification_distribution.h"
#include "notify_info.h"
#include "media_observer_manager.h"
#include "media_datashare_stub_impl.h"
#include "data_ability_observer_interface.h"
#include "observer_info.h"
#include "data_ability_observer_stub.h"
#include "media_log.h"
#include "get_self_permissions.h"
#include "access_token.h"
#include "accesstoken_kit.h"
#include "token_setproc.h"
#include "media_file_utils.h"
#include "accurate_common_data.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_command.h"
#include "asset_accurate_refresh.h"
#include "album_accurate_refresh.h"
#include "accurate_refresh_base.h"
#include "medialibrary_kvstore_manager.h"
#include "photo_album_column.h"
#include "photo_album_column.h"
#include "media_column.h"
#include <iostream>
#include <vector>
#include <algorithm>
#include <random>

namespace OHOS {
using namespace Media;
using namespace std;

FuzzedDataProvider *provider = nullptr;
std::shared_ptr<Media::MediaLibraryRdbStore> g_rdbStore;
static const int32_t NUM_BYTES = 1;
static const uint32_t MAX_ID = 10000;
static const int32_t RDB_OPERATION_MAX_SIZE = 3;
static const std::string ALBUM_SELECT_SQL_STR = "SELECT * FROM PhotoAlbum WHERE album_id = ";
static const std::string PHOTOS_DELETE_SQL_STR = "DELETE FROM Photos WHERE file_id = ";
static const std::string ALBUM_DELETE_SQL_STR = "DELETE FROM PhotoAlbum WHERE album_id = ";
static const std::string ALBUM_TABLE_NAME = "PhotoAlbum";
static const std::string PHOTO_TABLE_NAME = "Photos";

static inline AccurateRefresh::RdbOperation GetRdbOperation()
{
    int32_t value = provider->ConsumeIntegralInRange<int32_t>(0, RDB_OPERATION_MAX_SIZE);
    return static_cast<AccurateRefresh::RdbOperation>(value);
}

void SetTables()
{
    // 创建Photos/PhotoAlbum表
    vector<string> createTableSqlList = {
        CREATE_PHOTO_ALBUM_TABLE,
        CREATE_PHOTO_TABLE,
    };
    for (auto &createTableSql : createTableSqlList) {
        if (g_rdbStore == nullptr) {
            MEDIA_ERR_LOG("can not get g_rdbstore");
            return;
        }
        int32_t ret = g_rdbStore->ExecuteSql(createTableSql);
        if (ret != E_OK) {
            MEDIA_ERR_LOG("Execute sql %{private}s failed", createTableSql.c_str());
            return;
        }
        MEDIA_INFO_LOG("Execute sql %{private}s success", createTableSql.c_str());
    }
    MEDIA_INFO_LOG("SetTables");
}

static void Init()
{
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start MediaLibraryPhotoOperationsTest failed, can not get rdbstore");
        exit(1);
    }
    SetTables();
}

static inline void ClearKvStore()
{
    Media::MediaLibraryKvStoreManager::GetInstance().CloseAllKvStore();
}

Media::AccurateRefresh::PhotoAssetChangeInfo GetPhotoAssetChangeInfo()
{
    Media::AccurateRefresh::PhotoAssetChangeInfo assetChangeInfo = NORMAL_ASSET;
    assetChangeInfo.isFavorite_ = provider->ConsumeBool();
    assetChangeInfo.isHidden_ = provider->ConsumeBool();
    assetChangeInfo.thumbnailVisible_ =  MediaFileUtils::UTCTimeMilliSeconds();
    assetChangeInfo.strongAssociation_ = provider->ConsumeIntegralInRange<int32_t>(0, 1);
    assetChangeInfo.isTemp_ = provider->ConsumeBool();
    assetChangeInfo.dateAddedMs_ = MediaFileUtils::UTCTimeMilliSeconds();
    assetChangeInfo.fileId_ = provider->ConsumeIntegralInRange<int32_t>(0, MAX_ID);
    assetChangeInfo.ownerAlbumId_ = provider->ConsumeIntegralInRange<int32_t>(0, MAX_ID);
    assetChangeInfo.ownerAlbumUri_ = provider->ConsumeBytesAsString(NUM_BYTES);
    return assetChangeInfo;
}

Media::AccurateRefresh::AlbumChangeInfo GetAlbumChangeInfo()
{
    Media::AccurateRefresh::AlbumChangeInfo albumChangeInfo;
    albumChangeInfo.albumId_ = provider->ConsumeIntegralInRange<int32_t>(0, MAX_ID);
    albumChangeInfo.imageCount_ = provider->ConsumeIntegralInRange<int32_t>(0, MAX_ID);
    albumChangeInfo.videoCount_ = provider->ConsumeIntegralInRange<int32_t>(0, MAX_ID);
    albumChangeInfo.albumType_ =  provider->ConsumeIntegralInRange<int32_t>(0, MAX_ID);
    albumChangeInfo.albumSubType_ = provider->ConsumeIntegralInRange<int32_t>(0, MAX_ID);
    albumChangeInfo.count_ = provider->ConsumeIntegralInRange<int32_t>(0, MAX_ID);
    albumChangeInfo.hiddenCount_ = provider->ConsumeIntegralInRange<int32_t>(0, MAX_ID);
    albumChangeInfo.isCoverChange_ = provider->ConsumeBool();
    albumChangeInfo.coverInfo_ = GetPhotoAssetChangeInfo();
    albumChangeInfo.isHiddenCoverChange_ = provider->ConsumeBool();
    albumChangeInfo.hiddenCoverInfo_ = GetPhotoAssetChangeInfo();
    albumChangeInfo.coverDateTime_ = MediaFileUtils::UTCTimeMilliSeconds();
    albumChangeInfo.hiddenCoverDateTime_ = MediaFileUtils::UTCTimeMilliSeconds();
    albumChangeInfo.albumName_ = provider->ConsumeBytesAsString(NUM_BYTES);
    return albumChangeInfo;
}

NativeRdb::ValuesBucket GetAssetValuesBucket(Media::AccurateRefresh::PhotoAssetChangeInfo &assetInfo)
{
    NativeRdb::ValuesBucket value;
    value.PutInt(PhotoColumn::MEDIA_ID, assetInfo.fileId_);
    value.PutString(PhotoColumn::PHOTO_DATE_DAY, assetInfo.dateDay_);
    value.PutInt(PhotoColumn::MEDIA_IS_FAV, static_cast<int32_t>(assetInfo.isFavorite_));
    value.PutInt(PhotoColumn::MEDIA_TYPE, assetInfo.mediaType_);
    value.PutInt(PhotoColumn::MEDIA_HIDDEN, assetInfo.isHidden_);
    value.PutLong(PhotoColumn::MEDIA_DATE_TRASHED, assetInfo.dateTrashedMs_);
    value.PutInt(PhotoColumn::PHOTO_STRONG_ASSOCIATION, assetInfo.strongAssociation_);
    value.PutInt(PhotoColumn::PHOTO_THUMBNAIL_VISIBLE, assetInfo.thumbnailVisible_);
    value.PutLong(PhotoColumn::MEDIA_DATE_ADDED, assetInfo.dateAddedMs_);
    value.PutLong(PhotoColumn::MEDIA_DATE_TAKEN, assetInfo.dateTakenMs_);
    value.PutInt(PhotoColumn::PHOTO_SUBTYPE, assetInfo.subType_);
    value.PutInt(PhotoColumn::PHOTO_SYNC_STATUS, assetInfo.syncStatus_);
    value.PutInt(PhotoColumn::PHOTO_CLEAN_FLAG, assetInfo.cleanFlag_);
    value.PutInt(PhotoColumn::MEDIA_TIME_PENDING, assetInfo.timePending_);
    value.PutInt(PhotoColumn::PHOTO_IS_TEMP, assetInfo.isTemp_);
    value.PutInt(PhotoColumn::PHOTO_BURST_COVER_LEVEL, assetInfo.burstCoverLevel_);
    value.PutInt(PhotoColumn::PHOTO_OWNER_ALBUM_ID, assetInfo.ownerAlbumId_);
    value.PutLong(PhotoColumn::PHOTO_HIDDEN_TIME, assetInfo.hiddenTime_);
    value.PutString(PhotoColumn::MEDIA_NAME, assetInfo.displayName_);
    value.PutString(PhotoColumn::MEDIA_FILE_PATH, assetInfo.path_);
    return value;
}

NativeRdb::ValuesBucket GetAlbumValuesBucket(Media::AccurateRefresh::AlbumChangeInfo &albumInfo)
{
    NativeRdb::ValuesBucket value;
    value.PutInt(PhotoAlbumColumns::ALBUM_ID, albumInfo.albumId_);
    value.PutInt(PhotoAlbumColumns::ALBUM_TYPE, albumInfo.albumType_);
    value.PutInt(PhotoAlbumColumns::ALBUM_SUBTYPE, albumInfo.albumSubType_);
    value.PutInt(PhotoAlbumColumns::ALBUM_COUNT, albumInfo.count_);
    value.PutInt(PhotoAlbumColumns::ALBUM_IMAGE_COUNT, albumInfo.imageCount_);
    value.PutInt(PhotoAlbumColumns::ALBUM_VIDEO_COUNT, albumInfo.videoCount_);
    value.PutString(PhotoAlbumColumns::ALBUM_COVER_URI, albumInfo.coverUri_);
    value.PutInt(PhotoAlbumColumns::HIDDEN_COUNT, albumInfo.hiddenCount_);
    value.PutString(PhotoAlbumColumns::HIDDEN_COVER, albumInfo.hiddenCoverUri_);
    value.PutLong(PhotoAlbumColumns::COVER_DATE_TIME, albumInfo.coverDateTime_);
    value.PutLong(PhotoAlbumColumns::HIDDEN_COVER_DATE_TIME, albumInfo.hiddenCoverDateTime_);
    value.PutInt(PhotoAlbumColumns::ALBUM_DIRTY, albumInfo.dirty_);
    value.PutString(PhotoAlbumColumns::ALBUM_NAME, albumInfo.albumName_);
    return value;
}

void SetAssetValuesBuckets(std::vector<NativeRdb::ValuesBucket> &valuesBuckets,
    Media::AccurateRefresh::PhotoAssetChangeInfo &assetInfo)
{
    auto valuesBucket = GetAssetValuesBucket(assetInfo);
    valuesBuckets.push_back(valuesBucket);
}

void SetAlbumValuesBuckets(std::vector<NativeRdb::ValuesBucket> &valuesBuckets,
    Media::AccurateRefresh::AlbumChangeInfo &albumInfo)
{
    auto valuesBucket = GetAlbumValuesBucket(albumInfo);
    valuesBuckets.push_back(valuesBucket);
}

void AssetInsertOperation()
{
    int64_t outRowId = 0;
    Media::AccurateRefresh::PhotoAssetChangeInfo assetInfo = GetPhotoAssetChangeInfo();
    AccurateRefresh::AssetAccurateRefresh assetRefresh("AssetInsertOperation");
    Uri uri(provider->ConsumeBytesAsString(NUM_BYTES));
    Media::MediaLibraryCommand cmd(uri);
    cmd.SetTableName(PHOTO_TABLE_NAME);
    cmd.SetValueBucket(GetAssetValuesBucket(assetInfo));
    assetRefresh.Insert(cmd, outRowId);
    assetRefresh.RefreshAlbum();
    assetRefresh.Notify();
}

void AssetBatchInsert()
{
    int64_t insertChangedRows = 0;
    Media::AccurateRefresh::PhotoAssetChangeInfo assetInfo = GetPhotoAssetChangeInfo();
    AccurateRefresh::AssetAccurateRefresh assetRefresh("AssetBatchInsert");
    Uri uri(provider->ConsumeBytesAsString(NUM_BYTES));
    Media::MediaLibraryCommand cmd(uri);
    cmd.SetTableName(PHOTO_TABLE_NAME);
    std::vector<NativeRdb::ValuesBucket> valuesBuckets;
    SetAssetValuesBuckets(valuesBuckets, assetInfo);
    assetRefresh.BatchInsert(cmd, insertChangedRows, valuesBuckets);
    assetRefresh.RefreshAlbum();
    assetRefresh.Notify();
}

void AssetUpdate()
{
    int32_t changedRow = 0;
    AccurateRefresh::AssetAccurateRefresh assetRefresh("AssetUpdate");
    NativeRdb::RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    auto newId = provider->ConsumeIntegralInRange<int32_t>(0, MAX_ID);
    predicates.EqualTo(PhotoColumn::MEDIA_ID, newId);
    NativeRdb::ValuesBucket value;
    int64_t dataTrashTime = MediaFileUtils::UTCTimeMilliSeconds();
    value.PutInt(PhotoColumn::MEDIA_DATE_TRASHED, dataTrashTime);
    assetRefresh.Update(changedRow, value, predicates);
    assetRefresh.RefreshAlbum();
    assetRefresh.Notify();
}

void AssetLogicalDeleteByCmd()
{
    int32_t changeRows = 0;
    AccurateRefresh::AssetAccurateRefresh assetRefresh("AssetLogicalDeleteByCmd");
    Uri uri(provider->ConsumeBytesAsString(NUM_BYTES));
    MediaLibraryCommand cmd(uri);
    cmd.SetTableName(PHOTO_TABLE_NAME);
    auto predicates = cmd.GetAbsRdbPredicates();
    predicates->SetWhereClause(PhotoAlbumColumns::ALBUM_SUBTYPE + " = ?");
    int32_t instIndex = provider->ConsumeIntegralInRange<int32_t>(0, PHOTO_ALBUM_SUB_TYPE.size()-1);
    predicates->SetWhereArgs({to_string(PHOTO_ALBUM_SUB_TYPE[instIndex])});
    assetRefresh.LogicalDeleteReplaceByUpdate(cmd, changeRows);
    assetRefresh.RefreshAlbum();
    assetRefresh.Notify();
}

void AssetExecuteSql()
{
    std::string deleteSql = PHOTOS_DELETE_SQL_STR + to_string(provider->ConsumeIntegralInRange<int32_t>(0, MAX_ID));
    std::shared_ptr<TransactionOperations> trans = make_shared<TransactionOperations>(__func__);
    AccurateRefresh::AssetAccurateRefresh assetRefresh("AssetLogicalDeleteByCmd", trans);
    assetRefresh.Init();
    assetRefresh.ExecuteSql(deleteSql, GetRdbOperation());
    assetRefresh.RefreshAlbum();
    assetRefresh.Notify();
}

void AlbumInsertOperation()
{
    int64_t outRowId = 0;
    Media::AccurateRefresh::AlbumChangeInfo albumInfo = GetAlbumChangeInfo();
    AccurateRefresh::AlbumAccurateRefresh albumRefresh("AlbumInsertOperation");
    Uri uri(provider->ConsumeBytesAsString(NUM_BYTES));
    Media::MediaLibraryCommand cmd(uri);
    cmd.SetTableName(ALBUM_TABLE_NAME);
    cmd.SetValueBucket(GetAlbumValuesBucket(albumInfo));
    albumRefresh.Insert(cmd, outRowId);
    albumRefresh.Notify();
}

void AlbumLogicalDeleteByCmd()
{
    int32_t deletedRows = 0;
    Media::AccurateRefresh::AlbumChangeInfo albumInfo = GetAlbumChangeInfo();
    AccurateRefresh::AlbumAccurateRefresh albumRefresh("AlbumLogicalDeleteByCmd");
    Uri uri(provider->ConsumeBytesAsString(NUM_BYTES));
    Media::MediaLibraryCommand cmd(uri);
    cmd.SetTableName(ALBUM_TABLE_NAME);
    auto predicates = cmd.GetAbsRdbPredicates();
    predicates->SetWhereClause(PhotoAlbumColumns::ALBUM_SUBTYPE + " = ?");
    int32_t instIndex = provider->ConsumeIntegralInRange<int32_t>(0, PHOTO_ALBUM_SUB_TYPE.size()-1);
    predicates->SetWhereArgs({to_string(PHOTO_ALBUM_SUB_TYPE[instIndex])});
    albumRefresh.LogicalDeleteReplaceByUpdate(cmd, deletedRows);
    albumRefresh.Notify();
}

void AlbumLogicalDeleteByPredicates()
{
    int32_t deletedRows = 0;
    Media::AccurateRefresh::AlbumChangeInfo albumInfo = GetAlbumChangeInfo();
    AccurateRefresh::AlbumAccurateRefresh albumRefresh("AlbumLogicalDeleteByPredicates");
    NativeRdb::RdbPredicates predicates(ALBUM_TABLE_NAME);
    int32_t instIndex = provider->ConsumeIntegralInRange<int32_t>(0, PHOTO_ALBUM_SUB_TYPE.size()-1);
    predicates.EqualTo(PhotoAlbumColumns::ALBUM_SUBTYPE, to_string(PHOTO_ALBUM_SUB_TYPE[instIndex]));
    albumRefresh.LogicalDeleteReplaceByUpdate(predicates, deletedRows);
    albumRefresh.Notify();
}

void AlbumBatchInsert()
{
    int64_t insertChangedRows = 0;
    Media::AccurateRefresh::AlbumChangeInfo albumInfo = GetAlbumChangeInfo();
    AccurateRefresh::AlbumAccurateRefresh albumRefresh("AlbumBatchInsert");
    Uri uri(provider->ConsumeBytesAsString(NUM_BYTES));
    Media::MediaLibraryCommand cmd(uri);
    cmd.SetTableName(ALBUM_TABLE_NAME);
    cmd.SetValueBucket(GetAlbumValuesBucket(albumInfo));
    std::vector<NativeRdb::ValuesBucket> valuesBuckets;
    SetAlbumValuesBuckets(valuesBuckets, albumInfo);
    albumRefresh.BatchInsert(cmd, insertChangedRows, valuesBuckets);
    albumRefresh.Notify();
}

void AlbumUpdate()
{
    int32_t changedRows = 0;
    Media::AccurateRefresh::AlbumChangeInfo albumInfo = GetAlbumChangeInfo();
    AccurateRefresh::AlbumAccurateRefresh albumRefresh("AlbumUpdate");
    Uri uri(provider->ConsumeBytesAsString(NUM_BYTES));
    Media::MediaLibraryCommand cmd(uri);
    cmd.SetTableName(ALBUM_TABLE_NAME);
    cmd.SetValueBucket(GetAlbumValuesBucket(albumInfo));
    albumRefresh.Update(cmd, changedRows);
    albumRefresh.Notify();
}

void AlbumExecuteSql()
{
    int64_t outRowId = 0;
    auto oldAlbumId = provider->ConsumeIntegralInRange<int32_t>(0, MAX_ID);
    auto newAlbumId = provider->ConsumeIntegralInRange<int32_t>(0, MAX_ID);
    std::string initSql = ALBUM_SELECT_SQL_STR + to_string(oldAlbumId);
    std::string deleteSql = ALBUM_DELETE_SQL_STR + to_string(oldAlbumId);
    AccurateRefresh::RdbOperation operation = GetRdbOperation();
    std::shared_ptr<TransactionOperations> trans = make_shared<TransactionOperations>(__func__);
    AccurateRefresh::AlbumAccurateRefresh albumRefresh("AlbumExecuteSql", trans);

    std::vector<NativeRdb::ValuesBucket> valuesBuckets;
    Media::AccurateRefresh::AlbumChangeInfo albumInfo = GetAlbumChangeInfo();
    albumInfo.albumId_ = newAlbumId;
    auto value = GetAlbumValuesBucket(albumInfo);
    albumRefresh.Insert(outRowId, ALBUM_TABLE_NAME, value);

    NativeRdb::RdbPredicates rdbPredicatesAlbum(ALBUM_TABLE_NAME);
    rdbPredicatesAlbum.EqualTo(PhotoAlbumColumns::ALBUM_ID, oldAlbumId);
    albumRefresh.Init(rdbPredicatesAlbum);
    albumRefresh.ExecuteSql(deleteSql, operation);
    albumRefresh.Notify();
}

void AlbumExecuteForLastInsertedRowId()
{
    auto insertSql = ALBUM_SELECT_SQL_STR + to_string(provider->ConsumeIntegralInRange<int32_t>(0, MAX_ID));
    AccurateRefresh::RdbOperation operation = GetRdbOperation();
    AccurateRefresh::AlbumAccurateRefresh albumRefresh("AlbumExecuteForLastInsertedRowId");
    albumRefresh.Init();
    vector<NativeRdb::ValueObject> valueObjects = {to_string(provider->ConsumeIntegralInRange<int32_t>(0, MAX_ID))};
    albumRefresh.ExecuteForLastInsertedRowId(insertSql, valueObjects, operation);
    albumRefresh.Notify();
}

static void AssetAccurateRefreshFuzzerTest()
{
    AssetInsertOperation();
    AssetBatchInsert();
    AssetUpdate();
    AssetLogicalDeleteByCmd();
    AssetExecuteSql();
}

static void AlbumAccurateRefreshFuzzerTest()
{
    AlbumInsertOperation();
    AlbumLogicalDeleteByCmd();
    AlbumLogicalDeleteByPredicates();
    AlbumBatchInsert();
    AlbumUpdate();
    AlbumExecuteSql();
    AlbumExecuteForLastInsertedRowId();
}

} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::Init();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::provider = &provider;
    if (data == nullptr) {
        return 0;
    }
    OHOS::AssetAccurateRefreshFuzzerTest();
    OHOS::AlbumAccurateRefreshFuzzerTest();
    OHOS::ClearKvStore();
    return 0;
}