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

#define MLOG_TAG "AccurateRefresh::AssetAccurateRefresh"

#ifndef MEDIA_REFRESH_TEST
#include "cloud_sync_helper.h"
#endif
#include <cstdint>
#include "medialibrary_errno.h"
#include "media_file_utils.h"
#include "asset_accurate_refresh.h"
#include "medialibrary_notify_new.h"
#include "accurate_debug_log.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media::AccurateRefresh {

extern bool IS_ACCURATE_REFRESH_DEBUG;

AssetAccurateRefresh::AssetAccurateRefresh(std::shared_ptr<TransactionOperations> trans) : AccurateRefreshBase(trans)
{
    ACCURATE_DEBUG("new AssetAccurateRefresh");
}

int32_t AssetAccurateRefresh::Init()
{
    if (!dataManager_) {
        ACCURATE_DEBUG("Init");
        dataManager_ = make_shared<AssetDataManager>(trans_);
        notifyExe_ = make_shared<AssetChangeNotifyExecution>();
    } else {
        ACCURATE_DEBUG("already init.");
    }

    return ACCURATE_REFRESH_RET_OK;
}

int32_t AssetAccurateRefresh::Init(const AbsRdbPredicates &predicates)
{
    if (!IsValidTable(predicates.GetTableName())) {
        return ACCURATE_REFRESH_RDB_INVALITD_TABLE;
    }
    if (!dataManager_) {
        Init();
        return dataManager_->Init(predicates);
    }
    ACCURATE_DEBUG("already init.");
    return ACCURATE_REFRESH_RET_OK;
}

int32_t AssetAccurateRefresh::Init(const string &sql, const vector<ValueObject> bindArgs)
{
    if (!dataManager_) {
        Init();
        return dataManager_->Init(sql, bindArgs);
    }
    ACCURATE_DEBUG("already init.");
    return ACCURATE_REFRESH_RET_OK;
}

// 增删场景下初始化数据
int32_t AssetAccurateRefresh::Init(const vector<int32_t> &fileIds)
{
    if (!dataManager_) {
        Init();
        return dataManager_->Init(fileIds);
    }
    ACCURATE_DEBUG("already init.");
    return ACCURATE_REFRESH_RET_OK;
}

// refresh album based on init datas and modified datas.
int32_t AssetAccurateRefresh::RefreshAlbum()
{
    ACCURATE_DEBUG("RefreshAlbum");
    if (!dataManager_) {
        MEDIA_WARN_LOG("no Init.");
        return ACCURATE_REFRESH_DATA_MGR_NULL;
    }

    auto assetChangeDatas = dataManager_->GetChangeDatas();
    if (assetChangeDatas.empty()) {
        MEDIA_WARN_LOG("change data empty.");
        return ACCURATE_REFRESH_CHANGE_DATA_EMPTY;
    }
    return RefreshAlbum(assetChangeDatas);
}

// 根据传递的assetChangeDatas更新相册，不需要dataManager_处理
int32_t AssetAccurateRefresh::RefreshAlbum(const vector<PhotoAssetChangeData> &assetChangeDatas)
{
    if (assetChangeDatas.empty()) {
        MEDIA_WARN_LOG("input asset change datas empty.");
        return ACCURATE_REFRESH_INPUT_PARA_ERR;
    }
    auto diffCount = assetChangeDatas.size();
    for (const auto &assetChangeData : assetChangeDatas) {
        if (assetChangeData.infoBeforeChange_ != assetChangeData.infoAfterChange_) {
            break;
        }
        diffCount--;
    }
    if (diffCount == 0) {
        MEDIA_WARN_LOG("asset change datas are same, no need refresh album.");
        return ACCURATE_REFRESH_RET_OK;
    }
    if (!albumRefreshExe_) {
        albumRefreshExe_ = make_shared<AlbumRefreshExecution>();
    }
    return albumRefreshExe_->RefreshAlbum(assetChangeDatas);
}

// notify assest change infos based on init datas and modified datas.
int32_t AssetAccurateRefresh::Notify()
{
    ACCURATE_DEBUG("Notify");
    // 相册通知
    if (albumRefreshExe_) {
        albumRefreshExe_->Notify();
    }

    // 资产通知
    if (!dataManager_) {
        MEDIA_WARN_LOG("dataManager_ null.");
        return ACCURATE_REFRESH_DATA_MGR_NULL;
    }

    return Notify(dataManager_->GetChangeDatas());
}

// 根据传递的assetChangeDatas进行通知，不需要dataManager_处理
int32_t AssetAccurateRefresh::Notify(std::vector<PhotoAssetChangeData> assetChangeDatas)
{
    if (assetChangeDatas.empty()) {
        MEDIA_WARN_LOG("assetChangeDatas empty.");
        return ACCURATE_REFRESH_INPUT_PARA_ERR;
    }

    if (!notifyExe_) {
        MEDIA_WARN_LOG("notifyExe_ null.");
        return ACCURATE_REFRESH_NOTIFY_EXE_NULL;
    }

    notifyExe_->Notify(assetChangeDatas);
    return ACCURATE_REFRESH_RET_OK;
}

int32_t AssetAccurateRefresh::UpdateModifiedDatasInner(const std::vector<int> &fileIds, RdbOperation operation)
{
    ACCURATE_DEBUG("UpdateModifiedDatasInner");

    auto modifiedFileIds = fileIds;
    if (modifiedFileIds.empty()) {
        MEDIA_WARN_LOG("input modifiedFileIds empty.");
        return ACCURATE_REFRESH_INPUT_PARA_ERR;
    }

    if (!dataManager_) {
        MEDIA_WARN_LOG("dataManager_ null.");
        return ACCURATE_REFRESH_DATA_MGR_NULL;
    }

    return dataManager_->UpdateModifiedDatasInner(modifiedFileIds, operation);
}

int32_t AssetAccurateRefresh::UpdateModifiedDatas()
{
    if (!dataManager_) {
        MEDIA_WARN_LOG("dataManager_ null.");
        return ACCURATE_REFRESH_DATA_MGR_NULL;
    }

    return dataManager_->UpdateModifiedDatas();
}

string AssetAccurateRefresh::GetReturningKeyName()
{
    return PhotoColumn::MEDIA_ID;
}

int32_t AssetAccurateRefresh::Delete(MediaLibraryCommand &cmd, int32_t &deletedRows)
{
    if (!IsValidTable(cmd.GetTableName())) {
        return ACCURATE_REFRESH_RDB_INVALITD_TABLE;
    }
    return DeleteCommon([&](ValuesBucket &values) {
        return Update(deletedRows, values, *(cmd.GetAbsRdbPredicates()), RDB_OPERATION_REMOVE);
    });
}

int32_t AssetAccurateRefresh::Delete(const AbsRdbPredicates &predicates, int32_t &deletedRows)
{
    if (!IsValidTable(predicates.GetTableName())) {
        return ACCURATE_REFRESH_RDB_INVALITD_TABLE;
    }
    return DeleteCommon(
        [&](ValuesBucket &values) { return Update(deletedRows, values, predicates, RDB_OPERATION_REMOVE); });
}

int32_t AssetAccurateRefresh::DeleteCommon(function<int32_t(ValuesBucket &)> updateExe)
{
    ValuesBucket valuesBucket;
    valuesBucket.PutInt(MEDIA_DATA_DB_DIRTY, static_cast<int32_t>(DirtyType::TYPE_DELETED));
    valuesBucket.PutInt(MEDIA_DATA_DB_SYNC_STATUS, static_cast<int32_t>(SyncStatusType::TYPE_UPLOAD));
    valuesBucket.PutLong(PhotoColumn::PHOTO_META_DATE_MODIFIED, MediaFileUtils::UTCTimeMilliSeconds());
    auto ret = updateExe(valuesBucket);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("rdbStore_->Delete failed, ret = %{public}d", ret);
        return E_HAS_DB_ERROR;
    }

#ifndef MEDIA_REFRESH_TEST
    CloudSyncHelper::GetInstance()->StartSync();
    ACCURATE_DEBUG("Delete update done, start sync.");
#endif

    return ret;
}

bool AssetAccurateRefresh::IsValidTable(std::string tableName)
{
    return PhotoColumn::PHOTOS_TABLE == tableName;
}

int32_t AssetAccurateRefresh::SetContentChanged(int32_t fileId, bool isChanged)
{
    return dataManager_->SetContentChanged(fileId, isChanged);
}

int32_t AssetAccurateRefresh::SetThumbnailStatus(int32_t fileId, int32_t status)
{
    return dataManager_->SetContentChanged(fileId, status);
}

int32_t AssetAccurateRefresh::NotifyForReCheck()
{
    Notification::NotifyInfoInner notifyInfo;
    notifyInfo.tableType = Notification::NotifyTableType::PHOTOS;
    notifyInfo.operationType = Notification::ASSET_OPERATION_RECHECK;
    Notification::MediaLibraryNotifyNew::AddItem(notifyInfo);
    ACCURATE_DEBUG("asset recheck");
    return ACCURATE_REFRESH_RET_OK;
}

}  // namespace Media::AccurateRefresh
}  // namespace OHOS