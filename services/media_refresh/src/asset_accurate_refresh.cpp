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
#include "medialibrary_trigger_manager.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media::AccurateRefresh {

class TransactionManager {
public:
    bool Init(AccurateRefreshBase& refresh, const std::string& info, int32_t& ret)
    {
        CHECK_AND_RETURN_RET_INFO_LOG(!refresh.trans_, true, "refresh has alreay got transaction");
        auto trans = std::make_shared<TransactionOperations>(info);
        CHECK_AND_RETURN_RET_LOG(trans, false, "TransactionManager fail to create transaction");
        auto transStartRet = trans->Start();
        CHECK_AND_RETURN_RET_LOG(transStartRet == NativeRdb::E_OK, false,
            "TransactionManager fail to start trans, ret: %{public}d", transStartRet);
        refresh.trans_ = trans;
        MEDIA_DEBUG_LOG("TransactionManager init trans info:%{public}s trans:%{public}p",
            info.c_str(), refresh.trans_.get());
        refresh.SetDataManagerTransaction(refresh.trans_);
        callback = [&]() -> void {
            CHECK_AND_RETURN_LOG(refresh.trans_,
                "TransactionManager try to finish/rollback transaction, but transaction is null");
            int32_t retTemp;
            if (ret == ACCURATE_REFRESH_RET_OK) {
                retTemp = refresh.trans_->Finish();
            } else {
                retTemp = refresh.trans_->Rollback();
            }
            std::string operationType = ((ret == ACCURATE_REFRESH_RET_OK) ? "Finish" : "RollBack");
            if (retTemp != NativeRdb::E_OK) {
                MEDIA_ERR_LOG("TransactionManager fail to %{public}s transaction",
                    operationType.c_str());
            } else {
                MEDIA_INFO_LOG("TransactionManager succeed to %{public}s transaction",
                    operationType.c_str());
            }
            refresh.trans_ = nullptr;
            MEDIA_DEBUG_LOG("TransactionManager set trans trans:%{public}p", refresh.trans_.get());
            refresh.SetDataManagerTransaction(refresh.trans_);
        };
        return true;
    }
    ~TransactionManager()
    {
        callback();
    }
private:
    std::function<void()> callback = []() -> void {return;};
};

AssetAccurateRefresh::AssetAccurateRefresh(std::shared_ptr<TransactionOperations> trans) : AccurateRefreshBase(trans)
{
    SetDataManagerTransaction(trans);
}

int32_t AssetAccurateRefresh::Init()
{
    return ACCURATE_REFRESH_RET_OK;
}

void AssetAccurateRefresh::SetDataManagerTransaction(std::shared_ptr<TransactionOperations> trans)
{
    dataManager_.SetTransaction(trans);
}

int32_t AssetAccurateRefresh::Insert(MediaLibraryCommand &cmd, int64_t &outRowId)
{
    int32_t ret;
    {
        TransactionManager transactionManager;
        if (!transactionManager.Init(*this, "AssetAccurateRefresh::Insert", ret)) {
            MEDIA_ERR_LOG("transactionManager init failed");
            ret = ACCURATE_REFRESH_RDB_TRANS_GEN_ERR;
            return ret;
        }
        CHECK_AND_RETURN_RET_LOG(trans_, ret = ACCURATE_REFRESH_RDB_TRANS_GEN_ERR,
            "trans_ of assetAccurateRefresh for insert is nullptr");
        ret = AccurateRefreshBase::Insert(cmd, outRowId);
        CHECK_AND_RETURN_RET_LOG(ret == ACCURATE_REFRESH_RET_OK,
            ret, "assetAccurateRefresh fail to Insert, ret: %{public}d", ret);
        auto trigger = MediaLibraryTriggerManager::GetInstance().GetTrigger(
            cmd.GetTableName(), MediaLibraryTriggerManager::TriggerType::INSERT);
        CHECK_AND_RETURN_RET_LOG(trigger,
            ret = ACCURATE_REFRESH_RDB_TRIGGER_ERR, "assetAccurateRefresh fail to get trigger");
        auto changeDataVec = dataManager_.GetChangeDatas();
        MEDIA_DEBUG_LOG("get %{public}zu changedata for trigger", changeDataVec.size());
        ret = trigger->Process(trans_, changeDataVec);
        CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, ret,
            "trigger fail to process, ret:%{public}d", ret);
    }
    return ret;
}

int32_t AssetAccurateRefresh::Insert(int64_t &outRowId, const std::string &table, NativeRdb::ValuesBucket &value)
{
    int32_t ret;
    {
        TransactionManager transactionManager;
        if (!transactionManager.Init(*this, "AssetAccurateRefresh::Insert", ret)) {
            MEDIA_ERR_LOG("transactionManager init failed");
            ret = ACCURATE_REFRESH_RDB_TRANS_GEN_ERR;
            return ret;
        }
        CHECK_AND_RETURN_RET_LOG(trans_, ret = ACCURATE_REFRESH_RDB_TRANS_GEN_ERR,
            "trans_ of assetAccurateRefresh for insert is nullptr");
        ret =  AccurateRefreshBase::Insert(outRowId, table, value);
        CHECK_AND_RETURN_RET_LOG(ret == ACCURATE_REFRESH_RET_OK,
            ret, "assetAccurateRefresh fail to Insert, ret: %{public}d", ret);
        auto trigger = MediaLibraryTriggerManager::GetInstance().GetTrigger(table,
            MediaLibraryTriggerManager::TriggerType::INSERT);
        CHECK_AND_RETURN_RET_LOG(trigger, ret = ACCURATE_REFRESH_RDB_TRIGGER_ERR,
            "assetAccurateRefresh fail to get trigger");
        auto changeDataVec = dataManager_.GetChangeDatas();
        MEDIA_DEBUG_LOG("get %{public}zu changedata for trigger", changeDataVec.size());
        ret = trigger->Process(trans_, changeDataVec);
        CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, ret,
            "trigger fail to process, ret:%{public}d", ret);
    }
    return ret;
}

int32_t AssetAccurateRefresh::BatchInsert(int64_t &changedRows, const std::string &table,
    std::vector<NativeRdb::ValuesBucket> &values)
{
    int32_t ret;
    {
        TransactionManager transactionManager;
        if (!transactionManager.Init(*this, "AssetAccurateRefresh::BatchInsert", ret)) {
            MEDIA_ERR_LOG("transactionManager init failed");
            ret = ACCURATE_REFRESH_RDB_TRANS_GEN_ERR;
            return ret;
        }
        CHECK_AND_RETURN_RET_LOG(trans_, ret = ACCURATE_REFRESH_RDB_TRANS_GEN_ERR,
            "trans_ of assetAccurateRefresh for BatchInsert is nullptr");
        ret =  AccurateRefreshBase::BatchInsert(changedRows, table, values);
        CHECK_AND_RETURN_RET_LOG(ret == ACCURATE_REFRESH_RET_OK, ret,
            "assetAccurateRefresh fail to BatchInsert, ret: %{public}d", ret);
        auto trigger = MediaLibraryTriggerManager::GetInstance().GetTrigger(table,
            MediaLibraryTriggerManager::TriggerType::INSERT);
        CHECK_AND_RETURN_RET_LOG(trigger, ret = ACCURATE_REFRESH_RDB_TRIGGER_ERR,
            "assetAccurateRefresh fail to get trigger");
        auto changeDataVec = dataManager_.GetChangeDatas();
        MEDIA_DEBUG_LOG("get %{public}zu changedata for trigger", changeDataVec.size());
        ret = trigger->Process(trans_, changeDataVec);
        CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, ret,
            "trigger fail to process, ret:%{public}d", ret);
    }
    return ret;
}


int32_t AssetAccurateRefresh::ExecuteForLastInsertedRowId(const std::string &sql,
    const std::vector<NativeRdb::ValueObject> &bindArgs, RdbOperation operation)
{
    int32_t ret;
    if (operation == RDB_OPERATION_ADD) {
        TransactionManager transactionManager;
        if (!transactionManager.Init(*this, "AssetAccurateRefresh::ExecuteForLastInsertedRowId", ret)) {
            MEDIA_ERR_LOG("transactionManager init failed");
            ret = ACCURATE_REFRESH_RDB_TRANS_GEN_ERR;
            return ret;
        }
        CHECK_AND_RETURN_RET_LOG(trans_, ret = ACCURATE_REFRESH_RDB_TRANS_GEN_ERR,
            "trans_ of assetAccurateRefresh for ExecuteForLastInsertedRowId is nullptr");
        ret =  AccurateRefreshBase::ExecuteForLastInsertedRowId(sql, bindArgs, operation);
        CHECK_AND_RETURN_RET_LOG(ret == ACCURATE_REFRESH_RET_OK, ret,
            "assetAccurateRefresh fail to ExecuteForLastInsertedRowId, ret: %{public}d", ret);
        auto trigger = MediaLibraryTriggerManager::GetInstance().GetTrigger(PhotoColumn::PHOTOS_TABLE,
            MediaLibraryTriggerManager::TriggerType::INSERT);
        CHECK_AND_RETURN_RET_LOG(trigger, ret = ACCURATE_REFRESH_RDB_TRIGGER_ERR,
            "assetAccurateRefresh fail to get trigger");
        auto changeDataVec = dataManager_.GetChangeDatas();
        MEDIA_DEBUG_LOG("get %{public}zu changedata for trigger", changeDataVec.size());
        ret = trigger->Process(trans_, changeDataVec);
        CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, ret,
            "trigger fail to process, ret:%{public}d", ret);
    } else {
        ret = AccurateRefreshBase::ExecuteForLastInsertedRowId(sql, bindArgs, operation);
    }
    return ret;
}

int32_t AssetAccurateRefresh::ExecuteSql(const std::string &sql,
    const std::vector<NativeRdb::ValueObject> &bindArgs, RdbOperation operation)
{
    int32_t ret;
    if (operation == RDB_OPERATION_ADD) {
        TransactionManager transactionManager;
        if (!transactionManager.Init(*this, "AssetAccurateRefresh::ExecuteSql", ret)) {
            MEDIA_ERR_LOG("transactionManager init failed");
            ret = ACCURATE_REFRESH_RDB_TRANS_GEN_ERR;
            return ret;
        }
        CHECK_AND_RETURN_RET_LOG(trans_, ret = ACCURATE_REFRESH_RDB_TRANS_GEN_ERR,
            "trans_ of assetAccurateRefresh for ExecuteSql is nullptr");
        ret =  AccurateRefreshBase::ExecuteSql(sql, bindArgs, operation);
        CHECK_AND_RETURN_RET_LOG(ret == ACCURATE_REFRESH_RET_OK, ret,
            "assetAccurateRefresh fail to ExecuteSql, ret: %{public}d", ret);
        auto trigger = MediaLibraryTriggerManager::GetInstance().GetTrigger(PhotoColumn::PHOTOS_TABLE,
            MediaLibraryTriggerManager::TriggerType::INSERT);
        CHECK_AND_RETURN_RET_LOG(trigger, ret = ACCURATE_REFRESH_RDB_TRIGGER_ERR,
            "assetAccurateRefresh fail to get trigger");
        auto changeDataVec = dataManager_.GetChangeDatas();
        MEDIA_DEBUG_LOG("get %{public}zu changedata for trigger", changeDataVec.size());
        ret = trigger->Process(trans_, changeDataVec);
        CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, ret,
            "trigger fail to process, ret:%{public}d", ret);
    } else {
        ret = AccurateRefreshBase::ExecuteSql(sql, bindArgs, operation);
    }
    return ret;
}

int32_t AssetAccurateRefresh::ExecuteForChangedRowCount(int64_t &outValue, const std::string &sql,
    const std::vector<NativeRdb::ValueObject> &bindArgs, RdbOperation operation)
{
    int32_t ret;
    if (operation == RDB_OPERATION_ADD) {
        TransactionManager transactionManager;
        if (!transactionManager.Init(*this, "AssetAccurateRefresh::ExecuteForChangedRowCount", ret)) {
            MEDIA_ERR_LOG("transactionManager init failed");
            ret = ACCURATE_REFRESH_RDB_TRANS_GEN_ERR;
            return ret;
        }
        CHECK_AND_RETURN_RET_LOG(trans_, ret = ACCURATE_REFRESH_RDB_TRANS_GEN_ERR,
            "trans_ of assetAccurateRefresh for ExecuteForChangedRowCount is nullptr");
        ret =  AccurateRefreshBase::ExecuteForChangedRowCount(outValue, sql, bindArgs, operation);
        CHECK_AND_RETURN_RET_LOG(ret == ACCURATE_REFRESH_RET_OK, ret,
            "assetAccurateRefresh fail to ExecuteForChangedRowCount, ret: %{public}d", ret);
        auto trigger = MediaLibraryTriggerManager::GetInstance().GetTrigger(PhotoColumn::PHOTOS_TABLE,
            MediaLibraryTriggerManager::TriggerType::INSERT);
        CHECK_AND_RETURN_RET_LOG(trigger, ret = ACCURATE_REFRESH_RDB_TRIGGER_ERR,
            "assetAccurateRefresh fail to get trigger");
        auto changeDataVec = dataManager_.GetChangeDatas();
        MEDIA_DEBUG_LOG("get %{public}zu changedata for trigger", changeDataVec.size());
        ret = trigger->Process(trans_, changeDataVec);
        CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, ret,
            "trigger fail to process, ret:%{public}d", ret);
    } else {
        ret = AccurateRefreshBase::ExecuteForChangedRowCount(outValue, sql, bindArgs, operation);
    }
    return ret;
}

int32_t AssetAccurateRefresh::Init(const AbsRdbPredicates &predicates)
{
    if (!IsValidTable(predicates.GetTableName())) {
        return ACCURATE_REFRESH_RDB_INVALITD_TABLE;
    }

    return dataManager_.Init(predicates);
}

int32_t AssetAccurateRefresh::Init(const string &sql, const vector<ValueObject> bindArgs)
{
    return dataManager_.Init(sql, bindArgs);
}

// 增删场景下初始化数据
int32_t AssetAccurateRefresh::Init(const vector<int32_t> &fileIds)
{
    return dataManager_.Init(fileIds);
}

// refresh album based on init datas and modified datas.
int32_t AssetAccurateRefresh::RefreshAlbum(NotifyAlbumType notifyAlbumType)
{
    auto assetChangeDatas = dataManager_.GetChangeDatas();
    if (assetChangeDatas.empty()) {
        MEDIA_WARN_LOG("change data empty.");
        return ACCURATE_REFRESH_CHANGE_DATA_EMPTY;
    }
    return RefreshAlbum(assetChangeDatas, notifyAlbumType);
}

// 根据传递的assetChangeDatas更新相册，不需要dataManager_处理
int32_t AssetAccurateRefresh::RefreshAlbum(const vector<PhotoAssetChangeData> &assetChangeDatas,
    NotifyAlbumType notifyAlbumType)
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

    return albumRefreshExe_.RefreshAlbum(assetChangeDatas, notifyAlbumType);
}

// notify assest change infos based on init datas and modified datas.
int32_t AssetAccurateRefresh::Notify()
{
    // 相册通知
    albumRefreshExe_.Notify();

    // 资产通知
    return Notify(dataManager_.GetChangeDatas());
}

// 根据传递的assetChangeDatas进行通知，不需要dataManager_处理
int32_t AssetAccurateRefresh::Notify(const std::vector<PhotoAssetChangeData> &assetChangeDatas)
{
    if (assetChangeDatas.empty()) {
        MEDIA_WARN_LOG("assetChangeDatas empty.");
        return ACCURATE_REFRESH_INPUT_PARA_ERR;
    }

    notifyExe_.Notify(assetChangeDatas);
    return ACCURATE_REFRESH_RET_OK;
}

int32_t AssetAccurateRefresh::UpdateModifiedDatasInner(const std::vector<int> &fileIds, RdbOperation operation)
{
    auto modifiedFileIds = fileIds;
    if (modifiedFileIds.empty()) {
        MEDIA_WARN_LOG("input modifiedFileIds empty.");
        return ACCURATE_REFRESH_INPUT_PARA_ERR;
    }

    int32_t err = dataManager_.UpdateModifiedDatasInner(modifiedFileIds, operation);
    CHECK_AND_RETURN_RET_LOG(err == ACCURATE_REFRESH_RET_OK, err,
        "UpdateModifiedDatasInner failed, err:%{public}d", err);
    err = dataManager_.PostProcessModifiedDatas(modifiedFileIds);
    CHECK_AND_RETURN_RET_LOG(err == ACCURATE_REFRESH_RET_OK, err,
        "PostProcessModifiedDatas failed, err:%{public}d", err);
    return ACCURATE_REFRESH_RET_OK;
}

int32_t AssetAccurateRefresh::UpdateModifiedDatas()
{
    return dataManager_.UpdateModifiedDatas();
}

string AssetAccurateRefresh::GetReturningKeyName()
{
    return PhotoColumn::MEDIA_ID;
}

int32_t AssetAccurateRefresh::LogicalDeleteReplaceByUpdate(MediaLibraryCommand &cmd, int32_t &deletedRows)
{
    if (!IsValidTable(cmd.GetTableName())) {
        return ACCURATE_REFRESH_RDB_INVALITD_TABLE;
    }
    return DeleteCommon([&](ValuesBucket &values) {
        return Update(deletedRows, values, *(cmd.GetAbsRdbPredicates()), RDB_OPERATION_REMOVE);
    });
}

int32_t AssetAccurateRefresh::LogicalDeleteReplaceByUpdate(const AbsRdbPredicates &predicates, int32_t &deletedRows)
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
    if (!trans_) {
        CloudSyncHelper::GetInstance()->StartSync();
        ACCURATE_DEBUG("Delete update done, start sync.");
    }
#endif

    return ACCURATE_REFRESH_RET_OK;
}

bool AssetAccurateRefresh::IsValidTable(std::string tableName)
{
    return PhotoColumn::PHOTOS_TABLE == tableName;
}

int32_t AssetAccurateRefresh::SetContentChanged(int32_t fileId, bool isChanged)
{
    return dataManager_.SetContentChanged(fileId, isChanged);
}

int32_t AssetAccurateRefresh::SetThumbnailStatus(int32_t fileId, int32_t status)
{
    // 函数调用错误
    return dataManager_.SetThumbnailStatus(fileId, status);
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