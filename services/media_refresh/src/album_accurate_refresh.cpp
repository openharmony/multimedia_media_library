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

#define MLOG_TAG "AccurateRefresh::AlbumAccurateRefresh"
#include <cstdint>

#ifndef MEDIA_REFRESH_TEST
    #include "cloud_sync_helper.h"
#endif

#include "medialibrary_errno.h"
#include "album_accurate_refresh.h"
#include "medialibrary_notify_new.h"
#include "accurate_debug_log.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media::AccurateRefresh {

AlbumAccurateRefresh::AlbumAccurateRefresh(std::shared_ptr<TransactionOperations> trans) : AccurateRefreshBase(trans)
{
    ACCURATE_DEBUG("new AlbumAccurateRefresh");
}

int32_t AlbumAccurateRefresh::Init()
{
    if (!dataManager_) {
        ACCURATE_DEBUG("Init");
        dataManager_ = make_shared<AlbumDataManager>(trans_);
        notifyExe_ = make_shared<ALbumChangeNotifyExecution>();
    } else {
        ACCURATE_DEBUG("already init.");
    }
    return ACCURATE_REFRESH_RET_OK;
}

int32_t AlbumAccurateRefresh::Init(const AbsRdbPredicates &predicates)
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

int32_t AlbumAccurateRefresh::Init(const string &sql, const vector<ValueObject> bindArgs)
{
    if (!dataManager_) {
        Init();
        return dataManager_->Init(sql, bindArgs);
    }
    ACCURATE_DEBUG("already init.");
    return ACCURATE_REFRESH_RET_OK;
}

int32_t AlbumAccurateRefresh::Init(const std::vector<PhotoAlbumSubType> &systemTypes, const vector<int32_t> &albumIds)
{
    if (!dataManager_) {
        Init();
        return dataManager_->InitAlbumInfos(systemTypes, albumIds);
    }
    ACCURATE_DEBUG("already init.");
    return ACCURATE_REFRESH_RET_OK;
}

int32_t AlbumAccurateRefresh::Init(const std::vector<int32_t> &albumIds)
{
    if (!dataManager_) {
        Init();
        return dataManager_->InitAlbumInfos(vector<PhotoAlbumSubType>(), albumIds);
    }
    ACCURATE_DEBUG("already init.");
    return ACCURATE_REFRESH_RET_OK;
}

int32_t AlbumAccurateRefresh::Notify()
{
    ACCURATE_DEBUG("Notify");
    if (!dataManager_) {
        MEDIA_WARN_LOG("dataManager_ null.");
        return ACCURATE_REFRESH_DATA_MGR_NULL;
    }

    return Notify(dataManager_->GetChangeDatas());
}

int32_t AlbumAccurateRefresh::Notify(vector<AlbumChangeData> albumChangeDatas)
{
    if (albumChangeDatas.empty()) {
        MEDIA_WARN_LOG("albumChangeDatas empty.");
        return ACCURATE_REFRESH_INPUT_PARA_ERR;
    }
    if (!notifyExe_) {
        MEDIA_WARN_LOG("notifyExe_ null.");
        return ACCURATE_REFRESH_NOTIFY_EXE_NULL;
    }
    notifyExe_->Notify(albumChangeDatas);
    return ACCURATE_REFRESH_RET_OK;
}

int32_t AlbumAccurateRefresh::UpdateModifiedDatasInner(const std::vector<int> &albumIds, RdbOperation operation)
{
    ACCURATE_DEBUG("UpdateModifiedDatasInner");
    auto modifiedAlbumIds = albumIds;
    if (modifiedAlbumIds.empty()) {
        MEDIA_WARN_LOG("modifiedAlbumIds empty.");
        return ACCURATE_REFRESH_INPUT_PARA_ERR;
    }
    if (!dataManager_) {
        MEDIA_WARN_LOG("dataManager_ null.");
        return ACCURATE_REFRESH_DATA_MGR_NULL;
    }

    return dataManager_->UpdateModifiedDatasInner(modifiedAlbumIds, operation);
}

int32_t AlbumAccurateRefresh::UpdateModifiedDatas()
{
    if (!dataManager_) {
        MEDIA_WARN_LOG("dataManager_ null.");
        return ACCURATE_REFRESH_DATA_MGR_NULL;
    }
    
    return dataManager_->UpdateModifiedDatas();
}

map<int32_t, AlbumChangeInfo> AlbumAccurateRefresh::GetInitAlbumInfos()
{
    map<int32_t, AlbumChangeInfo> initAlbumInfos;
    if (!dataManager_) {
        MEDIA_WARN_LOG("dataManager_ null.");
        return initAlbumInfos;
    }
    
    return dataManager_->GetInitAlbumInfos();
}

string AlbumAccurateRefresh::GetReturningKeyName()
{
    return PhotoAlbumColumns::ALBUM_ID;
}

int32_t AlbumAccurateRefresh::Delete(MediaLibraryCommand &cmd, int32_t &deletedRows)
{
    if (!IsValidTable(cmd.GetTableName())) {
        return ACCURATE_REFRESH_RDB_INVALITD_TABLE;
    }
    return DeleteCommon([&](ValuesBucket &values) {
        return Update(deletedRows, values, *(cmd.GetAbsRdbPredicates()), RDB_OPERATION_REMOVE);
    });
}

int32_t AlbumAccurateRefresh::Delete(const AbsRdbPredicates &predicates, int &deletedRows)
{
    if (!IsValidTable(predicates.GetTableName())) {
        return E_HAS_DB_ERROR;
    }
    return DeleteCommon([&](ValuesBucket& values) {
        return Update(deletedRows, values, predicates, RDB_OPERATION_REMOVE);
    });
}

int32_t AlbumAccurateRefresh::DeleteCommon(function<int32_t(ValuesBucket&)> updateExe)
{
    ValuesBucket valuesBucket;
    valuesBucket.PutInt(PhotoAlbumColumns::ALBUM_DIRTY, static_cast<int32_t>(DirtyType::TYPE_DELETED));
    auto ret = updateExe(valuesBucket);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("rdbStore_->Delete failed, ret = %{public}d", ret);
        return E_HAS_DB_ERROR;
    }

    #ifndef MEDIA_REFRESH_TEST
        if (!trans_) {
            CloudSyncHelper::GetInstance()->StartSync(); // 事务场景不需要执行
            ACCURATE_DEBUG("Delete update done, start sync.");
        }
    #endif
    
    return ret;
}

bool AlbumAccurateRefresh::IsValidTable(std::string tableName)
{
    return PhotoAlbumColumns::TABLE == tableName;
}

int32_t AlbumAccurateRefresh::NotifyForReCheck()
{
    Notification::NotifyInfoInner notifyInfo;
    notifyInfo.tableType = Notification::NotifyTableType::PHOTO_ALBUM;
    notifyInfo.operationType = Notification::ALBUM_OPERATION_RECHECK;
    Notification::MediaLibraryNotifyNew::AddItem(notifyInfo);
    ACCURATE_DEBUG("album recheck");
    return ACCURATE_REFRESH_RET_OK;
}

} // namespace Media
} // namespace OHOS