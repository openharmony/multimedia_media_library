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
#include "medialibrary_tracer.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media::AccurateRefresh {

AlbumAccurateRefresh::AlbumAccurateRefresh(std::shared_ptr<TransactionOperations> trans) : AccurateRefreshBase(trans)
{
    dataManager_.SetTransaction(trans);
}

int32_t AlbumAccurateRefresh::Init()
{
    return ACCURATE_REFRESH_RET_OK;
}

int32_t AlbumAccurateRefresh::Init(const AbsRdbPredicates &predicates)
{
    if (!IsValidTable(predicates.GetTableName())) {
        return ACCURATE_REFRESH_RDB_INVALITD_TABLE;
    }

    return dataManager_.Init(predicates);
}

int32_t AlbumAccurateRefresh::Init(const string &sql, const vector<ValueObject> bindArgs)
{
    return dataManager_.Init(sql, bindArgs);
}

int32_t AlbumAccurateRefresh::Init(const std::vector<PhotoAlbumSubType> &systemTypes, const vector<int32_t> &albumIds)
{
    return dataManager_.InitAlbumInfos(systemTypes, albumIds);
}

int32_t AlbumAccurateRefresh::Init(const std::vector<int32_t> &albumIds)
{
    return dataManager_.InitAlbumInfos(vector<PhotoAlbumSubType>(), albumIds);
}

int32_t AlbumAccurateRefresh::Notify()
{
    if (dataManager_.CheckIsExceed()) {
        return NotifyForReCheck();
    }
    return Notify(dataManager_.GetChangeDatas());
}

int32_t AlbumAccurateRefresh::Notify(vector<AlbumChangeData> albumChangeDatas)
{
    if (albumChangeDatas.empty()) {
        MEDIA_WARN_LOG("albumChangeDatas empty.");
        return ACCURATE_REFRESH_INPUT_PARA_ERR;
    }
    notifyExe_.Notify(albumChangeDatas);
    return ACCURATE_REFRESH_RET_OK;
}

int32_t AlbumAccurateRefresh::NotifyAddAlbums(const vector<string> &albumIdsStr)
{
    return Notify(dataManager_.GetAlbumDatasFromAddAlbum(albumIdsStr));
}

int32_t AlbumAccurateRefresh::UpdateModifiedDatasInner(const std::vector<int> &albumIds, RdbOperation operation)
{
    auto modifiedAlbumIds = albumIds;
    if (modifiedAlbumIds.empty()) {
        MEDIA_WARN_LOG("modifiedAlbumIds empty.");
        return ACCURATE_REFRESH_INPUT_PARA_ERR;
    }

    int32_t err = dataManager_.UpdateModifiedDatasInner(modifiedAlbumIds, operation);
    CHECK_AND_RETURN_RET_WARN_LOG(err == ACCURATE_REFRESH_RET_OK, err,
        "UpdateModifiedDatasInner failed, err:%{public}d", err);
    err = dataManager_.PostProcessModifiedDatas(modifiedAlbumIds);
    CHECK_AND_RETURN_RET_WARN_LOG(err == ACCURATE_REFRESH_RET_OK, err,
        "PostProcessModifiedDatas failed, err:%{public}d", err);
    return ACCURATE_REFRESH_RET_OK;
}

int32_t AlbumAccurateRefresh::UpdateModifiedDatas()
{
    return dataManager_.UpdateModifiedDatas();
}

map<int32_t, AlbumChangeInfo> AlbumAccurateRefresh::GetInitAlbumInfos()
{
    return dataManager_.GetInitAlbumInfos();
}

string AlbumAccurateRefresh::GetReturningKeyName()
{
    return PhotoAlbumColumns::ALBUM_ID;
}

int32_t AlbumAccurateRefresh::LogicalDeleteReplaceByUpdate(MediaLibraryCommand &cmd, int32_t &deletedRows)
{
    if (!IsValidTable(cmd.GetTableName())) {
        return ACCURATE_REFRESH_RDB_INVALITD_TABLE;
    }
    return DeleteCommon([&](ValuesBucket &values) {
        return Update(deletedRows, values, *(cmd.GetAbsRdbPredicates()), RDB_OPERATION_REMOVE);
    });
}

int32_t AlbumAccurateRefresh::LogicalDeleteReplaceByUpdate(const AbsRdbPredicates &predicates, int &deletedRows)
{
    if (!IsValidTable(predicates.GetTableName())) {
        return ACCURATE_REFRESH_RDB_INVALITD_TABLE;
    }
    return DeleteCommon([&](ValuesBucket& values) {
        return Update(deletedRows, values, predicates, RDB_OPERATION_REMOVE);
    });
}

int32_t AlbumAccurateRefresh::DeleteCommon(function<int32_t(ValuesBucket&)> updateExe)
{
    MediaLibraryTracer tracer;
    tracer.Start("AlbumAccurateRefresh::DeleteCommon");
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
    
    return ACCURATE_REFRESH_RET_OK;
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